// Subscription claim — the join between a payment made on the website and a
// keypair held on a device.
//
// The two never meet directly. Stripe knows an email address; the device knows
// a public key; neither knows the other. An OTP sent to that address is the
// only bridge, and crossing it binds the public key to the subscription. From
// then on `/auth/paid/init` is a single primary-key lookup.
//
// The address itself is never stored. Everything here is keyed by
//   H = sha256(lowercased, trimmed email)
// so this server holds the fact that *a* subscription exists without holding
// whose it is. Stripe remains the only system with the plaintext, which is also
// what keeps the App Privacy answers honest.

import * as crypto from "crypto";
import { DB } from "../db/api";
import { logger } from "../../lib/logger";
import { sendMail } from "../../lib/mailer";
import { isTestAccount, testAccountCodeMatches, claimTestAccountDevice, TEST_ACCOUNT_EMAIL } from "./test-account";

/** How many devices one subscription admits. A cap, not a lock: re-claiming a
 *  device already bound costs nothing, and forgetDevices() is the way out. */
export const DEVICE_CAP = Number(process.env.SUBSCRIPTION_DEVICE_CAP || 3);

const OTP_TTL_SECONDS = 10 * 60;
/** Guesses allowed against one code before it is burned. Six digits over five
 *  tries is a 1-in-200 000 shot; the rate limits below bound how often that
 *  shot can be re-bought with a fresh code. */
const OTP_MAX_ATTEMPTS = 5;

const CLAIM_IP_LIMIT = Number(process.env.CLAIM_IP_LIMIT || 5);
const CLAIM_EMAIL_LIMIT = Number(process.env.CLAIM_EMAIL_LIMIT || 3);
const CLAIM_WINDOW_SECONDS = 15 * 60;

const APP_NAME = process.env.APP_NAME || process.env.SERVER_NAME || "DissQus";

// Deliberately permissive: this is a sanity bound on what we will hand to a
// mail provider, not an opinion about which addresses are real. The only test
// that matters is whether the code arrives.
const EMAIL_RE = /^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/;

/**
 * A pepper, not a salt. The stored value is sha256(code + pepper), and a
 * six-digit code has only a million preimages — without a server-side secret,
 * anyone who reads a database dump can invert every pending OTP with a laptop and
 * a for-loop. The pepper lives in the environment, so a dump alone is not
 * enough. Unset in development, which is safe there and loud here.
 */
function pepper(): string {
  const p = process.env.OTP_PEPPER?.trim();
  if (!p && process.env.NODE_ENV === "production") {
    logger.error("[claim] OTP_PEPPER is unset in production — stored codes are brute-forceable from a database dump");
  }
  return p || "";
}

/** Normalise then hash. Every key in this module derives from this and nothing
 *  else, so the app and the Stripe webhook agree without either sending the
 *  plaintext to the other. */
export function emailHash(email: string): string {
  return crypto.createHash("sha256").update(email.trim().toLowerCase(), "utf8").digest("hex");
}

export function validEmail(email: string): boolean {
  return email.length <= 254 && EMAIL_RE.test(email.trim());
}

function hashCode(code: string): string {
  return crypto.createHash("sha256").update(code + pepper(), "utf8").digest("hex");
}

function safeEqualHex(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

/** Six digits, uniformly. `randomInt` rejects modulo bias; `Math.random` would
 *  make the code guessable from a couple of observations. */
function generateCode(): string {
  return String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");
}

export type StartResult =
  | { ok: true; sent: boolean }
  | { ok: false; reason: "invalid_email" | "rate_limited" };

export type VerifyResult =
  | { ok: true }
  | { ok: false; reason: "invalid_email" | "no_code" | "bad_code" | "cap_reached" | "not_active" };

export const SubscriptionService = {

  /**
   * A checkout completed. Called from the Stripe webhook, which is the only
   * place a plaintext address enters this server — it is hashed here and
   * discarded. `customerId` is indexed both ways so a later
   * `customer.subscription.*` event, which carries no address at all, still
   * resolves to the same subscription.
   */
  async recordPurchase(email: string, customerId: string): Promise<string> {
    const H = emailHash(email);
    await DB.setSubscription(H, "active", customerId);
    logger.info(`💳 [claim] subscription active for ${H.slice(0, 8)}…`);

    // Not the OTP — just the one instruction the user needs next. Sent here
    // rather than at claim time because this is the moment they are looking at
    // a "thank you" page wondering what happens now.
    await sendMail({
      to: email,
      subject: `Your ${APP_NAME} subscription is active`,
      text:
        `Your subscription is active.\n\n` +
        `Open ${APP_NAME} on your device and enter this email address to link it. ` +
        `We'll send you a 6-digit code to confirm.\n\n` +
        `You can link up to ${DEVICE_CAP} devices.\n`,
    });
    return H;
  },

  /** Flip a subscription's state from a `customer.subscription.*` event.
   *  Returns the public keys bound to it, so the caller can end their access
   *  the moment it lapses rather than at the next login. */
  async setStateForCustomer(customerId: string, state: "active" | "cancelled"): Promise<string[]> {
    const H = await DB.emailHashForCustomer(customerId);
    if (!H) {
      logger.warn(`[claim] no subscription indexed for customer ${customerId}; ignoring ${state}`);
      return [];
    }
    await DB.setSubscription(H, state);
    return await DB.claimedDevices(H);
  },

  /**
   * Begin a claim: mail a code to the address, if it bought anything.
   *
   * The caller MUST answer identically whichever branch this takes. `sent`
   * exists for the log, not for the response — a "no subscription for that
   * address" reply would turn this endpoint into a paid-customer lookup for
   * anyone with a list of emails.
   */
  async startClaim(email: string, ip: string): Promise<StartResult> {
    if (!validEmail(email)) return { ok: false, reason: "invalid_email" };
    const H = emailHash(email);

    const byIp = await DB.bumpCounter(`claim:ip:${ip}`, CLAIM_WINDOW_SECONDS);
    // The test account is exempt from the per-ADDRESS limit and only that one:
    // it is a single shared address, so three starts a quarter-hour is a global
    // choke on everyone testing at once. The per-IP limit still applies to it,
    // and that is the one that actually bounds a stranger hammering this.
    const byEmail = isTestAccount(email)
      ? 0
      : await DB.bumpCounter(`claim:email:${H}`, CLAIM_WINDOW_SECONDS);
    if (byIp > CLAIM_IP_LIMIT || byEmail > CLAIM_EMAIL_LIMIT) {
      // Rate limiting is the one thing that may be visible: it is a property of
      // the CALLER, and reveals nothing about the address.
      return { ok: false, reason: "rate_limited" };
    }

    if (isTestAccount(email)) {
      // Nothing to send: the address is not deliverable and the code is a
      // constant. The subscription is created here rather than at verify time
      // so that a tester who only ever taps "send code" still ends up with the
      // account in the state the next screen expects.
      await DB.setSubscription(H, "active");
      logger.info(`[claim] start for the TEST account (${TEST_ACCOUNT_EMAIL}) — no mail, the code is fixed`);
      return { ok: true, sent: false };
    }

    const sub = await DB.getSubscription(H);
    if (!sub || sub.state !== "active") {
      logger.debug(`[claim] start for ${H.slice(0, 8)}… — no active subscription`);
      return { ok: true, sent: false };
    }

    const devices = await DB.claimedDevices(H);
    if (devices.length >= DEVICE_CAP) {
      logger.info(`[claim] start for ${H.slice(0, 8)}… — device cap reached`);
      return { ok: true, sent: false };
    }

    const code = generateCode();
    await DB.putOtp(H, hashCode(code), OTP_TTL_SECONDS);

    const sent = await sendMail({
      to: email,
      subject: `${APP_NAME} device code: ${code}`,
      text:
        `Your ${APP_NAME} device code is ${code}\n\n` +
        `Enter it in the app to link this device to your subscription. ` +
        `The code expires in 10 minutes.\n\n` +
        `If you didn't ask for this, ignore this email — nothing has changed.\n`,
    });
    if (!sent) {
      // Loud, because from the user's side this is indistinguishable from a
      // wrong address: they wait for a code that was never going to arrive.
      logger.error(`[claim] code for ${H.slice(0, 8)}… could not be sent`);
    }
    return { ok: true, sent };
  },

  /**
   * Finish a claim: check the code, bind the device.
   *
   * The attempt is counted before the comparison, and the code is burned once
   * the count passes the limit — so a wrong guess costs something whether or
   * not the caller waits for the answer.
   */
  async verifyClaim(email: string, code: string, pkHex: string): Promise<VerifyResult> {
    if (!validEmail(email)) return { ok: false, reason: "invalid_email" };
    const H = emailHash(email);

    if (isTestAccount(email)) {
      if (!testAccountCodeMatches(code)) return { ok: false, reason: "bad_code" };
      // Deliberately independent of startClaim: the code never changes and
      // never expires, so a tester who types it straight in is not left waiting
      // on an OTP row that no email was ever going to announce.
      await claimTestAccountDevice(H, pkHex);
      return { ok: true };
    }

    const pending = await DB.takeOtpAttempt(H);
    if (!pending) return { ok: false, reason: "no_code" };

    if (pending.attempts > OTP_MAX_ATTEMPTS) {
      await DB.clearOtp(H);
      logger.warn(`[claim] code for ${H.slice(0, 8)}… burned after ${pending.attempts} attempts`);
      return { ok: false, reason: "no_code" };
    }
    if (!safeEqualHex(hashCode(code), pending.codeHash)) {
      return { ok: false, reason: "bad_code" };
    }

    // The code was right; it does not get a second life.
    await DB.clearOtp(H);

    // Re-check state rather than trust the check made when the code was sent —
    // a subscription can be cancelled inside the ten-minute window.
    const sub = await DB.getSubscription(H);
    if (!sub || sub.state !== "active") return { ok: false, reason: "not_active" };

    const result = await DB.addClaimedDevice(H, pkHex, DEVICE_CAP);
    if (result === "cap") return { ok: false, reason: "cap_reached" };

    logger.info(`🔗 [claim] device bound to ${H.slice(0, 8)}…`);
    return { ok: true };
  },

  /** Whether this public key is bound to a live subscription. The paid door's
   *  entire question, and deliberately two GETs — it runs before the KEM. */
  async isClaimed(pkHex: string): Promise<boolean> {
    const H = await DB.emailHashForClaim(pkHex);
    if (!H) return false;
    const sub = await DB.getSubscription(H);
    return sub?.state === "active";
  },

  /** Release every device on a subscription — the escape hatch for someone who
   *  hit the cap with phones they no longer own. Returns the released public
   *  keys so the caller can end their sessions. */
  async forgetDevices(email: string): Promise<string[]> {
    return await DB.forgetClaimedDevices(emailHash(email));
  },
};
