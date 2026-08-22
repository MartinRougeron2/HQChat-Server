// Shared admission policy — decides whether an authenticated public key may use
// this server, and at which door. Extracted from server.ts so every entrypoint
// enforces identical rules with no drift.
//
//   open      — anyone who passes HQC auth (default; self-host friendly)
//   allowlist — only public keys in ADMISSION_ALLOWLIST (private/family servers)
//   stripe    — the free door is open to all; the paid door requires a claimed,
//               live subscription (the official server)
//
// This function used to answer "has this person paid?", and answered it by
// calling Stripe on every login. It does not any more: payment is a claim in
// the database, resolved by services/subscription, and what is left here is the
// question the name always implied — is this key allowed on this server at all.

import { DB } from "../services/db/api";
import { SubscriptionService } from "../services/subscription/api";
import { logger } from "./logger";

export const ADMISSION_POLICY = (process.env.ADMISSION_POLICY || "open").toLowerCase();
export const ADMISSION_ALLOWLIST = (process.env.ADMISSION_ALLOWLIST || "")
  .split(",").map((s) => s.trim()).filter(Boolean);

/**
 * Which door a client knocked on. The free door grants a bot-only session; the
 * paid door grants everything, and only to a key bound to a live subscription.
 *
 * They are separate endpoints rather than one endpoint with a flag because the
 * paid door answers BEFORE the KEM handshake: an unclaimed key is turned away
 * for the cost of one primary-key lookup. That is only safe to do because the free door
 * exists — refusing at the paid door denies nobody access to the app, so it is
 * a gate rather than a subscriber-status oracle on the only way in.
 */
export type Door = "free" | "paid";

export type Admission =
  | { ok: true }
  | { ok: false; reason: "denied" | "not_claimed" };

/** Whether a public key is exempt from every gate (the helper bot). Exemption
 *  waives policy, never the proof of key possession. */
async function isExempt(pkHex: string): Promise<boolean> {
  const configured = (process.env.EXEMPT_PUBLIC_KEYS || "")
    .split(",").map((s) => s.trim()).filter(Boolean);
  if (configured.includes(pkHex)) return true;

  // Self-registered exemptions (the helper bot writes its own pk on startup;
  // see bot/bot.ts). Survives the bot's identity changing without an operator
  // editing EXEMPT_PUBLIC_KEYS. Best-effort: a database blip here must not
  // hard-fail admission, so a failure falls through to the policy check.
  try {
    return await DB.isAdmissionExempt(pkHex);
  } catch (e: any) {
    logger.error(`[admission] exempt-set lookup failed: ${e.message}`);
    return false;
  }
}

export async function checkAdmission(pkHex: string, door: Door): Promise<Admission> {
  if (await isExempt(pkHex)) return { ok: true };

  switch (ADMISSION_POLICY) {
    case "stripe":
      // The free door sells nothing and asks nothing. The paid door asks the
      // only question that matters, and it is one primary-key lookup.
      if (door === "free") return { ok: true };
      return (await SubscriptionService.isClaimed(pkHex))
        ? { ok: true }
        : { ok: false, reason: "not_claimed" };

    case "allowlist":
      // A private server has no free tier to speak of: an unlisted key is not
      // welcome through either door.
      return ADMISSION_ALLOWLIST.includes(pkHex) ? { ok: true } : { ok: false, reason: "denied" };

    case "open":
    default:
      // Self-hosters get the whole product. There is nothing to pay for here,
      // so the paid door is a pass rather than a gate.
      return { ok: true };
  }
}
