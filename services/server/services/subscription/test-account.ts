// The test account — one address that links any device, with a code that never
// changes and no payment behind it.
//
// It exists because the claim flow is otherwise impossible to exercise without
// a card: App Review cannot buy a subscription, a fresh preprod stack has no
// Stripe data in it, and "link this device" is the one screen that cannot be
// tested against a dry run.
//
// This is a DELIBERATE hole in the paid door, and it is worth naming as one.
// The address and the code are constants — anyone who reads this file can use
// them. What they get is the premium SCOPE and nothing else: every device still
// carries its own keypair and its own conversations, so the cost is a
// subscription that was not paid for, not a way into anyone's messages. The
// hole is kept in one file, off the normal claim path, so it audits in one read
// and closes with one environment variable:
//
//   TEST_ACCOUNT_EMAIL     the address. EMPTY DISABLES the test account entirely.
//   TEST_ACCOUNT_CODE      the code it always accepts.
//   TEST_ACCOUNT_ALERT_TO  who gets mailed every time a device links this way.
//                          Empty sends no alert.
//
// Every successful link mails TEST_ACCOUNT_ALERT_TO, because a hole nobody
// watches is the kind that is still open two years later.

import { DB } from "../db/api";
import { logger } from "../../lib/logger";
import { sendMail } from "../../lib/mailer";

const APP_NAME = process.env.APP_NAME || process.env.SERVER_NAME || "DissQus";

/** Normalised the same way emailHash() normalises, so the comparison below and
 *  the key everything is stored under agree about what the address is. */
export const TEST_ACCOUNT_EMAIL = (process.env.TEST_ACCOUNT_EMAIL ?? "test@test.test").trim().toLowerCase();

const TEST_ACCOUNT_CODE = (process.env.TEST_ACCOUNT_CODE || "000000").trim();

const TEST_ACCOUNT_ALERT_TO = (process.env.TEST_ACCOUNT_ALERT_TO ?? "martin.rougeron@gmail.com").trim();

/** Whether the test account is configured at all. Unsetting TEST_ACCOUNT_EMAIL
 *  removes every branch below from the flow. */
export function testAccountEnabled(): boolean {
  return TEST_ACCOUNT_EMAIL !== "";
}

export function isTestAccount(email: string): boolean {
  return testAccountEnabled() && email.trim().toLowerCase() === TEST_ACCOUNT_EMAIL;
}

/** Plain comparison, deliberately. Constant time protects a secret, and this
 *  code is published in the file you are reading. */
export function testAccountCodeMatches(code: string): boolean {
  return code.trim() === TEST_ACCOUNT_CODE;
}

/**
 * Tell the operator a device just linked itself with the test account.
 *
 * Sent on a NEW binding only — re-linking a device that already holds the test
 * account is silent, so a tester signing in and out repeatedly does not turn
 * the alert into noise that gets filtered and then ignored.
 *
 * Best-effort, like every other send: a mail outage must not fail the link the
 * user is standing in front of.
 */
export async function notifyTestAccountLink(deviceId: string, emailHash: string): Promise<void> {
  if (!TEST_ACCOUNT_ALERT_TO) return;
  const sent = await sendMail({
    to: TEST_ACCOUNT_ALERT_TO,
    subject: `[${APP_NAME}] device linked uses the test account`,
    text:
      `device linked uses the test account\n\n` +
      `A device linked itself to ${TEST_ACCOUNT_EMAIL} and now holds a premium session ` +
      `without a subscription behind it.\n\n` +
      `client id  : ${deviceId}\n` +
      `when       : ${new Date().toISOString()}\n\n` +
      `If this was not you or a reviewer: unsetting TEST_ACCOUNT_EMAIL on the auth service ` +
      `stops NEW links, but it does not revoke the ones already made — by then the claim is ` +
      `an ordinary row. To take that access back too:\n\n` +
      `  UPDATE subscriptions SET state = 'cancelled' WHERE email_hash = '${emailHash}';\n` +
      `  DELETE FROM subscription_claims WHERE email_hash = '${emailHash}';\n`,
  });
  if (!sent) logger.warn("[claim] the test-account link alert could not be sent");
}

/**
 * Bind a device to the test account, creating the subscription behind it if
 * this is the first time anyone has asked.
 *
 * The subscription row is real: writing it here is what lets the paid door stay
 * ignorant of the test account entirely — `isClaimed()` reads `subscriptions`
 * and finds an active one, exactly as it would for a paying customer.
 *
 * There is no device cap. "Linked to all devices" is the whole point, and a cap
 * would mean the fourth reviewer to pick the app up is the one who cannot open it.
 */
export async function claimTestAccountDevice(emailHash: string, deviceId: string): Promise<void> {
  await DB.setSubscription(emailHash, "active");
  const alreadyOurs = (await DB.emailHashForClaim(deviceId)) === emailHash;
  await DB.addClaimedDevice(emailHash, deviceId, Number.MAX_SAFE_INTEGER);
  logger.info(`🔗 [claim] device ${deviceId.slice(0, 12)}… bound to the TEST account`);
  if (!alreadyOurs) await notifyTestAccountLink(deviceId, emailHash);
}
