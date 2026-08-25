// The claim: a subscription bought on the website, bound to a device key by a
// code sent to the buyer's mailbox.
//
// What is worth testing here is everything that decides whether someone gets in
// without paying, and everything that decides whether someone who DID pay gets
// locked out. The address handling is the third thing: it must normalise the
// same way on both sides, because the webhook and the app hash it independently
// and never compare anything else.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "crypto";
import { DB } from "../services/db/api";
import { pgAvailable, closePg, NEEDS_PG } from "./pg-helper";
import { setLogLevel } from "../lib/logger";
import { SubscriptionService, emailHash, validEmail, DEVICE_CAP } from "../services/subscription/api";
import { TEST_ACCOUNT_EMAIL } from "../services/subscription/test-account";

// Set before anything hashes a code, so the test computes the same value the
// service does. In production this is a deploy secret; here it only has to be
// consistent.
process.env.OTP_PEPPER = "test-pepper";

// Product logs off. These tests drive the claim flow dozens of times and each
// pass writes several lines; that volume interleaves with the test runner's own
// serialized IPC frames and fails the FILE with "Unable to deserialize cloned
// data" — a runner fault, but one this file provokes. Test output should be
// assertions anyway.
setLogLevel("silent");


const PK_A = "aa".repeat(64);
const PK_B = "bb".repeat(64);
const EMAIL = "Buyer@Example.com";
const CUSTOMER = "cus_test_claim";

function codeHash(code: string): string {
  return crypto.createHash("sha256").update(code + process.env.OTP_PEPPER, "utf8").digest("hex");
}

/** Put a known code in play, bypassing the mailer (which no-ops unconfigured).
 *  Everything downstream of this is the real verification path. */
async function plantCode(email: string, code: string) {
  await DB.putOtp(emailHash(email), codeHash(code), 600);
}


async function reset(email: string) {
  const H = emailHash(email);
  await DB.forgetClaimedDevices(H);
  await DB.clearOtp(H);
  await DB.clearCounter(`claim:email:${H}`);
  await DB.clearCounter(`claim:ip:1.2.3.4`);
}

// --- address handling (no database) ----------------------------------------

test("the email hash ignores case and surrounding whitespace", () => {
  // The webhook hashes what Stripe reports; the app hashes what the user typed.
  // If those disagree on normalisation, a real buyer is told they have nothing.
  assert.equal(emailHash("  Buyer@Example.com "), emailHash("buyer@example.com"));
  assert.notEqual(emailHash("buyer@example.com"), emailHash("buyer2@example.com"));
});

test("the email hash never contains the address", () => {
  const h = emailHash("buyer@example.com");
  assert.match(h, /^[0-9a-f]{64}$/);
  assert.ok(!h.includes("buyer"));
});

test("obvious non-addresses are refused before they reach a mail provider", () => {
  assert.ok(validEmail("a@b.co"));
  assert.ok(validEmail("a.b+tag@sub.example.co.uk"));
  assert.ok(!validEmail("no-at-sign"));
  assert.ok(!validEmail("no@tld"));
  assert.ok(!validEmail("spaces in@example.com"));
  assert.ok(!validEmail("a@" + "x".repeat(300) + ".com"));
});

// --- the claim (needs Postgres) ---------------------------------------------

test("a correct code binds the device, and cannot be used twice", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  await reset(EMAIL);
  await SubscriptionService.recordPurchase(EMAIL, CUSTOMER);

  await plantCode(EMAIL, "123456");
  assert.deepEqual(await SubscriptionService.verifyClaim(EMAIL, "123456", PK_A), { ok: true });
  assert.equal(await SubscriptionService.isClaimed(PK_A), true);

  // Replaying the same code must not bind a second device.
  const replay = await SubscriptionService.verifyClaim(EMAIL, "123456", PK_B);
  assert.deepEqual(replay, { ok: false, reason: "no_code" });
  assert.equal(await SubscriptionService.isClaimed(PK_B), false);
});

test("a wrong code fails, and five of them burn it", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  await reset(EMAIL);
  await SubscriptionService.recordPurchase(EMAIL, CUSTOMER);
  await plantCode(EMAIL, "424242");

  for (let i = 0; i < 5; i++) {
    assert.deepEqual(
      await SubscriptionService.verifyClaim(EMAIL, "000000", PK_A),
      { ok: false, reason: "bad_code" },
      `attempt ${i + 1} should still be a plain wrong answer`
    );
  }
  // Past the limit the code is gone — the RIGHT code no longer works either,
  // which is the point: guessing has to cost the attacker the code.
  assert.deepEqual(
    await SubscriptionService.verifyClaim(EMAIL, "424242", PK_A),
    { ok: false, reason: "no_code" }
  );
});

test("claiming against a cancelled subscription is refused", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  await reset(EMAIL);
  await SubscriptionService.recordPurchase(EMAIL, CUSTOMER);
  await plantCode(EMAIL, "555555");
  // Cancelled inside the code's ten-minute window: the state is re-read at
  // verification, not trusted from when the code was sent.
  await SubscriptionService.setStateForCustomer(CUSTOMER, "cancelled");

  assert.deepEqual(
    await SubscriptionService.verifyClaim(EMAIL, "555555", PK_A),
    { ok: false, reason: "not_active" }
  );
  assert.equal(await SubscriptionService.isClaimed(PK_A), false);
});

test("a lapsed subscription stops admitting a device that already claimed it", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  await reset(EMAIL);
  await SubscriptionService.recordPurchase(EMAIL, CUSTOMER);
  await plantCode(EMAIL, "777777");
  await SubscriptionService.verifyClaim(EMAIL, "777777", PK_A);
  assert.equal(await SubscriptionService.isClaimed(PK_A), true);

  const affected = await SubscriptionService.setStateForCustomer(CUSTOMER, "cancelled");
  assert.deepEqual(affected, [PK_A], "the webhook must learn which keys to cut off");
  assert.equal(await SubscriptionService.isClaimed(PK_A), false);
});

test("the device cap holds, and forgetting devices reopens it", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  await reset(EMAIL);
  await SubscriptionService.recordPurchase(EMAIL, CUSTOMER);

  const pks = Array.from({ length: DEVICE_CAP }, (_, i) => String(i).repeat(128));
  for (const pk of pks) {
    await plantCode(EMAIL, "111111");
    assert.deepEqual(await SubscriptionService.verifyClaim(EMAIL, "111111", pk), { ok: true });
  }

  await plantCode(EMAIL, "111111");
  assert.deepEqual(
    await SubscriptionService.verifyClaim(EMAIL, "111111", PK_B),
    { ok: false, reason: "cap_reached" }
  );

  const released = await SubscriptionService.forgetDevices(EMAIL);
  assert.equal(released.length, DEVICE_CAP);
  await plantCode(EMAIL, "111111");
  assert.deepEqual(await SubscriptionService.verifyClaim(EMAIL, "111111", PK_B), { ok: true });
});

test("re-claiming a device already bound does not spend another slot", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  await reset(EMAIL);
  await SubscriptionService.recordPurchase(EMAIL, CUSTOMER);

  for (let i = 0; i < 3; i++) {
    await plantCode(EMAIL, "222222");
    assert.deepEqual(await SubscriptionService.verifyClaim(EMAIL, "222222", PK_A), { ok: true });
  }
  assert.deepEqual(await DB.claimedDevices(emailHash(EMAIL)), [PK_A]);
});

test("starting a claim answers the same for a stranger as for a subscriber", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  await reset(EMAIL);
  await SubscriptionService.recordPurchase(EMAIL, CUSTOMER);
  await reset("nobody@example.com");

  // `sent` differs — it is for the server log. `ok` is what the caller returns,
  // and it must not distinguish the two, or this is a paid-customer lookup for
  // anyone with a list of addresses.
  const known = await SubscriptionService.startClaim(EMAIL, "1.2.3.4");
  const stranger = await SubscriptionService.startClaim("nobody@example.com", "1.2.3.4");
  assert.equal(known.ok, true);
  assert.equal(stranger.ok, true);
});

test("deleting an account releases its device slot but not the subscription", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  await reset(EMAIL);
  await SubscriptionService.recordPurchase(EMAIL, CUSTOMER);
  await plantCode(EMAIL, "333333");
  await SubscriptionService.verifyClaim(EMAIL, "333333", PK_A);

  await DB.createUser(PK_A, `claimtest${Date.now()}`);
  await DB.deleteUser(PK_A);

  assert.equal(await SubscriptionService.isClaimed(PK_A), false);
  assert.deepEqual(await DB.claimedDevices(emailHash(EMAIL)), []);
  // The person still has a subscription; they just no longer have that identity.
  assert.equal((await DB.getSubscription(emailHash(EMAIL)))?.state, "active");
});

// --- the test account -------------------------------------------------------
// A deliberate hole in the paid door (services/subscription/test-account.ts).
// These tests pin its EDGES: what it lets through is meant to be exactly one
// address with exactly one code, and nothing about the real claim path may
// loosen because it exists.

const TEST_PK_A = "ee".repeat(64);
const TEST_PK_B = "ef".repeat(64);

test("the test account links a device with the fixed code and no subscription behind it", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  await reset(TEST_ACCOUNT_EMAIL);

  // Nothing was purchased and no code was planted: the whole point is that a
  // reviewer with no card and no mailbox can still get through this screen.
  assert.deepEqual(
    await SubscriptionService.verifyClaim(TEST_ACCOUNT_EMAIL, "000000", TEST_PK_A),
    { ok: true }
  );
  assert.equal(await SubscriptionService.isClaimed(TEST_PK_A), true);
});

test("the test account takes the fixed code and nothing else", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  await reset(TEST_ACCOUNT_EMAIL);

  assert.deepEqual(
    await SubscriptionService.verifyClaim(TEST_ACCOUNT_EMAIL, "123456", TEST_PK_B),
    { ok: false, reason: "bad_code" }
  );
  assert.equal(await SubscriptionService.isClaimed(TEST_PK_B), false);
});

test("the test account has no device cap", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  await reset(TEST_ACCOUNT_EMAIL);

  // Two past the cap a paying subscription would stop at — "linked to all
  // devices" means the fourth tester is not the one who cannot open the app.
  const pks = Array.from({ length: DEVICE_CAP + 2 }, (_, i) => "e" + String(i).repeat(127));
  for (const pk of pks) {
    assert.deepEqual(await SubscriptionService.verifyClaim(TEST_ACCOUNT_EMAIL, "000000", pk), { ok: true });
  }
  assert.equal((await DB.claimedDevices(emailHash(TEST_ACCOUNT_EMAIL))).length, DEVICE_CAP + 2);
});

test("a real address still cannot be claimed with the test account's code", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  await reset(EMAIL);
  await SubscriptionService.recordPurchase(EMAIL, CUSTOMER);

  // No code planted, so this is the state a stranger typing 000000 is in.
  assert.deepEqual(
    await SubscriptionService.verifyClaim(EMAIL, "000000", PK_B),
    { ok: false, reason: "no_code" }
  );
  assert.equal(await SubscriptionService.isClaimed(PK_B), false);
});

test("starting a claim for the test account is not throttled by the per-address limit", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  await reset(TEST_ACCOUNT_EMAIL);
  await DB.clearCounter(`claim:ip:5.6.7.8`);

  // One shared address means the per-email counter would be a global choke on
  // everyone testing at once. The per-IP one still applies, which is why each
  // call here comes from its own address.
  for (let i = 0; i < 5; i++) {
    const r = await SubscriptionService.startClaim(TEST_ACCOUNT_EMAIL, `5.6.7.${i}`);
    assert.deepEqual(r, { ok: true, sent: false }, `start ${i + 1} should not be rate limited`);
  }
});

test.after(async () => {
  if (await pgAvailable()) {
    await reset(EMAIL);
    await reset(TEST_ACCOUNT_EMAIL);
  }
  await closePg();
});
