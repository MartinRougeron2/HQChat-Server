// Admission, per door.
//
// The interesting property is not "does a subscriber get in" — it is that the
// two doors disagree, and disagree in the right direction. The free door must
// never refuse for want of payment (that is what makes the App Store build a
// working app rather than a locked one), and the paid door must never admit an
// unclaimed key (that is the paywall).
//
// ADMISSION_POLICY is read once, at module load, so each case reloads the
// module with the policy it wants. `require` rather than a static import for
// exactly that reason: an import would be hoisted above the env assignment.

import { test } from "node:test";
import assert from "node:assert/strict";
import { DB } from "../services/db/api";
import { peerId } from "../lib/identity";
import { pgAvailable, closePg, NEEDS_PG } from "./pg-helper";
import { setLogLevel } from "../lib/logger";
import { SubscriptionService, emailHash } from "../services/subscription/api";

process.env.OTP_PEPPER = "test-pepper";
setLogLevel("silent");

type Admission = typeof import("../lib/admission");

function admissionUnder(policy: string, allowlist = ""): Admission {
  process.env.ADMISSION_POLICY = policy;
  process.env.ADMISSION_ALLOWLIST = allowlist;
  delete require.cache[require.resolve("../lib/admission")];
  return require("../lib/admission") as Admission;
}

// `checkAdmission` takes a PUBLIC KEY, because it runs on the auth path — the
// one place a key is in hand. Everything it looks up is keyed by the ID that key
// commits to, and the conversion happens inside lib/admission.ts so that neither
// an operator (who has keys) nor the schema (which has ids) has to know about
// the other's form.
//
// Which means a test that plants a row has to plant it under the ID, exactly as
// the production writers do — the same asymmetry EXEMPT_PUBLIC_KEYS and
// `admission_exempt` have.
const PK = "cc".repeat(64);
const OTHER = "dd".repeat(64);
const PK_ID = peerId(PK);
const OTHER_ID = peerId(OTHER);
const EMAIL = "admission@example.com";
const CUSTOMER = "cus_test_admission";


test("an open server admits both doors — self-hosting buys nothing", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const { checkAdmission } = admissionUnder("open");
  assert.deepEqual(await checkAdmission(PK, "free"), { ok: true });
  assert.deepEqual(await checkAdmission(PK, "paid"), { ok: true });
});

test("an allowlist server refuses an unlisted key at BOTH doors", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // A private server has no free tier to fall back to: being turned away is the
  // whole answer, and the client must not retry the other door hoping for less.
  // The allowlist is spelled in KEYS — that is what an operator copies out of a
  // client — and compared as ids, so an entry differing only in case still
  // matches.
  const { checkAdmission } = admissionUnder("allowlist", PK);
  assert.deepEqual(await checkAdmission(PK, "free"), { ok: true });
  assert.deepEqual(await checkAdmission(PK, "paid"), { ok: true });
  assert.deepEqual(await checkAdmission(PK.toUpperCase(), "paid"), { ok: true },
    "the same key in a different case is the same identity");
  assert.deepEqual(await checkAdmission(OTHER, "free"), { ok: false, reason: "denied" });
  assert.deepEqual(await checkAdmission(OTHER, "paid"), { ok: false, reason: "denied" });
});

test("on a selling server the free door never asks about payment", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const { checkAdmission } = admissionUnder("stripe");
  await DB.forgetClaimedDevices(emailHash(EMAIL));
  assert.deepEqual(await checkAdmission(OTHER, "free"), { ok: true });
});

test("the paid door refuses an unclaimed key and admits a claimed one", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const { checkAdmission } = admissionUnder("stripe");
  await DB.forgetClaimedDevices(emailHash(EMAIL));

  assert.deepEqual(await checkAdmission(PK, "paid"), { ok: false, reason: "not_claimed" });

  await SubscriptionService.recordPurchase(EMAIL, CUSTOMER);
  // Under the id, which is what `/claim/verify` records and what revocation
  // (an ACL edit plus a kick) can actually address.
  await DB.addClaimedDevice(emailHash(EMAIL), PK_ID, 3);

  assert.deepEqual(await checkAdmission(PK, "paid"), { ok: true });

  // And it stops the moment the subscription does.
  await DB.setSubscription(emailHash(EMAIL), "cancelled");
  assert.deepEqual(await checkAdmission(PK, "paid"), { ok: false, reason: "not_claimed" });
});

test("an exempt key passes either door under any policy", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // The helper bot registers itself. It has no subscription and never will, and
  // every new account is auto-friended to it, so a policy that shut it out would
  // empty the first screen every user sees.
  // The bot writes its own ID here, not its key — see bot/bot.ts.
  await DB.addAdmissionExempt(OTHER_ID);
  const { checkAdmission } = admissionUnder("stripe");
  assert.deepEqual(await checkAdmission(OTHER, "paid"), { ok: true });

  const allow = admissionUnder("allowlist", PK);
  assert.deepEqual(await allow.checkAdmission(OTHER, "paid"), { ok: true });
});

test.after(async () => {
  if (await pgAvailable()) {
    await DB.forgetClaimedDevices(emailHash(EMAIL));
    // `admission_exempt` outlives the process, so leaving OTHER in it would
    // make the allowlist case above pass for the wrong reason on the next run.
    await DB.removeAdmissionExempt(OTHER_ID);
  }
  await closePg();
});
