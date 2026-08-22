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

const PK = "cc".repeat(64);
const OTHER = "dd".repeat(64);
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
  const { checkAdmission } = admissionUnder("allowlist", PK);
  assert.deepEqual(await checkAdmission(PK, "free"), { ok: true });
  assert.deepEqual(await checkAdmission(PK, "paid"), { ok: true });
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
  await DB.addClaimedDevice(emailHash(EMAIL), PK, 3);

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
  await DB.addAdmissionExempt(OTHER);
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
    await DB.removeAdmissionExempt(OTHER);
  }
  await closePg();
});
