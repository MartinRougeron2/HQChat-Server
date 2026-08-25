// Every table keyed by a public key must accept a REAL one.
//
// A btree index entry may not exceed about 2704 bytes. An HQC-256 public key is
// 7237 bytes and travels as hex — 14474 characters — so the original Postgres
// schema's `pk text PRIMARY KEY` did not merely index badly, it rejected every
// write that carried a genuine key:
//
//   ERROR: index row requires 14488 bytes, maximum size is 8191
//
// Nothing caught that for a full release cycle. The only tests that use
// key-shaped values are the e2e ones, and CI's `changes` job was failing on
// every pull request, which skipped them; the unit suite used short stand-ins
// like "aa".repeat(32), which fit comfortably and proved nothing.
//
// So this file uses a key of the true size against every pk-keyed write, and it
// lives in `npm test` — the suite that actually runs on every PR.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "crypto";
import { DB } from "../services/db/api";
import { pgAvailable, closePg, NEEDS_PG } from "./pg-helper";

// HQC_CONSTANTS.PUBLIC_KEY_BYTES from lib/hqc.ts, as a literal: importing that
// module loads the native library, which this test has no need of and which is
// built for one platform only.
const PUBLIC_KEY_BYTES = 7237;

/** A key of exactly the size the wire carries. Random, so it cannot compress
 *  down under the limit the way a repeated character would. */
const bigPk = () => crypto.randomBytes(PUBLIC_KEY_BYTES).toString("hex");

const tag = () => crypto.randomBytes(4).toString("hex");

test("a full-size public key survives identity, social graph and ACL writes", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const a = bigPk(), b = bigPk(), id = tag();
  const [na, nb] = [`big_a_${id}`, `big_b_${id}`];

  await DB.createUser(a, na);
  await DB.createUser(b, nb);
  assert.equal(await DB.getUsername(a), na);

  // The upsert path, which is where the index is written a second time.
  await DB.setUsername(a, `big_a2_${id}`);
  assert.equal(await DB.getUsername(a), `big_a2_${id}`);

  await DB.addAdmissionExempt(a);
  assert.ok(await DB.isAdmissionExempt(a));

  await DB.invite(a, nb);
  assert.equal((await DB.getMyInvites(b)).length, 1);
  assert.ok(await DB.acceptInvite(`big_a2_${id}`, b));
  assert.ok(await DB.checkFriendship(a, b), "friendship pair key");

  // `topic` embeds a key as well, so mqtt_acl is oversized on both columns.
  await DB.grantSelfTopics(a);
  await DB.grantFriendTopic(a, b);
  assert.ok((await DB.getAclTopics(a)).length >= 3);

  await DB.deleteUser(a);
  await DB.deleteUser(b);
});

test("a full-size public key survives the ephemeral tier", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const a = bigPk();

  await DB.setPushToken(a, "ios", "tok-1");
  await DB.setPushToken(a, "ios", "tok-2");
  assert.equal((await DB.getPushToken(a))?.token, "tok-2");

  await DB.mintMqttToken(a);
  const live = await DB.mintMqttToken(a);
  assert.ok((await DB.verifyMqttToken(a, live)).ok);

  await DB.startAuthChallenge(a, "proof-1");
  await DB.startAuthChallenge(a, "proof-2");
  assert.equal(await DB.takeAuthChallenge(a), "proof-2");

  const token = await DB.mintSessionToken(a, "free", 60);
  assert.equal((await DB.resolveSessionToken(token))?.pk, a);

  // auth/main.ts counts per key, so the whole key lands in rate_counters.key.
  assert.equal(await DB.bumpCounter(`init:pk:${a}`, 60), 1);
  assert.equal(await DB.bumpCounter(`init:pk:${a}`, 60), 2);
  await DB.clearCounter(`init:pk:${a}`);

  await DB.deleteUser(a);
});

test("a full-size public key survives a subscription claim", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const a = bigPk();
  const emailHash = crypto.randomBytes(32).toString("hex");

  await DB.setSubscription(emailHash, "active");
  assert.equal(await DB.addClaimedDevice(emailHash, a, 3), "ok");
  // Re-claiming the same device is an upsert, not a second slot.
  assert.equal(await DB.addClaimedDevice(emailHash, a, 3), "ok");
  assert.deepEqual(await DB.claimedDevices(emailHash), [a]);

  await DB.deleteUser(a);
  await DB.forgetClaimedDevices(emailHash);
});

test.after(closePg);
