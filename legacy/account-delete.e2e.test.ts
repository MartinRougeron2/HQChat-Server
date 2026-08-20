import { test } from "node:test";
import { strict as assert } from "node:assert";
import Redis from "ioredis";
import { MessageTypesToReceive as In } from "./enums";
import { TestClient, loadCrypto } from "./test-client";

// Account deletion must leave NOTHING behind server-side — this is the evidence
// for App Store Guideline 5.1.1(v), and it is the kind of thing that silently
// regresses whenever a new key namespace is introduced.
//
// Same preconditions as e2e.test.ts: the native HQC lib and a reachable server.
// Skips cleanly when either is missing.

const WS_URL = process.env.TEST_WS_URL || "ws://localhost:8080/ws";
const REDIS_URL = process.env.REDIS_URL || "redis://127.0.0.1:6379";

test("e2e: deleting an account purges every server-side key", async (t) => {
  let crypto;
  try {
    crypto = await loadCrypto();
  } catch {
    return t.skip("HQC native lib unavailable on this platform");
  }

  const alice = new TestClient(crypto, WS_URL);
  try {
    await alice.connectAndAuth();
  } catch (e: any) {
    return t.skip(`no usable server at ${WS_URL} (${e?.message ?? e})`);
  }

  const redis = new Redis(REDIS_URL);
  const bob = new TestClient(crypto, WS_URL);
  await bob.connectAndAuth();

  const suffix = Date.now().toString(36) + Math.floor(Math.random() * 1000);
  const aliceName = `del_a_${suffix}`;
  const bobName = `del_b_${suffix}`;
  const alicePk = alice.pkHex;
  const bobPk = bob.pkHex;

  try {
    await alice.setUsername(aliceName);
    await bob.setUsername(bobName);

    // Build real state: a friendship, a queued message, and a pending invite
    // Alice sent to a third party — each lives in a different key namespace.
    alice.addFriend(bobName);
    await bob.waitFor(In.FRIEND_REQUEST);
    bob.acceptInvite(aliceName);
    await Promise.all([
      alice.waitForSecureChannel(bobName),
      bob.waitForSecureChannel(aliceName),
    ]);

    await t.test("state exists before deletion", async () => {
      assert.equal(await redis.exists(`user:${alicePk}`), 1, "user record");
      assert.equal(await redis.exists(`username:${aliceName}`), 1, "username binding");
      assert.equal(await redis.sismember(`friends:${alicePk}`, bobPk), 1, "friend set");
      assert.equal(await redis.sismember(`friends:${bobPk}`, alicePk), 1, "peer's friend set");
    });

    await alice.deleteAccount();

    await t.test("nothing keyed by the deleted pk survives", async () => {
      for (const key of [
        `user:${alicePk}`,
        `friends:${alicePk}`,
        `invites:${alicePk}`,
        `pending:${alicePk}`,
        `push:${alicePk}`,
        `mqtt_acl:${alicePk}`,
        `mqtt_auth:${alicePk}`,
      ]) {
        assert.equal(await redis.exists(key), 0, `${key} should be gone`);
      }
    });

    await t.test("the username is released for reuse", async () => {
      assert.equal(await redis.exists(`username:${aliceName}`), 0);
      assert.equal(await redis.sismember("usernames:taken", aliceName), 0);
    });

    await t.test("the peer keeps no dangling reference", async () => {
      assert.equal(await redis.sismember(`friends:${bobPk}`, alicePk), 0,
        "peer's friend set still lists the deleted account");
      const bobAcl = await redis.hkeys(`mqtt_acl:${bobPk}`);
      assert.ok(!bobAcl.some((topic) => topic.includes(alicePk)),
        "peer's MQTT ACL still grants topics involving the deleted account");
    });
  } finally {
    alice.close();
    bob.close();
    await redis.quit();
  }
});
