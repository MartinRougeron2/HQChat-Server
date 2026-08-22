import { test } from "node:test";
import { strict as assert } from "node:assert";
import { q, disconnect } from "../services/db/pg";
import { MessageTypesToReceive as In } from "./enums";
import { TestClient, loadCrypto } from "./test-client";

// Account deletion must leave NOTHING behind server-side — this is the evidence
// for App Store Guideline 5.1.1(v), and it is the kind of thing that silently
// regresses whenever a new table is introduced.
//
// It asserts against the database directly rather than through DB, on purpose:
// the point is that no ROW survives, and a bug in the read path would otherwise
// hide a bug in the delete path.
//
// Same preconditions as e2e.test.ts: the native HQC lib and a reachable server.
// Skips cleanly when either is missing.

const WS_URL = process.env.TEST_WS_URL || "ws://localhost:8080/ws";

/** How many rows a query returns — the whole vocabulary this test needs. */
async function count(sql: string, params: unknown[]): Promise<number> {
  const res = await q<{ n: number }>(`SELECT count(*)::int AS n FROM ${sql}`, params);
  return res.rows[0]?.n ?? 0;
}

test("e2e: deleting an account purges every server-side row", async (t) => {
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

    // Build real state: an identity, a username binding and a friendship, each
    // in a different table.
    alice.addFriend(bobName);
    await bob.waitFor(In.FRIEND_REQUEST);
    bob.acceptInvite(aliceName);
    await Promise.all([
      alice.waitForSecureChannel(bobName),
      bob.waitForSecureChannel(aliceName),
    ]);

    await t.test("state exists before deletion", async () => {
      assert.equal(await count("users WHERE pk = $1", [alicePk]), 1, "user record");
      assert.equal(await count("users WHERE username = $1", [aliceName]), 1, "username binding");
      // One row is the friendship from both sides — there is no second copy that
      // could be left behind, which is half of what this test used to check.
      assert.equal(
        await count("friendships WHERE (pk_lo, pk_hi) IN (($1, $2), ($2, $1))", [alicePk, bobPk]),
        1,
        "friendship"
      );
    });

    await alice.deleteAccount();

    await t.test("no row naming the deleted pk survives", async () => {
      const byPk: Array<[string, string]> = [
        ["users", "pk = $1"],
        ["friendships", "pk_lo = $1 OR pk_hi = $1"],
        ["invites", "to_pk = $1 OR from_pk = $1"],
        ["push_tokens", "pk = $1"],
        ["mqtt_acl", "pk = $1"],
        ["mqtt_tokens", "pk = $1"],
        ["sessions", "pk = $1"],
        ["subscription_claims", "pk = $1"],
      ];
      for (const [table, where] of byPk) {
        assert.equal(await count(`${table} WHERE ${where}`, [alicePk]), 0,
          `${table} still has a row for the deleted account`);
      }
    });

    await t.test("the username is released for reuse", async () => {
      assert.equal(await count("users WHERE username = $1", [aliceName]), 0);
    });

    await t.test("the peer keeps no dangling reference", async () => {
      // The grants the PEER holds are the ones a delete can most easily miss:
      // they are keyed by bob, and only their topic names mention alice.
      const res = await q<{ topic: string }>("SELECT topic FROM mqtt_acl WHERE pk = $1", [bobPk]);
      assert.ok(
        !res.rows.some((r) => r.topic.includes(alicePk)),
        "peer's MQTT ACL still grants a topic naming the deleted account"
      );
    });
  } finally {
    alice.close();
    bob.close();
    await disconnect();
  }
});
