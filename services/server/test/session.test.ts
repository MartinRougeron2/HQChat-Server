// The session model that LAT-1 and ASVS-1 turned on.
//
// Sliding sessions are easy to get subtly wrong in the two directions that
// matter: a session that never slides costs the user a biometric prompt on a
// timer, and one that slides without a cap never dies. Both are asserted here.

import { test } from "node:test";
import assert from "node:assert/strict";
import { DB } from "../services/db/api";
import { pgAvailable, closePg, NEEDS_PG } from "./pg-helper";

const PK = "aa".repeat(32);

// These need a real database — see test/pg-helper.ts for why the probe skips
// rather than fails.

test("a fresh session resolves to its pk and scope", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const token = await DB.mintSessionToken(PK, "free", 60);
  assert.deepEqual(await DB.resolveSessionToken(token), { pk: PK, scope: "free" });
});

test("the scope a session was minted with is the scope it keeps", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // Nothing re-derives an entitlement per request, so this IS the paywall: if
  // the value did not survive a round trip, /friends/invite would read wrong.
  const token = await DB.mintSessionToken(PK, "premium", 60);
  assert.equal((await DB.resolveSessionToken(token))?.scope, "premium");
});

test("using a session slides its idle timeout forward", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // Mint with a deliberately short idle window, then use it: the slide should
  // push the TTL back up to the default, not leave it at 2 seconds.
  const token = await DB.mintSessionToken(PK, "free", 2);
  assert.equal((await DB.resolveSessionToken(token))?.pk, PK);
  const ttl = await DB.sessionTtl(token);
  assert.ok(ttl > 2, `expected the TTL to slide past its original 2s, got ${ttl}`);
});

test("an unknown or revoked token resolves to nothing", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const token = await DB.mintSessionToken(PK, "free", 60);
  await DB.revokeSessionToken(token);
  assert.equal(await DB.resolveSessionToken(token), null);
  assert.equal(await DB.resolveSessionToken("not-a-token"), null);
});

test("revoking a pk ends every live session it holds", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // What makes a cancelled subscription bite now rather than in thirty days.
  // A key of its own, because the other tests in this file mint against PK and
  // revokeAllSessions ends every session the pk holds.
  const lonePk = "ee".repeat(64);
  const a = await DB.mintSessionToken(lonePk, "premium", 60);
  const b = await DB.mintSessionToken(lonePk, "premium", 60);
  assert.equal(await DB.revokeAllSessions(lonePk), 2);
  assert.equal(await DB.resolveSessionToken(a), null);
  assert.equal(await DB.resolveSessionToken(b), null);
});

test("a session past its absolute cap is refused and deleted", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // Backdate `iat` beyond the cap: sliding must not resurrect it.
  const token = await DB.mintSessionTokenAt(PK, 60, 1);
  assert.equal(await DB.resolveSessionToken(token), null);
  assert.equal(await DB.sessionTtl(token), -2, "the row should be gone, not merely refused");
});

test.after(closePg);
