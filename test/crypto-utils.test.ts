import { test } from "node:test";
import { strict as assert } from "node:assert";
import { friendshipHash, blindedPk } from "../lib/crypto-utils";

const PK_A = "a".repeat(64);
const PK_B = "b".repeat(64);
const PK_C = "c".repeat(64);

test("friendshipHash is order-independent", () => {
  assert.equal(friendshipHash(PK_A, PK_B), friendshipHash(PK_B, PK_A));
});

test("friendshipHash differs for different pairs", () => {
  assert.notEqual(friendshipHash(PK_A, PK_B), friendshipHash(PK_A, PK_C));
});

test("friendshipHash is a 64-char hex digest", () => {
  assert.match(friendshipHash(PK_A, PK_B), /^[0-9a-f]{64}$/);
});

test("blindedPk is deterministic", () => {
  assert.equal(blindedPk(PK_A), blindedPk(PK_A));
});

test("blindedPk never returns the raw key and is hex", () => {
  const hash = blindedPk(PK_A);
  assert.notEqual(hash, PK_A);
  assert.match(hash, /^[0-9a-f]{64}$/);
});

test("blindedPk differs per key", () => {
  assert.notEqual(blindedPk(PK_A), blindedPk(PK_B));
});
