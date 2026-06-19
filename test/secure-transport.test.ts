import { test } from "node:test";
import { strict as assert } from "node:assert";
import * as nodeCrypto from "node:crypto";
import {
  aesEncrypt,
  aesDecrypt,
  deriveSessionKeys,
  wrapString,
  unwrap,
} from "../lib/secure-transport";

// These cover the transport-encryption layer that does NOT need the native HQC
// lib (AES envelope + HKDF session key). The HQC seed exchange is exercised by
// the bot/lib HQC tests; here we pin the envelope format and key derivation that
// the Swift client and the bot must match exactly.

test("transport AES envelope round-trips (matches Swift [IV][tag][ct])", () => {
  const key = nodeCrypto.randomBytes(32);
  const enc = aesEncrypt("control-plane action 🔐", key);
  assert.equal(aesDecrypt(enc, key), "control-plane action 🔐");
});

test("deriveSessionKeys: deterministic, 32 bytes, distinct per direction", () => {
  const seed = nodeCrypto.randomBytes(24); // PARAM_K
  const a = deriveSessionKeys(seed);
  const b = deriveSessionKeys(seed);
  assert.ok(a.c2s.equals(b.c2s) && a.s2c.equals(b.s2c), "same seed → same keys");
  assert.equal(a.c2s.length, 32);
  assert.equal(a.s2c.length, 32);
  assert.ok(!a.c2s.equals(a.s2c), "the two directions use different keys");
});

test("deriveSessionKeys pins the HKDF parameters (must match Swift client/bot)", () => {
  // Guards against an accidental param change that would silently break interop.
  const seed = Buffer.alloc(24, 0xab);
  const expectC2s = Buffer.from(
    nodeCrypto.hkdfSync("sha256", seed, Buffer.from("salt", "utf8"), Buffer.from("session-c2s", "utf8"), 32)
  );
  const expectS2c = Buffer.from(
    nodeCrypto.hkdfSync("sha256", seed, Buffer.from("salt", "utf8"), Buffer.from("session-s2c", "utf8"), 32)
  );
  const keys = deriveSessionKeys(seed);
  assert.ok(keys.c2s.equals(expectC2s));
  assert.ok(keys.s2c.equals(expectS2c));
});

test("wrap/unwrap: encrypted when keyed, plaintext when not", () => {
  const key = nodeCrypto.randomBytes(32);
  const action = { type: "add_friend", payload: "alice" };
  const json = JSON.stringify(action);

  // Keyed: the wire frame must be an {enc} envelope, not the plaintext action.
  const wire = wrapString(json, key);
  const parsed = JSON.parse(wire);
  assert.ok(typeof parsed.enc === "string", "keyed frame is an envelope");
  assert.ok(!wire.includes("add_friend"), "action type not visible on the wire");
  assert.ok(!wire.includes("alice"), "username not visible on the wire");
  assert.deepEqual(unwrap(wire, key), action, "unwrap recovers the action");

  // Unkeyed (handshake): passes through plaintext both ways.
  const plain = wrapString(json, undefined);
  assert.equal(plain, json);
  assert.deepEqual(unwrap(plain, undefined), action);
});

test("unwrap rejects an encrypted frame with no session key", () => {
  const key = nodeCrypto.randomBytes(32);
  const wire = wrapString(JSON.stringify({ type: "message" }), key);
  assert.throws(() => unwrap(wire, undefined), /before session key/);
});
