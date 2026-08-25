import { test } from "node:test";
import { strict as assert } from "node:assert";
import * as nodeCrypto from "node:crypto";

// Exercises the bot's KEM crypto against the real HQC library. The lib is
// Linux/x86 only, so on other platforms (e.g. the dev Mac) these are skipped
// rather than crashing on import. In CI (ubuntu) they run for real.

test("bot HQC KEM + AES + HKDF round-trip", async (t) => {
  let botCrypto: typeof import("../bot/crypto");
  let hqc: typeof import("../lib/hqc");
  try {
    botCrypto = await import("../bot/crypto");
    hqc = await import("../lib/hqc");
  } catch {
    return t.skip("HQC native lib unavailable on this platform");
  }

  const { hqcEncapsulate, hqcDecapsulate, aesEncrypt, aesDecrypt, deriveSharedKey, freshSeed } = botCrypto;
  const { HqcWrapper } = hqc;

  // Deterministic keypair from a seed; the public key is reproducible.
  const seed = nodeCrypto.randomBytes(32);
  const { pk, sk } = HqcWrapper.keypairFromSeed(seed);
  assert.ok(HqcWrapper.keypairFromSeed(seed).pk.equals(pk), "keygen is deterministic (stable pk)");

  // KEM: encapsulate → (ct, ss); decapsulate recovers the same 32-byte secret.
  const { ct, ss } = hqcEncapsulate(pk);
  assert.equal(ss.length, 32, "shared secret is 32 bytes");
  assert.ok(hqcDecapsulate(sk, ct).equals(ss), "KEM encapsulate/decapsulate agree");

  // A different encapsulation yields a different (fresh) shared secret.
  assert.ok(!hqcEncapsulate(pk).ss.equals(ss), "each encapsulation is fresh");

  // AES-GCM (the Swift [IV][tag][ct] layout) round-trips, incl. emoji.
  const key = nodeCrypto.randomBytes(32);
  const enc = aesEncrypt("hello, post-quantum 🔒", key);
  assert.equal(aesDecrypt(enc, key), "hello, post-quantum 🔒", "AES round-trip");

  // Shared-key derivation is order-independent (both peers get the same key).
  const a = freshSeed();
  const b = freshSeed();
  assert.ok(deriveSharedKey(a, b).equals(deriveSharedKey(b, a)), "HKDF symmetry");
  assert.equal(deriveSharedKey(a, b).length, 32, "AES-256 key length");
});

// A GCM verifier that will compare fewer bytes than it should is a forgery
// oracle: a 4-byte tag is guessable at 2^-32 instead of 2^-128. Node accepts a
// short tag unless `authTagLength` says otherwise, and `subarray` hands one over
// silently when the payload is truncated — so the length is both declared to the
// cipher and checked before `setAuthTag`. This pins the check.
test("aesDecrypt refuses a truncated GCM tag", async (t) => {
  let botCrypto: typeof import("../bot/crypto");
  try {
    botCrypto = await import("../bot/crypto");
  } catch {
    return t.skip("HQC native lib unavailable on this platform");
  }
  const { aesEncrypt, aesDecrypt } = botCrypto;

  const key = nodeCrypto.randomBytes(32);
  const sealed = Buffer.from(aesEncrypt("hello", key), "base64");
  assert.equal(aesDecrypt(sealed.toString("base64"), key), "hello", "round-trip still works");

  // iv(12) + tag(16) + ct — chop the payload so the tag slice comes up short.
  for (const tagBytes of [0, 4, 8, 15]) {
    const truncated = sealed.subarray(0, 12 + tagBytes);
    assert.throws(
      () => aesDecrypt(truncated.toString("base64"), key),
      /truncated GCM tag/,
      `a ${tagBytes}-byte tag is rejected by length, before any verification`
    );
  }

  // A full-length but wrong tag must still fail — on authentication, not length.
  const forged = Buffer.from(sealed);
  forged.writeUInt8(forged.readUInt8(12) ^ 0xff, 12);
  assert.throws(() => aesDecrypt(forged.toString("base64"), key),
    (e: Error) => !/truncated GCM tag/.test(e.message),
    "a 16-byte forgery is refused by GCM itself");
});
