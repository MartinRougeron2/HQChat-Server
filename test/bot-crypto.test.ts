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
