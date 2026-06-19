import { test } from "node:test";
import { strict as assert } from "node:assert";
import * as nodeCrypto from "node:crypto";

// Exercises the bot's crypto against the real HQC library. The lib is Linux/x86
// only, so on other platforms (e.g. the dev Mac) these are skipped rather than
// crashing on import. In CI (ubuntu) they run for real.

test("bot HQC + AES + HKDF round-trip", async (t) => {
  let botCrypto: typeof import("../bot/crypto");
  let hqc: typeof import("../lib/hqc");
  try {
    botCrypto = await import("../bot/crypto");
    hqc = await import("../lib/hqc");
  } catch {
    return t.skip("HQC native lib unavailable on this platform");
  }

  const { hqcEncrypt, hqcDecrypt, aesEncrypt, aesDecrypt, deriveSharedKey, freshSeed } = botCrypto;
  const { HqcWrapper } = hqc;

  // Keypair from a random seed.
  const { pk, sk } = HqcWrapper.generateKeypair(nodeCrypto.randomBytes(32));

  // HQC chunking round-trips a multi-block message (>24 bytes).
  const msg = Buffer.from("the quick brown fox jumps over the lazy dog — 1234567890");
  const recovered = hqcDecrypt(sk, hqcEncrypt(pk, msg), true);
  assert.equal(recovered.toString("utf8"), msg.toString("utf8"), "HQC round-trip");

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
