import { describe, it, test } from 'node:test';
import assert from 'node:assert';
import { HqcWrapper, HQC_CONSTANTS } from './hqc';
import * as crypto from "crypto";

describe('HQC KEM Wrapper Tests', () => {

  // ==========================================
  // 1. CONSTANTS & SETUP
  // ==========================================

  const validSeed = crypto.randomBytes(HQC_CONSTANTS.SEED_BYTES);

  console.log(`\n[INFO] Testing LibHQC KEM`);
  console.log(`[INFO] PK Size: ${HQC_CONSTANTS.PUBLIC_KEY_BYTES}`);
  console.log(`[INFO] SK Size: ${HQC_CONSTANTS.SECRET_KEY_BYTES}`);
  console.log(`[INFO] CT Size: ${HQC_CONSTANTS.CIPHERTEXT_BYTES}`);
  console.log(`[INFO] SS Size: ${HQC_CONSTANTS.SHARED_SECRET_BYTES}\n`);

  // ==========================================
  // 2. KEY GENERATION TESTS
  // ==========================================

  it('should generate a keypair with correct buffer sizes', () => {
    const keys = HqcWrapper.keypairFromSeed(validSeed);
    assert.ok(keys.pk, 'Public Key should exist');
    assert.ok(keys.sk, 'Secret Key should exist');
    assert.strictEqual(keys.pk.length, HQC_CONSTANTS.PUBLIC_KEY_BYTES, 'PK length mismatch');
    assert.strictEqual(keys.sk.length, HQC_CONSTANTS.SECRET_KEY_BYTES, 'SK length mismatch');
  });

  it('should be deterministic (Same Seed = Same Keys)', () => {
    const seed = Buffer.alloc(HQC_CONSTANTS.SEED_BYTES, 0xAA);
    const keys1 = HqcWrapper.keypairFromSeed(seed);
    const keys2 = HqcWrapper.keypairFromSeed(seed);
    assert.deepStrictEqual(keys1.pk, keys2.pk, 'Public Keys must be identical for same seed');
    assert.deepStrictEqual(keys1.sk, keys2.sk, 'Secret Keys must be identical for same seed');
  });

  it('should produce different keys for different seeds', () => {
    const keys1 = HqcWrapper.keypairFromSeed(Buffer.alloc(HQC_CONSTANTS.SEED_BYTES, 1));
    const keys2 = HqcWrapper.keypairFromSeed(Buffer.alloc(HQC_CONSTANTS.SEED_BYTES, 2));
    assert.notDeepStrictEqual(keys1.pk, keys2.pk, 'PKs should differ');
    assert.notDeepStrictEqual(keys1.sk, keys2.sk, 'SKs should differ');
  });

  // ==========================================
  // 3. ENCAPSULATION / DECAPSULATION TESTS
  // ==========================================

  it('should encapsulate to a valid ciphertext + 32-byte shared secret', () => {
    const keys = HqcWrapper.keypairFromSeed(validSeed);
    const { ct, ss } = HqcWrapper.encapsulate(keys.pk);
    assert.strictEqual(ct.length, HQC_CONSTANTS.CIPHERTEXT_BYTES, 'Ciphertext size mismatch');
    assert.strictEqual(ss.length, HQC_CONSTANTS.SHARED_SECRET_BYTES, 'Shared secret size mismatch');
  });

  it('should produce a fresh (random) encapsulation each call', () => {
    const keys = HqcWrapper.keypairFromSeed(validSeed);
    const a = HqcWrapper.encapsulate(keys.pk);
    const b = HqcWrapper.encapsulate(keys.pk);
    assert.notDeepStrictEqual(a.ct, b.ct, 'Ciphertexts should differ (fresh entropy)');
    assert.notDeepStrictEqual(a.ss, b.ss, 'Shared secrets should differ (fresh entropy)');
  });

  it('should perform a full correctness cycle (Keygen -> Encaps -> Decaps)', () => {
    const keys = HqcWrapper.keypairFromSeed(validSeed);
    const { ct, ss } = HqcWrapper.encapsulate(keys.pk);
    const ss2 = HqcWrapper.decapsulate(keys.sk, ct);
    assert.deepStrictEqual(ss2, ss, 'Decapsulated secret must match the encapsulated secret');
  });

  it('should not reveal the sender secret for a corrupted ciphertext (CCA2)', () => {
    const keys = HqcWrapper.keypairFromSeed(validSeed);
    const { ct, ss } = HqcWrapper.encapsulate(keys.pk);
    const bad = Buffer.from(ct);
    bad[0] = (bad[0] ?? 0) ^ 0xff; // flip a bit
    const ssBad = HqcWrapper.decapsulate(keys.sk, bad); // constant-time: returns pseudo-random ss, never throws
    assert.notDeepStrictEqual(ssBad, ss, 'A tampered ciphertext must not decapsulate to the real secret');
  });

  // ==========================================
  // 4. ERROR HANDLING TESTS
  // ==========================================

  it('should throw error if Seed is wrong size', () => {
    assert.throws(() => HqcWrapper.keypairFromSeed(Buffer.alloc(10)), /Seed must be 32 bytes/);
  });

  it('should throw error if PK is wrong size during encapsulation', () => {
    assert.throws(() => HqcWrapper.encapsulate(Buffer.alloc(100)), /Invalid PK length/);
  });

  it('should throw error if Ciphertext is wrong size during decapsulation', () => {
    const keys = HqcWrapper.keypairFromSeed(validSeed);
    assert.throws(() => HqcWrapper.decapsulate(keys.sk, Buffer.alloc(64)), /Invalid Ciphertext length/);
  });

  // ==========================================
  // 5. STRESS / LEAK TEST (Optional)
  // ==========================================

  test('Memory Leak Check (Run 1000 iterations)', () => {
    const iterations = 1000;
    const startMemory = process.memoryUsage().rss;
    const keys = HqcWrapper.keypairFromSeed(validSeed);
    for (let i = 0; i < iterations; i++) {
      const { ct } = HqcWrapper.encapsulate(keys.pk);
      HqcWrapper.decapsulate(keys.sk, ct);
    }
    const diffMB = (process.memoryUsage().rss - startMemory) / 1024 / 1024;
    console.log(`[INFO] Memory diff after ${iterations} runs: ${diffMB.toFixed(2)} MB`);
    assert.ok(diffMB < 500, 'Potential memory leak detected');
  });

});
