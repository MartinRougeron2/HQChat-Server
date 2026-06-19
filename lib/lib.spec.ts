import { describe, it, test } from 'node:test';
import assert from 'node:assert';
import { HqcWrapper, HQC_CONSTANTS } from './hqc';
import * as crypto from "crypto";

describe('HQC Crypto Wrapper Tests', () => {

  // ==========================================
  // 1. CONSTANTS & SETUP
  // ==========================================
  
  // Create reusable valid inputs
  const validSeed = crypto.randomBytes(HQC_CONSTANTS.SEED_BYTES);
  const validMessage = crypto.randomBytes(HQC_CONSTANTS.PARAM_K);
  const validTheta = crypto.randomBytes(HQC_CONSTANTS.SEED_BYTES);

  console.log(`\n[INFO] Testing with LibHQC`);
  console.log(`[INFO] PK Size: ${HQC_CONSTANTS.PUBLIC_KEY_BYTES}`);
  console.log(`[INFO] SK Size: ${HQC_CONSTANTS.SECRET_KEY_BYTES}`);
  console.log(`[INFO] CT Size: ${HQC_CONSTANTS.CIPHERTEXT_SIZE_BYTES}\n`);

  // ==========================================
  // 2. KEY GENERATION TESTS
  // ==========================================

  it('should generate a keypair with correct buffer sizes', () => {
    const keys = HqcWrapper.generateKeypair(validSeed);

    assert.ok(keys.pk, 'Public Key should exist');
    assert.ok(keys.sk, 'Secret Key should exist');
    
    // Check lengths
    assert.strictEqual(keys.pk.length, HQC_CONSTANTS.PUBLIC_KEY_BYTES, 'PK length mismatch');
    assert.strictEqual(keys.sk.length, HQC_CONSTANTS.SECRET_KEY_BYTES, 'SK length mismatch');
  });

  it('should be deterministic (Same Seed = Same Keys)', () => {
    const seed = Buffer.alloc(HQC_CONSTANTS.SEED_BYTES, 0xAA); // Fixed seed

    const keys1 = HqcWrapper.generateKeypair(seed);
    const keys2 = HqcWrapper.generateKeypair(seed);

    assert.deepStrictEqual(keys1.pk, keys2.pk, 'Public Keys must be identical for same seed');
    assert.deepStrictEqual(keys1.sk, keys2.sk, 'Secret Keys must be identical for same seed');
  });

  it('should produce different keys for different seeds', () => {
    const seed1 = Buffer.alloc(HQC_CONSTANTS.SEED_BYTES, 1);
    const seed2 = Buffer.alloc(HQC_CONSTANTS.SEED_BYTES, 2);

    const keys1 = HqcWrapper.generateKeypair(seed1);
    const keys2 = HqcWrapper.generateKeypair(seed2);

    assert.notDeepStrictEqual(keys1.pk, keys2.pk, 'PKs should differ');
    assert.notDeepStrictEqual(keys1.sk, keys2.sk, 'SKs should differ');
  });

  // ==========================================
  // 3. ENCRYPTION TESTS
  // ==========================================

  it('should encrypt a message into a valid ciphertext blob', () => {
    const keys = HqcWrapper.generateKeypair(validSeed);
    
    const ciphertext = HqcWrapper.encrypt(
      keys.pk, 
      validMessage, 
      validTheta
    );

    assert.ok(ciphertext, 'Ciphertext should be returned');
    assert.strictEqual(ciphertext.length, HQC_CONSTANTS.CIPHERTEXT_SIZE_BYTES, 'Ciphertext size mismatch');
  });

  it('should be deterministic (Same Inputs = Same Ciphertext)', () => {
    const keys = HqcWrapper.generateKeypair(validSeed);
    
    // Encrypt twice with identical parameters
    const ct1 = HqcWrapper.encrypt(keys.pk, validMessage, validTheta);
    const ct2 = HqcWrapper.encrypt(keys.pk, validMessage, validTheta);

    assert.deepStrictEqual(ct1, ct2, 'Encryption must be deterministic given fixed theta');
  });

  it('should perform a full correctness cycle (Keygen -> Encrypt -> Decrypt)', () => {
    // 1. Generate Keypair
    const keys = HqcWrapper.generateKeypair(validSeed);
    
    // 2. Encrypt
    const ciphertext = HqcWrapper.encrypt(keys.pk, validMessage, validTheta);
    
    // 3. Decrypt
    const decryptedMessage = HqcWrapper.decrypt(keys.sk, ciphertext);

    // 4. Verify
    assert.deepStrictEqual(
      decryptedMessage, 
      validMessage, 
      'Decrypted message must strictly match the original plaintext'
    );
  });

  // ==========================================
  // 4. ERROR HANDLING TESTS
  // ==========================================

  it('should throw error if Seed is wrong size', () => {
    const badSeed = Buffer.alloc(10); // Too small
    assert.throws(() => {
      HqcWrapper.generateKeypair(badSeed);
    }, /Seed must be 32 bytes/);
  });

  it('should throw error if PK is wrong size during encryption', () => {
    const badPK = Buffer.alloc(100); 
    assert.throws(() => {
      HqcWrapper.encrypt(badPK, validMessage, validTheta);
    }, /Invalid PK length/);
  });

  it('should throw error if Message (Session Key) is wrong size', () => {
    const badMsg = Buffer.alloc(64); // HQC-128 usually takes ~24 bytes msg
    const keys = HqcWrapper.generateKeypair(validSeed);
    
    assert.throws(() => {
      HqcWrapper.encrypt(keys.pk, badMsg, validTheta);
    }, /Invalid Message length/);
  });

  // ==========================================
  // 5. STRESS / LEAK TEST (Optional)
  // ==========================================
  
  test('Memory Leak Check (Run 1000 iterations)', () => {
    // This doesn't strictly "fail" on leaks, but ensures stability
    const iterations = 1000;
    const startMemory = process.memoryUsage().rss;

    for (let i = 0; i < iterations; i++) {
      const keys = HqcWrapper.generateKeypair(validSeed);
      HqcWrapper.encrypt(keys.pk, validMessage, validTheta);
    }

    const endMemory = process.memoryUsage().rss;
    const diffMB = (endMemory - startMemory) / 1024 / 1024;
    
    console.log(`[INFO] Memory diff after ${iterations} runs: ${diffMB.toFixed(2)} MB`);
    
    // Rough check: If it grew by > 500MB, we likely have a massive leak
    assert.ok(diffMB < 500, 'Potential memory leak detected');
  });

});