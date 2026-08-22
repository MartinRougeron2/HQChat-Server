import { logger } from './logger';
import koffi, { load, IKoffiLib } from 'koffi';

// ==========================================
// HQC IND-CCA2 KEM binding (SECURITY_AUDIT §KM-1)
// ==========================================
// The bare IND-CPA PKE (encrypt-a-seed) is gone. This binds the three native KEM
// wrappers from implement/lib/src/low_wrap.c:
//   • hqc_kem_keypair_wrap(seed) -> (pk, sk)   — deterministic from a 32-byte seed
//   • hqc_kem_enc_wrap(pk)       -> (ct, ss)   — encapsulate, fresh OS entropy
//   • hqc_kem_dec_wrap(ct, sk)   -> ss          — decapsulate (constant-time)
// The shared secret `ss` is 32 bytes; callers stretch it with HKDF + a per-use
// `info` (domain separation, §KM-2). KM-3 hygiene: the wrappers write into
// CALLER-allocated Buffers and return an int status, so there is no malloc on the
// native side and no cross-module `free()` here (the old libc `free` binding is
// removed).

export const HQC_CONSTANTS = {
  SEED_BYTES: 32,
  PUBLIC_KEY_BYTES: 7237,
  SECRET_KEY_BYTES: 7333,
  CIPHERTEXT_BYTES: 14421, // CRYPTO_CIPHERTEXTBYTES (HQC-256 KEM)
  SHARED_SECRET_BYTES: 32, // CRYPTO_BYTES
};

// ==========================================
// Load the native library
// ==========================================
let libHQC: IKoffiLib;
try {
  libHQC = load('./lib/libhqc_x86.so');
} catch (e) {
  logger.error('Could not load hqc lib.', e);
  throw e;
}

// Output buffers are pre-allocated in JS and passed as koffi.out pointers; koffi
// copies the native-written bytes back after the call. `seed`/`pk`/`ct`/`sk`
// inputs are plain `uint8*`.
const outU8 = koffi.out(koffi.pointer('uint8'));

// int hqc_kem_keypair_wrap(const uint8_t seed[32], uint8_t pk[7237], uint8_t sk[7333]);
const hqc_kem_keypair_wrap = libHQC.func('hqc_kem_keypair_wrap', 'int', ['uint8*', outU8, outU8]);
// int hqc_kem_enc_wrap(uint8_t ct[14421], uint8_t ss[32], const uint8_t pk[7237]);
const hqc_kem_enc_wrap = libHQC.func('hqc_kem_enc_wrap', 'int', [outU8, outU8, 'uint8*']);
// int hqc_kem_dec_wrap(uint8_t ss[32], const uint8_t ct[14421], const uint8_t sk[7333]);
const hqc_kem_dec_wrap = libHQC.func('hqc_kem_dec_wrap', 'int', [outU8, 'uint8*', 'uint8*']);

// ==========================================
// Wrapper class
// ==========================================
export class HqcWrapper {
  /**
   * Deterministic KEM keypair from a 32-byte identity seed. The public key is
   * byte-identical to the pre-KEM build for the same seed (stable identity).
   */
  static keypairFromSeed(seed: Buffer | Uint8Array | number[]): { pk: Buffer; sk: Buffer } {
    const seedBuf = Buffer.from(seed as any);
    if (seedBuf.length !== HQC_CONSTANTS.SEED_BYTES) {
      throw new Error(`Seed must be ${HQC_CONSTANTS.SEED_BYTES} bytes`);
    }
    const pk = Buffer.alloc(HQC_CONSTANTS.PUBLIC_KEY_BYTES);
    const sk = Buffer.alloc(HQC_CONSTANTS.SECRET_KEY_BYTES);
    const rc = hqc_kem_keypair_wrap(seedBuf, pk, sk);
    if (rc !== 0) throw new Error(`HQC keypair failed (rc=${rc})`);
    return { pk, sk };
  }

  /**
   * Encapsulate to a public key. Returns the KEM ciphertext and the 32-byte
   * shared secret. Fresh, unpredictable per call (native draws OS entropy).
   */
  static encapsulate(pk: Buffer): { ct: Buffer; ss: Buffer } {
    if (pk.length !== HQC_CONSTANTS.PUBLIC_KEY_BYTES) throw new Error('Invalid PK length');
    const ct = Buffer.alloc(HQC_CONSTANTS.CIPHERTEXT_BYTES);
    const ss = Buffer.alloc(HQC_CONSTANTS.SHARED_SECRET_BYTES);
    const rc = hqc_kem_enc_wrap(ct, ss, pk);
    if (rc !== 0) throw new Error(`HQC encapsulate failed (rc=${rc})`);
    return { ct, ss };
  }

  /**
   * Decapsulate a KEM ciphertext with the secret key. Returns the 32-byte shared
   * secret. Constant-time: a malformed/attacker-chosen ciphertext yields a
   * pseudo-random secret (which won't match the sender's), never an error — so
   * there is no decryption oracle to probe.
   */
  static decapsulate(sk: Buffer, ct: Buffer): Buffer {
    if (sk.length !== HQC_CONSTANTS.SECRET_KEY_BYTES) throw new Error('Invalid SK length');
    if (ct.length !== HQC_CONSTANTS.CIPHERTEXT_BYTES) throw new Error('Invalid Ciphertext length');
    const ss = Buffer.alloc(HQC_CONSTANTS.SHARED_SECRET_BYTES);
    const rc = hqc_kem_dec_wrap(ss, ct, sk);
    if (rc !== 0) throw new Error(`HQC decapsulate failed (rc=${rc})`);
    return ss;
  }
}
