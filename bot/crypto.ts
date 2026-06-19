import * as crypto from "crypto";
import { HqcWrapper, HQC_CONSTANTS } from "../lib/hqc";

const { PARAM_K, SEED_BYTES, CIPHERTEXT_SIZE_BYTES } = HQC_CONSTANTS;

// ── HQC (matches the Swift HQCService chunking) ──────────────────────────────
// Encrypt: split into 24-byte blocks, zero-pad the last, one HQC block each,
// concatenated. Decrypt: per-block, concat, trim trailing zeros.

export function hqcEncrypt(pk: Buffer, message: Buffer): Buffer {
  const blocks: Buffer[] = [];
  for (let off = 0; off < message.length; off += PARAM_K) {
    let chunk = message.subarray(off, off + PARAM_K);
    if (chunk.length < PARAM_K) {
      const padded = Buffer.alloc(PARAM_K);
      chunk.copy(padded);
      chunk = padded;
    }
    const theta = crypto.randomBytes(SEED_BYTES);
    blocks.push(HqcWrapper.encrypt(pk, Buffer.from(chunk), theta));
  }
  return Buffer.concat(blocks);
}

export function hqcDecrypt(sk: Buffer, ciphertext: Buffer, trim = true): Buffer {
  if (ciphertext.length % CIPHERTEXT_SIZE_BYTES !== 0) {
    throw new Error("HQC ciphertext size not a multiple of block size");
  }
  const chunks: Buffer[] = [];
  for (let off = 0; off < ciphertext.length; off += CIPHERTEXT_SIZE_BYTES) {
    const block = ciphertext.subarray(off, off + CIPHERTEXT_SIZE_BYTES);
    chunks.push(HqcWrapper.decrypt(sk, Buffer.from(block)));
  }
  let out = Buffer.concat(chunks);
  if (trim) {
    let end = out.length;
    while (end > 0 && out[end - 1] === 0) end--;
    out = out.subarray(0, end);
  }
  return out;
}

// ── AES-256-GCM (matches Swift AESService: [IV 12][tag 16][ct], base64) ───────

export function aesEncrypt(plaintext: string, key: Buffer): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]).toString("base64");
}

export function aesDecrypt(b64: string, key: Buffer): string {
  const data = Buffer.from(b64, "base64");
  const iv = data.subarray(0, 12);
  const tag = data.subarray(12, 28);
  const ct = data.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
}

// ── Shared key (HKDF-SHA256 of sorted seeds, salt="salt", info="info") ────────

export function deriveSharedKey(seedA: Buffer, seedB: Buffer): Buffer {
  const [s1, s2] = Buffer.compare(seedA, seedB) <= 0 ? [seedA, seedB] : [seedB, seedA];
  const combined = Buffer.concat([s1, s2]);
  const dk = crypto.hkdfSync(
    "sha256",
    combined,
    Buffer.from("salt", "utf8"),
    Buffer.from("info", "utf8"),
    32
  );
  return Buffer.from(dk);
}

/** A 24-byte seed whose last byte is non-zero (so it survives null-trimming). */
export function freshSeed(): Buffer {
  let seed: Buffer;
  do {
    seed = crypto.randomBytes(PARAM_K);
  } while (seed[PARAM_K - 1] === 0);
  return seed;
}
