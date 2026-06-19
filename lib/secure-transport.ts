/**
 * Client↔server transport encryption ("home protocol").
 *
 * Every action sent between a client and the server — the message *type*, the
 * username to add, routing fields, everything — is encrypted with a
 * per-connection AES-256-GCM key once the session is established. This is a
 * separate layer from the end-to-end client↔client content encryption: it hides
 * the control plane (instructions/metadata) from anyone who breaks TLS, while
 * the inner client-to-client payload stays sealed end-to-end.
 *
 * Key establishment is a dedicated HQC key exchange (separate from the auth
 * nonce): after auth, the server generates a fresh 24-byte seed, HQC-encrypts it
 * to the client's public key, and both sides derive
 *   sessionKey = HKDF-SHA256(seed, salt="salt", info="session", 32).
 *
 * Wire format once the key exists: `{"enc":"<base64 AES-GCM>"}` where the
 * AES-GCM blob is `[IV 12][tag 16][ciphertext]` — identical to the Swift
 * AESService / bot crypto, so client, server, and bot interoperate.
 */
import * as crypto from "crypto";

// HQC params (mirror HQC_CONSTANTS in ./hqc). Hardcoded here so this module can
// be imported without loading the native HQC lib — only hqcEncryptSeed needs it,
// and it lazy-loads it at call time. Lets the AES/HKDF/envelope code (and its
// tests) run on platforms without the Linux .so.
const PARAM_K = 24;
const SEED_BYTES = 32;

// AES-256-GCM, [IV 12][tag 16][ct], base64 — matches Swift AESService.
export function aesEncrypt(plaintext: string, key: Buffer): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]).toString("base64");
}

export function aesDecrypt(b64: string, key: Buffer): string {
  const d = Buffer.from(b64, "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, d.subarray(0, 12));
  decipher.setAuthTag(d.subarray(12, 28));
  return Buffer.concat([decipher.update(d.subarray(28)), decipher.final()]).toString("utf8");
}

/** Derive a directional transport key from the session seed. `dir` is "c2s"
 *  (client→server) or "s2c" (server→client) — separate keys per direction avoid
 *  any cross-direction GCM nonce-collision risk from sharing one key. */
function deriveOne(seed: Buffer, dir: "c2s" | "s2c"): Buffer {
  return Buffer.from(
    crypto.hkdfSync(
      "sha256",
      seed,
      Buffer.from("salt", "utf8"),
      Buffer.from("session-" + dir, "utf8"),
      32
    )
  );
}

/** Both per-connection transport keys derived from the exchanged session seed.
 *  c2s: client encrypts / server decrypts. s2c: server encrypts / client decrypts. */
export function deriveSessionKeys(seed: Buffer): { c2s: Buffer; s2c: Buffer } {
  return { c2s: deriveOne(seed, "c2s"), s2c: deriveOne(seed, "s2c") };
}

/** A 24-byte session seed whose last byte is non-zero, so the HQC null-trim on
 *  the receiving side leaves it intact. */
export function freshSessionSeed(): Buffer {
  let s: Buffer;
  do {
    s = crypto.randomBytes(PARAM_K);
  } while (s[PARAM_K - 1] === 0);
  return s;
}

/** HQC-encrypt a 24-byte session seed to a public key (single block). Lazy-loads
 *  the native HQC lib so this module is importable where the lib is absent. */
export function hqcEncryptSeed(pk: Buffer, seed: Buffer): Buffer {
  if (seed.length !== PARAM_K) throw new Error("session seed must be PARAM_K bytes");
  const { HqcWrapper } = require("./hqc") as typeof import("./hqc");
  const theta = crypto.randomBytes(SEED_BYTES);
  return HqcWrapper.encrypt(pk, Buffer.from(seed), theta);
}

/** Encrypt an already-serialized JSON string into a transport envelope. When no
 *  key is present yet (the auth handshake), the string passes through plaintext. */
export function wrapString(json: string, key?: Buffer): string {
  return key ? JSON.stringify({ enc: aesEncrypt(json, key) }) : json;
}

/** Parse an incoming frame, decrypting the envelope if present. Throws if an
 *  encrypted frame arrives before the session key is established. */
export function unwrap(raw: string, key?: Buffer): any {
  const outer = JSON.parse(raw);
  if (outer && typeof outer.enc === "string") {
    if (!key) throw new Error("encrypted frame received before session key");
    return JSON.parse(aesDecrypt(outer.enc, key));
  }
  return outer;
}
