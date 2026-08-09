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
 * Key establishment is a dedicated HQC KEM encapsulation (SECURITY_AUDIT §KM-1,
 * separate from the auth handshake): after auth, the server encapsulates to the
 * client's public key → (ct, ss), sends the KEM ciphertext `ct`, the client
 * decapsulates it to recover the same 32-byte shared secret `ss`, and both sides
 * derive per-direction transport keys
 *   sessionKey_dir = HKDF-SHA256(ss, salt="salt", info="session-"+dir, 32).
 * The "session-c2s"/"session-s2c" info values are the transport domain (§KM-2).
 *
 * Wire format once the key exists: `{"enc":"<base64 AES-GCM>"}` where the
 * AES-GCM blob is `[IV 12][tag 16][ciphertext]` — identical to the Swift
 * AESService / bot crypto, so client, server, and bot interoperate.
 */
import * as crypto from "crypto";

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

/** Auth proof from a KEM shared secret (§KM-1/§KM-2). One-way HKDF with the
 *  "auth" domain: proves possession of `ss` without revealing it, and can't be
 *  replayed as the transport ("session-*") or channel key. The server stores this
 *  as the expected value; the client returns the identical value computed from
 *  its decapsulated `ss`. Shared here so server and client can't drift. */
export function authProof(ss: Buffer): Buffer {
  return Buffer.from(
    crypto.hkdfSync("sha256", ss, Buffer.from("salt", "utf8"), Buffer.from("auth", "utf8"), 32)
  );
}

/** Encapsulate a fresh transport shared secret to the client's public key.
 *  Returns the KEM ciphertext `ct` to send to the client and the 32-byte shared
 *  secret `ss` to derive the session keys from. Lazy-loads the native HQC lib so
 *  this module is importable where the lib is absent (AES/HKDF tests). */
export function encapsulateSession(pk: Buffer): { ct: Buffer; ss: Buffer } {
  const { HqcWrapper } = require("./hqc") as typeof import("./hqc");
  return HqcWrapper.encapsulate(pk);
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
