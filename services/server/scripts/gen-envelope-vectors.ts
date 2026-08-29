// Regenerates test/helpers/envelope-vectors.json.
//
//   npx tsx scripts/gen-envelope-vectors.ts > test/helpers/envelope-vectors.json
//
// The canonical header is the one place in the protocol where a single byte of
// difference between the Swift client and the TS bot means NOTHING decrypts —
// and it fails as a tag mismatch, which looks identical to a wrong key. So the
// exact bytes are pinned here and asserted from both sides.

import { canonicalHeader, EnvelopeV2 } from "../lib/envelope";
import { peerId } from "../lib/identity";
import * as crypto from "crypto";

const b64 = (s: string) => Buffer.from(s, "utf8").toString("base64");

/** HQC-256 public key size (lib/hqc.ts). */
const PUBLIC_KEY_BYTES = 7237;

/**
 * A deterministic key of the TRUE size, and the id that names it.
 *
 * The vectors used to carry `sender: "a1b2c3d4e5f6"` — twelve characters, when
 * the field held a 14474-character public key. It fit the old `1–20000 hex`
 * bound, so the suite passed while asserting a shape no client ever sends. The
 * `sender` is a fixed-width id now, so it is generated the same way the
 * identity vectors are, and `init` carries the real key beside it.
 */
function deterministicKey(label: string): string {
  const out: Buffer[] = [];
  let block = crypto.createHash("sha256").update(label, "utf8").digest();
  while (Buffer.concat(out).length < PUBLIC_KEY_BYTES) {
    out.push(block);
    block = crypto.createHash("sha256").update(block).digest();
  }
  return Buffer.concat(out).subarray(0, PUBLIC_KEY_BYTES).toString("hex");
}

const SENDER_PK = deterministicKey("hqchat/envelope-vector/sender");
const SENDER = peerId(SENDER_PK);

const msg: EnvelopeV2 = {
  v: 2,
  t: "msg",
  sender: SENDER,
  msgId: "01HQZX9K2M4N6P8R",
  cid: "0123456789abcdef0123456789abcdef",
  n: 7,
  pn: 3,
  payload: b64("ciphertext-goes-here"),
};

const stepping: EnvelopeV2 = {
  ...msg,
  msgId: "01HQZX9K2M4N6P8S",
  n: 0,
  pn: 12,
  rk: b64("ratchet-public-key"),
  kemCt: b64("kem-ciphertext"),
};

const init: EnvelopeV2 = {
  v: 2,
  t: "init",
  sender: SENDER,
  // The initiator's full public key. It rides on `init` alone, so the responder
  // learns it without a fetch — and it is REFUSED unless peerId(senderPk)
  // equals `sender`, which is what makes it safe to pin from a frame.
  senderPk: SENDER_PK,
  msgId: "01HQZX9K2M4N6P8T",
  cid: "fedcba9876543210fedcba9876543210",
  n: 0,
  pn: 0,
  rk: b64("initiator-ratchet-key"),
  kemCt: b64("kem-ciphertext"),
  ctId: b64("identity-encapsulation"),
  ctMt: b64("medium-encapsulation"),
  ctOt: b64("one-time-encapsulation"),
  otId: 5,
  payload: b64("first-message"),
};

// The exhausted-pool path: no one-time key, so both ctOt and otId are absent.
// Their absence must encode as empty fields, not as a shorter header.
const initNoOneTime: EnvelopeV2 = {
  ...init,
  msgId: "01HQZX9K2M4N6P8U",
  ctOt: null,
  otId: null,
};

// A multi-byte msgId: the length prefix is in BYTES, so a character count would
// desynchronise the two implementations here and nowhere else.
const unicode: EnvelopeV2 = { ...msg, msgId: "id-café-🔒", n: 1, pn: 0 };

const cases = { msg, stepping, init, initNoOneTime, unicode };

console.log(JSON.stringify({
  _comment:
    "Canonical AAD encoding for the v2 envelope. Asserted by BOTH " +
    "services/server/test/envelope.test.ts and apps/apple/tests/EnvelopeTests.swift, " +
    "which READ this file. `aad` is the exact byte string both sides must bind; " +
    "`aadHex` is the same bytes in hex, so a whitespace or encoding difference " +
    "cannot hide in a string comparison. `sender` is a client id (64 hex); an " +
    "`init` frame also carries the initiator's full public key as `senderPk`, " +
    "which both sides verify against `sender` before using. `senderPk` is " +
    "deliberately NOT part of the canonical header — see lib/envelope.ts.",
  version: 2,
  cases: Object.fromEntries(
    Object.entries(cases).map(([name, env]) => {
      const aad = canonicalHeader(env);
      return [name, {
        envelope: env,
        aad: aad.toString("utf8"),
        aadHex: aad.toString("hex"),
        aadBytes: aad.length,
      }];
    })
  ),
}, null, 2));
