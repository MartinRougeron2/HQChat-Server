/**
 * The v2 client↔client wire format, and the canonical header encoding that binds
 * it to the ciphertext.
 *
 * Replaces the v1 envelope (`{type, sender, payload, messageId, epoch, idx,
 * isReply}`) and its three frame kinds. `aes` and `key_rotate` are gone: the
 * handshake is a single `init` frame that already carries a real message, so
 * first contact costs one publish instead of a live round trip.
 *
 * ── Why the header is bound as AAD ───────────────────────────────────────────
 * The header is what SELECTS the key — `cid` picks the chain, `n` picks the
 * position, `rk`/`kemCt` advance the ratchet. So it is necessarily read before
 * the payload it selects for can authenticate it. In v1 those fields (`epoch`,
 * `idx`, `sender`) rode entirely outside the AEAD, which is the mechanism behind
 * TM-1: a forged `key_rotate` desynchronised a conversation permanently, and
 * nothing in the ciphertext could contradict it.
 *
 * Binding the header as additional authenticated data closes that. A tampered
 * field does not produce a wrong message, it produces no message: the tag check
 * fails and the frame is dropped.
 *
 * ── Why not JSON as the AAD ──────────────────────────────────────────────────
 * Because the two implementations would have to agree on it byte-for-byte, and
 * JSON gives them far too many ways to differ: key order, whether `null` is
 * emitted or the key omitted, integer vs float formatting, unicode escaping,
 * whitespace. Any one of those silently breaks decryption between a Swift client
 * and the TS bot — or worse, agrees on some inputs and not others.
 *
 * So the AAD is a length-prefixed encoding of a FIXED field order. Every field
 * is written as `<byte length in decimal>:<bytes>`, which cannot be confused by
 * a value that happens to contain a delimiter (a netstring, essentially). An
 * absent field is the empty string, which is distinct from a field containing
 * "" only in that both encode as `0:` — deliberate, since no optional field here
 * is ever meaningfully empty-but-present.
 */

import { keyMatchesId, PEER_ID_RE } from "./identity";

/** Frame kinds. `init` opens a session; `msg` is everything after. */
export type EnvelopeKind = "init" | "msg";

export interface EnvelopeV2 {
  /** Protocol version. Refuse anything else rather than guess. */
  v: 2;
  t: EnvelopeKind;
  /**
   * The sender's CLIENT ID — `sha256(lowercase-hex(pk))`, exactly 64 hex
   * characters. Not a username: usernames are mutable and must never decide
   * which key decrypts a message.
   *
   * This was the public key itself, 14474 characters, on every frame. The id
   * names the same thing in 64 — and, because it is a commitment to the key,
   * it names it in a way a receiver can CHECK rather than merely look up.
   */
  sender: string;
  msgId: string;

  /** Chain selector — `chainId` of the sender's current ratchet key. */
  cid: string;
  n: number;
  pn: number;

  /** Ratchet step (base64). Both present or both absent. */
  rk?: string;
  kemCt?: string;

  /** `init` only (base64): the three handshake encapsulations. */
  ctId?: string;
  ctMt?: string;
  ctOt?: string | null;
  /** `init` only: which one-time prekey `ctOt` was encapsulated to. */
  otId?: number | null;

  /**
   * `init` only: the initiator's full public key, hex.
   *
   * The responder needs it — to encapsulate its own ratchet steps back — and an
   * `init` is by definition the frame from someone this device may never have
   * fetched a key for. Carrying it here saves a round trip on first contact,
   * which is the whole reason `init` also carries a real message.
   *
   * It is NOT trusted on arrival. `parseEnvelope` refuses any frame where
   * `peerId(senderPk) !== sender`, so this field cannot introduce a key the
   * `sender` id does not already commit to. That is also why it does not appear
   * in the canonical header: `sender` is bound as AAD, and `senderPk` is bound
   * to `sender` by arithmetic — adding it to FIELDS would bind it twice and
   * break every existing vector for nothing.
   */
  senderPk?: string;

  /** AES-GCM `[IV 12][tag 16][ct]`, base64. */
  payload: string;
}

/**
 * Field order for the canonical encoding. Changing it is a wire break.
 *
 * DELIBERATELY unchanged by the move to client ids: the shape and the order are
 * the same twelve fields, and only the VALUE of `sender` shrank. `senderPk` is
 * absent on purpose — see the field's own comment.
 */
const FIELDS = [
  "t",
  "sender",
  "msgId",
  "cid",
  "n",
  "pn",
  "rk",
  "kemCt",
  "ctId",
  "ctMt",
  "ctOt",
  "otId",
] as const;

const PREFIX = "hqchat/v2/aad\n";

/**
 * The bytes both peers must bind as AAD for this frame.
 *
 * `payload` is deliberately NOT included — it is the thing being authenticated,
 * and GCM already covers it.
 */
export function canonicalHeader(env: EnvelopeV2): Buffer {
  const parts: string[] = [PREFIX];
  for (const field of FIELDS) {
    const raw = env[field as keyof EnvelopeV2];
    const value =
      raw === undefined || raw === null
        ? ""
        : typeof raw === "number"
          ? String(raw)
          : String(raw);
    // Byte length, not character length: a multi-byte msgId would otherwise
    // encode a prefix the other side reads differently.
    parts.push(`${Buffer.byteLength(value, "utf8")}:${value}`);
  }
  return Buffer.from(parts.join(""), "utf8");
}

/** Reject anything that is not a well-formed v2 envelope. */
export function parseEnvelope(raw: unknown): EnvelopeV2 | null {
  if (typeof raw !== "object" || raw === null) return null;
  const e = raw as Record<string, unknown>;

  if (e.v !== 2) return null;
  if (e.t !== "init" && e.t !== "msg") return null;
  // Exactly 64 lowercase hex. This was `1–20000 hex`, which admitted anything
  // from a nibble to a public key — a bound wide enough that it could not
  // reject a wrong-shaped identifier, which is exactly what a peer sending the
  // old form now is.
  if (!isPeerIdValue(e.sender)) return null;
  if (typeof e.msgId !== "string" || e.msgId.length === 0 || e.msgId.length > 128) return null;
  if (typeof e.cid !== "string" || !/^[0-9a-f]{32}$/.test(e.cid)) return null;
  if (!isIndex(e.n) || !isIndex(e.pn)) return null;
  if (typeof e.payload !== "string" || e.payload.length === 0) return null;

  // A step needs both halves: a ratchet key with no ciphertext is not something
  // a receiver can act on, and a ciphertext with no key names no chain.
  //
  // On an `init` this pairing does NOT apply, and requiring it here was a
  // cross-implementation divergence. An init has no peer ratchet key to
  // encapsulate against — its root comes from ctId/ctMt/ctOt — so `kemCt` is
  // meaningless on one, and the bot omits it (bot.ts builds the init branch
  // from `initHeader` alone). Swift accepts that and says so in a test:
  // "an init WITHOUT kemCt is accepted — the bot omits a field an init has no
  // use for" (apps/apple/tests/EnvelopeTests.swift). This parser rejected it,
  // so a TypeScript client could not read an init that a TypeScript client had
  // written — which is why every e2e conversation test failed with the frame
  // dropped at parse, and why no test caught it: nothing here had ever parsed a
  // frame this repo produced.
  const hasRk = e.rk !== undefined && e.rk !== null;
  const hasCt = e.kemCt !== undefined && e.kemCt !== null;
  if (e.t !== "init" && hasRk !== hasCt) return null;
  if (hasRk && !isB64(e.rk)) return null;
  if (hasCt && !isB64(e.kemCt)) return null;

  if (e.t === "init") {
    // The identity and medium-term encapsulations are what make an init frame
    // an init frame; without them there is no root to derive.
    if (!isB64(e.ctId) || !isB64(e.ctMt)) return null;
    // An `init` must carry the initiator's key, and the key must be the one
    // `sender` names. This is the check that makes the id a commitment rather
    // than a label: a substituted key does not produce a wrong session, it
    // produces no frame at all. A responder that skipped it would be pinning
    // whatever the network handed it, which is the MITM this design closes.
    if (!isFullKeyHex(e.senderPk)) return null;
    if (!keyMatchesId(e.senderPk, e.sender)) return null;
    if (!hasRk) return null; // an init always advertises the initiator's chain
    const hasOt = e.ctOt !== undefined && e.ctOt !== null;
    if (hasOt && !isB64(e.ctOt)) return null;
    // `otId` says which one-time secret to open `ctOt` with, so the two travel
    // together or not at all.
    const hasOtId = e.otId !== undefined && e.otId !== null;
    if (hasOt !== hasOtId) return null;
    if (hasOtId && !isIndex(e.otId)) return null;
  }

  return raw as EnvelopeV2;
}

/** A client id: 64 lowercase hex characters, and nothing else. Uppercase is
 *  refused rather than normalised — it would encode to different AAD bytes than
 *  the lowercase the other side produces. */
function isPeerIdValue(v: unknown): v is string {
  return typeof v === "string" && PEER_ID_RE.test(v);
}

/** A full HQC-256 public key in lowercase hex. The length is a constant of the
 *  scheme (7237 bytes), so it is checked exactly: a key of any other size
 *  cannot be one this protocol uses, and `keyMatchesId` would reject it a
 *  moment later anyway — but for a much less obvious reason. */
function isFullKeyHex(v: unknown): v is string {
  return typeof v === "string" && v.length === 7237 * 2 && /^[0-9a-f]+$/.test(v);
}

function isB64(v: unknown): v is string {
  return typeof v === "string" && v.length > 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(v);
}

/** A non-negative safe integer — the only shape `n`, `pn` and `otId` may take. */
function isIndex(v: unknown): v is number {
  return typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= Number.MAX_SAFE_INTEGER;
}
