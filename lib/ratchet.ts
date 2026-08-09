import * as crypto from "crypto";

/**
 * Double-ratchet-style key rotation core — pure, dependency-free, and mirrored
 * byte-for-byte by the Swift `RatchetService`. Kept out of the native-HQC path
 * so it unit-tests anywhere (like `crypto-utils.ts`).
 *
 * Two tiers ride the existing symmetric mutual-seed handshake:
 *   • Tier 2 — per-message symmetric ratchet (text): each message key is a KDF
 *     step off a per-direction chain, deleted after use → forward secrecy.
 *   • Tier 1 — epoch re-handshake: a fresh mutual seed pair reseeds the chains
 *     and bumps the epoch → post-compromise security.
 *
 * All derivations are HKDF-SHA256 with salt="salt" (matching the rest of the
 * codebase). Epoch 0 is NOT handled here — it stays on the legacy static
 * `deriveSharedKey` path for backward compatibility. This module governs
 * epoch ≥ 1 only.
 */

const SALT = Buffer.from("salt", "utf8");

// --- Shared operational policy (KM-4) --------------------------------------
// These two constants are part of the cross-impl contract and MUST stay equal
// to their Swift twins in `RatchetService.swift` (`rotateAfterMessages`,
// `maxSkipped`). They are NOT pinned by `ratchet-vectors.json` (which asserts
// KDF derivations only), so drift here is silent: a smaller `maxSkipped` on one
// side drops skipped keys the peer still serves → undecryptable messages after a
// large offline gap. Keep both files in sync when changing either value.

/** Rotate to a new epoch after this many messages sent within an epoch. */
export const ROTATE_AFTER_MESSAGES = 100;

/** Upper bound on cached skipped message keys (out-of-order / offline). */
export const MAX_SKIPPED = 2000;

function hkdf(ikm: Buffer, info: string): Buffer {
  return Buffer.from(crypto.hkdfSync("sha256", ikm, SALT, Buffer.from(info, "utf8"), 32));
}

/**
 * Epoch root from the two fresh per-epoch seeds. Sorted so both peers derive the
 * same root regardless of who initiated — which is also why simultaneous
 * rotation needs no tie-break (each side contributes exactly one seed).
 */
export function deriveEpochRoot(seedA: Buffer, seedB: Buffer): Buffer {
  const [s1, s2] = Buffer.compare(seedA, seedB) <= 0 ? [seedA, seedB] : [seedB, seedA];
  return hkdf(Buffer.concat([s1, s2]), "epoch");
}

/** Am I party "a" (the lower seed owns the a→b send chain)? */
export function iAmA(mySeed: Buffer, peerSeed: Buffer): boolean {
  return Buffer.compare(mySeed, peerSeed) <= 0;
}

export interface EpochKeys {
  root: Buffer;
  sendCK: Buffer; // my sending chain root (== peer's recvCK)
  recvCK: Buffer; // my receiving chain root (== peer's sendCK)
  mediaKey: Buffer; // per-epoch static key for images/audio/streams/calls
}

/** Derive the full per-epoch key set from my/peer epoch seeds. */
export function deriveEpoch(mySeed: Buffer, peerSeed: Buffer): EpochKeys {
  const root = deriveEpochRoot(mySeed, peerSeed);
  const a2b = hkdf(root, "chain-a2b");
  const b2a = hkdf(root, "chain-b2a");
  const mine = iAmA(mySeed, peerSeed);
  return {
    root,
    sendCK: mine ? a2b : b2a,
    recvCK: mine ? b2a : a2b,
    mediaKey: hkdf(root, "media"),
  };
}

/** Message key at the current chain position (delete after use). */
export function messageKey(ck: Buffer): Buffer {
  return hkdf(ck, "msg");
}

/** Advance the chain one step (delete the old ck after use). */
export function chainNext(ck: Buffer): Buffer {
  return hkdf(ck, "ck");
}

export interface RatchetStep {
  messageKey: Buffer; // key for `targetIdx`
  ck: Buffer; // chain advanced to targetIdx+1
  nextIdx: number; // == targetIdx + 1
  skipped: { idx: number; key: Buffer }[]; // keys for [fromIdx, targetIdx)
}

/**
 * Walk a receiving chain from `fromIdx` (chain currently at ck) up to and
 * including `targetIdx`, returning the target's message key, the advanced chain,
 * and the skipped keys in between (to cache for out-of-order/offline delivery).
 * `targetIdx` must be ≥ `fromIdx`; earlier indices are served from the cache by
 * the caller.
 */
export function ratchetTo(ck: Buffer, fromIdx: number, targetIdx: number): RatchetStep {
  if (targetIdx < fromIdx) throw new Error("ratchetTo: targetIdx < fromIdx");
  const skipped: { idx: number; key: Buffer }[] = [];
  let cur = ck;
  for (let i = fromIdx; i < targetIdx; i++) {
    skipped.push({ idx: i, key: messageKey(cur) });
    cur = chainNext(cur);
  }
  const mk = messageKey(cur);
  return { messageKey: mk, ck: chainNext(cur), nextIdx: targetIdx + 1, skipped };
}
