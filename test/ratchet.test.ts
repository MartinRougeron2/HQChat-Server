import { test } from "node:test";
import { strict as assert } from "node:assert";
import * as fs from "node:fs";
import * as path from "node:path";
import * as nodeCrypto from "node:crypto";
import {
  deriveEpoch,
  deriveEpochRoot,
  messageKey,
  chainNext,
  ratchetTo,
  iAmA,
} from "../lib/ratchet";

// Inline AES-256-GCM in the same [IV 12][tag 16][ct] layout as bot/crypto and
// the Swift AESService — so this test proves the whole seal/open flow without
// needing the native HQC lib (which is Linux-only).
function aesSeal(pt: string, key: Buffer): string {
  const iv = nodeCrypto.randomBytes(12);
  const c = nodeCrypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([c.update(pt, "utf8"), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]).toString("base64");
}
function aesOpen(b64: string, key: Buffer): string {
  const d = Buffer.from(b64, "base64");
  const dc = nodeCrypto.createDecipheriv("aes-256-gcm", key, d.subarray(0, 12));
  dc.setAuthTag(d.subarray(12, 28));
  return Buffer.concat([dc.update(d.subarray(28)), dc.final()]).toString("utf8");
}

const V = JSON.parse(
  fs.readFileSync(path.join(__dirname, "helpers", "ratchet-vectors.json"), "utf8")
);
const seedA = Buffer.from(V.seedA_hex, "hex");
const seedB = Buffer.from(V.seedB_hex, "hex");
const hex = (b: Buffer) => b.toString("hex");

test("epoch root matches the pinned cross-impl vector", () => {
  assert.equal(hex(deriveEpochRoot(seedA, seedB)), V.root_hex);
});

test("epoch root is symmetric (no tie-break needed for simultaneous rotation)", () => {
  assert.equal(hex(deriveEpochRoot(seedA, seedB)), hex(deriveEpochRoot(seedB, seedA)));
});

test("A's chains/media match the pinned vector", () => {
  const a = deriveEpoch(seedA, seedB);
  assert.equal(hex(a.sendCK), V.A.sendCK_hex);
  assert.equal(hex(a.recvCK), V.A.recvCK_hex);
  assert.equal(hex(a.mediaKey), V.A.mediaKey_hex);
});

test("A.sendCK == B.recvCK and A.recvCK == B.sendCK (directional split)", () => {
  const a = deriveEpoch(seedA, seedB);
  const b = deriveEpoch(seedB, seedA);
  assert.equal(hex(a.sendCK), hex(b.recvCK));
  assert.equal(hex(a.recvCK), hex(b.sendCK));
  assert.equal(hex(a.mediaKey), hex(b.mediaKey));
});

test("iAmA is the lower-seed rule and mutually exclusive", () => {
  assert.equal(iAmA(seedA, seedB), true); // seedA sorts before seedB
  assert.equal(iAmA(seedB, seedA), false);
});

test("first three message keys match the pinned vector (both directions)", () => {
  const a = deriveEpoch(seedA, seedB);
  let ck = a.sendCK;
  for (let i = 0; i < 3; i++) {
    assert.equal(hex(messageKey(ck)), V.A.sendMsgKeys_0_2[i]);
    ck = chainNext(ck);
  }
  const b = deriveEpoch(seedB, seedA);
  ck = b.sendCK;
  for (let i = 0; i < 3; i++) {
    assert.equal(hex(messageKey(ck)), V.B.sendMsgKeys_0_2[i]);
    ck = chainNext(ck);
  }
});

test("ratchetTo yields the target key and the skipped keys in between", () => {
  const a = deriveEpoch(seedA, seedB);
  const step = ratchetTo(a.sendCK, 0, 2);
  assert.equal(hex(step.messageKey), V.A.sendMsgKeys_0_2[2]);
  assert.equal(step.nextIdx, 3);
  assert.equal(step.skipped.length, 2);
  assert.equal(hex(step.skipped[0]!.key), V.A.sendMsgKeys_0_2[0]);
  assert.equal(hex(step.skipped[1]!.key), V.A.sendMsgKeys_0_2[1]);
});

test("ratchetTo with no gap returns the immediate key and no skips", () => {
  const a = deriveEpoch(seedA, seedB);
  const step = ratchetTo(a.sendCK, 0, 0);
  assert.equal(hex(step.messageKey), V.A.sendMsgKeys_0_2[0]);
  assert.equal(step.skipped.length, 0);
  assert.equal(step.nextIdx, 1);
});

test("ratchetTo rejects a target below the current index", () => {
  const a = deriveEpoch(seedA, seedB);
  assert.throws(() => ratchetTo(a.sendCK, 5, 4));
});

test("a full out-of-order exchange decrypts: sender seals 0..4, receiver opens 3,1,4,0,2", () => {
  // Sender = A on its send chain; receiver = B on its recv chain (== A.sendCK).
  const a = deriveEpoch(seedA, seedB);
  const b = deriveEpoch(seedB, seedA);
  // Sender's per-index keys.
  const sealed: string[] = [];
  let ck = a.sendCK;
  for (let i = 0; i < 5; i++) {
    sealed.push(hex(messageKey(ck)));
    ck = chainNext(ck);
  }
  // Receiver walks its chain on demand, caching skips.
  let recvCK = b.recvCK;
  let recvIdx = 0;
  const cache = new Map<number, string>();
  const open = (idx: number): string => {
    if (cache.has(idx)) {
      const k = cache.get(idx)!;
      cache.delete(idx);
      return k;
    }
    const step = ratchetTo(recvCK, recvIdx, idx);
    for (const s of step.skipped) cache.set(s.idx, hex(s.key));
    recvCK = step.ck;
    recvIdx = step.nextIdx;
    return hex(step.messageKey);
  };
  for (const idx of [3, 1, 4, 0, 2]) {
    assert.equal(open(idx), sealed[idx], `opened idx ${idx} matches sealed key`);
  }
  assert.equal(cache.size, 0, "every skipped key was consumed");
});

test("a different epoch root gives entirely different chains (post-compromise)", () => {
  const a1 = deriveEpoch(seedA, seedB);
  const seedA2 = Buffer.alloc(24, 0x11);
  const seedB2 = Buffer.alloc(24, 0x22);
  const a2 = deriveEpoch(seedA2, seedB2);
  assert.notEqual(hex(a1.sendCK), hex(a2.sendCK));
  assert.notEqual(hex(a1.mediaKey), hex(a2.mediaKey));
});

// A minimal peer mirroring the bot / Swift stateful glue: send seals with the
// current chain key then advances; receive fetches the key by (epoch, idx) via
// the shared ratchet, caching skips. Rotation installs a fresh epoch and demotes
// the old one to a recv-only grace window.
class Peer {
  cur: ReturnType<typeof deriveEpoch> & { epoch: number; sendIdx: number; recvIdx: number };
  skipped = new Map<string, Buffer>();
  prev?: { epoch: number; recvCK: Buffer; recvIdx: number };
  constructor(mySeed: Buffer, peerSeed: Buffer, epoch = 1) {
    const k = deriveEpoch(mySeed, peerSeed);
    this.cur = { ...k, epoch, sendIdx: 0, recvIdx: 0 };
  }
  seal(text: string) {
    const mk = messageKey(this.cur.sendCK);
    const frame = { epoch: this.cur.epoch, idx: this.cur.sendIdx, ct: aesSeal(text, mk) };
    this.cur.sendCK = chainNext(this.cur.sendCK);
    this.cur.sendIdx++;
    return frame;
  }
  open(frame: { epoch: number; idx: number; ct: string }) {
    const cacheKey = `${frame.epoch}:${frame.idx}`;
    if (this.skipped.has(cacheKey)) {
      const mk = this.skipped.get(cacheKey)!;
      this.skipped.delete(cacheKey);
      return aesOpen(frame.ct, mk);
    }
    let ck: Buffer, from: number;
    const grace = this.prev && frame.epoch === this.prev.epoch;
    if (grace) { ck = this.prev!.recvCK; from = this.prev!.recvIdx; }
    else { ck = this.cur.recvCK; from = this.cur.recvIdx; }
    const step = ratchetTo(ck, from, frame.idx);
    for (const s of step.skipped) this.skipped.set(`${frame.epoch}:${s.idx}`, s.key);
    if (grace) { this.prev!.recvCK = step.ck; this.prev!.recvIdx = step.nextIdx; }
    else { this.cur.recvCK = step.ck; this.cur.recvIdx = step.nextIdx; }
    return aesOpen(frame.ct, step.messageKey);
  }
  rotate(mySeed: Buffer, peerSeed: Buffer) {
    this.prev = { epoch: this.cur.epoch, recvCK: this.cur.recvCK, recvIdx: this.cur.recvIdx };
    const k = deriveEpoch(mySeed, peerSeed);
    this.cur = { ...k, epoch: this.cur.epoch + 1, sendIdx: 0, recvIdx: 0 };
  }
}

test("two peers hold a conversation across a rotation, including a late old-epoch message", () => {
  const a = new Peer(seedA, seedB);
  const b = new Peer(seedB, seedA);

  // Epoch 1, in order.
  assert.equal(b.open(a.seal("hi from A")), "hi from A");
  assert.equal(a.open(b.seal("hi from B")), "hi from B");

  // A sends three more; B receives them out of order (2, 0, 1).
  const f0 = a.seal("m0"), f1 = a.seal("m1"), f2 = a.seal("m2");
  assert.equal(b.open(f2), "m2");
  assert.equal(b.open(f0), "m0");
  assert.equal(b.open(f1), "m1");

  // A queues one more old-epoch message BEFORE the rotation is applied on A.
  const lateOld = a.seal("sent just before rotation");

  // Rotate to epoch 2 (each side contributes one fresh seed → same root).
  const nsA = Buffer.alloc(24, 0x33), nsB = Buffer.alloc(24, 0x44);
  a.rotate(nsA, nsB);
  b.rotate(nsB, nsA);

  // New-epoch traffic flows.
  assert.equal(b.open(a.seal("epoch2 from A")), "epoch2 from A");
  assert.equal(a.open(b.seal("epoch2 from B")), "epoch2 from B");

  // The straggler from epoch 1 still decrypts via B's grace window.
  assert.equal(b.open(lateOld), "sent just before rotation");
});
