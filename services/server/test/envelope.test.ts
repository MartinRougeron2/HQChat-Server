// The v2 wire format: canonical AAD encoding and envelope validation.
//
// This file and apps/apple/tests/EnvelopeTests.swift assert the SAME
// helpers/envelope-vectors.json, and both READ it. The canonical header is the
// one place where a single byte of disagreement between the Swift client and the
// TS bot means nothing decrypts — and it surfaces as a GCM tag mismatch, which
// is indistinguishable from a wrong key. Pinning the exact bytes is what turns
// that into a test failure instead of a field report.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { canonicalHeader, parseEnvelope, EnvelopeV2 } from "../lib/envelope";
import { peerId } from "../lib/identity";

const V = JSON.parse(
  fs.readFileSync(path.join(__dirname, "helpers", "envelope-vectors.json"), "utf8")
);

const caseNames = ["msg", "stepping", "init", "initNoOneTime", "unicode"] as const;

test("the vector file is the v2 shape and covers every case", () => {
  assert.equal(V.version, 2);
  for (const name of caseNames) {
    assert.ok(V.cases[name], `vector file is missing the "${name}" case`);
  }
});

test("canonicalHeader matches the pinned bytes for every case", () => {
  for (const name of caseNames) {
    const c = V.cases[name];
    const aad = canonicalHeader(c.envelope as EnvelopeV2);
    // Hex as well as the string: a trailing-whitespace or encoding difference
    // can hide in a string comparison and not in a byte one.
    assert.equal(aad.toString("hex"), c.aadHex, `${name}: AAD bytes`);
    assert.equal(aad.toString("utf8"), c.aad, `${name}: AAD text`);
    assert.equal(aad.length, c.aadBytes, `${name}: AAD length`);
  }
});

test("the length prefix counts BYTES, not characters", () => {
  const c = V.cases.unicode;
  // "id-café-🔒" is 9 characters but 13 bytes. A character count would agree
  // with Swift on ASCII and disagree here — the worst possible failure mode,
  // because it would pass every test that used a plain ASCII id.
  assert.match(c.aad, /13:id-café-🔒/);
  assert.equal(canonicalHeader(c.envelope as EnvelopeV2).toString("hex"), c.aadHex);
});

test("an absent optional field encodes as empty, not as a shorter header", () => {
  // `initNoOneTime` is the exhausted-pool path. Its ctOt/otId are absent, and
  // that must still occupy their positions — otherwise a header with a one-time
  // key could encode identically to one without, and the two sides could
  // disagree about which session they are in.
  const withOt = V.cases.init;
  const withoutOt = V.cases.initNoOneTime;
  assert.notEqual(withOt.aadHex, withoutOt.aadHex);
  assert.ok(withoutOt.aad.endsWith("0:0:"), "both trailing fields are present but empty");
});

test("every header field is actually bound — changing any one changes the AAD", () => {
  const base = V.cases.init.envelope as EnvelopeV2;
  const baseline = canonicalHeader(base).toString("hex");

  const mutations: Array<[string, Partial<EnvelopeV2>]> = [
    ["t", { t: "msg" }],
    ["sender", { sender: "d".repeat(64) }],
    ["msgId", { msgId: "different" }],
    ["cid", { cid: "00000000000000000000000000000000" }],
    ["n", { n: 8 }],
    ["pn", { pn: 4 }],
    ["rk", { rk: "b3RoZXI=" }],
    ["kemCt", { kemCt: "b3RoZXI=" }],
    ["ctId", { ctId: "b3RoZXI=" }],
    ["ctMt", { ctMt: "b3RoZXI=" }],
    ["ctOt", { ctOt: "b3RoZXI=" }],
    ["otId", { otId: 6 }],
  ];
  for (const [field, patch] of mutations) {
    const mutated = canonicalHeader({ ...base, ...patch } as EnvelopeV2).toString("hex");
    assert.notEqual(mutated, baseline, `${field} is not bound into the AAD`);
  }
});

test("the payload is NOT in the AAD — GCM already covers it", () => {
  const base = V.cases.msg.envelope as EnvelopeV2;
  const other = canonicalHeader({ ...base, payload: "c29tZXRoaW5nRWxzZQ==" } as EnvelopeV2);
  assert.equal(other.toString("hex"), V.cases.msg.aadHex);
});

// ── Validation ───────────────────────────────────────────────────────────────

test("well-formed envelopes parse", () => {
  for (const name of caseNames) {
    assert.ok(parseEnvelope(V.cases[name].envelope), `${name} should parse`);
  }
});

test("a wrong or missing version is refused rather than guessed at", () => {
  const base = V.cases.msg.envelope;
  assert.equal(parseEnvelope({ ...base, v: 1 }), null);
  assert.equal(parseEnvelope({ ...base, v: 3 }), null);
  assert.equal(parseEnvelope({ ...base, v: undefined }), null);
  assert.equal(parseEnvelope({ ...base, v: "2" }), null);
});

test("a half-formed ratchet step is refused", () => {
  const base = V.cases.stepping.envelope;
  // A ratchet key with no ciphertext is not something a receiver can act on;
  // a ciphertext with no key names no chain.
  assert.equal(parseEnvelope({ ...base, kemCt: undefined }), null, "rk without kemCt");
  assert.equal(parseEnvelope({ ...base, rk: undefined }), null, "kemCt without rk");
});

test("an init without its handshake ciphertexts is refused", () => {
  const base = V.cases.init.envelope;
  assert.equal(parseEnvelope({ ...base, ctId: undefined }), null, "no identity encapsulation");
  assert.equal(parseEnvelope({ ...base, ctMt: undefined }), null, "no medium encapsulation");
  assert.equal(parseEnvelope({ ...base, rk: undefined, kemCt: undefined }), null,
    "an init must advertise the initiator's chain");
  // ctOt and otId travel together — otId is what says which secret opens ctOt.
  assert.equal(parseEnvelope({ ...base, otId: undefined }), null, "ctOt without otId");
  assert.equal(parseEnvelope({ ...base, ctOt: undefined }), null, "otId without ctOt");
});

test("malformed indices and selectors are refused", () => {
  const base = V.cases.msg.envelope;
  for (const n of [-1, 1.5, NaN, Infinity, "0", null]) {
    assert.equal(parseEnvelope({ ...base, n }), null, `n = ${String(n)}`);
  }
  for (const pn of [-1, 2.5, "3"]) {
    assert.equal(parseEnvelope({ ...base, pn }), null, `pn = ${String(pn)}`);
  }
  for (const cid of ["", "short", "0123456789ABCDEF0123456789ABCDEF", "g".repeat(32)]) {
    assert.equal(parseEnvelope({ ...base, cid }), null, `cid = ${cid}`);
  }
  // Uppercase hex would encode to different AAD bytes than the lowercase the
  // other side produces, so it is refused rather than normalised.
  assert.equal(parseEnvelope({ ...base, sender: "A".repeat(64) }), null, "uppercase sender");
});

// ── `sender` is a client id ─────────────────────────────────────────────────
//
// It used to be the public key, and the bound was `1–20000 hex` — wide enough
// to admit a nibble, a chain id, a key, or 10 kB of anything. A fixed width is
// what lets a wrong-shaped identifier be REFUSED rather than looked up and not
// found, which matters most for exactly the frames a shipped client would send
// across this change.

test("sender must be exactly 64 lowercase hex — a client id", () => {
  const base = V.cases.msg.envelope;
  assert.equal(base.sender.length, 64);
  assert.ok(parseEnvelope({ ...base }), "the pinned id parses");
  for (const sender of [
    "",                       // absent
    "a".repeat(63),           // one short
    "a".repeat(65),           // one long
    "a".repeat(12),           // the OLD vector's sender, which used to pass
    "a".repeat(14474),        // a full public key — the OLD wire form
    "g".repeat(64),           // not hex
    42,
    null,
  ]) {
    assert.equal(parseEnvelope({ ...base, sender }), null, `sender = ${String(sender).slice(0, 24)}`);
  }
});

test("an init carries the initiator's key, and it must be the key `sender` names", () => {
  const base = V.cases.init.envelope as EnvelopeV2;
  assert.ok(parseEnvelope(base), "the pinned init parses");
  assert.equal(peerId(base.senderPk!), base.sender, "the vector is self-consistent");

  // Missing entirely: a responder would have no key to encapsulate back to, and
  // nothing would say so until the first reply silently failed to be sealed.
  assert.equal(parseEnvelope({ ...base, senderPk: undefined }), null, "no senderPk");

  // Present but NOT the key the id commits to. This is the substitution the
  // whole design exists to refuse: a frame naming a peer we trust while
  // carrying a key we would then pin and encrypt to.
  const impostor = "b".repeat(7237 * 2);
  assert.notEqual(peerId(impostor), base.sender);
  assert.equal(parseEnvelope({ ...base, senderPk: impostor }), null, "a substituted key");

  // A single flipped character — the near-miss, and the one a length check
  // alone would wave through.
  const tweaked = base.senderPk!.slice(0, -1) + (base.senderPk!.endsWith("0") ? "1" : "0");
  assert.equal(parseEnvelope({ ...base, senderPk: tweaked }), null, "one changed character");

  // Wrong size for an HQC-256 key at all.
  assert.equal(parseEnvelope({ ...base, senderPk: "ab" }), null, "too short to be a key");
  assert.equal(parseEnvelope({ ...base, senderPk: base.senderPk! + "ab" }), null, "too long");
  assert.equal(parseEnvelope({ ...base, senderPk: base.senderPk!.toUpperCase() }), null, "uppercase");
});

test("a msg frame does not need senderPk — the session already holds the key", () => {
  // The key travels on `init` because that is the frame from someone the
  // receiver may never have fetched a key for. Repeating 14 kB on every message
  // afterwards would undo most of what this change is for.
  const base = V.cases.msg.envelope as EnvelopeV2;
  assert.equal(base.senderPk, undefined);
  assert.ok(parseEnvelope(base));
});

test("senderPk is bound transitively, not directly — the AAD is unchanged in shape", () => {
  // `senderPk` is deliberately absent from FIELDS. It cannot be tampered with
  // regardless: `sender` IS in the AAD, and senderPk must hash to it.
  const base = V.cases.init.envelope as EnvelopeV2;
  const withKey = canonicalHeader(base).toString("hex");
  const stripped: EnvelopeV2 = { ...base };
  delete stripped.senderPk;
  const withoutKey = canonicalHeader(stripped).toString("hex");
  assert.equal(withKey, withoutKey, "senderPk does not enter the canonical header");
  assert.equal(withKey, V.cases.init.aadHex);
});

test("a missing or oversized msgId is refused", () => {
  const base = V.cases.msg.envelope;
  assert.equal(parseEnvelope({ ...base, msgId: "" }), null);
  assert.equal(parseEnvelope({ ...base, msgId: "x".repeat(129) }), null);
  assert.equal(parseEnvelope({ ...base, msgId: 42 }), null);
});

test("a non-object is refused without throwing", () => {
  for (const junk of [null, undefined, 42, "string", [], true]) {
    assert.equal(parseEnvelope(junk), null, `${String(junk)} is refused`);
  }
});
