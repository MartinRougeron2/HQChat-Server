// TypeScript and Swift must agree on what an `init` frame looks like.
//
// They did not. `parseEnvelope` applied the rk/kemCt pairing rule to every
// frame, so an init with `rk` and no `kemCt` was refused — while
// apps/apple/tests/EnvelopeTests.swift asserts the opposite in as many words:
//
//   check(decodeMutated("init", ["kemCt": nil]) != nil,
//         "an init WITHOUT kemCt is accepted — the bot omits a field an init
//          has no use for")
//
// And the bot does omit it: bot.ts builds the init branch from `initHeader`
// alone, because an init has no peer ratchet key to encapsulate against — its
// root comes from ctId/ctMt/ctOt, which makes `kemCt` meaningless on one.
//
// So a TypeScript client could not read an init that a TypeScript client had
// written. Production survived on an asymmetry (the bot writes them, Swift
// reads them), and it surfaced only when the e2e suite — TS talking to TS —
// ran for the first time and dropped every init at parse.
//
// The vector file's init case carries `kemCt`, which is legal but not required,
// and is why the vector round-trip test never caught this.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parseEnvelope } from "../lib/envelope";

const V = JSON.parse(
  readFileSync(join(__dirname, "helpers", "envelope-vectors.json"), "utf8")
);

test("an init without kemCt is accepted, as Swift and the bot require", () => {
  const base = { ...V.cases.init.envelope };
  assert.ok(parseEnvelope(base), "the pinned init parses");

  const { kemCt, ...withoutKemCt } = base;
  assert.ok(kemCt, "the vector's init has a kemCt to remove");
  assert.ok(
    parseEnvelope(withoutKemCt),
    "an init with rk and no kemCt must parse — it is exactly what bot.ts emits, " +
    "and what EnvelopeTests.swift asserts is valid"
  );
});

test("an init still has to advertise its chain", () => {
  // Relaxing the pairing rule must not relax this: without `rk` the responder
  // has no key to encapsulate back to.
  const base = { ...V.cases.init.envelope };
  assert.equal(
    parseEnvelope({ ...base, rk: undefined, kemCt: undefined }), null,
    "an init must advertise the initiator's chain"
  );
  assert.equal(
    parseEnvelope({ ...base, rk: undefined }), null,
    "…even when kemCt is present"
  );
});

test("a msg frame still needs both halves of a step", () => {
  // The pairing rule is right for `msg`; it was only ever wrong for `init`.
  const base = { ...V.cases.stepping.envelope };
  assert.equal(parseEnvelope({ ...base, kemCt: undefined }), null, "rk without kemCt");
  assert.equal(parseEnvelope({ ...base, rk: undefined }), null, "kemCt without rk");
});

test("the bot and the e2e harness build the same init field set", () => {
  // The divergence was invisible because two files build this object and
  // nothing compared them. They are the only two TypeScript writers of an init.
  const fields = (src: string): string[] => {
    const from = src.indexOf("senderPk:");
    assert.ok(from > 0, "could not find an init branch");
    const branch = src.slice(from, from + 1200);
    return ["senderPk", "rk", "ctId", "ctMt", "ctOt", "otId", "kemCt"]
      .filter((f) => new RegExp(`\\b${f}\\b`).test(branch));
  };
  const bot = fields(readFileSync(join(__dirname, "..", "bot", "bot.ts"), "utf8"));
  const harness = fields(readFileSync(join(__dirname, "helpers", "mqtt-client.ts"), "utf8"));
  assert.deepEqual(harness, bot,
    "the e2e harness must build the init the bot builds, or it is testing a shape " +
    "nothing in production sends");
});
