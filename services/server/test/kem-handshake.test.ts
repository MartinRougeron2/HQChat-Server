// Recovery of the epoch-0 KEM handshake when ONE side loses its state.
//
// The bug this pins: the two implementations disagreed about re-offers. The bot
// (bot.ts `case "aes"`) always answered with its stored ciphertext; the app
// (ConversationRouter.handleAES) answered only `if myAESSeed == nil`. So a bot
// that lost its state re-offered forever into an app that would never reply —
// the bot could not derive the channel key, and dropped every message the app
// sent, silently, for good. Observed in production: two friends, both
// `mySeed:true, peerSeed:false, sharedKey:false`.
//
// The KEM is stubbed. What is under test is the state machine around it, which
// is where the two sides drifted apart — and unlike the real HQC library, a stub
// runs on every platform.

import { test } from "node:test";
import assert from "node:assert/strict";

/** Stand-in for HQC: a ciphertext carries the secret only its owner recovers. */
let counter = 0;
function encapsulate(to: string): { ct: string; ss: string } {
  const ss = `ss-${to}-${++counter}`;
  return { ct: `ct[to=${to}|${ss}]`, ss };
}
function decapsulate(me: string, ct: string): string {
  const m = /^ct\[to=([^|]+)\|(.+)\]$/.exec(ct);
  assert.ok(m && m[1] === me, "a ciphertext is only openable by its addressee");
  return m[2]!;
}
/** Order-independent, like the real `deriveSharedKey` / `AESService`. */
function derive(a: string, b: string): string {
  return [a, b].sort().join("+");
}

interface Side {
  name: string;
  mySeed?: string;
  myCt?: string;
  peerSeed?: string;
  sharedKey?: string;
  /** false reproduces the app's pre-fix rule: never re-offer once we hold a seed. */
  fixed: boolean;
}

function fresh(name: string, fixed = true): Side {
  return { name, fixed };
}

/** Our half of the agreement, encapsulated once and remembered. */
function offer(self: Side, peer: Side): string {
  if (!self.mySeed || !self.myCt) {
    const { ct, ss } = encapsulate(peer.name);
    self.mySeed = ss;
    self.myCt = ct;
  }
  return self.myCt;
}

/**
 * Handle an inbound `aes` frame. Returns our ciphertext if we answer.
 *
 * The rule has to do two things at once: heal a peer that lost its half, and
 * terminate. "Always answer" heals but ping-pongs forever once BOTH sides do it
 * (the bot's `this can't loop` comment was relying on the app staying silent).
 * "Answer only if we hold no seed" terminates but never heals — the production
 * bug. So: answer anything that is not itself an answer, and only while it still
 * tells us something (the peer's contribution changed, or we have no key yet).
 */
function onOffer(self: Side, peer: Side, ct: string, isReply = false): { ct: string; isReply: boolean } | null {
  const incoming = decapsulate(self.name, ct);
  const advanced = self.peerSeed !== incoming || !self.sharedKey;
  self.peerSeed = incoming;

  const shouldAnswer = self.fixed
    ? !isReply && advanced
    : self.mySeed === undefined;          // the pre-fix rule
  const answer = shouldAnswer ? { ct: offer(self, peer), isReply: true } : null;

  if (self.mySeed && self.peerSeed) {
    self.sharedKey = derive(self.mySeed, self.peerSeed);
  }
  return answer;
}

/** Run frames to quiescence, so a settled handshake is observable as termination. */
function exchange(from: Side, to: Side, ct: string, maxFrames = 10): number {
  interface Frame { from: Side; to: Side; ct: string; isReply: boolean }
  let frames = 0;
  let inFlight: Frame | null = { from, to, ct, isReply: false };
  while (inFlight) {
    assert.ok(++frames <= maxFrames, "handshake did not settle — frames are ping-ponging");
    const cur: Frame = inFlight;
    const answer = onOffer(cur.to, cur.from, cur.ct, cur.isReply);
    inFlight = answer ? { from: cur.to, to: cur.from, ct: answer.ct, isReply: answer.isReply } : null;
  }
  return frames;
}

test("a first handshake converges on one key and stops", () => {
  const bot = fresh("bot");
  const app = fresh("app");
  exchange(bot, app, offer(bot, app));

  assert.ok(bot.sharedKey, "bot derived a key");
  assert.ok(app.sharedKey, "app derived a key");
  assert.equal(bot.sharedKey, app.sharedKey, "both sides derived the SAME key");
});

test("a side that loses its state recovers — the whole point of storing myCt", () => {
  const bot = fresh("bot");
  const app = fresh("app");
  exchange(bot, app, offer(bot, app));
  const before = app.sharedKey;

  // The bot's state volume comes up empty; the app keeps everything.
  const revived = fresh("bot");
  exchange(revived, app, offer(revived, app));

  assert.ok(revived.sharedKey, "the revived side derived a key");
  assert.equal(revived.sharedKey, app.sharedKey, "and both sides agree again");
  assert.notEqual(app.sharedKey, before, "the app rekeyed to match — it did not keep a key alone");
});

test("re-offering is idempotent: repeats settle rather than minting new secrets", () => {
  const bot = fresh("bot");
  const app = fresh("app");
  exchange(bot, app, offer(bot, app));
  const key = bot.sharedKey;

  for (let i = 0; i < 3; i++) exchange(bot, app, offer(bot, app));

  assert.equal(bot.sharedKey, key, "the key did not drift under repeated offers");
  assert.equal(app.sharedKey, key);
});

test("the pre-fix rule deadlocks — this is the production failure", () => {
  const bot = fresh("bot");
  const appPreFix = fresh("app", /* fixed */ false);
  exchange(bot, appPreFix, offer(bot, appPreFix));

  const revived = fresh("bot");
  exchange(revived, appPreFix, offer(revived, appPreFix));

  // Exactly the state the production bot was found in.
  assert.ok(revived.mySeed, "the revived side offered its half");
  assert.equal(revived.peerSeed, undefined, "…and was never answered");
  assert.equal(revived.sharedKey, undefined, "…so it can never decrypt: silent drops forever");
  // Worse: the peer rekeyed to a key the revived side cannot compute.
  assert.ok(appPreFix.sharedKey, "while the peer believes the channel is healthy");
});

test("an answer is never answered — the exchange terminates", () => {
  const bot = fresh("bot");
  const app = fresh("app");
  // offer → answer, and then silence. Three frames would mean the answer was
  // itself answered, which is how "always reciprocate" runs away.
  assert.equal(exchange(bot, app, offer(bot, app)), 2);
});

test("a peer that keeps re-offering a ciphertext we already settled is ignored", () => {
  // Guards the rollout combination: an un-updated peer that answers everything,
  // talking to an updated side. Without the `advanced` half of the rule the two
  // would trade frames forever.
  const bot = fresh("bot");
  const app = fresh("app");
  exchange(bot, app, offer(bot, app));

  const answer = onOffer(app, bot, offer(bot, app), false);
  assert.equal(answer, null, "nothing new was learned, so nothing is sent");
  assert.ok(app.sharedKey, "and the settled key is untouched");
});
