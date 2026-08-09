/**
 * DissQus helper bot — an always-on protocol client.
 *
 * It authenticates like a normal user (HQC challenge/response), sets a
 * username, auto-accepts friend requests, completes the AES secure-channel
 * handshake, and replies to messages. Its identity (seed) and per-friend keys
 * are persisted so it survives restarts.
 *
 * Run on the VPS (it needs the Linux HQC lib). Env:
 *   SERVER_WS_URL   default wss://chat.martinrougeron.me/ws
 *   BOT_USERNAME    default "helper"
 *   BOT_SEED        32-byte hex seed (optional; generated + saved if absent)
 *
 * The bot self-admits: on startup it writes its own public key into the Redis
 * `admission:exempt` set (shared with the server), so it's admitted under any
 * ADMISSION_POLICY without an operator hand-copying its key into
 * EXEMPT_PUBLIC_KEYS. That survives the bot's seed/identity changing. It still
 * needs the server's Redis credentials (already provided in docker-compose).
 */

// First import: loads .env and resolves *_FILE Docker secrets (e.g. BOT_SEED_FILE).
import "../lib/config";
// Init Sentry + global crash handlers (uncaughtException / unhandledRejection)
// before anything else runs — the bot is a long-lived client that must survive
// server hiccups and reconnects without silently dying.
import { initObservability } from "../lib/observability";
initObservability("bot");
import { logger } from "../lib/logger";
import WebSocket from "ws";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { HqcWrapper, HQC_CONSTANTS } from "../lib/hqc";
import { MessageTypesToSent as Out, MessageTypesToReceive as In } from "../enums";
import {
  hqcEncapsulate,
  hqcDecapsulate,
  aesEncrypt,
  aesDecrypt,
  deriveSharedKey,
} from "./crypto";
import {
  deriveEpoch,
  messageKey,
  chainNext,
  ratchetTo,
  ROTATE_AFTER_MESSAGES,
  MAX_SKIPPED,
} from "../lib/ratchet";
import { unwrap, deriveSessionKeys, authProof } from "../lib/secure-transport";
import { DB } from "../services/db/api";
const WS_URL = process.env.SERVER_WS_URL || "wss://chat.martinrougeron.me/ws";
const USERNAME = process.env.BOT_USERNAME || "helper";
// Persist state (seed + per-friend keys) in a directory SEPARATE from the code.
// In Docker the bot-state volume mounts at BOT_STATE_DIR — never over /app/bot
// (the code dir), which would shadow bot.ts and pin the container to stale code
// across image updates. Defaults to __dirname for local / pm2 runs.
const STATE_DIR = process.env.BOT_STATE_DIR || __dirname;
fs.mkdirSync(STATE_DIR, { recursive: true });
const SEED_FILE = path.join(STATE_DIR, ".bot-seed");
const STATE_FILE = path.join(STATE_DIR, ".bot-state.json");

// ── Identity ─────────────────────────────────────────────────────────────────
function loadSeed(): Buffer {
  if (process.env.BOT_SEED) return Buffer.from(process.env.BOT_SEED, "hex");
  if (fs.existsSync(SEED_FILE)) return Buffer.from(fs.readFileSync(SEED_FILE, "utf8").trim(), "hex");
  const seed = crypto.randomBytes(HQC_CONSTANTS.SEED_BYTES);
  fs.writeFileSync(SEED_FILE, seed.toString("hex"), { mode: 0o600 });
  return seed;
}

const seed = loadSeed();
const { pk, sk } = HqcWrapper.keypairFromSeed(seed);
const pkHex = pk.toString("hex");

// ── Per-friend state ─────────────────────────────────────────────────────────
// Epoch ≥ 1 ratchet state (Tier 1 + Tier 2). All keys hex. `skipped` holds
// message keys for out-of-order/offline receives, keyed by chain index.
interface EpochState {
  epoch: number;
  sendCK: string;
  sendIdx: number;
  recvCK: string;
  recvIdx: number;
  mediaKey: string;
  skipped: Record<string, string>;
}
interface FriendState {
  pk: string; // hex public key
  // Epoch 0 static channel key from the KEM handshake (§KM-1). `mySeed` is the
  // shared secret WE contributed (our encapsulation's ss); `myCt` is the KEM
  // ciphertext we sent for it (base64) — kept so a re-handshake re-sends the SAME
  // encapsulation and both sides derive the same key. `peerSeed` is the ss we
  // recovered from the peer's ciphertext.
  mySeed?: string;   // hex — our contributed shared secret (ss)
  myCt?: string;     // base64 — the KEM ciphertext we sent for mySeed
  peerSeed?: string; // hex — the ss we decapsulated from the peer's ciphertext
  sharedKey?: string; // hex AES-256 key
  // Epoch ≥ 1 ratchet.
  cur?: EpochState; // current epoch
  prev?: EpochState; // one previous epoch, recv-only grace window
  rot?: { epoch: number; mySeed?: string; myCt?: string; peerSeed?: string }; // in-flight rotation
  sentInEpoch?: number; // messages sent since the last epoch install (count trigger)
}
type State = { friends: Record<string, FriendState> };

let state: State = { friends: {} };
function loadState() {
  if (fs.existsSync(STATE_FILE)) {
    try { state = JSON.parse(fs.readFileSync(STATE_FILE, "utf8")); } catch { /* ignore */ }
  }
}
function saveState() {
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2), { mode: 0o600 });
}
loadState();

// ── Connection ───────────────────────────────────────────────────────────────
let ws: WebSocket;
// Per-connection transport keys (see lib/secure-transport). The bot is a client,
// so it encrypts with c2s (txKey) and decrypts with s2c (rxKey). Null until the
// server's SESSION_KEY arrives; reset on every (re)connect.
let txKey: Buffer | null = null;
let rxKey: Buffer | null = null;

function send(obj: object) {
  if (!(ws && ws.readyState === WebSocket.OPEN)) return;
  const json = JSON.stringify(obj);
  ws.send(txKey ? JSON.stringify({ enc: aesEncrypt(json, txKey) }) : json);
}

function connect() {
  logger.debug(`🤖 [bot] connecting to ${WS_URL} as "${USERNAME}"`);
  logger.debug(`🤖 [bot] public key: ${pkHex.substring(0, 8)}…${pkHex.substring(pkHex.length - 8)}`);
  txKey = null;
  rxKey = null;
  ws = new WebSocket(WS_URL);

  ws.on("open", () => send({ type: Out.AUTH_INIT, payload: pkHex }));
  ws.on("message", (data) => handle(data.toString()));
  ws.on("close", () => {
    logger.debug("🤖 [bot] disconnected — reconnecting in 3s");
    setTimeout(connect, 3000);
  });
  ws.on("error", (e) => logger.error("🤖 [bot] ws error:", e.message));
}

// ── Message handling ─────────────────────────────────────────────────────────
async function handle(raw: string) {
  let msg: any;
  try { msg = unwrap(raw, rxKey ?? undefined); } catch { return; }

  switch (msg.type) {
    case In.AUTH_CHALLENGE: {
      // KEM challenge (§KM-1): decapsulate the ciphertext → the shared secret ss,
      // then return HKDF(ss,"auth") to prove we hold the secret key. We never send
      // ss or any decrypted plaintext.
      const ss = hqcDecapsulate(sk, Buffer.from(msg.payload, "base64"));
      send({ type: Out.AUTH_VERIFY, payload: authProof(ss).toString("base64") });
      break;
    }

    case In.SESSION_KEY: {
      // Transport key exchange (§KM-1): decapsulate the ciphertext → the 32-byte
      // shared secret, then derive the per-direction transport keys. From here,
      // send() encrypts and unwrap() decrypts.
      const ss = hqcDecapsulate(sk, Buffer.from(msg.payload, "base64"));
      const keys = deriveSessionKeys(ss);
      txKey = keys.c2s; // bot (client) encrypts with c2s
      rxKey = keys.s2c; // bot (client) decrypts with s2c
      logger.debug("🤖 [bot] transport session keys established");
      break;
    }
    case In.AUTH_SUCCESS:
      logger.debug("🤖 [bot] authenticated");
      send({ type: Out.SET_USERNAME, payload: USERNAME });
      break;

    case In.USERNAME_UPDATED:
      logger.debug(`🤖 [bot] username set to @${msg.payload}`);
      break;

    case In.FRIEND_REQUEST: {
      const sender = msg.sender as string;
      if (msg.pk) state.friends[sender] = { ...(state.friends[sender] || {}), pk: msg.pk };
      saveState();
      logger.debug(`🤖 [bot] friend request from @${sender} — accepting`);
      send({ type: Out.ACCEPT_INVITE, payload: sender });
      break;
    }

    case In.FRIEND_ADDED: {
      const username = (msg.username || msg.sender) as string;
      const f = state.friends[username] || ({} as FriendState);
      if (msg.pk) f.pk = msg.pk;
      state.friends[username] = f;
      saveState();
      // Kick off the AES handshake unless we're already secure with them.
      if (!f.sharedKey) sendAesSeed(username);
      logger.debug(`🤖 [bot] friend added: @${username}`);
      break;
    }

    case In.AES: {
      const sender = msg.sender as string;
      const f = state.friends[sender];
      if (!f) break;
      try {
        // Decapsulate the peer's KEM ciphertext → the shared secret they contributed.
        const peerSs = hqcDecapsulate(sk, Buffer.from(msg.payload, "base64"));
        f.peerSeed = peerSs.toString("hex");
        // (Re)send OUR encapsulation so the peer can derive too. sendAesSeed reuses
        // our stored ciphertext (f.myCt) if present, so on a re-handshake we resend
        // the SAME encapsulation rather than a new one — both sides stay on one key.
        // The peer only replies while it has no secret of its own, so this can't loop.
        sendAesSeed(sender);
        if (f.mySeed && f.peerSeed) {
          const key = deriveSharedKey(Buffer.from(f.mySeed, "hex"), Buffer.from(f.peerSeed, "hex"));
          f.sharedKey = key.toString("hex");
          logger.debug(`🔒 [bot] secure channel established with @${sender}`);
        }
        saveState();
      } catch (e: any) {
        logger.error(`🤖 [bot] AES handshake error with @${sender}:`, e.message);
      }
      break;
    }

    case In.DIRECT_MESSAGE: {
      const sender = msg.sender as string;
      const f = state.friends[sender];
      if (!f || sender === "SYSTEM") break;
      const epoch = Number.isInteger(msg.epoch) ? Number(msg.epoch) : 0;
      try {
        // §KM-1 step 5: the per-message outer HQC layer is gone. The payload is
        // the AES-GCM base64 directly, sealed under the ratchet key (epoch ≥ 1) or
        // the epoch-0 static channel key.
        const aesB64 = msg.payload as string;
        let text: string;
        if (epoch >= 1) {
          const mk = obtainRecvKey(f, epoch, Number(msg.idx));
          if (!mk) {
            logger.error(`🤖 [bot] no ratchet key for @${sender} (epoch ${epoch}, idx ${msg.idx})`);
            break;
          }
          text = aesDecrypt(aesB64, mk);
          saveState();
        } else {
          if (!f.sharedKey) break;
          text = aesDecrypt(aesB64, Buffer.from(f.sharedKey, "hex"));
        }
        const answer = reply(text);
        logger.debug(`💬 [bot] @${sender}: ${text}  →  ${answer.split("\n")[0]}`);
        sendMessage(sender, answer);
      } catch (e: any) {
        logger.error(`🤖 [bot] message decrypt error from @${sender}:`, e.message);
      }
      break;
    }

    case In.KEY_ROTATE: {
      // Tier-1 epoch re-handshake — a near-clone of the AES case, epoch-scoped.
      const sender = msg.sender as string;
      const f = state.friends[sender];
      if (!f?.pk) break;
      const epoch = Number(msg.epoch);
      if (!Number.isInteger(epoch) || epoch <= currentEpoch(f)) break; // stale/duplicate
      try {
        const peerSs = hqcDecapsulate(sk, Buffer.from(msg.payload, "base64"));
        if (!f.rot || f.rot.epoch !== epoch) f.rot = { epoch }; // peer-initiated
        f.rot.peerSeed = peerSs.toString("hex");
        // Contribute our own encapsulation for this epoch if we haven't yet
        // (symmetric: each side sends exactly one, so simultaneous rotation needs
        // no tie-break).
        if (!f.rot.mySeed) {
          const { ct, ss } = hqcEncapsulate(Buffer.from(f.pk, "hex"));
          f.rot.mySeed = ss.toString("hex");
          f.rot.myCt = ct.toString("base64");
          send({ type: Out.KEY_ROTATE, targetPk: sender, payload: f.rot.myCt, epoch });
        }
        if (f.rot.mySeed && f.rot.peerSeed) {
          installEpoch(sender, f, epoch, Buffer.from(f.rot.mySeed, "hex"), Buffer.from(f.rot.peerSeed, "hex"));
        }
        saveState();
      } catch (e: any) {
        logger.error(`🤖 [bot] KEY_ROTATE error with @${sender}:`, e.message);
      }
      break;
    }

    case In.HEARTBEAT_PING:
      send({ type: Out.HEARTBEAT_PONG });
      break;

    case In.PAYMENT_REQUIRED:
      logger.error("🤖 [bot] PAYMENT_REQUIRED — add the bot's public key to EXEMPT_PUBLIC_KEYS on the server.");
      break;

    case In.ERROR:
      logger.error("🤖 [bot] server error:", msg.payload);
      break;
  }
}

// ── Ratchet helpers (epoch ≥ 1) ──────────────────────────────────────────────
function currentEpoch(f: FriendState): number {
  return f.cur?.epoch ?? 0;
}

function epochStateFor(f: FriendState, epoch: number): EpochState | undefined {
  if (f.cur?.epoch === epoch) return f.cur;
  if (f.prev?.epoch === epoch) return f.prev;
  return undefined;
}

/** Install a freshly negotiated epoch; demote the current one to recv-only grace. */
function installEpoch(username: string, f: FriendState, epoch: number, mySeed: Buffer, peerSeed: Buffer) {
  const ek = deriveEpoch(mySeed, peerSeed);
  if (f.cur) f.prev = f.cur; // keep exactly one previous epoch (drops any older)
  f.cur = {
    epoch,
    sendCK: ek.sendCK.toString("hex"),
    sendIdx: 0,
    recvCK: ek.recvCK.toString("hex"),
    recvIdx: 0,
    mediaKey: ek.mediaKey.toString("hex"),
    skipped: {},
  };
  delete f.rot;
  f.sentInEpoch = 0;
  logger.debug(`🔄 [bot] installed epoch ${epoch} with @${username}`);
}

/** Start a Tier-1 rotation to the next epoch by sending our fresh seed. */
function initiateRotation(username: string) {
  const f = state.friends[username];
  if (!f?.pk) return;
  const nextEpoch = currentEpoch(f) + 1;
  if (f.rot && f.rot.epoch >= nextEpoch) return; // one already in flight
  const { ct, ss } = hqcEncapsulate(Buffer.from(f.pk, "hex"));
  f.rot = { epoch: nextEpoch, mySeed: ss.toString("hex"), myCt: ct.toString("base64") };
  send({ type: Out.KEY_ROTATE, targetPk: username, payload: f.rot.myCt!, epoch: nextEpoch });
  saveState();
  logger.debug(`🔄 [bot] initiating rotation to epoch ${nextEpoch} with @${username}`);
}

/** Cap the skipped-key cache, evicting the lowest (oldest) indices first. */
function boundSkipped(es: EpochState) {
  const keys = Object.keys(es.skipped);
  if (keys.length <= MAX_SKIPPED) return;
  keys.map(Number).sort((a, b) => a - b).slice(0, keys.length - MAX_SKIPPED)
    .forEach((k) => delete es.skipped[String(k)]);
}

/** Message key for a received (epoch, idx): cache hit, or ratchet forward. */
function obtainRecvKey(f: FriendState, epoch: number, idx: number): Buffer | undefined {
  const es = epochStateFor(f, epoch);
  if (!es || !Number.isInteger(idx) || idx < 0) return undefined;
  const cached = es.skipped[String(idx)];
  if (cached) {
    delete es.skipped[String(idx)];
    return Buffer.from(cached, "hex");
  }
  if (idx < es.recvIdx) return undefined; // already consumed and not cached
  const step = ratchetTo(Buffer.from(es.recvCK, "hex"), es.recvIdx, idx);
  for (const s of step.skipped) es.skipped[String(s.idx)] = s.key.toString("hex");
  es.recvCK = step.ck.toString("hex");
  es.recvIdx = step.nextIdx;
  boundSkipped(es);
  return step.messageKey;
}

function bumpAndMaybeRotate(username: string, f: FriendState) {
  f.sentInEpoch = (f.sentInEpoch ?? 0) + 1;
  if (f.sentInEpoch >= ROTATE_AFTER_MESSAGES) initiateRotation(username);
}

// ── Crypto-aware senders ─────────────────────────────────────────────────────
function sendAesSeed(username: string) {
  const f = state.friends[username];
  if (!f?.pk) return;
  // Encapsulate ONCE and remember (ss, ct). Re-sends reuse the stored ciphertext
  // so a re-handshake keeps both peers on the same shared secret.
  if (!f.mySeed || !f.myCt) {
    const { ct, ss } = hqcEncapsulate(Buffer.from(f.pk, "hex"));
    f.mySeed = ss.toString("hex");
    f.myCt = ct.toString("base64");
  }
  send({ type: Out.AES, payload: f.myCt, targetPk: username });
}

function sendMessage(username: string, text: string) {
  const f = state.friends[username];
  if (!f?.pk) return;
  if (f.cur) {
    // Epoch ≥ 1: seal with the per-message ratchet key, then advance the chain.
    // §KM-1 step 5: no outer per-message HQC — the payload is the AES-GCM base64.
    const mk = messageKey(Buffer.from(f.cur.sendCK, "hex"));
    send({
      type: Out.MESSAGE,
      targetPk: username,
      payload: aesEncrypt(text, mk),
      messageId: crypto.randomUUID(),
      epoch: f.cur.epoch,
      idx: f.cur.sendIdx,
    });
    f.cur.sendCK = chainNext(Buffer.from(f.cur.sendCK, "hex")).toString("hex");
    f.cur.sendIdx++;
    bumpAndMaybeRotate(username, f);
    saveState();
    return;
  }
  // Epoch 0: static channel key (also counts toward the first rotation).
  if (!f.sharedKey) return;
  send({
    type: Out.MESSAGE,
    targetPk: username,
    payload: aesEncrypt(text, Buffer.from(f.sharedKey, "hex")),
    messageId: crypto.randomUUID(),
  });
  bumpAndMaybeRotate(username, f);
  saveState();
}

function gameReply(text: string): string {
  const lower = text.toLowerCase();
  if (lower.startsWith("/game prc")) {
    if (lower.includes("rock")) return "Paper! I win!";
    if (lower.includes("paper")) return "Scissors! I win!";
    if (lower.includes("scissors")) return "Rock! I win!";
    return "I only play rock-paper-scissors. Try sending 'rock', 'paper', or 'scissors'.";
  }
  if (lower.startsWith("/game guess")) {
    const parts = lower.split(" ");
    if (parts.length < 3) return "I only play number guessing with '/game guess <number>'.";
    const numberFromString = parts[2];
    if (numberFromString === undefined) return "I only play number guessing with '/game guess <number>'.";
    const number = parseInt(numberFromString, 10);
    if (isNaN(number) || number < 1 || number > 10) return "Guess a number between 1 and 10.";
    const botNumber = Math.floor(Math.random() * 10) + 1;
    if (number === botNumber) return `You guessed ${number} and I guessed ${botNumber}. You win!`;
    return `You guessed ${number} and I guessed ${botNumber}. I win!`;
  }
  return "I only play rock-paper-scissors or number guessing. Try '/game prc' or '/game guess <number>'.";
}

// ── Bot brain ────────────────────────────────────────────────────────────────
// Testing build: always replies "hello" to any message.
function reply(_text: string): string {
  if (_text.toLowerCase().includes("hello")) return "Hello! I'm a bot. How can I help you?";
  if (_text.toLowerCase().startsWith("martin")) return "go to the url https://martinrougeron.me";
  if (_text.toLowerCase().startsWith("/support")) return "For support, please email contact@martinrougeron.me";
  if (_text.toLowerCase().startsWith("/game")) return gameReply(_text);
  if (_text.toLowerCase().startsWith("/help")) return "I can play simple games or answer basic questions. Try '/game prc' for rock-paper-scissors or '/game guess <number>' to guess a number between 1 and 10.";
  // Default: echo back the message.
  return `You said: "${_text}"`;
}

// ── Self-admission ────────────────────────────────────────────────────────────
// Register our pk in the shared Redis exempt set BEFORE connecting, so it's in
// place by the time the server runs checkAdmission after our AUTH_VERIFY. SADD
// is idempotent; retry a few times so a Redis still coming up at boot doesn't
// leave us un-exempt. Non-fatal: connect regardless (harmless under the default
// open policy, and a later reconnect re-runs this).
async function registerExempt(attempts = 5): Promise<void> {
  for (let i = 1; i <= attempts; i++) {
    try {
      await DB.addAdmissionExempt(pkHex);
      logger.debug("🤖 [bot] self-registered in admission exempt set");
      return;
    } catch (e: any) {
      logger.error(`🤖 [bot] exempt registration failed (try ${i}/${attempts}): ${e.message}`);
      await new Promise((r) => setTimeout(r, 1000 * i));
    }
  }
  logger.error("🤖 [bot] could not register admission exemption — connecting anyway");
}

registerExempt().finally(connect);
