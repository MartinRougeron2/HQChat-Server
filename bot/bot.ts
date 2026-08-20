/**
 * DissQus helper bot — an always-on protocol client.
 *
 * It authenticates like a normal user (HQC-KEM handshake over REST), claims a
 * username, accepts friend invites, completes the KEM secure-channel handshake
 * and replies to messages. Its identity (seed) and per-friend keys are persisted
 * so it survives restarts.
 *
 * TRANSPORT (Phase 4 — see deploy/EXTRACTION_PLAN.md). The bot used to be the
 * heaviest user of the `/ws` monolith: one socket carrying auth, the friend
 * graph, presence and messages. It now speaks exactly what the apps speak —
 * REST for control (auth + friends + username) and MQTT for conversations — so
 * retiring `/ws` leaves it untouched, and there is no protocol only the bot
 * knows how to talk.
 *
 * One behavioural consequence, shared with the apps: nothing pushes graph
 * changes any more, so invites are picked up by POLLING (`FRIEND_POLL_MS`)
 * rather than arriving as an event.
 *
 * The bot is a NORMAL MQTT user, not a service: it connects with its own public
 * key as client id and username and a short-lived token as password, and EMQX
 * holds it to the same per-topic ACL as everyone else. It never touches the
 * `svc-internal` superuser credential — a bot that could read every
 * conversation would undo the point of the ACL.
 *
 * Run on the VPS (it needs the Linux HQC lib). Env:
 *   AUTH_BASE_URL   default http://auth:8080
 *   API_BASE_URL    default http://app-api:8080
 *   EMQX_URL        default ws://emqx:8083/mqtt
 *   BOT_USERNAME    default "helper"
 *   BOT_SEED        32-byte hex seed (optional; generated + saved if absent)
 *
 * The bot self-admits: on startup it writes its own public key into the Redis
 * `admission:exempt` set (shared with the auth server), so it's admitted under
 * any ADMISSION_POLICY without an operator hand-copying its key into
 * EXEMPT_PUBLIC_KEYS. That survives the bot's seed/identity changing.
 */

// First import: loads .env and resolves *_FILE Docker secrets (e.g. BOT_SEED_FILE).
import "../lib/config";
// Init Sentry + global crash handlers (uncaughtException / unhandledRejection)
// before anything else runs — the bot is a long-lived client that must survive
// server hiccups and reconnects without silently dying.
import { initObservability } from "../lib/observability";
initObservability("bot");
import { healthMonitor } from "../lib/health-monitor";
import { logger } from "../lib/logger";
import mqtt, { type MqttClient } from "mqtt";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { HqcWrapper, HQC_CONSTANTS } from "../lib/hqc";
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
import { authProof } from "../lib/auth-proof";
import { friendshipHash } from "../lib/crypto-utils";
import { DB } from "../services/db/api";

const AUTH_BASE = (process.env.AUTH_BASE_URL || "http://auth:8080").replace(/\/$/, "");
const API_BASE = (process.env.API_BASE_URL || "http://app-api:8080").replace(/\/$/, "");
const EMQX_URL = process.env.EMQX_URL || "ws://emqx:8083/mqtt";
const USERNAME = process.env.BOT_USERNAME || "helper";
// Shown by the bot's /support reply. Deployment config, not a code constant.
const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || "support@example.com";
/// How often to re-read the friend graph. There is no server push for it any
/// more, and an invite that waits a few seconds is not worth a second protocol.
const FRIEND_POLL_MS = Number(process.env.FRIEND_POLL_MS || 15_000);
/// Don't re-offer our KEM ciphertext to an unresponsive peer on every single
/// poll — once a minute is enough to heal a handshake that was lost in flight.
const HANDSHAKE_RETRY_MS = 60_000;
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

/** Public keys are 2KB of hex; logs get the ends only. */
function short(hex: string): string {
  return hex.length <= 20 ? hex : `${hex.slice(0, 8)}…${hex.slice(-8)}`;
}

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
  username?: string; // display only — logs and the greeting text
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
  // Whether this user has had the welcome message. Persisted with the rest of
  // the friend state so a bot restart never re-greets someone.
  greeted?: boolean;
}
/// Keyed by the peer's PUBLIC KEY hex — the same identity the conversation
/// topic, the EMQX ACL and the envelope's `sender` are keyed on. It used to be
/// keyed by username, because the `/ws` server resolved names for us; MQTT has
/// no such mediator, and a mutable display name must never be what decides
/// which key decrypts a message.
type State = { friends: Record<string, FriendState> };

let state: State = { friends: {} };

function loadState() {
  if (!fs.existsSync(STATE_FILE)) return;
  let raw: any;
  try { raw = JSON.parse(fs.readFileSync(STATE_FILE, "utf8")); } catch { return; }

  // Migrate username-keyed state (every entry already carries its `pk`) to
  // pk-keyed, keeping the old key as the display name. Entries with no usable
  // pk are dropped: without one there is no topic to reach that peer on, so
  // their keys are unusable regardless.
  const friends: Record<string, FriendState> = {};
  let migrated = 0;
  let dropped = 0;
  for (const [key, entry] of Object.entries((raw?.friends ?? {}) as Record<string, FriendState>)) {
    const peerPk = String(entry?.pk || "").toLowerCase();
    if (!/^[0-9a-f]{16,}$/.test(peerPk)) { dropped++; continue; }
    if (peerPk !== key) {
      if (!entry.username) entry.username = key;
      migrated++;
    }
    entry.pk = peerPk;
    friends[peerPk] = entry;
  }
  state = { friends };
  if (migrated || dropped) {
    logger.startup(`🤖 [bot] state re-keyed by public key: ${migrated} migrated, ${dropped} unusable`);
    saveState();
  }
}
function saveState() {
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2), { mode: 0o600 });
}
loadState();

/** Log/greeting label for a peer — its username if we know one, else its key. */
function label(peerPk: string): string {
  return state.friends[peerPk]?.username || short(peerPk);
}

// ── REST control plane (auth + directory + friend graph) ─────────────────────
// The `/ws` protocol carried all of this inline; it is now plain HTTP against
// the auth server and app-api, exactly as the apps do it.

/** REST session bearer (app-api + token refresh) and the current MQTT password. */
let sessionToken = "";
let mqttToken = "";

/** A 401: the REST session itself is gone, so the KEM handshake must be redone. */
class Unauthenticated extends Error {}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function httpJson(
  url: string,
  opts: { method: string; body?: unknown; bearer?: string }
): Promise<{ status: number; body: any }> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (opts.bearer) headers.authorization = `Bearer ${opts.bearer}`;
  const init: RequestInit = { method: opts.method, headers };
  if (opts.body !== undefined) init.body = JSON.stringify(opts.body);
  const res = await fetch(url, init);
  const text = await res.text();
  let body: any = null;
  try { body = text ? JSON.parse(text) : null; } catch { /* non-JSON error page */ }
  return { status: res.status, body };
}

/** Call app-api with our session bearer. Throws Unauthenticated on 401. */
async function api(method: string, path: string, body?: unknown): Promise<any> {
  const opts: { method: string; body?: unknown; bearer?: string } = { method, bearer: sessionToken };
  if (body !== undefined) opts.body = body;
  const r = await httpJson(`${API_BASE}${path}`, opts);
  if (r.status === 401) throw new Unauthenticated(`${method} ${path} → 401`);
  if (r.status < 200 || r.status >= 300) {
    throw new Error(`${method} ${path} → ${r.status} ${JSON.stringify(r.body)}`);
  }
  return r.body ?? {};
}

/**
 * The HQC-KEM handshake, over REST (auth/main.ts): the server encapsulates to
 * our public key, we decapsulate and return HKDF(ss,"auth") to prove we hold the
 * secret key. We never send ss or any decrypted plaintext. Yields a REST session
 * bearer plus the first (~5m) MQTT connect token.
 */
async function handshake(): Promise<void> {
  const init = await httpJson(`${AUTH_BASE}/auth/init`, { method: "POST", body: { pk: pkHex } });
  if (init.status !== 200 || typeof init.body?.ct !== "string") {
    throw new Error(`/auth/init → ${init.status}`);
  }
  const ss = hqcDecapsulate(sk, Buffer.from(init.body.ct, "base64"));
  const verify = await httpJson(`${AUTH_BASE}/auth/verify`, {
    method: "POST",
    body: { pk: pkHex, solution: authProof(ss).toString("base64") },
  });
  if (verify.status === 402 || verify.status === 403) {
    // Self-admission (registerExempt) should make this impossible; if it does
    // happen the Redis exempt write failed, so say so rather than spin silently.
    throw new Error(`not admitted (${verify.status}) — the admission exemption did not stick`);
  }
  if (verify.status !== 200 || typeof verify.body?.sessionToken !== "string") {
    throw new Error(`/auth/verify → ${verify.status}`);
  }
  sessionToken = verify.body.sessionToken;
  mqttToken = String(verify.body.mqttToken || "");
  logger.startup(`🤖 [bot] authenticated as ${short(pkHex)}`);
}

/**
 * Rotate the MQTT token on the existing REST session — the ordinary path after
 * EMQX force-disconnects us at token expiry. Returns false when the session
 * itself has lapsed (401), which is the caller's cue to redo the handshake.
 */
async function refreshMqttToken(): Promise<boolean> {
  if (!sessionToken) return false;
  const r = await httpJson(`${AUTH_BASE}/auth/refresh`, { method: "POST", bearer: sessionToken });
  if (r.status === 401) return false;
  if (r.status !== 200 || typeof r.body?.mqttToken !== "string") {
    throw new Error(`/auth/refresh → ${r.status}`);
  }
  mqttToken = r.body.mqttToken;
  return true;
}

/** Claim the reserved handle. app-api lets an admission-exempt pk reclaim it. */
async function claimUsername(): Promise<void> {
  await api("POST", "/username", { username: USERNAME });
  logger.startup(`🤖 [bot] username @${USERNAME}`);
}

/**
 * Re-read the friend graph: auto-accept anything pending, then make sure every
 * friend has state, a subscription and a secure channel. This is the whole
 * replacement for FRIEND_REQUEST / FRIEND_ADDED — there is nothing to push it
 * to us any more.
 */
async function syncGraph(): Promise<void> {
  const invites = await api("GET", "/friends/invites");
  for (const invite of (invites?.invites ?? []) as Array<{ pk?: string; username?: string }>) {
    const from = String(invite?.pk || "").toLowerCase();
    if (!from) continue;
    logger.debug(`🤖 [bot] invite from @${invite?.username ?? short(from)} — accepting`);
    // Accepting is also what grants BOTH of us the conversation topic in the
    // EMQX ACL, so it must land before we try to subscribe.
    await api("POST", "/friends/accept", { from });
  }

  const list = await api("GET", "/friends");
  for (const friend of (list?.friends ?? []) as Array<{ pk?: string; username?: string }>) {
    const peerPk = String(friend?.pk || "").toLowerCase();
    if (!/^[0-9a-f]{16,}$/.test(peerPk) || peerPk === pkHex) continue;
    trackFriend(peerPk, String(friend?.username || ""));
  }
}

/** Ensure state + subscription + key agreement for one peer. Idempotent. */
function trackFriend(peerPk: string, username: string) {
  const known = state.friends[peerPk];
  const f: FriendState = known ?? { pk: peerPk };
  const renamed = !!username && username !== f.username;
  if (renamed) f.username = username;
  state.friends[peerPk] = f;
  // The poll runs every few seconds; only touch the state file when it changed.
  if (!known || renamed) saveState();
  if (!known) logger.debug(`🤖 [bot] friend: @${username || short(peerPk)}`);
  subscribeConversation(peerPk);
  // No channel yet (fresh friend, or a handshake lost while one side was down).
  // Re-offering our ciphertext is safe — sendAesSeed reuses the stored one.
  if (!f.sharedKey && !f.cur) maybeOfferSeed(peerPk);
}

const lastSeedOffer = new Map<string, number>();
/** Offer our KEM ciphertext, at most once per HANDSHAKE_RETRY_MS per peer. */
function maybeOfferSeed(peerPk: string) {
  if (!client?.connected) return; // nothing to publish onto yet; CONNACK retries
  const now = Date.now();
  if (now - (lastSeedOffer.get(peerPk) ?? 0) < HANDSHAKE_RETRY_MS) return;
  lastSeedOffer.set(peerPk, now);
  sendAesSeed(peerPk);
}

// ── MQTT conversations ───────────────────────────────────────────────────────
// One topic per friendship, `c/{friendshipHash}`, which only the two members may
// publish to (EMQX enforces it from the Redis ACL app-api maintains). The broker
// sees ciphertext and our own public key, never plaintext.

let client: MqttClient | null = null;
/** True while a relink is already scheduled/in flight, so one drop = one retry. */
let relinking = false;
let relinkDelay = 2_000;
const MAX_RELINK_MS = 30_000;
/** Bumped per connection. A discarded client's late `close` carries the old
 *  generation, so it can be ignored instead of tearing down its replacement.
 *  (We can't just drop its listeners — mqtt.js keeps its own on the client.) */
let linkGeneration = 0;

function convoTopic(peerPk: string): string {
  return `c/${friendshipHash(pkHex, peerPk)}`;
}
const PRESENCE_TOPIC = `u/${pkHex}/presence`;
const PRESENCE_ONLINE = JSON.stringify({ s: "online" });
const PRESENCE_OFFLINE = JSON.stringify({ s: "offline" });

/**
 * What one conversation payload carries. This is the wire contract with the
 * apps' `ConversationEnvelope` (ConversationRouter.swift) and must stay
 * byte-compatible with it. `sender` is the PUBLIC KEY hex, not a username.
 */
interface Envelope {
  type: "message" | "aes" | "key_rotate";
  sender: string;
  payload: string;
  messageId?: string;
  epoch?: number;
  idx?: number;
}

function publish(peerPk: string, envelope: Envelope) {
  if (!client) return;
  // QoS 1 into the client's own outgoing store: a publish issued while the link
  // is down is delivered on the next connect rather than lost.
  client.publish(convoTopic(peerPk), JSON.stringify(envelope), { qos: 1 });
}

function subscribeConversation(peerPk: string) {
  if (!client?.connected) return; // (re)subscribed wholesale on CONNACK
  client.subscribe(convoTopic(peerPk), { qos: 1 }, (err) => {
    if (err) logger.error(`🤖 [bot] subscribe ${label(peerPk)}: ${err.message}`);
  });
}

function connectMqtt() {
  const gen = ++linkGeneration;
  logger.debug(`🤖 [bot] connecting to ${EMQX_URL} as ${short(pkHex)}`);
  const c = mqtt.connect(EMQX_URL, {
    // The client id IS the public key: EMQX keys the topic ACL on it, and a
    // duplicate id kicks the previous session (single-session enforcement).
    clientId: pkHex,
    username: pkHex,
    password: mqttToken,
    // Persistent session — this IS the offline queue. Messages published to our
    // conversations while the bot is restarting are held by the broker and
    // delivered on reconnect, which is what the `/ws` pending-queue used to do.
    clean: false,
    // We reconnect by hand, because a reconnect needs a FRESH token: the library
    // would happily retry forever with the expired password that just got us
    // disconnected.
    reconnectPeriod: 0,
    keepalive: 30,
    will: {
      topic: PRESENCE_TOPIC,
      payload: Buffer.from(PRESENCE_OFFLINE),
      qos: 1,
      retain: true,
    },
  });
  client = c;

  c.on("connect", () => {
    relinkDelay = 2_000;
    logger.startup(`🤖 [bot] connected to EMQX at ${EMQX_URL}`);
    c.publish(PRESENCE_TOPIC, PRESENCE_ONLINE, { qos: 1, retain: true });
    for (const [peerPk, f] of Object.entries(state.friends)) {
      subscribeConversation(peerPk);
      // Anything that was still mid-handshake when the link died: the offers
      // made while we were down went nowhere, so make them again now.
      if (!f.sharedKey && !f.cur) maybeOfferSeed(peerPk);
    }
  });
  c.on("message", (topic, payload) => { void onEnvelope(topic, payload); });
  c.on("error", (e) => logger.error(`🤖 [bot] mqtt: ${e.message}`));
  c.on("close", () => { if (gen === linkGeneration) relink("connection closed"); });
}

/**
 * Come back after a drop. EMQX disconnects us at token expiry (~5m), so the
 * first thing a reconnect needs is a new password: rotate it on the REST
 * session, and if that session has lapsed too, redo the whole KEM handshake.
 */
function relink(why: string) {
  if (relinking) return;
  relinking = true;
  const stale = client;
  client = null;
  stale?.end(true); // force — the link is already gone; don't wait on DISCONNECT
  const delay = relinkDelay;
  relinkDelay = Math.min(MAX_RELINK_MS, relinkDelay * 2);
  logger.warn(`🤖 [bot] link down (${why}) — reconnecting in ${delay}ms`);
  setTimeout(() => {
    void (async () => {
      try {
        if (!(await refreshMqttToken())) await handshake();
        relinking = false;
        connectMqtt();
      } catch (e: any) {
        logger.error(`🤖 [bot] reconnect failed: ${e.message}`);
        relinking = false;
        relink("reconnect failed");
      }
    })();
  }, delay);
}

/** Inbound conversation payload. */
async function onEnvelope(topic: string, raw: Buffer) {
  let env: any;
  try { env = JSON.parse(raw.toString("utf8")); } catch { return; }

  const sender = typeof env?.sender === "string" ? env.sender.toLowerCase() : "";
  // MQTT delivers our own publishes back to us (we subscribe to the topic we
  // publish on). Nothing to do with them.
  if (!sender || sender === pkHex) return;

  const f = state.friends[sender];
  if (!f) return;
  // The topic is derived from the two public keys, so a payload naming a
  // `sender` who is not a member of THIS conversation is not addressable state.
  if (topic !== convoTopic(sender)) return;

  switch (env.type) {
    case "aes": {
      try {
        // Decapsulate the peer's KEM ciphertext → the shared secret they contributed.
        const peerSs = hqcDecapsulate(sk, Buffer.from(String(env.payload), "base64"));
        f.peerSeed = peerSs.toString("hex");
        // (Re)send OUR encapsulation so the peer can derive too. sendAesSeed reuses
        // our stored ciphertext (f.myCt) if present, so on a re-handshake we resend
        // the SAME encapsulation rather than a new one — both sides stay on one key.
        // The peer only replies while it has no secret of its own, so this can't loop.
        sendAesSeed(sender);
        if (f.mySeed && f.peerSeed) {
          const key = deriveSharedKey(Buffer.from(f.mySeed, "hex"), Buffer.from(f.peerSeed, "hex"));
          f.sharedKey = key.toString("hex");
          logger.debug(`🔒 [bot] secure channel established with @${label(sender)}`);
          greet(sender);
        }
        saveState();
      } catch (e: any) {
        logger.error(`🤖 [bot] AES handshake error with @${label(sender)}:`, e.message);
      }
      break;
    }

    case "message": {
      const epoch = Number.isInteger(env.epoch) ? Number(env.epoch) : 0;
      try {
        // §KM-1 step 5: the per-message outer HQC layer is gone. The payload is
        // the AES-GCM base64 directly, sealed under the ratchet key (epoch ≥ 1) or
        // the epoch-0 static channel key.
        const aesB64 = String(env.payload);
        let text: string;
        if (epoch >= 1) {
          const mk = obtainRecvKey(f, epoch, Number(env.idx));
          if (!mk) {
            logger.error(`🤖 [bot] no ratchet key for @${label(sender)} (epoch ${epoch}, idx ${env.idx})`);
            break;
          }
          text = aesDecrypt(aesB64, mk);
          saveState();
        } else {
          if (!f.sharedKey) break;
          text = aesDecrypt(aesB64, Buffer.from(f.sharedKey, "hex"));
        }
        const answer = reply(text);
        logger.debug(`💬 [bot] @${label(sender)}: ${text}  →  ${answer.split("\n")[0]}`);
        sendMessage(sender, answer);
      } catch (e: any) {
        logger.error(`🤖 [bot] message decrypt error from @${label(sender)}:`, e.message);
      }
      break;
    }

    case "key_rotate": {
      // Tier-1 epoch re-handshake — a near-clone of the AES case, epoch-scoped.
      if (!f.pk) break;
      const epoch = Number(env.epoch);
      if (!Number.isInteger(epoch) || epoch <= currentEpoch(f)) break; // stale/duplicate
      try {
        const peerSs = hqcDecapsulate(sk, Buffer.from(String(env.payload), "base64"));
        if (!f.rot || f.rot.epoch !== epoch) f.rot = { epoch }; // peer-initiated
        f.rot.peerSeed = peerSs.toString("hex");
        // Contribute our own encapsulation for this epoch if we haven't yet
        // (symmetric: each side sends exactly one, so simultaneous rotation needs
        // no tie-break).
        if (!f.rot.mySeed) {
          const { ct, ss } = hqcEncapsulate(Buffer.from(f.pk, "hex"));
          f.rot.mySeed = ss.toString("hex");
          f.rot.myCt = ct.toString("base64");
          publish(sender, { type: "key_rotate", sender: pkHex, payload: f.rot.myCt, epoch });
        }
        if (f.rot.mySeed && f.rot.peerSeed) {
          installEpoch(sender, f, epoch, Buffer.from(f.rot.mySeed, "hex"), Buffer.from(f.rot.peerSeed, "hex"));
        }
        saveState();
      } catch (e: any) {
        logger.error(`🤖 [bot] key_rotate error with @${label(sender)}:`, e.message);
      }
      break;
    }
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
function installEpoch(peerPk: string, f: FriendState, epoch: number, mySeed: Buffer, peerSeed: Buffer) {
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
  logger.debug(`🔄 [bot] installed epoch ${epoch} with @${label(peerPk)}`);
}

/** Start a Tier-1 rotation to the next epoch by sending our fresh seed. */
function initiateRotation(peerPk: string) {
  const f = state.friends[peerPk];
  if (!f?.pk) return;
  const nextEpoch = currentEpoch(f) + 1;
  if (f.rot && f.rot.epoch >= nextEpoch) return; // one already in flight
  const { ct, ss } = hqcEncapsulate(Buffer.from(f.pk, "hex"));
  f.rot = { epoch: nextEpoch, mySeed: ss.toString("hex"), myCt: ct.toString("base64") };
  publish(peerPk, { type: "key_rotate", sender: pkHex, payload: f.rot.myCt!, epoch: nextEpoch });
  saveState();
  logger.debug(`🔄 [bot] initiating rotation to epoch ${nextEpoch} with @${label(peerPk)}`);
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

function bumpAndMaybeRotate(peerPk: string, f: FriendState) {
  f.sentInEpoch = (f.sentInEpoch ?? 0) + 1;
  if (f.sentInEpoch >= ROTATE_AFTER_MESSAGES) initiateRotation(peerPk);
}

// ── Crypto-aware senders ─────────────────────────────────────────────────────
function sendAesSeed(peerPk: string) {
  const f = state.friends[peerPk];
  if (!f?.pk) return;
  // Encapsulate ONCE and remember (ss, ct). Re-sends reuse the stored ciphertext
  // so a re-handshake keeps both peers on the same shared secret.
  if (!f.mySeed || !f.myCt) {
    const { ct, ss } = hqcEncapsulate(Buffer.from(f.pk, "hex"));
    f.mySeed = ss.toString("hex");
    f.myCt = ct.toString("base64");
    saveState();
  }
  publish(peerPk, { type: "aes", sender: pkHex, payload: f.myCt });
}

/** The first thing a new user ever receives. The server auto-friends the bot to
 *  every account, so this lands moments after the first login — which used to
 *  leave the new user staring at an empty conversation with an account they
 *  hadn't chosen and no idea what it was for.
 *
 *  Sent exactly once per user (`greeted`, persisted), and only after the secure
 *  channel exists — there is no unencrypted path to send it on. */
function greet(peerPk: string) {
  const f = state.friends[peerPk];
  if (!f || f.greeted) return;
  f.greeted = true;
  saveState();
  const name = f.username || "there";
  // A beat, so the peer has certainly installed its side of the channel before
  // the first ciphertext arrives (the AES frame precedes this one on the wire,
  // but the client's handshake work is asynchronous).
  setTimeout(() => {
    sendMessage(
      peerPk,
      [
        `welcome to dissqus, @${name}.`,
        "",
        "i'm helper — the account you start with, so your first conversation isn't an empty screen. this chat is end-to-end encrypted like every other one: the server relays it and can't read it.",
        "",
        "try /help for what i can do, or just say hello.",
      ].join("\n")
    );
    logger.debug(`👋 [bot] greeted @${label(peerPk)}`);
  }, 1500);
}

function sendMessage(peerPk: string, text: string) {
  const f = state.friends[peerPk];
  if (!f?.pk) return;
  if (f.cur) {
    // Epoch ≥ 1: seal with the per-message ratchet key, then advance the chain.
    // §KM-1 step 5: no outer per-message HQC — the payload is the AES-GCM base64.
    const mk = messageKey(Buffer.from(f.cur.sendCK, "hex"));
    publish(peerPk, {
      type: "message",
      sender: pkHex,
      payload: aesEncrypt(text, mk),
      messageId: crypto.randomUUID(),
      epoch: f.cur.epoch,
      idx: f.cur.sendIdx,
    });
    f.cur.sendCK = chainNext(Buffer.from(f.cur.sendCK, "hex")).toString("hex");
    f.cur.sendIdx++;
    bumpAndMaybeRotate(peerPk, f);
    saveState();
    return;
  }
  // Epoch 0: static channel key (also counts toward the first rotation).
  if (!f.sharedKey) return;
  publish(peerPk, {
    type: "message",
    sender: pkHex,
    payload: aesEncrypt(text, Buffer.from(f.sharedKey, "hex")),
    messageId: crypto.randomUUID(),
  });
  bumpAndMaybeRotate(peerPk, f);
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
  if (_text.toLowerCase().startsWith("/support")) return `For support, please email ${SUPPORT_EMAIL}`;
  if (_text.toLowerCase().startsWith("/game")) return gameReply(_text);
  if (_text.toLowerCase().startsWith("/help")) return "I can play simple games or answer basic questions. Try '/game prc' for rock-paper-scissors or '/game guess <number>' to guess a number between 1 and 10.";
  // Default: echo back the message.
  return `You said: "${_text}"`;
}

// ── Self-admission ────────────────────────────────────────────────────────────
// Register our pk in the shared Redis exempt set BEFORE authenticating, so it's
// in place by the time the auth server runs checkAdmission on our /auth/verify.
// SADD is idempotent; retry a few times so a Redis still coming up at boot
// doesn't leave us un-exempt. Non-fatal: connect regardless (harmless under the
// default open policy, and a later reconnect re-runs the handshake).
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

// ── Boot ─────────────────────────────────────────────────────────────────────

/** One poll of the friend graph, re-authenticating if the session has lapsed. */
async function pollGraph(): Promise<void> {
  try {
    await syncGraph();
  } catch (e: any) {
    if (!(e instanceof Unauthenticated)) {
      logger.error(`🤖 [bot] friend poll: ${e.message}`);
      return;
    }
    logger.warn("🤖 [bot] REST session lapsed — redoing the handshake");
    try {
      await handshake();
      await claimUsername();
      await syncGraph();
    } catch (e2: any) {
      logger.error(`🤖 [bot] re-authentication failed: ${e2.message}`);
    }
  }
}

/** Authenticate, claim the handle, learn the graph, then open the broker link.
 *  Retries with backoff so a bot that boots before auth/app-api are up recovers
 *  on its own instead of exiting into a restart loop. */
async function start(): Promise<void> {
  for (let attempt = 1; ; attempt++) {
    try {
      await handshake();
      await claimUsername();
      await syncGraph(); // populate state BEFORE connecting, so CONNACK subscribes everything
      connectMqtt();
      setInterval(() => { void pollGraph(); }, FRIEND_POLL_MS);
      return;
    } catch (e: any) {
      const wait = Math.min(30_000, 2_000 * attempt);
      logger.error(`🤖 [bot] startup attempt ${attempt} failed (${e.message}) — retrying in ${wait}ms`);
      await sleep(wait);
    }
  }
}

// Event-loop / memory / Redis-latency early warning → Sentry.
healthMonitor.start();

registerExempt().finally(() => { void start(); });
