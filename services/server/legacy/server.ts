// DEPRECATED — NOT DEPLOYED. This is the original single-`/ws` monolith. As of
// Phase 4 (deploy/EXTRACTION_PLAN.md) nothing runs it: it is absent from
// deploy/docker-compose.yml, there is no `/ws` location in nginx, and both the
// apps and the helper bot speak REST (auth/main.ts + api/main.ts) and MQTT
// instead. Do not add features here, and do not point a client at it.
//
// It stays in the tree on purpose: test/e2e.test.ts and
// test/account-delete.e2e.test.ts drive it end-to-end and are the only coverage
// we have of the HQC handshake and the double ratchet running against a real
// server. Deleting the file would delete that.
//
// Must be first: loads .env, resolves *_FILE Docker secrets, and prepares
// process.env before any service module reads it (assertConfig is called below).
import { assertConfig } from "../lib/config";
// Second: init Sentry + global crash handlers before anything else can throw.
import { initObservability } from "../lib/observability";
initObservability("server");
import { logger } from "../lib/logger";
import { healthMonitor } from "../lib/health-monitor";
import { WebSocketServer, WebSocket } from "ws";
import * as http from "http";
import * as crypto from "crypto";
import { HqcWrapper, HQC_CONSTANTS } from "../lib/hqc";
import { DB } from "../services/db/api"; // See DB changes below
import { ApnsService } from "../services/apns/api";
import { MessageTypesToSent, MessageTypesToReceive } from "./enums";
import { checkAdmission, ADMISSION_POLICY } from "../lib/admission";
import {
  aesEncrypt,
  unwrap,
  deriveSessionKeys,
  encapsulateSession,
  authProof,
} from "./secure-transport";

// --- TYPES ---
interface AuthState {
  step: "INIT" | "CHALLENGE_SENT" | "AUTHENTICATED";
  publicKey?: string;
  username?: string; // Cache username after auth/set
  // KEM auth (§KM-1): the proof we expect the client to return — HKDF(ss,"auth")
  // where ss is the shared secret only the sk-holder can decapsulate. We never
  // send ss or any decrypted plaintext, so there is no decryption oracle.
  expectedProof?: Buffer | undefined;
  // Per-connection transport-encryption keys (per direction). Once set (right
  // after auth), outgoing frames are AES-GCM encrypted with txKey (s2c) and
  // incoming frames decrypted with rxKey (c2s). See deriveSessionKeys.
  txKey?: Buffer; // server→client
  rxKey?: Buffer; // client→server
  // The client told us it went into the background. iOS keeps the socket open
  // while it suspends the app, so "the socket is open" is not the same as "the
  // user can receive anything" — a suspended client is treated exactly like an
  // offline one: queue the message and push, don't relay into a frozen socket.
  suspended?: boolean;
}

interface ChatSocket extends WebSocket {
  auth: AuthState;
  isAlive: boolean;
  // Throttled diagnostics for the call media relay (optional, lazily set).
  mediaRelayCount?: number;
  mediaDropCount?: number;
  // Count of frames received before AUTHENTICATED (pre-auth flood guard).
  preAuthMsgs?: number;
  // Per-socket cache of usernames confirmed as friends, so relay handlers
  // (esp. high-rate call media) don't hit the database on every frame.
  friendCache?: Map<string, boolean>;
}

const PORT = Number(process.env.PORT) || 8080;

// --- SERVER IDENTITY & ADMISSION (self-host config) ------------------------
// A DissQus server is an open component anyone can run. /info advertises this.
const PROTOCOL_VERSION = 1;
const SERVER_NAME = process.env.SERVER_NAME || "DissQus";
const SERVER_VERSION = "0.1.0";
// Admission policy (open | allowlist | stripe) + checkAdmission now live in
// lib/admission.ts, shared with the extracted auth server (auth/main.ts) so both
// enforce identical rules. ADMISSION_POLICY + checkAdmission are imported above.

// HTTP server hosts the Stripe webhook + a health check, and the WebSocket
// server is attached to it (so nginx can proxy both /ws and /stripe/webhook).
const httpServer = http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    return res.end("ok");
  }

  // Crash early-warning metrics. Returns the same snapshot the alerting uses, so
  // the stress test (and any external monitor) can read the leading indicators
  // — event-loop lag, rss, ws clients, active handles, and query latency
  // (p50/p99/max + slowest ops) — and tune thresholds.
  // Optional bearer guard: set METRICS_TOKEN to require ?token= / Authorization.
  if (req.method === "GET" && req.url && req.url.startsWith("/metrics")) {
    const token = process.env.METRICS_TOKEN; // resolved from METRICS_TOKEN_FILE by config.ts
    // Fail closed in production (SRV-2): /metrics leaks health/vitals topology,
    // so an unauthenticated prod endpoint is refused rather than served. nginx
    // does not proxy /metrics (localhost:8080 only), but this is defence in depth
    // for any future exposure. Set METRICS_TOKEN(_FILE) to enable authenticated
    // scraping in prod; dev/test (NODE_ENV!=production) stays open when unset.
    if (!token && process.env.NODE_ENV === "production") {
      res.writeHead(404, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ error: "not found" }));
    }
    if (token) {
      const u = new URL(req.url, "http://localhost");
      const provided =
        u.searchParams.get("token") ||
        (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
      if (provided !== token) {
        res.writeHead(401, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: "unauthorized" }));
      }
    }
    const snap = healthMonitor.getSnapshot();
    res.writeHead(snap ? 200 : 503, {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    });
    return res.end(
      JSON.stringify(
        snap
          ? { ...snap, thresholds: healthMonitor.getThresholds() }
          : { status: "starting" }
      )
    );
  }

  // Server discovery: lets a client validate a URL, learn the admission policy
  // (so it can show/hide the subscription UI), and check protocol compatibility.
  if (req.method === "GET" && req.url === "/info") {
    res.writeHead(200, {
      "Content-Type": "application/json",
      "X-Content-Type-Options": "nosniff",
      "Access-Control-Allow-Origin": "*",
    });
    return res.end(
      JSON.stringify({
        name: SERVER_NAME,
        version: SERVER_VERSION,
        protocolVersion: PROTOCOL_VERSION,
        admission: ADMISSION_POLICY,
        features: ["calls", "photos"],
      })
    );
  }

  res.writeHead(404);
  res.end();
});

// maxPayload caps a single WS frame (~4 MB) — enough for a compressed photo
// inside the transport envelope, but bounds memory abuse from oversized frames.
const wss = new WebSocketServer({
  server: httpServer,
  path: "/ws",
  maxPayload: 4 * 1024 * 1024,
});

// CRASH FIX: without this listener, an "error" emitted on the WebSocketServer
// (e.g. an upgrade/handshake failure under a connection flood) is re-thrown and
// takes the whole process down. Capture instead. (Per-socket "error" listeners
// are attached in the connection handler below — that was the actual killer.)
wss.on("error", (err) => {
  healthMonitor.noteError();
  logger.error("[wss] server error", err);
});

// The HTTP server can also emit "error" (e.g. EADDRINUSE, client socket resets
// on the upgrade path). Same rule: capture, don't crash.
httpServer.on("error", (err) => {
  healthMonitor.noteError();
  logger.error("[http] server error", err);
});

// Map<Username, ChatSocket> - For routing by Username
const onlineUsers = new Map<string, ChatSocket>();
// Map<PublicKey, ChatSocket> - For cleanup/auth
const onlinePks = new Map<string, ChatSocket>();

// --- RATE LIMITING (per-IP, in-memory) -------------------------------------
// Bounds pre-auth abuse: connection floods and message spraying before a client
// has proven its identity. Behind Cloudflare/nginx the real client IP is in
// x-forwarded-for. Not a substitute for an edge WAF, but a cheap first line.
const RATE_WINDOW_MS = 60_000;
// New sockets per IP per minute. Overridable (env) so a load test — where every
// synthetic client shares one source IP — can raise the ceiling; the default
// stays 30 for real deployments.
const MAX_CONNECTIONS_PER_WINDOW = Number(process.env.MAX_CONNECTIONS_PER_WINDOW) || 30;
const MAX_PREAUTH_MSGS = 20;           // frames allowed before AUTHENTICATED
const ipConnections = new Map<string, { count: number; windowStart: number }>();

// Resolve the client IP used for per-IP rate limiting (SRV-1). The naive
// "first X-Forwarded-For token" is fully client-controlled: anyone who can reach
// the origin directly can spoof it and evade the limits entirely. Our ingress is
// locked to Cloudflare-only (deploy/scripts/harden-vm.sh) and fronted by nginx,
// which applies `real_ip_header CF-Connecting-IP` from Cloudflare's ranges, so we
// trust — in order — only values our own edge sets:
//
//   1. `CF-Connecting-IP` — set by Cloudflare and *overwritten* on every request,
//      so a client can't forge it. Present only if the origin is hit directly by
//      CF (no nginx hop); nginx does not forward it upstream. Disable with
//      TRUST_CF_CONNECTING_IP=false for a non-Cloudflare deployment.
//   2. `X-Real-IP` — nginx sets this to the resolved real client IP ($remote_addr
//      after the CF real-ip rewrite): a single, clean, trusted value.
//   3. The Nth X-Forwarded-For token counted from the RIGHT, where N =
//      TRUSTED_PROXY_HOPS (the number of proxies WE operate; nginx = 1). The
//      rightmost token is the one nginx appends and can't be spoofed past it; the
//      leftmost tokens are attacker-supplied and must never be trusted.
//   4. The raw socket address as a last resort.
const TRUSTED_PROXY_HOPS = Math.max(1, Number(process.env.TRUSTED_PROXY_HOPS) || 1);
function clientIp(req: http.IncomingMessage): string {
  if (process.env.TRUST_CF_CONNECTING_IP !== "false") {
    const cf = ((req.headers["cf-connecting-ip"] as string) || "").trim();
    if (cf) return cf;
  }
  const realIp = ((req.headers["x-real-ip"] as string) || "").trim();
  if (realIp) return realIp;

  const xff = ((req.headers["x-forwarded-for"] as string) || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (xff.length) {
    const idx = Math.max(0, xff.length - TRUSTED_PROXY_HOPS);
    return xff[idx] ?? req.socket.remoteAddress ?? "unknown";
  }
  return req.socket.remoteAddress || "unknown";
}

function allowConnection(ip: string): boolean {
  const now = Date.now();
  const entry = ipConnections.get(ip);
  if (!entry || now - entry.windowStart > RATE_WINDOW_MS) {
    ipConnections.set(ip, { count: 1, windowStart: now });
    return true;
  }
  entry.count++;
  return entry.count <= MAX_CONNECTIONS_PER_WINDOW;
}

// --- PRESENCE ---

/** Tell a user's online friends that they came online / went offline. */
/**
 * The socket to deliver to, or undefined when this user cannot receive right
 * now. "Open" was the only test before, which quietly included clients iOS had
 * suspended: their messages were written into a socket nobody was reading,
 * neither queued nor pushed, until the 30s heartbeat finally reaped it.
 */
function deliverySocket(username: string): ChatSocket | undefined {
  const sock = onlineUsers.get(username);
  if (!sock || sock.readyState !== WebSocket.OPEN) return undefined;
  if (sock.auth.suspended) return undefined;
  return sock;
}

// --- Offline queue (this file only) -----------------------------------------
//
// `pending:{pk}` used to live in the shared store, and this is the only code
// that ever read or wrote it — EMQX owns offline delivery for the deployed
// stack, so nothing in production has a queue to keep. It did not survive the
// move to Postgres, and it did not need to: this is a single-process test
// server, so a Map is a faithful stand-in for what a list key was doing.
//
// Bounded the same way it was, so a sender still cannot balloon a recipient's
// memory. There is no TTL because the process does not outlive a test run.
const MAX_PENDING = 500;
const pendingQueues = new Map<string, object[]>();

/** Queue a ready-to-send envelope for a recipient who is currently offline.
 *  Oldest-first, so a flush delivers in chronological order. */
function enqueuePending(targetPk: string, envelope: object) {
  const queue = pendingQueues.get(targetPk) ?? [];
  queue.push(envelope);
  if (queue.length > MAX_PENDING) queue.splice(0, queue.length - MAX_PENDING);
  pendingQueues.set(targetPk, queue);
}

/** Read and clear a recipient's queue. */
function flushPending(targetPk: string): object[] {
  const queue = pendingQueues.get(targetPk) ?? [];
  pendingQueues.delete(targetPk);
  return queue;
}

/** Deliver everything queued for this user while they were away. */
async function flushPendingTo(ws: ChatSocket, label: string) {
  const pending = flushPending(ws.auth.publicKey!);
  if (pending.length === 0) return;
  logger.debug(`📬 [${label}] Delivering ${pending.length} queued message(s)`);
  for (const envelope of pending) {
    ws.send(JSON.stringify(envelope));

    // Now that it's delivered, flip the sender's status queued → delivered
    // (if they're online to receive the receipt).
    const env = envelope as any;
    if (
      env.type === MessageTypesToReceive.DIRECT_MESSAGE &&
      env.messageId &&
      env.sender
    ) {
      const receipt = {
        type: MessageTypesToReceive.MESSAGE_DELIVERED,
        messageId: env.messageId,
      };
      const senderSock = deliverySocket(env.sender);
      if (senderSock) {
        senderSock.send(JSON.stringify(receipt));
        logger.debug(`✅ [${env.sender}] queued→delivered (${env.messageId})`);
      } else {
        // Sender away too — queue the receipt for their next sign-in.
        const senderPk = await DB.getPkByUsername(env.sender);
        if (senderPk) enqueuePending(senderPk, receipt);
      }
    }
  }
}

async function broadcastPresence(pk: string, username: string, online: boolean) {
  const type = online
    ? MessageTypesToReceive.USER_ONLINE
    : MessageTypesToReceive.USER_OFFLINE;
  const friends = await DB.getFriendsList(pk);
  for (const f of friends) {
    const sock = onlinePks.get(f.pk);
    if (sock && sock.readyState === WebSocket.OPEN) {
      sock.send(JSON.stringify({ type, sender: username }));
    }
  }
}

/**
 * Make the helper bot a friend of every user automatically. Creates the
 * friendship (idempotent) and sends FRIEND_ADDED both ways so the AES handshake
 * runs — so a new user can message the bot without adding it manually.
 */
async function ensureBotFriend(ws: ChatSocket) {
  const BOT = process.env.BOT_USERNAME || "helper";
  if (!ws.auth.username || ws.auth.username === BOT) return;

  const botPk = await DB.getPkByUsername(BOT);
  if (!botPk || botPk === ws.auth.publicKey) return; // bot not registered yet

  if (!(await DB.areFriends(ws.auth.publicKey!, botPk))) {
    await DB.createFriendship(ws.auth.publicKey!, botPk);
  }

  // Tell this user about the bot (client creates the Friend + handshakes).
  ws.send(
    JSON.stringify({ type: MessageTypesToReceive.FRIEND_ADDED, username: BOT, pk: botPk })
  );

  // Tell the bot about this user (so it handshakes back). Queue it when the bot
  // is offline so it learns the user — with pk — on its next reconnect and can
  // initiate the handshake. Without this, a user who joins while the bot is down
  // never gets a secure channel (the bot never hears about them).
  const friendAdded = {
    type: MessageTypesToReceive.FRIEND_ADDED,
    username: ws.auth.username,
    pk: ws.auth.publicKey,
  };
  const botSock = onlineUsers.get(BOT);
  if (botSock && botSock.readyState === WebSocket.OPEN) {
    botSock.send(JSON.stringify(friendAdded));
  } else {
    enqueuePending(botPk, friendAdded);
  }
}

/** On connect, tell this user which of their friends are already online. */
async function sendOnlineFriendsTo(ws: ChatSocket, pk: string) {
  const friends = await DB.getFriendsList(pk);
  for (const f of friends) {
    if (onlinePks.has(f.pk)) {
      ws.send(
        JSON.stringify({ type: MessageTypesToReceive.USER_ONLINE, sender: f.username })
      );
    }
  }
}

// --- CONTROLLERS ---

/** Friendship check with a per-socket cache (relay handlers call this a lot —
 *  notably call media at ~20/s — so we avoid a database round-trip per frame). */
async function isVerifiedFriend(ws: ChatSocket, targetUsername: string): Promise<boolean> {
  if (!ws.auth.publicKey) return false;
  if (!ws.friendCache) ws.friendCache = new Map();
  const cached = ws.friendCache.get(targetUsername);
  if (cached !== undefined) return cached;
  const targetPk = await DB.getPkByUsername(targetUsername);
  const ok = !!targetPk && (await DB.checkFriendship(ws.auth.publicKey, targetPk));
  ws.friendCache.set(targetUsername, ok);
  return ok;
}

const Handlers = {
  async onAuthInit(ws: ChatSocket, pkHex: string) {
    const senderId = pkHex.substring(0, 8);
    logger.debug(`📤 [${senderId}] Sending: AUTH_INIT`);

    // Validate the public key shape BEFORE any expensive work — pkHex is
    // attacker-controlled and gets passed to HQC and (after auth) Stripe.
    if (!/^[0-9a-fA-F]+$/.test(pkHex) ||
      pkHex.length !== HQC_CONSTANTS.PUBLIC_KEY_BYTES * 2) {
      return ws.close();
    }

    // HQC KEM challenge (§KM-1): encapsulate to the client's public key. Only the
    // holder of the matching secret key can decapsulate the same shared secret
    // `ss`; it then proves possession by returning HKDF(ss,"auth") — we never send
    // ss nor echo any decrypted plaintext, so there is no decryption oracle. A
    // chosen/garbled ciphertext yields a pseudo-random ss (CCA2) → a wrong proof.
    // NOTE: the Stripe subscription gate still runs in onAuthVerify, AFTER the
    // client proves it owns this key, so pk-spraying can't trigger Stripe/rate.
    const { ct, ss } = HqcWrapper.encapsulate(Buffer.from(pkHex, "hex"));

    ws.auth.step = "CHALLENGE_SENT";
    ws.auth.publicKey = pkHex;
    ws.auth.expectedProof = authProof(ss);

    ws.send(
      JSON.stringify({
        type: MessageTypesToReceive.AUTH_CHALLENGE,
        payload: ct.toString("base64"),
      })
    );
    logger.debug(`📥 [${senderId}] Receiving: AUTH_CHALLENGE`);
  },

  async onAuthVerify(ws: ChatSocket, solutionBase64: string) {
    if (ws.auth.step !== "CHALLENGE_SENT") return;
    const senderId = ws.auth.publicKey?.substring(0, 8) || "Unknown";
    logger.debug(`📤 [${senderId}] Sending: AUTH_VERIFY`);

    const solution = Buffer.from(solutionBase64, "base64");

    // Constant-time proof check (§KM-1). timingSafeEqual requires equal lengths,
    // so guard the length first (a wrong-length solution is simply a failure).
    const expected = ws.auth.expectedProof;
    if (
      expected &&
      solution.length === expected.length &&
      crypto.timingSafeEqual(solution, expected)
    ) {
      ws.auth.expectedProof = undefined;

      // Admission gate — now that the client has PROVEN it owns this key.
      //
      // This transport predates the free/paid split and has no way to express
      // it: one WebSocket, one set of capabilities. It knocks on the free door,
      // which is exactly right under the policy it is still exercised with
      // (ADMISSION_POLICY=open, where the free door grants everything) and
      // refuses to sell anything under the policy it is not. Subscriptions live
      // on auth/main.ts + api/main.ts.
      const admission = await checkAdmission(ws.auth.publicKey!, "free");
      if (!admission.ok) {
        ws.send(
          JSON.stringify({ type: MessageTypesToReceive.ERROR, payload: "NOT_ADMITTED" })
        );
        logger.debug(`📥 [${senderId}] Receiving: ERROR (NOT_ADMITTED)`);
        return ws.close();
      }

      ws.auth.step = "AUTHENTICATED";

      // Load Username
      const username = await DB.getUsername(ws.auth.publicKey!);
      if (username) {
        ws.auth.username = username;
        onlineUsers.set(username, ws);
      }
      onlinePks.set(ws.auth.publicKey!, ws);

      // Establish the per-connection transport key via a dedicated HQC KEM
      // encapsulation (§KM-1, separate from the auth challenge above). SESSION_KEY
      // carries the KEM ciphertext, sent plaintext (the key isn't set yet); from
      // the moment we set sessionKey, the send override encrypts every subsequent
      // frame — including the AUTH_SUCCESS just below and all relay traffic. The
      // client decapsulates the ciphertext to recover the same 32-byte `ss`.
      const session = encapsulateSession(Buffer.from(ws.auth.publicKey!, "hex"));
      ws.send(
        JSON.stringify({
          type: MessageTypesToReceive.SESSION_KEY,
          payload: session.ct.toString("base64"),
        })
      );
      const sessionKeys = deriveSessionKeys(session.ss);
      ws.auth.txKey = sessionKeys.s2c; // server→client
      ws.auth.rxKey = sessionKeys.c2s; // client→server
      logger.debug(`🔐 [${senderId}] transport session keys established`);

      ws.send(JSON.stringify({ type: MessageTypesToReceive.AUTH_SUCCESS }));
      logger.debug(`✅ Auth: ${username || ws.auth.publicKey?.substring(0, 8)}`);
      logger.debug(`📥 [${username || senderId}] Receiving: AUTH_SUCCESS`);

      // Presence: learn which friends are already online, and announce
      // ourselves to our online friends so calls become available both ways.
      if (ws.auth.username) {
        await ensureBotFriend(ws);
        await sendOnlineFriendsTo(ws, ws.auth.publicKey!);
        await broadcastPresence(ws.auth.publicKey!, ws.auth.username, true);
      }

      // Flush any messages queued while this user was offline.
      await flushPendingTo(ws, username || senderId);
    } else {
      ws.send(
        JSON.stringify({
          type: MessageTypesToReceive.ERROR,
          payload: "AUTH_FAILED",
        })
      );
      logger.debug(`📥 [${senderId}] Receiving: ERROR (AUTH_FAILED)`);
      ws.close();
    }
  },

  /**
   * The client is going into the background. iOS does not close the socket when
   * it suspends an app, so without this frame the server keeps the user in
   * `onlineUsers` and relays into a socket nobody is reading: the message is
   * neither queued nor pushed, and it stays that way until the 30s heartbeat
   * reaps the connection. That window is exactly when a user backgrounds the
   * app and expects a notification.
   *
   * The socket stays open — this is a presence change, not a disconnect, so
   * coming back costs no reconnect and no re-authentication (and so no second
   * biometric prompt).
   */
  async onAppBackground(ws: ChatSocket) {
    if (ws.auth.step !== "AUTHENTICATED" || ws.auth.suspended) return;
    ws.auth.suspended = true;
    logger.debug(`🌙 [${ws.auth.username}] backgrounded — delivering via push`);
    if (ws.auth.username && ws.auth.publicKey) {
      await broadcastPresence(ws.auth.publicKey, ws.auth.username, false);
    }
  },

  /** Back in the foreground: deliver what arrived while we were away. */
  async onAppForeground(ws: ChatSocket) {
    if (ws.auth.step !== "AUTHENTICATED" || !ws.auth.suspended) return;
    ws.auth.suspended = false;
    logger.debug(`☀️ [${ws.auth.username}] foregrounded — flushing queue`);
    if (ws.auth.username && ws.auth.publicKey) {
      await broadcastPresence(ws.auth.publicKey, ws.auth.username, true);
      await sendOnlineFriendsTo(ws, ws.auth.publicKey);
    }
    await flushPendingTo(ws, ws.auth.username || "unknown");
  },

  async onSetUsername(ws: ChatSocket, newUsername: string) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";
    logger.debug(`📤 [${sender}] Sending: SET_USERNAME`);
    try {
      if (ws.auth.username) onlineUsers.delete(ws.auth.username);
      await DB.setUsername(ws.auth.publicKey!, newUsername);

      ws.auth.username = newUsername;
      onlineUsers.set(newUsername, ws);

      ws.send(
        JSON.stringify({
          type: MessageTypesToReceive.USERNAME_UPDATED,
          payload: newUsername,
        })
      );
      logger.debug(`📥 [${newUsername}] Receiving: USERNAME_UPDATED`);

      // First login often sets the username after auth — announce presence and
      // auto-friend the bot now (a new user has no username at auth time).
      await ensureBotFriend(ws);
      await sendOnlineFriendsTo(ws, ws.auth.publicKey!);
      await broadcastPresence(ws.auth.publicKey!, newUsername, true);
    } catch (e: any) {
      ws.send(
        JSON.stringify({
          type: MessageTypesToReceive.ERROR,
          payload: e.message,
        })
      );
      logger.debug(`📥 [${sender}] Receiving: ERROR (${e.message})`);
    }
  },

  async onAddFriend(ws: ChatSocket, targetUsername: string) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";
    logger.debug(
      `📤 [${sender}] Sending: ADD_FRIEND (target: ${targetUsername})`
    );

    // 1. Resolve Target
    const targetPk = await DB.getPkByUsername(targetUsername);
    if (!targetPk) {
      ws.send(
        JSON.stringify({
          type: MessageTypesToReceive.ERROR,
          payload: "USER_NOT_FOUND",
        })
      );
      logger.debug(`📥 [${sender}] Receiving: ERROR (USER_NOT_FOUND)`);
      return;
    }

    // 2. Send the request to the target — deliver live, or queue if offline.
    // PKs are public via the user directory, so including the sender's key is
    // fine and lets the recipient render + accept the request.
    const requestEnvelope = {
      type: MessageTypesToReceive.FRIEND_REQUEST,
      sender: ws.auth.username || "Unknown",
      pk: ws.auth.publicKey,
      payload: "Wants to add you as a friend",
    };
    const peer = deliverySocket(targetUsername);
    if (peer) {
      peer.send(JSON.stringify(requestEnvelope));
      logger.debug(
        `📥 [${targetUsername}] Receiving: FRIEND_REQUEST (from: ${sender})`
      );
    } else {
      enqueuePending(targetPk, requestEnvelope);
      logger.debug(`📦 [${targetUsername}] Queued: FRIEND_REQUEST (from: ${sender})`);
      // Wake the recipient — an invite sat silently in the queue until they
      // happened to reopen the app, which is how invites went unanswered.
      ApnsService.send(targetPk, "Friend request", `${sender} wants to connect`);
    }

    ws.send(
      JSON.stringify({
        type: MessageTypesToReceive.DIRECT_MESSAGE,
        sender: "SYSTEM",
        payload: `Invite sent to ${targetUsername}`,
      })
    );
    logger.debug(`📥 [${sender}] Receiving: DIRECT_MESSAGE (from: SYSTEM)`);
  },

  async onAcceptInvite(ws: ChatSocket, targetUsername: string) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";
    logger.debug(
      `📤 [${sender}] Sending: ACCEPT_INVITE (target: ${targetUsername})`
    );

    const targetPk = await DB.getPkByUsername(targetUsername);
    if (!targetPk) {
      ws.send(
        JSON.stringify({
          type: MessageTypesToReceive.ERROR,
          payload: "USER_NOT_FOUND",
        })
      );
      logger.debug(`📥 [${sender}] Receiving: ERROR (USER_NOT_FOUND)`);
      return;
    }

    // 1. Create Blind Friendship Hash in DB
    await DB.createFriendship(ws.auth.publicKey!, targetPk);

    // 2. Send "FRIEND_ADDED" to ME (Contains Target PK)
    ws.send(
      JSON.stringify({
        type: MessageTypesToReceive.FRIEND_ADDED,
        username: targetUsername,
        pk: targetPk,
      })
    );
    logger.debug(
      `📥 [${sender}] Receiving: FRIEND_ADDED (username: ${targetUsername})`
    );

    // 3. Send "FRIEND_ADDED" to TARGET (Contains MY PK) — live or queued.
    const addedEnvelope = {
      type: MessageTypesToReceive.FRIEND_ADDED,
      username: ws.auth.username,
      pk: ws.auth.publicKey!,
    };
    const peer = deliverySocket(targetUsername);
    if (peer) {
      peer.send(JSON.stringify(addedEnvelope));
      logger.debug(
        `📥 [${targetUsername}] Receiving: FRIEND_ADDED (username: ${sender})`
      );
    } else {
      enqueuePending(targetPk, addedEnvelope);
      logger.debug(`📦 [${targetUsername}] Queued: FRIEND_ADDED (username: ${sender})`);
    }

    // 4. Exchange presence immediately. Presence is otherwise only sent at
    //    auth/disconnect, so without this both sides see each other offline
    //    (and can't call) until one of them reopens the app. If the peer is
    //    online, tell each side the other is online — same as the auth path.
    if (peer && peer.readyState === WebSocket.OPEN && ws.auth.username) {
      ws.send(
        JSON.stringify({
          type: MessageTypesToReceive.USER_ONLINE,
          sender: targetUsername,
        })
      );
      peer.send(
        JSON.stringify({
          type: MessageTypesToReceive.USER_ONLINE,
          sender: ws.auth.username,
        })
      );
    }
  },

  /**
   * Withdraw an invite you sent, or decline one you received. Both directions
   * are the same operation on a different inbox, so one handler covers them.
   */
  async onCancelInvite(ws: ChatSocket, targetUsername: string) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";
    logger.debug(
      `📤 [${sender}] Sending: CANCEL_INVITE (target: ${targetUsername})`
    );

    const targetPk = await DB.getPkByUsername(targetUsername);
    if (!targetPk) {
      ws.send(
        JSON.stringify({
          type: MessageTypesToReceive.ERROR,
          payload: "USER_NOT_FOUND",
        })
      );
      return;
    }

    const myPk = ws.auth.publicKey!;
    // Try both directions: an outbound invite sits in *their* inbox, an inbound
    // one in ours. Exactly one can match.
    const withdrew = await DB.cancelInvite(myPk, targetUsername);
    const declined = withdrew ? false : await DB.declineInvite(myPk, targetUsername);

    if (!withdrew && !declined) {
      ws.send(
        JSON.stringify({
          type: MessageTypesToReceive.ERROR,
          payload: "NO_PENDING_INVITE",
        })
      );
      return;
    }

    ws.send(
      JSON.stringify({
        type: MessageTypesToReceive.INVITE_CANCELLED,
        username: targetUsername,
      })
    );

    // Tell the other side so their pending row disappears too.
    const peer = onlineUsers.get(targetUsername);
    if (peer) {
      peer.send(
        JSON.stringify({
          type: MessageTypesToReceive.INVITE_CANCELLED,
          username: ws.auth.username,
        })
      );
    }
  },

  async onRemoveFriend(ws: ChatSocket, targetUsername: string) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";
    logger.debug(
      `📤 [${sender}] Sending: REMOVE_FRIEND (target: ${targetUsername})`
    );

    const targetPk = await DB.getPkByUsername(targetUsername);
    if (!targetPk) {
      ws.send(
        JSON.stringify({
          type: MessageTypesToReceive.ERROR,
          payload: "USER_NOT_FOUND",
        })
      );
      logger.debug(`📥 [${sender}] Receiving: ERROR (USER_NOT_FOUND)`);
      return;
    }

    // Remove friendship from database
    const success = await DB.removeFriend(ws.auth.publicKey!, targetUsername);
    if (!success) {
      ws.send(
        JSON.stringify({
          type: MessageTypesToReceive.ERROR,
          payload: "NOT_FRIENDS",
        })
      );
      logger.debug(`📥 [${sender}] Receiving: ERROR (NOT_FRIENDS)`);
      return;
    }

    // Notify the sender
    ws.send(
      JSON.stringify({
        type: MessageTypesToReceive.FRIEND_REMOVED,
        username: targetUsername,
      })
    );
    logger.debug(
      `📥 [${sender}] Receiving: FRIEND_REMOVED (username: ${targetUsername})`
    );

    // Notify the peer if online
    const peer = onlineUsers.get(targetUsername);
    if (peer) {
      peer.send(
        JSON.stringify({
          type: MessageTypesToReceive.FRIEND_REMOVED,
          username:
            ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown",
        })
      );
      logger.debug(
        `📥 [${targetUsername}] Receiving: FRIEND_REMOVED (username: ${sender})`
      );
    }
  },

  async onMessage(ws: ChatSocket, targetUsername: string, payload: any, messageId?: string, epoch?: number, idx?: number) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";
    logger.debug(`📤 [${sender}] Sending: MESSAGE (target: ${targetUsername})`);

    const targetPk = await DB.getPkByUsername(targetUsername);
    if (!targetPk) return; // Silent fail or error

    // Verify Friendship Hash
    const areFriends = await DB.checkFriendship(ws.auth.publicKey!, targetPk);
    if (!areFriends) {
      ws.send(
        JSON.stringify({
          type: MessageTypesToReceive.ERROR,
          payload: "NOT_FRIENDS",
        })
      );
      logger.debug(`📥 [${sender}] Receiving: ERROR (NOT_FRIENDS)`);
      return;
    }

    // Heal older friendships that only stored a blind hash, so presence works
    // on the next reconnect (fire-and-forget — must not delay the message).
    DB.ensureFriendLink(ws.auth.publicKey!, targetPk).catch(() => { });

    const envelope = {
      type: MessageTypesToReceive.DIRECT_MESSAGE,
      sender: ws.auth.username, // Send Username, Client resolves PK locally
      payload,
      messageId, // carried so a queued message can ack its sender on flush
      // Opaque key-rotation header (epoch ≥ 1). Relayed as-is; the server never
      // interprets it. Absent (undefined → dropped by JSON.stringify) for the
      // legacy static-key path, keeping epoch-0 frames byte-identical.
      epoch,
      idx,
    };
    const peer = deliverySocket(targetUsername);
    if (peer) {
      peer.send(JSON.stringify(envelope));
      logger.debug(
        `📥 [${targetUsername}] Receiving: DIRECT_MESSAGE (from: ${sender})`
      );
      // Receipt: delivered to the recipient's live socket.
      if (messageId) {
        ws.send(JSON.stringify({ type: MessageTypesToReceive.MESSAGE_DELIVERED, messageId }));
      }
    } else {
      // Recipient offline: queue for delivery on next auth.
      enqueuePending(targetPk, envelope);
      logger.debug(`📦 [${targetUsername}] Queued: DIRECT_MESSAGE (from: ${sender})`);
      // Wake the recipient's device so they see it now.
      ApnsService.send(targetPk, ws.auth.username || "New message", "Sent you a message");
      // Receipt: stored server-side until the recipient reconnects.
      if (messageId) {
        ws.send(JSON.stringify({ type: MessageTypesToReceive.MESSAGE_QUEUED, messageId }));
      }
    }
  },

  // Photo message. Like onMessage, the server is a pure relay: `payload` is the
  // sender's already-encrypted image (AES under the per-friend key — NOT the
  // HQC-per-block wrapping text uses, which would explode an image's size). We
  // relay live or queue it offline + send the sender a delivery receipt.
  async onImageMessage(ws: ChatSocket, targetUsername: string, payload: any, messageId?: string, epoch?: number) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";
    logger.debug(`📤 [${sender}] Sending: IMAGE_MESSAGE (target: ${targetUsername})`);

    const targetPk = await DB.getPkByUsername(targetUsername);
    if (!targetPk) return;

    const areFriends = await DB.checkFriendship(ws.auth.publicKey!, targetPk);
    if (!areFriends) {
      ws.send(JSON.stringify({ type: MessageTypesToReceive.ERROR, payload: "NOT_FRIENDS" }));
      return;
    }
    DB.ensureFriendLink(ws.auth.publicKey!, targetPk).catch(() => { });

    const envelope = {
      type: MessageTypesToReceive.IMAGE_MESSAGE,
      sender: ws.auth.username,
      payload,
      messageId,
      epoch, // per-epoch media key selector; undefined on the legacy path
    };
    const peer = deliverySocket(targetUsername);
    if (peer) {
      peer.send(JSON.stringify(envelope));
      logger.debug(`📥 [${targetUsername}] Receiving: IMAGE_MESSAGE (from: ${sender})`);
      if (messageId) {
        ws.send(JSON.stringify({ type: MessageTypesToReceive.MESSAGE_DELIVERED, messageId }));
      }
    } else {
      enqueuePending(targetPk, envelope);
      logger.debug(`📦 [${targetUsername}] Queued: IMAGE_MESSAGE (from: ${sender})`);
      ApnsService.send(targetPk, ws.auth.username || "New photo", "Sent you a photo");
      if (messageId) {
        ws.send(JSON.stringify({ type: MessageTypesToReceive.MESSAGE_QUEUED, messageId }));
      }
    }
  },

  async onAudio(ws: ChatSocket, targetUsername: string, payload: any, epoch?: number) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";
    logger.debug(
      `📤 [${sender}] Sending: AUDIO_MESSAGE (target: ${targetUsername})`
    );

    const targetPk = await DB.getPkByUsername(targetUsername);
    if (!targetPk) return; // Silent fail or error

    // Verify Friendship Hash
    const areFriends = await DB.checkFriendship(ws.auth.publicKey!, targetPk);
    if (!areFriends) {
      ws.send(
        JSON.stringify({
          type: MessageTypesToReceive.ERROR,
          payload: "NOT_FRIENDS",
        })
      );
      logger.debug(`📥 [${sender}] Receiving: ERROR (NOT_FRIENDS)`);
      return;
    }

    const envelope = {
      type: MessageTypesToReceive.AUDIO_MESSAGE,
      sender: ws.auth.username, // Send Username, Client resolves PK locally
      payload,
      epoch, // per-epoch media key selector; undefined on the legacy path
    };
    const peer = deliverySocket(targetUsername);
    if (peer) {
      peer.send(JSON.stringify(envelope));
      logger.debug(
        `📥 [${targetUsername}] Receiving: AUDIO_MESSAGE (from: ${sender})`
      );
    } else {
      // Recipient offline: queue for delivery on next auth.
      enqueuePending(targetPk, envelope);
      logger.debug(`📦 [${targetUsername}] Queued: AUDIO_MESSAGE (from: ${sender})`);
    }
  },

  async onAudioStreamStart(
    ws: ChatSocket,
    targetUsername: string,
    payload: any
  ) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";
    logger.debug(
      `📤 [${sender}] Sending: AUDIO_STREAM_START (target: ${targetUsername})`
    );

    const targetPk = await DB.getPkByUsername(targetUsername);
    if (!targetPk) return;

    const areFriends = await DB.checkFriendship(ws.auth.publicKey!, targetPk);
    if (!areFriends) {
      ws.send(
        JSON.stringify({
          type: MessageTypesToReceive.ERROR,
          payload: "NOT_FRIENDS",
        })
      );
      return;
    }

    const peer = deliverySocket(targetUsername);
    if (peer) {
      peer.send(
        JSON.stringify({
          type: MessageTypesToReceive.AUDIO_STREAM_START,
          sender: ws.auth.username,
          payload,
        })
      );
    }
  },

  async onAudioStreamChunk(
    ws: ChatSocket,
    targetUsername: string,
    payload: any
  ) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";

    const targetPk = await DB.getPkByUsername(targetUsername);
    if (!targetPk) return;

    const areFriends = await DB.checkFriendship(ws.auth.publicKey!, targetPk);
    if (!areFriends) return;

    const peer = deliverySocket(targetUsername);
    if (peer) {
      peer.send(
        JSON.stringify({
          type: MessageTypesToReceive.AUDIO_STREAM_CHUNK,
          sender: ws.auth.username,
          payload,
        })
      );
    }
  },

  async onAudioStreamEnd(ws: ChatSocket, targetUsername: string, payload: any) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";
    logger.debug(
      `📤 [${sender}] Sending: AUDIO_STREAM_END (target: ${targetUsername})`
    );

    const targetPk = await DB.getPkByUsername(targetUsername);
    if (!targetPk) return;

    const areFriends = await DB.checkFriendship(ws.auth.publicKey!, targetPk);
    if (!areFriends) return;

    const peer = deliverySocket(targetUsername);
    if (peer) {
      peer.send(
        JSON.stringify({
          type: MessageTypesToReceive.AUDIO_STREAM_END,
          sender: ws.auth.username,
          payload,
        })
      );
    }
  },

  // Exact-username lookup — NOT a bulk directory. Returning every username + pk
  // to any user was a social-graph enumeration leak (and pk → blinded billing
  // code). You must now know the exact handle; we return that one user or none.
  async onListUsers(ws: ChatSocket, query: any) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";
    const q = (typeof query === "string" ? query : "").trim().toLowerCase();
    logger.debug(`📤 [${sender}] Sending: GET_ALL_USERS (query: "${q}")`);

    let results: { username: string; pk: string }[] = [];
    if (q.length > 0) {
      const pk = await DB.getPkByUsername(q);
      if (pk) results = [{ username: q, pk }];
    }
    ws.send(
      JSON.stringify({
        type: MessageTypesToReceive.USER_LIST_RESPONSE,
        payload: results,
      })
    );
    logger.debug(`📥 [${sender}] Receiving: USER_LIST_RESPONSE (${results.length})`);
  },

  // AES is treated just like a message, but logic is handled by client
  async onAes(ws: ChatSocket, targetUsername: string, payload: any) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";
    logger.debug(`📤 [${sender}] Sending: AES (target: ${targetUsername})`);

    // Only friends may push handshake material — blocks unsolicited handshakes.
    if (!(await isVerifiedFriend(ws, targetUsername))) return;

    const envelope = {
      type: MessageTypesToReceive.AES,
      sender: ws.auth.username,
      payload,
    };
    const peer = deliverySocket(targetUsername);
    if (peer) {
      peer.send(JSON.stringify(envelope));
      logger.debug(`📥 [${targetUsername}] Receiving: AES (from: ${sender})`);
    } else {
      // Recipient offline: queue the handshake seed (like onMessage does for
      // messages). The AES handshake must complete before any message can be
      // sent, so dropping it here stranded anyone who handshook while their peer
      // — e.g. the helper bot mid-restart — was offline.
      const targetPk = await DB.getPkByUsername(targetUsername);
      if (targetPk) enqueuePending(targetPk, envelope);
      logger.debug(`📦 [${targetUsername}] Queued: AES (from: ${sender})`);
    }
  },

  // Tier-1 epoch re-handshake. Identical relay/queue semantics to onAes: the
  // payload is a fresh per-epoch seed HQC-encrypted to the peer (server-opaque);
  // `epoch` names the target epoch. Must be durably queued when the peer is
  // offline — a dropped rotation would strand messages sent under the new epoch.
  async onKeyRotate(ws: ChatSocket, targetUsername: string, payload: any, epoch?: number) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";
    logger.debug(`📤 [${sender}] Sending: KEY_ROTATE (target: ${targetUsername}, epoch: ${epoch})`);

    // Only friends may push rotation material — blocks unsolicited rotations.
    if (!(await isVerifiedFriend(ws, targetUsername))) return;

    const envelope = {
      type: MessageTypesToReceive.KEY_ROTATE,
      sender: ws.auth.username,
      payload,
      epoch,
    };
    const peer = deliverySocket(targetUsername);
    if (peer) {
      peer.send(JSON.stringify(envelope));
      logger.debug(`📥 [${targetUsername}] Receiving: KEY_ROTATE (from: ${sender})`);
    } else {
      const targetPk = await DB.getPkByUsername(targetUsername);
      if (targetPk) enqueuePending(targetPk, envelope);
      logger.debug(`📦 [${targetUsername}] Queued: KEY_ROTATE (from: ${sender})`);
    }
  },

  async onCallInitiate(ws: ChatSocket, targetUsername: string, payload: any) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";
    logger.debug(
      `📤 [${sender}] Sending: CALL_INITIATE (target: ${targetUsername})`
    );

    const targetPk = await DB.getPkByUsername(targetUsername);
    if (!targetPk) return;

    const areFriends = await DB.checkFriendship(ws.auth.publicKey!, targetPk);
    if (!areFriends) {
      ws.send(
        JSON.stringify({
          type: MessageTypesToReceive.ERROR,
          payload: "NOT_FRIENDS",
        })
      );
      return;
    }

    const peer = deliverySocket(targetUsername);
    if (peer) {
      peer.send(
        JSON.stringify({
          type: MessageTypesToReceive.CALL_INCOMING,
          sender: ws.auth.username,
          payload,
        })
      );
      logger.debug(
        `📥 [${targetUsername}] Receiving: CALL_INCOMING (from: ${sender})`
      );
    } else {
      // Peer is offline — notify the caller, and push the callee to wake them.
      ws.send(
        JSON.stringify({
          type: MessageTypesToReceive.ERROR,
          payload: "PEER_OFFLINE",
        })
      );
      ApnsService.send(targetPk, "Incoming call", `${ws.auth.username || "Someone"} is calling you`);
    }
  },

  async onCallAccept(ws: ChatSocket, targetUsername: string, payload: any) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";
    logger.debug(
      `📤 [${sender}] Sending: CALL_ACCEPT (target: ${targetUsername})`
    );

    if (!(await isVerifiedFriend(ws, targetUsername))) return;
    const peer = deliverySocket(targetUsername);
    if (peer) {
      peer.send(
        JSON.stringify({
          type: MessageTypesToReceive.CALL_ACCEPTED,
          sender: ws.auth.username,
        })
      );
      logger.debug(
        `📥 [${targetUsername}] Receiving: CALL_ACCEPTED (from: ${sender})`
      );
    }
  },

  async onCallReject(ws: ChatSocket, targetUsername: string, payload: any) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";
    logger.debug(
      `📤 [${sender}] Sending: CALL_REJECT (target: ${targetUsername})`
    );

    if (!(await isVerifiedFriend(ws, targetUsername))) return;
    const peer = deliverySocket(targetUsername);
    if (peer) {
      peer.send(
        JSON.stringify({
          type: MessageTypesToReceive.CALL_REJECTED,
          sender: ws.auth.username,
        })
      );
      logger.debug(
        `📥 [${targetUsername}] Receiving: CALL_REJECTED (from: ${sender})`
      );
    }
  },

  async onCallEnd(ws: ChatSocket, targetUsername: string, payload: any) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";
    logger.debug(`📤 [${sender}] Sending: CALL_END (target: ${targetUsername})`);

    if (!(await isVerifiedFriend(ws, targetUsername))) return;
    const peer = deliverySocket(targetUsername);
    if (peer) {
      peer.send(
        JSON.stringify({
          type: MessageTypesToReceive.CALL_ENDED,
          sender: ws.auth.username,
        })
      );
      logger.debug(
        `📥 [${targetUsername}] Receiving: CALL_ENDED (from: ${sender})`
      );
    }
  },

  // Pure relay. `payload` is the sender's already E2E-encrypted audio chunk
  // (AES-GCM under the per-friend key). The server NEVER decrypts, inspects, or
  // re-encrypts it — it only looks up the recipient by username and forwards the
  // opaque payload. The server's job for calls is routing, not crypto.
  async onCallMediaChunk(ws: ChatSocket, targetUsername: string, payload: any) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";

    // Drop media to non-friends (cached, so this is cheap per chunk).
    if (!(await isVerifiedFriend(ws, targetUsername))) return;
    const peer = deliverySocket(targetUsername);
    if (peer) {
      peer.send(
        JSON.stringify({
          type: MessageTypesToReceive.CALL_MEDIA_CHUNK,
          sender: ws.auth.username,
          payload,
        })
      );
      // Throttled relay trace (chunks fly ~20/sec).
      ws.mediaRelayCount = (ws.mediaRelayCount || 0) + 1;
      if (ws.mediaRelayCount <= 3 || ws.mediaRelayCount % 100 === 0) {
        logger.debug(
          `🔀 [${sender}→${targetUsername}] relay CALL_MEDIA_CHUNK #${ws.mediaRelayCount} (${typeof payload === "string" ? payload.length : "?"
          } chars)`
        );
      }
    } else {
      // Recipient not connected → chunk is dropped (calls need both online).
      ws.mediaDropCount = (ws.mediaDropCount || 0) + 1;
      if (ws.mediaDropCount <= 3 || ws.mediaDropCount % 100 === 0) {
        logger.debug(
          `⚠️ [${sender}→${targetUsername}] DROP CALL_MEDIA_CHUNK #${ws.mediaDropCount} — recipient offline`
        );
      }
    }
  },

  /** Store the device's APNs token. Payload is "platform:hextoken". */
  async onRegisterPushToken(ws: ChatSocket, payload: string) {
    if (!ws.auth.publicKey || !payload) return;
    const idx = payload.indexOf(":");
    if (idx < 0) return;
    const platform = payload.substring(0, idx);
    const token = payload.substring(idx + 1);
    await DB.setPushToken(ws.auth.publicKey, platform, token);
    logger.debug(`🔔 [${ws.auth.username || "?"}] push token registered (${platform})`);
  },

  /** Irreversibly delete the caller's account (App Store Guideline 5.1.1(v)).
   *  Purges all server-side data, tells online friends we've gone offline,
   *  confirms, and closes the socket. Local device data is wiped by the client. */
  async onDeleteAccount(ws: ChatSocket) {
    const pk = ws.auth.publicKey;
    if (!pk) return;
    const username = ws.auth.username;
    logger.debug(`🗑️  [${username || pk.substring(0, 8)}] DELETE_ACCOUNT`);

    // Announce offline to friends BEFORE the friend set is purged.
    if (username) {
      await broadcastPresence(pk, username, false).catch(() => { });
    }

    // Stop routing to this socket, then purge everything we store.
    if (username) onlineUsers.delete(username);
    onlinePks.delete(pk);
    await DB.deleteUser(pk);
    // Parity with the REST `/account/delete` route, which already did this. The
    // WS path — the one the apps actually use — left the MQTT connect token
    // valid until its TTL expired.
    await DB.revokeMqttAuth(pk);

    ws.send(JSON.stringify({ type: MessageTypesToReceive.ACCOUNT_DELETED }));
    ws.close();
  },
};

// --- SERVER LOOP ---

wss.on("connection", (ws: WebSocket, req: http.IncomingMessage) => {
  const socket = ws as ChatSocket;
  socket.auth = { step: "INIT" };
  socket.isAlive = true;
  socket.preAuthMsgs = 0;

  // CRASH FIX (root cause of the stress-test crash): a `ws` socket that emits
  // "error" with no listener re-throws on the process and kills Node. Under a
  // flood, ECONNRESET/EPIPE on individual sockets are routine. Attach a listener
  // to EVERY socket so those become logged, counted events — never a crash.
  socket.on("error", (err) => {
    healthMonitor.noteError();
    logger.debug(`[socket] error (${socket.auth?.username || "unauth"}): ${(err as Error).message}`);
  });

  // Per-IP connection rate limit (pre-auth flood guard).
  const ip = clientIp(req);
  if (!allowConnection(ip)) {
    logger.debug(`⛔ [${ip}] connection rate-limited`);
    return socket.close();
  }

  // Transport encryption: once a session key is established, every outgoing
  // string frame is wrapped in an AES-GCM envelope. We override send() here so
  // all ~45 handler call sites (ws.send / peer.send / sock.send) are covered
  // automatically — no site can accidentally leak a plaintext frame. The raw,
  // unwrapped send is kept for the handshake frames sent before the key exists.
  const rawSend = ws.send.bind(ws);
  socket.send = ((data: any, ...args: any[]) => {
    if (typeof data === "string" && socket.auth?.txKey) {
      return rawSend(
        JSON.stringify({ enc: aesEncrypt(data, socket.auth.txKey) }),
        ...args
      );
    }
    return rawSend(data, ...args);
  }) as typeof ws.send;

  socket.on("message", async (data) => {
    try {
      healthMonitor.noteMessage();
      // Pre-auth flood guard: bound how many frames a socket may send before
      // it authenticates.
      if (socket.auth.step !== "AUTHENTICATED") {
        socket.preAuthMsgs = (socket.preAuthMsgs || 0) + 1;
        if (socket.preAuthMsgs > MAX_PREAUTH_MSGS) {
          logger.debug(`⛔ pre-auth message flood — closing socket`);
          return socket.close();
        }
      }

      // Decrypt the transport envelope (plaintext during the auth handshake).
      const msg = unwrap(data.toString(), socket.auth?.rxKey);
      if (
        socket.auth.step !== "AUTHENTICATED" &&
        msg.type !== MessageTypesToSent.AUTH_INIT &&
        msg.type !== MessageTypesToSent.AUTH_VERIFY
      ) {
        return socket.close();
      }

      const sender =
        socket.auth.username ||
        socket.auth.publicKey?.substring(0, 8) ||
        "Unknown";
      logger.debug(`📨 [${sender}] Received message type: ${msg.type}`);

      // A suspended app runs no code, so it cannot send us anything: any frame
      // other than the one announcing the background is proof this client is
      // awake. Clearing the flag here makes presence self-healing — a lost or
      // never-sent APP_FOREGROUND used to leave the user marked away with a
      // perfectly good socket, so every message queued and arrived as a push
      // while their conversation stayed empty.
      // HEARTBEAT_PONG is excluded deliberately: it is a reflex, and it is the
      // one frame that can still go out in the short window between the app
      // entering the background and iOS actually suspending it — which would
      // clear the flag just in time to lose the next message.
      if (
        socket.auth.suspended &&
        msg.type !== MessageTypesToSent.APP_BACKGROUND &&
        msg.type !== MessageTypesToSent.HEARTBEAT_PONG
      ) {
        await Handlers.onAppForeground(socket);
      }

      switch (msg.type) {
        case MessageTypesToSent.AUTH_INIT:
          await Handlers.onAuthInit(socket, msg.payload);
          break;
        case MessageTypesToSent.AUTH_VERIFY:
          await Handlers.onAuthVerify(socket, msg.payload);
          break;
        case MessageTypesToSent.SET_USERNAME:
          await Handlers.onSetUsername(socket, msg.payload);
          break;
        case MessageTypesToSent.ADD_FRIEND:
          await Handlers.onAddFriend(socket, msg.payload);
          break;
        case MessageTypesToSent.ACCEPT_INVITE:
          await Handlers.onAcceptInvite(socket, msg.payload);
          break;
        case MessageTypesToSent.REMOVE_FRIEND:
          await Handlers.onRemoveFriend(socket, msg.payload);
          break;
        case MessageTypesToSent.CANCEL_INVITE:
          await Handlers.onCancelInvite(socket, msg.payload);
          break;
        case MessageTypesToSent.MESSAGE:
          await Handlers.onMessage(socket, msg.targetPk, msg.payload, msg.messageId, msg.epoch, msg.idx); // msg.targetPk here acts as username field container
          break;
        case MessageTypesToSent.IMAGE_MESSAGE:
          await Handlers.onImageMessage(socket, msg.targetPk, msg.payload, msg.messageId, msg.epoch);
          break;
        case MessageTypesToSent.AUDIO_MESSAGE:
          await Handlers.onAudio(socket, msg.targetPk, msg.payload, msg.epoch); // msg.targetPk here acts as username field container
          break;
        case MessageTypesToSent.AUDIO_STREAM_START:
          await Handlers.onAudioStreamStart(socket, msg.targetPk, msg.payload);
          break;
        case MessageTypesToSent.AUDIO_STREAM_CHUNK:
          await Handlers.onAudioStreamChunk(socket, msg.targetPk, msg.payload);
          break;
        case MessageTypesToSent.AUDIO_STREAM_END:
          await Handlers.onAudioStreamEnd(socket, msg.targetPk, msg.payload);
          break;
        case MessageTypesToSent.AES:
          await Handlers.onAes(socket, msg.targetPk, msg.payload);
          break;
        case MessageTypesToSent.KEY_ROTATE:
          await Handlers.onKeyRotate(socket, msg.targetPk, msg.payload, msg.epoch);
          break;
        case MessageTypesToSent.GET_ALL_USERS:
          await Handlers.onListUsers(socket, msg.payload);
          break;
        case MessageTypesToSent.CALL_INITIATE:
          await Handlers.onCallInitiate(socket, msg.targetPk, msg.payload);
          break;
        case MessageTypesToSent.CALL_ACCEPT:
          await Handlers.onCallAccept(socket, msg.targetPk, msg.payload);
          break;
        case MessageTypesToSent.CALL_REJECT:
          await Handlers.onCallReject(socket, msg.targetPk, msg.payload);
          break;
        case MessageTypesToSent.CALL_END:
          await Handlers.onCallEnd(socket, msg.targetPk, msg.payload);
          break;
        case MessageTypesToSent.CALL_MEDIA_CHUNK:
          await Handlers.onCallMediaChunk(socket, msg.targetPk, msg.payload);
          break;
        case MessageTypesToSent.HEARTBEAT_PONG:
          socket.isAlive = true;
          break;
        case MessageTypesToSent.APP_BACKGROUND:
          await Handlers.onAppBackground(socket);
          break;
        case MessageTypesToSent.APP_FOREGROUND:
          await Handlers.onAppForeground(socket);
          break;
        case MessageTypesToSent.REGISTER_PUSH_TOKEN:
          await Handlers.onRegisterPushToken(socket, msg.payload);
          break;
        case MessageTypesToSent.DELETE_ACCOUNT:
          await Handlers.onDeleteAccount(socket);
          break;
      }
    } catch (e) {
      healthMonitor.noteError();
      logger.error(e);
    }
  });

  socket.on("close", () => {
    const username = socket.auth.username;
    const pk = socket.auth.publicKey;
    // Remove from the online maps FIRST so we aren't counted as online.
    if (username) onlineUsers.delete(username);
    if (pk) onlinePks.delete(pk);
    // Then tell online friends we went offline.
    if (username && pk) {
      broadcastPresence(pk, username, false).catch((e) =>
        logger.error("[presence] offline broadcast failed", e)
      );
    }
  });
});

// --- HEARTBEAT ---
// Every 30s, ping all authenticated sockets. A socket that has not replied
// with a pong since the previous tick is considered stale and terminated,
// which also fires the `close` handler to clean up the online maps.
const HEARTBEAT_INTERVAL_MS = 30_000;
const heartbeat = setInterval(() => {
  wss.clients.forEach((client) => {
    const socket = client as ChatSocket;
    if (socket.auth.step !== "AUTHENTICATED") return;

    if (socket.isAlive === false) {
      logger.debug(`💔 Terminating stale connection: ${socket.auth.username || "Unknown"}`);
      return socket.terminate();
    }

    socket.isAlive = false;
    socket.send(JSON.stringify({ type: MessageTypesToReceive.HEARTBEAT_PING }));
  });

  // Prune expired rate-limit windows so the map doesn't grow unbounded.
  const now = Date.now();
  for (const [ip, entry] of ipConnections) {
    if (now - entry.windowStart > RATE_WINDOW_MS) ipConnections.delete(ip);
  }
}, HEARTBEAT_INTERVAL_MS);

wss.on("close", () => clearInterval(heartbeat));

assertConfig();

// Start the crash early-warning monitor. It reads wss.clients for connection /
// backpressure pressure; MAX_BUFFERED matches the client-side soft cap.
healthMonitor.start(wss, 4 * 1024 * 1024);

httpServer.listen(PORT, () => {
  logger.startup(`🚀 Server running on port ${PORT} — WS at /ws, metrics at /metrics, Stripe webhook at /stripe/webhook`);
});
