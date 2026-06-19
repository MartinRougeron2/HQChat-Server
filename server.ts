import { WebSocketServer, WebSocket } from "ws";
import * as http from "http";
import * as crypto from "crypto";
import { HqcWrapper, HQC_CONSTANTS } from "./lib/hqc";
import { DB } from "./services/db/api"; // See DB changes below
import { StripeService } from "./services/stripe/api";
import { ApnsService } from "./services/apns/api";
import { handleSubscribe } from "./services/web/subscribe";
import { MessageTypesToSent, MessageTypesToReceive } from "./enums";
import {
  aesEncrypt,
  unwrap,
  deriveSessionKeys,
  freshSessionSeed,
  hqcEncryptSeed,
} from "./lib/secure-transport";

// --- TYPES ---
interface AuthState {
  step: "INIT" | "CHALLENGE_SENT" | "AUTHENTICATED";
  publicKey?: string;
  username?: string; // Cache username after auth/set
  expectedNonce?: Buffer | undefined;
  // Per-connection transport-encryption keys (per direction). Once set (right
  // after auth), outgoing frames are AES-GCM encrypted with txKey (s2c) and
  // incoming frames decrypted with rxKey (c2s). See deriveSessionKeys.
  txKey?: Buffer; // server→client
  rxKey?: Buffer; // client→server
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
  // (esp. high-rate call media) don't hit Redis on every frame.
  friendCache?: Map<string, boolean>;
}

const PORT = Number(process.env.PORT) || 8080;

// --- SERVER IDENTITY & ADMISSION (self-host config) ------------------------
// A DissQus server is an open component anyone can run. /info advertises this.
const PROTOCOL_VERSION = 1;
const SERVER_NAME = process.env.SERVER_NAME || "DissQus";
const SERVER_VERSION = "0.1.0";
// Admission policy controls who may use this server once authenticated:
//   open      — anyone who passes HQC auth (default; self-host friendly)
//   allowlist — only public keys in ADMISSION_ALLOWLIST (private/family servers)
//   stripe    — requires an active Stripe subscription (the official server)
const ADMISSION_POLICY = (process.env.ADMISSION_POLICY || "open").toLowerCase();
const ADMISSION_ALLOWLIST = (process.env.ADMISSION_ALLOWLIST || "")
  .split(",").map((s) => s.trim()).filter(Boolean);

type Admission =
  | { ok: true }
  | { ok: false; reason: "payment"; checkoutUrl: string | undefined }
  | { ok: false; reason: "denied" };

/** Decide whether an authenticated public key may use this server. Exempt keys
 *  (e.g. the helper bot) always pass, regardless of policy. */
async function checkAdmission(pkHex: string): Promise<Admission> {
  const exempt = (process.env.EXEMPT_PUBLIC_KEYS || "")
    .split(",").map((s) => s.trim()).filter(Boolean);
  if (exempt.includes(pkHex)) return { ok: true };

  switch (ADMISSION_POLICY) {
    case "stripe": {
      const sub = await StripeService.syncAndGetStatus(pkHex);
      return sub.active ? { ok: true } : { ok: false, reason: "payment", checkoutUrl: sub.checkoutUrl };
    }
    case "allowlist":
      return ADMISSION_ALLOWLIST.includes(pkHex) ? { ok: true } : { ok: false, reason: "denied" };
    case "open":
    default:
      return { ok: true };
  }
}

// HTTP server hosts the Stripe webhook + a health check, and the WebSocket
// server is attached to it (so nginx can proxy both /ws and /stripe/webhook).
const httpServer = http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    return res.end("ok");
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

  if (req.method === "POST" && req.url === "/stripe/webhook") {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", async () => {
      const raw = Buffer.concat(chunks);
      const sig = req.headers["stripe-signature"] as string;
      try {
        const event = StripeService.constructEvent(raw, sig);
        if (event.type.startsWith("customer.subscription.")) {
          const sub = event.data.object as any;
          const active = sub.status === "active" || sub.status === "trialing";
          await StripeService.handleSubscriptionChange(sub.customer, active);
        }
        res.writeHead(200);
        res.end("ok");
      } catch (e: any) {
        console.error(`❌ [stripe-webhook] ${e.message}`);
        res.writeHead(400);
        res.end(`Webhook Error: ${e.message}`);
      }
    });
    return;
  }

  // Web subscription flow (the iOS "linking code" model).
  if (req.url && req.url.startsWith("/subscribe")) {
    handleSubscribe(req, res).catch((e) => {
      console.error("[subscribe] handler error", e);
      if (!res.headersSent) {
        res.writeHead(500);
        res.end("error");
      }
    });
    return;
  }

  if (req.url && req.url.startsWith("/account")) {
    if (req.method === "GET") {
      res.writeHead(200, {
        "Content-Type": "text/html",
        "X-Content-Type-Options": "nosniff",
        "Access-Control-Allow-Origin": "*",
      });
      return res.end(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>DissQus — Account</title>
</head>
<body>
  <h1>DissQus — Account</h1>
  <p>Welcome to your DissQus account!</p>
  <div>
    <p>Input your subscription code below to see your subscription status:</p>
    <form id="subscription-form">
      <input type="text" id="subscription-code" name="subscription-code" placeholder="Enter your subscription code" required>
      <button type="submit">Check Subscription</button>
    </form>
  </div>
</body>
</html>`);
    }
    if (req.method === "POST") {
      const url = new URL(req.url || "/", "http://localhost");

      let code = url.searchParams.get("code") || "";
      if (!code) {
        res.writeHead(400, { "Content-Type": "text/plain" });
        return res.end("Missing subscription code");
      }
      const blindedPk = code.trim().toLowerCase();
      req.on("end", async () => {
        const customerId = await StripeService.getCustomerId(blindedPk);
        if (!customerId) {
          res.writeHead(404, { "Content-Type": "text/plain" });
          return res.end("Subscription not found");
        }
        const customerPageUrl = await StripeService.getCustomerPageUrl(customerId);
        res.writeHead(200, { "Content-Type": "text/plain" });
        return res.end(customerPageUrl);
      });
    }
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

// Map<Username, ChatSocket> - For routing by Username
const onlineUsers = new Map<string, ChatSocket>();
// Map<PublicKey, ChatSocket> - For cleanup/auth
const onlinePks = new Map<string, ChatSocket>();

// --- RATE LIMITING (per-IP, in-memory) -------------------------------------
// Bounds pre-auth abuse: connection floods and message spraying before a client
// has proven its identity. Behind Cloudflare/nginx the real client IP is in
// x-forwarded-for. Not a substitute for an edge WAF, but a cheap first line.
const RATE_WINDOW_MS = 60_000;
const MAX_CONNECTIONS_PER_WINDOW = 30; // new sockets per IP per minute
const MAX_PREAUTH_MSGS = 20;           // frames allowed before AUTHENTICATED
const ipConnections = new Map<string, { count: number; windowStart: number }>();

function clientIp(req: http.IncomingMessage): string {
  const xff = (req.headers["x-forwarded-for"] as string) || "";
  return xff.split(",")[0]?.trim() || req.socket.remoteAddress || "unknown";
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

  // Tell the bot about this user (so it handshakes back), if online.
  const botSock = onlineUsers.get(BOT);
  if (botSock && botSock.readyState === WebSocket.OPEN) {
    botSock.send(
      JSON.stringify({
        type: MessageTypesToReceive.FRIEND_ADDED,
        username: ws.auth.username,
        pk: ws.auth.publicKey,
      })
    );
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
 *  notably call media at ~20/s — so we avoid a Redis round-trip per frame). */
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
    console.log(`📤 [${senderId}] Sending: AUTH_INIT`);

    // Validate the public key shape BEFORE any expensive work — pkHex is
    // attacker-controlled and gets passed to HQC and (after auth) Stripe.
    if (!/^[0-9a-fA-F]+$/.test(pkHex) ||
      pkHex.length !== HQC_CONSTANTS.PUBLIC_KEY_BYTES * 2) {
      return ws.close();
    }

    // HQC Challenge. NOTE: the Stripe subscription gate runs in onAuthVerify,
    // AFTER the client proves it owns this key — so an unauthenticated attacker
    // spraying random pks can't trigger Stripe customer creation / rate limits.
    const nonce = crypto.randomBytes(HQC_CONSTANTS.PARAM_K);
    const theta = crypto.randomBytes(HQC_CONSTANTS.SEED_BYTES);
    const ciphertext = HqcWrapper.encrypt(
      Buffer.from(pkHex, "hex"),
      nonce,
      theta
    );

    ws.auth.step = "CHALLENGE_SENT";
    ws.auth.publicKey = pkHex;
    ws.auth.expectedNonce = nonce;

    ws.send(
      JSON.stringify({
        type: MessageTypesToReceive.AUTH_CHALLENGE,
        payload: ciphertext.toString("base64"),
      })
    );
    console.log(`📥 [${senderId}] Receiving: AUTH_CHALLENGE`);
  },

  async onAuthVerify(ws: ChatSocket, solutionBase64: string) {
    if (ws.auth.step !== "CHALLENGE_SENT") return;
    const senderId = ws.auth.publicKey?.substring(0, 8) || "Unknown";
    console.log(`📤 [${senderId}] Sending: AUTH_VERIFY`);

    const solution = Buffer.from(solutionBase64, "base64");

    if (ws.auth.expectedNonce && solution.equals(ws.auth.expectedNonce)) {
      ws.auth.expectedNonce = undefined;

      // Admission gate — now that the client has PROVEN it owns this key.
      // Deferred to here (not onAuthInit) so unauthenticated key-spraying can't
      // trigger Stripe customer creation. Policy is configurable per server.
      const admission = await checkAdmission(ws.auth.publicKey!);
      if (!admission.ok) {
        if (admission.reason === "payment") {
          ws.send(
            JSON.stringify({
              type: MessageTypesToReceive.PAYMENT_REQUIRED,
              checkoutUrl: admission.checkoutUrl,
            })
          );
          console.log(`📥 [${senderId}] Receiving: PAYMENT_REQUIRED`);
        } else {
          ws.send(
            JSON.stringify({ type: MessageTypesToReceive.ERROR, payload: "NOT_ADMITTED" })
          );
          console.log(`📥 [${senderId}] Receiving: ERROR (NOT_ADMITTED)`);
        }
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

      // Establish the per-connection transport key via a dedicated HQC key
      // exchange (separate from the auth nonce above). SESSION_KEY is sent
      // plaintext (the key isn't set yet); from the moment we set sessionKey,
      // the send override encrypts every subsequent frame — including the
      // AUTH_SUCCESS just below and all presence/queue/relay traffic.
      const sessionSeed = freshSessionSeed();
      const sessionCt = hqcEncryptSeed(
        Buffer.from(ws.auth.publicKey!, "hex"),
        sessionSeed
      );
      ws.send(
        JSON.stringify({
          type: MessageTypesToReceive.SESSION_KEY,
          payload: sessionCt.toString("base64"),
        })
      );
      const sessionKeys = deriveSessionKeys(sessionSeed);
      ws.auth.txKey = sessionKeys.s2c; // server→client
      ws.auth.rxKey = sessionKeys.c2s; // client→server
      console.log(`🔐 [${senderId}] transport session keys established`);

      ws.send(JSON.stringify({ type: MessageTypesToReceive.AUTH_SUCCESS }));
      console.log(`✅ Auth: ${username || ws.auth.publicKey?.substring(0, 8)}`);
      console.log(`📥 [${username || senderId}] Receiving: AUTH_SUCCESS`);

      // Presence: learn which friends are already online, and announce
      // ourselves to our online friends so calls become available both ways.
      if (ws.auth.username) {
        await ensureBotFriend(ws);
        await sendOnlineFriendsTo(ws, ws.auth.publicKey!);
        await broadcastPresence(ws.auth.publicKey!, ws.auth.username, true);
      }

      // Flush any messages queued while this user was offline.
      const pending = await DB.flushPending(ws.auth.publicKey!);
      if (pending.length > 0) {
        console.log(`📬 [${username || senderId}] Delivering ${pending.length} queued message(s)`);
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
            const senderSock = onlineUsers.get(env.sender);
            if (senderSock && senderSock.readyState === WebSocket.OPEN) {
              senderSock.send(JSON.stringify(receipt));
              console.log(`✅ [${env.sender}] queued→delivered (${env.messageId})`);
            } else {
              // Sender offline too — queue the receipt for their next sign-in.
              const senderPk = await DB.getPkByUsername(env.sender);
              if (senderPk) await DB.enqueuePending(senderPk, receipt);
            }
          }
        }
      }
    } else {
      ws.send(
        JSON.stringify({
          type: MessageTypesToReceive.ERROR,
          payload: "AUTH_FAILED",
        })
      );
      console.log(`📥 [${senderId}] Receiving: ERROR (AUTH_FAILED)`);
      ws.close();
    }
  },

  async onSetUsername(ws: ChatSocket, newUsername: string) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";
    console.log(`📤 [${sender}] Sending: SET_USERNAME`);
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
      console.log(`📥 [${newUsername}] Receiving: USERNAME_UPDATED`);

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
      console.log(`📥 [${sender}] Receiving: ERROR (${e.message})`);
    }
  },

  async onAddFriend(ws: ChatSocket, targetUsername: string) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";
    console.log(
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
      console.log(`📥 [${sender}] Receiving: ERROR (USER_NOT_FOUND)`);
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
    const peer = onlineUsers.get(targetUsername);
    if (peer) {
      peer.send(JSON.stringify(requestEnvelope));
      console.log(
        `📥 [${targetUsername}] Receiving: FRIEND_REQUEST (from: ${sender})`
      );
    } else {
      await DB.enqueuePending(targetPk, requestEnvelope);
      console.log(`📦 [${targetUsername}] Queued: FRIEND_REQUEST (from: ${sender})`);
    }

    ws.send(
      JSON.stringify({
        type: MessageTypesToReceive.DIRECT_MESSAGE,
        sender: "SYSTEM",
        payload: `Invite sent to ${targetUsername}`,
      })
    );
    console.log(`📥 [${sender}] Receiving: DIRECT_MESSAGE (from: SYSTEM)`);
  },

  async onAcceptInvite(ws: ChatSocket, targetUsername: string) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";
    console.log(
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
      console.log(`📥 [${sender}] Receiving: ERROR (USER_NOT_FOUND)`);
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
    console.log(
      `📥 [${sender}] Receiving: FRIEND_ADDED (username: ${targetUsername})`
    );

    // 3. Send "FRIEND_ADDED" to TARGET (Contains MY PK) — live or queued.
    const addedEnvelope = {
      type: MessageTypesToReceive.FRIEND_ADDED,
      username: ws.auth.username,
      pk: ws.auth.publicKey!,
    };
    const peer = onlineUsers.get(targetUsername);
    if (peer) {
      peer.send(JSON.stringify(addedEnvelope));
      console.log(
        `📥 [${targetUsername}] Receiving: FRIEND_ADDED (username: ${sender})`
      );
    } else {
      await DB.enqueuePending(targetPk, addedEnvelope);
      console.log(`📦 [${targetUsername}] Queued: FRIEND_ADDED (username: ${sender})`);
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

  async onRemoveFriend(ws: ChatSocket, targetUsername: string) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";
    console.log(
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
      console.log(`📥 [${sender}] Receiving: ERROR (USER_NOT_FOUND)`);
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
      console.log(`📥 [${sender}] Receiving: ERROR (NOT_FRIENDS)`);
      return;
    }

    // Notify the sender
    ws.send(
      JSON.stringify({
        type: MessageTypesToReceive.FRIEND_REMOVED,
        username: targetUsername,
      })
    );
    console.log(
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
      console.log(
        `📥 [${targetUsername}] Receiving: FRIEND_REMOVED (username: ${sender})`
      );
    }
  },

  async onMessage(ws: ChatSocket, targetUsername: string, payload: any, messageId?: string) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";
    console.log(`📤 [${sender}] Sending: MESSAGE (target: ${targetUsername})`);

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
      console.log(`📥 [${sender}] Receiving: ERROR (NOT_FRIENDS)`);
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
    };
    const peer = onlineUsers.get(targetUsername);
    if (peer && peer.readyState === WebSocket.OPEN) {
      peer.send(JSON.stringify(envelope));
      console.log(
        `📥 [${targetUsername}] Receiving: DIRECT_MESSAGE (from: ${sender})`
      );
      // Receipt: delivered to the recipient's live socket.
      if (messageId) {
        ws.send(JSON.stringify({ type: MessageTypesToReceive.MESSAGE_DELIVERED, messageId }));
      }
    } else {
      // Recipient offline: queue for delivery on next auth.
      await DB.enqueuePending(targetPk, envelope);
      console.log(`📦 [${targetUsername}] Queued: DIRECT_MESSAGE (from: ${sender})`);
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
  async onImageMessage(ws: ChatSocket, targetUsername: string, payload: any, messageId?: string) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";
    console.log(`📤 [${sender}] Sending: IMAGE_MESSAGE (target: ${targetUsername})`);

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
    };
    const peer = onlineUsers.get(targetUsername);
    if (peer && peer.readyState === WebSocket.OPEN) {
      peer.send(JSON.stringify(envelope));
      console.log(`📥 [${targetUsername}] Receiving: IMAGE_MESSAGE (from: ${sender})`);
      if (messageId) {
        ws.send(JSON.stringify({ type: MessageTypesToReceive.MESSAGE_DELIVERED, messageId }));
      }
    } else {
      await DB.enqueuePending(targetPk, envelope);
      console.log(`📦 [${targetUsername}] Queued: IMAGE_MESSAGE (from: ${sender})`);
      ApnsService.send(targetPk, ws.auth.username || "New photo", "Sent you a photo");
      if (messageId) {
        ws.send(JSON.stringify({ type: MessageTypesToReceive.MESSAGE_QUEUED, messageId }));
      }
    }
  },

  async onAudio(ws: ChatSocket, targetUsername: string, payload: any) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";
    console.log(
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
      console.log(`📥 [${sender}] Receiving: ERROR (NOT_FRIENDS)`);
      return;
    }

    const envelope = {
      type: MessageTypesToReceive.AUDIO_MESSAGE,
      sender: ws.auth.username, // Send Username, Client resolves PK locally
      payload,
    };
    const peer = onlineUsers.get(targetUsername);
    if (peer && peer.readyState === WebSocket.OPEN) {
      peer.send(JSON.stringify(envelope));
      console.log(
        `📥 [${targetUsername}] Receiving: AUDIO_MESSAGE (from: ${sender})`
      );
    } else {
      // Recipient offline: queue for delivery on next auth.
      await DB.enqueuePending(targetPk, envelope);
      console.log(`📦 [${targetUsername}] Queued: AUDIO_MESSAGE (from: ${sender})`);
    }
  },

  async onAudioStreamStart(
    ws: ChatSocket,
    targetUsername: string,
    payload: any
  ) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";
    console.log(
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

    const peer = onlineUsers.get(targetUsername);
    if (peer && peer.readyState === WebSocket.OPEN) {
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

    const peer = onlineUsers.get(targetUsername);
    if (peer && peer.readyState === WebSocket.OPEN) {
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
    console.log(
      `📤 [${sender}] Sending: AUDIO_STREAM_END (target: ${targetUsername})`
    );

    const targetPk = await DB.getPkByUsername(targetUsername);
    if (!targetPk) return;

    const areFriends = await DB.checkFriendship(ws.auth.publicKey!, targetPk);
    if (!areFriends) return;

    const peer = onlineUsers.get(targetUsername);
    if (peer && peer.readyState === WebSocket.OPEN) {
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
    console.log(`📤 [${sender}] Sending: GET_ALL_USERS (query: "${q}")`);

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
    console.log(`📥 [${sender}] Receiving: USER_LIST_RESPONSE (${results.length})`);
  },

  // AES is treated just like a message, but logic is handled by client
  async onAes(ws: ChatSocket, targetUsername: string, payload: any) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";
    console.log(`📤 [${sender}] Sending: AES (target: ${targetUsername})`);

    // Only friends may push handshake material — blocks unsolicited handshakes.
    if (!(await isVerifiedFriend(ws, targetUsername))) return;

    const peer = onlineUsers.get(targetUsername);
    if (peer && peer.readyState === WebSocket.OPEN) {
      peer.send(
        JSON.stringify({
          type: MessageTypesToReceive.AES,
          sender: ws.auth.username,
          payload,
        })
      );
      console.log(`📥 [${targetUsername}] Receiving: AES (from: ${sender})`);
    }
  },

  async onCallInitiate(ws: ChatSocket, targetUsername: string, payload: any) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";
    console.log(
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

    const peer = onlineUsers.get(targetUsername);
    if (peer && peer.readyState === WebSocket.OPEN) {
      peer.send(
        JSON.stringify({
          type: MessageTypesToReceive.CALL_INCOMING,
          sender: ws.auth.username,
          payload,
        })
      );
      console.log(
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
    console.log(
      `📤 [${sender}] Sending: CALL_ACCEPT (target: ${targetUsername})`
    );

    if (!(await isVerifiedFriend(ws, targetUsername))) return;
    const peer = onlineUsers.get(targetUsername);
    if (peer && peer.readyState === WebSocket.OPEN) {
      peer.send(
        JSON.stringify({
          type: MessageTypesToReceive.CALL_ACCEPTED,
          sender: ws.auth.username,
        })
      );
      console.log(
        `📥 [${targetUsername}] Receiving: CALL_ACCEPTED (from: ${sender})`
      );
    }
  },

  async onCallReject(ws: ChatSocket, targetUsername: string, payload: any) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";
    console.log(
      `📤 [${sender}] Sending: CALL_REJECT (target: ${targetUsername})`
    );

    if (!(await isVerifiedFriend(ws, targetUsername))) return;
    const peer = onlineUsers.get(targetUsername);
    if (peer && peer.readyState === WebSocket.OPEN) {
      peer.send(
        JSON.stringify({
          type: MessageTypesToReceive.CALL_REJECTED,
          sender: ws.auth.username,
        })
      );
      console.log(
        `📥 [${targetUsername}] Receiving: CALL_REJECTED (from: ${sender})`
      );
    }
  },

  async onCallEnd(ws: ChatSocket, targetUsername: string, payload: any) {
    const sender =
      ws.auth.username || ws.auth.publicKey?.substring(0, 8) || "Unknown";
    console.log(`📤 [${sender}] Sending: CALL_END (target: ${targetUsername})`);

    if (!(await isVerifiedFriend(ws, targetUsername))) return;
    const peer = onlineUsers.get(targetUsername);
    if (peer && peer.readyState === WebSocket.OPEN) {
      peer.send(
        JSON.stringify({
          type: MessageTypesToReceive.CALL_ENDED,
          sender: ws.auth.username,
        })
      );
      console.log(
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
    const peer = onlineUsers.get(targetUsername);
    if (peer && peer.readyState === WebSocket.OPEN) {
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
        console.log(
          `🔀 [${sender}→${targetUsername}] relay CALL_MEDIA_CHUNK #${ws.mediaRelayCount} (${typeof payload === "string" ? payload.length : "?"
          } chars)`
        );
      }
    } else {
      // Recipient not connected → chunk is dropped (calls need both online).
      ws.mediaDropCount = (ws.mediaDropCount || 0) + 1;
      if (ws.mediaDropCount <= 3 || ws.mediaDropCount % 100 === 0) {
        console.log(
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
    console.log(`🔔 [${ws.auth.username || "?"}] push token registered (${platform})`);
  },
};

// --- SERVER LOOP ---

wss.on("connection", (ws: WebSocket, req: http.IncomingMessage) => {
  const socket = ws as ChatSocket;
  socket.auth = { step: "INIT" };
  socket.isAlive = true;
  socket.preAuthMsgs = 0;

  // Per-IP connection rate limit (pre-auth flood guard).
  const ip = clientIp(req);
  if (!allowConnection(ip)) {
    console.log(`⛔ [${ip}] connection rate-limited`);
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
      // Pre-auth flood guard: bound how many frames a socket may send before
      // it authenticates.
      if (socket.auth.step !== "AUTHENTICATED") {
        socket.preAuthMsgs = (socket.preAuthMsgs || 0) + 1;
        if (socket.preAuthMsgs > MAX_PREAUTH_MSGS) {
          console.log(`⛔ pre-auth message flood — closing socket`);
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
      console.log(`📨 [${sender}] Received message type: ${msg.type}`);

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
        case MessageTypesToSent.MESSAGE:
          await Handlers.onMessage(socket, msg.targetPk, msg.payload, msg.messageId); // msg.targetPk here acts as username field container
          break;
        case MessageTypesToSent.IMAGE_MESSAGE:
          await Handlers.onImageMessage(socket, msg.targetPk, msg.payload, msg.messageId);
          break;
        case MessageTypesToSent.AUDIO_MESSAGE:
          await Handlers.onAudio(socket, msg.targetPk, msg.payload); // msg.targetPk here acts as username field container
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
        case MessageTypesToSent.REGISTER_PUSH_TOKEN:
          await Handlers.onRegisterPushToken(socket, msg.payload);
          break;
      }
    } catch (e) {
      console.error(e);
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
        console.error("[presence] offline broadcast failed", e)
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
      console.log(`💔 Terminating stale connection: ${socket.auth.username || "Unknown"}`);
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

httpServer.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT} — WS at /ws, Stripe webhook at /stripe/webhook`);
});
