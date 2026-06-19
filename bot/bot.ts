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
 * IMPORTANT: add the bot's public key (printed on first run) to the server's
 * EXEMPT_PUBLIC_KEYS so it skips the Stripe gate.
 */

import WebSocket from "ws";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { HqcWrapper, HQC_CONSTANTS } from "../lib/hqc";
import { MessageTypesToSent as Out, MessageTypesToReceive as In } from "../enums";
import {
  hqcEncrypt,
  hqcDecrypt,
  aesEncrypt,
  aesDecrypt,
  deriveSharedKey,
  freshSeed,
} from "./crypto";
import { unwrap, deriveSessionKeys } from "../lib/secure-transport";

const { PARAM_K } = HQC_CONSTANTS;
const WS_URL = process.env.SERVER_WS_URL || "wss://chat.martinrougeron.me/ws";
const USERNAME = process.env.BOT_USERNAME || "helper";
const SEED_FILE = path.join(__dirname, ".bot-seed");
const STATE_FILE = path.join(__dirname, ".bot-state.json");

// ── Identity ─────────────────────────────────────────────────────────────────
function loadSeed(): Buffer {
  if (process.env.BOT_SEED) return Buffer.from(process.env.BOT_SEED, "hex");
  if (fs.existsSync(SEED_FILE)) return Buffer.from(fs.readFileSync(SEED_FILE, "utf8").trim(), "hex");
  const seed = crypto.randomBytes(HQC_CONSTANTS.SEED_BYTES);
  fs.writeFileSync(SEED_FILE, seed.toString("hex"));
  return seed;
}

const seed = loadSeed();
const { pk, sk } = HqcWrapper.generateKeypair(seed);
const pkHex = pk.toString("hex");

// ── Per-friend state ─────────────────────────────────────────────────────────
interface FriendState {
  pk: string; // hex public key
  mySeed?: string;
  peerSeed?: string;
  sharedKey?: string; // hex AES-256 key
}
type State = { friends: Record<string, FriendState> };

let state: State = { friends: {} };
function loadState() {
  if (fs.existsSync(STATE_FILE)) {
    try { state = JSON.parse(fs.readFileSync(STATE_FILE, "utf8")); } catch { /* ignore */ }
  }
}
function saveState() {
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
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
  console.log(`🤖 [bot] connecting to ${WS_URL} as "${USERNAME}"`);
  console.log(`🤖 [bot] public key: ${pkHex}|  (add full key to EXEMPT_PUBLIC_KEYS)`);
  txKey = null;
  rxKey = null;
  ws = new WebSocket(WS_URL);

  ws.on("open", () => send({ type: Out.AUTH_INIT, payload: pkHex }));
  ws.on("message", (data) => handle(data.toString()));
  ws.on("close", () => {
    console.log("🤖 [bot] disconnected — reconnecting in 3s");
    setTimeout(connect, 3000);
  });
  ws.on("error", (e) => console.error("🤖 [bot] ws error:", e.message));
}

// ── Message handling ─────────────────────────────────────────────────────────
async function handle(raw: string) {
  let msg: any;
  try { msg = unwrap(raw, rxKey ?? undefined); } catch { return; }

  switch (msg.type) {
    case In.AUTH_CHALLENGE: {
      // Decrypt the HQC challenge (one block) → the 24-byte nonce.
      const ct = Buffer.from(msg.payload, "base64");
      const nonce = hqcDecrypt(sk, ct, false).subarray(0, PARAM_K);
      send({ type: Out.AUTH_VERIFY, payload: nonce.toString("base64") });
      break;
    }

    case In.SESSION_KEY: {
      // Dedicated HQC key exchange: decrypt the 24-byte session seed and derive
      // the transport key. From here, send() encrypts and unwrap() decrypts.
      const seed = hqcDecrypt(sk, Buffer.from(msg.payload, "base64"), false).subarray(0, PARAM_K);
      const keys = deriveSessionKeys(seed);
      txKey = keys.c2s; // bot (client) encrypts with c2s
      rxKey = keys.s2c; // bot (client) decrypts with s2c
      console.log("🤖 [bot] transport session keys established");
      break;
    }
    case In.AUTH_SUCCESS:
      console.log("🤖 [bot] authenticated");
      send({ type: Out.SET_USERNAME, payload: USERNAME });
      break;

    case In.USERNAME_UPDATED:
      console.log(`🤖 [bot] username set to @${msg.payload}`);
      break;

    case In.FRIEND_REQUEST: {
      const sender = msg.sender as string;
      if (msg.pk) state.friends[sender] = { ...(state.friends[sender] || {}), pk: msg.pk };
      saveState();
      console.log(`🤖 [bot] friend request from @${sender} — accepting`);
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
      console.log(`🤖 [bot] friend added: @${username}`);
      break;
    }

    case In.AES: {
      const sender = msg.sender as string;
      const f = state.friends[sender];
      if (!f) break;
      try {
        const peerSeed = hqcDecrypt(sk, Buffer.from(msg.payload, "base64"), false).subarray(0, PARAM_K);
        f.peerSeed = peerSeed.toString("hex");
        // Always (re)send our seed so the peer can derive too. On a re-handshake
        // (e.g. the peer reset after our identity changed) they generated a fresh
        // seed and need ours again; the peer only replies while it has no seed of
        // its own, so this can't loop.
        sendAesSeed(sender);
        if (f.mySeed && f.peerSeed) {
          const key = deriveSharedKey(Buffer.from(f.mySeed, "hex"), Buffer.from(f.peerSeed, "hex"));
          f.sharedKey = key.toString("hex");
          console.log(`🔒 [bot] secure channel established with @${sender}`);
        }
        saveState();
      } catch (e: any) {
        console.error(`🤖 [bot] AES handshake error with @${sender}:`, e.message);
      }
      break;
    }

    case In.DIRECT_MESSAGE: {
      const sender = msg.sender as string;
      const f = state.friends[sender];
      if (!f?.sharedKey || sender === "SYSTEM") break;
      try {
        const key = Buffer.from(f.sharedKey, "hex");
        // Outer HQC → AES base64 string → inner AES → plaintext.
        const aesB64 = hqcDecrypt(sk, Buffer.from(msg.payload, "base64"), true).toString("utf8");
        const text = aesDecrypt(aesB64, key);
        const answer = reply(text);
        console.log(`💬 [bot] @${sender}: ${text}  →  ${answer.split("\n")[0]}`);
        sendMessage(sender, answer);
      } catch (e: any) {
        console.error(`🤖 [bot] message decrypt error from @${sender}:`, e.message);
      }
      break;
    }

    case In.HEARTBEAT_PING:
      send({ type: Out.HEARTBEAT_PONG });
      break;

    case In.PAYMENT_REQUIRED:
      console.error("🤖 [bot] PAYMENT_REQUIRED — add the bot's public key to EXEMPT_PUBLIC_KEYS on the server.");
      break;

    case In.ERROR:
      console.error("🤖 [bot] server error:", msg.payload);
      break;
  }
}

// ── Crypto-aware senders ─────────────────────────────────────────────────────
function sendAesSeed(username: string) {
  const f = state.friends[username];
  if (!f?.pk) return;
  if (!f.mySeed) f.mySeed = freshSeed().toString("hex");
  const ct = hqcEncrypt(Buffer.from(f.pk, "hex"), Buffer.from(f.mySeed, "hex"));
  send({ type: Out.AES, payload: ct.toString("base64"), targetPk: username });
}

function sendMessage(username: string, text: string) {
  const f = state.friends[username];
  if (!f?.sharedKey || !f.pk) return;
  const aesB64 = aesEncrypt(text, Buffer.from(f.sharedKey, "hex"));
  const ct = hqcEncrypt(Buffer.from(f.pk, "hex"), Buffer.from(aesB64, "utf8"));
  send({
    type: Out.MESSAGE,
    targetPk: username,
    payload: ct.toString("base64"),
    messageId: crypto.randomUUID(),
  });
}

// ── Bot brain ────────────────────────────────────────────────────────────────
// Testing build: always replies "hello" to any message.
function reply(_text: string): string {
  return "hello";
}

connect();
