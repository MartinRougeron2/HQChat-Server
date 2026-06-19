/**
 * TestClient — a full DissQus protocol client for end-to-end tests.
 *
 * It speaks exactly what the Swift apps speak: HQC challenge/response auth, the
 * per-direction transport session keys, the per-friend AES handshake, and the
 * message/image crypto (inner AES + outer HQC for text; AES-only for images).
 * Two of these driven against a running server reproduce the real user journey.
 *
 * Needs the native HQC lib, so it only runs where that lib is present
 * (Linux/CI/VPS). Callers should skip when `loadCrypto()` throws.
 */
import WebSocket from "ws";
import { MessageTypesToSent as Out, MessageTypesToReceive as In } from "../../enums";

type Crypto = {
  HqcWrapper: typeof import("../../lib/hqc").HqcWrapper;
  PARAM_K: number;
  hqcEncrypt: typeof import("../../bot/crypto").hqcEncrypt;
  hqcDecrypt: typeof import("../../bot/crypto").hqcDecrypt;
  aesEncrypt: typeof import("../../bot/crypto").aesEncrypt;
  aesDecrypt: typeof import("../../bot/crypto").aesDecrypt;
  deriveSharedKey: typeof import("../../bot/crypto").deriveSharedKey;
  freshSeed: typeof import("../../bot/crypto").freshSeed;
  deriveSessionKeys: typeof import("../../lib/secure-transport").deriveSessionKeys;
  unwrap: typeof import("../../lib/secure-transport").unwrap;
};

/** Load the crypto modules; throws where the native HQC lib is unavailable. */
export async function loadCrypto(): Promise<Crypto> {
  const hqc = await import("../../lib/hqc");
  const botCrypto = await import("../../bot/crypto");
  const transport = await import("../../lib/secure-transport");
  return {
    HqcWrapper: hqc.HqcWrapper,
    PARAM_K: hqc.HQC_CONSTANTS.PARAM_K,
    hqcEncrypt: botCrypto.hqcEncrypt,
    hqcDecrypt: botCrypto.hqcDecrypt,
    aesEncrypt: botCrypto.aesEncrypt,
    aesDecrypt: botCrypto.aesDecrypt,
    deriveSharedKey: botCrypto.deriveSharedKey,
    freshSeed: botCrypto.freshSeed,
    deriveSessionKeys: transport.deriveSessionKeys,
    unwrap: transport.unwrap,
  };
}

interface FriendState {
  pk: string;
  mySeed?: Buffer;
  peerSeed?: Buffer;
  sharedKey?: Buffer;
}

interface Waiter {
  match: (msg: any) => boolean;
  resolve: (msg: any) => void;
  reject: (e: Error) => void;
  timer: NodeJS.Timeout;
}

export interface ReceivedMessage {
  from: string;
  text?: string;
  imageContent?: string; // e.g. "IMAGE:<b64>" / "IMAGE_ONCE:<b64>"
}

export class TestClient {
  readonly pkHex: string;
  username = "";
  private ws!: WebSocket;
  private readonly sk: Buffer;
  private readonly pk: Buffer;
  private txKey: Buffer | null = null;
  private rxKey: Buffer | null = null;
  private friends: Record<string, FriendState> = {};
  private waiters: Waiter[] = [];
  readonly inbox: ReceivedMessage[] = [];
  private cursor = 0; // next unread index into inbox

  constructor(private readonly c: Crypto, private readonly wsUrl: string, seed?: Buffer) {
    const s = seed ?? require("crypto").randomBytes(32);
    const kp = c.HqcWrapper.generateKeypair(s);
    this.pk = kp.pk;
    this.sk = kp.sk;
    this.pkHex = kp.pk.toString("hex");
  }

  // --- lifecycle ------------------------------------------------------------

  async connectAndAuth(timeoutMs = 15000): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      this.ws = new WebSocket(this.wsUrl);
      const to = setTimeout(() => reject(new Error("connect timeout")), timeoutMs);
      this.ws.on("open", () => { clearTimeout(to); resolve(); });
      this.ws.on("error", (e) => { clearTimeout(to); reject(e); });
      this.ws.on("message", (d) => this.onFrame(d.toString()));
    });
    this.rawSend({ type: Out.AUTH_INIT, payload: this.pkHex });
    await this.once((m) => m.type === In.AUTH_SUCCESS, timeoutMs, "AUTH_SUCCESS");
  }

  async setUsername(name: string, timeoutMs = 10000): Promise<void> {
    this.username = name;
    this.send({ type: Out.SET_USERNAME, payload: name });
    await this.once((m) => m.type === In.USERNAME_UPDATED, timeoutMs, "USERNAME_UPDATED");
  }

  close() {
    for (const w of this.waiters) { clearTimeout(w.timer); }
    this.waiters = [];
    try { this.ws?.close(); } catch { /* ignore */ }
  }

  // --- friendship + handshake ----------------------------------------------

  addFriend(username: string) { this.send({ type: Out.ADD_FRIEND, payload: username }); }
  acceptInvite(username: string) { this.send({ type: Out.ACCEPT_INVITE, payload: username }); }

  /** Resolve once the AES secure channel with `username` is established. */
  async waitForSecureChannel(username: string, timeoutMs = 15000): Promise<void> {
    if (this.friends[username]?.sharedKey) return;
    await this.once(
      (m) => m.type === In.AES && m.sender === username && !!this.friends[username]?.sharedKey,
      timeoutMs,
      `secure channel with ${username}`
    );
  }

  // --- messaging ------------------------------------------------------------

  /** Send a text message (inner AES + outer HQC, like the apps). */
  sendMessage(username: string, text: string, messageId = require("crypto").randomUUID()) {
    const f = this.friends[username];
    if (!f?.sharedKey || !f.pk) throw new Error(`no secure channel with ${username}`);
    const aesB64 = this.c.aesEncrypt(text, f.sharedKey);
    const ct = this.c.hqcEncrypt(Buffer.from(f.pk, "hex"), Buffer.from(aesB64, "utf8"));
    this.send({ type: Out.MESSAGE, targetPk: username, payload: ct.toString("base64"), messageId });
    return messageId;
  }

  /** Send a photo (AES-only on the channel key, like the apps). `content` is the
   *  ready-to-store string, e.g. "IMAGE:<base64>" or "IMAGE_ONCE:<base64>". */
  sendImage(username: string, content: string, messageId = require("crypto").randomUUID()) {
    const f = this.friends[username];
    if (!f?.sharedKey) throw new Error(`no secure channel with ${username}`);
    const payload = this.c.aesEncrypt(content, f.sharedKey);
    this.send({ type: Out.IMAGE_MESSAGE, targetPk: username, payload, messageId });
    return messageId;
  }

  /** Return the next not-yet-read decrypted message (waits if none pending). */
  async nextMessage(timeoutMs = 10000): Promise<ReceivedMessage> {
    if (this.cursor < this.inbox.length) return this.inbox[this.cursor++]!;
    await this.once(
      (m) => (m.type === In.DIRECT_MESSAGE || m.type === In.IMAGE_MESSAGE),
      timeoutMs,
      "incoming message"
    );
    return this.inbox[this.cursor++]!;
  }

  async waitFor(type: string, timeoutMs = 10000) {
    return this.once((m) => m.type === type, timeoutMs, type);
  }

  // --- internals ------------------------------------------------------------

  private once(match: (m: any) => boolean, timeoutMs: number, label: string): Promise<any> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiters = this.waiters.filter((w) => w.timer !== timer);
        reject(new Error(`timeout waiting for ${label}`));
      }, timeoutMs);
      this.waiters.push({ match, resolve, reject, timer });
    });
  }

  private rawSend(obj: any) {
    if (this.ws.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify(obj));
  }

  private send(obj: any) {
    const json = JSON.stringify(obj);
    this.rawSend(this.txKey ? { enc: this.c.aesEncrypt(json, this.txKey) } : JSON.parse(json));
  }

  private onFrame(raw: string) {
    let msg: any;
    try { msg = this.c.unwrap(raw, this.rxKey ?? undefined); } catch { return; }
    this.handle(msg);
    // Resolve any matching waiters AFTER handling (so state is up to date).
    const still: Waiter[] = [];
    for (const w of this.waiters) {
      if (w.match(msg)) { clearTimeout(w.timer); w.resolve(msg); } else { still.push(w); }
    }
    this.waiters = still;
  }

  private handle(msg: any) {
    switch (msg.type) {
      case In.AUTH_CHALLENGE: {
        const nonce = this.c.hqcDecrypt(this.sk, Buffer.from(msg.payload, "base64"), false).subarray(0, this.c.PARAM_K);
        this.rawSend({ type: Out.AUTH_VERIFY, payload: nonce.toString("base64") });
        break;
      }
      case In.SESSION_KEY: {
        const seed = this.c.hqcDecrypt(this.sk, Buffer.from(msg.payload, "base64"), false).subarray(0, this.c.PARAM_K);
        const keys = this.c.deriveSessionKeys(seed);
        this.txKey = keys.c2s;
        this.rxKey = keys.s2c;
        break;
      }
      case In.FRIEND_REQUEST: {
        const sender = msg.sender as string;
        if (msg.pk) this.friends[sender] = { ...(this.friends[sender] || {}), pk: msg.pk };
        break;
      }
      case In.FRIEND_ADDED: {
        const username = (msg.username || msg.sender) as string;
        const f = this.friends[username] || ({} as FriendState);
        if (msg.pk) f.pk = msg.pk;
        this.friends[username] = f;
        if (!f.sharedKey) this.sendAesSeed(username);
        break;
      }
      case In.AES: {
        const sender = msg.sender as string;
        const f = this.friends[sender];
        if (!f) break;
        f.peerSeed = this.c.hqcDecrypt(this.sk, Buffer.from(msg.payload, "base64"), false).subarray(0, this.c.PARAM_K);
        this.sendAesSeed(sender);
        if (f.mySeed && f.peerSeed) f.sharedKey = this.c.deriveSharedKey(f.mySeed, f.peerSeed);
        break;
      }
      case In.DIRECT_MESSAGE: {
        const sender = msg.sender as string;
        const f = this.friends[sender];
        if (!f?.sharedKey || sender === "SYSTEM") break;
        try {
          const aesB64 = this.c.hqcDecrypt(this.sk, Buffer.from(msg.payload, "base64"), true).toString("utf8");
          this.inbox.push({ from: sender, text: this.c.aesDecrypt(aesB64, f.sharedKey) });
        } catch { /* ignore undecryptable */ }
        break;
      }
      case In.IMAGE_MESSAGE: {
        const sender = msg.sender as string;
        const f = this.friends[sender];
        if (!f?.sharedKey) break;
        try {
          this.inbox.push({ from: sender, imageContent: this.c.aesDecrypt(msg.payload, f.sharedKey) });
        } catch { /* ignore */ }
        break;
      }
    }
  }

  private sendAesSeed(username: string) {
    const f = this.friends[username];
    if (!f?.pk) return;
    if (!f.mySeed) f.mySeed = this.c.freshSeed();
    const ct = this.c.hqcEncrypt(Buffer.from(f.pk, "hex"), f.mySeed);
    this.send({ type: Out.AES, payload: ct.toString("base64"), targetPk: username });
  }
}
