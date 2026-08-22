/**
 * TestClient — a full DissQus protocol client for end-to-end tests.
 *
 * It speaks exactly what the Swift apps speak (SECURITY_AUDIT §KM-1): the HQC KEM
 * auth (decapsulate → HKDF proof), the per-direction transport session keys, the
 * per-friend mutual-encapsulation AES handshake, and the message/image crypto
 * (AES-GCM under the ratchet/channel key — no per-message HQC). Two of these
 * driven against a running server reproduce the real user journey.
 *
 * Needs the native HQC lib, so it only runs where that lib is present
 * (Linux/CI/VPS). Callers should skip when `loadCrypto()` throws.
 */
import WebSocket from "ws";
import { MessageTypesToSent as Out, MessageTypesToReceive as In } from "./enums";

type Crypto = {
  HqcWrapper: typeof import("../lib/hqc").HqcWrapper;
  hqcEncapsulate: typeof import("../bot/crypto").hqcEncapsulate;
  hqcDecapsulate: typeof import("../bot/crypto").hqcDecapsulate;
  aesEncrypt: typeof import("../bot/crypto").aesEncrypt;
  aesDecrypt: typeof import("../bot/crypto").aesDecrypt;
  deriveSharedKey: typeof import("../bot/crypto").deriveSharedKey;
  freshSeed: typeof import("../bot/crypto").freshSeed;
  deriveSessionKeys: typeof import("./secure-transport").deriveSessionKeys;
  authProof: typeof import("./secure-transport").authProof;
  unwrap: typeof import("./secure-transport").unwrap;
  deriveEpoch: typeof import("../lib/ratchet").deriveEpoch;
  messageKey: typeof import("../lib/ratchet").messageKey;
  chainNext: typeof import("../lib/ratchet").chainNext;
  ratchetTo: typeof import("../lib/ratchet").ratchetTo;
};

/** Load the crypto modules; throws where the native HQC lib is unavailable. */
export async function loadCrypto(): Promise<Crypto> {
  const hqc = await import("../lib/hqc");
  const botCrypto = await import("../bot/crypto");
  const transport = await import("./secure-transport");
  const ratchet = await import("../lib/ratchet");
  return {
    HqcWrapper: hqc.HqcWrapper,
    hqcEncapsulate: botCrypto.hqcEncapsulate,
    hqcDecapsulate: botCrypto.hqcDecapsulate,
    aesEncrypt: botCrypto.aesEncrypt,
    aesDecrypt: botCrypto.aesDecrypt,
    deriveSharedKey: botCrypto.deriveSharedKey,
    freshSeed: botCrypto.freshSeed,
    deriveSessionKeys: transport.deriveSessionKeys,
    authProof: transport.authProof,
    unwrap: transport.unwrap,
    deriveEpoch: ratchet.deriveEpoch,
    messageKey: ratchet.messageKey,
    chainNext: ratchet.chainNext,
    ratchetTo: ratchet.ratchetTo,
  };
}

interface EpochState {
  epoch: number;
  sendCK: Buffer;
  sendIdx: number;
  recvCK: Buffer;
  recvIdx: number;
  skipped: Record<string, Buffer>;
}
interface FriendState {
  pk: string;
  mySeed?: Buffer; // our contributed shared secret (ss)
  myCt?: Buffer;   // the KEM ciphertext we sent for mySeed (resent on re-handshake)
  peerSeed?: Buffer; // ss decapsulated from the peer's ciphertext
  sharedKey?: Buffer;
  cur?: EpochState;
  prev?: EpochState;
  rot?: { epoch: number; mySeed?: Buffer; myCt?: Buffer; peerSeed?: Buffer };
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
    const kp = c.HqcWrapper.keypairFromSeed(s);
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
  cancelInvite(username: string) { this.send({ type: Out.CANCEL_INVITE, payload: username }); }
  removeFriend(username: string) { this.send({ type: Out.REMOVE_FRIEND, payload: username }); }

  /** Irreversibly delete this account server-side and wait for confirmation. */
  async deleteAccount(timeoutMs = 10000): Promise<void> {
    this.send({ type: Out.DELETE_ACCOUNT });
    await this.once((m) => m.type === In.ACCOUNT_DELETED, timeoutMs, "ACCOUNT_DELETED");
  }

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

  /** Send a text message (AES-GCM under the ratchet/static key — no outer HQC,
   *  §KM-1 step 5). At epoch ≥ 1 the key is a per-message ratchet key and the
   *  frame carries epoch/idx. */
  sendMessage(username: string, text: string, messageId = require("crypto").randomUUID()) {
    const f = this.friends[username];
    if (!f?.pk) throw new Error(`no secure channel with ${username}`);
    let key: Buffer, epoch: number | undefined, idx: number | undefined;
    if (f.cur) {
      key = this.c.messageKey(f.cur.sendCK);
      epoch = f.cur.epoch;
      idx = f.cur.sendIdx;
      f.cur.sendCK = this.c.chainNext(f.cur.sendCK);
      f.cur.sendIdx++;
    } else {
      if (!f.sharedKey) throw new Error(`no secure channel with ${username}`);
      key = f.sharedKey;
    }
    const aesB64 = this.c.aesEncrypt(text, key);
    this.send({ type: Out.MESSAGE, targetPk: username, payload: aesB64, messageId, epoch, idx });
    return messageId;
  }

  /** Tell the server this client is backgrounded (socket stays open). From here
   *  on the server must queue + push rather than relay to us. */
  background() { this.send({ type: Out.APP_BACKGROUND }); }

  /** Back in the foreground — the server flushes anything queued meanwhile. */
  foreground() { this.send({ type: Out.APP_FOREGROUND }); }

  /** Current key-rotation epoch with `username` (0 = legacy static key). */
  currentEpoch(username: string) { return this.friends[username]?.cur?.epoch ?? 0; }

  /** Initiate a Tier-1 rotation to the next epoch (encapsulates our contribution). */
  rotateKeys(username: string) {
    const f = this.friends[username];
    if (!f?.pk) throw new Error(`no friend ${username}`);
    const nextEpoch = this.currentEpoch(username) + 1;
    const { ct, ss } = this.c.hqcEncapsulate(Buffer.from(f.pk, "hex"));
    f.rot = { epoch: nextEpoch, mySeed: ss, myCt: ct };
    this.send({ type: Out.KEY_ROTATE, targetPk: username, payload: ct.toString("base64"), epoch: nextEpoch });
  }

  /** Resolve once the epoch with `username` reaches at least `epoch`. */
  async waitForEpoch(username: string, epoch: number, timeoutMs = 15000): Promise<void> {
    if (this.currentEpoch(username) >= epoch) return;
    await this.once(
      (m) => m.type === In.KEY_ROTATE && this.currentEpoch(username) >= epoch,
      timeoutMs,
      `epoch ${epoch} with ${username}`
    );
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
        // §KM-1: decapsulate → ss, return HKDF(ss,"auth"). No plaintext echoed.
        const ss = this.c.hqcDecapsulate(this.sk, Buffer.from(msg.payload, "base64"));
        this.rawSend({ type: Out.AUTH_VERIFY, payload: this.c.authProof(ss).toString("base64") });
        break;
      }
      case In.SESSION_KEY: {
        const ss = this.c.hqcDecapsulate(this.sk, Buffer.from(msg.payload, "base64"));
        const keys = this.c.deriveSessionKeys(ss);
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
        f.peerSeed = this.c.hqcDecapsulate(this.sk, Buffer.from(msg.payload, "base64"));
        this.sendAesSeed(sender);
        if (f.mySeed && f.peerSeed) f.sharedKey = this.c.deriveSharedKey(f.mySeed, f.peerSeed);
        break;
      }
      case In.DIRECT_MESSAGE: {
        const sender = msg.sender as string;
        const f = this.friends[sender];
        if (!f || sender === "SYSTEM") break;
        const epoch = Number.isInteger(msg.epoch) ? Number(msg.epoch) : 0;
        try {
          // §KM-1 step 5: the payload is the AES-GCM base64 directly.
          const aesB64 = msg.payload as string;
          let key: Buffer | undefined;
          if (epoch >= 1) key = this.obtainRecvKey(f, epoch, Number(msg.idx));
          else key = f.sharedKey;
          if (!key) break;
          this.inbox.push({ from: sender, text: this.c.aesDecrypt(aesB64, key) });
        } catch { /* ignore undecryptable */ }
        break;
      }
      case In.KEY_ROTATE: {
        const sender = msg.sender as string;
        const f = this.friends[sender];
        if (!f?.pk) break;
        const epoch = Number(msg.epoch);
        if (!Number.isInteger(epoch) || epoch <= this.currentEpoch(sender)) break;
        try {
          const peerSs = this.c.hqcDecapsulate(this.sk, Buffer.from(msg.payload, "base64"));
          if (!f.rot || f.rot.epoch !== epoch) f.rot = { epoch };
          f.rot.peerSeed = peerSs;
          if (!f.rot.mySeed) {
            const { ct, ss } = this.c.hqcEncapsulate(Buffer.from(f.pk, "hex"));
            f.rot.mySeed = ss;
            f.rot.myCt = ct;
            this.send({ type: Out.KEY_ROTATE, targetPk: sender, payload: ct.toString("base64"), epoch });
          }
          if (f.rot.mySeed && f.rot.peerSeed) this.installEpoch(f, epoch, f.rot.mySeed, f.rot.peerSeed);
        } catch { /* ignore */ }
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
    // Encapsulate once and remember (ss, ct); resend the stored ct on re-handshake.
    if (!f.mySeed || !f.myCt) {
      const { ct, ss } = this.c.hqcEncapsulate(Buffer.from(f.pk, "hex"));
      f.mySeed = ss;
      f.myCt = ct;
    }
    this.send({ type: Out.AES, payload: f.myCt.toString("base64"), targetPk: username });
  }

  private installEpoch(f: FriendState, epoch: number, mySeed: Buffer, peerSeed: Buffer) {
    const k = this.c.deriveEpoch(mySeed, peerSeed);
    if (f.cur) f.prev = f.cur;
    f.cur = { epoch, sendCK: k.sendCK, sendIdx: 0, recvCK: k.recvCK, recvIdx: 0, skipped: {} };
    delete f.rot;
  }

  private obtainRecvKey(f: FriendState, epoch: number, idx: number): Buffer | undefined {
    const es = f.cur?.epoch === epoch ? f.cur : (f.prev?.epoch === epoch ? f.prev : undefined);
    if (!es || !Number.isInteger(idx) || idx < 0) return undefined;
    const cached = es.skipped[String(idx)];
    if (cached) { delete es.skipped[String(idx)]; return cached; }
    if (idx < es.recvIdx) return undefined;
    const step = this.c.ratchetTo(es.recvCK, es.recvIdx, idx);
    for (const s of step.skipped) es.skipped[String(s.idx)] = s.key;
    es.recvCK = step.ck;
    es.recvIdx = step.nextIdx;
    return step.messageKey;
  }
}
