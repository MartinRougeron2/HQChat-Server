/**
 * A headless v2 protocol client, for the end-to-end suite.
 *
 * This is the replacement for `legacy/test-client.ts`, which drove the retired
 * `/ws` monolith. That file was the ONLY end-to-end coverage of the handshake
 * and the ratchet against a running server, and `legacy/README.md` set the
 * condition for deleting it: "connect through EMQX with a real token, publish a
 * ConversationEnvelope, assert the peer decrypts it, assert the topic ACL
 * refuses a stranger." That is what this does.
 *
 * It speaks exactly what the apps speak — REST for auth and the friend graph,
 * MQTT for conversations — so a bug it does not see is a bug the apps would not
 * see either. Nothing here re-implements crypto: it drives `lib/ratchet-session`
 * and `lib/envelope` directly, which is the point.
 */

import mqtt, { type MqttClient } from "mqtt";
import * as crypto from "crypto";
import { authProof } from "../../lib/auth-proof";
import { friendshipHash } from "../../lib/crypto-utils";
import { keyMatchesId, peerId } from "../../lib/identity";
import {
  Kem,
  SessionState,
  InitHeader,
  MessageHeader,
  startAsInitiator,
  startAsResponder,
  seal,
  open as openRatchet,
} from "../../lib/ratchet-session";
import { EnvelopeV2, canonicalHeader, parseEnvelope } from "../../lib/envelope";

const AUTH_BASE = (process.env.TEST_AUTH_URL || "http://127.0.0.1:8081").replace(/\/$/, "");
const API_BASE = (process.env.TEST_API_URL || "http://127.0.0.1:8080").replace(/\/$/, "");
const EMQX_URL = process.env.TEST_EMQX_URL || "ws://127.0.0.1:8083/mqtt";

/**
 * The native HQC library is loaded LAZILY.
 *
 * `lib/hqc.ts` dlopen's an x86 `.so` at module scope and throws if it is not
 * loadable — on an arm64 laptop, say. A top-level import would therefore crash
 * this file before any test could skip, which is exactly what it did the first
 * time. So the crypto arrives through `loadCrypto()`, the same bargain
 * `legacy/test-client.ts` made.
 */
type Crypto = {
  kem: Kem;
  seedBytes: number;
  hqcDecapsulate: (sk: Buffer, ct: Buffer) => Buffer;
  aesEncrypt: (text: string, key: Buffer, aad?: Buffer) => string;
  aesDecrypt: (b64: string, key: Buffer, aad?: Buffer) => string;
  keypair: () => { pk: Buffer; sk: Buffer };
};

let cached: Crypto | null = null;

export async function loadCrypto(): Promise<Crypto> {
  if (cached) return cached;
  const hqc = await import("../../lib/hqc");
  const bot = await import("../../bot/crypto");
  const keypair = () =>
    hqc.HqcWrapper.keypairFromSeed(crypto.randomBytes(hqc.HQC_CONSTANTS.SEED_BYTES));
  cached = {
    kem: {
      generateKeypair: keypair,
      encapsulate: (pk) => bot.hqcEncapsulate(pk),
      decapsulate: (sk, ct) => bot.hqcDecapsulate(sk, ct),
    },
    seedBytes: hqc.HQC_CONSTANTS.SEED_BYTES,
    hqcDecapsulate: bot.hqcDecapsulate,
    aesEncrypt: bot.aesEncrypt,
    aesDecrypt: bot.aesDecrypt,
    keypair,
  };
  return cached;
}

export interface Received {
  from: string;
  text: string;
}

/** Thrown when the environment cannot support the suite, so callers can skip. */
export class NotAvailable extends Error {}

async function http(base: string, method: string, path: string, body?: unknown, token?: string) {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: {
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const text = await res.text();
  let json: any;
  try { json = text ? JSON.parse(text) : {}; } catch { json = { raw: text }; }
  return { status: res.status, body: json };
}

export class TestClient {
  readonly pk: Buffer;
  readonly sk: Buffer;
  readonly pkHex: string;
  /** What the server, the broker and every peer call this client. */
  readonly id: string;
  username = "";

  private sessionToken = "";
  private mqttToken = "";
  private client: MqttClient | undefined;
  private sessions = new Map<string, SessionState>();
  /** Our own prekey secrets, by id. */
  private prekeySecrets: { mediumSk: Buffer; oneTime: Map<number, Buffer> } = {
    mediumSk: Buffer.alloc(0),
    oneTime: new Map(),
  };

  readonly inbox: Received[] = [];
  private cursor = 0;
  /** Frames that arrived but could not be opened — the suite asserts on these. */
  readonly undecryptable: string[] = [];

  private readonly c: Crypto;

  constructor(c: Crypto) {
    this.c = c;
    const pair = c.keypair();
    this.pk = pair.pk;
    this.sk = pair.sk;
    this.pkHex = pair.pk.toString("hex");
    this.id = peerId(this.pkHex);
  }

  // ── REST ───────────────────────────────────────────────────────────────────

  async register(username: string): Promise<void> {
    const init = await http(AUTH_BASE, "POST", "/auth/free/init", { pk: this.pkHex });
    if (init.status !== 200 || !init.body?.ct) {
      throw new NotAvailable(`auth/init returned ${init.status}`);
    }
    // The challenge proves possession of the secret key: decapsulate, then HKDF
    // with the "auth" label. It is NOT a decryption oracle — the server never
    // sees a plaintext we chose.
    const ss = this.c.hqcDecapsulate(this.sk, Buffer.from(String(init.body.ct), "base64"));
    const verify = await http(AUTH_BASE, "POST", "/auth/free/verify", {
      pk: this.pkHex,
      // BASE64, not the raw Buffer. `handleVerify` does
      // `Buffer.from(String(solution), "base64")`, and JSON.stringify turns a
      // Buffer into `{"type":"Buffer","data":[…]}` — so `String(...)` of that is
      // "[object Object]", which base64-decodes to garbage and 401s. Every e2e
      // test failed on this and none of them could say why, because a wrong
      // proof and a wrong ENCODING of a right proof are the same 401.
      solution: authProof(ss).toString("base64"),
    });
    if (verify.status !== 200) {
      throw new Error(`auth/verify returned ${verify.status} ${JSON.stringify(verify.body)}`);
    }
    this.sessionToken = verify.body.sessionToken;
    this.mqttToken = verify.body.mqttToken;
    // The server's view of who we are has to match ours, or every topic we touch
    // belongs to somebody else and the broker refuses it with 0x87.
    if (verify.body.id && verify.body.id !== this.id) {
      throw new Error(`the server named us ${verify.body.id}, we are ${this.id}`);
    }

    this.username = username;
    const named = await http(API_BASE, "POST", "/username", { username }, this.sessionToken);
    if (named.status !== 200) {
      throw new Error(`username returned ${named.status} ${JSON.stringify(named.body)}`);
    }
  }

  api(method: string, path: string, body?: unknown) {
    return http(API_BASE, method, path, body, this.sessionToken);
  }

  /** Publish a bundle so peers can open sessions with us. */
  async publishPrekeys(count = 4): Promise<void> {
    const medium = this.c.kem.generateKeypair();
    this.prekeySecrets.mediumSk = medium.sk;
    const oneTime: Array<{ id: number; prekey: string }> = [];
    for (let id = 0; id < count; id++) {
      const pair = this.c.kem.generateKeypair();
      this.prekeySecrets.oneTime.set(id, pair.sk);
      oneTime.push({ id, prekey: pair.pk.toString("hex") });
    }
    const res = await this.api("POST", "/prekeys", {
      medium: medium.pk.toString("hex"),
      oneTime,
    });
    if (res.status !== 200) {
      throw new Error(`POST /prekeys returned ${res.status} ${JSON.stringify(res.body)}`);
    }
  }

  // ── MQTT ───────────────────────────────────────────────────────────────────

  async connect(timeoutMs = 15000): Promise<void> {
    return new Promise((resolve, reject) => {
      const c = mqtt.connect(EMQX_URL, {
        // The client id, not the public key. EMQX keys the topic ACL on this
        // (`WHERE id = ${clientid}`), and it used to carry 14474 characters in
        // every CONNECT packet.
        clientId: this.id,
        username: this.id,
        password: this.mqttToken,
        protocolVersion: 5,
        // Persistent, exactly as the apps connect — this is what makes the
        // broker queue an `init` for a client that is offline.
        clean: false,
        reconnectPeriod: 0,
        connectTimeout: timeoutMs,
      });
      const timer = setTimeout(() => reject(new NotAvailable("MQTT connect timed out")), timeoutMs);
      c.on("connect", () => {
        clearTimeout(timer);
        this.client = c;
        c.subscribe(`u/${this.id}/inbox`, { qos: 1 }, (err) =>
          err ? reject(err) : resolve()
        );
      });
      c.on("error", (e) => { clearTimeout(timer); reject(new NotAvailable(e.message)); });
      c.on("message", (topic, payload) => this.onFrame(topic, payload));
    });
  }

  /** Drop the connection without unsubscribing, so the broker keeps queueing. */
  async goOffline(): Promise<void> {
    await new Promise<void>((r) => this.client?.end(true, {}, () => r()));
    this.client = undefined;
  }

  subscribeConversation(peerId_: string): Promise<void> {
    return new Promise((resolve, reject) => {
      this.client?.subscribe(`c/${friendshipHash(this.id, peerId_)}`, { qos: 1 }, (err) =>
        err ? reject(err) : resolve()
      );
    });
  }

  /**
   * Fetch a peer's identity key and VERIFY it against their id.
   *
   * Exactly what the real clients do at friend-add: the directory ships ids, and
   * the key is checked rather than trusted. A key that does not hash to the id
   * is refused, which is the property the whole identifier change buys.
   */
  async fetchPeerKey(peerId_: string): Promise<Buffer> {
    const res = await http(API_BASE, "GET", `/peer/${peerId_}/key`);
    if (res.status !== 200 || typeof res.body?.publicKey !== "string") {
      throw new Error(`GET /peer/{id}/key returned ${res.status} ${JSON.stringify(res.body)}`);
    }
    const served = String(res.body.publicKey);
    if (!keyMatchesId(served, peerId_)) {
      throw new Error(`the key served for ${peerId_.slice(0, 12)}… does not hash to that id`);
    }
    return Buffer.from(served, "hex");
  }

  /** Attempt a publish and report whether the broker accepted it. Used to prove
   *  the ACL refuses a stranger — an unauthorized publish is dropped, and with
   *  MQTT 5 the broker returns a reason code for it. */
  publishRaw(topic: string, payload: string): Promise<{ accepted: boolean; reason?: number }> {
    return new Promise((resolve) => {
      if (!this.client) return resolve({ accepted: false });
      this.client.publish(topic, payload, { qos: 1 }, (err: any) => {
        if (err) return resolve({ accepted: false, reason: err?.code });
        resolve({ accepted: true });
      });
    });
  }

  // ── Protocol ───────────────────────────────────────────────────────────────

  /** Seal a frame WITHOUT publishing it, so a test can reorder or tamper first. */
  async sealOnly(peer: TestClient, text: string): Promise<EnvelopeV2> {
    let session = this.sessions.get(peer.id);
    if (!session) {
      // The CLIENT ID, exactly as the bot and the app send it. This used to send
      // `peer.username`, which is why the suite passed while both real clients
      // were being refused with `peer must be 1–128 characters`: the test was
      // exercising an input shape nothing in production uses. Sending the id is
      // now that shape.
      const claimed = await this.api("POST", "/prekeys/claim", { peer: peer.id });
      if (claimed.status !== 200) {
        throw new Error(`claim returned ${claimed.status} ${JSON.stringify(claimed.body)}`);
      }
      // The identity key comes from the server and is VERIFIED against the id,
      // rather than being reached for out of the peer object — the real clients
      // have no such shortcut, and the check is the thing worth exercising.
      const identityPk = await this.fetchPeerKey(peer.id);
      const started = startAsInitiator(this.c.kem, {
        identityPk,
        mediumPk: Buffer.from(String(claimed.body.medium), "hex"),
        oneTimePk: claimed.body.oneTime
          ? Buffer.from(String(claimed.body.oneTime.prekey), "hex")
          : null,
        oneTimeId: claimed.body.oneTime ? Number(claimed.body.oneTime.id) : null,
      });
      session = started.state;
      this.sessions.set(peer.id, session);
    }

    const sealed = seal(this.c.kem, session);
    const env: EnvelopeV2 = {
      v: 2,
      t: sealed.initHeader ? "init" : "msg",
      sender: this.id,
      msgId: crypto.randomUUID(),
      cid: sealed.header.cid,
      n: sealed.header.n,
      pn: sealed.header.pn,
      ...(sealed.initHeader
        ? {
            // On `init` only: the responder may never have fetched our key, and
            // verifies this against `sender` rather than trusting it.
            senderPk: this.pkHex,
            rk: sealed.initHeader.rk.toString("base64"),
            ctId: sealed.initHeader.ctId.toString("base64"),
            ctMt: sealed.initHeader.ctMt.toString("base64"),
            ...(sealed.initHeader.ctOt
              ? {
                  ctOt: sealed.initHeader.ctOt.toString("base64"),
                  otId: sealed.initHeader.otId,
                }
              : {}),
          }
        : {
            ...(sealed.header.rk ? { rk: sealed.header.rk.toString("base64") } : {}),
            ...(sealed.header.kemCt ? { kemCt: sealed.header.kemCt.toString("base64") } : {}),
          }),
      payload: "",
    };
    env.payload = this.c.aesEncrypt(text, sealed.key, canonicalHeader(env));

    return env;
  }

  /** Seal and publish, on whichever topic can deliver the frame. */
  async send(peer: TestClient, text: string): Promise<EnvelopeV2> {
    const env = await this.sealOnly(peer, text);
    const topic = env.t === "init"
      ? `u/${peer.id}/inbox`
      : `c/${friendshipHash(this.id, peer.id)}`;
    await this.publishRaw(topic, JSON.stringify(env));
    return env;
  }

  private onFrame(topic: string, payload: Buffer) {
    let parsed: unknown;
    try { parsed = JSON.parse(payload.toString("utf8")); } catch { return; }
    // `parseEnvelope` has already refused any frame whose `sender` is not a
    // well-formed client id, and any `init` whose `senderPk` does not hash to it.
    const env = parseEnvelope(parsed);
    if (!env) return;
    if (env.sender === this.id) return;

    const expected = env.t === "init"
      ? `u/${this.id}/inbox`
      : `c/${friendshipHash(this.id, env.sender)}`;
    if (topic !== expected) return;

    const header: MessageHeader = {
      cid: env.cid,
      n: env.n,
      pn: env.pn,
      ...(env.rk ? { rk: Buffer.from(env.rk, "base64") } : {}),
      ...(env.kemCt ? { kemCt: Buffer.from(env.kemCt, "base64") } : {}),
    };

    let session = this.sessions.get(env.sender);
    if (env.t === "init") {
      if (session) return; // never replace a live session from an inbound init
      if (!env.ctId || !env.ctMt || !env.rk) return;
      const init: InitHeader = {
        ctId: Buffer.from(env.ctId, "base64"),
        ctMt: Buffer.from(env.ctMt, "base64"),
        ctOt: env.ctOt ? Buffer.from(env.ctOt, "base64") : null,
        otId: env.ctOt ? (env.otId ?? null) : null,
        rk: Buffer.from(env.rk, "base64"),
        cid: env.cid,
      };
      const opened = startAsResponder(this.c.kem, {
        identitySk: this.sk,
        mediumSk: this.prekeySecrets.mediumSk,
        oneTimeSk: (id) => this.prekeySecrets.oneTime.get(id) ?? null,
      }, init);
      if (!opened) { this.undecryptable.push(env.msgId); return; }
      session = opened;
    }
    if (!session) { this.undecryptable.push(env.msgId); return; }

    const mk = openRatchet(this.c.kem, session, header);
    if (!mk) { this.undecryptable.push(env.msgId); return; }
    try {
      const text = this.c.aesDecrypt(env.payload, mk, canonicalHeader(env));
      this.sessions.set(env.sender, session);
      this.inbox.push({ from: env.sender, text });
    } catch {
      this.undecryptable.push(env.msgId);
    }
  }

  /** Next unread message, waiting up to `timeoutMs` for it to arrive. */
  async next(timeoutMs = 8000): Promise<Received> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (this.cursor < this.inbox.length) return this.inbox[this.cursor++]!;
      await new Promise((r) => setTimeout(r, 50));
    }
    throw new Error(`no message within ${timeoutMs}ms`);
  }

  async close(): Promise<void> {
    await new Promise<void>((r) => this.client?.end(true, {}, () => r()));
  }
}

/** Probe: are a live auth server, api and broker actually reachable? */
export async function e2eAvailable(): Promise<boolean> {
  try {
    await loadCrypto();
  } catch {
    return false; // native HQC library missing (an arm64 laptop, for instance)
  }
  try {
    const [auth, api, broker] = await Promise.all([
      fetch(`${AUTH_BASE}/health`).then((r) => r.ok).catch(() => false),
      fetch(`${API_BASE}/health`).then((r) => r.ok).catch(() => false),
      brokerReachable(),
    ]);
    return auth && api && broker;
  } catch {
    return false;
  }
}

/** A broker that answers a CONNECT. Checked separately from the HTTP services
 *  because a missing one would otherwise surface as a test timeout rather than
 *  a skip — and, in CI, as a green job that ran nothing. */
function brokerReachable(timeoutMs = 4000): Promise<boolean> {
  return new Promise((resolve) => {
    const probe = mqtt.connect(EMQX_URL, {
      reconnectPeriod: 0,
      connectTimeout: timeoutMs,
      clientId: `probe-${crypto.randomBytes(6).toString("hex")}`,
    });
    const done = (ok: boolean) => {
      probe.end(true, {}, () => resolve(ok));
    };
    // A refused CONNECT still proves a broker is THERE — the credentials are
    // what it is rejecting, and the real clients bring their own.
    probe.on("connect", () => done(true));
    probe.on("error", (e) => done(/not authorized|bad user|unauthorized/i.test(e.message)));
    setTimeout(() => done(false), timeoutMs + 500);
  });
}
