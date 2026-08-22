/**
 * DissQus message stress test — hammer the helper bot with messages.
 *
 * Spins up a synthetic protocol client (real HQC identity, real transport
 * encryption, real AES secure channel) and blasts `message` frames at the
 * always-on helper bot as fast as the configured rate allows. Message path only
 * — no calls / images / audio. The server auto-friends the bot to every user, so
 * the client just auths, sets a username, completes the AES handshake, then
 * fires messages at `@helper`. This exercises the server relay AND the bot
 * (decrypt + reply).
 *
 * Defaults to ONE client on ONE WebSocket: run against the prod origin through
 * Cloudflare and a fleet of parallel connections looks like a connection flood
 * and gets dropped at the edge — a single socket firing many messages doesn't.
 * Every connection also sends `User-Agent: githubstress` so the traffic is easy
 * to identify (or allow-list in a Cloudflare WAF rule).
 *
 * Because the server is a pure relay (it never decrypts message payloads), each
 * client HQC+AES-encrypts ONE fixed payload at startup and reuses it for every
 * send. With the epoch-0 static key the bot still decrypts it correctly every
 * time (no ratchet index involved), so its reply path is exercised too. This
 * keeps the client-side crypto off the hot path so the *server + bot* are what's
 * under load, not this generator.
 *
 * ⚠️  Must run where the server runs (the VPS / a Linux box): it loads the same
 *     native HQC lib (`lib/libhqc_x86.so` + libc.so.6) the server does, which
 *     does NOT load on macOS. Point it at a locally-running server + bot.
 *
 * Run:  cd server/messages && npm run stress
 * Tune via env (all optional):
 *   SERVER_WS_URL     ws://localhost:8080/ws  server to hit
 *   STRESS_CLIENTS    1                       # of sender clients (1 socket by default)
 *   STRESS_UA         githubstress            User-Agent header on every connection
 *   STRESS_RATE       50                      messages/sec PER client (0 = unbounded)
 *   STRESS_DURATION   15                      seconds to fire for
 *   STRESS_MSG_LEN    32                      plaintext length (bytes) per message
 *   STRESS_RAMP_MS    150                     stagger between client connects
 *   BOT_USERNAME      helper                  bot target
 *   STRESS_MAX_BUFFERED  8388608              per-socket backpressure cap (bytes)
 *   STRESS_METRICS_URL  <derived>/metrics     crash-indicator endpoint to poll
 *   STRESS_HTTP_BASE    <derived from WS URL> base for /metrics + /health
 *   METRICS_TOKEN     (unset)                 bearer token if /metrics is guarded
 *   STRESS_POLL_MS    1000                    how often to poll /metrics
 *
 * While blasting, it polls the server's /metrics and prints, at the end, the
 * server-side crash indicators observed UNDER load (event-loop lag, rss, ws
 * clients, active handles) plus a set of REFINED alert thresholds derived from
 * those peaks — paste them into deploy/server.env. If the server stops answering
 * mid-run, that's reported as a crash with the last healthy sample.
 */

import "../lib/config";
import WebSocket from "ws";
import * as crypto from "crypto";
import { HqcWrapper, HQC_CONSTANTS } from "../lib/hqc";
import { MessageTypesToSent as Out, MessageTypesToReceive as In } from "./enums";
import { hqcEncapsulate, hqcDecapsulate, aesEncrypt, deriveSharedKey } from "../bot/crypto";
import { unwrap, wrapString, deriveSessionKeys, authProof } from "./secure-transport";

// ── Config ────────────────────────────────────────────────────────────────────
const WS_URL = process.env.SERVER_WS_URL || "ws://localhost:8080/ws";
const N_CLIENTS = int("STRESS_CLIENTS", 1);
const USER_AGENT = process.env.STRESS_UA || "githubstress";
const RATE = int("STRESS_RATE", 50); // per client per second; 0 = unbounded
const DURATION_S = int("STRESS_DURATION", 15);
const MSG_LEN = int("STRESS_MSG_LEN", 32);
const RAMP_MS = int("STRESS_RAMP_MS", 150);
const BOT = process.env.BOT_USERNAME || "helper";
const MAX_BUFFERED = int("STRESS_MAX_BUFFERED", 8 * 1024 * 1024);

// HTTP crash-indicator endpoints (added alongside /ws). Derived from the WS URL
// unless overridden: ws→http, wss→https, drop the /ws path.
const HTTP_BASE = (process.env.STRESS_HTTP_BASE ||
  WS_URL.replace(/^ws/, "http").replace(/\/ws\/?$/, "")).replace(/\/$/, "");
const METRICS_URL = process.env.STRESS_METRICS_URL || `${HTTP_BASE}/metrics`;
const HEALTH_URL = `${HTTP_BASE}/health`;
const METRICS_TOKEN = process.env.METRICS_TOKEN || "";
const POLL_MS = int("STRESS_POLL_MS", 1000);

const TICK_MS = 5; // pacer resolution
const UNBOUNDED_BURST = 256; // msgs/client/tick when RATE=0 (bounded by backpressure)
const LATENCY_SAMPLE = 20; // record send→delivered latency for 1 in N messages
const MAX_INFLIGHT = 5000; // cap the latency-tracking map

function int(name: string, def: number): number {
  const v = process.env[name];
  const n = v == null ? def : parseInt(v, 10);
  return Number.isFinite(n) ? n : def;
}

// ── Aggregate metrics ───────────────────────────────────────────────────────────
const M = {
  connected: 0,
  ready: 0, // secure channel with the bot established → allowed to fire
  failed: 0,
  sent: 0,
  delivered: 0, // MESSAGE_DELIVERED receipts
  queued: 0, // MESSAGE_QUEUED receipts (bot was offline)
  replies: 0, // DIRECT_MESSAGE frames received back (bot answers)
  rateLimited: 0,
  notFriends: 0,
  otherErrors: 0,
  throttleTicks: 0, // ticks where a client skipped sending due to backpressure
  latencies: [] as number[], // ms, sampled
};
const inflight = new Map<string, number>(); // messageId → send timestamp (sampled)

// ── Server-side crash indicators (polled from /metrics during the blast) ──────────
interface HealthSample {
  tSec: number;
  status: string;
  loopP99: number;
  loopMean: number;
  rssMB: number;
  heapMB: number;
  clients: number;
  handles: number;
  backpressured: number;
  errWindow: number;
  msgPerSec: number;
  tripped: string[];
}
const H = {
  polls: 0,
  fails: 0,
  gotAnyOk: false,
  serverDied: false,
  diedAtSec: null as number | null,
  firstWarnAtSec: null as number | null,
  firstCritAtSec: null as number | null,
  samples: [] as HealthSample[],
  thresholds: null as any, // server's currently-configured thresholds (echoed by /metrics)
  peak: {
    loopP99: 0,
    loopMean: 0,
    rssMB: 0,
    heapMB: 0,
    clients: 0,
    handles: 0,
    backpressured: 0,
    errWindow: 0,
    msgPerSec: 0,
  },
};

async function fetchJson(url: string, timeoutMs = 2000): Promise<any | null> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const headers: Record<string, string> = {};
    if (METRICS_TOKEN) headers.Authorization = `Bearer ${METRICS_TOKEN}`;
    const res = await fetch(url, { signal: ac.signal, headers });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

/** One /metrics poll. Records peaks, status transitions, and server death. */
async function pollHealthOnce(tSec: number) {
  H.polls++;
  const m = await fetchJson(METRICS_URL);
  if (!m) {
    H.fails++;
    // A failure AFTER we've seen the server healthy, while the blast is running,
    // means it stopped answering — the crash we're hunting for.
    if (H.gotAnyOk && !H.serverDied) {
      H.serverDied = true;
      H.diedAtSec = tSec;
    }
    return;
  }
  H.gotAnyOk = true;
  if (m.thresholds) H.thresholds = m.thresholds;
  const s: HealthSample = {
    tSec: Math.round(tSec),
    status: m.status ?? "?",
    loopP99: m.eventLoopLagP99Ms ?? 0,
    loopMean: m.eventLoopLagMeanMs ?? 0,
    rssMB: m.rssMB ?? 0,
    heapMB: m.heapUsedMB ?? 0,
    clients: m.wsClients ?? 0,
    handles: m.activeHandles ?? 0,
    backpressured: m.wsBackpressured ?? 0,
    errWindow: m.errorsPerWindow ?? 0,
    msgPerSec: m.messagesPerSec ?? 0,
    tripped: m.tripped ?? [],
  };
  H.samples.push(s);
  const p = H.peak;
  p.loopP99 = Math.max(p.loopP99, s.loopP99);
  p.loopMean = Math.max(p.loopMean, s.loopMean);
  p.rssMB = Math.max(p.rssMB, s.rssMB);
  p.heapMB = Math.max(p.heapMB, s.heapMB);
  p.clients = Math.max(p.clients, s.clients);
  p.handles = Math.max(p.handles, s.handles);
  p.backpressured = Math.max(p.backpressured, s.backpressured);
  p.errWindow = Math.max(p.errWindow, s.errWindow);
  p.msgPerSec = Math.max(p.msgPerSec, s.msgPerSec);
  if (s.status === "warn" && H.firstWarnAtSec === null) H.firstWarnAtSec = tSec;
  if (s.status === "crit" && H.firstCritAtSec === null) H.firstCritAtSec = tSec;
}

// ── One synthetic client ─────────────────────────────────────────────────────────
class Client {
  id: number;
  name: string;
  seed: Buffer;
  pk: Buffer;
  sk: Buffer;
  pkHex: string;
  ws!: WebSocket;
  txKey: Buffer | null = null;
  rxKey: Buffer | null = null;

  // Handshake state with the bot.
  botPk: string | null = null; // hex pk of the bot
  mySeed: Buffer | null = null;   // our contributed KEM shared secret (ss)
  myCt: Buffer | null = null;     // the KEM ciphertext we sent for mySeed
  peerSeed: Buffer | null = null; // ss decapsulated from the bot's ciphertext
  sharedKey: Buffer | null = null;
  payload: string | null = null; // precomputed AES(msg) base64 — reused every send

  ready = false;
  sent = 0;
  seq = 0;

  constructor(id: number) {
    this.id = id;
    this.name = `stress_${process.pid}_${id}`;
    this.seed = crypto.randomBytes(HQC_CONSTANTS.SEED_BYTES);
    const kp = HqcWrapper.keypairFromSeed(this.seed);
    this.pk = kp.pk;
    this.sk = kp.sk;
    this.pkHex = this.pk.toString("hex");
  }

  connect() {
    // Identify the load traffic (and let a Cloudflare WAF rule allow it).
    this.ws = new WebSocket(WS_URL, { headers: { "User-Agent": USER_AGENT } });
    this.ws.on("open", () => {
      M.connected++;
      this.send({ type: Out.AUTH_INIT, payload: this.pkHex });
    });
    this.ws.on("message", (d) => this.onMessage(d.toString()));
    this.ws.on("error", () => {});
    this.ws.on("close", () => {
      if (!this.ready) M.failed++;
    });
  }

  private send(obj: object) {
    if (this.ws.readyState !== WebSocket.OPEN) return;
    this.ws.send(wrapString(JSON.stringify(obj), this.txKey ?? undefined));
  }

  private onMessage(raw: string) {
    let msg: any;
    try {
      msg = unwrap(raw, this.rxKey ?? undefined);
    } catch {
      return;
    }
    switch (msg.type) {
      case In.AUTH_CHALLENGE: {
        const ss = hqcDecapsulate(this.sk, Buffer.from(msg.payload, "base64"));
        this.send({ type: Out.AUTH_VERIFY, payload: authProof(ss).toString("base64") });
        break;
      }
      case In.SESSION_KEY: {
        const ss = hqcDecapsulate(this.sk, Buffer.from(msg.payload, "base64"));
        const keys = deriveSessionKeys(ss);
        this.txKey = keys.c2s;
        this.rxKey = keys.s2c;
        break;
      }
      case In.AUTH_SUCCESS:
        this.send({ type: Out.SET_USERNAME, payload: this.name });
        break;

      case In.FRIEND_ADDED: {
        // The server auto-friends the bot to us — that's the only friend we
        // care about. Kick off the AES handshake with it.
        const uname = (msg.username || msg.sender) as string;
        if (uname !== BOT) break;
        if (msg.pk) this.botPk = msg.pk;
        if (!this.sharedKey) this.sendAesSeed();
        break;
      }

      case In.AES: {
        if ((msg.sender as string) !== BOT) break;
        if (!this.botPk && msg.pk) this.botPk = msg.pk;
        this.peerSeed = hqcDecapsulate(this.sk, Buffer.from(msg.payload, "base64"));
        if (!this.mySeed) this.sendAesSeed(); // respond if we haven't yet
        this.deriveIfReady();
        break;
      }

      case In.DIRECT_MESSAGE:
        // A reply from the bot. We don't decrypt — just count it as return-path
        // load handled.
        if ((msg.sender as string) !== "SYSTEM") M.replies++;
        break;

      case In.MESSAGE_DELIVERED: {
        M.delivered++;
        const t = inflight.get(msg.messageId);
        if (t !== undefined) {
          M.latencies.push(performance.now() - t);
          inflight.delete(msg.messageId);
        }
        break;
      }
      case In.MESSAGE_QUEUED:
        M.queued++;
        break;

      case In.HEARTBEAT_PING:
        this.send({ type: Out.HEARTBEAT_PONG });
        break;

      case In.ERROR:
        if (msg.payload === "RATE_LIMITED") M.rateLimited++;
        else if (msg.payload === "NOT_FRIENDS") M.notFriends++;
        else M.otherErrors++;
        break;

      case In.PAYMENT_REQUIRED:
        M.otherErrors++;
        break;
    }
  }

  private sendAesSeed() {
    if (!this.botPk) return;
    // Encapsulate once to the bot; keep (ss, ct) and resend the stored ct.
    if (!this.mySeed || !this.myCt) {
      const { ct, ss } = hqcEncapsulate(Buffer.from(this.botPk, "hex"));
      this.mySeed = ss;
      this.myCt = ct;
    }
    this.send({ type: Out.AES, payload: this.myCt.toString("base64"), targetPk: BOT });
  }

  private deriveIfReady() {
    if (this.sharedKey || !this.mySeed || !this.peerSeed || !this.botPk) return;
    this.sharedKey = deriveSharedKey(this.mySeed, this.peerSeed);
    // Precompute the payload we'll reuse for every send: AES(plaintext) base64
    // (no outer HQC — §KM-1 step 5). Fixed content — the server relays it verbatim
    // and the bot decrypts it the same way each time under the epoch-0 static key.
    const plaintext = "s".repeat(Math.max(1, MSG_LEN));
    this.payload = aesEncrypt(plaintext, this.sharedKey);
    this.ready = true;
    M.ready++;
  }

  /** Fire up to `budget` messages at the bot now, honoring socket backpressure. */
  fire(budget: number) {
    if (!this.ready || !this.payload || this.ws.readyState !== WebSocket.OPEN) return;
    for (let i = 0; i < budget; i++) {
      if (this.ws.bufferedAmount > MAX_BUFFERED) {
        M.throttleTicks++;
        return;
      }
      const messageId = `${this.id}:${this.seq++}`;
      const frame = JSON.stringify({
        type: Out.MESSAGE,
        targetPk: BOT,
        payload: this.payload,
        messageId,
      });
      this.ws.send(wrapString(frame, this.txKey ?? undefined));
      this.sent++;
      M.sent++;
      if (this.seq % LATENCY_SAMPLE === 0 && inflight.size < MAX_INFLIGHT) {
        inflight.set(messageId, performance.now());
      }
    }
  }

  close() {
    try {
      this.ws.close();
    } catch {}
  }
}

// ── Orchestration ─────────────────────────────────────────────────────────────
const clients: Client[] = [];

function pct(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const i = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[i] ?? 0;
}

async function main() {
  console.log("── DissQus message stress test → helper bot ─────────────────");
  console.log(`  server     ${WS_URL}`);
  console.log(`  target     @${BOT}`);
  console.log(`  clients    ${N_CLIENTS}   user-agent "${USER_AGENT}"`);
  console.log(`  rate       ${RATE > 0 ? `${RATE} msg/s per client` : "unbounded (backpressure-bound)"}`);
  console.log(`  duration   ${DURATION_S}s   msg len ${MSG_LEN}B`);
  console.log("─────────────────────────────────────────────────────────────");

  for (let i = 0; i < N_CLIENTS; i++) clients.push(new Client(i));
  for (const c of clients) {
    c.connect();
    await sleep(RAMP_MS);
  }

  // Barrier: wait until (nearly) all clients have a secure channel with the bot.
  const readyDeadline = Date.now() + 30_000;
  while (M.ready < N_CLIENTS && Date.now() < readyDeadline) await sleep(200);
  console.log(`▶ handshakes: ${M.ready}/${N_CLIENTS} ready — starting blast for ${DURATION_S}s\n`);

  // ── Timed blast ──────────────────────────────────────────────────────────────
  const t0 = performance.now();
  const endAt = t0 + DURATION_S * 1000;
  let lastReport = t0;
  let lastSent = 0;

  // Poll the server's crash indicators (/metrics) in parallel with the blast so
  // we capture event-loop lag / rss / handles UNDER load and can spot the server
  // going unresponsive (i.e. crashing) mid-test.
  void pollHealthOnce(0); // baseline before load ramps
  const healthTimer = setInterval(() => {
    void pollHealthOnce((performance.now() - t0) / 1000);
  }, POLL_MS);

  await new Promise<void>((resolve) => {
    const timer = setInterval(() => {
      const now = performance.now();
      const elapsed = (now - t0) / 1000;

      for (const c of clients) {
        if (!c.ready) continue;
        let budget: number;
        if (RATE > 0) {
          const due = Math.floor(RATE * elapsed);
          budget = Math.max(0, due - c.sent);
        } else {
          budget = UNBOUNDED_BURST;
        }
        if (budget > 0) c.fire(budget);
      }

      // Live line ~1/s.
      if (now - lastReport >= 1000) {
        const inst = ((M.sent - lastSent) / ((now - lastReport) / 1000)).toFixed(0);
        const last = H.samples[H.samples.length - 1];
        const srv = H.serverDied
          ? "DOWN"
          : last
          ? `${last.status} loop${last.loopP99}ms rss${last.rssMB}MB`
          : "?";
        process.stdout.write(
          `\r  t=${elapsed.toFixed(0).padStart(2)}s  sent=${M.sent}  ` +
            `delivered=${M.delivered}  replies=${M.replies}  ` +
            `${inst} msg/s  err=${M.rateLimited + M.notFriends + M.otherErrors}  srv[${srv}]   `
        );
        lastReport = now;
        lastSent = M.sent;
      }

      if (now >= endAt) {
        clearInterval(timer);
        resolve();
      }
    }, TICK_MS);
  });

  const wallSec = (performance.now() - t0) / 1000;
  process.stdout.write("\n\n⏳ draining receipts (2s)…\n");
  await sleep(2000);
  // One final poll during drain (catches a crash that happened right at the end),
  // then stop polling.
  await pollHealthOnce(wallSec);
  clearInterval(healthTimer);

  // ── Summary ──────────────────────────────────────────────────────────────────
  const lat = M.latencies.slice().sort((a, b) => a - b);
  const avgLat = lat.length ? lat.reduce((a, b) => a + b, 0) / lat.length : 0;
  console.log("\n═══════════════════ RESULTS ═══════════════════");
  console.log(`  clients               ${N_CLIENTS}  (ready ${M.ready}, failed ${M.failed})`);
  console.log(`  wall time             ${wallSec.toFixed(2)}s`);
  console.log(`  messages sent         ${M.sent}`);
  console.log(`  delivered (receipts)  ${M.delivered}`);
  console.log(`  queued (bot offline)  ${M.queued}`);
  console.log(`  bot replies           ${M.replies}`);
  console.log(`  ── throughput ──`);
  console.log(`  aggregate send rate   ${(M.sent / wallSec).toFixed(0)} msg/s`);
  console.log(`  per-client send rate  ${(M.sent / wallSec / Math.max(1, N_CLIENTS)).toFixed(1)} msg/s`);
  console.log(`  delivered rate        ${(M.delivered / wallSec).toFixed(0)} msg/s`);
  console.log(`  bot reply rate        ${(M.replies / wallSec).toFixed(0)} msg/s`);
  console.log(`  ── send→delivered latency (${lat.length} samples) ──`);
  console.log(`  avg / p50 / p95 / p99 / max  ` +
    `${avgLat.toFixed(1)} / ${pct(lat, 50).toFixed(1)} / ${pct(lat, 95).toFixed(1)} / ` +
    `${pct(lat, 99).toFixed(1)} / ${(lat[lat.length - 1] || 0).toFixed(1)} ms`);
  console.log(`  ── errors / health ──`);
  console.log(`  rate-limited          ${M.rateLimited}`);
  console.log(`  not-friends           ${M.notFriends}`);
  console.log(`  other errors          ${M.otherErrors}`);
  console.log(`  backpressure stalls   ${M.throttleTicks} ticks`);
  const undelivered = M.sent - M.delivered - M.queued;
  console.log(`  undelivered (no rcpt) ${undelivered}${undelivered > M.sent * 0.02 ? "  ⚠️  >2% — server may be dropping/lagging" : ""}`);
  console.log("════════════════════════════════════════════════");

  printServerHealth();
  printRefinedRules();

  for (const c of clients) c.close();
  await sleep(300);
  process.exit(0);
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Print the server-side crash indicators captured during the blast. */
function printServerHealth() {
  console.log("\n═══════════ SERVER CRASH INDICATORS (/metrics) ═══════════");
  if (H.polls === 0) {
    console.log("  (no polls attempted)");
    return;
  }
  if (!H.gotAnyOk) {
    console.log(`  ⚠️  /metrics never responded at ${METRICS_URL}`);
    console.log(`      → the server is likely pre-instrumentation, unreachable,`);
    console.log(`        or METRICS_TOKEN is required. Skipping indicator analysis.`);
    return;
  }
  console.log(`  endpoint              ${METRICS_URL}`);
  console.log(`  polls (ok/fail)       ${H.polls - H.fails}/${H.fails}`);
  console.log(`  ── peaks under load ──`);
  console.log(`  event-loop p99        ${H.peak.loopP99.toFixed(0)} ms   (mean peak ${H.peak.loopMean.toFixed(0)} ms)`);
  console.log(`  rss / heap            ${H.peak.rssMB} / ${H.peak.heapMB} MB`);
  console.log(`  ws clients            ${H.peak.clients}`);
  console.log(`  active handles        ${H.peak.handles}`);
  console.log(`  backpressured socks   ${H.peak.backpressured}`);
  console.log(`  errors / window (max) ${H.peak.errWindow}`);
  console.log(`  server msg throughput ${H.peak.msgPerSec} msg/s (peak)`);
  if (H.firstWarnAtSec !== null)
    console.log(`  first WARN status at  t=${H.firstWarnAtSec.toFixed(0)}s`);
  if (H.firstCritAtSec !== null)
    console.log(`  first CRIT status at  t=${H.firstCritAtSec.toFixed(0)}s`);

  if (H.serverDied) {
    console.log("  ──────────────────────────────────────────────");
    console.log(`  ❌ SERVER STOPPED RESPONDING at t≈${H.diedAtSec?.toFixed(0)}s — it crashed/hung under load.`);
    const last = H.samples[H.samples.length - 1];
    if (last)
      console.log(
        `     last healthy sample: status=${last.status} loop=${last.loopP99}ms rss=${last.rssMB}MB clients=${last.clients} handles=${last.handles}`
      );
    console.log(`     Check Sentry for the fatal event (uncaughtException/unhandledRejection).`);
  } else {
    console.log(`  ✅ server stayed responsive for the whole run.`);
  }
  console.log("══════════════════════════════════════════════════════════");
}

/**
 * Turn the observed peaks into concrete, paste-able alert thresholds. The logic:
 *   - Survived → the peaks are "known-safe under this load". Set WARN a bit above
 *     them and CRIT with more headroom, floored to sane minimums so a tiny 1-client
 *     run doesn't produce absurdly low thresholds.
 *   - Crashed  → the last healthy sample is the danger zone; set CRIT just BELOW it
 *     so the early-warning fires before the next crash.
 */
function printRefinedRules() {
  if (!H.gotAnyOk) return;
  console.log("\n════════════ REFINED ALERT RULES (env vars) ════════════");
  if (H.samples.length < 3 || N_CLIENTS < 2) {
    console.log("  ⚠️  Small sample (few polls / few clients). For meaningful");
    console.log("      thresholds, run a representative load, e.g.:");
    console.log("        STRESS_CLIENTS=200 STRESS_RATE=50 STRESS_DURATION=60 npm run stress");
    console.log("      Thresholds below are derived from what little was observed:");
  }

  const rule = (
    name: string,
    peak: number,
    warnFloor: number,
    critFloor: number,
    warnFactor = 1.25,
    critFactor = 1.6
  ) => {
    let warn: number;
    let crit: number;
    if (H.serverDied) {
      // Alert BELOW the danger zone next time.
      warn = Math.max(warnFloor, Math.floor(peak * 0.6));
      crit = Math.max(critFloor, Math.floor(peak * 0.8));
    } else {
      warn = Math.max(warnFloor, Math.ceil(peak * warnFactor));
      crit = Math.max(critFloor, Math.ceil(peak * critFactor));
    }
    return { warn, crit };
  };

  const loop = rule("loop", H.peak.loopP99, 100, 500);
  const rss = rule("rss", H.peak.rssMB, 512, 768); // container mem_limit 1g
  const clients = rule("clients", H.peak.clients, 500, 2000);
  const handles = rule("handles", H.peak.handles, 2000, 6000);
  const errWarn = Math.max(20, Math.ceil(H.peak.errWindow * 1.5) || 20);
  const errCrit = Math.max(100, Math.ceil(H.peak.errWindow * 3) || 100);

  console.log(`  # derived from peaks observed at ~${H.peak.msgPerSec} msg/s, ${H.peak.clients} clients`);
  console.log(`  HEALTH_LOOP_WARN_MS=${loop.warn}`);
  console.log(`  HEALTH_LOOP_CRIT_MS=${loop.crit}`);
  console.log(`  HEALTH_RSS_WARN_MB=${rss.warn}`);
  console.log(`  HEALTH_RSS_CRIT_MB=${rss.crit}`);
  console.log(`  HEALTH_CLIENTS_WARN=${clients.warn}`);
  console.log(`  HEALTH_CLIENTS_CRIT=${clients.crit}`);
  console.log(`  HEALTH_HANDLES_WARN=${handles.warn}`);
  console.log(`  HEALTH_HANDLES_CRIT=${handles.crit}`);
  console.log(`  HEALTH_ERR_WARN=${errWarn}`);
  console.log(`  HEALTH_ERR_CRIT=${errCrit}`);
  if (H.thresholds) {
    console.log(`  # current server thresholds: loop ${H.thresholds.loopWarnMs}/${H.thresholds.loopCritMs}ms,` +
      ` rss ${H.thresholds.rssWarnMB}/${H.thresholds.rssCritMB}MB, clients ${H.thresholds.clientsWarn}/${H.thresholds.clientsCrit}`);
  }
  console.log("  → set these in deploy/server.env (or compose) and restart.");
  console.log("═════════════════════════════════════════════════════════");
}

process.on("SIGINT", () => {
  console.log("\n\ninterrupted — closing clients");
  for (const c of clients) c.close();
  process.exit(1);
});

main().catch((e) => {
  console.error("stress test failed:", e);
  process.exit(1);
});
