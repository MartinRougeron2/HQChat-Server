// Broker/infra watchdog (see deploy/EXTRACTION_PLAN.md, deploy/emqx/acl-notes.md).
//
// WHY THIS EXISTS. Every Node service reports itself to Sentry (lib/observability
// .ts) — but two things in the stack are NOT Node and reported NOTHING:
//
//   1. EMQX's own connections. The broker keeps its own Redis link (the topic-ACL
//      authorizer) and its own HTTP link to the auth server. Either can be flat on
//      its back while every app service's Redis client is perfectly healthy, so
//      nothing in Sentry moves and the dashboard is the only place the failure is
//      visible — and only if someone opens it. A dead authorizer means the ACL
//      never matches, which is either "everything is denied" or (if the config
//      ever falls back to stock EMQX) "everything is allowed". Both are incidents.
//   2. Redis itself. Services log their own client errors, but a Redis that is up
//      yet not answering (blocked on AOF rewrite, evicting, wrong password after a
//      secret regeneration) shows up as scattered noise rather than one alert.
//
// So: poll, hold the last state, and escalate TRANSITIONS to Sentry via
// logger.error (which the Sentry sink turns into an event). Steady-state healthy
// is silent; a stuck failure re-alerts every BROKER_WATCH_REALERT_MS so it can't
// be forgotten.

// Must be first: loads .env + resolves *_FILE secrets before anything reads env.
import "../lib/config";
import { initObservability } from "../lib/observability";
initObservability("broker-watch");
import { logger } from "../lib/logger";
import { healthMonitor } from "../lib/health-monitor";
import * as http from "http";
import Redis from "ioredis";

const PORT = Number(process.env.PORT || 8080);
const INTERVAL_MS = Number(process.env.BROKER_WATCH_INTERVAL_MS || 30_000);
const REALERT_MS = Number(process.env.BROKER_WATCH_REALERT_MS || 30 * 60_000);
const API = `${process.env.EMQX_API_URL || "http://emqx:18083"}/api/v5`;
const DASH_USER = process.env.EMQX_DASHBOARD_USER || "admin";
// Resolved from EMQX_DASHBOARD_PASSWORD_FILE (the runtime-secrets tmpfs) by config.ts.
const DASH_PASS = process.env.EMQX_DASHBOARD_PASSWORD || "";

interface Check {
  name: string;
  ok: boolean;
  detail: string;
}

// --- EMQX dashboard API ------------------------------------------------------
// The dashboard admin credential is the API credential; the emqx entrypoint
// re-syncs it to the generated secret on every boot, so it never drifts.
let token: string | null = null;

async function login(): Promise<string> {
  const res = await fetch(`${API}/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: DASH_USER, password: DASH_PASS }),
    signal: AbortSignal.timeout(5000),
  });
  if (!res.ok) throw new Error(`login ${res.status}`);
  const body = (await res.json()) as { token?: string };
  if (!body.token) throw new Error("login returned no token");
  return body.token;
}

/** GET an API path, logging in (once) on 401 so an expired token self-heals. */
async function api<T>(path: string, retry = true): Promise<T> {
  if (!token) token = await login();
  const res = await fetch(`${API}/${path}`, {
    headers: { authorization: `Bearer ${token}` },
    signal: AbortSignal.timeout(5000),
  });
  if (res.status === 401 && retry) {
    token = null;
    return api<T>(path, false);
  }
  if (!res.ok) throw new Error(`GET ${path} → ${res.status}`);
  return (await res.json()) as T;
}

/**
 * Healthy = enabled, and (for the sources that hold a CONNECTION) connected.
 * EMQX only reports `status` for connector-backed sources; the built-in file
 * authorizer and the built-in authn mechanisms have none, and a missing status
 * must not read as an outage.
 */
function linkOk(x: { enable?: boolean; status?: string }): boolean {
  if (x.enable === false) return false;
  return x.status === undefined || x.status === "connected";
}

/** EMQX reports per-node errors on a source; flatten them into one line. */
function nodeErrors(x: { node_error?: unknown[] }): string {
  const errs = x.node_error || [];
  if (!errs.length) return "";
  return ` — ${errs.map((e) => (typeof e === "string" ? e : JSON.stringify(e))).join("; ").slice(0, 300)}`;
}

async function checkEmqx(): Promise<Check[]> {
  const out: Check[] = [];

  type Node = { node: string; node_status: string; connections: number };
  const nodes = await api<Node[]>("nodes");
  for (const n of nodes) {
    out.push({
      name: `emqx.node.${n.node}`,
      ok: n.node_status === "running",
      detail: `${n.node_status}, ${n.connections} connections`,
    });
  }

  // Authentication chain — if this breaks, NOBODY can connect.
  type Authn = { mechanism?: string; backend?: string; enable?: boolean; status?: string; node_error?: unknown[] };
  const authn = await api<Authn[]>("authentication");
  if (!authn.length) {
    // No authenticator at all = EMQX admits every CONNECT. Never intended here.
    out.push({ name: "emqx.authn", ok: false, detail: "no authenticator configured — the broker is admitting everyone" });
  }
  for (const a of authn) {
    const id = [a.mechanism, a.backend].filter(Boolean).join(":") || "authn";
    out.push({
      name: `emqx.authn.${id}`,
      ok: linkOk(a),
      detail: `status=${a.status ?? "n/a"} enable=${a.enable}${nodeErrors(a)}`,
    });
  }

  // Authorization sources — the per-conversation topic ACL (Redis).
  type Authz = { type?: string; enable?: boolean; status?: string; node_error?: unknown[] };
  const authz = await api<Authz[]>("authorization/sources");
  if (!authz.length) {
    out.push({ name: "emqx.authz", ok: false, detail: "no authorization source configured — the topic ACL is not enforced" });
  }
  for (const s of authz) {
    out.push({
      name: `emqx.authz.${s.type || "source"}`,
      ok: linkOk(s),
      detail: `status=${s.status ?? "n/a"} enable=${s.enable}${nodeErrors(s)}`,
    });
  }

  return out;
}

// --- Redis -------------------------------------------------------------------
// Own client (lazyConnect, no command queue backing up on a dead server) so a
// watchdog failure is never confused with app traffic.
const redis = new Redis(process.env.REDIS_URL || "redis://127.0.0.1:6379", {
  lazyConnect: true,
  maxRetriesPerRequest: 1,
  enableOfflineQueue: false,
});
redis.on("error", () => {
  /* surfaced by the PING check below; no per-reconnect log spam */
});

async function checkRedis(): Promise<Check> {
  const t0 = Date.now();
  try {
    const pong = await redis.ping();
    return { name: "redis.ping", ok: pong === "PONG", detail: `${pong} in ${Date.now() - t0}ms` };
  } catch (e) {
    return { name: "redis.ping", ok: false, detail: (e as Error).message };
  }
}

// --- Alerting ----------------------------------------------------------------
// Only transitions (and stuck failures) reach Sentry; steady state is silent.
const state = new Map<string, { ok: boolean; since: number; lastAlertAt: number }>();

function escalate(c: Check): void {
  const now = Date.now();
  const prev = state.get(c.name);

  if (!c.ok) {
    const firstFailure = !prev || prev.ok;
    const stale = prev && !prev.ok && now - prev.lastAlertAt >= REALERT_MS;
    if (firstFailure || stale) {
      const forMs = prev && !prev.ok ? now - prev.since : 0;
      const forStr = forMs ? ` (unhealthy for ${Math.round(forMs / 60_000)}m)` : "";
      // logger.error → Sentry event (lib/logger.ts sink).
      logger.error(`🚨 [broker-watch] ${c.name} unhealthy${forStr}: ${c.detail}`);
      state.set(c.name, { ok: false, since: prev && !prev.ok ? prev.since : now, lastAlertAt: now });
      return;
    }
    state.set(c.name, { ok: false, since: prev?.since ?? now, lastAlertAt: prev?.lastAlertAt ?? now });
    return;
  }

  if (prev && !prev.ok) {
    logger.startup(`✅ [broker-watch] ${c.name} recovered after ${Math.round((now - prev.since) / 60_000)}m: ${c.detail}`);
  }
  state.set(c.name, { ok: true, since: prev?.ok ? prev.since : now, lastAlertAt: 0 });
}

let lastRun: { ts: number; checks: Check[] } = { ts: 0, checks: [] };

async function tick(): Promise<void> {
  const checks: Check[] = [await checkRedis()];
  try {
    checks.push(...(await checkEmqx()));
  } catch (e) {
    // The API itself is unreachable/unauthorised — that IS the alert.
    token = null;
    checks.push({ name: "emqx.api", ok: false, detail: (e as Error).message });
  }
  for (const c of checks) escalate(c);
  lastRun = { ts: Date.now(), checks };
}

// --- Health endpoint (compose healthcheck + a human-readable status) ----------
http
  .createServer((req, res) => {
    if (req.method === "GET" && (req.url === "/health" || req.url === "/status")) {
      const unhealthy = lastRun.checks.filter((c) => !c.ok);
      res.writeHead(200, { "content-type": "application/json" });
      // 200 even when a dependency is down: this process is fine, and flapping
      // its own container on a broker blip would take the watchdog off the air.
      return res.end(
        JSON.stringify({
          ok: true,
          service: "broker-watch",
          lastRunAgoMs: lastRun.ts ? Date.now() - lastRun.ts : null,
          unhealthy: unhealthy.map((c) => `${c.name}: ${c.detail}`),
          checks: lastRun.checks,
        })
      );
    }
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
  })
  .listen(PORT, () => logger.startup(`🛎️  broker-watch health on :${PORT} — polling every ${INTERVAL_MS}ms`));

if (!DASH_PASS) {
  logger.error("[broker-watch] EMQX_DASHBOARD_PASSWORD unset — cannot query the broker API");
}

// Event-loop/memory early warning for this process too.
healthMonitor.start();

void tick();
setInterval(() => void tick(), INTERVAL_MS).unref?.();
