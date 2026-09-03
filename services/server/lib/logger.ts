// Leveled logger — replaces the ~100 raw console.* calls scattered through the
// relay + bot so that (a) Docker stdout stops carrying the per-message emoji
// firehose, and (b) errors/warnings still reach Sentry with a trail of recent
// activity.
//
// Docker-noise policy (the ask: "remove logging to docker but ok for Sentry"):
//   - Per-message chatter was moved to logger.debug(), which is OFF by default
//     (LOG_LEVEL defaults to "info" in prod, "debug" in dev). So under normal
//     load Docker's json-file driver stays quiet.
//   - logger.error()/logger.warn() still print (to stderr/stdout) AND forward to
//     Sentry, so real problems are never silently swallowed.
//   - info/warn/error also drop a Sentry *breadcrumb*, so when something does
//     crash, the event carries the last N log lines as context — without those
//     lines ever hitting Docker's logs.
//
// This module must not import Sentry eagerly (observability.ts imports the
// logger during its own init). It looks Sentry up lazily via a registered sink.
//
// Stdout scrubbing (OBS-2): Docker's json-file driver captures whatever we print,
// so — as defence in depth on top of keeping LOG_LEVEL=info in prod — every arg
// is run through the same pure `redact`/`scrubDeep` used at the Sentry boundary
// before it reaches the console. `scrub.ts` is dependency-free (no Sentry), so
// importing it here is safe. Errors are passed through untouched so their stack
// stays intact; the Sentry side redacts exception values separately.

import { redact, scrubDeep } from "./scrub";

function scrubArg(a: unknown): unknown {
  if (typeof a === "string") return redact(a);
  if (a instanceof Error) return a; // keep the stack readable for local debugging
  return scrubDeep(a);
}
function scrubArgs(args: unknown[]): unknown[] {
  return args.map(scrubArg);
}

export type LogLevel = "silent" | "error" | "warn" | "info" | "debug";

const ORDER: Record<LogLevel, number> = {
  silent: 0,
  error: 1,
  warn: 2,
  info: 3,
  debug: 4,
};

function resolveLevel(): LogLevel {
  const raw = (process.env.LOG_LEVEL || "").toLowerCase();
  if (raw in ORDER) return raw as LogLevel;
  // Default: quiet in prod (info — no per-message debug), chatty in dev.
  return process.env.NODE_ENV === "production" ? "info" : "debug";
}

let currentLevel: LogLevel = resolveLevel();
export function setLogLevel(l: LogLevel) {
  currentLevel = l;
}
export function getLogLevel(): LogLevel {
  return currentLevel;
}
function enabled(l: Exclude<LogLevel, "silent">): boolean {
  return ORDER[currentLevel] >= ORDER[l];
}

// --- Sentry sink (registered by observability.ts once Sentry is initialised) ---
export interface SentrySink {
  breadcrumb: (level: "info" | "warning" | "error", message: string) => void;
  captureError: (err: unknown, message?: string) => void;
  captureMessage: (message: string, level: "warning" | "error") => void;
}
let sink: SentrySink | null = null;
export function registerSentrySink(s: SentrySink) {
  sink = s;
}

function fmt(args: unknown[]): string {
  return args
    .map((a) =>
      typeof a === "string"
        ? a
        : a instanceof Error
        ? a.stack || a.message
        : (() => {
            try {
              return JSON.stringify(a);
            } catch {
              return String(a);
            }
          })()
    )
    .join(" ");
}

// --- Sentry flood control (quota protection) --------------------------------
//
// Every logger.error() used to become one Sentry EVENT, unconditionally. That
// is what exhausted a month's quota in production: the bot's `openSession`
// catch-all fired once per peer per FRIEND_POLL_MS (15s) for any user who had
// not yet published prekeys — 240 events an hour, per user, for a condition
// that is expected and self-resolving.
//
// The call sites are being fixed, but a call site is the wrong place for the
// only defence: the next one is written by someone who has not read this
// comment, on a path that only floods in production, under a condition nobody
// reproduced locally. So the throttle lives HERE, where every current and
// future error passes.
//
// Shape: first occurrence of a fingerprint goes straight through, then at most
// one per THROTTLE_MS, and that one carries how many were suppressed. So a
// genuine new failure is never delayed, a persistent one stays visible at a
// readable cadence, and neither can spend the quota.
//
// NOTHING is throttled on the console — stderr is not metered and an operator
// tailing logs should see every occurrence. This only gates the Sentry sink.
// Resolved per call rather than at module load. Read once into a const, the
// knob could not actually be turned: an operator raising it on a flooding host
// would have had to restart the process to apply it, which is the worst moment
// to need a restart. It is one env lookup on an already-expensive path.
function throttleMs(): number {
  const raw = Number(process.env.SENTRY_THROTTLE_MS);
  return Number.isFinite(raw) && raw >= 0 ? raw : 10 * 60 * 1000;
}
// Bounded so a process with unbounded distinct fingerprints cannot grow this
// map forever; oldest-first eviction is fine because an evicted key simply gets
// one more event through.
const THROTTLE_MAX_KEYS = 500;

interface Seen { until: number; suppressed: number }
const seen = new Map<string, Seen>();

// Injectable so the throttle's own tests are deterministic. They used to drive
// it with a 1 ms window and a busy-wait, which passed locally and failed on a
// loaded CI runner: 1 ms elapsed between two synchronous calls, the window
// lapsed, and a "suppressed" event was sent. A test for time-based behaviour
// should not itself depend on how fast the machine is.
let clock: () => number = Date.now;
/** Test seam. Pass nothing to restore the real clock. */
export function setLoggerClock(fn?: () => number): void {
  clock = fn ?? Date.now;
}

/**
 * Collapse the volatile parts of a message so that the same FAILURE, about
 * different peers or at different offsets, shares one budget.
 *
 * Without this, "could not open a session with @alice…" and "…with @bob…" are
 * distinct fingerprints and 200 users still produce 200 events per cycle. The
 * per-peer detail is not lost — it is on the event that does get through, and
 * on every console line.
 */
export function fingerprint(message: string): string {
  // Truncate FIRST. Every pattern below then runs over at most 200 characters,
  // which bounds the work regardless of how long a log line gets.
  //
  // The handle pattern used to be `[^\s]*@[^\s]*`, which is quadratic: on a
  // long run of non-space characters with no `@`, the engine consumes to the
  // end and backtracks from every start position. A ReDoS on the ERROR path is
  // a bad place to have one — that path is reached exactly when something is
  // already going wrong, and often in a loop. Anchoring on the literal `@`
  // makes it linear, and `@` is where the volatile part starts anyway.
  return message
    .slice(0, 200)
    .replace(/\b[0-9a-f]{6,}\b/gi, "#")   // ids, hashes, key fragments
    .replace(/\b\d+\b/g, "#")             // counts, ports, status codes
    .replace(/@\S*/g, "@")                 // handles and addresses
    .replace(/\s+/g, " ")
    .trim();
}

/** Whether this message may spend a Sentry event now, and what to append. */
function admit(message: string): { send: boolean; note: string } {
  const now = clock();
  const key = fingerprint(message);
  const prev = seen.get(key);

  if (prev && now < prev.until) {
    prev.suppressed++;
    return { send: false, note: "" };
  }

  if (seen.size >= THROTTLE_MAX_KEYS && !prev) {
    const oldest = seen.keys().next();
    if (!oldest.done) seen.delete(oldest.value);
  }
  const window = throttleMs();
  seen.set(key, { until: now + window, suppressed: 0 });

  const n = prev?.suppressed ?? 0;
  return {
    send: true,
    note: n > 0 ? ` [+${n} identical suppressed in the last ${Math.round(window / 60000)}m]` : "",
  };
}

/** Test seam: forget every throttle window. */
export function resetSentryThrottle(): void {
  seen.clear();
}

export const logger = {
  /** High-volume per-message tracing. Off by default (LOG_LEVEL=debug to see). */
  debug(...args: unknown[]) {
    if (enabled("debug")) console.log(...scrubArgs(args));
    // Deliberately NOT breadcrumbed — this is the firehose we're keeping out of
    // both Docker and Sentry under normal load.
  },
  info(...args: unknown[]) {
    if (enabled("info")) console.log(...scrubArgs(args));
    sink?.breadcrumb("info", fmt(args));
  },
  warn(...args: unknown[]) {
    if (enabled("warn")) console.warn(...scrubArgs(args));
    const msg = fmt(args);
    sink?.breadcrumb("warning", msg);
  },
  /**
   * Real errors: always surfaced to stderr (unless LOG_LEVEL=silent) AND sent to
   * Sentry as an exception event. Pass an Error first for a proper stack.
   *
   * The Sentry half is throttled per fingerprint — see the note above. The
   * console half never is.
   *
   * If what you are reporting is EXPECTED and self-resolving (a peer with no
   * prekeys yet, a reconnect that will succeed), it is not an error: use warn
   * for the first occurrence, or debug. The throttle bounds the damage; it does
   * not make a non-error into one.
   */
  error(...args: unknown[]) {
    if (enabled("error")) console.error(...scrubArgs(args));
    const errArg = args.find((a) => a instanceof Error);
    const msg = fmt(args);
    if (!sink) return;
    const { send, note } = admit(msg);
    if (!send) return;
    if (errArg) sink.captureError(errArg, msg + note);
    else sink.captureMessage(msg + note, "error");
  },
  /** Startup/operational lines we always want visible even at LOG_LEVEL=info. */
  startup(...args: unknown[]) {
    if (currentLevel !== "silent") console.log(...scrubArgs(args));
    sink?.breadcrumb("info", fmt(args));
  },
};

export type Logger = typeof logger;
