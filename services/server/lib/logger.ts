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
   */
  error(...args: unknown[]) {
    if (enabled("error")) console.error(...scrubArgs(args));
    const errArg = args.find((a) => a instanceof Error);
    const msg = fmt(args);
    if (sink) {
      if (errArg) sink.captureError(errArg, msg);
      else sink.captureMessage(msg, "error");
    }
  },
  /** Startup/operational lines we always want visible even at LOG_LEVEL=info. */
  startup(...args: unknown[]) {
    if (currentLevel !== "silent") console.log(...scrubArgs(args));
    sink?.breadcrumb("info", fmt(args));
  },
};

export type Logger = typeof logger;
