// The small HTTP layer every service shares.
//
// `auth/main.ts` and `api/main.ts` each carried their own copy of readJson /
// send / bearer — same code, drifting body caps (64 KB vs 256 KB) and no shared
// error shape. Two services is where copy-paste stops being cheaper than a
// module, and a third (ops) is already here.
//
// It also carries the request id, which is the thing that makes a report like
// "it failed for me at 14:32" actionable: one id ties the client's error to a
// server log line to a Sentry event.

import * as http from "http";
import * as crypto from "crypto";
import { logger } from "./logger";

/** Max request body. Anything larger is refused before it is buffered. */
export const MAX_BODY_BYTES = 256 * 1024;

export class HttpError extends Error {
  constructor(readonly status: number, readonly code: string, message?: string) {
    super(message || code);
  }
}

/** Parse a JSON body, refusing anything oversized or malformed. */
export function readJson(req: http.IncomingMessage): Promise<any> {
  return new Promise((resolve, reject) => {
    let data = "";
    let tooBig = false;
    req.on("data", (c) => {
      data += c;
      if (data.length > MAX_BODY_BYTES) {
        tooBig = true;
        req.destroy();
      }
    });
    req.on("end", () => {
      if (tooBig) return reject(new HttpError(413, "BODY_TOO_LARGE"));
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch {
        reject(new HttpError(400, "INVALID_JSON"));
      }
    });
    req.on("error", reject);
  });
}

/** JSON response. Echoes the request id so a client can quote it in a report. */
export function send(res: http.ServerResponse, status: number, body: unknown, requestId?: string): void {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (requestId) headers["x-request-id"] = requestId;
  res.writeHead(status, headers);
  res.end(JSON.stringify(body));
}

export function bearer(req: http.IncomingMessage): string {
  return (req.headers.authorization || "").replace(/^Bearer\s+/i, "").trim();
}

/**
 * The caller's request id, or a fresh one. Trusted only for correlation — it is
 * client-supplied, never an identity, and never used in a security decision.
 */
export function requestId(req: http.IncomingMessage): string {
  const given = String(req.headers["x-request-id"] || "").trim();
  if (/^[A-Za-z0-9_.:-]{1,64}$/.test(given)) return given;
  return crypto.randomUUID();
}

// --- Body validation -------------------------------------------------------
// Routes used to do `String(body.username)`, which turns `undefined` into the
// string "undefined" and an object into "[object Object]" — both of which then
// travel into Redis as if they were real values.

/** A required string field, trimmed and length-bounded. Throws HttpError(400). */
export function requireString(body: any, field: string, opts: { min?: number; max?: number } = {}): string {
  const { min = 1, max = 512 } = opts;
  const raw = body?.[field];
  if (typeof raw !== "string") throw new HttpError(400, "INVALID_FIELD", `${field} must be a string`);
  const value = raw.trim();
  if (value.length < min || value.length > max) {
    throw new HttpError(400, "INVALID_FIELD", `${field} must be ${min}–${max} characters`);
  }
  return value;
}

/** A required lowercase-hex field of an exact byte length (public keys, hashes). */
export function requireHex(body: any, field: string, bytes: number): string {
  const value = requireString(body, field, { min: bytes * 2, max: bytes * 2 });
  if (!/^[0-9a-fA-F]+$/.test(value)) throw new HttpError(400, "INVALID_FIELD", `${field} must be hex`);
  return value;
}

/**
 * Wrap a request handler: assigns a request id, times the call, logs one line
 * per request at debug, and turns a thrown HttpError into its status + code.
 * Anything else is a 500 with no detail — the detail goes to the log and Sentry.
 */
export function handler(
  service: string,
  fn: (req: http.IncomingMessage, res: http.ServerResponse, ctx: { id: string }) => Promise<void>
): http.RequestListener {
  return async (req, res) => {
    const id = requestId(req);
    const started = Date.now();
    try {
      await fn(req, res, { id });
    } catch (e) {
      const err = e as Error;
      if (err instanceof HttpError) {
        send(res, err.status, { error: err.code, message: err.message }, id);
      } else {
        logger.error(`[${service}] ${req.method} ${req.url} [${id}] — ${err.message}`, err);
        send(res, 500, { error: "INTERNAL" }, id);
      }
    } finally {
      logger.debug(`[${service}] ${req.method} ${req.url} → ${res.statusCode} ${Date.now() - started}ms [${id}]`);
    }
  };
}
