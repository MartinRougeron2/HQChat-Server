// Auth server entrypoint (Phase 1 — see deploy/EXTRACTION_PLAN.md).
//
// Owns the HQC-KEM handshake that proves a client owns its public key, the
// admission gate, and token issuance. It replaces the WS AUTH_INIT/AUTH_CHALLENGE
// /AUTH_VERIFY flow from server.ts with stateless REST:
//
//   POST /auth/init   { pk }                  -> { ct }           (KEM challenge)
//   POST /auth/verify { pk, solution }        -> { sessionToken, mqttToken, ... }
//   POST /auth/refresh (Bearer sessionToken)  -> { mqttToken, ttl } (rotation)
//   POST /mqtt/authn  (EMQX hook)             -> { result }        (one-time token)
//
// Transport confidentiality is TLS (WSS via nginx) — there is NO per-connection
// AES session key here anymore (the SESSION_KEY step is deleted; TLS replaces it).
// Runs the SAME image as the monolith via `command:` in the compose overlay.

// Must be first: loads .env + resolves *_FILE secrets before anything reads env.
import "../lib/config";
import { initObservability } from "../lib/observability";
initObservability("auth");
import { healthMonitor } from "../lib/health-monitor";
import { logger } from "../lib/logger";
import * as http from "http";
import { readJson, send, bearer, requireString, requireHex, HttpError } from "../lib/http";
import * as crypto from "crypto";
// hqc is lazy-required inside /auth/init (it dlopen's the native x86 .so; keeping
// it out of the import graph lets the auth server boot — and serve the token/
// refresh/authn paths — anywhere the lib is absent, matching secure-transport.ts).
import { authProof } from "../lib/auth-proof";
import { checkAdmission } from "../lib/admission";
import { DB } from "../services/db/api";

const PORT = Number(process.env.PORT || 8080);

// Internal service credential (push-bridge etc.): a privileged MQTT identity that
// authn grants superuser so it can subscribe across conversations. The secret is
// a compose secret resolved via INTERNAL_MQTT_SECRET_FILE.
const INTERNAL_MQTT_USER = process.env.INTERNAL_MQTT_USER || "svc-internal";
const INTERNAL_MQTT_SECRET = process.env.INTERNAL_MQTT_SECRET || "";

const BOT_USERNAME = process.env.BOT_USERNAME || "helper";

/**
 * Friend the helper bot to a user, so a brand-new account opens on a
 * conversation instead of an empty screen (the bot's welcome message rides that
 * friendship). The `/ws` monolith did this on every login and was the ONLY
 * place it happened, so retiring it at Phase 4 would have silently removed the
 * first thing a new user ever sees. It lives here now, on the one path every
 * client — apps and bot alike — goes through.
 *
 * Idempotent and best-effort: on a cold stack the bot may not have claimed its
 * handle yet, and a login must never fail because of that. The next login
 * retries.
 */
async function ensureBotFriendship(pk: string): Promise<void> {
  try {
    const botPk = await DB.getPkByUsername(BOT_USERNAME);
    if (!botPk || botPk === pk) return; // bot not registered yet, or this IS the bot
    if (!(await DB.areFriends(pk, botPk))) await DB.createFriendship(pk, botPk);
    // The friend sets alone are invisible to MQTT — the ACL entry is what lets
    // either side use the shared topic, and it records the members push-bridge
    // resolves. Idempotent, so re-running it per login is harmless.
    await DB.grantFriendTopic(pk, botPk);
  } catch (e) {
    logger.warn(`[auth] helper-bot auto-friend failed for ${pk.slice(0, 12)}…: ${(e as Error).message}`);
  }
}

/** Constant-time equality for two utf8/hex strings of possibly differing length. */
function safeEqualStr(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

const server = http.createServer(async (req, res) => {
  const url = req.url || "";
  const method = req.method || "GET";
  try {
    if (method === "GET" && url === "/health") {
      return send(res, 200, { ok: true, service: "auth" });
    }

    // --- 1. HQC-KEM challenge -------------------------------------------------
    // Encapsulate to the client's public key → (ct, ss). Only the holder of the
    // matching secret key can decapsulate the same ss; it proves possession by
    // returning HKDF(ss,"auth"). We store the expected proof under chal:{pk} and
    // never send ss nor echo any decrypted plaintext (no decryption oracle).
    if (method === "POST" && url === "/auth/init") {
      const { HqcWrapper, HQC_CONSTANTS } = require("../lib/hqc") as typeof import("../lib/hqc");
      const { pk } = await readJson(req);
      const pkHex = String(pk || "");
      if (!/^[0-9a-fA-F]+$/.test(pkHex) || pkHex.length !== HQC_CONSTANTS.PUBLIC_KEY_BYTES * 2) {
        return send(res, 400, { error: "bad public key" });
      }
      const { ct, ss } = HqcWrapper.encapsulate(Buffer.from(pkHex, "hex"));
      await DB.startAuthChallenge(pkHex, authProof(ss).toString("hex"));
      return send(res, 200, { ct: ct.toString("base64") });
    }

    // --- 2. Verify the proof, admit, issue tokens ----------------------------
    if (method === "POST" && url === "/auth/verify") {
      const { pk, solution } = await readJson(req);
      const pkHex = String(pk || "");
      const solutionHex = Buffer.from(String(solution || ""), "base64").toString("hex");

      // Atomically consume the open challenge (single-use — no replay).
      const expectedHex = await DB.takeAuthChallenge(pkHex);
      if (!expectedHex || !safeEqualStr(solutionHex, expectedHex)) {
        return send(res, 401, { error: "auth failed" });
      }

      // Admission gate — only AFTER the client proved it owns this key, so
      // key-spraying can't trigger Stripe customer creation.
      const admission = await checkAdmission(pkHex);
      if (!admission.ok) {
        if (admission.reason === "payment") {
          return send(res, 402, { error: "payment required", checkoutUrl: admission.checkoutUrl });
        }
        return send(res, 403, { error: "not admitted" });
      }

      // Ensure the caller owns its self topics (presence publish + inbox), then
      // issue a REST session bearer + an MQTT connect token (~5m, expiry-rotated).
      await DB.grantSelfTopics(pkHex);
      // Every account gets the helper bot as its first friend (see above).
      await ensureBotFriendship(pkHex);
      const username = await DB.getUsername(pkHex);
      const sessionToken = await DB.mintSessionToken(pkHex);
      const mqttToken = await DB.mintMqttToken(pkHex);
      return send(res, 200, {
        pk: pkHex,
        username: username || null,
        sessionToken,
        mqttToken,
        mqttTtl: DB.MQTT_TOKEN_TTL_SECONDS,
        // Absolute expiry (unix seconds) so the client can refresh proactively,
        // before EMQX force-disconnects at expire_at.
        mqttExpiresAt: Math.floor(Date.now() / 1000) + DB.MQTT_TOKEN_TTL_SECONDS,
      });
    }

    // --- 3. Rotate the MQTT token (proactive refresh / after expiry) ---------
    // Authenticated by the REST session bearer, so a client refreshes without
    // redoing the KEM handshake. Grants a fresh ~5m token + new expiry.
    if (method === "POST" && url === "/auth/refresh") {
      const pk = await DB.resolveSessionToken(bearer(req));
      if (!pk) return send(res, 401, { error: "unauthenticated" });
      const mqttToken = await DB.mintMqttToken(pk);
      return send(res, 200, {
        mqttToken,
        mqttTtl: DB.MQTT_TOKEN_TTL_SECONDS,
        mqttExpiresAt: Math.floor(Date.now() / 1000) + DB.MQTT_TOKEN_TTL_SECONDS,
      });
    }

    // --- 4. EMQX HTTP authentication hook ------------------------------------
    // EMQX posts { username, password, clientid, nonce? } on every CONNECT.
    // Internal services present the privileged credential → superuser. Everyone
    // else: username=pk, password=token; we verify it and hand EMQX the token's
    // `expire_at` so EMQX DISCONNECTS the client at expiry → the client refreshes
    // and reconnects (expiration-based rotation, ~5m). Optional per-CONNECT nonce
    // blocks exact-packet replay.
    // EMQX expects HTTP 200 with { result: "allow"|"deny", is_superuser?, expire_at? }.
    if (method === "POST" && url === "/mqtt/authn") {
      const body = await readJson(req);
      const username = String(body.username || "");
      const password = String(body.password || "");
      const nonce = body.nonce ? String(body.nonce) : "";

      // Privileged internal identity (push-bridge, ops tools). No expiry.
      if (
        INTERNAL_MQTT_SECRET &&
        username === INTERNAL_MQTT_USER &&
        safeEqualStr(password, INTERNAL_MQTT_SECRET)
      ) {
        return send(res, 200, { result: "allow", is_superuser: true });
      }

      const pk = username;
      if (!pk || !password) return send(res, 200, { result: "deny" });

      // Replay guard: a captured CONNECT can't be resent with the same nonce.
      if (nonce && !(await DB.useNonce(nonce))) {
        logger.warn(`[auth] CONNECT nonce replay for pk=${pk.slice(0, 12)}…`);
        return send(res, 200, { result: "deny" });
      }

      const { ok, expireAt } = await DB.verifyMqttToken(pk, password);
      if (!ok) return send(res, 200, { result: "deny" });
      // expire_at (unix seconds) → EMQX force-disconnects at this time.
      return send(res, 200, { result: "allow", expire_at: expireAt });
    }

    return send(res, 404, { error: "not found" });
  } catch (e) {
    if (e instanceof HttpError) {
      return send(res, e.status, { error: e.code, message: e.message });
    }
    logger.error(`[auth] ${method} ${url} — ${(e as Error).message}`, e as Error);
    return send(res, 500, { error: "INTERNAL" });
  }
});

server.listen(PORT, () => {
  logger.startup(`🔐 auth server on :${PORT} — handshake /auth/*, EMQX hook /mqtt/authn`);
});

// Event-loop / memory / Redis-latency early warning → Sentry. This process gates
// every CONNECT (EMQX calls /mqtt/authn synchronously), so a stall here stalls
// the whole broker — worth watching in its own right.
healthMonitor.start();
