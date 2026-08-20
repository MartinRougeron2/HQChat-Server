// App-API entrypoint (Phase 1 — see deploy/EXTRACTION_PLAN.md).
//
// "The monolith minus auth and messages": the HTTP/REST control plane for
// directory, the friend graph, payments, push-token registration, and account
// deletion. It NEVER sees message content. Friend-graph mutations here maintain
// the MQTT topic ACL (DB.grantFriendTopic / DB.revokeFriendTopic) that EMQX
// enforces as RLS.
//
// Auth: every mutating route requires a REST session bearer (Authorization:
// Bearer <sessionToken>) minted by the auth server after the HQC handshake and
// resolved here via DB.resolveSessionToken. Runs the SAME image as the monolith.

// Must be first: loads .env + resolves *_FILE secrets before anything reads env.
import "../lib/config";
import { initObservability } from "../lib/observability";
initObservability("api");
import { healthMonitor } from "../lib/health-monitor";
import { logger } from "../lib/logger";
import * as http from "http";
import { readJson, send, bearer, requireString, HttpError } from "../lib/http";
import { DB } from "../services/db/api";
import { StripeService } from "../services/stripe/api";
import { handleSubscribe } from "../services/web/subscribe";
import { ADMISSION_POLICY } from "../lib/admission";

const PORT = Number(process.env.PORT || 8080);

/** Resolve the caller's pk from its REST session bearer, or null if invalid. */
async function authPk(req: http.IncomingMessage): Promise<string | null> {
  return DB.resolveSessionToken(bearer(req));
}

const server = http.createServer(async (req, res) => {
  const url = req.url || "";
  const method = req.method || "GET";
  try {
    if (method === "GET" && url === "/health") {
      return send(res, 200, { ok: true, service: "api" });
    }

    // --- /info + /metrics -----------------------------------------------------
    // Both lived on the retired monolith and, for a while, nowhere at all: the
    // apps' server-info screen and any uptime monitor pointed at a 404. app-api
    // is the natural host — it is the only public HTTP service left.
    if (method === "GET" && url === "/info") {
      return send(res, 200, {
        name: process.env.SERVER_NAME || "hqchat",
        version: process.env.SERVER_VERSION || "dev",
        admission: ADMISSION_POLICY,
        // What a client needs to decide whether it can talk to this deployment
        // at all, without a round trip per capability.
        transport: "mqtt",
        endpoints: { auth: "/auth", mqtt: "/mqtt", api: "/" },
      });
    }
    if (method === "GET" && url === "/metrics") {
      // Fail closed in production: no token configured means no metrics, not
      // open metrics (SRV-2). Localhost-only at the nginx layer as well.
      const token = process.env.METRICS_TOKEN || "";
      if (!token || bearer(req) !== token) return send(res, 404, { error: "not found" });
      return send(res, 200, {
        service: "api",
        uptimeSec: Math.round(process.uptime()),
        health: healthMonitor.getSnapshot(),
      });
    }

    // --- Payments (Stripe) — raw body needed for signature verification ------
    if (ADMISSION_POLICY === "stripe" && method === "POST" && url === "/stripe/webhook") {
      const chunks: Buffer[] = [];
      req.on("data", (c) => chunks.push(c as Buffer));
      req.on("end", async () => {
        try {
          const event = StripeService.constructEvent(
            Buffer.concat(chunks),
            req.headers["stripe-signature"] as string
          );
          if (event.type.startsWith("customer.subscription.")) {
            const sub = event.data.object as any;
            const active = sub.status === "active" || sub.status === "trialing";
            await StripeService.handleSubscriptionChange(sub.customer, active);
          }
          res.writeHead(200); res.end("ok");
        } catch (e: any) {
          logger.error(`❌ [stripe-webhook] ${e.message}`);
          res.writeHead(400); res.end(`Webhook Error: ${e.message}`);
        }
      });
      return;
    }
    if (ADMISSION_POLICY === "stripe" && url.startsWith("/subscribe")) {
      handleSubscribe(req, res).catch((e) => {
        logger.error("[subscribe] handler error", e);
        if (!res.headersSent) { res.writeHead(500); res.end("error"); }
      });
      return;
    }

    // --- Directory --------------------------------------------------------
    if (method === "GET" && url.startsWith("/users")) {
      // Exact-username lookup only (?username=…) — no bulk enumeration (M3).
      const q = new URL(url, "http://x").searchParams.get("username") || "";
      const pk = q ? await DB.getPkByUsername(q) : null;
      return send(res, 200, { username: q, pk });
    }
    if (method === "POST" && url === "/username") {
      const pk = await authPk(req);
      if (!pk) return send(res, 401, { error: "unauthenticated" });
      const body = await readJson(req);
      const username = requireString(body, "username", { min: 3, max: 32 });
      // The client distinguishes "someone else owns that handle" from a
      // transient failure and shows a banner with a way out (AppState
      // .isUsernameTaken), so this code has to survive the round trip as a code
      // — not collapse into a generic 500 with the rest.
      try {
        await DB.setUsername(pk, username);
      } catch (e) {
        const msg = (e as Error).message;
        if (msg === "USERNAME_TAKEN") throw new HttpError(409, "USERNAME_TAKEN", "That username is taken");
        throw new HttpError(400, "INVALID_USERNAME", msg);
      }
      return send(res, 200, { ok: true, username });
    }

    // --- Friend graph (also maintains the MQTT ACL) -----------------------
    if (method === "GET" && url === "/friends") {
      const pk = await authPk(req);
      if (!pk) return send(res, 401, { error: "unauthenticated" });
      return send(res, 200, { friends: await DB.getFriendsList(pk) });
    }
    if (method === "GET" && url === "/friends/invites") {
      const pk = await authPk(req);
      if (!pk) return send(res, 401, { error: "unauthenticated" });
      return send(res, 200, { invites: await DB.getMyInvites(pk) });
    }
    if (method === "POST" && url === "/friends/invite") {
      const pk = await authPk(req);
      if (!pk) return send(res, 401, { error: "unauthenticated" });
      const to = requireString(await readJson(req), "to", { max: 128 });
      await DB.invite(pk, to);
      return send(res, 200, { ok: true });
    }
    if (method === "POST" && url === "/friends/accept") {
      const pk = await authPk(req);
      if (!pk) return send(res, 401, { error: "unauthenticated" });
      const from = requireString(await readJson(req), "from", { max: 128 });
      const fromPk = await DB.resolveToPk(from);
      const ok = fromPk ? await DB.acceptInvite(fromPk, pk) : false;
      // Grant the conversation + presence topics to BOTH members.
      if (ok && fromPk) await DB.grantFriendTopic(pk, fromPk);
      return send(res, ok ? 200 : 400, { ok });
    }
    if (method === "POST" && url === "/friends/cancel") {
      const pk = await authPk(req);
      if (!pk) return send(res, 401, { error: "unauthenticated" });
      const peer = requireString(await readJson(req), "peer", { max: 128 });
      // Withdraw an invite we sent, or decline one addressed to us. Only one of
      // the two can match a real pending invite.
      const withdrew = await DB.cancelInvite(pk, peer);
      const declined = withdrew ? false : await DB.declineInvite(pk, peer);
      const ok = withdrew || declined;
      return send(res, ok ? 200 : 400, { ok });
    }
    if (method === "POST" && url === "/friends/remove") {
      const pk = await authPk(req);
      if (!pk) return send(res, 401, { error: "unauthenticated" });
      const peer = requireString(await readJson(req), "peer", { max: 128 });
      const peerPk = await DB.resolveToPk(peer);
      const ok = await DB.removeFriend(pk, peer);
      // Revoke the shared topics. TODO(Phase 2): also kick any live subscription
      // via the EMQX API — the ACL edit only blocks the NEXT pub/sub.
      if (ok && peerPk) await DB.revokeFriendTopic(pk, peerPk);
      return send(res, ok ? 200 : 400, { ok });
    }

    // --- Push token -------------------------------------------------------
    if (method === "POST" && url === "/push/token") {
      const pk = await authPk(req);
      if (!pk) return send(res, 401, { error: "unauthenticated" });
      const pushBody = await readJson(req);
      const platform = requireString({ platform: pushBody.platform ?? "ios" }, "platform", { max: 16 });
      const token = requireString(pushBody, "token", { min: 8, max: 512 });
      await DB.setPushToken(pk, platform, token);
      return send(res, 200, { ok: true });
    }

    // --- Account deletion (purge + revoke MQTT + session tokens) ----------
    if (method === "POST" && url === "/account/delete") {
      const pk = await authPk(req);
      if (!pk) return send(res, 401, { error: "unauthenticated" });
      await DB.deleteUser(pk);
      await DB.revokeMqttAuth(pk);
      await DB.revokeSessionToken(bearer(req));
      // TODO(Phase 2): kick the client from EMQX so its live session drops.
      return send(res, 200, { ok: true });
    }

    return send(res, 404, { error: "not found" });
  } catch (e) {
    // A validation failure is the caller's problem and says which field; anything
    // else is ours, and its detail goes to the log and Sentry rather than to the
    // client. Previously every error came back as a 400 carrying its raw message,
    // which leaked internals (Redis errors included) to whoever asked.
    if (e instanceof HttpError) {
      return send(res, e.status, { error: e.code, message: e.message });
    }
    logger.error(`[api] ${method} ${url} — ${(e as Error).message}`, e as Error);
    return send(res, 500, { error: "INTERNAL" });
  }
});

server.listen(PORT, () => {
  logger.startup(`📇 app-api on :${PORT} — REST directory/friends/push/account/payments`);
});

// Event-loop / memory / Redis-latency early warning → Sentry. Same monitor the
// monolith runs: every service in the stack now reports its own vitals, so a
// stall or leak in an extracted service is as visible as one in server.ts.
healthMonitor.start();
