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
//
// The bearer also carries its SCOPE — which door minted it. Adding friends is
// the paid feature, so those two routes read one field off the resolved session
// instead of asking the database (or Stripe) whether this person has paid. The
// entitlement was decided once, at the door.

// Must be first: loads .env + resolves *_FILE secrets before anything reads env.
import { assertConfig } from "../lib/config";
import { initObservability } from "../lib/observability";
initObservability("api");
import { healthMonitor } from "../lib/health-monitor";
import { logger } from "../lib/logger";
import * as http from "http";
import { readJson, send, bearer, requireString, HttpError } from "../lib/http";
import { DB } from "../services/db/api";
import { EMQX } from "../lib/emqx";
import { friendshipHash } from "../lib/crypto-utils";
import { StripeService } from "../services/stripe/api";
import { SubscriptionService } from "../services/subscription/api";
import { handleSubscribe } from "../services/web/subscribe";
import { ADMISSION_POLICY } from "../lib/admission";

const PORT = Number(process.env.PORT || 8080);

/** Resolve the caller's pk + scope from its REST session bearer, or null. */
async function authSession(req: http.IncomingMessage) {
  return DB.resolveSessionToken(bearer(req));
}

/**
 * End a lapsed subscriber's access, now.
 *
 * A row edit only binds the NEXT authorization check, so each step has a live
 * counterpart: revoke the ACL AND drop the open subscription, revoke the bearer
 * AND kick the connection. Friendships and message history are deliberately
 * untouched — this is a paywall closing, not an account being deleted, and
 * resubscribing regrants every topic on the next paid login.
 */
async function endPremiumAccess(pk: string): Promise<void> {
  const botPk = await DB.getPkByUsername(process.env.BOT_USERNAME || "helper");
  const peers = await DB.revokeAllFriendTopics(pk, botPk || undefined);
  for (const peer of peers) {
    await EMQX.revokeTopic(pk, peer, `c/${friendshipHash(pk, peer)}`);
  }
  await DB.revokeAllSessions(pk);
  await DB.revokeMqttAuth(pk);
  await EMQX.kick(pk);
  logger.info(`🔒 [claim] premium access ended for ${pk.slice(0, 12)}… (${peers.length} conversations)`);
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
    //
    // Two events matter, and they arrive in that order:
    //
    //   checkout.session.completed   the ONLY place a plaintext email address
    //                                enters this server. It is hashed into the
    //                                subscription record and discarded.
    //   customer.subscription.*      renewals and cancellations, which carry a
    //                                customer id and no address at all — hence
    //                                the `subcus:` index written above.
    if (ADMISSION_POLICY === "stripe" && method === "POST" && url === "/stripe/webhook") {
      const chunks: Buffer[] = [];
      req.on("data", (c) => chunks.push(c as Buffer));
      req.on("end", async () => {
        try {
          const event = StripeService.constructEvent(
            Buffer.concat(chunks),
            req.headers["stripe-signature"] as string
          );

          if (event.type === "checkout.session.completed") {
            const cs = event.data.object as any;
            const email: string = cs?.customer_details?.email || cs?.customer_email || "";
            const customerId: string = typeof cs?.customer === "string" ? cs.customer : cs?.customer?.id;
            if (email && customerId) {
              const emailHash = await SubscriptionService.recordPurchase(email, customerId);
              // A second copy on the Stripe customer, so subscriptions can be
              // rebuilt if the database is ever restored from before the purchase.
              await StripeService.tagCustomerEmailHash(customerId, emailHash);
            } else {
              logger.error(`❌ [stripe-webhook] checkout.session.completed without an email or customer`);
            }
          }

          if (event.type.startsWith("customer.subscription.")) {
            const sub = event.data.object as any;
            const active = sub.status === "active" || sub.status === "trialing";
            const pks = await SubscriptionService.setStateForCustomer(
              sub.customer,
              active ? "active" : "cancelled"
            );
            // Access has to end when the subscription does, not when the last
            // bearer happens to lapse — a 30-day session cap is not a refund
            // policy. Regranting on the next paid login is what makes this safe
            // to do eagerly.
            if (!active) for (const pk of pks) await endPremiumAccess(pk);
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
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const pk = session.pk;
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
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const pk = session.pk;
      return send(res, 200, { friends: await DB.getFriendsList(pk) });
    }
    if (method === "GET" && url === "/friends/invites") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const pk = session.pk;
      return send(res, 200, { invites: await DB.getMyInvites(pk) });
    }
    if (method === "POST" && url === "/friends/invite") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const pk = session.pk;
      // The paywall, in full. A free session talks to the helper bot and
      // nothing else; growing the friend graph is what a subscription buys.
      if (session.scope !== "premium") return send(res, 402, { error: "PREMIUM_REQUIRED" });
      const to = requireString(await readJson(req), "to", { max: 128 });
      await DB.invite(pk, to);
      return send(res, 200, { ok: true });
    }
    if (method === "POST" && url === "/friends/accept") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const pk = session.pk;
      if (session.scope !== "premium") return send(res, 402, { error: "PREMIUM_REQUIRED" });
      const from = requireString(await readJson(req), "from", { max: 128 });
      const fromPk = await DB.resolveToPk(from);
      const ok = fromPk ? await DB.acceptInvite(fromPk, pk) : false;
      // Grant the conversation + presence topics to BOTH members.
      if (ok && fromPk) await DB.grantFriendTopic(pk, fromPk);
      return send(res, ok ? 200 : 400, { ok });
    }
    if (method === "POST" && url === "/friends/cancel") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const pk = session.pk;
      const peer = requireString(await readJson(req), "peer", { max: 128 });
      // Withdraw an invite we sent, or decline one addressed to us. Only one of
      // the two can match a real pending invite.
      const withdrew = await DB.cancelInvite(pk, peer);
      const declined = withdrew ? false : await DB.declineInvite(pk, peer);
      const ok = withdrew || declined;
      return send(res, ok ? 200 : 400, { ok });
    }
    if (method === "POST" && url === "/friends/remove") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const pk = session.pk;
      const peer = requireString(await readJson(req), "peer", { max: 128 });
      const peerPk = await DB.resolveToPk(peer);
      const ok = await DB.removeFriend(pk, peer);
      if (ok && peerPk) {
        await DB.revokeFriendTopic(pk, peerPk);
        // The ACL edit blocks the NEXT authorization check; a subscription that
        // is already open keeps delivering until the client disconnects for its
        // own reasons (ASVS-1). Drop it now. Best effort by design — the
        // unfriend has already succeeded and must not fail on the broker.
        await EMQX.revokeTopic(pk, peerPk, `c/${friendshipHash(pk, peerPk)}`);
      }
      return send(res, ok ? 200 : 400, { ok });
    }

    // --- Push token -------------------------------------------------------
    if (method === "POST" && url === "/push/token") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const pk = session.pk;
      const pushBody = await readJson(req);
      const platform = requireString({ platform: pushBody.platform ?? "ios" }, "platform", { max: 16 });
      const token = requireString(pushBody, "token", { min: 8, max: 512 });
      await DB.setPushToken(pk, platform, token);
      return send(res, 200, { ok: true });
    }

    // --- Account deletion (purge + revoke MQTT + session tokens) ----------
    if (method === "POST" && url === "/account/delete") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const pk = session.pk;
      await DB.deleteUser(pk);
      await DB.revokeMqttAuth(pk);
      await DB.revokeSessionToken(bearer(req));
      // Everything above stops the NEXT connect. This ends the current one —
      // otherwise a deleted account keeps a live session, and its queued backlog,
      // for as long as the connection happens to last.
      await EMQX.kick(pk);
      return send(res, 200, { ok: true });
    }

    return send(res, 404, { error: "not found" });
  } catch (e) {
    // A validation failure is the caller's problem and says which field; anything
    // else is ours, and its detail goes to the log and Sentry rather than to the
    // client. Previously every error came back as a 400 carrying its raw message,
    // which leaked internals (database errors included) to whoever asked.
    if (e instanceof HttpError) {
      return send(res, e.status, { error: e.code, message: e.message });
    }
    logger.error(`[api] ${method} ${url} — ${(e as Error).message}`, e as Error);
    return send(res, 500, { error: "INTERNAL" });
  }
});

// Fail fast, before the port opens: this process owns /stripe/webhook and
// /subscribe. (Beside the import it would be hoisted over; here it is not.)
assertConfig(["stripe"]);

server.listen(PORT, () => {
  logger.startup(`📇 app-api on :${PORT} — REST directory/friends/push/account/payments`);
});

// Event-loop / memory / query-latency early warning → Sentry. Same monitor the
// monolith runs: every service in the stack now reports its own vitals, so a
// stall or leak in an extracted service is as visible as one in server.ts.
healthMonitor.start();
