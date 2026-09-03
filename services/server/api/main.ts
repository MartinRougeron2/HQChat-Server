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
import { assertConfig, DONATIONS_ENABLED } from "../lib/config";
import { donationsDead, donationSummary, resolvePrices } from "../lib/donations-config";
import { initObservability } from "../lib/observability";
initObservability("api");
import { healthMonitor } from "../lib/health-monitor";
import { logger } from "../lib/logger";
import * as http from "http";
import { readJson, send, bearer, requireString, requireHex, HttpError, MAX_BODY_BYTES } from "../lib/http";
import { DB } from "../services/db/api";
import { EMQX } from "../lib/emqx";
import { friendshipHash } from "../lib/crypto-utils";
import { isPeerId, PEER_ID_LENGTH } from "../lib/identity";
import { StripeService, displayNameFromSession } from "../services/stripe/api";
import { handleDonate } from "../services/web/donate";
import { ADMISSION_POLICY } from "../lib/admission";

const PORT = Number(process.env.PORT || 8080);

/** HQC-256 public key size (lib/hqc.ts). Prekeys are HQC public keys too. */
const HQC_PUBLIC_KEY_BYTES = 7237;

/**
 * One-time prekeys accepted per upload.
 *
 * A key travels as hex, so it costs 2 x 7237 = 14474 characters on the wire —
 * the byte count is NOT the wire cost, which is the easy way to size this wrong.
 * A bundle is the medium-term key plus N one-time keys, so the body is roughly
 * (N + 1) x 14474 bytes: at N = 16 that is ~246 kB against a 256 kB
 * MAX_BODY_BYTES, close enough that a couple of extra fields would start
 * returning 413 in production and nowhere else.
 *
 * Eight keeps the body near 130 kB, half the cap. The pool is not limited to
 * eight: putPrekeyBundle is additive (ON CONFLICT DO NOTHING), so a client that
 * wants a deeper pool uploads more than one batch.
 */
const MAX_ONETIME_PER_UPLOAD = 8;

/**
 * Longest `peer` identifier a route will accept.
 *
 * One number again, for every route. It was two: the friend routes capped at
 * 128 because you invite people by HANDLE, while `/prekeys/claim` had to fit a
 * peer's IDENTITY — and an identity was a 14474-character public key, so the
 * cap was raised to exactly that (#105, after 128 refused every real client
 * with `peer must be 1–128 characters`).
 *
 * An identity is 64 characters now, which is comfortably inside the handle-sized
 * bound, so the two forms stop needing different limits and the widest thing
 * this route accepts stops being "a public key's worth of anything".
 */
const MAX_PEER_IDENTIFIER = 128;

// --- QoS caps ---------------------------------------------------------------
// These replace the paywall. The infrastructure bill is fixed monthly — droplets,
// one managed Postgres — so users do not cost money; they cost capacity. What
// actually threatens the deployment is a script, not a popular account, and
// these are set where no real person will ever meet them.
//
// The friend cap also bounds a real fan-out: `endPremiumAccess`-style ACL walks
// and `notifyGraphChanged` are O(friends), and `regrantAllFriendTopics` runs on
// every full-door login.
const FRIEND_CAP = Number(process.env.FRIEND_CAP || 150);
// Per calendar-ish day, on the existing `rate_counters` table — no new storage.
const INVITES_PER_DAY = Number(process.env.INVITES_PER_DAY || 20);

// Refuse to boot rather than 413 in production if either constant drifts into
// the body cap. At startup, where an operator sees it — a type-level assertion
// cannot express this (comparing two number literals yields `boolean`, and the
// cast that would silence it would also stop it ever failing).
//
// The same reasoning applies to the peer bound: an identifier must fit, and the
// only reason it does is that identities are digests now.
{
  if (MAX_PEER_IDENTIFIER < PEER_ID_LENGTH) {
    throw new Error(
      `MAX_PEER_IDENTIFIER (${MAX_PEER_IDENTIFIER}) is shorter than a client id ` +
      `(${PEER_ID_LENGTH}) — every peer-addressed route would refuse every real caller`
    );
  }
}
{
  const worstCaseBody = (MAX_ONETIME_PER_UPLOAD + 1) * HQC_PUBLIC_KEY_BYTES * 2;
  if (worstCaseBody > MAX_BODY_BYTES / 2) {
    throw new Error(
      `prekey bundle upload can reach ${worstCaseBody}B against MAX_BODY_BYTES ${MAX_BODY_BYTES}B — ` +
      `lower MAX_ONETIME_PER_UPLOAD (${MAX_ONETIME_PER_UPLOAD}) or raise the cap`
    );
  }
}

/** Resolve the caller's client id + scope from its REST session bearer, or
 *  null. No route below needs the caller's KEY — the id is the name for
 *  everything the control plane does. */
async function authSession(req: http.IncomingMessage) {
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

    // --- Donations (Stripe) — raw body needed for signature verification ----
    //
    // ONE event matters, and it carries almost nothing we want:
    //
    //   checkout.session.completed   a donation went through. The only field
    //                                read is the optional display name for the
    //                                supporters page. Not the email, not the
    //                                customer id, not the amount.
    //
    // `customer.subscription.*` is deliberately NOT handled. A recurring
    // donation that lapses removes no access, because it granted none — there is
    // nothing to revoke, so subscribing to those events would only invite a
    // handler that did something.
    if (DONATIONS_ENABLED && method === "POST" && url === "/stripe/webhook") {
      const chunks: Buffer[] = [];
      req.on("data", (c) => chunks.push(c as Buffer));
      req.on("end", async () => {
        try {
          const event = StripeService.constructEvent(
            Buffer.concat(chunks),
            req.headers["stripe-signature"] as string
          );

          if (event.type === "checkout.session.completed") {
            const name = displayNameFromSession(event.data.object);
            // Blank is the expected answer: recognition is opt-in, and a
            // donation with no name must leave no row at all.
            if (name) await DB.recordSupporter(name);
          }

          res.writeHead(200); res.end("ok");
        } catch (e: any) {
          logger.error(`❌ [stripe-webhook] ${e.message}`);
          res.writeHead(400); res.end(`Webhook Error: ${e.message}`);
        }
      });
      return;
    }
    if (DONATIONS_ENABLED && (url.startsWith("/donate") || url.startsWith("/supporters"))) {
      handleDonate(req, res).catch((e: unknown) => {
        logger.error("[donate] handler error", e);
        if (!res.headersSent) { res.writeHead(500); res.end("error"); }
      });
      return;
    }

    // --- Directory --------------------------------------------------------
    if (method === "GET" && url.startsWith("/users")) {
      // Exact-username lookup only (?username=…) — no bulk enumeration (M3).
      const q = new URL(url, "http://x").searchParams.get("username") || "";
      const id = q ? await DB.getIdByUsername(q) : null;
      return send(res, 200, { username: q, id });
    }

    // The public key an id names.
    //
    // The directory ships IDS — 64 characters per friend rather than 14474 —
    // so a client that has just learned about someone, or that lost its local
    // store, needs one place to fetch the key itself. This is that place.
    //
    // Unauthenticated, and that is deliberate: the response is a public key,
    // the id that addresses it is derivable from that same key by anyone who
    // holds it, and requiring a session would buy nothing an attacker does not
    // already have. What makes it SAFE is not access control but the
    // commitment — the caller checks `sha256(hex(key)) == id` before pinning
    // anything, so this server cannot substitute a key even for itself.
    //
    // ⚠️ A client that skips that check has re-created the MITM this design
    // exists to close. Both clients do it (lib/identity.keyMatchesId,
    // PeerID.matches).
    if (method === "GET" && url.startsWith("/peer/")) {
      const m = url.match(/^\/peer\/([^/?]+)\/key$/);
      if (!m) return send(res, 404, { error: "not found" });
      const id = decodeURIComponent(m[1]!).toLowerCase();
      // Shape-checked before it reaches the database: an id is a fixed-width
      // hex string, and anything else is a caller error rather than a lookup.
      if (!isPeerId(id)) {
        throw new HttpError(400, "INVALID_FIELD", `id must be ${PEER_ID_LENGTH} lowercase hex characters`);
      }
      const identityPk = await DB.identityKey(id);
      if (!identityPk) return send(res, 404, { error: "UNKNOWN_PEER" });
      return send(res, 200, { id, publicKey: identityPk });
    }

    if (method === "POST" && url === "/username") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const id = session.id;
      const body = await readJson(req);
      const username = requireString(body, "username", { min: 3, max: 32 });
      // The client distinguishes "someone else owns that handle" from a
      // transient failure and shows a banner with a way out (AppState
      // .isUsernameTaken), so this code has to survive the round trip as a code
      // — not collapse into a generic 500 with the rest.
      try {
        await DB.setUsername(id, username);
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
      const id = session.id;
      return send(res, 200, { friends: await DB.getFriendsList(id) });
    }
    if (method === "GET" && url === "/friends/invites") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const id = session.id;
      return send(res, 200, { invites: await DB.getMyInvites(id) });
    }
    if (method === "POST" && url === "/friends/invite") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const id = session.id;
      // What used to be the paywall. A subscription bought the right to grow
      // the friend graph at all; now everyone has it, and what stands here
      // instead are ceilings — high enough that no real account meets them,
      // low enough that a script cannot turn one signup into unbounded work.
      //
      // Deliberately NOT 402. The app reads 402 as "fall back to the free
      // door" and re-authenticates; a user who hit a daily invite limit would
      // silently lose their friend topics for the trouble.
      if (await DB.countFriends(id) >= FRIEND_CAP) {
        return send(res, 409, { error: "FRIEND_LIMIT", limit: FRIEND_CAP });
      }
      const sent = await DB.bumpCounter(`invite:day:${id}`, 24 * 60 * 60);
      if (sent > INVITES_PER_DAY) {
        logger.warn(`[friends] invite rate-limited for ${id.slice(0, 12)}… (${sent}/${INVITES_PER_DAY} today)`);
        return send(res, 429, { error: "RATE_LIMITED", limit: INVITES_PER_DAY });
      }
      const to = requireString(await readJson(req), "to", { max: MAX_PEER_IDENTIFIER });
      await DB.invite(id, to);
      // The recipient has no other way to learn an invite exists: nothing pushed
      // graph changes, so an invite sat unseen until their next poll — which is
      // why one needed a manual refresh to appear at all.
      const toId = await DB.resolveToId(to);
      if (toId) await EMQX.notifyGraphChanged([toId]);
      return send(res, 200, { ok: true });
    }
    if (method === "POST" && url === "/friends/accept") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const id = session.id;
      if (await DB.countFriends(id) >= FRIEND_CAP) {
        return send(res, 409, { error: "FRIEND_LIMIT", limit: FRIEND_CAP });
      }
      const from = requireString(await readJson(req), "from", { max: MAX_PEER_IDENTIFIER });
      const fromId = await DB.resolveToId(from);
      // BOTH sides, because a friendship adds a contact to each. The inviter
      // was under the cap when they sent it; accepting is what would push them
      // over, and only this side can see that.
      if (fromId && (await DB.countFriends(fromId)) >= FRIEND_CAP) {
        return send(res, 409, { error: "FRIEND_LIMIT", limit: FRIEND_CAP, peer: true });
      }
      const ok = fromId ? await DB.acceptInvite(fromId, id) : false;
      // Grant the conversation + presence topics to BOTH members.
      if (ok && fromId) await DB.grantFriendTopic(id, fromId);
      // AFTER the grant, and both sides.
      //
      // The inviter is the one that matters. They invited a HANDLE, so their
      // contact row holds no client id until a directory sync fills it in — and
      // the accepter now greets immediately, so that greeting reached the
      // inviter BEFORE they knew who the sender was. The frame named an id their
      // directory did not contain, and it was dropped. Nudging here closes the
      // window instead of leaving it to a 60-second timer.
      if (ok && fromId) await EMQX.notifyGraphChanged([fromId, id]);
      return send(res, ok ? 200 : 400, { ok });
    }
    if (method === "POST" && url === "/friends/cancel") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const id = session.id;
      const peer = requireString(await readJson(req), "peer", { max: MAX_PEER_IDENTIFIER });
      // Withdraw an invite we sent, or decline one addressed to us. Only one of
      // the two can match a real pending invite.
      const withdrew = await DB.cancelInvite(id, peer);
      const declined = withdrew ? false : await DB.declineInvite(id, peer);
      const ok = withdrew || declined;
      if (ok) {
        const peerId = await DB.resolveToId(peer);
        if (peerId) await EMQX.notifyGraphChanged([peerId, id]);
      }
      return send(res, ok ? 200 : 400, { ok });
    }
    if (method === "POST" && url === "/friends/remove") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const id = session.id;
      const peer = requireString(await readJson(req), "peer", { max: MAX_PEER_IDENTIFIER });
      const peerId = await DB.resolveToId(peer);
      const ok = await DB.removeFriend(id, peer);
      if (ok && peerId) {
        await DB.revokeFriendTopic(id, peerId);
        // The ACL edit blocks the NEXT authorization check; a subscription that
        // is already open keeps delivering until the client disconnects for its
        // own reasons (ASVS-1). Drop it now. Best effort by design — the
        // unfriend has already succeeded and must not fail on the broker.
        //
        // This is the line that has never once worked on this deployment. Both
        // arguments used to be 14474-character public keys, so the admin URL it
        // built was ~29 kB and EMQX answered 414 every single time — and because
        // authorization is checked at SUBSCRIBE, the unfriended peer's open
        // subscription kept delivering. At 64 characters the request fits.
        await EMQX.revokeTopic(id, peerId, `c/${friendshipHash(id, peerId)}`);
        // Both sides: the removed peer should stop showing a contact they can no
        // longer reach, and the remover's other devices need the same news.
        await EMQX.notifyGraphChanged([peerId, id]);
      }
      return send(res, ok ? 200 : 400, { ok });
    }

    // --- Prekeys ----------------------------------------------------------
    // The ephemeral half of the initial key agreement (003_prekeys.sql). The
    // server is untrusted here by design: it can withhold one-time keys to force
    // the weaker medium-term fallback, but it cannot read anything, because the
    // initiator also encapsulates to the peer's PINNED identity key and mixes
    // both secrets into the root.
    if (method === "POST" && url === "/prekeys") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const id = session.id;
      const body = await readJson(req);
      const medium = requireHex(body, "medium", HQC_PUBLIC_KEY_BYTES);

      const raw = Array.isArray(body?.oneTime) ? body.oneTime : [];
      if (raw.length > MAX_ONETIME_PER_UPLOAD) {
        throw new HttpError(400, "TOO_MANY_PREKEYS",
          `at most ${MAX_ONETIME_PER_UPLOAD} one-time prekeys per upload`);
      }
      const oneTime = raw.map((entry: unknown, i: number) => {
        const item = entry as Record<string, unknown>;
        const id = item?.id;
        if (!Number.isInteger(id) || (id as number) < 0) {
          throw new HttpError(400, "INVALID_FIELD", `oneTime[${i}].id must be a non-negative integer`);
        }
        return { id: id as number, prekey: requireHex(item, "prekey", HQC_PUBLIC_KEY_BYTES) };
      });

      await DB.putPrekeyBundle(id, medium, oneTime);
      return send(res, 200, { ok: true, accepted: oneTime.length });
    }

    // Claim one prekey for a peer. POST rather than GET with the peer in the
    // path — kept that way now that an id would fit in a URL, because the
    // RESPONSE is key material and has no business in an access log or a proxy
    // cache, and because a claim mutates (it consumes a one-time key).
    if (method === "POST" && url === "/prekeys/claim") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const id = session.id;
      const peer = requireString(await readJson(req), "peer", { max: MAX_PEER_IDENTIFIER });
      const peerId = await DB.resolveToId(peer);
      // Friendship is the authorization. Without it, anyone with a session could
      // drain a stranger's one-time pool — a cheap way to force every one of
      // their future conversations onto the reusable medium-term key.
      if (!peerId || !(await DB.areFriends(id, peerId))) {
        return send(res, 403, { error: "NOT_FRIENDS" });
      }
      const claimed = await DB.claimPrekey(peerId);
      if (!claimed) return send(res, 404, { error: "NO_PREKEYS" });
      return send(res, 200, claimed);
    }

    // How many one-time keys this account has left, so the client knows when to
    // replenish. Only ever about the caller's own pool.
    if (method === "GET" && url === "/prekeys/count") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const id = session.id;
      return send(res, 200, {
        remaining: await DB.countOneTimePrekeys(id),
        maxId: await DB.maxOneTimePrekeyId(id),
        target: MAX_ONETIME_PER_UPLOAD,
      });
    }

    // --- Push token -------------------------------------------------------
    if (method === "POST" && url === "/push/token") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const id = session.id;
      const pushBody = await readJson(req);
      const platform = requireString({ platform: pushBody.platform ?? "ios" }, "platform", { max: 16 });
      const token = requireString(pushBody, "token", { min: 8, max: 512 });
      await DB.setPushToken(id, platform, token);
      return send(res, 200, { ok: true });
    }

    // --- Account deletion (purge + revoke MQTT + session tokens) ----------
    if (method === "POST" && url === "/account/delete") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const id = session.id;
      await DB.deleteUser(id);
      await DB.revokeMqttAuth(id);
      await DB.revokeSessionToken(bearer(req));
      // Everything above stops the NEXT connect. This ends the current one —
      // otherwise a deleted account keeps a live session, and its queued backlog,
      // for as long as the connection happens to last. It also only started
      // working when the client id stopped being a 14 kB URL path segment.
      await EMQX.kick(id);
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
// /donate. (Beside the import it would be hoisted over; here it is not.)
assertConfig(["stripe"]);

// A donate button that cannot charge is worth a Sentry event, not just a line in
// a boot log nobody reads after the first rollout. Same escalation push-bridge
// makes for a half-configured APNs (push/main.ts): the process is fine, the
// feature is dead, and the only person who can tell is looking somewhere else.
//
// It does NOT refuse to boot, deliberately. This process is the whole REST API —
// directory, friends, push registration, account deletion — and taking all of it
// down over a broken donate button would be a far worse outage than the one it
// reports.
const DONATION_PRICES = resolvePrices(process.env);
if (DONATIONS_ENABLED && donationsDead(DONATION_PRICES)) {
  logger.error(`[api] ${donationSummary(DONATION_PRICES)}`);
}

server.listen(PORT, () => {
  logger.startup(
    `📇 app-api on :${PORT} — REST directory/friends/push/account` +
    (DONATIONS_ENABLED ? ` + ${donationSummary(DONATION_PRICES)}` : "")
  );
});

// Event-loop / memory / query-latency early warning → Sentry. Same monitor the
// monolith runs: every service in the stack now reports its own vitals, so a
// stall or leak in an extracted service is as visible as one in server.ts.
healthMonitor.start();
