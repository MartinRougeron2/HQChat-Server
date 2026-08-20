import { logger } from '../../lib/logger';
import Redis from 'ioredis';
import * as crypto from 'crypto';
import { friendshipHash, blindedPk } from '../../lib/crypto-utils';
import { queryMetrics } from '../../lib/metrics';
import { performance } from 'perf_hooks';
require('dotenv').config();

// Use REDIS_URL when provided (production, with password); fall back to a
// default localhost connection for local development.
//
// lazyConnect: don't open a socket until the first command is issued. Importing
// this module (e.g. from a unit test with no Redis running) then does NOT dial
// Redis — which avoids ioredis' "Unhandled error event" reconnect spam and an
// open handle that keeps the test process alive. The server/bot issue commands,
// which connect on demand.
// Module-level so it can be referenced from default parameter positions (where
// `this` is not typed).
// MQTT connect token lifetime. Expiration-based rotation: EMQX is told the
// token's `expire_at` and DISCONNECTS the client when it lapses; the client then
// refreshes (/auth/refresh, using its longer REST session — no re-handshake) and
// reconnects. Short (5m) to keep the replay window tight; reusable across
// reconnects within that window.
const MQTT_TOKEN_TTL_SECONDS = 5 * 60;

// REST bearer session (app-api + /auth/refresh). Longer-lived than the one-time
// MQTT connect token, refreshable, revoked on logout/delete.
const REST_SESSION_TTL_SECONDS = 60 * 60;

// How long an auth challenge (the KEM proof the client must return) stays open.
const AUTH_CHALLENGE_TTL_SECONDS = 60;

const redisOptions = { lazyConnect: true } as const;
const redis = process.env.REDIS_URL
  ? new Redis(process.env.REDIS_URL, redisOptions)
  : new Redis(redisOptions);

// Attach an error listener so a connection problem is logged as one line rather
// than surfacing as Node's noisy "Unhandled error event" (which only fires when
// no 'error' listener is registered). With lazyConnect this stays silent in
// tests that never touch Redis.
redis.on('error', (err) => logger.error(`[redis] ${err.message}`));

const usernamesBlacklist = new Set([
  'admin', 'administrator', 'root', 'system', 'support', 'help', 'contact',
  'info', 'security', 'test', 'tester', 'bot', 'moderator', 'mod',
  'staff', 'team', 'owner', 'founder',
  // The helper bot's handle — the server auto-friends it to every user, so it
  // must not be reclaimable by a normal account (would hijack that routing).
  'helper', 'dissqus'
]);

const DBImpl = {
  // ============================================================
  // 1. IDENTITY & USER MANAGEMENT
  // ============================================================

  async createUser(pk: string, username: string) {
    const isTaken = await redis.sismember('usernames:taken', username);
    if (isTaken) throw new Error(`Username '${username}' is already taken.`);

    const userExists = await redis.exists(`user:${pk}`);
    if (userExists) throw new Error(`Public Key already registered.`);

    const pipeline = redis.pipeline();
    pipeline.hset(`user:${pk}`, { username, pk, created_at: Date.now(), tier: 'free' });
    pipeline.set(`username:${username}`, pk);
    pipeline.sadd('usernames:taken', username);
    await pipeline.exec();
  },

  async getUser(pk: string) {
    return await redis.hgetall(`user:${pk}`);
  },

  async getUsername(pk: string): Promise<string | null> {
    return await redis.hget(`user:${pk}`, 'username');
  },

  async getPkByUsername(username: string): Promise<string | null> {
    return await redis.get(`username:${username}`);
  },

  // NOTE: the bulk user directory (getUserDirectory / getAllUsernames) was
  // removed. Returning every username + pk to any authenticated user was a
  // social-graph enumeration leak, and pk → SHA-256(pk) → billing/linking code
  // (M3). Discovery is now exact-username lookup only (getPkByUsername), used by
  // the GET_ALL_USERS handler in server.ts.

  /**
   * Helper used by the server to handle inputs that could be either a PK or Username
   */
  async resolveToPk(identifier: string): Promise<string | null> {
    if (!identifier) return null;
    // Assuming HQC Public Keys are long hex strings (> 50 chars)
    if (identifier.length > 50) return identifier;
    return await this.getPkByUsername(identifier);
  },

  async setUsername(pk: string, newUsername: string) {
    // check new username 
    if (!newUsername || newUsername.length < 3 || newUsername.length > 32) {
      throw new Error("Username must be between 3 and 32 characters.");
    }
    if (!/^[a-zA-Z0-9_]+$/.test(newUsername)) {
      throw new Error("Username can only contain letters, numbers, and underscores.");
    }
    if (usernamesBlacklist.has(newUsername.toLowerCase())) {
      // Reserved handles (incl. the bot's 'helper'/'dissqus') are blocked for
      // normal users. A trusted service identity that self-registered in the
      // `admission:exempt` set — i.e. the helper bot — is allowed to claim its
      // reserved handle; that's the whole reason the handle is reserved.
      if (!(await this.isAdmissionExempt(pk))) {
        throw new Error("This username is not allowed.");
      }
    }
    // Who currently owns this name (if anyone)?
    const currentOwner = await this.getPkByUsername(newUsername);

    // Idempotent: re-setting the name you already own is a no-op success
    // (previously this threw "Username taken." against your own pk).
    if (currentOwner === pk) return;

    // A name owned by a *different* pk may NOT be transferred — blindly handing
    // it over let any authenticated user take over (impersonate) another user or
    // the helper bot (H3). The only exception is a trusted service identity: the
    // helper bot legitimately needs to reclaim its handle after a seed/keypair
    // regeneration (e.g. its state volume was lost). We recognise it by the same
    // self-registered `admission:exempt` set it writes on startup — so this needs
    // no manual, stale-prone BOT_PUBLIC_KEY list. The static env is still honoured
    // as an optional override. Everything else is refused.
    if (currentOwner && currentOwner !== pk) {
      const botKeys = (process.env.BOT_PUBLIC_KEY || '')
        .split(',').map((s) => s.trim()).filter(Boolean);
      const trusted = botKeys.includes(pk) || (await this.isAdmissionExempt(pk));
      if (!trusted) {
        throw new Error('USERNAME_TAKEN');
      }
      await redis.hdel(`user:${currentOwner}`, 'username');
    }

    const oldUsername = await this.getUsername(pk);
    const pipeline = redis.pipeline();

    pipeline.hset(`user:${pk}`, 'username', newUsername);
    pipeline.set(`username:${newUsername}`, pk);
    pipeline.sadd('usernames:taken', newUsername);

    if (oldUsername && oldUsername !== newUsername) {
      pipeline.del(`username:${oldUsername}`);
      pipeline.srem('usernames:taken', oldUsername);
    }
    await pipeline.exec();
  },

  /**
   * Permanently delete a user and everything we store about them — used by the
   * in-app "Delete Account" flow (App Store Guideline 5.1.1(v)). Removes the
   * identity record, frees the username, tears down both sides of every
   * friendship (friend sets + blind hashes), and drops invites, the offline
   * queue, and the push token. The tier record is keyed by the blinded pk, so
   * we clear that too. End-to-end message content lives only on devices, so
   * this purges the user's entire server-side footprint.
   */
  async deleteUser(pk: string): Promise<void> {
    const username = await this.getUsername(pk);
    const friendPks = await redis.smembers(`friends:${pk}`);

    const pipeline = redis.pipeline();

    // Free the username binding + reservation.
    if (username) {
      pipeline.del(`username:${username}`);
      pipeline.srem('usernames:taken', username);
    }

    // Tear down each friendship from BOTH sides (set link + blind hash), and
    // with it the MQTT authorization both sides held for the shared topic.
    // Without the ACL cleanup the deleted account's grants survived in Redis,
    // and every friend kept a dangling entry for a pk that no longer exists.
    for (const friendPk of friendPks) {
      const hash = friendshipHash(pk, friendPk);
      pipeline.srem(`friends:${friendPk}`, pk);
      pipeline.del(`friendship:${hash}`);
      pipeline.hdel(`mqtt_acl:${friendPk}`, `c/${hash}`, this.presenceTopic(pk));
      pipeline.del(`hashmembers:${hash}`);
    }

    // Drop everything keyed by this pk.
    pipeline.del(`friends:${pk}`);
    pipeline.del(`invites:${pk}`);
    pipeline.del(`pending:${pk}`);
    pipeline.del(`push:${pk}`);
    pipeline.del(`user:${pk}`);
    // MQTT authorization + any outstanding connect token.
    pipeline.del(`mqtt_acl:${pk}`);
    pipeline.del(`mqtt_auth:${pk}`);
    // Subscription/tier is stored under the blinded pk.
    pipeline.del(`user:${blindedPk(pk)}`);
    pipeline.del(`storekit:${blindedPk(pk)}`);

    await pipeline.exec();

    // Invites this user SENT live in other people's inboxes, keyed by our pk.
    // They are not reachable from `friends:*`, so they need their own sweep —
    // otherwise a deleted account keeps showing up as a pending invite.
    // SCAN rather than KEYS: KEYS blocks the whole Redis instance, and this
    // runs on a user-facing request.
    await new Promise<void>((resolve, reject) => {
      const stream = redis.scanStream({ match: 'invites:*', count: 200 });
      const pending: Promise<unknown>[] = [];
      stream.on('data', (keys: string[]) => {
        if (keys.length === 0) return;
        const sweep = redis.pipeline();
        for (const key of keys) sweep.hdel(key, pk);
        pending.push(sweep.exec());
      });
      stream.on('end', () => { Promise.all(pending).then(() => resolve(), reject); });
      stream.on('error', reject);
    });
  },

  // ============================================================
  // 2. SUBSCRIPTION & TIER
  // ============================================================

  async updateUserTier(pk: string, tier: 'free' | 'premium', stripeId?: string) {
    const key = `user:${pk}`;
    const updates: any = { tier };
    if (stripeId) updates.stripe_customer_id = stripeId;
    await redis.hset(key, updates);
  },

  async getUserTier(pk: string): Promise<string> {
    const tier = await redis.hget(`user:${pk}`, 'tier');
    return tier || 'free';
  },

  async getStripeId(pk: string): Promise<string | null> {
    return await redis.hget(`user:${pk}`, 'stripe_customer_id');
  },

  /**
   * Record a verified StoreKit (App Store) subscription for the blinded pk.
   * Stored as a key with a TTL set to the subscription's expiry so it lapses
   * automatically if no renewal/refresh arrives. `expiresMs = 0` clears it.
   * Kept separate from the Stripe `tier` so the two payment paths don't clobber
   * each other in checkAdmission.
   */
  async setStoreKitPremium(blindedPk: string, expiresMs: number) {
    const key = `storekit:${blindedPk}`;
    if (!expiresMs || expiresMs <= Date.now()) {
      await redis.del(key);
      return;
    }
    const ttl = Math.ceil((expiresMs - Date.now()) / 1000);
    // Small grace window so a brief renewal gap doesn't lock the user out.
    await redis.set(key, String(expiresMs), 'EX', ttl + 86_400);
  },

  /** Whether the blinded pk has an active StoreKit subscription on record. */
  async isStoreKitPremium(blindedPk: string): Promise<boolean> {
    return (await redis.exists(`storekit:${blindedPk}`)) === 1;
  },

  /**
   * Self-registered admission exemptions. The helper bot writes its own pk here
   * on startup (see messages/bot/bot.ts) so it's admitted under any policy
   * without an operator hand-copying its key into EXEMPT_PUBLIC_KEYS — which
   * would go stale whenever the bot's seed/identity changes. Being exempt only
   * waives the payment/allowlist gate; the caller still had to pass HQC auth,
   * so only the holder of that private key benefits.
   */
  async addAdmissionExempt(pk: string) {
    await redis.sadd('admission:exempt', pk.toLowerCase());
  },

  /** Whether this pk self-registered an admission exemption. */
  async isAdmissionExempt(pk: string): Promise<boolean> {
    return (await redis.sismember('admission:exempt', pk.toLowerCase())) === 1;
  },

  // ============================================================
  // 3. INVITES & SOCIAL
  // ============================================================

  async invite(fromPk: string, toIdentifier: string) {
    const toPk = await this.resolveToPk(toIdentifier);
    if (!toPk || !(await redis.exists(`user:${toPk}`))) throw new Error("User not found");
    if (fromPk === toPk) throw new Error("Self-invite not allowed");

    if (await this.areFriends(fromPk, toPk)) throw new Error("Already friends");

    // We store the invite in the recipient's "inbox"
    await redis.hset(`invites:${toPk}`, fromPk, Date.now());
  },

  /**
   * Withdraw an invite this user sent, or decline one they received.
   * `removeFriend` cannot do this: it requires an established friendship, so a
   * pending invite had no way to be taken back at all.
   * Returns true when an invite was actually removed.
   */
  async cancelInvite(fromPk: string, toIdentifier: string): Promise<boolean> {
    const toPk = await this.resolveToPk(toIdentifier);
    if (!toPk) return false;
    // The invite lives in the *recipient's* inbox, keyed by the sender.
    const removed = await redis.hdel(`invites:${toPk}`, fromPk);
    return removed > 0;
  },

  /** Decline an invite addressed to this user. */
  async declineInvite(myPk: string, fromIdentifier: string): Promise<boolean> {
    const fromPk = await this.resolveToPk(fromIdentifier);
    if (!fromPk) return false;
    const removed = await redis.hdel(`invites:${myPk}`, fromPk);
    return removed > 0;
  },

  async getMyInvites(myPk: string) {
    const raw = await redis.hgetall(`invites:${myPk}`);
    const enriched = [];

    for (const [senderPk, timestamp] of Object.entries(raw)) {
      const username = await this.getUsername(senderPk);
      enriched.push({
        pk: senderPk,
        username: username || "Unknown",
        sent_at: parseInt(timestamp)
      });
    }
    return enriched;
  },

  /**
   * Refined to support the server's need to notify the peer.
   * Returns true if the acceptance was successful.
   */
  async acceptInvite(fromIdentifier: string, myPk: string): Promise<boolean> {
    const fromPk = await this.resolveToPk(fromIdentifier);
    if (!fromPk) return false;

    const hasInvite = await redis.hexists(`invites:${myPk}`, fromPk);
    if (!hasInvite) return false;

    const pipeline = redis.pipeline();
    pipeline.sadd(`friends:${myPk}`, fromPk);
    pipeline.sadd(`friends:${fromPk}`, myPk);
    pipeline.hdel(`invites:${myPk}`, fromPk);

    const results = await pipeline.exec();
    return !!results;
  },

  async getFriendsList(myPk: string) {
    const friendPks = await redis.smembers(`friends:${myPk}`);
    if (friendPks.length === 0) return [];

    const pipeline = redis.pipeline();
    friendPks.forEach(pk => pipeline.hget(`user:${pk}`, 'username'));
    const usernames = await pipeline.exec();

    return friendPks.map((pk, index) => {
      //@ts-ignore
      const username = usernames ? usernames[index][1] : null;
      return { pk, username: (username as string) || 'Anonymous' };
    });
  },

  async areFriends(pkA: string, pkB: string): Promise<boolean> {
    const res = await redis.sismember(`friends:${pkA}`, pkB);
    return res === 1;
  },

  async removeFriend(fromPk: string, toIdentifier: string): Promise<boolean> {
    const toPk = await this.resolveToPk(toIdentifier);
    if (!toPk) return false;

    // Check if they are actually friends
    if (!(await this.areFriends(fromPk, toPk))) return false;

    // Remove from both sides
    const pipeline = redis.pipeline();
    pipeline.srem(`friends:${fromPk}`, toPk);
    pipeline.srem(`friends:${toPk}`, fromPk);

    // Also remove the friendship hash
    const hash = this.getFriendshipHash(fromPk, toPk);
    pipeline.del(`friendship:${hash}`);

    const results = await pipeline.exec();
    return !!results;
  },

  async createFriendship(pk1: string, pk2: string) {
    const hash = this.getFriendshipHash(pk1, pk2);
    const pipeline = redis.pipeline();
    // Blind hash for checkFriendship…
    pipeline.set(`friendship:${hash}`, '1');
    // …and the friend sets so getFriendsList / presence work.
    pipeline.sadd(`friends:${pk1}`, pk2);
    pipeline.sadd(`friends:${pk2}`, pk1);
    await pipeline.exec();
  },

  /** Idempotently ensure the friend-set link exists (heals older friendships
   *  that were stored only as a blind hash). */
  async ensureFriendLink(pk1: string, pk2: string) {
    const pipeline = redis.pipeline();
    pipeline.sadd(`friends:${pk1}`, pk2);
    pipeline.sadd(`friends:${pk2}`, pk1);
    await pipeline.exec();
  },

  /**
   * Checks if friendship exists based on blind hash
   */
  async checkFriendship(pk1: string, pk2: string): Promise<boolean> {
    const hash = this.getFriendshipHash(pk1, pk2);
    const exists = await redis.exists(`friendship:${hash}`);
    return exists === 1;
  },

  getFriendshipHash(pk1: string, pk2: string): string {
    return friendshipHash(pk1, pk2);
  },

  // ============================================================
  // 4. OFFLINE MESSAGE QUEUE
  // ============================================================

  /** TTL for queued messages: 7 days. */
  PENDING_TTL_SECONDS: 7 * 24 * 60 * 60,

  /**
   * Queue a ready-to-send envelope for a recipient who is currently offline.
   * Stored oldest-first (rpush) so flush delivers in chronological order.
   */
  // Cap a recipient's offline queue so a sender can't balloon their Redis
  // memory. Oldest entries are trimmed once the cap is exceeded.
  MAX_PENDING: 500,

  async enqueuePending(targetPk: string, envelope: object) {
    const key = `pending:${targetPk}`;
    const pipeline = redis.pipeline();
    pipeline.rpush(key, JSON.stringify(envelope));
    pipeline.ltrim(key, -this.MAX_PENDING, -1); // keep only the newest MAX_PENDING
    pipeline.expire(key, this.PENDING_TTL_SECONDS);
    await pipeline.exec();
  },

  /**
   * Atomically read and clear a recipient's pending queue.
   * Returns the envelopes in chronological order (oldest first).
   */
  async flushPending(targetPk: string): Promise<object[]> {
    const key = `pending:${targetPk}`;
    const pipeline = redis.pipeline();
    pipeline.lrange(key, 0, -1);
    pipeline.del(key);
    const results = await pipeline.exec();
    const raw = (results?.[0]?.[1] as string[]) || [];
    return raw.map((s) => JSON.parse(s));
  },

  // ============================================================
  // 5. PUSH TOKENS
  // ============================================================

  async setPushToken(pk: string, platform: string, token: string) {
    await redis.hset(`push:${pk}`, { platform, token });
  },

  async getPushToken(pk: string): Promise<{ platform: string; token: string } | null> {
    const data = await redis.hgetall(`push:${pk}`);
    if (!data || !data.token) return null;
    return { platform: data.platform || "ios", token: data.token };
  },

  // ============================================================
  // 6. MQTT AUTHORIZATION (RLS) — friend-hash topic ACL
  // ============================================================
  //
  // The MQTT migration (see deploy/EXTRACTION_PLAN.md) makes each conversation a
  // topic `c/{friendshipHash}`. EMQX's Redis authorizer reads `mqtt_acl:{pk}` —
  // a hash of `topic -> action` — on every SUBSCRIBE/PUBLISH. We grant the topic
  // to BOTH members when a friendship forms and revoke it when it ends, so
  // authorization is live: unfriending blocks the next pub/sub immediately
  // (already-open subscriptions must additionally be kicked via the EMQX API).
  //
  // The topic name is derivable by anyone who knows both public keys, so security
  // rests ENTIRELY on this ACL — never on topic-name secrecy.

  /** Conversation topic between two public keys. */
  mqttTopicFor(pk1: string, pk2: string): string {
    return `c/${friendshipHash(pk1, pk2)}`;
  },

  /** A user's own presence + inbox topics. Presence: owner publishes (retained +
   *  LWT), friends subscribe. Inbox: owner subscribes (offline wake target). */
  presenceTopic(pk: string): string { return `u/${pk}/presence`; },
  inboxTopic(pk: string): string { return `u/${pk}/inbox`; },

  /** Grant a pk the topics it owns: publish on its presence, all on its inbox.
   *  Idempotent; call on user creation and (harmlessly) on each token mint. */
  async grantSelfTopics(pk: string): Promise<void> {
    await redis.hset(`mqtt_acl:${pk}`, this.presenceTopic(pk), 'publish', this.inboxTopic(pk), 'all');
  },

  /** Grant both members everything they need for a friendship: pub/sub on the
   *  shared conversation topic and subscribe on each other's presence. Also
   *  records the topic's members so push-bridge can resolve recipients.
   *  Idempotent. */
  async grantFriendTopic(pkA: string, pkB: string): Promise<void> {
    const hash = friendshipHash(pkA, pkB);
    const convo = `c/${hash}`;
    const pipeline = redis.pipeline();
    pipeline.hset(`mqtt_acl:${pkA}`, convo, 'all', this.presenceTopic(pkB), 'subscribe');
    pipeline.hset(`mqtt_acl:${pkB}`, convo, 'all', this.presenceTopic(pkA), 'subscribe');
    pipeline.sadd(`hashmembers:${hash}`, pkA, pkB);
    await pipeline.exec();
  },

  /** Revoke both members' friendship topics (conversation + each other's
   *  presence) and forget the membership. Idempotent. Callers should ALSO kick
   *  any live subscription via the EMQX API — the Redis edit only affects the
   *  NEXT authorization check, not an already-open subscription. */
  async revokeFriendTopic(pkA: string, pkB: string): Promise<void> {
    const hash = friendshipHash(pkA, pkB);
    const convo = `c/${hash}`;
    const pipeline = redis.pipeline();
    pipeline.hdel(`mqtt_acl:${pkA}`, convo, this.presenceTopic(pkB));
    pipeline.hdel(`mqtt_acl:${pkB}`, convo, this.presenceTopic(pkA));
    pipeline.del(`hashmembers:${hash}`);
    await pipeline.exec();
  },

  /** The two public keys that share a conversation hash (for push-bridge). */
  async getHashMembers(hash: string): Promise<string[]> {
    return await redis.smembers(`hashmembers:${hash}`);
  },

  /** All topics a pk may access (for backfill/debugging). */
  async getAclTopics(pk: string): Promise<string[]> {
    return await redis.hkeys(`mqtt_acl:${pk}`);
  },

  // ============================================================
  // 7. MQTT AUTHENTICATION — opaque connect token (password)
  // ============================================================
  //
  // No JWT. The auth server, after the HQC-KEM handshake proves pk ownership,
  // mints a random 32-byte token, stores only its SHA-256 in `mqtt_auth:{pk}`
  // with a ~5m TTL, and returns the raw token to the client. The client presents
  // it as the MQTT CONNECT password; EMQX's authn hook verifies it (below) and
  // is handed the token's `expire_at` so EMQX disconnects the client at expiry —
  // expiration-based rotation. Grant = mintMqttToken; revoke = revokeMqttAuth.

  /** Seconds a freshly-minted MQTT token stays valid before refresh is required. */
  MQTT_TOKEN_TTL_SECONDS,

  /** Mint (and store the hash of) a fresh opaque MQTT connect token for `pk`.
   *  Returns the RAW token — the only time it is ever available. */
  async mintMqttToken(pk: string, ttlSeconds = MQTT_TOKEN_TTL_SECONDS): Promise<string> {
    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const key = `mqtt_auth:${pk}`;
    const pipeline = redis.pipeline();
    pipeline.hset(key, { token_hash: tokenHash, exp: Date.now() + ttlSeconds * 1000 });
    pipeline.expire(key, ttlSeconds);
    await pipeline.exec();
    return token;
  },

  /** Verify a presented token against the stored hash (constant-time) WITHOUT
   *  consuming it — the token is reusable across reconnects until it expires.
   *  Returns whether it is valid and, if so, its absolute `expireAt` (unix
   *  seconds) so the auth hook can tell EMQX when to force a re-auth. Revocation
   *  is immediate via revokeMqttAuth (DEL), and TTL bounds a stale token. */
  async verifyMqttToken(pk: string, token: string): Promise<{ ok: boolean; expireAt: number }> {
    const key = `mqtt_auth:${pk}`;
    const stored = await redis.hget(key, 'token_hash');
    if (!stored) return { ok: false, expireAt: 0 };
    const a = Buffer.from(crypto.createHash('sha256').update(token).digest('hex'));
    const b = Buffer.from(stored);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return { ok: false, expireAt: 0 };
    const ttl = await redis.ttl(key);
    const expireAt = ttl > 0 ? Math.floor(Date.now() / 1000) + ttl : 0;
    return { ok: true, expireAt };
  },

  /** Revoke a pk's current MQTT token immediately (account deletion / forced
   *  logout). The next reconnect fails until a new token is minted; to drop an
   *  already-open connection before its token expires, ALSO kick it via the EMQX
   *  API (the "server can revoke" half of grant/revoke). */
  async revokeMqttAuth(pk: string): Promise<void> {
    await redis.del(`mqtt_auth:${pk}`);
  },

  /** Single-use nonce guard for a CONNECT. Returns true the FIRST time a nonce is
   *  seen (and reserves it for `ttlSeconds`), false on any replay. */
  async useNonce(nonce: string, ttlSeconds = MQTT_TOKEN_TTL_SECONDS): Promise<boolean> {
    const ok = await redis.set(`mqttnonce:${nonce}`, '1', 'EX', ttlSeconds, 'NX');
    return ok === 'OK';
  },

  // ============================================================
  // 8. AUTH HANDSHAKE + REST SESSION (used by the auth server)
  // ============================================================
  //
  // The HQC-KEM handshake proves a client owns its public key: the auth server
  // encapsulates to the pk and stores the expected proof under `chal:{pk}`; the
  // client decapsulates, returns the proof, and the server compares + consumes
  // it. On success it issues a multi-use REST session bearer (app-api auth +
  // token refresh) alongside the one-time MQTT connect token.

  /** Store the expected KEM proof for an open challenge (hex). */
  async startAuthChallenge(pk: string, proofHex: string, ttlSeconds = AUTH_CHALLENGE_TTL_SECONDS): Promise<void> {
    await redis.set(`chal:${pk}`, proofHex, 'EX', ttlSeconds);
  },

  /** Atomically read AND delete the open challenge proof for `pk` (so it can't be
   *  replayed). Returns the stored proof hex, or null if none. The caller does a
   *  constant-time compare against the client's solution. */
  async takeAuthChallenge(pk: string): Promise<string | null> {
    const script =
      "local v = redis.call('GET', KEYS[1]) if v then redis.call('DEL', KEYS[1]) end return v";
    return (await redis.eval(script, 1, `chal:${pk}`)) as string | null;
  },

  /** Mint a multi-use REST session bearer for `pk`. Returns the raw token. */
  async mintSessionToken(pk: string, ttlSeconds = REST_SESSION_TTL_SECONDS): Promise<string> {
    const token = crypto.randomBytes(32).toString('hex');
    await redis.set(`session:${token}`, pk, 'EX', ttlSeconds);
    return token;
  },

  /** Resolve a REST session bearer to its pk (or null if unknown/expired). */
  async resolveSessionToken(token: string): Promise<string | null> {
    if (!token) return null;
    return await redis.get(`session:${token}`);
  },

  /** Revoke a REST session bearer (logout / account deletion). */
  async revokeSessionToken(token: string): Promise<void> {
    await redis.del(`session:${token}`);
  },

  disconnect() { redis.disconnect(); }
};

// Wrap every DB method so its wall-clock time is recorded (see lib/metrics.ts).
// Only async methods (the ones that hit Redis) are timed; sync helpers and plain
// value members pass straight through. `this` is bound to the raw impl so a
// method that calls a sibling (e.g. resolveToPk → getPkByUsername) records only
// the top-level operation, not a double-counted nested one.
function instrument<T extends object>(impl: T): T {
  return new Proxy(impl, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver);
      if (typeof value !== 'function') return value;
      const op = String(prop);
      return (...args: unknown[]) => {
        const start = performance.now();
        let out: unknown;
        try {
          out = (value as (...a: unknown[]) => unknown).apply(target, args);
        } catch (e) {
          queryMetrics.record(op, performance.now() - start, false);
          throw e;
        }
        // Only time genuine promises; sync helpers keep their return value.
        if (out && typeof (out as any).then === 'function') {
          return (out as Promise<unknown>).then(
            (r) => {
              queryMetrics.record(op, performance.now() - start, true);
              return r;
            },
            (e) => {
              queryMetrics.record(op, performance.now() - start, false);
              throw e;
            }
          );
        }
        return out;
      };
    },
  });
}

export const DB = instrument(DBImpl);