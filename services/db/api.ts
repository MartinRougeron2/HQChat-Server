import Redis from 'ioredis';
import { friendshipHash, blindedPk } from '../../lib/crypto-utils';
require('dotenv').config();

// Use REDIS_URL when provided (production, with password); fall back to a
// default localhost connection for local development.
//
// lazyConnect: don't open a socket until the first command is issued. Importing
// this module (e.g. from a unit test with no Redis running) then does NOT dial
// Redis — which avoids ioredis' "Unhandled error event" reconnect spam and an
// open handle that keeps the test process alive. The server/bot issue commands,
// which connect on demand.
const redisOptions = { lazyConnect: true } as const;
const redis = process.env.REDIS_URL
  ? new Redis(process.env.REDIS_URL, redisOptions)
  : new Redis(redisOptions);

// Attach an error listener so a connection problem is logged as one line rather
// than surfacing as Node's noisy "Unhandled error event" (which only fires when
// no 'error' listener is registered). With lazyConnect this stays silent in
// tests that never touch Redis.
redis.on('error', (err) => console.error(`[redis] ${err.message}`));

const usernamesBlacklist = new Set([
  'admin', 'administrator', 'root', 'system', 'support', 'help', 'contact',
  'info', 'security', 'test', 'tester', 'bot', 'moderator', 'mod',
  'staff', 'team', 'owner', 'founder',
  // The helper bot's handle — the server auto-friends it to every user, so it
  // must not be reclaimable by a normal account (would hijack that routing).
  'helper', 'dissqus'
]);

export const DB = {
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
      throw new Error("This username is not allowed.");
    }
    // Who currently owns this name (if anyone)?
    const currentOwner = await this.getPkByUsername(newUsername);

    // Idempotent: re-setting the name you already own is a no-op success
    // (previously this threw "Username taken." against your own pk).
    if (currentOwner === pk) return;

    // A name owned by a *different* pk may NOT be transferred — blindly handing
    // it over let any authenticated user take over (impersonate) another user or
    // the helper bot (H3). The only exception is an explicitly allowlisted key:
    // the helper bot legitimately needs to reclaim its handle after a seed/keypair
    // regeneration. Everything else is refused.
    if (currentOwner && currentOwner !== pk) {
      const botKeys = (process.env.BOT_PUBLIC_KEY || '')
        .split(',').map((s) => s.trim()).filter(Boolean);
      if (!botKeys.includes(pk)) {
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

    // Tear down each friendship from BOTH sides (set link + blind hash).
    for (const friendPk of friendPks) {
      pipeline.srem(`friends:${friendPk}`, pk);
      pipeline.del(`friendship:${friendshipHash(pk, friendPk)}`);
    }

    // Drop everything keyed by this pk.
    pipeline.del(`friends:${pk}`);
    pipeline.del(`invites:${pk}`);
    pipeline.del(`pending:${pk}`);
    pipeline.del(`push:${pk}`);
    pipeline.del(`user:${pk}`);
    // Subscription/tier is stored under the blinded pk.
    pipeline.del(`user:${blindedPk(pk)}`);
    pipeline.del(`storekit:${blindedPk(pk)}`);

    await pipeline.exec();
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

  disconnect() { redis.disconnect(); }
};