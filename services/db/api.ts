import Redis from 'ioredis';
import { friendshipHash } from '../../lib/crypto-utils';
require('dotenv').config();

// Use REDIS_URL when provided (production, with password); fall back to a
// default localhost connection for local development.
const redis = process.env.REDIS_URL ? new Redis(process.env.REDIS_URL) : new Redis();

const usernamesBlacklist = new Set([
  'admin', 'administrator', 'root', 'system', 'support', 'help', 'contact',
  'info', 'security', 'test', 'tester', 'bot', 'moderator', 'mod',
  'staff', 'team', 'owner', 'founder'
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

  async getAllUsernames(): Promise<string[]> {
    return await redis.smembers('usernames:taken');
  },

  /**
   * Optional: Retrieves a directory of users (Username + PK)
   * Useful for a "User Discovery" feature.
   */
  async getUserDirectory(): Promise<{ username: string, pk: string }[]> {
    const usernames = await this.getAllUsernames();
    if (usernames.length === 0) return [];

    const pipeline = redis.pipeline();
    usernames.forEach(name => pipeline.get(`username:${name}`));
    const pks = await pipeline.exec();

    return usernames.map((name, i) => ({
      username: name,
      pk: (pks?.[i]?.[1] as string) || 'unknown'
    }));
  },

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

    // Reclaim: if a *different* pk holds the name, transfer it to the requester.
    // The origin is trusted (testing), so this lets a client whose identity
    // changed — notably the helper bot after its seed/keypair was regenerated —
    // take its name back instead of being stuck in a "Username taken." loop.
    if (currentOwner && currentOwner !== pk) {
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