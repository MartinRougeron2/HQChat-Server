import { logger } from '../../lib/logger';
import * as crypto from 'crypto';
import { friendshipHash } from '../../lib/crypto-utils';
import { queryMetrics } from '../../lib/metrics';
import { performance } from 'perf_hooks';
import { q, one, tx, disconnect as pgDisconnect } from './pg';
require('dotenv').config();

// The whole backing store is Postgres — see docs/architecture/postgres-migration.md
// for why, and services/db/migrations/ for the schema. Two properties of that
// move show up all through this file:
//
//   - Anything that used to need a Lua script or a pipeline pretending to be
//     atomic is now a constraint, a single statement, or an explicit
//     transaction. Check-then-set races (username claim, seat cap, invite
//     accept) are gone rather than narrowed.
//   - TTLs are `expires_at` columns. Every read filters on them; sweepExpired()
//     in pg.ts reclaims the space, called on an interval from ops/broker-watch.
//
// MQTT connect token lifetime.
//
// This used to be 5 minutes, and the reason was revocation: with no way to end a
// live session, expiry WAS the revocation mechanism, so it had to be short. The
// cost was that every connected client was disconnected and made to reconnect
// twelve times an hour whether or not it sent anything — a TLS handshake, an
// authn hook call, a store read and a full re-subscribe each time, for every
// client, forever (LAT-1).
//
// `lib/emqx.ts` can now kick a session and drop a single subscription on demand,
// so revocation no longer waits for a clock. The TTL goes back to meaning what a
// credential lifetime should mean: a bound on how long a STOLEN token is useful,
// not a polling interval. Twelve hours keeps a leaked token from being
// indefinite while making the disconnect a daily event rather than a constant one.
const MQTT_TOKEN_TTL_SECONDS = 12 * 60 * 60;

// REST bearer session (app-api + /auth/refresh). SLIDING: every use extends it,
// up to an absolute cap.
//
// Fixed at one hour, this quietly cost a biometric prompt every hour of use. A
// client whose MQTT token expired called /auth/refresh with its session; once the
// session itself lapsed, that 401'd and the app fell back to a full KEM
// handshake, which needs the private key, which prompts. An idle timeout is what
// was wanted; a hard cap on an ACTIVE session was not.
const REST_SESSION_TTL_SECONDS = 60 * 60;
// However long it stays active, a session cannot outlive this. A stolen bearer
// that is used continuously would otherwise never expire.
const REST_SESSION_MAX_AGE_SECONDS = 30 * 24 * 60 * 60;

// Don't rewrite `expires_at` on every authenticated request. Resolving a session
// is the single hottest operation in the system and the old implementation made
// it a WRITE — one `EXPIRE` per request, per user, forever. Sliding only once
// the session is within this much of lapsing keeps the behaviour identical from
// the client's side (it never sees a session die while in use) and turns almost
// every resolve into a pure read.
const SESSION_SLIDE_AFTER_SECONDS = 5 * 60;

// How long an auth challenge (the KEM proof the client must return) stays open.
const AUTH_CHALLENGE_TTL_SECONDS = 60;

/**
 * Which door minted a REST session. `premium` is granted only by
 * /auth/paid/verify against a claimed subscription; `free` is what the open
 * door hands out. It is STORED in the session rather than recomputed per
 * request, so a route reads one column instead of re-deciding an entitlement -
 * which is only honest because revocation acts (revokeAllSessions) instead of
 * waiting for a TTL.
 */
export type SessionScope = 'free' | 'premium';

export interface SessionInfo {
  pk: string;
  scope: SessionScope;
}

const usernamesBlacklist = new Set([
  'admin', 'administrator', 'root', 'system', 'support', 'help', 'contact',
  'info', 'security', 'test', 'tester', 'bot', 'moderator', 'mod',
  'staff', 'team', 'owner', 'founder',
  // The helper bot's handle — the server auto-friends it to every user, so it
  // must not be reclaimable by a normal account (would hijack that routing).
  'helper', 'dissqus'
]);

/** A session bearer is stored by its HASH, never in the clear. `session:{token}`
 *  used the token itself as the key, so anyone who could read the store held
 *  every live bearer in it. */
function tokenHash(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/** The friendship pair, normalised. Must sort exactly the way friendshipHash
 *  does (JS default lexicographic), which is also why the CHECK constraint in
 *  001_schema.sql carries COLLATE "C". */
function pair(pk1: string, pk2: string): [string, string] {
  const [lo, hi] = [pk1, pk2].sort();
  return [lo!, hi!];
}

/** Seconds → a Postgres interval parameter. */
const secs = (n: number) => `${Math.max(0, Math.floor(n))} seconds`;

const DBImpl = {
  // ============================================================
  // 1. IDENTITY & USER MANAGEMENT
  // ============================================================

  async createUser(pk: string, username: string) {
    // One statement, and the UNIQUE index decides. The Redis version read
    // `usernames:taken`, then wrote a pipeline — two clients could both pass the
    // read and both write, and the loser silently overwrote the winner's binding.
    try {
      await q(
        `INSERT INTO users (pk, username, created_at, tier)
         VALUES ($1, $2, now(), 'free')`,
        [pk, username]
      );
    } catch (e) {
      const code = (e as { code?: string }).code;
      if (code === '23505') {
        // 23505 is unique_violation; which constraint tripped says which of the
        // two callers' errors to raise.
        const detail = String((e as { constraint?: string }).constraint || '');
        if (detail.includes('username')) throw new Error(`Username '${username}' is already taken.`);
        throw new Error(`Public Key already registered.`);
      }
      throw e;
    }
  },

  async getUser(pk: string) {
    const row = await one<{ pk: string; username: string | null; created_at: Date; tier: string }>(
      `SELECT pk, username, created_at, tier FROM users WHERE pk = $1`,
      [pk]
    );
    // `{}` for an unknown key, as HGETALL gave.
    if (!row) return {} as Record<string, string>;
    return {
      pk: row.pk,
      username: row.username || '',
      created_at: String(row.created_at.getTime()),
      tier: row.tier,
    } as Record<string, string>;
  },

  async getUsername(pk: string): Promise<string | null> {
    const row = await one<{ username: string | null }>(
      `SELECT username FROM users WHERE pk = $1`, [pk]
    );
    return row?.username ?? null;
  },

  async getPkByUsername(username: string): Promise<string | null> {
    // `username` is citext, so this is case-insensitive — which is the point.
    // `username:{u}` was a case-SENSITIVE key while the reserved-handle list
    // lowercased, so `Helper` was claimable while `helper` was not.
    const row = await one<{ pk: string }>(`SELECT pk FROM users WHERE username = $1`, [username]);
    return row?.pk ?? null;
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
      // normal users. A trusted service identity that self-registered in
      // `admission_exempt` — i.e. the helper bot — is allowed to claim its
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
    // self-registered `admission_exempt` row it writes on startup — so this needs
    // no manual, stale-prone BOT_PUBLIC_KEY list. The static env is still honoured
    // as an optional override. Everything else is refused.
    if (currentOwner && currentOwner !== pk) {
      const botKeys = (process.env.BOT_PUBLIC_KEY || '')
        .split(',').map((s) => s.trim()).filter(Boolean);
      const trusted = botKeys.includes(pk) || (await this.isAdmissionExempt(pk));
      if (!trusted) {
        throw new Error('USERNAME_TAKEN');
      }
    }

    // Releasing the old owner's name and taking it must not be two round trips:
    // between them the name belongs to nobody, and a third caller could claim it.
    await tx(async (c) => {
      if (currentOwner && currentOwner !== pk) {
        await c.query(`UPDATE users SET username = NULL WHERE pk = $1`, [currentOwner]);
      }
      // Upsert rather than update: `hset user:{pk} username` created the record
      // if it did not exist, and at least one caller relies on that.
      await c.query(
        `INSERT INTO users (pk, username) VALUES ($1, $2)
         ON CONFLICT (pk) DO UPDATE SET username = EXCLUDED.username`,
        [pk, newUsername]
      );
    });
  },

  /**
   * Permanently delete a user and everything we store about them — used by the
   * in-app "Delete Account" flow (App Store Guideline 5.1.1(v)). Removes the
   * identity record, frees the username, tears down both sides of every
   * friendship (and the MQTT grants that went with them), drops invites in both
   * directions, the push token, and every live session. It also RELEASES the
   * subscription claim: a deleted account must give its device slot back, or a
   * user who deletes and re-creates burns through the cap on their own
   * subscription. The subscription itself survives - it belongs to the payer,
   * not to this key. End-to-end message content lives only on devices, so this
   * purges the user's entire server-side footprint.
   *
   * One transaction. The Redis version could not be: it ran a pipeline, then
   * revoked sessions separately (because the session keys were only reachable
   * through an index it had to delete last), and then SCANned every `invites:*`
   * key in the database — on a user-facing request — because invites this user
   * SENT lived in other people's inboxes with nothing pointing back. An index on
   * `invites.from_pk` makes that last part a single statement.
   */
  async deleteUser(pk: string): Promise<void> {
    await tx(async (c) => {
      // Each friend also holds ACL rows naming this user: the shared
      // conversation topic and this user's presence topic. Without removing
      // them the deleted account's grants survive, and every friend keeps a
      // dangling entry for a pk that no longer exists.
      const { rows: peers } = await c.query<{ peer: string; hash: string }>(
        `SELECT CASE WHEN pk_lo = $1 THEN pk_hi ELSE pk_lo END AS peer, hash
           FROM friendships WHERE pk_lo = $1 OR pk_hi = $1`,
        [pk]
      );
      for (const { peer, hash } of peers) {
        await c.query(`DELETE FROM mqtt_acl WHERE pk = $1 AND topic = ANY($2::text[])`, [
          peer,
          [`c/${hash}`, this.presenceTopic(pk)],
        ]);
      }

      await c.query(`DELETE FROM friendships WHERE pk_lo = $1 OR pk_hi = $1`, [pk]);
      await c.query(`DELETE FROM invites WHERE to_pk = $1 OR from_pk = $1`, [pk]);
      await c.query(`DELETE FROM mqtt_acl WHERE pk = $1`, [pk]);
      // MQTT connect credential + every live REST bearer.
      await c.query(`DELETE FROM mqtt_tokens WHERE pk = $1`, [pk]);
      await c.query(`DELETE FROM sessions WHERE pk = $1`, [pk]);
      await c.query(`DELETE FROM push_tokens WHERE pk = $1`, [pk]);
      // Release the subscription claim (and its device slot). The subscription
      // record itself is deliberately untouched: it belongs to whoever paid, not
      // to the identity being deleted.
      await c.query(`DELETE FROM subscription_claims WHERE pk = $1`, [pk]);
      // Last: the identity, which also frees the username.
      await c.query(`DELETE FROM users WHERE pk = $1`, [pk]);
    });
  },

  // ============================================================
  // 2. SUBSCRIPTION CLAIM (web purchase -> device key)
  // ============================================================
  //
  // A subscription is bought on the website and claimed from the app, and the
  // two are joined by an email address this server never stores. Stripe holds
  // the address; here it exists only as H = sha256(lowercased email), so a dump
  // of this database says which subscriptions exist but not whose.
  //
  //   subscriptions           state (waiting|active|cancelled) + Stripe customer
  //   subscription_customers  reverse index, so a webhook carrying only a
  //                           customer id resolves without calling Stripe
  //   subscription_claims     the public keys that have claimed it (capped) —
  //                           and, read the other way, the hot path on every
  //                           paid-door auth
  //   otp                     the pending code's HASH + its attempt count
  //
  // Devices are recorded by RAW public key, not a blinded one. Blinding existed
  // to keep the crypto identity away from Stripe, and nothing here goes to
  // Stripe; meanwhile revoking a lapsed subscriber means editing `mqtt_acl` and
  // kicking `{pk}` off the broker, neither of which a hash can address.
  //
  // Entitlement lives in the claim rather than on the user row: `users`
  // describes an identity, and an identity is not the thing that was paid for.

  /** Record or update a subscription's state under its email hash. `waiting` is
   *  written when checkout completes and becomes `active` once Stripe confirms;
   *  only an `active` one can be claimed. */
  async setSubscription(
    emailHash: string,
    state: 'waiting' | 'active' | 'cancelled',
    customerId?: string
  ): Promise<void> {
    await tx(async (c) => {
      await c.query(
        `INSERT INTO subscriptions (email_hash, state, customer_id, updated_at)
         VALUES ($1, $2, $3, now())
         ON CONFLICT (email_hash) DO UPDATE SET
           state = EXCLUDED.state,
           -- A state-only update (a customer.subscription.* webhook) carries
           -- no customer id; it must not erase the one already recorded.
           customer_id = COALESCE(EXCLUDED.customer_id, subscriptions.customer_id),
           updated_at = now()`,
        [emailHash, state, customerId ?? null]
      );
      if (customerId) {
        await c.query(
          `INSERT INTO subscription_customers (customer_id, email_hash) VALUES ($1, $2)
           ON CONFLICT (customer_id) DO UPDATE SET email_hash = EXCLUDED.email_hash`,
          [customerId, emailHash]
        );
      }
    });
  },

  async getSubscription(emailHash: string): Promise<{ state: string; customer?: string } | null> {
    const row = await one<{ state: string; customer_id: string | null }>(
      `SELECT state, customer_id FROM subscriptions WHERE email_hash = $1`,
      [emailHash]
    );
    if (!row) return null;
    return { state: row.state, ...(row.customer_id ? { customer: row.customer_id } : {}) };
  },

  /** Resolve a Stripe customer back to the email hash everything else is keyed
   *  by. Written at checkout so a `customer.subscription.*` event - which
   *  carries a customer id and nothing else useful - costs no Stripe API call. */
  async emailHashForCustomer(customerId: string): Promise<string | null> {
    const row = await one<{ email_hash: string }>(
      `SELECT email_hash FROM subscription_customers WHERE customer_id = $1`,
      [customerId]
    );
    return row?.email_hash ?? null;
  },

  /** Bind a device (public key) to a subscription, up to `cap` devices.
   *  Re-claiming a device already bound is a no-op that does NOT spend a slot,
   *  so a repeated OTP does not lock a user out of their own subscription. */
  async addClaimedDevice(emailHash: string, pk: string, cap: number): Promise<'ok' | 'cap'> {
    return await tx(async (c) => {
      // Count-then-insert lets two devices race past the cap, which is why this
      // was a Lua script. Locking the subscription row is the same guarantee
      // without the script: concurrent claims against ONE subscription
      // serialise here, and claims against different ones do not block at all.
      await c.query(`SELECT 1 FROM subscriptions WHERE email_hash = $1 FOR UPDATE`, [emailHash]);

      const already = await c.query(
        `SELECT 1 FROM subscription_claims WHERE pk = $1 AND email_hash = $2`,
        [pk, emailHash]
      );
      if (already.rowCount) return 'ok';

      const { rows } = await c.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM subscription_claims WHERE email_hash = $1`,
        [emailHash]
      );
      if ((rows[0]?.n ?? 0) >= cap) return 'cap';

      // ON CONFLICT moves a key that was bound to a DIFFERENT subscription,
      // which also releases the slot it held there — `SET claim:{pk} H` moved
      // the forward pointer but left the old `sub:pks` set naming a device that
      // had gone elsewhere.
      await c.query(
        `INSERT INTO subscription_claims (pk, email_hash, claimed_at) VALUES ($1, $2, now())
         ON CONFLICT (pk) DO UPDATE SET email_hash = EXCLUDED.email_hash, claimed_at = now()`,
        [pk, emailHash]
      );
      return 'ok';
    });
  },

  /** The subscription a device is bound to, or null. Read on every paid-door
   *  `/auth/paid/init`, which is why it is one primary-key lookup. */
  async emailHashForClaim(pk: string): Promise<string | null> {
    const row = await one<{ email_hash: string }>(
      `SELECT email_hash FROM subscription_claims WHERE pk = $1`,
      [pk]
    );
    return row?.email_hash ?? null;
  },

  async claimedDevices(emailHash: string): Promise<string[]> {
    const res = await q<{ pk: string }>(
      `SELECT pk FROM subscription_claims WHERE email_hash = $1 ORDER BY claimed_at, pk`,
      [emailHash]
    );
    return res.rows.map((r) => r.pk);
  },

  /** Release every device bound to a subscription. Returns the public keys that
   *  were released, so the caller can also end whatever they still have open. */
  async forgetClaimedDevices(emailHash: string): Promise<string[]> {
    const res = await q<{ pk: string }>(
      `DELETE FROM subscription_claims WHERE email_hash = $1 RETURNING pk`,
      [emailHash]
    );
    return res.rows.map((r) => r.pk);
  },

  /** Store the HASH of a pending OTP. One live code per address: a resend
   *  replaces the previous one rather than leaving two valid at once, and
   *  resets the attempt count with it. */
  async putOtp(emailHash: string, codeHash: string, ttlSeconds: number): Promise<void> {
    await q(
      `INSERT INTO otp (email_hash, code_hash, attempts, expires_at)
       VALUES ($1, $2, 0, now() + $3::interval)
       ON CONFLICT (email_hash) DO UPDATE SET
         code_hash = EXCLUDED.code_hash, attempts = 0, expires_at = EXCLUDED.expires_at`,
      [emailHash, codeHash, secs(ttlSeconds)]
    );
  },

  /** Read the pending code hash and count this as an attempt, in one statement.
   *  Null when no code is live. Counting BEFORE the comparison is what makes
   *  brute force finite - a caller that increments only on failure can be
   *  starved by a client that disconnects mid-request. */
  async takeOtpAttempt(emailHash: string): Promise<{ codeHash: string; attempts: number } | null> {
    const row = await one<{ code_hash: string; attempts: number }>(
      `UPDATE otp SET attempts = attempts + 1
        WHERE email_hash = $1 AND expires_at > now()
        RETURNING code_hash, attempts`,
      [emailHash]
    );
    if (!row) return null;
    return { codeHash: row.code_hash, attempts: row.attempts };
  },

  async clearOtp(emailHash: string): Promise<void> {
    await q(`DELETE FROM otp WHERE email_hash = $1`, [emailHash]);
  },

  /**
   * Self-registered admission exemptions. The helper bot writes its own pk here
   * on startup (see bot/bot.ts) so it's admitted under any policy without an
   * operator hand-copying its key into EXEMPT_PUBLIC_KEYS — which would go stale
   * whenever the bot's seed/identity changes. Being exempt only waives the
   * payment/allowlist gate; the caller still had to pass HQC auth, so only the
   * holder of that private key benefits.
   */
  async addAdmissionExempt(pk: string) {
    await q(
      `INSERT INTO admission_exempt (pk) VALUES ($1) ON CONFLICT DO NOTHING`,
      [pk.toLowerCase()]
    );
  },

  /** Whether this pk self-registered an admission exemption. */
  async isAdmissionExempt(pk: string): Promise<boolean> {
    const row = await one(`SELECT 1 FROM admission_exempt WHERE pk = $1`, [pk.toLowerCase()]);
    return row !== null;
  },

  /** Withdraw an exemption. The bot re-registers its own on every startup, so
   *  this is for an operator retiring a key - or a test cleaning up after one. */
  async removeAdmissionExempt(pk: string): Promise<void> {
    await q(`DELETE FROM admission_exempt WHERE pk = $1`, [pk.toLowerCase()]);
  },

  // ============================================================
  // 3. INVITES & SOCIAL
  // ============================================================

  async invite(fromPk: string, toIdentifier: string) {
    const toPk = await this.resolveToPk(toIdentifier);
    if (!toPk) throw new Error("User not found");
    if (fromPk === toPk) throw new Error("Self-invite not allowed");
    if (!(await one(`SELECT 1 FROM users WHERE pk = $1`, [toPk]))) throw new Error("User not found");

    if (await this.areFriends(fromPk, toPk)) throw new Error("Already friends");

    // We store the invite in the recipient's "inbox"
    await q(
      `INSERT INTO invites (to_pk, from_pk, created_at) VALUES ($1, $2, now())
       ON CONFLICT (to_pk, from_pk) DO UPDATE SET created_at = now()`,
      [toPk, fromPk]
    );
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
    const res = await q(`DELETE FROM invites WHERE to_pk = $1 AND from_pk = $2`, [toPk, fromPk]);
    return (res.rowCount ?? 0) > 0;
  },

  /** Decline an invite addressed to this user. */
  async declineInvite(myPk: string, fromIdentifier: string): Promise<boolean> {
    const fromPk = await this.resolveToPk(fromIdentifier);
    if (!fromPk) return false;
    const res = await q(`DELETE FROM invites WHERE to_pk = $1 AND from_pk = $2`, [myPk, fromPk]);
    return (res.rowCount ?? 0) > 0;
  },

  async getMyInvites(myPk: string) {
    // One join, where the Redis version did an HGETALL and then a round trip per
    // sender to look up a username.
    const res = await q<{ pk: string; username: string | null; sent_at: string }>(
      `SELECT i.from_pk AS pk,
              u.username::text AS username,
              (EXTRACT(epoch FROM i.created_at) * 1000)::bigint::text AS sent_at
         FROM invites i
         LEFT JOIN users u ON u.pk = i.from_pk
        WHERE i.to_pk = $1
        ORDER BY i.created_at`,
      [myPk]
    );
    return res.rows.map((r) => ({
      pk: r.pk,
      username: r.username || "Unknown",
      sent_at: Number(r.sent_at),
    }));
  },

  /**
   * Refined to support the server's need to notify the peer.
   * Returns true if the acceptance was successful.
   *
   * Consuming the invite and creating the friendship are one transaction, so
   * two simultaneous accepts cannot both succeed — the Redis version checked
   * HEXISTS and then wrote, with a window in between.
   */
  async acceptInvite(fromIdentifier: string, myPk: string): Promise<boolean> {
    const fromPk = await this.resolveToPk(fromIdentifier);
    if (!fromPk) return false;

    return await tx(async (c) => {
      const taken = await c.query(`DELETE FROM invites WHERE to_pk = $1 AND from_pk = $2`, [
        myPk, fromPk,
      ]);
      if (!taken.rowCount) return false;

      // One row IS the friendship. Accepting used to write only the friend sets
      // and not the blind hash, so `checkFriendship` — which reads the hash —
      // answered false for a friendship the friend LIST showed. There is nothing
      // left to keep in sync.
      const [lo, hi] = pair(myPk, fromPk);
      await c.query(
        `INSERT INTO friendships (pk_lo, pk_hi, hash) VALUES ($1, $2, $3)
         ON CONFLICT (pk_lo, pk_hi) DO NOTHING`,
        [lo, hi, friendshipHash(myPk, fromPk)]
      );
      return true;
    });
  },

  async getFriendsList(myPk: string) {
    const res = await q<{ pk: string; username: string | null }>(
      `SELECT peer.pk, u.username::text AS username
         FROM friendships f
         CROSS JOIN LATERAL (
           SELECT CASE WHEN f.pk_lo = $1 THEN f.pk_hi ELSE f.pk_lo END AS pk
         ) peer
         LEFT JOIN users u ON u.pk = peer.pk
        WHERE f.pk_lo = $1 OR f.pk_hi = $1`,
      [myPk]
    );
    return res.rows.map((r) => ({ pk: r.pk, username: r.username || 'Anonymous' }));
  },

  /** Just the peers, for the ACL walks below. */
  async friendPks(myPk: string): Promise<string[]> {
    const res = await q<{ pk: string }>(
      `SELECT CASE WHEN pk_lo = $1 THEN pk_hi ELSE pk_lo END AS pk
         FROM friendships WHERE pk_lo = $1 OR pk_hi = $1`,
      [myPk]
    );
    return res.rows.map((r) => r.pk);
  },

  async areFriends(pkA: string, pkB: string): Promise<boolean> {
    const [lo, hi] = pair(pkA, pkB);
    const row = await one(`SELECT 1 FROM friendships WHERE pk_lo = $1 AND pk_hi = $2`, [lo, hi]);
    return row !== null;
  },

  async removeFriend(fromPk: string, toIdentifier: string): Promise<boolean> {
    const toPk = await this.resolveToPk(toIdentifier);
    if (!toPk) return false;

    // Deleting the one row is both directions and the blind hash at once; the
    // "are they actually friends" check is its rowcount.
    const [lo, hi] = pair(fromPk, toPk);
    const res = await q(`DELETE FROM friendships WHERE pk_lo = $1 AND pk_hi = $2`, [lo, hi]);
    return (res.rowCount ?? 0) > 0;
  },

  async createFriendship(pk1: string, pk2: string) {
    const [lo, hi] = pair(pk1, pk2);
    await q(
      `INSERT INTO friendships (pk_lo, pk_hi, hash) VALUES ($1, $2, $3)
       ON CONFLICT (pk_lo, pk_hi) DO NOTHING`,
      [lo, hi, friendshipHash(pk1, pk2)]
    );
  },

  /** Idempotently ensure the friendship exists. It used to heal older
   *  friendships that were stored only as a blind hash with no friend-set link;
   *  one row cannot drift from itself, so this is now exactly
   *  `createFriendship` and is kept only for its callers. */
  async ensureFriendLink(pk1: string, pk2: string) {
    await this.createFriendship(pk1, pk2);
  },

  /**
   * Checks if friendship exists based on blind hash
   */
  async checkFriendship(pk1: string, pk2: string): Promise<boolean> {
    const row = await one(`SELECT 1 FROM friendships WHERE hash = $1`, [
      friendshipHash(pk1, pk2),
    ]);
    return row !== null;
  },

  getFriendshipHash(pk1: string, pk2: string): string {
    return friendshipHash(pk1, pk2);
  },

  // ============================================================
  // 4. PUSH TOKENS
  // ============================================================

  async setPushToken(pk: string, platform: string, token: string) {
    // The client re-registers its APNs token on every app launch
    // (apps/apple/DissQus/AppState.swift), so this is one of the few writes that
    // scales with usage rather than with events. `IS DISTINCT FROM` makes the
    // unchanged case a no-op instead of a new row version to vacuum.
    await q(
      `INSERT INTO push_tokens (pk, platform, token, updated_at) VALUES ($1, $2, $3, now())
       ON CONFLICT (pk) DO UPDATE SET
         platform = EXCLUDED.platform, token = EXCLUDED.token, updated_at = now()
       WHERE push_tokens.token IS DISTINCT FROM EXCLUDED.token
          OR push_tokens.platform IS DISTINCT FROM EXCLUDED.platform`,
      [pk, platform, token]
    );
  },

  async getPushToken(pk: string): Promise<{ platform: string; token: string } | null> {
    const row = await one<{ platform: string; token: string }>(
      `SELECT platform, token FROM push_tokens WHERE pk = $1`, [pk]
    );
    if (!row?.token) return null;
    return { platform: row.platform || "ios", token: row.token };
  },

  // ============================================================
  // 5. MQTT AUTHORIZATION (RLS) — friend-hash topic ACL
  // ============================================================
  //
  // Each conversation is a topic `c/{friendshipHash}`. EMQX's PostgreSQL
  // authorizer reads `mqtt_acl` for the connecting clientid (see
  // infra/deploy/emqx/emqx.conf) — with a 15m cache in front, so this is not a
  // per-message lookup. We grant the topic to BOTH members when a friendship
  // forms and revoke it when it ends, and revocation ALSO acts on the live
  // connection through lib/emqx.ts rather than waiting for the cache.
  //
  // The topic name is derivable by anyone who knows both public keys, so security
  // rests ENTIRELY on this table — never on topic-name secrecy.

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
    await this.grant([
      [pk, this.presenceTopic(pk), 'publish'],
      [pk, this.inboxTopic(pk), 'all'],
    ]);
  },

  /** Grant both members everything they need for a friendship: pub/sub on the
   *  shared conversation topic and subscribe on each other's presence.
   *  Idempotent. (The topic's membership no longer needs recording separately —
   *  `friendships.hash` already answers it; see getHashMembers.) */
  async grantFriendTopic(pkA: string, pkB: string): Promise<void> {
    const convo = `c/${friendshipHash(pkA, pkB)}`;
    await this.grant([
      [pkA, convo, 'all'],
      [pkA, this.presenceTopic(pkB), 'subscribe'],
      [pkB, convo, 'all'],
      [pkB, this.presenceTopic(pkA), 'subscribe'],
    ]);
  },

  /** Write a batch of (pk, topic, action) grants in one statement. */
  async grant(rows: Array<[string, string, string]>): Promise<void> {
    await q(
      `INSERT INTO mqtt_acl (pk, topic, action)
       SELECT * FROM unnest($1::text[], $2::text[], $3::text[])
       ON CONFLICT (pk, topic) DO UPDATE SET action = EXCLUDED.action`,
      [rows.map((r) => r[0]), rows.map((r) => r[1]), rows.map((r) => r[2])]
    );
  },

  /** Revoke both members' friendship topics (conversation + each other's
   *  presence). Idempotent. Callers should ALSO kick any live subscription via
   *  the EMQX API — the row edit only affects the NEXT authorization check that
   *  misses the cache, not an already-open subscription. */
  async revokeFriendTopic(pkA: string, pkB: string): Promise<void> {
    const convo = `c/${friendshipHash(pkA, pkB)}`;
    await q(
      `DELETE FROM mqtt_acl
        WHERE (pk = $1 AND topic = ANY($3::text[]))
           OR (pk = $2 AND topic = ANY($4::text[]))`,
      [pkA, pkB, [convo, this.presenceTopic(pkB)], [convo, this.presenceTopic(pkA)]]
    );
  },

  /** Re-grant every friend topic this pk is entitled to. A lapsed subscription
   *  revokes them - a paywall has to bite on the live session, not only on the
   *  next one - and resubscribing has to put them back. The friend list was
   *  never deleted, so it is the record of what to restore. */
  async regrantAllFriendTopics(pk: string): Promise<number> {
    const friends = await this.friendPks(pk);
    for (const peer of friends) await this.grantFriendTopic(pk, peer);
    return friends.length;
  },

  /** Revoke every friend topic except `keepPk` (the helper bot, which the free
   *  tier keeps). Returns the peers revoked so the caller can ALSO drop their
   *  live subscriptions via the EMQX API. */
  async revokeAllFriendTopics(pk: string, keepPk?: string): Promise<string[]> {
    const friends = (await this.friendPks(pk)).filter((p) => p !== keepPk);
    for (const peer of friends) await this.revokeFriendTopic(pk, peer);
    return friends;
  },

  /** The two public keys that share a conversation hash (for push-bridge).
   *  Answered from the friendship itself — `hashmembers:{h}` was a third copy of
   *  a fact the edge already carried, and one more thing to keep in sync. */
  async getHashMembers(hash: string): Promise<string[]> {
    const row = await one<{ pk_lo: string; pk_hi: string }>(
      `SELECT pk_lo, pk_hi FROM friendships WHERE hash = $1`, [hash]
    );
    return row ? [row.pk_lo, row.pk_hi] : [];
  },

  /** All topics a pk may access (for repair/debugging). */
  async getAclTopics(pk: string): Promise<string[]> {
    const res = await q<{ topic: string }>(`SELECT topic FROM mqtt_acl WHERE pk = $1`, [pk]);
    return res.rows.map((r) => r.topic);
  },

  // ============================================================
  // 6. MQTT AUTHENTICATION — opaque connect token (password)
  // ============================================================
  //
  // No JWT. The auth server, after the HQC-KEM handshake proves pk ownership,
  // mints a random 32-byte token, stores only its SHA-256, and returns the raw
  // token to the client. The client presents it as the MQTT CONNECT password;
  // EMQX's authn hook verifies it and is handed the token's `expire_at` so EMQX
  // disconnects the client at expiry — expiration-based rotation.
  // Grant = mintMqttToken; revoke = revokeMqttAuth.

  /** Seconds a freshly-minted MQTT token stays valid before refresh is required. */
  MQTT_TOKEN_TTL_SECONDS,

  /** Mint (and store the hash of) a fresh opaque MQTT connect token for `pk`.
   *  Returns the RAW token — the only time it is ever available. */
  async mintMqttToken(pk: string, ttlSeconds = MQTT_TOKEN_TTL_SECONDS): Promise<string> {
    const token = crypto.randomBytes(32).toString('hex');
    await q(
      `INSERT INTO mqtt_tokens (pk, token_hash, expires_at)
       VALUES ($1, $2, now() + $3::interval)
       ON CONFLICT (pk) DO UPDATE SET
         token_hash = EXCLUDED.token_hash, expires_at = EXCLUDED.expires_at`,
      [pk, tokenHash(token), secs(ttlSeconds)]
    );
    return token;
  },

  /** Verify a presented token against the stored hash (constant-time) WITHOUT
   *  consuming it — the token is reusable across reconnects until it expires.
   *  Returns whether it is valid and, if so, its absolute `expireAt` (unix
   *  seconds) so the auth hook can tell EMQX when to force a re-auth. Revocation
   *  is immediate via revokeMqttAuth, and the expiry bounds a stale token. */
  async verifyMqttToken(pk: string, token: string): Promise<{ ok: boolean; expireAt: number }> {
    const row = await one<{ token_hash: string; expire_at: string }>(
      `SELECT token_hash, EXTRACT(epoch FROM expires_at)::bigint::text AS expire_at
         FROM mqtt_tokens WHERE pk = $1 AND expires_at > now()`,
      [pk]
    );
    if (!row) return { ok: false, expireAt: 0 };
    const a = Buffer.from(tokenHash(token));
    const b = Buffer.from(row.token_hash);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return { ok: false, expireAt: 0 };
    return { ok: true, expireAt: Number(row.expire_at) };
  },

  /** Revoke a pk's current MQTT token immediately (account deletion / forced
   *  logout). The next reconnect fails until a new token is minted; to drop an
   *  already-open connection before its token expires, ALSO kick it via the EMQX
   *  API (the "server can revoke" half of grant/revoke). */
  async revokeMqttAuth(pk: string): Promise<void> {
    await q(`DELETE FROM mqtt_tokens WHERE pk = $1`, [pk]);
  },

  /** Single-use nonce guard for a CONNECT. Returns true the FIRST time a nonce is
   *  seen (and reserves it for `ttlSeconds`), false on any replay.
   *
   *  `SET NX EX` became an INSERT whose primary key decides — strictly more
   *  correct, because the decision is the write rather than a round trip before
   *  it. The DO UPDATE re-takes a nonce whose reservation has lapsed, which is
   *  what the Redis TTL did by deleting the key. */
  async useNonce(nonce: string, ttlSeconds = MQTT_TOKEN_TTL_SECONDS): Promise<boolean> {
    const res = await q(
      `INSERT INTO mqtt_nonces (nonce, expires_at) VALUES ($1, now() + $2::interval)
       ON CONFLICT (nonce) DO UPDATE SET expires_at = EXCLUDED.expires_at
       WHERE mqtt_nonces.expires_at <= now()
       RETURNING nonce`,
      [nonce, secs(ttlSeconds)]
    );
    return (res.rowCount ?? 0) === 1;
  },

  // ============================================================
  // 7. AUTH HANDSHAKE + REST SESSION (used by the auth server)
  // ============================================================
  //
  // The HQC-KEM handshake proves a client owns its public key: the auth server
  // encapsulates to the pk and stores the expected proof; the client
  // decapsulates, returns the proof, and the server compares + consumes it. On
  // success it issues a multi-use REST session bearer (app-api auth + token
  // refresh) alongside the MQTT connect token.

  /** Store the expected KEM proof for an open challenge (hex). */
  async startAuthChallenge(pk: string, proofHex: string, ttlSeconds = AUTH_CHALLENGE_TTL_SECONDS): Promise<void> {
    await q(
      `INSERT INTO auth_challenges (pk, proof, expires_at)
       VALUES ($1, $2, now() + $3::interval)
       ON CONFLICT (pk) DO UPDATE SET proof = EXCLUDED.proof, expires_at = EXCLUDED.expires_at`,
      [pk, proofHex, secs(ttlSeconds)]
    );
  },

  /** Atomically read AND delete the open challenge proof for `pk` (so it can't be
   *  replayed). Returns the stored proof hex, or null if none. The caller does a
   *  constant-time compare against the client's solution. */
  async takeAuthChallenge(pk: string): Promise<string | null> {
    const row = await one<{ proof: string }>(
      `DELETE FROM auth_challenges WHERE pk = $1 AND expires_at > now() RETURNING proof`,
      [pk]
    );
    return row?.proof ?? null;
  },

  /** Mint a multi-use REST session bearer for `pk` at `scope`. Returns the raw
   *  token — the only time it exists outside the caller. */
  async mintSessionToken(
    pk: string,
    scope: SessionScope = 'free',
    ttlSeconds = REST_SESSION_TTL_SECONDS
  ): Promise<string> {
    const token = crypto.randomBytes(32).toString('hex');
    // `iat` enforces the absolute cap; `expires_at` is the idle timeout. There
    // is no separate per-pk index to maintain — revokeAllSessions is a WHERE
    // clause, so the set of live bearers cannot drift from the bearers.
    await q(
      `INSERT INTO sessions (token_hash, pk, scope, iat, expires_at)
       VALUES ($1, $2, $3, now(), now() + $4::interval)`,
      [tokenHash(token), pk, scope, secs(ttlSeconds)]
    );
    return token;
  },

  /**
   * Resolve a REST session bearer to its pk AND scope, sliding its idle timeout
   * forward. Returns null when unknown, idle-expired, or past the absolute cap.
   *
   * One statement, and usually a pure read: the slide only writes once the
   * session is within SESSION_SLIDE_AFTER_SECONDS of lapsing. Sliding on every
   * request made the hottest path in the system a write, for no behaviour a
   * client can observe.
   */
  async resolveSessionToken(token: string): Promise<SessionInfo | null> {
    if (!token) return null;
    const row = await one<{ pk: string; scope: SessionScope }>(
      `WITH found AS (
         SELECT token_hash, pk, scope, iat
           FROM sessions
          WHERE token_hash = $1 AND expires_at > now()
       ),
       -- Past the absolute cap: refused AND removed, so a bearer that is used
       -- continuously cannot live forever by sliding.
       capped AS (
         DELETE FROM sessions
          WHERE token_hash IN (SELECT token_hash FROM found WHERE iat <= now() - $2::interval)
       ),
       slid AS (
         UPDATE sessions SET expires_at = now() + $3::interval
          WHERE token_hash IN (SELECT token_hash FROM found WHERE iat > now() - $2::interval)
            AND expires_at < now() + $4::interval
       )
       SELECT pk, scope FROM found WHERE iat > now() - $2::interval`,
      [
        tokenHash(token),
        secs(REST_SESSION_MAX_AGE_SECONDS),
        secs(REST_SESSION_TTL_SECONDS),
        secs(REST_SESSION_TTL_SECONDS - SESSION_SLIDE_AFTER_SECONDS),
      ]
    );
    return row ? { pk: row.pk, scope: row.scope } : null;
  },

  /** Revoke a REST session bearer (logout / account deletion). */
  async revokeSessionToken(token: string): Promise<void> {
    if (!token) return;
    await q(`DELETE FROM sessions WHERE token_hash = $1`, [tokenHash(token)]);
  },

  /** End EVERY live REST session for `pk`. This is what makes a cancelled
   *  subscription take effect now instead of whenever the last bearer happens
   *  to lapse - the same reason revocation reaches into EMQX rather than
   *  trusting a token lifetime (see lib/emqx.ts). Returns how many were ended. */
  async revokeAllSessions(pk: string): Promise<number> {
    const res = await q(`DELETE FROM sessions WHERE pk = $1`, [pk]);
    return res.rowCount ?? 0;
  },

  /**
   * Fixed-window counter. Returns the count AFTER incrementing, so a caller can
   * compare it against a limit. One statement; the window is set only on the
   * first hit of each window, so the limit is per-window, not sliding — and a
   * later hit asking for a SHORTER window cannot shrink the one in progress.
   */
  async bumpCounter(key: string, windowSeconds: number): Promise<number> {
    const row = await one<{ n: number }>(
      `INSERT INTO rate_counters (key, n, window_ends_at)
       VALUES ($1, 1, now() + $2::interval)
       ON CONFLICT (key) DO UPDATE SET
         n = CASE WHEN rate_counters.window_ends_at <= now() THEN 1 ELSE rate_counters.n + 1 END,
         window_ends_at = CASE WHEN rate_counters.window_ends_at <= now()
                               THEN now() + $2::interval
                               ELSE rate_counters.window_ends_at END
       RETURNING n`,
      [key, secs(windowSeconds)]
    );
    return row?.n ?? 1;
  },

  /** Remaining seconds in a counter's window (-2 when absent, as Redis TTL
   *  reported it). Tests + ops. */
  async counterTtl(key: string): Promise<number> {
    const row = await one<{ ttl: string }>(
      `SELECT CEIL(EXTRACT(epoch FROM window_ends_at - now()))::bigint::text AS ttl
         FROM rate_counters WHERE key = $1 AND window_ends_at > now()`,
      [key]
    );
    return row ? Number(row.ttl) : -2;
  },

  /** Reset a counter (a success ends a run of failures). */
  async clearCounter(key: string): Promise<void> {
    await q(`DELETE FROM rate_counters WHERE key = $1`, [key]);
  },

  /** Remaining idle seconds on a session (-2 when it is gone). Tests + ops. */
  async sessionTtl(token: string): Promise<number> {
    const row = await one<{ ttl: string }>(
      `SELECT CEIL(EXTRACT(epoch FROM expires_at - now()))::bigint::text AS ttl
         FROM sessions WHERE token_hash = $1 AND expires_at > now()`,
      [tokenHash(token)]
    );
    return row ? Number(row.ttl) : -2;
  },

  /** Mint a session with a chosen issue time. Exists so a test can prove the
   *  absolute cap is enforced without waiting thirty days for it. */
  async mintSessionTokenAt(
    pk: string,
    ttlSeconds: number,
    issuedAtUnix: number,
    scope: SessionScope = 'free'
  ): Promise<string> {
    const token = crypto.randomBytes(32).toString('hex');
    await q(
      `INSERT INTO sessions (token_hash, pk, scope, iat, expires_at)
       VALUES ($1, $2, $3, to_timestamp($4), now() + $5::interval)`,
      [tokenHash(token), pk, scope, issuedAtUnix, secs(ttlSeconds)]
    );
    return token;
  },

  disconnect() { return pgDisconnect().catch((e) => logger.warn(`[pg] close: ${e.message}`)); }
};

// Wrap every DB method so its wall-clock time is recorded (see lib/metrics.ts).
// Only async methods (the ones that hit the database) are timed; sync helpers and
// plain value members pass straight through. `this` is bound to the raw impl so a
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
