> **Done — August 2026.** Redis is gone: there is no database container in the
> stack, and every key below is a table. Kept for the reasoning, which still
> explains why the schema is shaped this way.
>
> **What the implementation decided differently, and why:**
>
> - **No shadow mode, no backfill, no per-domain flip** (Phases 2–4). There was
>   nothing deployed to migrate, so the dual-write scaffolding would have been
>   built and deleted without ever protecting anything. One commit replaced the
>   implementation.
> - **The connection pooler is required from day one**, not "before the second
>   PoP". A `db-s-1vcpu-1gb` cluster allows **22** backend connections in total,
>   across both stacks, each of which runs five Node services plus EMQX. Direct
>   connections do not fit. See [`infra/database`](../../infra/database/README.md).
> - **One node, no standby.** Cheapest to start; means DigitalOcean's maintenance
>   window is a restart. The mitigations are in place (authz cache at 15m, a
>   retry on connection-level errors), and `node_count = 2` is a one-line change
>   when it is worth the money.
> - **Tier B lives on the same cluster**, not on a local Postgres per region.
>   `UNLOGGED` still removes the WAL cost of the hot writes; a local tier is a
>   multi-region change, and there is one region.
> - **Phase 0.1 was already done** — `EMQX.kick()` was wired into revocation
>   before this started, which is what made raising the authz cache TTL safe.
> - **`pending:{pk}` was not ported.** Its only caller was the undeployed legacy
>   monolith, where it is now an in-process `Map`.
>
> Three behaviour changes went in deliberately, each closing something the Redis
> shape got wrong: `username` is `citext` (case-insensitive, so `Helper` and
> `helper` cannot both be claimed), REST bearers are stored as `sha256(token)`
> rather than as the key itself, and accepting an invite now writes the same row
> `checkFriendship` reads (it used to write only the friend sets, so the two
> disagreed).

# Redis → Postgres — migration plan

Move every Redis key into Postgres and delete Redis. Then scale reads with
regional replicas without the writer becoming a bottleneck.

Context for *why*: the EMQX authz cache (`ttl = 1m`,
[emqx.conf:63](../../infra/deploy/emqx/emqx.conf)) means the ACL lookup is **not**
on the message path — it runs once per client-topic per minute. That removes the
latency argument for a KV store. Everything Redis does with Lua, Postgres does
with a constraint. See [components-regions.md](components-regions.md) for the
regional plan this feeds.

## What makes this tractable

- **One seam.** Only [`services/db/api.ts`](../../services/server/services/db/api.ts)
  opens a Redis client on the app path. Every service imports `DB`. `checks.ts`,
  `ops/broker-watch.ts` and `scripts/backfill-mqtt-acl.ts` are the only other
  clients, and they are ops tools.
- **Already instrumented.** `instrument()` ([api.ts:915](../../services/server/services/db/api.ts))
  proxies every `DB` method. Shadow-comparison and per-op latency come free.
- **`pending:{pk}` is dead.** The legacy WS offline queue has no callers left —
  EMQX owns offline delivery now. Delete it, don't port it.

## The core idea: three table tiers

This is what answers "how do replicas keep the writer from saturating". They
mostly don't — **the high-frequency writes never reach the writer at all.**

| Tier | Contents | Where it lives | Replicated |
|---|---|---|---|
| **A — global durable** | directory, social graph, entitlements, `mqtt_acl` | writer (home region) | yes, to every regional replica |
| **B — regional ephemeral** | sessions, rate counters, OTP, auth challenges | local PG in each region, `UNLOGGED` | **no** |
| **C — global ephemeral** | MQTT connect tokens, connect nonces | writer only | no |

Tier B is the trick. Session sliding and rate counters are the only genuinely
hot writes in the system, and neither has any business being global — a rate
counter or an idle timeout is a property of one region's traffic. Making them
`UNLOGGED` also means no WAL, and Postgres truncates them on crash recovery,
which is exactly the durability you want for state that is safe to lose.

Tier C is small and correctness-critical: a single-use nonce accepted in two
regions is a bug, not a race to tune. It stays with one writer. That costs
nothing because `auth` is already a single global service on the connect path
([components-regions.md](components-regions.md)), and a client connects once then
sends thousands of messages.

## Key → table mapping

⚠️ **The `pk` columns below are historical.** This section records the Redis →
Postgres mapping as it was designed; `004_identity_by_hash.sql` later replaced
every one of those identifiers with a 64-character client id
(`id = sha256(lowercase-hex(pk))`), because a 14474-character key broke
everything with a length limit — most consequentially the broker's admin API,
where every kick came back `414 URI Too Long`. Read the column names below as
`id`, `id_lo`/`id_hi`, `to_id`/`from_id`. See
[e2ee-protocol.md](e2ee-protocol.md) §2 and the migration itself.

### Tier A (writer, replicated)

| Redis today | Table |
|---|---|
| `user:{pk}`, `username:{u}`, `usernames:taken` | `users(pk PK, username CITEXT UNIQUE, created_at, tier)` |
| `friends:{pk}`, `friendship:{h}`, `hashmembers:{h}` | `friendships(pk_lo, pk_hi, hash GENERATED, PK(pk_lo,pk_hi))` |
| `invites:{pk}` | `invites(to_pk, from_pk, created_at, PK(to_pk,from_pk))` |
| `push:{pk}` | `push_tokens(pk PK, platform, token, updated_at)` |
| `claim:{pk}`, `sub:{h}`, `subcus:{id}`, `sub:pks:{h}` | `subscriptions(email_hash PK, …)`, `subscription_customers(customer_id PK, email_hash)`, `subscription_claims(pk PK, email_hash, claimed_at)` |
| `admission:exempt` | `admission_exempt(pk PK)` |
| `mqtt_acl:{pk}` | `mqtt_acl(pk, topic, action, PK(pk,topic))` |

> **The column is `id`, not `pk`.** This table is the plan as written, and it
> predates the identifier change: an account is keyed by
> `id = sha256(lowercase-hex(publicKey))` — 64 characters — not by the 14474-character
> key itself. Read every `pk` above as `id`, and `friendships(pk_lo, pk_hi)` as
> `friendships(id_lo, id_hi)`. The conversation `hash` is also **not** a generated
> column in the end: it is written explicitly on insert, because `grantFriendTopic`
> and the client both derive the same value from the ids and all three have to
> agree. `migrations/004_identity_by_hash.sql` is the schema that actually shipped.

`usernames:taken` becomes a `UNIQUE` index — which kills the check-then-set race
in [`createUser`](../../services/server/services/db/api.ts) (currently `SISMEMBER`
then a non-atomic pipeline). Same for the subscription seat cap: a `CHECK` or a
counted `INSERT … WHERE (SELECT count(*) …) < cap` replaces the Lua at
[api.ts:325](../../services/server/services/db/api.ts).

`friendships` normalises the pair (`pk_lo < pk_hi`) so the edge is one row, and
the conversation hash is a generated column — `hashmembers` stops being a
separate thing to keep in sync.

`mqtt_acl` stays materialised rather than a view over `friendships`, because EMQX
queries it directly and a view would join on every authz miss.

### Tier B (regional, `UNLOGGED`)

| Redis today | Table |
|---|---|
| `session:{token}`, `sessions:{pk}` | `sessions(token_hash PK, pk, scope, iat, expires_at)` |
| `rate:{key}` | `rate_counters(key PK, n, window_ends_at)` |
| `otp:{email_hash}` | `otp(email_hash PK, hash, attempts, expires_at)` |
| `chal:{pk}` | `auth_challenges(pk PK, proof, expires_at)` |

### Tier C (writer)

| Redis today | Table |
|---|---|
| `mqtt_auth:{pk}` | `mqtt_tokens(pk PK, token_hash, expires_at)` |
| `mqttnonce:{n}` | `mqtt_nonces(nonce PK, expires_at)` |

TTLs become `expires_at timestamptz`, every read filters `WHERE expires_at >
now()`, and a sweeper deletes. Partition the churny ones by hour and `DROP
PARTITION` instead of `DELETE` — that is how you avoid autovacuum debt, which is
the one operational cost Redis didn't have.

`SET NX EX` on nonces becomes `INSERT … ON CONFLICT DO NOTHING` and a rowcount
check — strictly more correct than the Redis version.

## Phases

**Phase 0 — prerequisites (do first, valuable alone)**
1. Wire `EMQX.kick()` ([lib/emqx.ts:68](../../services/server/lib/emqx.ts)) into
   `revokeFriendTopic` and the subscription-lapse path. Revocation becomes
   immediate and stops depending on the authz cache TTL.
2. Then raise `authorization.cache.ttl` from `1m`. At 15m the authz query rate
   drops ~15×. Residual exposure is presence metadata only (`u/{id}/presence` is
   plaintext, not E2E) for the window — conversation content is protected by the
   keys regardless.

   ⚠️ Step 1 was wired and step 2 was taken, but step 1 **did not work**: the
   kick built a ~14.5 kB URL out of a public key and EMQX answered 414 every
   time, silently, so the cache TTL was raised on the strength of a mitigation
   that was not in place. Fixed by `004_identity_by_hash.sql` (finding SRV-3).
3. Settle **LAT-4**: measure actual authz query rate, session-resolve rate and
   reconnect-storm behaviour on the compose stack. Every capacity number below is
   a derivation until this exists.

**Phase 1 — schema + PG alongside Redis.** Turn on `enable_managed_postgres`
([pops.tf:86](../../infra/multiregion/pops.tf)) or a `postgres` service in
[docker-compose.yml](../../infra/deploy/docker-compose.yml). Write migrations for
all three tiers. Nothing reads from it yet.

**Phase 2 — `DB` gets a Postgres implementation behind the same interface.**
Keep `DBImpl`'s exact method signatures. Add a `DB_BACKEND=redis|postgres|shadow`
switch. In `shadow`, write to both and read from Redis while logging divergence
through the existing `instrument()` proxy.

**Phase 3 — backfill + verify.** Port `backfill-mqtt-acl.ts` into a general
`redis→pg` backfill. Run it, then leave shadow mode on until divergence is zero
across a full day including a deploy.

**Phase 4 — flip reads per domain**, in ascending order of blast radius:
rate counters → OTP/challenges → sessions → push tokens → subscriptions →
invites → friendships → directory. Each is one config flip, reversible.

**Phase 5 — EMQX authz to Postgres.** Swap the `type = redis` source for
`type = postgresql` with `SELECT action, topic FROM mqtt_acl WHERE id =
${clientid}` — same shape as the current `HGETALL`. (It shipped as `WHERE pk =`;
`004_identity_by_hash.sql` renamed the column, and the two MUST move together —
this query lives on the broker, not in the migration.) Note the array-index env-var
trap documented at [emqx.conf:71](../../infra/deploy/emqx/emqx.conf) applies to
the PG source too: configure it in the file, not via `EMQX_AUTHORIZATION__*`.

**Phase 6 — delete Redis.** Remove the service from both compose files, the
`redis_password` secret, `REDIS_URL` from config, and the Redis probes in
`checks.ts` / `ops/broker-watch.ts`. Retires the `redis-data` AOF plaintext
caveat in [deploy.md](../runbooks/deploy.md).

## Keeping the writer unsaturated

**What actually reaches the writer**, once tiering is in place:

| Write | Rate | Note |
|---|---|---|
| friend accept / unfriend (+ ACL rows) | human-scale | rare |
| username claim | once per user, ever | — |
| Stripe webhook / claim | rare | — |
| MQTT token mint | ~1 per device per 12h | Tier C |
| nonce burn | 1 per connect | Tier C |
| push token upsert | **1 per app launch** | see below |

Only the last is a surprise: the client re-registers its APNs token on every
launch (AppState.swift:311). Make it a
no-op when unchanged so it doesn't churn a row version:

```sql
INSERT INTO push_tokens (pk, platform, token) VALUES ($1,$2,$3)
ON CONFLICT (pk) DO UPDATE SET token = EXCLUDED.token, updated_at = now()
WHERE push_tokens.token IS DISTINCT FROM EXCLUDED.token;
```

Everything else that is high-frequency — session resolution and its sliding
`EXPIRE` (currently a write on *every authenticated request*,
[api.ts:834](../../services/server/services/db/api.ts)), and rate counters — is
Tier B and never leaves its region. Additionally, make the slide lazy: only
update `expires_at` if more than ~5 minutes have elapsed since the last touch.
That alone cuts session writes by an order of magnitude and is worth doing on
day one.

**If session writes still dominate**, the highest-leverage change is to stop
storing them: make the REST bearer a short-lived signed token (ML-DSA is already
planned for MQTT creds per [mqtt-architecture.md](mqtt-architecture.md)) and keep
only a small replicated revocation list. Session resolution becomes zero reads
and zero writes. Deliberately out of scope for the migration — note it, do it
after.

## Multi-region

Target: writer in the home region, one streaming read replica per PoP, each
region's EMQX and app-api reading from the replica beside it.

```
home (lon)                     nyc                      sgp
  PG writer  ──replication──▶  PG replica               PG replica
  auth (global)                EMQX ─▶ local replica    EMQX ─▶ local replica
  Tier B local                 app-api ─▶ local         app-api ─▶ local
                               Tier B local             Tier B local
```

Reads that go local: `mqtt_acl` (EMQX authz), friend lists, directory lookups.
Writes route home. This matches the topology already sketched in
[components-regions.md](components-regions.md), with Postgres replicas in place of
the Redis replicas proposed there — same locality, no CDC pipeline to build, and
no dual-write divergence class.

**Decisions this forces, and the recommended answer:**

1. **Read-your-writes.** After a friend accept the client may read a lagging
   replica. Cheapest fix: return the post-write state in the write response so no
   read is needed. Where a read is unavoidable, pin that session to the writer for
   a few seconds after a write. LSN-wait is available if the PG version has
   `pg_wal_replay_wait()`; otherwise poll `pg_last_wal_replay_lsn()`.
2. **ACL read-after-write is the sharp edge.** A friend accept writes `mqtt_acl`
   at the writer; if the peer's client subscribes before the replica catches up,
   `no_match = deny` + `deny_action = disconnect` doesn't just refuse — it **drops
   the connection**. Write the ACL before returning the accept, and make the
   client tolerate a disconnect-then-retry on a freshly granted topic.
3. **Session revocation must fan out.** Tier B is regional, so `revokeAllSessions`
   (logout, account deletion) has to reach every region. Publish it on an internal
   MQTT topic and have each app-api delete locally. The stateless-token option
   above dissolves this too.
4. **Roaming.** A regional session doesn't follow a user who moves region; they
   re-handshake. Acceptable — it is rare and silent.
5. **Connection limits.** EMQX's PG connector opens its own pool per node, on top
   of every app-api replica. A `db-s-1vcpu-1gb` caps around 100 connections. Put
   PgBouncer (transaction mode) in front in each region before adding the second
   PoP.
6. **Cost.** DO managed read replicas are a paid add-on per replica; the current
   terraform provisions a single `node_count = 1` cluster
   ([pops.tf:86](../../infra/multiregion/pops.tf)).

**Monitor:** replication lag per replica, `sessions`/`rate_counters` table bloat
(or partition-drop lag), PgBouncer pool saturation, and authz query rate against
the Phase 0 baseline.

## Order of work

Phase 0 is worth doing this week regardless — the kick wiring is a real
improvement to revocation today, and the LAT-4 baseline is a prerequisite for
every capacity claim above. Phases 1–6 are single-region and should land fully
before any second PoP exists. Multi-region is a later change, and the tiering
above is what makes it a config change rather than a rewrite.
