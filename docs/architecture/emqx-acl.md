# EMQX auth + RLS — operator notes

How the broker enforces per-conversation access, and the table it reads.
Config: [emqx.conf](../../infra/deploy/emqx/emqx.conf). Overall design: ../EXTRACTION_PLAN.md.

## Topics

- Conversation between two public keys → `c/{friendshipHash(pkA,pkB)}`
  (`friendshipHash` = `sha256(sorted(pkA,pkB))`, see `lib/crypto-utils.ts`).
- The topic name is **derivable by anyone who knows both public keys**, so
  access control rests ENTIRELY on the `mqtt_acl` table below — never on secrecy
  of the topic name.

## Authentication (who may connect)

- `clientid = pk` (the client sets this), `username = pk`, `password = token`.
- The token is an opaque 32-byte secret minted by the auth server after the
  HQC-KEM handshake; only its SHA-256 is stored, in `mqtt_tokens` (12h).
- EMQX calls `POST http://auth:8080/mqtt/authn`; the auth server verifies the
  token (constant-time, reusable across reconnects) + optional per-CONNECT nonce
  and returns `{"result":"allow","expire_at":<unix>}`. **EMQX disconnects the
  client at `expire_at`** → the client refreshes (`/auth/refresh`) and reconnects
  (expiration-based rotation). Revoke early with `DB.revokeMqttAuth(pk)` (+ kick).

## Authorization / RLS (which topics)

- On a cache MISS, EMQX runs:

  ```sql
  SELECT 'allow' AS permission, action, topic FROM mqtt_acl WHERE pk = ${clientid}
  ```

  `permission`, `action` and `topic` are the three column names the PostgreSQL
  authorizer requires. `permission` is not stored — every row in the table is a
  grant, and `no_match = deny` decides everything else. `action` is
  `publish | subscribe | all`.

  Note "on a cache miss": with `cache.ttl = 15m` this is roughly one query per
  client-topic per quarter hour, not one per message. That is what makes a
  relational store the right shape here at all.

- Written by app-api on friend accept (`DB.grantFriendTopic`) and removed on
  unfriend (`DB.revokeFriendTopic`) — both members get the entry.
- `no_match = deny` + `deny_action = disconnect`: anything not explicitly granted
  is refused and the offending client is dropped.

## Revocation gotchas

1. **Authorization cache** (`ttl = 15m`): a revoked pk may still pub for up to
   the cache TTL. Do NOT lower it to get faster revocation — that trade was
   already made the other way. Revocation acts instead of waiting: app-api drops
   the live subscription through the admin API (`lib/emqx.ts`) at the same moment
   it deletes the row, so the cache window only matters to a client that
   RECONNECTS inside it, and all such a client can reach is presence metadata.
2. **Live subscriptions are not re-authorized.** Deleting the row blocks the NEXT
   pub/sub but an already-open SUBSCRIBE keeps flowing. On unfriend/delete you
   must ALSO kick it via the EMQX API, e.g.:
   ```
   curl -u admin:$PW -X DELETE \
     http://127.0.0.1:18083/api/v5/clients/$PK/subscriptions/c%2F$HASH
   ```
   or disconnect the client entirely. app-api already does both — see
   `EMQX.revokeTopic` on the unfriend path and `EMQX.kick` on account deletion
   and subscription lapse (`services/server/api/main.ts`).

## Repairing the table

`mqtt_acl` is materialised rather than a view over `friendships`, because EMQX
queries it directly and a view would join on every cache miss. The cost is that
it can drift. Re-derive it from the friend graph — idempotent, and additive
unless you ask for the prune:

```bash
docker compose run --rm app-api node --import tsx scripts/rebuild-mqtt-acl.ts
docker compose run --rm app-api node --import tsx scripts/rebuild-mqtt-acl.ts --prune
```

## Reaching the dashboard

It binds to `127.0.0.1:18083` on the VM and nginx does **not** proxy it. One
command from a laptop (single TOTP prompt — the script multiplexes one SSH
connection for the password read, the port-forward and the health report):

```bash
./deploy/scripts/emqx-dashboard.sh            # prod
./infra/deploy/scripts/emqx-dashboard.sh preprod   # the pre-prod VM
./deploy/scripts/emqx-dashboard.sh --status   # authn/authz health, then exit
```

## Secrets

`emqx.conf` carries NO secrets — it is a **template**, mounted read-only at
`/emqx.conf.template` and rendered at container start:

- `__PG_SERVER__`, `__PG_HOST__`, `__PG_DATABASE__`, `__PG_USERNAME__`,
  `__PG_PASSWORD__`, `__PG_SSL__` ← `/run/secrets/emqx_pg`, a file of
  `AUTHZ_PG_*` shell assignments the entrypoint sources before substituting them
  into `/opt/emqx/etc/emqx.conf`. A FILE and not environment variables, because
  EMQX reads the environment as configuration — an unrecognised var is a boot
  failure, not something it ignores.
- `EMQX_DASHBOARD__DEFAULT_PASSWORD` ← `/runtime-secrets/emqx_dashboard_password`

The dashboard password is generated at launch by `secrets-init` into a RAM-only
tmpfs volume (`infra/deploy/scripts/gen-runtime-secrets.sh`) — nothing to create
by hand. `emqx_pg` is not: it authenticates to a managed cluster this stack does
not own, so it comes from `terraform output` in
[`infra/database`](../../infra/database/README.md) and is placed on the host.

Two traps this arrangement exists to avoid:

1. **The database password cannot be an env override.** `authorization.sources`
   is an ARRAY, and EMQX stopped accepting indexed array overrides from the
   environment in 5.0.25 — `EMQX_AUTHORIZATION__SOURCES__1__PASSWORD` is either
   ignored or rejected with `missing_type_field`
   ([emqx/emqx#10264](https://github.com/emqx/emqx/issues/10264),
   [emqx/emqx#14587](https://github.com/emqx/emqx/issues/14587)). The authorizer
   then dials with an empty password and the source sits `disconnected` while
   every other service's database client is fine.
2. **The dashboard password drifts.** `dashboard.default_password` only seeds the
   admin user on the FIRST boot; after that the credential lives in mnesia
   (`emqx-data`), which survives the `docker compose down` that regenerates the
   RAM-only secret. The entrypoint therefore re-runs `emqx ctl admins passwd
   admin <secret>` after every boot, so the generated file is always the truth.

## What a broken authorizer actually costs (today vs. after cutover)

Worth knowing before you panic — or before you relax:

- **Clients still connect.** Authentication is a separate path: EMQX POSTs to
  `auth:8080/mqtt/authn` and the auth server checks the token with its OWN
  database client. The broker's database link is used only for the topic ACL.
- **The push-bridge is unaffected.** `/mqtt/authn` returns `is_superuser: true`
  for the internal identity, and a superuser bypasses authorization entirely —
  so the one MQTT client that runs continuously never touches the ACL.
- **Everyone is on MQTT now (Phase 4).** The apps and the helper bot are
  ordinary MQTT clients — the `/ws` monolith they used to message over is
  retired. A dead authorizer is therefore no longer invisible: it is an outage
  or a hole, depending on which config is live: with this file's `no_match = deny`,
  every pub/sub is refused and clients are disconnected; on stock EMQX defaults
  (`no_match = allow`, no sources) any authenticated key can subscribe to any
  conversation topic — the topic name is derivable from two public keys, so the
  ACL is the ONLY thing standing between a stranger and a conversation's
  ciphertext + metadata.

`broker-watch` (`services/server/ops/broker-watch.ts`) now polls the broker API
and pages Sentry on the transition, so this can no longer be a silent state.
