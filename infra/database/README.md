# `infra/database` — the production Postgres cluster

One DigitalOcean Managed Postgres cluster holds everything the production backend
knows: identity, the social graph, subscriptions, sessions, rate counters and the
MQTT topic ACL. There is no Redis anywhere in the stack.

**Production only.** Pre-prod runs a plain `postgres:17` container on its own
droplet ([`docker-compose.preprod.yml`](../deploy/docker-compose.preprod.yml)).

## Why pre-prod is not on this cluster

The short version is **LAT-4**. The load test that every capacity number in
[postgres-migration.md](../../docs/architecture/postgres-migration.md) depends on
runs on pre-prod. Sharing a `db-s-1vcpu-1gb` cluster would mean that test
saturating the 1 vCPU and the 22 connections production sits on — making the one
experiment the design needs the one experiment nobody can safely run.

Separate database users would have stopped *accidental* cross-reads. They do
nothing about CPU, connection exhaustion, or a maintenance window both stacks
share.

Separating costs nothing: production keeps the same single-node cluster, and
pre-prod's database becomes a container it can wipe, reset and hammer. What
pre-prod gives up is rehearsal of the managed path — TLS `verify-full`, the
pooler, DigitalOcean's maintenance behaviour. That is a connection-string
difference rather than a code difference, and production is where it is
exercised. If you specifically want to rehearse it, add the pre-prod droplet to
the firewall below and point that stack here for a day.

## What "private" means here

DigitalOcean **always** publishes a public hostname for a managed cluster and
gives you no way to withdraw it. Two things close the door instead:

1. **Trusted sources.** The firewall in `main.tf` contains exactly one rule — the
   production droplet. Everything else is refused before authentication, on the
   public *and* the private endpoint. That now includes the pre-prod droplet.
2. **The private endpoint.** Every connection string here uses `private_host`,
   which resolves only inside the region's VPC and never leaves DigitalOcean's
   network.

On top of that, connections are `sslmode=verify-full` against the cluster CA, so
a redirected hostname fails the handshake rather than silently connecting.

Confirm it after the first apply — from your laptop, which is *not* a trusted
source:

```bash
psql "postgresql://doadmin@$(terraform output -raw public_host):25060/defaultdb"
```

That must hang and time out. From the production droplet, the private URI must
connect immediately.

## Why this is its own module

`infra/multiregion` also creates the droplets. Ours already exist — they were
made by hand, see [from-scratch.md](../../docs/runbooks/from-scratch.md) §1 —
and are in no Terraform state, so applying that module would want imports first.
This module only *reads* the production droplet, so it applies on its own.

## Apply

```bash
export DIGITALOCEAN_TOKEN=dop_v1_...
export AWS_ACCESS_KEY_ID=...   AWS_SECRET_ACCESS_KEY=...   # R2, for state
cp terraform.tfvars.example terraform.tfvars               # then edit
terraform init -backend-config=backend.hcl
terraform apply
```

## Placing the secrets on the production host

Nothing fetches these automatically: the deploy agent pulls an image, never a
secret, and CI has no path to the box. Do it once, by hand.

```bash
terraform output -raw database_url        | ssh root@HOST "umask 077; cat > /etc/hqcat/prod/secrets/database_url"
terraform output -raw database_url_direct | ssh root@HOST "umask 077; cat > /etc/hqcat/prod/secrets/database_url_direct"
terraform output -raw pg_ca_cert          | ssh root@HOST "umask 077; cat > /etc/hqcat/prod/secrets/pg_ca_cert"
terraform output -raw emqx_pg             | ssh root@HOST "umask 077; cat > /etc/hqcat/prod/secrets/emqx_pg"
```

`emqx_pg` is already shaped as the file EMQX needs — four `AUTHZ_PG_*` shell
assignments. One file rather than environment variables, because EMQX reads the
environment as configuration and an unrecognised var is a boot failure.

Pre-prod needs none of this: `sudo infra/deploy/agent/set-host-secrets.sh preprod`
generates the equivalent four files for its own container.

## Grants

The DigitalOcean API has no grant primitive, so Terraform creates the roles and
the `000_roles.sql` migration applies the privileges — `app_prod` gets DML on
every table, `emqx_prod` gets `SELECT` on `mqtt_acl` and nothing else. The
migration reads the role names from `APP_ROLE` / `EMQX_ROLE`;
`terraform output app_roles` prints them.

## Raising it to highly available

`node_count = 2` adds a standby and is an in-place change — the cluster is not
recreated. It turns a maintenance restart from a production outage into a
~10–30s failover, and moves the SLA from 99.5% to 99.95%. Worth doing before the
app has users who notice; the connection budget below does not change.

## Connection budget

`db-s-1vcpu-1gb` allows **22** backend connections, and production has all of
them now that pre-prod is elsewhere.

| Consumer | Backends |
|---|---|
| `hqcat-prod-pool` — the five Node services, transaction mode | 15 |
| EMQX, connecting direct | 2 |
| unpooled headroom — migrations, `psql`, ops | 5 |

**EMQX is deliberately not pooled.** A DigitalOcean pool binds to one database
user, so the broker's read-only role would need a pool of its own — and behind a
15-minute authz cache it issues a handful of queries a minute, a rate transaction
pooling multiplexes nothing out of. Direct costs the same two backends, is one
less object to operate, and makes `disable_prepared_statements` a belt-and-braces
setting rather than a load-bearing one.
