# DissQus — Deployment Architecture

How code and secrets flow from GitHub to the production and pre-prod VMs, and
where Cloudflare fits. Operational steps live in [the deploy runbook](../runbooks/deploy.md);
this file explains the model and the moving parts.

```
 developer ── git push ──▶ GitHub
                              │
       ┌──────────────────────┴────────────────────────────────┐
       │ Release (release.yml)                                 │
       │   ci      ── server · e2e · terraform validate         │
       │   image   ── build + smoke test → GHCR                 │
       │              (the image also carries /deploy-bundle)   │
       │   cloudflare ── terraform plan + apply (main only)     │
       └──────────────────────┬────────────────────────────────┘
                              ▼
              GHCR  ghcr.io/.../dissqus-server
                 :sha-<12>   immutable, one per commit
                 :preprod    channel — moved by a push to preprod
                 :prod       channel — moved by the Promote workflow
                              │
              ┌───────────────┴───────────────┐
              │        (each VM PULLS)        │
              ▼                               ▼
       pre-prod VM                     production VM
   hqcat-agent (systemd timer, 2 min): digest changed?
     ▶ pull ▶ extract /deploy-bundle ▶ compose up -d
     ▶ nginx ▶ health gate ▶ commit, else roll back
              │                               │
   emqx ─ auth/app-api/push ─ bot             (same)
              ▲                               ▲
              └──────── Cloudflare ───────────┘
                  (TLS, WAF, DNS, Worker routes)

 Secrets never leave the host they are used on:
   /etc/hqcat/<stack>/secrets/  (root, 0700)
```

Nothing in GitHub can reach a server: there is no deploy SSH key, no
`DEPLOY_HOST`, and no git checkout on any VM. Releasing production means moving
the `:prod` tag; rolling back means moving it back.

The Apple apps are deliberately NOT built here — see
`apps/apple/verify.sh`.

## 1. GitHub is the single source of truth for secrets

Nothing secret lives in the repo or the image. The only ever-committed secret
file, `services/server/.env.prod`, only held the placeholder
`STRIPE_SECRET_KEY=STRIPE_SECRET_KEY` and is now deleted (verified: no
`sk_live`/`whsec`/private-key material anywhere in git history).

Secrets live on **the host that uses them**, not in GitHub:

| Location | Holds |
|---|---|
| `/etc/hqcat/<stack>/secrets/` (root, 0700) | `database_url`, `database_url_direct`, `pg_ca_cert`, `emqx_pg`, `stripe_secret_key`, `stripe_webhook_secret`, `resend_api_key`, `otp_pepper`, `apns_key_p8` — the compose `secrets:`. On prod the four database files come from `terraform output` in [`infra/database`](../../infra/database/README.md); on pre-prod `set-host-secrets.sh` generates them for that stack's own postgres container |
| `/etc/hqcat/<stack>/server.env` (root, 0600) | non-secret config: `SERVER_NAME`, `PUBLIC_BASE_URL`, `ADMISSION_POLICY`, `APNS_*`, `STOREKIT_*` |
| `runtime-secrets` tmpfs, per stack | `internal_mqtt_secret`, `emqx_dashboard_password`, `metrics_token` — generated at launch by `secrets-init`, never on disk. Only credentials both ends of which are inside the stack; the database's are not |
| `/etc/hqcat/agent.env` (root, 0600) | the agent's **read-only** `read:packages` GHCR token |

The agent symlinks the first two into the stack directory on each rollout;
`lib/config.ts` reads the secret files via the `*_FILE` convention. Rotate by
editing the file on the host and restarting the stack.

This used to be a table of GitHub Environment secrets that a CI runner wrote
onto the VM over SSH. Production Stripe/APNs/Resend material therefore passed
through GitHub and through a runner on every deploy, and was readable by anyone
who could add a workflow to the repo. It no longer enters GitHub at all.

What GitHub still holds is only what Terraform needs to manage the edge:
`CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_API_TOKEN_USER`, `ORIGIN_IPV4`,
`PREPROD_ORIGIN_IPV4`, plus the `R2_ACCESS_KEY_ID` / `CLOUDFLARE_ACCOUNT_ID` /
`CLOUDFLARE_ALERT_EMAIL` variables. `ORIGIN_IPV4` is the single definition of
the prod IP; `DEPLOY_HOST` used to duplicate it.

### Populating

```bash
# On the VM — secrets and config, interactively:
sudo infra/deploy/agent/set-host-secrets.sh prod
sudoedit /etc/hqcat/prod/server.env

# Apple variables + the APNs key, gathered interactively (feeds server.env):
infra/deploy/scripts/collect-apple-env.sh

# From your laptop — the Cloudflare/Terraform side only:
infra/deploy/scripts/set-ci-secrets.sh production
```

## 2. Container registry (GHCR) — build once, pull everywhere

The VM no longer builds the image (`docker compose up --build` was slow and made
each box subtly different). CI builds `linux/amd64` once — the only target that
matches the native `libhqc_x86.so` — smoke-tests the real compose stack through
the `*_FILE` secrets path, and pushes to **GitHub Container Registry**:

- `:sha-<commit>` — immutable, one per commit; what actually gets deployed
- `:prod` / `:preprod` — **release channels**. Each VM's agent follows one. A
  push to `preprod` moves `:preprod`; the Promote workflow moves `:prod`.
- `:latest` (main) — informational; nothing follows it

The agent resolves its channel tag to a digest and runs `docker compose up -d
--no-build` pinned to that digest. The image also carries `/deploy-bundle` — the
compose files, `nginx.conf`, `emqx/`, `scripts/` and the agent itself — so a host
needs no git checkout to run a release, and the manifests can never drift from
the binary they describe. Benefits: fast, reproducible, rollback = redeploy an older `:sha`
tag, and the VM only needs a read-only GHCR token (the workflow's `GITHUB_TOKEN`,
passed for the job's duration). Pin base images by digest for full supply-chain
integrity (see DEPLOY.md).

## 3. Pre-prod environment

Pre-prod is its **own VM**, running its own agent pinned to the `:preprod`
channel, with `open` admission (no real payments). A push to the `preprod`
branch moves that tag, so pre-prod deploys itself on merge. Files:
[docker-compose.preprod.yml](../../infra/deploy/docker-compose.preprod.yml);
secrets in `/etc/hqcat/preprod/secrets/` on that host.

It previously ran on the production droplet, isolated only by the Compose
project name and remapped host ports — and because the two stacks shared a
checkout, pre-prod's unoverridden compose secrets resolved to **production's**
`secrets/stripe_*` files. Separate hosts and per-host secret directories close
that; every external secret is redirected to `preprod/secrets/` in the overlay.

On its own host there is nothing to collide with, so pre-prod uses the same
upstream ports as prod (emqx 8083 / auth 8090 / app-api 8091) and the nginx
template applies verbatim. The compose project name is kept so a stray
`docker compose down` still cannot cross stacks.

The DNS record is Terraform-managed ([dns.tf](../../infra/cloudflare/dns.tf),
`preprod_origin_ipv4`), not hand-added in the dashboard:

```bash
sudo hqcat-apply-nginx preprod    # only if you need to force it; the agent does this
```

## 4. VM + nginx + host hardening

- **`harden-vm.sh`** — ufw (SSH rate-limited; 80/443 **Cloudflare IPs only**),
  key-only SSH, fail2ban, unattended security upgrades, sysctl hardening, and a
  hardened Docker daemon (`no-new-privileges`, log rotation, `live-restore`).
  Idempotent. It is an operator tool, not something that lives on the box — pipe
  it in from your laptop: `ssh root@HOST bash -s < infra/deploy/scripts/harden-vm.sh`.
  Re-run when Cloudflare's IP ranges change.
- **`hqcat-apply-nginx <prod|preprod>`** (installed at `/usr/local/sbin`) — renders,
  installs, validates (`nginx -t`) and reloads the [nginx.conf](../../infra/deploy/nginx.conf)
  template, from the bundle the agent extracted out of the released image. The
  agent calls it on every rollout; run it by hand only to force a reapply. Both
  stacks use the same upstreams (emqx 8083 / auth 8090 / app-api 8091) now that
  pre-prod has its own VM.
- Containers themselves are hardened in [docker-compose.yml](../../infra/deploy/docker-compose.yml):
  non-root, `cap_drop: ALL`, read-only rootfs, `no-new-privileges`, pids/mem/cpu
  caps, rotated logs. No port but nginx's is published beyond localhost.
- Production's database is not on the host at all: it is a DigitalOcean managed
  cluster whose trusted-sources firewall names exactly one droplet, reached over
  the VPC's private endpoint with `sslmode=verify-full`. Pre-prod deliberately
  runs its own container instead, so a load test there cannot reach production.
  See [`infra/database`](../../infra/database/README.md).

## 5. Cloudflare — current use and a better architecture

**Today:** Cloudflare proxies the domain (DNS + TLS termination, Full-strict to
the origin), and a single **Cloudflare Worker** serves the static marketing/legal
site (apps/web/src/index.js). All app traffic
(`/mqtt`, `/auth/*`, the REST control plane, `/subscribe`, `/stripe/webhook`)
goes CF → nginx → the compose services.

**Proposed, phased:**

1. **Edge protection (now, config-only).** Turn on Cloudflare **WAF + Rate
   Limiting rules** in front of `/mqtt` and the HTTP API, and **Turnstile** on the
   `/subscribe` page. This offloads H5-style abuse control to the edge before it
   reaches the VM, and lets you firewall the origin to CF IPs (already scripted).
2. **Move stateless edges to Workers (next).** Serve `/info` and `/health` from a
   Worker (cache at edge, hide origin), and verify the **Stripe webhook
   signature at the edge** with Web Crypto, forwarding only validated events to a
   minimal origin endpoint. Keep the `/mqtt` WebSocket straight through CF's
   proxy — Workers add little there and have WS constraints.
3. **Relay on Durable Objects (later, the real win).** A Cloudflare **Durable
   Object** per user/room with the **WebSocket Hibernation API** can host
   presence + message relay globally with no VM, replacing the in-memory
   `onlineUsers` maps and much of the ephemeral tier. Blocker: the HQC auth challenge uses the
   native `libhqc_x86.so`, which can't run in Workers — it must first be compiled
   to **WASM** (the KEM migration, audit **C1**, is the natural moment to produce
   a portable build). Until then the VM relay stays; the edge handles protection,
   static content, and stateless endpoints.

Net: Cloudflare becomes the security/perf front door immediately, and the
long-term path removes the VM from the hot messaging path once HQC is portable.
