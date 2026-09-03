# DissQus — Production Deployment (Docker)

> **Standing up a new environment?** Follow
> [from-scratch.md](from-scratch.md) instead — it covers DigitalOcean,
> Cloudflare, GitHub and the host in order, with the page to open at each step.
> This document is the day-to-day reference.


Goal: the broker reachable at `wss://YOUR_DOMAIN/mqtt` and the REST control
plane at `https://YOUR_DOMAIN/auth/*` + `/friends`, `/username`, … over TLS,
the database reachable only over the VPC, containers auto-restarting, secrets
kept out of git and the image, Stripe webhook live. Then point the apps at it and
live-test.

The stack runs under **Docker Compose** (`infra/deploy/docker-compose.yml`): EMQX
+ auth + app-api + push-bridge + broker-watch + the helper bot. **No database
container on production** — its state lives in a DigitalOcean managed Postgres
cluster ([`infra/database`](../../infra/database/README.md)), so the droplet
holds nothing that a rebuild would lose. Pre-prod is the deliberate exception: it
runs its own `postgres:17` container so it can be wiped and load-tested without
touching production. Secrets are
injected as **compose secrets** (files under `infra/deploy/secrets/`, mounted at
`/run/secrets/*`, read via the `*_FILE` convention in
`services/server/lib/config.ts`). **nginx** on the host terminates TLS from
Cloudflare and proxies to those services, each of which binds only to a
localhost port (emqx `8083`, auth `8090`, app-api `8091`).

> The single-`/ws` monolith was retired at Phase 4 (see
> EXTRACTION_PLAN.md). `services/server/server.ts` is still
> in the repo — undeployed — because the WS e2e tests are our only end-to-end
> coverage of the HQC handshake and the ratchet.

Prereqs you provide: a **VPS/VM** (Linux x86_64, Ubuntu 24.04), Docker + the
compose plugin, a **domain** on Cloudflare, and your **live Stripe keys**.

> **The model in one line:** CI builds the image once and pushes it to **GHCR**,
> the VM **pulls** it, and nothing in GitHub can reach a server. **Secrets** live
> on the host that uses them and never enter GitHub; **non-secret config** lives
> in GitHub repository variables and rides to the host inside the release bundle,
> where `/etc/hqcat/<stack>/server.env` can still override it. (This line used to
> say GitHub was the source of truth for *secrets* and that the VM materialized
> them from GitHub at deploy time — that was the pre-agent model, and had been
> false since it was retired.) See
> [ARCHITECTURE.md](../architecture/overview.md) for the full picture. The manual steps below
> are the **first-time VM bootstrap**. **Pre-prod** deploys automatically on push
> to `preprod`. **Production is human-gatekept** — push to `main` builds the image,
> but releasing it is a manual, OTP-authenticated step (see
> [§ OTP-gated prod deploy](#otp-gated-prod-deploy) below). Helper scripts live in
> `infra/deploy/scripts/`:
> `harden-vm.sh`, `collect-apple-env.sh`, `agent/install-agent.sh`,
> `emqx-dashboard.sh`.

> The native HQC library (`services/server/lib/libhqc_x86.so`) is x86_64/glibc,
> so the image uses a Debian (bookworm) base and must run on `linux/amd64`.

---

## 1. VM + base packages

```bash
ssh root@VPS_IP
apt update && apt install -y nginx docker.io docker-compose-v2 git
```

That is the whole host prerequisite — and note there is no `git` in it. There is
**no deploy user, no clone, and no source code on this machine, ever.** Releases
are pulled by an agent running as root from a systemd timer (section 7), and the
agent itself is installed out of the release image, not out of a checkout.

> `harden-vm.sh` (section 7) narrows 80/443 to Cloudflare's ranges, so once it
> has run the origin is only reachable through the proxy. Get the DNS record and
> the Origin cert in place (section 4) before or shortly after hardening.

## 2. Secrets (never committed)

Two classes of secret:

- **Internal service credentials** (internal MQTT identity, EMQX dashboard
  password, metrics token) are **generated at launch** by the `secrets-init`
  service into a RAM-only tmpfs volume — **you create nothing** for these, and
  they never touch the host disk or git. Only credentials both ends of which are
  inside this stack qualify; the database's do not, which is why they are
  external below.
- **External secrets** (Stripe, APNs) live on the host that uses them, under
  `/etc/hqcat/<stack>/secrets/` (root, 0700). They are **not** in GitHub and not
  in the repo — the agent symlinks that directory into the stack on every
  rollout. (`resend_api_key` and `otp_pepper` were here too, for the emailed
  subscription claim; nothing in this stack sends mail since the paywall was
  removed. Existing hosts keep both files; they are inert and can be deleted.)

Use the helper rather than writing the files by hand; it sets the permissions and
creates the empty placeholders that compose requires for secrets you do not use:

```bash
sudo infra/deploy/agent/set-host-secrets.sh prod     # prompts, nothing in shell history
sudoedit /etc/hqcat/prod/server.env                  # non-secret config
```

`server.env` wants: `SERVER_NAME`, `PUBLIC_BASE_URL`, `ADMISSION_POLICY` (`open`
— `stripe` was removed with the paywall and a host still carrying it refuses to
boot), `EXEMPT_PUBLIC_KEYS`, `DONATIONS_ENABLED` plus the two
`STRIPE_DONATION_*` price ids, and the `APNS_*` values — see
[.env.example](../../infra/deploy/.env.example). No secrets go in it.

> Every compose secret must exist as a file or `docker compose up` fails, which
> is why unused ones become empty placeholders. The four database files
> (`database_url`, `database_url_direct`, `pg_ca_cert`, `emqx_pg`) are the
> exception that must be real — pipe them in from `terraform output` in
> [`infra/database`](../../infra/database/README.md), which is also where they
> are generated. A stack with an empty `DATABASE_URL` has no state and stops at
> its migration step, which is the correct failure.

> To read a generated secret (e.g. the EMQX dashboard password) at runtime:
> `docker compose exec secrets-init cat /runtime-secrets/emqx_dashboard_password`.
> For the EMQX dashboard specifically, use `infra/deploy/scripts/emqx-dashboard.sh`
> from your laptop — one SSH connection (one TOTP code) that reads the password,
> forwards `:18083`, prints an authn/authz health report and opens the browser.
> A full `docker compose down` clears them; the next `up` regenerates a fresh set
> (nothing stored depends on them — they authenticate services to each other, not
> to data).

The server **fails fast at boot** (`assertConfig()`) if required settings are
missing for the chosen `ADMISSION_POLICY`, so a half-configured box won't run.

## 3. Bring up the stack

> **One-off, for the `004_identity_by_hash` release: restart EMQX after the
> migration.** Clients are named by `sha256(hex(pk))` from that migration onward,
> and the broker's authorization cache holds entries keyed on the OLD clientids
> for `15m` (`emqx.conf`). A cached grant for a name nothing uses any more is
> fifteen minutes of every client being refused on every topic, and with
> `deny_action = disconnect` that is a connect/drop loop, not an error message.
> `docker compose restart emqx` clears it immediately.
>
> The same release drops and recreates the identity tables — **users
> re-register**, and existing friendships and usernames do not survive. Paid
> subscriptions do (they are keyed by email hash), but each device re-links with
> the code flow. See the migration's own header for why a backfill was not the
> answer.

You do not run `docker compose` by hand, and the VM never builds. The agent does
it, from the stack directory it extracted out of the released image:

```bash
sudo systemctl start hqcat-agent.service     # deploy now instead of waiting
journalctl -u hqcat-agent.service -f
```

To inspect the running stack (note the path — `/opt/hqcat/<stack>`, not a checkout):

```bash
cd /opt/hqcat/prod
docker compose ps                                  # all healthy?
docker compose logs -f auth app-api
curl http://127.0.0.1:8090/health                  # auth         → ok
curl http://127.0.0.1:8091/health                  # app-api      → ok
curl http://127.0.0.1:8092/health                  # broker-watch → "unhealthy":[]
```

On production, application state is in the managed cluster, not on this box: the
only local volumes are the bot's identity (`bot-state`) and EMQX's mnesia
(`emqx-data`). Pre-prod adds `preprod-pgdata`, which is its whole database and is
meant to be disposable. Containers restart on crash/reboot (`restart:
unless-stopped`). Updating is not a thing you do here — merge, then Promote
(section 7), and the agent rolls it over within two minutes.

> **Container hardening already in `docker-compose.yml`:** every service runs
> with `no-new-privileges`, **all Linux capabilities dropped** (`cap_drop: ALL`),
> a **read-only root filesystem** (only the named volumes + a `/tmp` tmpfs are
> writable), a PID-1 `init` for signal/zombie handling, `pids_limit` + `mem_limit`
> + `cpus` caps, and rotated JSON logs (`max-size`/`max-file`). The server also
> runs as the non-root `node` user and binds only to `127.0.0.1`. **Tune `mem_limit`/`cpus` to your VM** — the defaults are
> conservative.
>
> **Pin images by digest** for reproducible, tamper-evident deploys. Resolve the
> current digest once and pin it, e.g.:
> ```bash
> docker buildx imagetools inspect emqx/emqx:5.8 --format '{{.Manifest.Digest}}'
> # then in docker-compose.yml:  image: emqx/emqx:5.8@sha256:<digest>
> ```
> Do the same for `node:22-bookworm-slim` in `services/server/Dockerfile`.

> **At-rest encryption for identity/graph data (DB-1).** Message bodies are
> ciphertext-only, but identity/graph data — public keys, usernames, the
> friendship graph, tiers, Stripe customer ids, push tokens — sits **plaintext**
> in the database. There is no application-level at-rest encryption, by design.
>
> This used to be a thing you had to arrange yourself, because the data was an
> AOF file on the droplet's disk. On production it no longer is: DigitalOcean
> encrypts managed cluster storage and its backups at rest, which is most of DB-1
> discharged by moving the data. (Pre-prod's container is back on the droplet's
> disk — acceptable, because it holds test accounts, not anyone's real graph.)
> What remains yours:
> - **In transit:** `sslmode=verify-full` against the cluster CA, so the
>   connection is both encrypted and authenticated. `lib/config.ts` warns in
>   production if the URL asks for anything weaker.
> - **Reach:** the trusted-sources firewall in
>   [`infra/database`](../../infra/database/README.md) names exactly one droplet,
>   production's. Verify from a laptop — `psql` against the public hostname must
>   time out, not prompt.
> - **Anything you copy off:** a `pg_dump` taken to a laptop is plaintext on that
>   laptop.

> **`/metrics` in production (SRV-2).** The endpoint exposes health/vitals
> topology. It was only ever served by the retired `/ws` monolith, so nothing in
> the current stack exposes it; the notes below apply if you re-introduce it.
> It binds to localhost only, **nginx does not proxy it**, and it **returns 404
> in production unless a token is set** (fail-closed). To allow authenticated
> scraping (e.g. a localhost Prometheus agent), create a token and wire it up:
> ```bash
> openssl rand -hex 32 > infra/deploy/secrets/metrics_token && chmod 600 infra/deploy/secrets/metrics_token
> ```
> then uncomment `METRICS_TOKEN_FILE`, the `- metrics_token` service secret, and
> the `metrics_token:` entry in `docker-compose.yml`, and scrape with
> `Authorization: Bearer <token>` (or `?token=<token>`).

### Helper bot

On first run the bot prints its public key. Add that to `EXEMPT_PUBLIC_KEYS` in
`infra/deploy/server.env` (so it bypasses the Stripe gate), then:

```bash
docker compose -f infra/deploy/docker-compose.yml restart bot
```

## 4. Cloudflare DNS + TLS (no certbot)

Cloudflare terminates the public TLS and proxies WebSockets automatically.

1. **Cloudflare → DNS:** add an `A` record (`@` or a subdomain) → VM IP,
   **Proxy status = Proxied (orange cloud)**.
2. **Cloudflare → SSL/TLS → Overview:** set mode to **Full (strict)** and enable
   **Always Use HTTPS**. (Do **not** use "Flexible" — the CF↔origin hop would be
   unencrypted.)
3. **Cloudflare → SSL/TLS → Origin Server → Create Certificate**, then save it:
   ```bash
   sudo mkdir -p /etc/ssl/cloudflare
   sudo nano /etc/ssl/cloudflare/origin.pem   # paste the certificate
   sudo nano /etc/ssl/cloudflare/origin.key   # paste the private key
   sudo chmod 600 /etc/ssl/cloudflare/origin.key
   ```
4. Install the nginx site:
   ```bash
   sudo cp deploy/nginx.conf /etc/nginx/sites-available/hqcat
   sudo sed -i 's/chat.example.com/YOUR_DOMAIN/g' /etc/nginx/sites-available/hqcat
   sudo ln -s /etc/nginx/sites-available/hqcat /etc/nginx/sites-enabled/hqcat
   sudo nginx -t && sudo systemctl reload nginx
   ```

> **Hardening already in `nginx.conf`:** HTTP/2, HSTS + `nosniff`/`DENY` headers,
> `server_tokens off`, a 1 MB request-body cap, a 20 r/s rate-limit on the HTTP
> API surface (WebSockets excluded), real client IP from `CF-Connecting-IP`, and
> a plain-:80 → HTTPS redirect.
>
> **Lock the origin to Cloudflare.** Anyone hitting the VM IP directly bypasses
> Cloudflare's WAF. Restrict :443 (and :80) to Cloudflare's published ranges,
> e.g. with ufw, or only allow Cloudflare in your cloud firewall:
> ```bash
> for ip in $(curl -s https://www.cloudflare.com/ips-v4); do sudo ufw allow from $ip to any port 443 proto tcp; done
> sudo ufw delete allow 443    # remove the open rule once CF rules are in
> ```
> Cloudflare's free plan supports WebSockets; its ~100s idle cutoff is covered by
> the app's 30s heartbeat. Keep the `set_real_ip_from` ranges in `nginx.conf`
> fresh from <https://www.cloudflare.com/ips/>.

## 5. Stripe donations

Donations fund the project. They grant nothing: every feature is free for every
account, no entitlement is recorded, and no payment is ever looked up again.
That is why this section is short — there is no claim flow, no device binding
and no revocation path to operate.

### Prices (in the Stripe dashboard, not in this repo)

No amount appears in the server source: it only ever names a Price id, and
Stripe decides what that costs. The **ids themselves are compiled in**
([`lib/donations-config.ts`](../../services/server/lib/donations-config.ts)), so
a host with an empty `server.env` charges correctly; the two variables are an
override for a fork pointing at its own Stripe account. Current deployment —
product `prod_VASN9Qoe1usGwM`:

| Price | Amount | Compiled in as | Overridden by |
|---|---|---|---|
| `price_1UA7SiKdAg16VdMqEwh5d0di` | €2 / month | `DEFAULT_DONATION_PRICE_IDS[0]` | `STRIPE_DONATION_PRICE_IDS` (1st) |
| `price_1UA7SiKdAg16VdMq6SgO0npz` | €5 / month | `DEFAULT_DONATION_PRICE_IDS[1]` | `STRIPE_DONATION_PRICE_IDS` (2nd) |
| `price_1UA7SiKdAg16VdMqFzizTrQV` | €15 / month | `DEFAULT_DONATION_PRICE_IDS[2]` | `STRIPE_DONATION_PRICE_IDS` (3rd) |
| `price_1UA7SiKdAg16VdMqlxdkR2Ib` | €10 one-time, **fixed** | `DEFAULT_DONATION_ONCE_PRICE_ID` | `STRIPE_DONATION_ONCE_PRICE_ID` |

A Price id is not a secret — it names a public thing to buy and is safe in a
client — and these four were already committed to this file. What the
env-only arrangement bought was a donate page depending on two lines of host
config invisible from the repo, and it is what took the buttons down.

`STRIPE_DONATION_PRICE_IDS` is comma-separated and **low to high** — that is the
order the donate page renders.

> **Why they are compiled in.** Leaving either variable unset never "simply did
> not offer" that option — it left a dead button on the page. The donate page
> visitors reach is the static Cloudflare Worker, which renders all three tiers
> and give-once unconditionally, because it cannot ask the server what is
> priced. An unset variable therefore showed the amounts and then refused the
> click.
>
> This is not hypothetical. Production ran with `DONATIONS_ENABLED=1` (set in
> compose, so it is on by default) and NEITHER price id in `server.env` — every
> button answered *"That option is not available. Go back and pick one of the
> amounts shown."* to a donor looking straight at the amounts. An empty or
> mangled override now falls back to the compiled-in Price rather than going
> dark. **Verify anyway after a host-config change or a price change**, because
> the one thing that can still break this is a Price archived in Stripe, which
> no config check can see:
>
> ```bash
> curl -s https://chat.example.com/donate/checkout | grep -c 'name="choice"'
> ```
>
> That path is the origin's own offer page and it asks Stripe for real labels,
> so it renders one button per *resolved* price — and because it asks, a label
> reading `monthly` instead of an amount means Stripe would not return that
> Price. Expect **4**. The boot log states the same verdict
> (`donations ready (3 monthly tier(s) + one-time)`), and a total absence is
> escalated to Sentry at startup.

`env_file` values are read when a container is **created**, not when it is
restarted, so editing `server.env` needs a recreate — `restart` re-runs the old
environment and looks like it worked:

```bash
cd /opt/hqcat/prod && docker compose up -d --force-recreate app-api
```

> **No price id lives in the site.** The donate buttons post an INDEX —
> `tier0`, `tier1`, … into `STRIPE_DONATION_PRICE_IDS` — and the server resolves
> it, the same way the one-time button posts `once`. So this deployment's Stripe
> account stays entirely in its own configuration, and a fork gets working
> buttons pointed at *its* prices. A test fails if a `price_…` string reappears
> in `apps/site/`.
>
> **What that makes load-bearing: the ORDER.** `apps/site/src/index.js` carries
> the display labels (`TIERS`, `ONE_TIME`) and must stay the same length and the
> same low-to-high order as `STRIPE_DONATION_PRICE_IDS`. Reorder one and not the
> other and a button charges the wrong tier. Two tests guard it — one asserts a
> button per configured price with contiguous indices, one asserts the labels
> ascend.
>
> **The one drift nothing can catch:** whether a label matches what Stripe
> actually charges. The site is a static Cloudflare Worker with no way to reach
> Stripe at render time, so an amount changed in Stripe and not in the label
> shows one number and charges another. (The origin-served fallback page in
> `services/web/donate.ts` *does* ask Stripe, via `tierLabels()`, so it is
> always right.)

**The one-time price is a fixed €10, not a donor-chosen amount.** Whether the
donor names the figure is a property of the Price: set `custom_unit_amount` on it
in Stripe and Checkout asks. Both work through the same code path. If you switch
it, update the site copy — several sentences on `/donate` name the €10.

A price id arriving from the public form is validated against the configured list
before it reaches Stripe, so a visitor cannot name a price of their own — the
same property the old hard-wired single price had for free. A stale id on the
site therefore fails safe: "that option is not available", not a wrong charge.

### Webhook

Stripe Dashboard → Developers → Webhooks → Add endpoint:

- URL: `https://YOUR_DOMAIN/stripe/webhook`
- Events: **`checkout.session.completed`, and nothing else.**

Do **not** subscribe `customer.subscription.*`. A lapsed recurring donation
removes no access, because it granted none; a handler for those events could
only do harm, and there is none.

The handler reads exactly one field off the completed session: the optional
display name for the supporters page. Not the email, not the customer id, not
the amount. That is what makes the site's strongest privacy claim true — **no
email address reaches this server in any form, not even a hash** — so keep it
that way.

Put the signing secret in `infra/deploy/secrets/stripe_webhook_secret`, then
`docker compose -f infra/deploy/docker-compose.yml up -d`. Test locally first:
`stripe listen --forward-to localhost:8091/stripe/webhook` (app-api owns
`/stripe/webhook`).

### Cancellation and refunds

There is no billing UI and no account area, by choice. Someone stops a recurring
donation through the customer-portal link in Stripe's own emails — enable the
portal in the dashboard so that link exists. Refunds are issued by hand from the
dashboard; `/terms` says we are not obliged to give one and would rather return
money than keep it from someone who regrets giving it.

### Routing

`/stripe/*`, `/donate/*` and `/supporters` are **app-api** (8091). Bare `/donate`
is a **Cloudflare Worker** route — the marketing page — while its sub-paths fall
through to the origin, because the Worker matches exact paths only. Adding
`/donate/*` to `worker_paths` would send checkout to the marketing site and break
it silently; `infra/cloudflare/variables.tf` rejects any `*` in that list for
exactly this reason.

(`/claim/*` used to be stated explicitly in `nginx.conf` because it was served by
**auth** (8090) while every other non-`/auth` path went to app-api. The claim
flow is gone, so the catch-all may have that path back.)

## 6. Point the apps at production

The client URLs are configurable (see `ServerConfig`):

- Add `ServerAuthURL`, `ServerAPIURL` and `ServerMQTTURL` to each target's
  Info.plist (`INFOPLIST_KEY_*`), pointing at `https://YOUR_DOMAIN/auth`,
  `https://YOUR_DOMAIN` and `wss://YOUR_DOMAIN/mqtt`, **or**
- Edit the Release fallbacks in `ServerConfig`.

<a name="releasing"></a>
## 7. Releasing (pull-based)

**GitHub never touches a server.** Each VM runs an agent that watches one GHCR
channel tag and rolls itself over when that tag's digest moves. There is no
`DEPLOY_SSH_KEY` in GitHub, no inbound SSH in the release path, and no git
checkout on any host.

```
  merge to main ──▶ Release workflow ──▶ ghcr.io/…/dissqus-server:sha-<12>
                                              │
                    Promote workflow ─────────┘  moves :prod onto that digest
                                              │
   prod VM: hqcat-agent (systemd timer, 2 min)┘
     digest changed ▶ pull ▶ extract /deploy-bundle ▶ compose up
     ▶ nginx ▶ health gate ▶ commit  (or roll back)
```

| Branch / action | Effect |
|---|---|
| push `preprod` | builds, moves `:preprod` → **pre-prod deploys itself** |
| push `main` | builds, publishes `:latest` + applies Cloudflare. **No rollout.** |
| run **Promote** | moves `:prod` onto a chosen `sha-<12>` → **prod deploys itself** |

### Releasing to production

1. On a Mac, if `apps/apple/` changed: `bash apps/apple/verify.sh` (CI does not
   build the Apple apps).
2. Actions → **Promote** → Run workflow. Leave `sha` blank for the tip of
   `main`, or paste an older SHA.
3. Watch it land: `journalctl -u hqcat-agent.service -f` on the VM.

Promote does not rebuild and does not re-run CI. It retags an existing manifest
server-side with `buildx imagetools create`, so the digest that reaches
production is byte-identical to the one the Release run built and smoke-tested.
Promoting something CI never built is impossible — the tag would not exist, and
the workflow fails with that message.

**Rolling back** is promoting an earlier SHA. The agent also rolls back on its
own: after `compose up` it polls `/health` on 8090 and 8091 for `HEALTH_TIMEOUT`
seconds (default 120) and, if the stack does not come up, restores the previous
release directory and image digest before failing the unit.

### Why this shape

The previous pipeline pushed releases over SSH with `appleboy/ssh-action`. That
required a long-lived private key in GitHub secrets, a `DEPLOY_HOST` that
duplicated the IP Terraform already knew, a full `git fetch && git reset --hard`
of the repository onto the server, and a manual `workflow_dispatch` per release.
All four are gone. What replaced them:

- **The image carries its own deploy bundle.** `/deploy-bundle` inside the
  server image holds `docker-compose.yml`, the pre-prod overlay, `nginx.conf`,
  `emqx/`, `scripts/` and `agent/`. Manifests can no longer drift from the
  binary they describe, and `hqcat-apply-nginx` keeps the integrity property it
  used to get from reading a committed git ref — the config comes from an
  immutable digest the host cannot edit.
- **Secrets live on the host**, in `/etc/hqcat/<stack>/secrets/` (root, 0700).
  They no longer round-trip through a CI runner. `sync-secrets-to-github.sh` is
  gone; use `infra/deploy/agent/set-host-secrets.sh` on the VM instead.
- **The only credential the VM holds** is a read-only `read:packages` GHCR
  token, in `/etc/hqcat/agent.env`. It cannot push images and cannot reach the
  repository.

### Standing up a host

Same for prod and pre-prod; only the stack and domain differ.

**From your laptop**, harden the box. `harden-vm.sh` is an operator tool, so pipe
it in rather than leaving a copy behind — and run it BEFORE any TOTP enrolment,
since it sets `KbdInteractiveAuthentication no`, which would disable the OTP path:

```bash
ssh root@HOST bash -s < infra/deploy/scripts/harden-vm.sh
```

**On the VM**, install the agent *out of the release image*. This is the whole
bootstrap; no repository is cloned at any point:

```bash
IMG=ghcr.io/YOUR-GITHUB-ACCOUNT/dissqus-server:prod
printf '%s' "$GHCR_READ_TOKEN" | docker login ghcr.io -u YOUR_GH_USER --password-stdin
docker pull "$IMG"
cid=$(docker create "$IMG")
docker cp "$cid:/deploy-bundle" /run/hqcat-bootstrap && docker rm "$cid"

/run/hqcat-bootstrap/agent/install-agent.sh prod chat.example.com
#   preprod: … install-agent.sh preprod preprod.chat.example.com

sudoedit /etc/hqcat/agent.env                 # add GHCR_USER / GHCR_TOKEN
/run/hqcat-bootstrap/agent/set-host-secrets.sh prod
sudoedit /etc/hqcat/prod/server.env

rm -rf /run/hqcat-bootstrap
```

`/run` is tmpfs, so the staging copy is gone on reboot even if that last line is
forgotten. Install the Cloudflare Origin cert at `/etc/ssl/cloudflare/origin.{pem,key}`
(section 4), then deploy without waiting for the timer:

```bash
sudo systemctl start hqcat-agent.service
journalctl -u hqcat-agent.service -f
```

From here the agent re-extracts the bundle from every release it deploys, so it
and its helper scripts stay current with no action from you.

> Chicken-and-egg: the bootstrap pulls `:prod`, so that tag must already exist.
> Merge to `main` (Release builds `:sha-<12>`) and run **Promote** once before
> standing up the first host.

### GitHub config

The app **secrets** that used to live in GitHub Environments are no longer read
by anything — **delete them** once the hosts have their own copies:
`STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `APNS_KEY_P8`, `BOT_SEED`, and all
four `DEPLOY_*` (plus `RESEND_API_KEY` and `OTP_PEPPER`, which nothing reads at
all any more). A live APNs `.p8` or Stripe
key sitting in a GitHub Environment is production key material readable by anyone
who can add a workflow — the exposure this model was built to remove.

Non-secret **variables** are the opposite: GitHub is where they belong. The
release workflow bakes an explicit list into `infra/deploy/release.env`, which
ships in the deploy bundle and reaches every host on its next rollover:

```
APNS_KEY_ID  APNS_TEAM_ID  APNS_TOPIC_IOS  APNS_TOPIC_MACOS  APNS_ENV  SENTRY_DSN
```

`SENTRY_DSN` is one value for all six server services — `initObservability()`
tags each event with its component, and `SENTRY_ENVIRONMENT` (per stack, in
compose) separates prod from preprod. A DSN can only *send*, so it is not a
secret. It ships inside the image, though: if the GHCR package is public, put it
in the host's `server.env` instead of a GitHub variable.

**Repository-level, not Environment-level.** One image is built and then promoted
to both `:preprod` and `:prod`, so it cannot carry an Environment's values — and
putting `environment: production` on the build job would gate every build behind
prod's protection rules. Anything that genuinely differs per stack goes in that
host's `server.env`, which compose reads *after* `release.env` and which therefore
wins — `APNS_ENV=sandbox` on a pre-prod box, for instance. The database credentials
were never in GitHub and must not be put there: they go from `terraform output`
straight to the host.

What GitHub still needs, on the `production` Environment, is only the Cloudflare
side: `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_API_TOKEN_USER`, `ORIGIN_IPV4`,
`PREPROD_ORIGIN_IPV4`, and the `R2_ACCESS_KEY_ID` /`CLOUDFLARE_ACCOUNT_ID` /
`CLOUDFLARE_ALERT_EMAIL` variables. `ORIGIN_IPV4` is now the single place the
prod IP is configured — `DEPLOY_HOST` used to hold the same value separately.

### Operating the agent

```bash
systemctl list-timers hqcat-agent.timer   # when the next poll is
systemctl start hqcat-agent.service       # poll now (no-op if the digest hasn't moved)
/opt/hqcat/<stack>/agent/hqcat-agent --reapply   # after editing server.env
journalctl -u hqcat-agent.service -n 100  # what it did
cat /var/lib/hqcat/prod/current           # digest currently deployed
cat /var/lib/hqcat/prod/history           # every rollout, timestamped
systemctl disable --now hqcat-agent.timer # freeze this host (e.g. during an incident)
```

## 8. Monitoring (optional, free)

UptimeRobot → HTTP(s) monitor on `https://YOUR_DOMAIN/health`, 5-min interval.

---

## PM2 alternative (no Docker)

Compose is the supported path; `deploy/ecosystem.config.js` was removed once it
had been superseded. To run bare-metal anyway, put **all** secrets inline in
`services/server/.env` (see `.env.example`), point `DATABASE_URL` at a Postgres
you run and apply the schema with `npm run migrate`, bring up an EMQX of your own (`infra/deploy/emqx/emqx.conf` is the config it expects),
and start the entrypoints directly:

```bash
pm2 start "node --import tsx auth/main.ts"   --name hqcat-auth   --cwd services/server
pm2 start "node --import tsx api/main.ts"    --name hqcat-api    --cwd services/server
pm2 start "node --import tsx push/main.ts"   --name hqcat-push   --cwd services/server
pm2 start "node --import tsx bot/bot.ts"     --name hqcat-bot    --cwd services/server
```

---

## Live test checklist

- Two profiles (iPhone + Mac, or two sims) connect over `wss://`.
- Send messages both ways; offline one client, send, reconnect → queued messages flush.
- Delivery ticks: ✓ when peer online, 🕐 queued when offline → flips on reconnect.
- Kill the broker (`docker compose stop emqx`) → clients show "Reconnecting…";
  `docker compose start emqx` → they recover (the client rotates its MQTT token
  on every reconnect).
- Subscription: unpaid profile shows the subscribe screen; after paying, the
  webhook flips the tier and a reconnect lets them in.
