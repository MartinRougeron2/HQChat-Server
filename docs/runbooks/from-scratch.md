# Deploying HQCAT from scratch

Everything from an empty DigitalOcean account to a serving production host, in
order, with the exact page to open at each step.

Read [the deploy runbook](deploy.md) for day-to-day operation and
[the architecture overview](../architecture/overview.md) for why it is shaped
this way. This document is the greenfield path only.

Budget about **two hours**, most of it waiting on installs. Do **pre-prod first**
— it is the same procedure and a much cheaper place to get something wrong.

---

## The automated path

**Actions → From scratch → Run workflow.** Give it the tokens from step 2, your
domain, a region and your SSH public key, and it does every step a cloud API can
do: the droplets, the R2 buckets, the GitHub secrets and variables, the cache
signing key, and both Terraform modules. It is idempotent — a run that fails half
way can just be run again.

Start with `apply: false`. That validates every credential and produces both
Terraform plans without changing any DNS. Note it still creates the buckets and
droplets, because neither plan can be produced without them: the database module
reads the production droplet by name, and the DNS records need its address.

What it cannot do is anything over SSH — installing NixOS, the origin
certificate, host secrets, TOTP. Nothing in GitHub is allowed to reach a host
(§0), and §6's second factor would break unattended SSH anyway. Those steps come
back as a **`bootstrap-hosts`** artifact on the run: a `bootstrap-hosts.sh` with
your IPs and outputs already filled in, which walks them in order.

```bash
gh run download <run-id> -n bootstrap-hosts && chmod +x bootstrap-hosts.sh && ./bootstrap-hosts.sh
```

> **The tokens are dispatch inputs**, which GitHub stores in plaintext in the
> run's event payload — readable by anyone with read access to this repo. Log
> masking does not cover that. Revoke and re-mint the DigitalOcean token and the
> GitHub PAT once bootstrap succeeds; the run summary reminds you.

The rest of this document is the manual path. Keep reading it anyway — the
workflow's summaries reference these sections by number, and this is where the
*why* lives.

---

## 0. What you are building

```
  you ──push──▶ GitHub ──▶ Release: test, build image, push to GHCR
                              │              (image carries /deploy-bundle)
                              ├──▶ Host: build NixOS closure ──▶ R2 cache
                              └──▶ Cloudflare: terraform apply (DNS, Worker, WAF)

  DigitalOcean droplet (NixOS)
       hqcat-host-agent  ──every 30 min──▶ R2 /channels/prod  → switch config
       hqcat-agent       ──every 2 min───▶ GHCR :prod tag     → compose up
```

Two things are worth understanding before you start, because they explain most
of the setup:

**Nothing in GitHub can reach your servers.** There is no deploy SSH key and no
inbound connection from CI. Each host *pulls* — the app from a GHCR tag, its own
OS config from an R2 bucket. So there is no `DEPLOY_HOST` to configure, and app
secrets never enter GitHub at all.

**No source code is ever placed on a server.** The app arrives as a container
image, the OS as a prebuilt Nix closure. You never clone the repo onto a box.

### Accounts and tools

| | |
|---|---|
| DigitalOcean | [cloud.digitalocean.com](https://cloud.digitalocean.com) — droplets |
| Cloudflare | [dash.cloudflare.com](https://dash.cloudflare.com) — DNS, TLS, R2, Workers |
| GitHub | repo + GHCR + Actions |
| Stripe, Resend, Apple | only if you use payments, email, or push |

Locally you need `gh`, `terraform` (≥1.10), `nix`, and `ssh`. On macOS:

```bash
brew install gh terraform && curl -L https://nixos.org/nix/install | sh
mkdir -p ~/.config/nix && printf 'experimental-features = nix-command flakes\n' >> ~/.config/nix/nix.conf
```

The second line is not optional. Every nix command in step 6 is `nix run` or
`--flake`, and the official installer enables neither feature — without it the
first one fails with `experimental Nix feature 'nix-command' is disabled`. The
Determinate installer (`curl -fsSL https://install.determinate.systems/nix | sh
-s -- install`) turns both on for you and needs no nix.conf.

---

## 1. DigitalOcean — create the droplets

> *✅ Automated by **From scratch** — both droplets, by the names the database module expects.*

**→ [cloud.digitalocean.com/account/security](https://cloud.digitalocean.com/account/security)**
Add your SSH public key first, so droplets come up with it installed.

**→ [cloud.digitalocean.com/droplets/new](https://cloud.digitalocean.com/droplets/new)**

| Setting | Value |
|---|---|
| Image | Ubuntu 24.04 LTS — *temporary*, NixOS replaces it in step 6 |
| Size | Basic → Regular → **2 GB / 1 vCPU** minimum (the stack runs EMQX and four Node services; the database is managed, not on the droplet) |
| Region | Near your users; the same one you will use for both hosts |
| Authentication | **SSH key**, not password |
| Hostname | `dissqus-prod` / `dissqus-preprod` |

DigitalOcean has no NixOS image — that is expected. You install Ubuntu and
convert it in place later.

Create **two** droplets. Note both public IPv4 addresses; you need them in
steps 4 and 5.

```bash
ssh root@<prod-ip> 'echo reachable'
```

---

## 2. Cloudflare — zone and API tokens

> *❌ Manual: tokens can only be minted in the dashboard. **From scratch** takes them as inputs.
> One addition to the list below when you use the workflow: the management token also needs
> Account → **Workers R2 Storage:Edit**, because the workflow creates the step 3 buckets.*

Your domain must already be on Cloudflare (nameservers delegated). Note the
**Zone ID** and **Account ID** from the zone's Overview page, bottom right.

### The management token

**→ [dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens)** →
Create Token → Create Custom Token.

Scopes (from `infra/cloudflare/providers.tf` — a scoped token, never a global key):

| Type | Permission |
|---|---|
| Zone | DNS → Edit |
| Zone | Zone Settings → Edit |
| Zone | Zone → Read |
| Zone | Workers Routes → Edit |
| Account | Workers Scripts → Edit |
| Zone | Health Checks → Edit *(only if you enable health checks)* |
| Account | Account Settings → Read, Notifications → Edit *(same)* |

Save the value — this is `CLOUDFLARE_API_TOKEN`.

### The R2 tokens

**→ [dash.cloudflare.com](https://dash.cloudflare.com) → R2 → Manage R2 API Tokens**

Create **two**, so that a leak of one is limited:

1. **Terraform state** — Object Read & Write on `your-tfstate-bucket`.
   You need both halves: the token **ID** (`R2_ACCESS_KEY_ID`) and its **value**
   (`CLOUDFLARE_API_TOKEN_USER`).
2. **Nix cache** — Object Read & Write on `dissqus-nix-cache`.
   You need both halves here too: the token **ID**
   (`R2_CACHE_ACCESS_KEY_ID`) and the **Secret Access Key** shown on creation
   (`R2_CACHE_SECRET_ACCESS_KEY`).

> Terraform derives its S3 secret as `SHA-256(token value)`, which is why it
> needs the token *value* and not the displayed secret key. The Nix cache uses
> the S3 credentials directly. They are genuinely different — do not mix them.

> **Each token's id goes with its own secret.** The Host workflow used to sign
> the cache upload with the *state* token's id and the *cache* token's secret,
> which R2 refuses — `Access Denied` on `nix-cache-info` — leaving the cache
> empty and every host with nothing to pull. `R2_ACCESS_KEY_ID` is the state
> token's; `R2_CACHE_ACCESS_KEY_ID` is the cache token's. If you would rather
> run one token for both buckets, set both variables to that token's id.

---

## 3. Cloudflare — R2 buckets

> *✅ Automated by **From scratch**, including the `cache.` custom domain.*

**→ R2 → Create bucket.** Two of them:

| Bucket | Public? | Holds |
|---|---|---|
| `your-tfstate-bucket` | **No** | Terraform state |
| `dissqus-nix-cache` | **Yes** | signed NixOS closures the hosts pull |

For `dissqus-nix-cache` → Settings → **Public access → Custom Domain** → add
`cache.<your-domain>`. Cloudflare creates the DNS record and serves it over
HTTPS free.

Public is safe here and is not an oversight: Nix refuses any store path that is
not signed by a key in its `trusted-public-keys`. A reader learns only which
packages you run; a writer still cannot make a host install anything, because
they do not have the signing key.

---

## 4. GitHub — environments, secrets, variables

> *✅ Automated by **From scratch**, which runs the same `set-ci-secrets.sh` shown below.*

**→ `https://github.com/<owner>/<repo>/settings/environments`** → New environment
→ `production`. Repeat for `preprod`.

> Optional but recommended on `production`: **Required reviewers**. Nothing in
> the pipeline breaks with it on — the plan-on-PR job is deliberately
> credential-free precisely so it never trips this gate.

Then, from a checkout:

```bash
gh secret set CLOUDFLARE_API_TOKEN        --env production   # step 2
gh secret set CLOUDFLARE_API_TOKEN_USER   --env production   # state token VALUE
gh secret set R2_ACCESS_KEY_ID            --env production   # state token ID
gh secret set R2_CACHE_SECRET_ACCESS_KEY  --env production   # cache secret key
gh secret set ORIGIN_IPV4                 --env production --body '<prod-ip>'
gh secret set PREPROD_ORIGIN_IPV4         --env production --body '<preprod-ip>'

gh variable set CLOUDFLARE_ACCOUNT_ID --env production --body '<account-id>'
gh variable set R2_ENDPOINT           --env production --body 'https://<account-id>.r2.cloudflarestorage.com'
gh variable set NIX_CACHE_BUCKET      --env production --body 'dissqus-nix-cache'
gh variable set R2_CACHE_ACCESS_KEY_ID --env production --body '<cache-token-id>'
gh variable set CLOUDFLARE_ZONE_NAME         --env production --body '<your-domain>'
gh variable set CLOUDFLARE_APP_HOST          --env production --body 'chat'
gh variable set CLOUDFLARE_PREPROD_HOST      --env production --body 'preprod.chat'
gh variable set CLOUDFLARE_WORKER_ROUTE_HOST --env production --body '<your-domain>'
gh variable set CLOUDFLARE_ALERT_EMAIL --env production --body 'you@example.com'   # optional
```

`NIX_CACHE_SIGNING_KEY` comes in step 6.

That is the complete list. **No app secrets and no `DEPLOY_*` here** — Stripe,
Resend, APNs and the OTP pepper live on the hosts (step 9), and the database
credentials come straight from Terraform (step 8). If you are migrating
from an older setup, delete any leftover `DEPLOY_HOST` / `DEPLOY_USER` /
`DEPLOY_PATH` / `DEPLOY_SSH_KEY`: nothing reads them, and while they exist an
environment without its own copies silently inherits them.

---

## 5. Cloudflare DNS via Terraform

> *✅ Automated by **From scratch**, including the existing-record import below.*

Edit `infra/cloudflare/terraform.tfvars` (copy the `.example`) — set
`zone_name`, `app_host`, `preprod_host`, `worker_route_host`.

```bash
cd infra/cloudflare
export CLOUDFLARE_API_TOKEN=...
export AWS_ACCESS_KEY_ID=<state token ID>
export AWS_SECRET_ACCESS_KEY=$(printf '%s' '<state token VALUE>' | sha256sum | cut -d' ' -f1)
terraform init -backend-config=backend.hcl
```

**If a `chat` A record already exists, import it first** or the apply fails
trying to create a duplicate:

```bash
ZONE=<zone-id>
curl -s -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  "https://api.cloudflare.com/client/v4/zones/$ZONE/dns_records?name=chat.<your-domain>" \
  | jq '.result[] | {id,name,content}'
terraform import 'cloudflare_record.app' "$ZONE/<record-id>"
```

```bash
terraform plan      # read it — this touches a shared zone
terraform apply
```

**→ Zone → SSL/TLS → Overview → set encryption mode to `Full (strict)`.**
This one is a dashboard click; the Terraform resource exists but
`manage_zone_settings` defaults off because the zone is shared with other
projects and Terraform would take ownership of settings they rely on.

---

## 6. NixOS — signing key, then install the hosts

> *⚡ Split: **From scratch** generates the signing key and opens a PR with its public half
> and your admin key. The install and the TOTP enrolment are steps 1 and 5 of `bootstrap-hosts.sh`.*

### Signing key

The public half is committed; the private half only ever exists as a GitHub
secret.

```bash
nix key generate-secret --key-name hqcat-cache-1 > cache-key.sec
nix key convert-secret-to-public < cache-key.sec        # → hqcat-cache-1:AAAA…
gh secret set NIX_CACHE_SIGNING_KEY --env production < cache-key.sec
rm cache-key.sec
```

Put the **public** key into `infra/nixos/modules/options.nix` as
`cachePublicKey`, then commit. Evaluation deliberately fails while it is still
the placeholder.

### Publish the first closure

Merge to `main` (or run the **Host** workflow manually). It builds, signs,
uploads and moves the channel pointer. Confirm:

```bash
curl -s https://cache.<your-domain>/channels/prod    # → /nix/store/…-nixos-system-…
```

### Who can log in

Before converting anything, put your public key in
[`infra/nixos/admin.nix`](../../infra/nixos/admin.nix):

```nix
hqcat.admin.sshKeys = [ "ssh-ed25519 AAAAC3Nz... you@laptop" ];
```

Evaluation fails while that list is empty — deliberately. Password
authentication is off and root is the only account, so a host built with no key
would be reachable only through the DigitalOcean web console.

**Nothing automated uses SSH.** The app and the OS are both pulled, so CI never
connects. That list is humans, and normally it is one key on one laptop.

### Convert the droplet

> **Destructive.** This replaces Ubuntu. Take a DigitalOcean snapshot first —
> droplet page → Snapshots → Take Snapshot.

```bash
cd infra/nixos
nix run github:nix-community/nixos-anywhere -- --flake .#preprod root@<preprod-ip>
```

It reboots into NixOS. Do pre-prod, confirm it works, then repeat with
`.#prod`.

```bash
ssh root@<ip> 'nixos-version && systemctl is-active hqcat-agent.timer hqcat-host-agent.timer'
```

---

### Add the second factor

Once the host is up and you have confirmed key-only SSH works, add TOTP. **Do it
in this order** — enabling it before enrolling locks you out of SSH, recoverable
only through the DigitalOcean web console.

```bash
# 1. Enrol root on the host. Scan the QR with your authenticator app and SAVE
#    the emergency scratch codes somewhere offline.
ssh root@<ip> -t 'google-authenticator -t -d -f -r 3 -R 30 -w 8'
```

The flags matter: `-w 8` accepts codes ±3.5 minutes out, which absorbs clock
drift on a droplet; `-r 3 -R 30` rate-limits attempts.

```bash
# 2. Prove it works while your CURRENT session is still open, so you have a way
#    back in if it does not.
ssh root@<ip> true      # from a NEW terminal
```

Then set `totp = true;` in `infra/nixos/admin.nix`, merge, and let the host
agent pick it up (or `systemctl start hqcat-host-agent.service`). From then on
SSH needs **both** your key and a code — `AuthenticationMethods
publickey,keyboard-interactive`, not one or the other.

> This is only practical because releases are pulled. The old push-based
> pipeline needed a key that worked unattended, so a second factor on SSH would
> have broken every deploy.

Repeat per host: TOTP enrolment is machine state, not configuration, so each
host needs its own `google-authenticator` run.

## 7. Cloudflare Origin certificate

> *➡️ Step 2 of `bootstrap-hosts.sh` (needs SSH).*

**→ Zone → SSL/TLS → Origin Server → Create Certificate.** Accept the defaults
(RSA, 15 years, covering `*.<domain>` and `<domain>`). **The private key is
shown exactly once** — save both halves before closing the page.

```bash
./infra/nixos/install-origin-cert.sh root@<ip> ~/origin.pem ~/origin.key
```

This validates the pair on your machine — wrong file type, empty file, or a cert
and key that do not match are rejected before anything touches the host — then
installs with the correct owner and mode, runs `nginx -t`, and reloads only if
the config is valid.

> **Before you do this the site returns Cloudflare error 526.** That is
> expected, not a fault. A host with no certificate would otherwise fail to
> start nginx, which would fail activation, which the host agent would read as a
> bad release — so it boots with a self-signed placeholder instead. 526 is the
> signal that the real certificate is still missing.

---

## 8. DigitalOcean — the production database

> *⚡ Split: **From scratch** applies the module; getting the credentials onto the host is
> step 3 of `bootstrap-hosts.sh`.*

The droplets hold no state. Everything the production backend knows — identities,
the friend graph, subscriptions, sessions, the MQTT topic ACL — lives in a managed
Postgres cluster, reachable **only** from the production droplet over the VPC's
private endpoint. [`infra/database`](../../infra/database/README.md) creates it.

**Pre-prod is not on it**, and that is deliberate: the load test every capacity
number in the architecture depends on runs there, and on a shared 1 vCPU cluster
it would saturate the one production sits on. Pre-prod runs its own `postgres:17`
container instead — nothing to provision, and step 9 generates its credentials.

```bash
cd infra/database
export DIGITALOCEAN_TOKEN=dop_v1_...
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...   # R2, for state
cp terraform.tfvars.example terraform.tfvars             # then edit
terraform init -backend-config=backend.hcl
terraform apply
```

It reads the production droplet by name — it does not create it — to learn which
VPC to join and which droplet id to trust.

**Prove the door is shut** before going further. From your laptop, which is not a
trusted source:

```bash
psql "postgresql://doadmin@$(terraform output -raw public_host):25060/defaultdb"
```

That must hang and time out. If it prompts for a password, the firewall is not
what you think it is.

Then put the four credentials on the production host, straight from
`terraform output`, never through GitHub:

```bash
terraform output -raw database_url        | ssh root@<prod-ip> "umask 077; cat > /etc/hqcat/prod/secrets/database_url"
terraform output -raw database_url_direct | ssh root@<prod-ip> "umask 077; cat > /etc/hqcat/prod/secrets/database_url_direct"
terraform output -raw pg_ca_cert          | ssh root@<prod-ip> "umask 077; cat > /etc/hqcat/prod/secrets/pg_ca_cert"
terraform output -raw emqx_pg             | ssh root@<prod-ip> "umask 077; cat > /etc/hqcat/prod/secrets/emqx_pg"
```

The schema is not applied by hand: the `db-migrate` one-shot in the compose stack
runs on every rollout, and everything else waits for it to succeed. A bad
migration therefore stops the deploy rather than producing a half-working stack.

The role names the migration grants to go in `server.env` in the next step:

```bash
terraform output -json app_roles | jq -r '"APP_ROLE=\(.app)\nEMQX_ROLE=\(.emqx)"'
```

> **One node, no standby.** Maintenance and any node failure are a full restart
> of the cluster — minutes of production downtime, during which MQTT clients are
> disconnected. `node_count = 2` fixes that (standby + ~10–30s failover, and a
> 99.95% SLA instead of 99.5%) and is an in-place change that does not recreate
> the cluster. Worth doing before the app has users who notice.

---

## 9. Host secrets

> *➡️ Step 4 of `bootstrap-hosts.sh` (needs SSH, and these never enter GitHub).*

These never enter GitHub.

```bash
for s in stripe_secret_key stripe_webhook_secret resend_api_key; do
  read -rsp "$s (blank to skip): " v; echo
  [ -n "$v" ] && printf '%s' "$v" | ssh root@<ip> "umask 077; cat > /etc/hqcat/prod/secrets/$s"
done
```

**The APNs key is not in that loop, and must not be.** `read` takes ONE LINE.
Apple's `.p8` is a multi-line PEM, so pasting it at that prompt stores
`-----BEGIN PRIVATE KEY-----` and throws the key away — leaving a file with the
right name, a plausible size, and no key in it. The symptom arrives much later
and points nowhere near here: `error:1E08010C:DECODER routines::unsupported`,
per push, from inside the signer. That is not hypothetical; this loop is how it
happened on prod.

Copy the file:

```bash
scp AuthKey_XXXXXXXXXX.p8 root@<ip>:/etc/hqcat/prod/secrets/apns_key_p8
ssh root@<ip> 'chmod 600 /etc/hqcat/prod/secrets/apns_key_p8 &&
               chown 1000:1000 /etc/hqcat/prod/secrets/apns_key_p8'
```

`set-host-secrets.sh` takes a path for this one for the same reason, and refuses
anything without both BEGIN and END markers.

Skipping is fine — every compose secret already exists as an empty file, so an
unused Stripe or APNs key will not stop the stack. The OTP pepper generates
itself on the host, and so do **pre-prod's** database credentials — that stack
runs its own postgres container, so `set-host-secrets.sh preprod` writes the
password and the URLs that embed it together, once. On **prod** the four database
files come from step 8 and must be real, or the stack stops at its migration
step.

Non-secret config:

```bash
ssh root@<ip> 'umask 077; cat > /etc/hqcat/prod/server.env' <<'ENV'
SERVER_NAME=DissQus
PUBLIC_BASE_URL=https://chat.<your-domain>
ADMISSION_POLICY=stripe
APP_ROLE=app_prod
EMQX_ROLE=emqx_prod
ENV
```

See [`.env.example`](../../infra/deploy/.env.example) for every key.

Most non-secret config does not belong here at all: `APNS_KEY_ID`,
`APNS_TEAM_ID`, `APNS_TOPIC_*`, `APNS_ENV` and `SENTRY_DSN` are GitHub
**repository variables**, baked into the release bundle and pulled by the agent.
Set them on the host only to override one stack — compose reads `server.env`
after the bundle, so the host always wins. See
[deploy.md § GitHub config](deploy.md#github-config).

**GHCR pull credentials.** Your package is private by default, so the host needs
a read-only token: **→ [github.com/settings/tokens](https://github.com/settings/tokens)**
→ classic token → **`read:packages` only**.

```bash
printf 'GHCR_USER=<you>\nGHCR_TOKEN=<token>\n' \
  | ssh root@<ip> 'umask 077; cat > /etc/hqcat/agent-auth.env'
```

Or make the package public at
**→ `https://github.com/<owner>?tab=packages`** → package → Package settings →
Change visibility, and skip the token.

---

## 10. First release

> *❌ Manual, deliberately: running Promote **is** the human gate.*

Nothing has been deployed yet — the `:prod` channel tag does not exist.

1. Merge to `main`. **Release** builds and pushes `:sha-<12>`.
2. **→ Actions → Promote → Run workflow**, target `prod`. This moves the tag.
3. The agent picks it up within two minutes:

```bash
ssh root@<ip> 'systemctl start hqcat-agent.service && journalctl -u hqcat-agent.service -f'
```

You should see it resolve the tag, pull, extract `/deploy-bundle`, run compose,
and pass the health gate.

Pre-prod needs no promote — a push to the `preprod` branch moves `:preprod`
directly.

> **Out of Actions minutes?** Build the first image locally instead:
> ```bash
> SHA=$(git rev-parse HEAD); docker buildx build --platform linux/amd64 \
>   --build-context deploy=infra/deploy \
>   -t ghcr.io/<owner>/dissqus-server:sha-${SHA:0:12} \
>   -t ghcr.io/<owner>/dissqus-server:prod --push services/server
> ```
> On Apple Silicon this is qemu-emulated and slow. One-time only.

---

## 11. Verify

> *➡️ Step 6 of `bootstrap-hosts.sh` runs all of these.*

```bash
curl -sS https://chat.<your-domain>/health                     # → ok
ssh root@<ip> 'cd /opt/hqcat/prod && docker compose ps'        # all healthy
ssh root@<ip> 'curl -sS localhost:8092/health'                 # → "unhealthy":[]
dig +short chat.<your-domain>                                  # → Cloudflare IPs, not your origin
ssh root@<ip> 'cat /var/lib/hqcat/prod/current'                # deployed digest
```

That last check on `8092` is the one worth not skipping: EMQX keeps its own
Postgres and auth links, and both can be broken while every other service reports
healthy.

---

## 12. Afterwards

| Task | How |
|---|---|
| Ship the app | merge → **Promote** |
| Ship host config | merge `infra/nixos/**` → hosts switch within 30 min |
| Roll back the app | **Promote** an older SHA |
| Roll back a host | put an older store path in `s3://dissqus-nix-cache/channels/prod` |
| Watch a rollout | `journalctl -u hqcat-agent -f` / `-u hqcat-host-agent -f` |
| Freeze a host | `systemctl disable --now hqcat-agent.timer` |

### When something is wrong

| Symptom | Cause |
|---|---|
| Cloudflare **526** | Origin certificate missing or not trusted — step 7 |
| Cloudflare **521/522** | Origin down, or the firewall is not allowing Cloudflare. `systemctl status nginx`, `nft list ruleset` |
| Agent logs `cannot pull` | GHCR token missing or expired — step 9 |
| SSH asks for a code you cannot supply | TOTP was enabled before enrolling. Recover via the DigitalOcean droplet console, run `google-authenticator`, or set `totp = false` and redeploy |
| Host agent logs `cannot reach` | `cache.<domain>` not resolving, or the bucket is not public — step 3 |
| Host workflow: `Access Denied` uploading `nix-cache-info` | The cache upload is signed with two halves of different R2 tokens. `R2_CACHE_ACCESS_KEY_ID` must be the id of the token whose secret is in `R2_CACHE_SECRET_ACCESS_KEY` — step 4 |
| `docker compose up` fails on a secret | a secret file is missing; `ls -l /etc/hqcat/prod/secrets/` |
| Stack stops, `db-migrate` exits non-zero | the database credentials are empty or wrong, or the cluster is unreachable. `docker compose logs db-migrate`, then re-check step 8 |
| `broker-watch` reports `authz-pg` disconnected | EMQX's own database link is down — its credentials are a separate file (`emqx_pg`) from the services'. This is an incident: `deny_action = disconnect` drops every client that touches a topic |
| Terraform: record already exists | import it — step 5 |
| Terraform: `no zone found`, plan shows `*.example.com` | The zone/host variables are not set on the environment. `terraform.tfvars` is gitignored, so CI cannot read it — step 4 |
