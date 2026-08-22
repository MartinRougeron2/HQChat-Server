# Cloudflare — Infrastructure as Code (Terraform)

Single source of truth for **everything Cloudflare**: DNS, zone TLS/security
posture, the marketing/legal **Worker** + its routes, edge **rate limiting** +
**WAF** rules, and an origin **health check**. Pairs with the GitHub→GHCR→VM app
deploy (../../deploy/ARCHITECTURE.md).

> **`example.com` is a SHARED zone** (Vercel apex + `backend`/`bbia`/`yt` +
> Cloudflare Email). This module is deliberately **surgical**: it manages only the
> DissQus records and the Worker's legal-page routes. Zone-wide settings (SSL/HSTS,
> WAF/rate-limit entrypoints) are **off by default** so an apply can never break
> your other projects. Turn them on only after dedicating a zone or confirming the
> blast radius.

## What it manages

| File | Resources | Default |
|------|-----------|---------|
| `dns.tf` | `chat` (import) A → prod origin + `preprod.chat` (create) A → the **separate** pre-prod VM, both proxied | on |
| `workers.tf` | `dissqus-home` Worker (from `apps/web/src/index.js`) + routes for `/privacy`,`/terms`,`/support` on the apex (overlays Vercel; **not** `/`) | on |
| `zone.tf` | Full-strict SSL, Always-HTTPS, TLS 1.2/1.3, HSTS, WebSockets | **off** (`manage_zone_settings`) — zone-wide |
| `security.tf` | WAF scanner blocks (`manage_security_rules`) + per-IP rate limiting (`enable_rate_limiting`, Pro) — both host-scoped to `chat` | **off** — zone-wide entrypoints |
| `health.tf` | Standalone Health Check on **origin `/health`** + email alert | **off** (`enable_health_check`, Pro) |

**Not managed (other projects):** apex `@`, `www`, `backend`, `bbia`, `yt`, MX/TXT.
**Stay on origin:** `/health`, `/ws`, `/stripe/webhook`, `/claim/*` (rate limits
and OTP state live in the database, which only the origin can reach). Other stateless endpoints (`/info`, `/subscribe`)
can migrate to the Worker later — stub in `workers.tf`. No Durable Objects.

## Usage

```bash
cd infra/cloudflare
export CLOUDFLARE_API_TOKEN=...           # scoped token (scopes in providers.tf)
cp terraform.tfvars.example terraform.tfvars   # fill account_id, origin_ipv4, …

terraform init
terraform plan
terraform apply
```

### Importing what already exists

The `chat` A record already exists, so **import it before the first apply** or
Terraform errors trying to create a duplicate (preprod is new — TF creates it):

```bash
ZONE=da2b21154d4f275b8bb107ac01d6d6ba
# Find the chat record id:
curl -s -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  "https://api.cloudflare.com/client/v4/zones/$ZONE/dns_records?name=chat.example.com" \
  | jq '.result[] | {id,name,content,proxied}'

terraform import 'cloudflare_record.app' "$ZONE/<chat_record_id>"
# If the dissqus-home Worker was ever `wrangler deploy`d, adopt it too:
terraform import 'cloudflare_workers_script.site[0]' '<account_id>/dissqus-home'
```
If you enable the zone-wide toggles later, import those first as well
(`cloudflare_zone_settings_override.this[0]`, the WAF ruleset).

### Remote state (Cloudflare R2)

State lives in an R2 bucket (S3-compatible) so CI and humans share one source of
truth and never race. Non-secret backend settings are in `backend.hcl`; the R2
credentials come from the environment.

**Two tokens, two jobs** (neither is a global/"big" token):
- **`CLOUDFLARE_API_TOKEN`** — the *management* token the Terraform provider uses
  for DNS/Workers/zone (scopes in `providers.tf`).
- **`CLOUDFLARE_API_TOKEN_USER`** — the *R2 bucket* token, used only for state.
  The S3 backend needs an Access Key ID + Secret, which Cloudflare **derives** from
  this token: `Access Key ID = the token's ID`, `Secret Access Key = SHA-256(token value)`.

**One-time bootstrap:**

```bash
# 1. Enable R2, then create the state bucket:
npx wrangler r2 bucket create your-tfstate-bucket
# 2. Create an R2 API token (R2 → Manage API Tokens → "Object Read & Write",
#    scoped to the your-tfstate-bucket bucket). Note its Token ID and Token value.
export CLOUDFLARE_API_TOKEN=<management token>          # provider
export AWS_ACCESS_KEY_ID=<r2 token ID>                  # = Access Key ID
export AWS_SECRET_ACCESS_KEY=$(printf '%s' '<r2 token value>' | shasum -a 256 | cut -d' ' -f1)
# 3. Migrate the existing local state into R2:
terraform init -backend-config=backend.hcl -migrate-state
```
(Cloudflare shows the Access Key ID + Secret directly on the token screen too —
you can paste those instead of deriving. On Linux use `sha256sum` not `shasum -a 256`.)

After that, everyone runs `terraform init -backend-config=backend.hcl` (creds
exported) and `plan`/`apply` against shared, locked state.

### CI

There is no separate Cloudflare workflow any more — the edge applies as part of
the deploy pipeline, so a release never leaves DNS/routes and the origin they
point at out of step:

- **`ci.yml` → `cloudflare-plan`** — on PRs touching `infra/cloudflare/**` or
  `apps/web/src/**`. Runs `fmt`/`init -backend=false`/`validate`. Deliberately
  credential-free: the creds are Environment secrets, and attaching
  `environment: production` to a PR job would make every PR wait on the
  required-reviewer gate for a read-only operation (and would expose a
  write-scoped token to fork PRs). `validate` is what catches the breakage that
  actually happened here — a moved file making the module unloadable.
- **`release.yml` → `cloudflare`** — on `main`. Runs `init`/`validate`/`plan`
  (diff visible in the log) then `apply`, **before** the VM rollout jobs.

It derives the R2 S3 creds from the token at runtime. Required GitHub config on
the **production** Environment:

| Kind | Name | Value |
|------|------|-------|
| secret | `CLOUDFLARE_API_TOKEN` | management token (provider) |
| secret | `CLOUDFLARE_API_TOKEN_USER` | R2 bucket token **value** (state) |
| secret | `ORIGIN_IPV4` | the prod VM IP (`TF_VAR_origin_ipv4`) |
| secret | `PREPROD_ORIGIN_IPV4` | the pre-prod VM IP (`TF_VAR_preprod_origin_ipv4`); omit to skip the record |
| variable | `R2_ACCESS_KEY_ID` | the R2 token's **ID** (Access Key ID — not secret). The workflow reads it from `vars` *or* `secrets`, since it has been set both ways. |
| variable | `CLOUDFLARE_ACCOUNT_ID` | `3af5c2d5…` |
| variable | `CLOUDFLARE_ALERT_EMAIL` | (optional) health-alert email |

Set them quickly with [`../deploy/scripts/set-ci-secrets.sh`](../deploy/scripts/set-ci-secrets.sh).

## Notes / plan requirements
- **Pro-plan features are written but default OFF** so a Free `apply` works:
  edge **rate limiting** (`security.tf`) and the **Health Check + alert**
  (`health.tf`). After upgrading the zone to Pro, set `enable_rate_limiting =
  true` and `enable_health_check = true`. Everything else (DNS, zone TLS/HSTS,
  Workers, WAF custom rules) is Free-compatible and active.
- The Worker is deployed straight from source (no build step); `wrangler dev`
  still works for local iteration, but **don't** `wrangler deploy` and `terraform
  apply` the same script — pick Terraform as the deployer to avoid drift.
- The provider is pinned to **v4** (`versions.tf`); v5 renamed several resources.
