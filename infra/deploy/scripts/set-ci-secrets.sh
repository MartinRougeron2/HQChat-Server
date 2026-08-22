#!/usr/bin/env bash
#
# set-ci-secrets.sh — set the INFRA/CI secrets + variables a GitHub Environment
# needs for the Cloudflare Terraform step of the deploy pipeline
# (the `cloudflare` job in .github/workflows/release.yml).
#
# App secrets (STRIPE_*, RESEND_API_KEY, OTP_PEPPER, APNS_*) do NOT belong in
# GitHub any more: deploys are pull-based, so they live on the host that uses
# them (infra/deploy/agent/set-host-secrets.sh). This script covers only the
# Cloudflare + R2 state side, which Terraform genuinely needs in CI.
#
# Reads values from the environment (prompts if a required one is unset), so
# nothing is hardcoded or echoed into shell history. Usage:
#
#   CLOUDFLARE_API_TOKEN=...        # management token (provider)
#   CLOUDFLARE_API_TOKEN_USER=...   # R2 bucket token VALUE (state)
#   R2_ACCESS_KEY_ID=...            # the R2 token's ID (Access Key ID; not secret)
#   ORIGIN_IPV4=...                 # prod VM public IPv4
#   PREPROD_ORIGIN_IPV4=...         # pre-prod VM public IPv4 (its OWN host; optional)
#   CLOUDFLARE_ACCOUNT_ID=... \
#   infra/deploy/scripts/set-ci-secrets.sh production
#
set -euo pipefail
ENVIRONMENT="${1:-production}"

command -v gh >/dev/null || { echo "❌ install the GitHub CLI: https://cli.github.com" >&2; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "❌ run: gh auth login" >&2; exit 1; }
REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
gh api -X PUT "repos/$REPO/environments/$ENVIRONMENT" >/dev/null
echo "→ repo $REPO   environment $ENVIRONMENT"

# prompt VAR "description" [secret?]
need() {
  local var="$1" desc="$2"; local val="${!1:-}"
  if [[ -z "$val" ]]; then read -r -p "  $desc ($var): " val; fi
  [[ -n "$val" ]] || { echo "❌ $var is required" >&2; exit 1; }
  printf -v "$var" '%s' "$val"
}

need CLOUDFLARE_API_TOKEN      "Cloudflare MANAGEMENT token (provider)"
need CLOUDFLARE_API_TOKEN_USER "R2 bucket token VALUE (state backend)"
need R2_ACCESS_KEY_ID          "R2 token ID (Access Key ID; not secret)"
need ORIGIN_IPV4               "PROD VM public IPv4 (origin)"
# Optional: pre-prod lives on its own VM. Unset ⇒ Terraform skips the record.
PREPROD_ORIGIN_IPV4="${PREPROD_ORIGIN_IPV4:-}"
need CLOUDFLARE_ACCOUNT_ID     "Cloudflare account id"
CLOUDFLARE_ALERT_EMAIL="${CLOUDFLARE_ALERT_EMAIL:-}"

# Secrets
for s in CLOUDFLARE_API_TOKEN CLOUDFLARE_API_TOKEN_USER ORIGIN_IPV4; do
  printf '%s' "${!s}" | gh secret set "$s" --env "$ENVIRONMENT"
  echo "🔐 secret  $s"
done
if [[ -n "$PREPROD_ORIGIN_IPV4" ]]; then
  printf '%s' "$PREPROD_ORIGIN_IPV4" | gh secret set PREPROD_ORIGIN_IPV4 --env "$ENVIRONMENT"
  echo "🔐 secret  PREPROD_ORIGIN_IPV4"
else
  echo "⏭  PREPROD_ORIGIN_IPV4 unset — Terraform will skip the preprod.chat record"
fi

# Variables (non-secret)
gh variable set R2_ACCESS_KEY_ID --env "$ENVIRONMENT" --body "$R2_ACCESS_KEY_ID"
echo "📋 variable R2_ACCESS_KEY_ID"
gh variable set CLOUDFLARE_ACCOUNT_ID --env "$ENVIRONMENT" --body "$CLOUDFLARE_ACCOUNT_ID"
echo "📋 variable CLOUDFLARE_ACCOUNT_ID"
if [[ -n "$CLOUDFLARE_ALERT_EMAIL" ]]; then
  gh variable set CLOUDFLARE_ALERT_EMAIL --env "$ENVIRONMENT" --body "$CLOUDFLARE_ALERT_EMAIL"
  echo "📋 variable CLOUDFLARE_ALERT_EMAIL"
fi

cat <<EOF

✅ Cloudflare/Terraform CI secrets set on '$ENVIRONMENT'.
   This is ALL GitHub needs. App secrets and the deploy target live on the VMs:
     sudo infra/deploy/agent/install-agent.sh <prod|preprod> <domain>
     sudo infra/deploy/agent/set-host-secrets.sh <prod|preprod>
EOF
