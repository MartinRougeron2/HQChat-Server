#!/usr/bin/env bash
#
# set-host-secrets.sh — put a stack's secrets on the machine that runs it.
#
# Run this ON the VM (root). It replaces sync-secrets-to-github.sh, which pushed
# the same values into GitHub Environments so a CI runner could write them back
# onto the box over SSH. Nothing does that any more: the agent pulls releases and
# reads secrets from local disk, so production Stripe/APNs/Resend material never
# enters GitHub, never passes through a runner, and is never in reach of anyone
# with repo access.
#
#   sudo infra/deploy/agent/set-host-secrets.sh prod
#
# Values are read from the environment and prompted for when unset, so nothing
# lands in shell history. Existing values are kept unless you supply a new one.
set -euo pipefail

STACK="${1:?usage: set-host-secrets.sh <prod|preprod>}"
case "$STACK" in prod|preprod) ;; *) echo "❌ stack must be prod|preprod" >&2; exit 1 ;; esac
[[ $EUID -eq 0 ]] || { echo "❌ run with sudo/root" >&2; exit 1; }

DIR="/etc/hqcat/$STACK/secrets"
mkdir -p "$DIR"; chmod 700 "/etc/hqcat" "/etc/hqcat/$STACK" "$DIR"

# put <file> <env-var> <description> [optional|generate]
put() {
  local file="$1" var="$2" desc="$3" mode="${4:-}" val="${!2:-}" path="$DIR/$1"
  if [[ -z "$val" && -s "$path" ]]; then echo "·  keep    $file"; return; fi
  if [[ -z "$val" && "$mode" == generate ]]; then
    openssl rand -hex 32 > "$path"; chmod 600 "$path"; echo "🎲 generate $file"; return
  fi
  if [[ -z "$val" ]]; then read -r -s -p "  $desc ($var, blank to skip): " val; echo; fi
  if [[ -z "$val" ]]; then
    if [[ "$mode" == optional ]]; then : > "$path"; chmod 600 "$path"; echo "⏭  empty   $file"; return; fi
    echo "❌ $var is required" >&2; exit 1
  fi
  printf '%s' "$val" > "$path"; chmod 600 "$path"; echo "🔐 wrote   $file"
}

# --- Database ---------------------------------------------------------------
# The two stacks get their database from different places, which is why this is
# the one section that branches on $STACK:
#
#   prod    — a managed cluster (infra/database). Credentials come from
#             `terraform output`, not from anyone's memory, and are NOT optional:
#             a stack with an empty DATABASE_URL has no state at all.
#   preprod — a postgres container on this host. Nothing external issues those
#             credentials, so they are generated here, once, and must persist:
#             postgres bakes the password in at initdb time, so the password file
#             and the URLs that embed it have to be written together and must not
#             drift from the data volume.
if [[ "$STACK" == preprod ]]; then
  PWFILE="$DIR/pg_local_password"
  if [[ ! -s "$PWFILE" ]]; then
    openssl rand -hex 24 > "$PWFILE"; chmod 600 "$PWFILE"
    echo "🎲 generate pg_local_password"
    # The volume may predate this password. Say so rather than let postgres come
    # up rejecting a connection string that looks correct.
    echo "   ⚠️  if a preprod-pgdata volume already exists it was initialised with"
    echo "      a different password — 'docker volume rm dissqus-preprod_preprod-pgdata' to reset."
  else
    echo "·  keep    pg_local_password"
  fi
  PW="$(cat "$PWFILE")"
  URL="postgresql://hqcat:$PW@postgres:5432/hqcat?sslmode=disable"
  printf '%s' "$URL" > "$DIR/database_url"
  printf '%s' "$URL" > "$DIR/database_url_direct"
  # Empty: the local container speaks plain postgres, so there is nothing to
  # verify. pg.ts falls back to an unencrypted connection when the CA is empty.
  : > "$DIR/pg_ca_cert"
  {
    echo "AUTHZ_PG_SERVER=postgres:5432"
    echo "AUTHZ_PG_DATABASE=hqcat"
    echo "AUTHZ_PG_USERNAME=hqcat"
    echo "AUTHZ_PG_PASSWORD=$PW"
    echo "AUTHZ_PG_SSL=false"
  } > "$DIR/emqx_pg"
  chmod 600 "$DIR/database_url" "$DIR/database_url_direct" "$DIR/pg_ca_cert" "$DIR/emqx_pg"
  echo "🔐 wrote   database_url, database_url_direct, pg_ca_cert, emqx_pg (local container)"
else
  # See infra/database/README.md for the one-liners that pipe these in from a
  # laptop straight out of `terraform output`.
  put database_url        DATABASE_URL          "DATABASE_URL (pooler endpoint)"
  put database_url_direct DATABASE_URL_DIRECT   "DATABASE_URL_DIRECT (migrations)"
  put pg_ca_cert          PG_CA_CERT            "Postgres cluster CA (PEM)"
  put emqx_pg             EMQX_PG               "EMQX authz DB creds (AUTHZ_PG_* assignments)"
fi

# --- Everything else --------------------------------------------------------
# The remaining compose `secrets:`. Every one must exist as a file or
# `docker compose up` fails — hence the empty placeholders.
put stripe_secret_key     STRIPE_SECRET_KEY     "Stripe secret key"        optional
put stripe_webhook_secret STRIPE_WEBHOOK_SECRET "Stripe webhook secret"    optional
put resend_api_key        RESEND_API_KEY        "Resend API key"           optional
put apns_key_p8           APNS_KEY_P8           "APNs .p8 key contents"    optional
# Pepper for stored OTP hashes: without it a database dump yields every pending
# claim code. Generated here if absent, and never rotated silently.
put otp_pepper            OTP_PEPPER            "OTP pepper (32-byte hex)" generate

ENVFILE="/etc/hqcat/$STACK/server.env"
if [[ ! -f "$ENVFILE" ]]; then
  printf '# Non-secret config for the %s stack. See infra/deploy/.env.example.\n' "$STACK" > "$ENVFILE"
  chmod 600 "$ENVFILE"
  echo "📝 created $ENVFILE — fill in SERVER_NAME / PUBLIC_BASE_URL / ADMISSION_POLICY / APNS_* / STOREKIT_*"
fi

cat <<EOF

✅ Secrets in place for '$STACK'. They stay on this host.

The agent symlinks them into the stack directory on its next run:
  systemctl start hqcat-agent.service
EOF
