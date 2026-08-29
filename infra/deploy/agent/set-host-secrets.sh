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
# ⚠️ Values left behind in GitHub from that era are NOT read by anything — no
# workflow references APNS_*, STRIPE_* or RESEND_* — but a real APNs .p8 or
# Stripe key still sitting in a GitHub Environment is live production material
# reachable by anyone with repo access, which is the exact exposure this model
# removed. Revoke and delete them at the source rather than leaving them as
# apparent configuration; they will mislead the next person who goes looking for
# where a value comes from.
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

# 32 random bytes as hex, without openssl. It is not on PATH on the NixOS hosts:
# nothing installs it globally (modules/default.nix forces
# environment.defaultPackages empty on purpose), and the units that need it carry
# it in their own systemd `path`. This script is scp'd and run over SSH, so it
# gets the plain login environment and has to stand on its own -- and it also has
# to work on the Ubuntu droplet, before NixOS is installed. /dev/urandom and
# coreutils are on both.
rand_hex() { od -vAn -N"$1" -tx1 < /dev/urandom | tr -d ' \n'; }

# 0600, owned by the uid the containers run as. Compose bind-mounts these into
# /run/secrets with the host's owner and mode intact, and every service that
# reads one runs as uid 1000 -- `node` in the server image, `emqx` in
# emqx/emqx:5.8. Root-owned 0600 is unreadable to them, and the stack halts on
# db-migrate with EACCES. This is ownership, not a loosening: the mode is
# unchanged, and no user other than root exists on these hosts.
own() { chmod 600 "$1"; chown 1000:1000 "$1" 2>/dev/null || true; }

# Multi-line secrets cannot come through `read`.
#
# `read -r -s -p` takes ONE line. For a Stripe key that is right; for a PEM it
# is silently destructive — pasting Apple's .p8 at that prompt keeps
# `-----BEGIN PRIVATE KEY-----` and throws the key away. The file that results
# is a plausible size, has the right name, and produces
# `error:1E08010C:DECODER routines::unsupported` from OpenSSL on every push,
# hours later, with nothing pointing back here.
#
# So a PEM is taken as a PATH, not as a paste, and validated before it is
# stored. Reading it from disk also means it never appears on a terminal.
put_pem() { # put_pem <file> <env-var-holding-a-path-or-pem> <description>
  local file="$1" var="$2" desc="$3" val="${!2:-}" path="$DIR/$1" src
  if [[ -z "$val" && -s "$path" ]]; then echo "·  keep    $file"; return; fi
  if [[ -z "$val" ]]; then
    read -r -p "  $desc — PATH to the file (blank to skip): " val || true
  fi
  if [[ -z "$val" ]]; then : > "$path"; own "$path"; echo "⏭  empty   $file"; return; fi

  if [[ -f "$val" ]]; then src="$val"
  else
    # A value rather than a path: accept it, but only if it looks like the whole
    # key. This is where the truncated paste gets caught instead of stored.
    src="$(mktemp)"; printf '%s' "$val" > "$src"
  fi

  if ! grep -q "BEGIN PRIVATE KEY" "$src" || ! grep -q "END PRIVATE KEY" "$src"; then
    echo "❌ $file: not a complete PKCS#8 PEM (needs both BEGIN and END PRIVATE KEY)." >&2
    echo "   Apple's .p8 is multi-line — give the PATH to it, do not paste it." >&2
    [[ "$src" == "$val" ]] || rm -f "$src"
    exit 1
  fi
  cp "$src" "$path"; own "$path"
  [[ "$src" == "$val" ]] || rm -f "$src"
  echo "🔐 wrote   $file ($(wc -l < "$path" | tr -d " ") lines)"
}

# put <file> <env-var> <description> [optional|generate]
put() {
  local file="$1" var="$2" desc="$3" mode="${4:-}" val="${!2:-}" path="$DIR/$1"
  if [[ -z "$val" && -s "$path" ]]; then echo "·  keep    $file"; return; fi
  if [[ -z "$val" && "$mode" == generate ]]; then
    rand_hex 32 > "$path"; own "$path"; echo "🎲 generate $file"; return
  fi
  if [[ -z "$val" ]]; then read -r -s -p "  $desc ($var, blank to skip): " val; echo; fi
  if [[ -z "$val" ]]; then
    if [[ "$mode" == optional ]]; then : > "$path"; own "$path"; echo "⏭  empty   $file"; return; fi
    echo "❌ $var is required" >&2; exit 1
  fi
  printf '%s' "$val" > "$path"; own "$path"; echo "🔐 wrote   $file"
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
    rand_hex 24 > "$PWFILE"; own "$PWFILE"
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
put_pem apns_key_p8       APNS_KEY_P8           "APNs signing key (.p8)"
# Pepper for stored OTP hashes: without it a database dump yields every pending
# claim code. Generated here if absent, and never rotated silently.
put otp_pepper            OTP_PEPPER            "OTP pepper (32-byte hex)" generate

ENVFILE="/etc/hqcat/$STACK/server.env"
if [[ ! -f "$ENVFILE" ]]; then
  printf '# Non-secret config for the %s stack. See infra/deploy/.env.example.\n' "$STACK" > "$ENVFILE"
  chmod 600 "$ENVFILE"
  echo "📝 created $ENVFILE — fill in SERVER_NAME / PUBLIC_BASE_URL / ADMISSION_POLICY / STOREKIT_*"
fi

# --- APNs: does anything actually supply the ids? ---------------------------
#
# The .p8 above is a secret and lives here. APNS_KEY_ID, APNS_TEAM_ID, the bundle
# ids and APNS_ENV are NOT secrets, and GitHub owns them: the release workflow
# bakes repository variables into the bundle (release.env) that the agent pulls,
# and compose reads that BEFORE server.env so this host can still override.
#
# So this script does not prompt for them — it checks. A host that holds a key
# and has no ids from either source sends nothing, silently, which is the state
# that made push look broken for months.
say_apns() {
  local bundle="/opt/hqcat/$STACK/release.env" env="/etc/hqcat/$STACK/server.env"
  local from missing=()
  for var in APNS_KEY_ID APNS_TEAM_ID APNS_ENV; do
    from=""
    [[ -f "$bundle" ]] && grep -q "^$var=." "$bundle" && from="bundle"
    grep -q "^$var=." "$env" 2>/dev/null && from="server.env (overriding)"
    if [[ -n "$from" ]]; then echo "·  $var ← $from"; else missing+=("$var"); fi
  done
  from=""
  for var in APNS_TOPIC_IOS APNS_TOPIC_MACOS; do
    [[ -f "$bundle" ]] && grep -q "^$var=." "$bundle" && from="bundle"
    grep -q "^$var=." "$env" 2>/dev/null && from="server.env (overriding)"
  done
  if [[ -n "$from" ]]; then echo "·  APNS_TOPIC_* ← $from"; else missing+=("APNS_TOPIC_IOS"); fi

  if (( ${#missing[@]} )); then
    echo "⚠️  An APNs key is installed but ${missing[*]} is set nowhere."
    echo "    push-bridge will wake nobody, and will say so on every connect."
    echo "    These are NOT secrets — set them as repository variables in GitHub"
    echo "    and they arrive with the next release; or put them in $env to"
    echo "    override for this stack only. See infra/deploy/.env.example."
    [[ -f "$bundle" ]] || echo "    (no bundle on this host yet — it has not rolled over.)"
  fi
}

if [[ -s "$DIR/apns_key_p8" ]]; then
  echo "── APNs ───────────────────────────────────────────────────────────"
  say_apns
fi

cat <<EOF

✅ Secrets in place for '$STACK'. They stay on this host.

The agent symlinks them into the stack directory on its next run:
  systemctl start hqcat-agent.service
EOF
