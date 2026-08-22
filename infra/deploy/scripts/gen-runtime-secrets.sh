#!/bin/sh
# Generate the INTERNAL, mutually-agreed service credentials at stack launch into
# a shared tmpfs volume (RAM, never on the host disk, wiped on `down`). Run once
# by the `secrets-init` one-shot before emqx/app services start; those read the
# same files via *_FILE. Idempotent within a stack lifetime — only generates a
# value if absent, so a mid-life container restart keeps the same credentials.
#
# ONLY internal secrets that every co-located service can agree on belong here —
# credentials both ends of which are inside this stack, so nobody has to be told
# what they are:
#   internal_mqtt_secret     push-bridge/ops -> EMQX (privileged identity)
#   emqx_dashboard_password  EMQX dashboard admin
#   metrics_token            optional /metrics bearer
# EXTERNAL secrets that must be provided/stable are NOT generated here — they
# come from the secret store / compose secrets. That now includes the DATABASE_URL
# and the EMQX database password: the database is a managed cluster outside this
# stack (infra/database), so its credentials are issued there, not invented here.
set -eu
DIR="${RUNTIME_SECRETS_DIR:-/runtime-secrets}"
mkdir -p "$DIR"
for name in internal_mqtt_secret emqx_dashboard_password metrics_token; do
  f="$DIR/$name"
  if [ ! -s "$f" ]; then
    node -e "process.stdout.write(require('crypto').randomBytes(32).toString('hex'))" > "$f"
    echo "[secrets-init] generated $name"
  else
    echo "[secrets-init] kept existing $name"
  fi
  # Readable by the non-root service users (node, emqx) inside the isolated
  # network; the material lives only in this tmpfs volume, never on disk.
  chmod 644 "$f"
done
echo "[secrets-init] runtime secrets ready in $DIR"
