#!/usr/bin/env sh
#
# Write the four database secrets the base compose stack requires, pointing at
# the throwaway `postgres` container in docker-compose.local.yml.
#
#   sh infra/deploy/local-secrets/generate.sh
#
# These values are NOT secret — they authenticate to a container that exists only
# on a laptop or a CI runner, and they match the POSTGRES_* env in the overlay.
# They are generated rather than committed for one reason: a committed connection
# URI trips every secret scanner that looks at this repo, and a security gate
# that is permanently red is a security gate nobody reads.
#
# The generated files are gitignored. Production credentials never come near this
# directory — they live in /etc/hqcat/<stack>/secrets/ on the host, and the base
# compose file resolves ./secrets/*, not ./local-secrets/*.
set -eu
DIR="$(cd "$(dirname "$0")" && pwd)"

URL='postgresql://hqcat:hqcat@postgres:5432/hqcat?sslmode=disable'
printf '%s' "$URL" > "$DIR/database_url"
printf '%s' "$URL" > "$DIR/database_url_direct"

# Deliberately empty: the local container speaks plain postgres, so there is no
# certificate to verify. services/db/pg.ts falls back to an unencrypted
# connection when the CA file is empty or unreadable, and lib/config.ts only
# insists on sslmode=verify-full when NODE_ENV=production.
: > "$DIR/pg_ca_cert"

# EMQX takes its four connection fields as shell assignments in ONE file, because
# it reads the environment as configuration and an unrecognised var is a boot
# failure. AUTHZ_PG_SSL=false is the only line that differs from production.
cat > "$DIR/emqx_pg" <<'EOF'
AUTHZ_PG_SERVER=postgres:5432
AUTHZ_PG_DATABASE=hqcat
AUTHZ_PG_USERNAME=hqcat
AUTHZ_PG_PASSWORD=hqcat
AUTHZ_PG_SSL=false
EOF

# 0644, not 0600. Compose bind-mounts a file secret with the host file's owner
# and mode intact, and every service in this stack runs as `node` (uid 1000 in
# node:22-bookworm-slim) -- not as whoever ran this script. On Linux that makes
# an 0600 file written by uid 1001 unreadable to the container:
#
#   config: DATABASE_URL_DIRECT_FILE=/run/secrets/database_url_direct could not
#   be read: EACCES: permission denied
#
# It works on a Mac only because Docker Desktop's file sharing maps ownership on
# the way in. Nothing is given away by the wider mode: as the header says, these
# four values authenticate to a throwaway container on a laptop or a CI runner,
# and the real credentials never come near this directory.
chmod 644 "$DIR/database_url" "$DIR/database_url_direct" "$DIR/pg_ca_cert" "$DIR/emqx_pg"
echo "[local-secrets] wrote database_url, database_url_direct, pg_ca_cert, emqx_pg"
