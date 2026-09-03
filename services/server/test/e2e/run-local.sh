#!/usr/bin/env bash
#
# run-local.sh — the end-to-end suite, on your own machine, for free.
#
# The CI job that runs this is opt-in on pull requests (label a PR `run-e2e`),
# because standing up a broker, an API and an auth server costs Actions minutes
# on every push. That is the same trade the Apple job made when it moved to
# apps/apple/verify.sh: the coverage is worth having, paying for it on every
# iteration is not.
#
#   bash services/server/test/e2e/run-local.sh
#
# Needs Docker (for Postgres and EMQX) and the native HQC library. The suite
# skips cleanly rather than failing if either is missing.
set -euo pipefail

cd "$(dirname "$0")/../.."          # services/server
ROOT="$(cd ../.. && pwd)"

PG_PORT="${PG_PORT:-55432}"
MQTT_PORT="${MQTT_PORT:-58083}"
API_PORT="${API_PORT:-58080}"
AUTH_PORT="${AUTH_PORT:-58081}"
NAME_PG="hqcat-e2e-pg"
NAME_MQ="hqcat-e2e-emqx"

step() { printf '\n\033[1m── %s\033[0m\n' "$1"; }
cleanup() {
  step "Tearing down"
  kill "${API_PID:-}" "${AUTH_PID:-}" 2>/dev/null || true
  docker rm -f "$NAME_PG" "$NAME_MQ" >/dev/null 2>&1 || true
}
trap cleanup EXIT

command -v docker >/dev/null || { echo "❌ docker is required" >&2; exit 1; }

step "Postgres"
docker rm -f "$NAME_PG" >/dev/null 2>&1 || true
docker run -d --name "$NAME_PG" \
  -e POSTGRES_USER=hqcat -e POSTGRES_PASSWORD=hqcat -e POSTGRES_DB=hqcat \
  -p "${PG_PORT}:5432" postgres:17-alpine >/dev/null
until docker exec "$NAME_PG" pg_isready -U hqcat -d hqcat >/dev/null 2>&1; do sleep 1; done

export DATABASE_URL="postgresql://hqcat:hqcat@localhost:${PG_PORT}/hqcat"
export ADMISSION_POLICY=open
step "Migrate"
npm run migrate

# The broker runs the REAL config, rendered exactly as CI renders it — see the
# long note in .github/workflows/ci.yml for why each substitution differs from
# production. The short version: CI and this script reach Postgres directly,
# production reaches it through PgBouncer, and `disable_prepared_statements`
# has to flip for that.
step "EMQX (with the deployment's authorizer)"
HOST_GW="host.docker.internal"
sed -e "s|__PG_SERVER__|${HOST_GW}:${PG_PORT}|" \
    -e "s|__PG_HOST__|${HOST_GW}|" \
    -e "s|__PG_DATABASE__|hqcat|" \
    -e "s|__PG_USERNAME__|hqcat|" \
    -e "s|__PG_PASSWORD__|hqcat|" \
    -e "s|__PG_SSL__|false|" \
    -e "/cacertfile = /d" \
    -e "s|disable_prepared_statements = true|disable_prepared_statements = false|" \
    -e "s|//auth:8080/mqtt/authn|//${HOST_GW}:${AUTH_PORT}/mqtt/authn|" \
    "$ROOT/infra/deploy/emqx/emqx.conf" > /tmp/hqcat-e2e-emqx.conf
grep -q "__PG_" /tmp/hqcat-e2e-emqx.conf && { echo "❌ unrendered placeholders"; exit 1; } || true

# The API and auth start FIRST: EMQX's authn webhook fails its initial connect
# otherwise, marks the resource down, and refuses every CONNECT until it retries.
step "API + auth"
PORT="$API_PORT"  npm run api  > /tmp/hqcat-e2e-api.log  2>&1 & API_PID=$!
PORT="$AUTH_PORT" npm run auth > /tmp/hqcat-e2e-auth.log 2>&1 & AUTH_PID=$!
for _ in $(seq 1 30); do
  curl -fsS "http://localhost:${API_PORT}/health"  >/dev/null 2>&1 &&
  curl -fsS "http://localhost:${AUTH_PORT}/health" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS "http://localhost:${API_PORT}/health"  >/dev/null || { cat /tmp/hqcat-e2e-api.log;  exit 1; }
curl -fsS "http://localhost:${AUTH_PORT}/health" >/dev/null || { cat /tmp/hqcat-e2e-auth.log; exit 1; }

docker rm -f "$NAME_MQ" >/dev/null 2>&1 || true
docker run -d --name "$NAME_MQ" \
  --add-host "${HOST_GW}:host-gateway" \
  -p "${MQTT_PORT}:8083" \
  -v /tmp/hqcat-e2e-emqx.conf:/opt/emqx/etc/emqx.conf:ro \
  emqx/emqx:5.8 >/dev/null
for _ in $(seq 1 40); do
  docker exec "$NAME_MQ" emqx ctl status >/dev/null 2>&1 && break
  sleep 2
done
docker exec "$NAME_MQ" emqx ctl status >/dev/null \
  || { echo "❌ emqx did not start"; docker logs "$NAME_MQ"; exit 1; }
for _ in $(seq 1 30); do
  docker exec "$NAME_MQ" emqx ctl alarms list 2>/dev/null \
    | grep -qiE "authn|authz|resource" || break
  echo "waiting for the auth resources…"; sleep 2
done

step "E2E"
TEST_AUTH_URL="http://localhost:${AUTH_PORT}" \
TEST_API_URL="http://localhost:${API_PORT}" \
TEST_EMQX_URL="ws://localhost:${MQTT_PORT}/mqtt" \
  npm run test:e2e
