#!/usr/bin/env bash
# EMQX dashboard, in one command.
#
# The dashboard binds to 127.0.0.1:18083 ON THE VM (docker-compose.yml) and nginx
# does NOT proxy it — the only way in is an SSH tunnel. SSH on the VM is TOTP-MFA
# gated, so this script opens ONE multiplexed connection (a single verification
# code), then reuses it for everything: reading the launch-generated dashboard
# password out of the RAM-only runtime-secrets volume, re-syncing it if it has
# drifted from what EMQX actually stores, forwarding the port, and opening a
# browser.
#
#   ./deploy/scripts/emqx-dashboard.sh                 # prod dashboard + browser
#   ./infra/deploy/scripts/emqx-dashboard.sh preprod   # pre-prod stack (its own VM)
#   ./deploy/scripts/emqx-dashboard.sh --status        # health report, then exit
#   ./deploy/scripts/emqx-dashboard.sh --password      # just print the password
#
# Overrides: EMQX_SSH_HOST, EMQX_SSH_USER, EMQX_STACK_DIR, EMQX_LOCAL_PORT.
set -euo pipefail

SSH_HOST="${EMQX_SSH_HOST:-chat.example.com}"
SSH_USER="${EMQX_SSH_USER:-deploy}"
STACK="prod"
STACK_DIR_OVERRIDE=""
MODE="tunnel"          # tunnel | status | password
OPEN_BROWSER=1

while [ $# -gt 0 ]; do
  case "$1" in
    prod|preprod)  STACK="$1" ;;
    --status)      MODE="status" ;;
    --password)    MODE="password" ;;
    --no-open)     OPEN_BROWSER=0 ;;
    --host)        SSH_HOST="$2"; shift ;;
    --user)        SSH_USER="$2"; shift ;;
    --path)        STACK_DIR_OVERRIDE="$2"; shift ;;
    -h|--help)     sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)             echo "unknown argument: $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done

# Per-stack remote port + compose invocation.
#
# The stack directory is the one the deploy agent extracts out of the released
# image (/opt/hqcat/<stack>), NOT a git checkout — the VMs no longer hold one.
# Pre-prod is its own VM now, so it uses the same dashboard port as prod; it
# keeps its own compose PROJECT so a stray `down` cannot cross stacks.
STACK_DIR="${STACK_DIR_OVERRIDE:-${EMQX_STACK_DIR:-/opt/hqcat/$STACK}}"
REMOTE_PORT=18083
if [ "$STACK" = "preprod" ]; then
  COMPOSE="docker compose -p dissqus-preprod -f docker-compose.yml -f docker-compose.preprod.yml"
else
  COMPOSE="docker compose -f docker-compose.yml"
fi
LOCAL_PORT="${EMQX_LOCAL_PORT:-$REMOTE_PORT}"
BASE="http://127.0.0.1:${LOCAL_PORT}"

CTL="${TMPDIR:-/tmp}/emqx-dash-${STACK}-$$.sock"

cleanup() {
  ssh -S "$CTL" -O exit "$SSH_USER@$SSH_HOST" 2>/dev/null || true
  rm -f "$CTL"
}
trap cleanup EXIT INT TERM

say() { printf '%s\n' "$*" >&2; }

# Run a command on the VM over the ALREADY-authenticated master connection.
remote() { ssh -S "$CTL" "$SSH_USER@$SSH_HOST" "$@"; }
# …inside the extracted stack directory, with the right compose project selected.
compose() { remote "cd '$STACK_DIR' && $COMPOSE $*"; }

# --- 1. One authenticated connection, carrying the port-forward --------------
say "→ connecting to $SSH_USER@$SSH_HOST (one TOTP prompt; forwarding :$LOCAL_PORT → :$REMOTE_PORT)…"
if ! ssh -f -N -M -S "$CTL" \
       -o ControlPersist=yes \
       -o ExitOnForwardFailure=yes \
       -L "127.0.0.1:${LOCAL_PORT}:127.0.0.1:${REMOTE_PORT}" \
       "$SSH_USER@$SSH_HOST"; then
  say "✗ could not connect / forward :$LOCAL_PORT."
  say "  If the port is already taken (another tunnel?), pick another one:"
  say "  EMQX_LOCAL_PORT=28083 $0 $STACK"
  exit 1
fi

# --- 2. Read the launch-generated dashboard password -------------------------
# Lives only in the runtime-secrets tmpfs (RAM) — never on the host disk or in
# git. See deploy/scripts/gen-runtime-secrets.sh.
PW="$(compose "exec -T secrets-init cat /runtime-secrets/emqx_dashboard_password" | tr -d '\r\n')"
if [ -z "$PW" ]; then
  say "✗ could not read emqx_dashboard_password — is the $STACK stack up?"
  exit 1
fi

if [ "$MODE" = "password" ]; then
  printf '%s\n' "$PW"
  exit 0
fi

# --- 3. Log in, re-syncing the password if EMQX has drifted from the secret ---
# `dashboard.default_password` only seeds the admin user on EMQX's FIRST boot;
# after that the credential lives in mnesia (the emqx-data volume). A full
# `docker compose down` wipes the tmpfs and regenerates the secret while mnesia
# survives — so the file and the broker can disagree. Fix it instead of failing.
login() {
  curl -fsS -m 8 -X POST "$BASE/api/v5/login" \
       -H 'content-type: application/json' \
       -d "{\"username\":\"admin\",\"password\":\"$1\"}" 2>/dev/null || true
}
token_of() { sed -n 's/.*"token" *: *"\([^"]*\)".*/\1/p'; }

TOKEN="$(login "$PW" | token_of)"
if [ -z "$TOKEN" ]; then
  say "… stored dashboard password differs from the generated secret — re-syncing"
  compose "exec -T emqx emqx ctl admins passwd admin '$PW'" >/dev/null 2>&1 \
    || compose "exec -T emqx emqx ctl admins add admin '$PW'" >/dev/null 2>&1 || true
  TOKEN="$(login "$PW" | token_of)"
fi
if [ -z "$TOKEN" ]; then
  say "✗ dashboard login failed. Check the broker: $COMPOSE logs --tail=50 emqx"
  exit 1
fi

api() { curl -fsS -m 8 -H "Authorization: Bearer $TOKEN" "$BASE/api/v5/$1" 2>/dev/null || true; }

# --- 4. Health report --------------------------------------------------------
# The blind spot this exists for: EMQX's POSTGRES AUTHORIZER is a separate
# connection, with its own read-only role and its own pool, from every app
# service's database client. It can be flat on its back while the apps look
# perfectly healthy — and with deny_action = disconnect, a dead authorizer drops
# every client that touches a topic.
report() {
  say ""
  say "EMQX $STACK — health"
  say "────────────────────"
  summarize "node"   "$(api 'nodes')"
  summarize "authn"  "$(api 'authentication')"
  summarize "authz"  "$(api 'authorization/sources')"
  summarize "authz-pg" "$(api 'authorization/sources/postgresql/status')"
  summarize "clients" "$(api 'clients?limit=1')"
}

summarize() {
  local label="$1" json="$2"
  if [ -z "$json" ]; then say "  ${label}: (no answer)"; return; fi
  if command -v python3 >/dev/null 2>&1; then
    printf '%s' "$json" | python3 -c "$PY_SUMMARY" "$label" >&2
  else
    say "  ${label}: ${json}"
  fi
}

# Formats one API answer as a line or two. Kept in a variable so the quoting
# stays sane; falls back to raw JSON when python3 is absent.
PY_SUMMARY=$(cat <<'PY'
import json, sys

label = sys.argv[1]
raw = sys.stdin.read()
def line(s): print("  %s: %s" % (label, s))
try:
    d = json.loads(raw)
except Exception:
    line(raw.strip()[:200]); raise SystemExit

def health(item):
    # EMQX reports `status` only for connector-backed sources; the built-in file
    # authorizer has none, and that absence is not a failure.
    st = item.get("status")
    ok = item.get("enable", True) and st in (None, "connected")
    parts = [item.get("type") or item.get("mechanism") or item.get("id") or ""]
    parts.append("status=%s" % (st or "n/a"))
    if "enable" in item:
        parts.append("enabled" if item["enable"] else "DISABLED")
    line(("OK " if ok else "!! ") + " ".join(p for p in parts if p))
    for e in item.get("node_error") or []:
        line("    error: %s" % str(e)[:180])

if label == "node" and isinstance(d, list):
    for n in d:
        line("%s %s v%s conns=%s" % (n.get("node"), n.get("node_status"), n.get("version"), n.get("connections")))
elif label == "clients":
    line("connected=%s" % d.get("meta", {}).get("count", "?"))
elif isinstance(d, list):
    if not d:
        line("!! none configured")
    for item in d:
        health(item)
else:
    health(d)
PY
)

report

if [ "$MODE" = "status" ]; then
  exit 0
fi

# --- 5. Hand it to the human -------------------------------------------------
say ""
say "Dashboard  $BASE"
say "  user     admin"
say "  password $PW"
say ""
say "Tunnel is open. Ctrl-C to close it."

if [ "$OPEN_BROWSER" = "1" ]; then
  if command -v open >/dev/null 2>&1; then open "$BASE" >/dev/null 2>&1 || true
  elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$BASE" >/dev/null 2>&1 || true
  fi
fi

# Hold the foreground until the user quits (or the master connection dies).
while ssh -S "$CTL" -O check "$SSH_USER@$SSH_HOST" >/dev/null 2>&1; do
  sleep 5
done
