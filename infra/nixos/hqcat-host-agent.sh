# shellcheck shell=bash
#
# No shebang on purpose: this is the body of a pkgs.writeShellApplication (see
# modules/host-agent.nix), which supplies its own and runs shellcheck at build
# time. The directive above lets shellcheck lint the file standalone too.
#
# hqcat-host-agent — pull-based NixOS updates.
#
# The host analogue of the app agent, and deliberately the same shape: watch a
# pointer, and when it moves, fetch a prebuilt, signed artifact and switch to it.
#
#   app  : GHCR channel tag  -> image digest   -> docker compose up
#   host : R2 channel pointer -> store path    -> switch-to-configuration
#
# What it does NOT do is as important as what it does. It never fetches the
# flake, never evaluates Nix, and never builds: CI does all of that once, and
# the host only substitutes a closure that is already built and signed. So there
# is no source code on the machine, and a 2 GB droplet is never asked to
# evaluate nixpkgs.
#
# Trust: nix refuses any store path not signed by a key in trusted-public-keys.
# The bucket being writable is therefore not sufficient to compromise a host —
# an attacker would need the signing key, which lives only in GitHub secrets.
set -euo pipefail

CACHE_URL="${CACHE_URL:?CACHE_URL unset}"
CHANNEL="${CHANNEL:?CHANNEL unset}"
STATE_DIR=/var/lib/hqcat-host
mkdir -p "$STATE_DIR"

log() { echo "[hqcat-host-agent] $*"; }

# --- 1. What should this host be running? -----------------------------------
pointer="$(curl -fsS --max-time 30 "${CACHE_URL}/channels/${CHANNEL}")" || {
  log "cannot reach ${CACHE_URL}/channels/${CHANNEL}; leaving the host as-is"
  exit 0
}
target="$(printf '%s' "$pointer" | tr -d '[:space:]')"

case "$target" in
  /nix/store/*) ;;
  *) log "ERROR: channel pointer is not a store path: ${target:0:120}"; exit 1 ;;
esac

current="$(readlink -f /run/current-system)"
if [[ "$target" == "$current" ]]; then
  log "up to date ($(basename "$target"))"
  exit 0
fi
log "new host generation: $(basename "$target")"
log "  (current: $(basename "$current"))"

# --- 2. Substitute the closure ------------------------------------------------
# --realise fetches from the configured substituters. It fails rather than
# building if the cache does not have it, which is what we want: a droplet must
# never attempt to compile a system closure.
log "fetching closure from $CACHE_URL"
nix-store --realise "$target" --add-root "$STATE_DIR/next" >/dev/null

# --- 3. Switch ------------------------------------------------------------------
# Register as a real system generation first, so the new config survives a
# reboot and shows up in `nix-env --list-generations`/the bootloader.
nix-env -p /nix/var/nix/profiles/system --set "$target"

log "activating"
if "$target/bin/switch-to-configuration" switch; then
  printf '%s %s\n' "$(date -Is)" "$target" >> "$STATE_DIR/history"
  log "✅ switched to $(basename "$target")"
else
  # Activation is largely atomic per-unit, but a failed switch can leave
  # services stopped. Roll the profile back and re-activate the known-good one;
  # `boot` rather than `switch` would defer it, and we want it live now.
  log "❌ activation failed — rolling back to $(basename "$current")"
  nix-env -p /nix/var/nix/profiles/system --set "$current"
  "$current/bin/switch-to-configuration" switch || log "rollback activation ALSO failed — manual intervention required"
  exit 1
fi

# --- 4. Housekeeping ------------------------------------------------------------
# Keep a month of generations for rollback, then reclaim.
nix-collect-garbage --delete-older-than 30d >/dev/null 2>&1 || true
