#!/usr/bin/env bash
#
# Regenerate modules/cloudflare-ips.nix from Cloudflare's published ranges.
#
# The firewall refreshes its live nftables sets daily on its own, so this only
# updates the *declared* state — the ranges a host boots with before that timer
# has ever run. Run it when Cloudflare announces a change, and commit the diff
# so the change is reviewed rather than silently absorbed.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

v4="$(curl -fsS --max-time 20 https://www.cloudflare.com/ips-v4)"
v6="$(curl -fsS --max-time 20 https://www.cloudflare.com/ips-v6)"
[ -n "$v4" ] && [ -n "$v6" ] || { echo "❌ empty response from Cloudflare" >&2; exit 1; }

fmt() { printf '%s\n' "$1" | sed '/^$/d' | sed 's/^/    "/; s/$/"/'; }

cat > modules/cloudflare-ips.nix <<EOF
# Cloudflare's published edge ranges — the ONLY sources allowed to reach 80/443.
#
# Pinned on purpose. firewall.nix refreshes the live nftables sets daily, but the
# declared state has to be a fixed value: a host must come up already closed,
# without depending on cloudflare.com being reachable at boot.
#
# Regenerate with: infra/nixos/update-cloudflare-ips.sh
# Fetched $(date -u +%F) from
#   https://www.cloudflare.com/ips-v4  ($(printf '%s\n' "$v4" | sed '/^$/d' | wc -l | tr -d ' ') ranges)
#   https://www.cloudflare.com/ips-v6  ($(printf '%s\n' "$v6" | sed '/^$/d' | wc -l | tr -d ' ') ranges)
{
  v4 = [
$(fmt "$v4")
  ];

  v6 = [
$(fmt "$v6")
  ];
}
EOF

echo "✅ modules/cloudflare-ips.nix regenerated — review \`git diff\` before committing."
