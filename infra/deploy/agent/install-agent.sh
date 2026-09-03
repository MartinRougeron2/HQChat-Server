#!/usr/bin/env bash
#
# install-agent.sh — one-time setup of the pull-based deploy agent on a VM.
#
# After this, the host deploys itself: it follows a GHCR channel tag and rolls
# over whenever that tag's digest moves. Nothing in GitHub holds an SSH key for
# this machine, and no source code is ever placed on it.
#
# BOOTSTRAP WITHOUT A CHECKOUT. This script ships inside the release image, so
# the image is also what installs the agent — there is no `git clone` step and
# no repository on the server at any point:
#
#   docker login ghcr.io -u <user> --password-stdin <<< "$GHCR_READ_TOKEN"
#   docker pull ghcr.io/YOUR-GITHUB-ACCOUNT/dissqus-server:prod
#   cid=$(docker create ghcr.io/YOUR-GITHUB-ACCOUNT/dissqus-server:prod)
#   docker cp "$cid:/deploy-bundle" /run/hqcat-bootstrap && docker rm "$cid"
#   sudo /run/hqcat-bootstrap/agent/install-agent.sh prod chat.example.com
#   rm -rf /run/hqcat-bootstrap
#
# /run is tmpfs, so the staging copy does not survive a reboot even if you
# forget the last line. Afterwards the agent re-extracts the bundle from every
# release it deploys, so this script and its siblings stay current on their own.
set -euo pipefail

STACK="${1:?usage: install-agent.sh <prod|preprod> <domain> [image-repo]}"
DOMAIN="${2:?usage: install-agent.sh <prod|preprod> <domain> [image-repo]}"
IMAGE="${3:-ghcr.io/YOUR-GITHUB-ACCOUNT/dissqus-server}"

case "$STACK" in prod|preprod) ;; *) echo "❌ stack must be prod|preprod" >&2; exit 1 ;; esac
[[ $EUID -eq 0 ]] || { echo "❌ run with sudo/root" >&2; exit 1; }
command -v docker >/dev/null || { echo "❌ docker not installed" >&2; exit 1; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

install -m 0755 -o root -g root "$HERE/hqcat-agent"                  /usr/local/sbin/hqcat-agent
install -m 0755 -o root -g root "$HERE/../scripts/hqcat-apply-nginx" /usr/local/sbin/hqcat-apply-nginx
install -m 0644 -o root -g root "$HERE/hqcat-agent.service"          /etc/systemd/system/hqcat-agent.service
install -m 0644 -o root -g root "$HERE/hqcat-agent.timer"            /etc/systemd/system/hqcat-agent.timer

mkdir -p "/etc/hqcat/$STACK/secrets" /var/lib/hqcat "/opt/hqcat/$STACK"
chmod 700 /etc/hqcat "/etc/hqcat/$STACK" "/etc/hqcat/$STACK/secrets"

# The agent's own config. GHCR_TOKEN is a READ-ONLY (read:packages) token — it
# cannot push images and cannot reach the repository. Fill it in below.
if [[ ! -f /etc/hqcat/agent.env ]]; then
  cat > /etc/hqcat/agent.env <<EOF
# Which stack this host runs, and which GHCR tag it follows.
STACK=$STACK
CHANNEL=$STACK
IMAGE=$IMAGE
DOMAIN=$DOMAIN

# Read-only GHCR pull credentials (read:packages ONLY). Leave blank if the
# package is public.
GHCR_USER=
GHCR_TOKEN=

# Seconds to wait for /health on 8090+8091 before rolling back.
HEALTH_TIMEOUT=120
EOF
  chmod 600 /etc/hqcat/agent.env
  echo "📝 wrote /etc/hqcat/agent.env — add GHCR_USER/GHCR_TOKEN if the package is private"
else
  echo "·  /etc/hqcat/agent.env already exists, left untouched"
fi

# nginx wrapper config (the agent runs as root, so no sudoers rule is needed —
# the old setup-nginx-automation.sh existed only to give a non-root deploy user
# a constrained path to reload nginx, and there is no deploy user any more).
u="${STACK^^}"
touch /etc/hqcat/nginx.env; chmod 600 /etc/hqcat/nginx.env
grep -q "^DOMAIN_${u}=" /etc/hqcat/nginx.env 2>/dev/null \
  || printf 'DOMAIN_%s=%s\nBUNDLE_DIR_%s=/opt/hqcat/%s\n' "$u" "$DOMAIN" "$u" "$STACK" >> /etc/hqcat/nginx.env

systemctl daemon-reload
systemctl enable --now hqcat-agent.timer

cat <<EOF

✅ Agent installed for the '$STACK' stack, following ${IMAGE}:${STACK}.

Still to do on THIS host (nothing of this goes into GitHub):
  1. Put the stack's secrets in /etc/hqcat/$STACK/secrets/ :
       stripe_secret_key  stripe_webhook_secret  apns_key_p8
  2. Put non-secret config in /etc/hqcat/$STACK/server.env (see .env.example).
  3. Install the Cloudflare Origin cert at /etc/ssl/cloudflare/origin.{pem,key}.

Then:
  systemctl start hqcat-agent.service      # deploy now, don't wait for the timer
  journalctl -u hqcat-agent.service -f     # watch it
  systemctl list-timers hqcat-agent.timer  # next poll

Nothing else needs to be on this machine — remove the staging copy:
  rm -rf "$HERE/.."
EOF
