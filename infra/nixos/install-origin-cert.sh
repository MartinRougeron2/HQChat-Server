#!/usr/bin/env bash
#
# install-origin-cert.sh — put the Cloudflare Origin certificate on a host.
#
# Run from your LAPTOP. The certificate is machine state, not configuration: the
# Nix store is world-readable, so the private key must never enter the closure,
# the cache, or the repo. This is the out-of-band channel for it.
#
#   ./install-origin-cert.sh root@203.0.113.10 ~/origin.pem ~/origin.key
#
# Until this runs, the host serves a self-signed placeholder (see
# modules/nginx.nix) so nginx starts and the rest of the stack comes up.
# Cloudflare Full (strict) answers 526 in that state.
#
# Get the certificate from: Cloudflare dashboard → your zone → SSL/TLS →
# Origin Server → Create Certificate. Keep the private key; Cloudflare shows it
# exactly once.
set -euo pipefail

TARGET="${1:?usage: install-origin-cert.sh <user@host> <origin.pem> <origin.key>}"
PEM="${2:?missing <origin.pem>}"
KEY="${3:?missing <origin.key>}"

for f in "$PEM" "$KEY"; do
  [[ -s "$f" ]] || { echo "❌ $f is missing or empty" >&2; exit 1; }
done

# Fail here rather than after nginx is already serving a broken pair.
command -v openssl >/dev/null || { echo "❌ openssl not found locally" >&2; exit 1; }
grep -q 'BEGIN CERTIFICATE'  "$PEM" || { echo "❌ $PEM is not a PEM certificate" >&2; exit 1; }
grep -q 'BEGIN .*PRIVATE KEY' "$KEY" || { echo "❌ $KEY is not a PEM private key" >&2; exit 1; }

# A cert and key that do not belong together produce an nginx that starts and
# then fails every handshake, which is a miserable thing to debug remotely.
cert_mod="$(openssl x509 -noout -modulus -in "$PEM" | openssl md5)"
key_mod="$(openssl rsa  -noout -modulus -in "$KEY" 2>/dev/null | openssl md5 || true)"
if [[ -n "$key_mod" && "$cert_mod" != "$key_mod" ]]; then
  echo "❌ certificate and key do not match" >&2; exit 1
fi

subject="$(openssl x509 -noout -subject -in "$PEM")"
expiry="$(openssl x509 -noout -enddate -in "$PEM" | cut -d= -f2)"
echo "→ installing to $TARGET"
echo "   $subject"
echo "   expires: $expiry"

# Ship both files in one stream under FIXED names.
#
# The names are normalised locally, on purpose: the earlier version interpolated
# `$(basename "$PEM")` straight into the remote shell string, so a certificate
# saved as `origin.pem; rm -rf /tmp/x` would have run as a command on the host.
# You control your own filenames, so this was never likely — but it is the
# shape of a command-injection bug, and it costs nothing to not have it. The
# remote script below now contains no interpolated local values whatsoever.
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
cp "$PEM" "$stage/origin.pem"
cp "$KEY" "$stage/origin.key"

tar -czf - -C "$stage" origin.pem origin.key \
| ssh "$TARGET" "set -euo pipefail
    umask 077
    mkdir -p /etc/ssl/cloudflare
    tmp=\$(mktemp -d)
    trap 'rm -rf \"\$tmp\"' EXIT
    tar -xzf - -C \"\$tmp\"
    install -m 0644 -o root -g ssl-cert \"\$tmp/origin.pem\" /etc/ssl/cloudflare/origin.pem
    install -m 0640 -o root -g ssl-cert \"\$tmp/origin.key\" /etc/ssl/cloudflare/origin.key
    # Re-run the guard so it picks up the real pair instead of the placeholder,
    # then validate before reloading — a bad config must not take nginx down.
    systemctl restart hqcat-origin-cert.service
    nginx -t
    systemctl reload nginx
    echo '   nginx reloaded'"

echo "✅ installed. Verify from outside:"
echo "   curl -sS -o /dev/null -w '%{http_code}\\n' https://\$(ssh $TARGET 'hostname -f' 2>/dev/null || echo YOUR_DOMAIN)/health"
