#!/usr/bin/env bash
# Print SPKI pin candidates for a host, in the form the app expects.
#
#   ./infra/deploy/scripts/compute-spki-pins.sh chat.example.com
#
# Paste the chosen values into apps/apple/DissQus/Deployment.swift
# (`pinnedSPKIHashes`) or a build's Info.plist `ServerPinnedSPKIHashes`.
#
# READ THIS BEFORE PINNING. A wrong or stale pin does not degrade the app, it
# BRICKS it — the client refuses the connection and no server-side change can
# reach it. Two rules follow:
#
#   1. Pin the CA or the intermediate, NOT the leaf, when the origin sits behind
#      a CDN. Cloudflare rotates leaf certificates on its own schedule.
#   2. Ship at least two pins from different issuers, so one revocation does not
#      strand every installed copy.
set -euo pipefail

HOST="${1:?usage: compute-spki-pins.sh <host> [port]}"
PORT="${2:-443}"

echo "Certificate chain for ${HOST}:${PORT} — leaf first."
echo

openssl s_client -servername "$HOST" -connect "${HOST}:${PORT}" -showcerts </dev/null 2>/dev/null \
| awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' \
| awk 'BEGIN{n=0} /-----BEGIN/{n++} {print > ("/tmp/spki-cert-" n ".pem")}'

i=1
while [ -f "/tmp/spki-cert-${i}.pem" ]; do
  subject=$(openssl x509 -in "/tmp/spki-cert-${i}.pem" -noout -subject 2>/dev/null | sed 's/^subject=//')
  pin=$(openssl x509 -in "/tmp/spki-cert-${i}.pem" -pubkey -noout 2>/dev/null \
        | openssl pkey -pubin -outform der 2>/dev/null \
        | openssl dgst -sha256 -binary | base64)
  role="intermediate/root  ← prefer these"
  [ "$i" = "1" ] && role="LEAF               ← do NOT pin behind a CDN"
  printf '  [%d] %s\n      %s\n      %s\n\n' "$i" "$role" "$subject" "$pin"
  rm -f "/tmp/spki-cert-${i}.pem"
  i=$((i + 1))
done

echo "Pick two from different issuers. Verify with a build before shipping —"
echo "a pin that does not match is indistinguishable from an outage."
