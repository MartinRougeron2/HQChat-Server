# The host nginx vhost, declared.
#
# This is a faithful translation of infra/deploy/nginx.conf, which on a non-NixOS
# host is rendered by hqcat-apply-nginx out of the release bundle. Here it is
# part of the system closure instead, which is strictly better in two ways: the
# real_ip ranges come from the SAME pinned list as the firewall (they used to be
# a hand-maintained third copy that could disagree with it), and there is no
# writable /etc/nginx/sites-enabled for anything to tamper with.
#
# app-agent.nix therefore leaves DOMAIN unset in the agent's config, which is
# what makes the agent skip its nginx step on these hosts.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.hqcat;
  cf = import ./cloudflare-ips.nix;

  # Every proxied location sets the same forwarding headers.
  fwd = ''
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  '';

  authUpstream = "http://127.0.0.1:8090";
  apiUpstream = "http://127.0.0.1:8091";

  # The plain rate-limited API paths, all pointing at app-api.
  apiPaths = [
    "/friends"
    "/username"
    "/users"
    "/push"
    "/account"
    "/stripe"
  ];
  apiLocation = {
    proxyPass = apiUpstream;
    extraConfig = ''
      limit_req zone=api burst=40 nodelay;
      ${fwd}
    '';
  };
in
{
  services.nginx = {
    enable = true;
    recommendedOptimisation = true;
    recommendedTlsSettings = false; # the vhost pins its own TLS below

    # Trust Cloudflare's ranges for CF-Connecting-IP. Same source of truth as
    # the firewall — one list, two consumers.
    commonHttpConfig = ''
      server_tokens off;

      limit_req_zone $binary_remote_addr zone=api:10m   rate=20r/s;
      limit_req_zone $binary_remote_addr zone=claim:10m rate=1r/s;

      # Only POSTs count against the checkout limit; GETs get an empty key,
      # which nginx ignores.
      map $request_method $checkout_limit_key {
          POST    $binary_remote_addr;
          default "";
      }
      limit_req_zone $checkout_limit_key zone=checkout:10m rate=10r/m;

      ${lib.concatMapStringsSep "\n" (r: "set_real_ip_from ${r};") (cf.v4 ++ cf.v6)}
      real_ip_header CF-Connecting-IP;
    '';

    virtualHosts.${cfg.domain} = {
      forceSSL = true;
      # Cloudflare Origin certificate, installed out of band. It is machine
      # state, not config: it must never enter the world-readable Nix store.
      sslCertificate = "/etc/ssl/cloudflare/origin.pem";
      sslCertificateKey = "/etc/ssl/cloudflare/origin.key";

      extraConfig = ''
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_prefer_server_ciphers off;
        client_max_body_size 1m;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Frame-Options "DENY" always;
        add_header Referrer-Policy "no-referrer" always;
      '';

      locations = {
        # MQTT over WebSocket. Long timeouts: these connections are meant to
        # stay open, and this path must never be challenged or buffered.
        "/mqtt" = {
          proxyPass = "http://127.0.0.1:8083";
          proxyWebsockets = true;
          extraConfig = ''
            ${fwd}
            proxy_read_timeout 3600s;
            proxy_send_timeout 3600s;
          '';
        };

        # Subscription claim codes — deliberately the tightest limit here.
        "/claim/" = {
          proxyPass = authUpstream;
          extraConfig = ''
            limit_req zone=claim burst=5 nodelay;
            ${fwd}
          '';
        };

        "/auth/" = {
          proxyPass = authUpstream;
          extraConfig = ''
            limit_req zone=api burst=40 nodelay;
            ${fwd}
          '';
        };

        # Stripe checkout creation: the api limit plus a per-POST cap.
        "/subscribe" = {
          proxyPass = apiUpstream;
          extraConfig = ''
            limit_req zone=api burst=40 nodelay;
            limit_req zone=checkout burst=3 nodelay;
            ${fwd}
          '';
        };

        "/" = apiLocation;
      }
      // lib.genAttrs apiPaths (_: apiLocation);
    };
  };

  # The origin key lives outside the store (the store is world-readable) and is
  # root-owned. nginx's master runs as root and reads it before dropping
  # privileges, so this group is belt-and-braces rather than load-bearing — but
  # it means the key is still readable if that ever changes.
  users.users.nginx.extraGroups = [ "ssl-cert" ];
  users.groups.ssl-cert = { };

  # `z` adjusts an existing path without creating it, so ownership and mode are
  # re-asserted on every boot and every rebuild no matter how the files were
  # copied in. A plain `scp` + `chmod 640` leaves the group as root, which is
  # the sort of thing that works until the day it doesn't.
  systemd.tmpfiles.rules = [
    "d /etc/ssl/cloudflare      0750 root ssl-cert -"
    "z /etc/ssl/cloudflare/origin.pem 0644 root ssl-cert -"
    "z /etc/ssl/cloudflare/origin.key 0640 root ssl-cert -"
  ];

  # Guarantee nginx can always start.
  #
  # Without this a fresh host is a trap: nixos-anywhere installs, nginx has no
  # certificate, the unit fails, activation fails — and hqcat-host-agent treats
  # a failed activation as a bad release and tries to roll back, on a machine
  # that has no previous generation to roll back to. The certificate is machine
  # state that cannot be in the closure, so the closure has to tolerate its
  # absence.
  #
  # A self-signed placeholder keeps nginx up. Cloudflare Full (strict) will
  # reject it with a 526 until the real Origin certificate is installed, which
  # is a clear and searchable signal — unlike a dead nginx.
  systemd.services.hqcat-origin-cert = {
    description = "Ensure an origin TLS certificate exists for nginx";
    wantedBy = [ "multi-user.target" ];
    before = [ "nginx.service" ];
    requiredBy = [ "nginx.service" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    path = with pkgs; [
      openssl
      coreutils
    ];
    script = ''
      set -euo pipefail
      dir=/etc/ssl/cloudflare
      mkdir -p "$dir"

      if [ ! -s "$dir/origin.pem" ] || [ ! -s "$dir/origin.key" ]; then
        echo "WARNING: no Cloudflare Origin certificate at $dir."
        echo "WARNING: generating a SELF-SIGNED placeholder so nginx can start."
        echo "WARNING: Cloudflare Full (strict) will return 526 until you install the real one:"
        echo "WARNING:   infra/nixos/install-origin-cert.sh root@<host> origin.pem origin.key"
        openssl req -x509 -nodes -newkey rsa:2048 -days 3650           -subj "/CN=${cfg.domain}"           -keyout "$dir/origin.key" -out "$dir/origin.pem" 2>/dev/null
      fi

      # Re-assert ownership/mode regardless of how the files arrived.
      chown root:ssl-cert "$dir/origin.pem" "$dir/origin.key"
      chmod 0644 "$dir/origin.pem"
      chmod 0640 "$dir/origin.key"
    '';
  };
}
