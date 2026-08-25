# Section 1 of harden-vm.sh: only Cloudflare may reach 80/443; SSH is
# rate-limited; everything else is denied.
#
# This is the one part of the old script that does NOT translate cleanly.
# harden-vm.sh curled cloudflare.com/ips-v4 at run time and expanded the result
# into ufw rules — a config whose content depended on when you ran it, which is
# exactly what declarative configuration is supposed to eliminate.
#
# The resolution here is deliberate and explicit: the pinned list below is the
# declared state and is what the firewall comes up with on boot, so a host is
# never briefly open and never depends on Cloudflare being reachable at boot. A
# timer then refreshes the nftables sets in place. If the fetch fails the pinned
# ranges stay in force, and a `nixos-rebuild` resets to them.
#
# Refresh the pins with: infra/nixos/update-cloudflare-ips.sh
{
  lib,
  pkgs,
  ...
}:
let
  cf = import ./cloudflare-ips.nix;
in
{
  networking.firewall.enable = false; # replaced wholesale by nftables below
  networking.nftables = {
    enable = true;
    ruleset = ''
      table inet filter {
        set cloudflare_v4 {
          type ipv4_addr
          flags interval
          elements = { ${lib.concatStringsSep ", " cf.v4} }
        }
        set cloudflare_v6 {
          type ipv6_addr
          flags interval
          elements = { ${lib.concatStringsSep ", " cf.v6} }
        }

        chain input {
          type filter hook input priority filter; policy drop;

          ct state established,related accept
          ct state invalid drop
          iif lo accept
          ip protocol icmp accept
          ip6 nexthdr ipv6-icmp accept

          # SSH, rate-limited (the ufw `limit` equivalent).
          tcp dport 22 ct state new limit rate 6/minute burst 6 packets accept

          # The origin is reachable ONLY through the Cloudflare proxy.
          ip  saddr @cloudflare_v4 tcp dport { 80, 443 } accept
          ip6 saddr @cloudflare_v6 tcp dport { 80, 443 } accept
        }

        # `policy drop` says this box is not a router, which is right -- but the
        # chain had no rules at all, and every container's traffic is forwarded
        # traffic. The daemon writes its own rules into the legacy `ip filter`
        # table; this chain sees the same packets and dropped them, so the whole
        # stack came up unable to reach anything:
        #
        #   [migrate] failed: connect ETIMEDOUT <private-db>:25060
        #
        # from a container, while the host itself reached that address fine.
        # With br_netfilter loaded (docker loads it) this also covers
        # container-to-container on one bridge, so pre-prod's postgres was
        # equally unreachable from the services next to it.
        chain forward {
          type filter hook forward priority filter; policy drop;

          ct state established,related accept
          ct state invalid drop

          # Anything leaving a docker bridge: the compose stack reaching the
          # managed database over the VPC, GHCR, APNs, Stripe, and each other.
          # Return traffic arrives on the `established` rule above, so nothing
          # needs to be opened INTO a container -- nginx reaches them from the
          # host, which is locally-originated and never forwarded.
          iifname "docker0" accept
          iifname "br-*" accept
        }
        chain output  { type filter hook output  priority filter; policy accept; }
      }
    '';
  };

  systemd.services.cloudflare-ips-refresh = {
    description = "Refresh the Cloudflare address sets in nftables";
    after = [
      "network-online.target"
      "nftables.service"
    ];
    wants = [ "network-online.target" ];
    serviceConfig = {
      Type = "oneshot";
      # Hardening: this only needs to talk to the network and run `nft`.
      PrivateTmp = true;
      ProtectHome = true;
      NoNewPrivileges = true;
    };
    path = with pkgs; [
      curl
      nftables
      gnused
    ];
    script = ''
      set -euo pipefail
      for v in 4 6; do
        list="$(curl -fsS --max-time 20 "https://www.cloudflare.com/ips-v$v")" || {
          echo "cloudflare ips-v$v unreachable; keeping the pinned set"
          continue
        }
        [ -n "$list" ] || continue
        # Replace atomically: flush + refill inside one nft invocation, so the
        # set is never momentarily empty (which would lock Cloudflare out).
        {
          echo "flush set inet filter cloudflare_v$v"
          echo -n "add element inet filter cloudflare_v$v { "
          echo -n "$(echo "$list" | sed '/^$/d' | paste -sd, -)"
          echo " }"
        } | nft -f -
        echo "cloudflare_v$v refreshed ($(echo "$list" | sed '/^$/d' | wc -l) ranges)"
      done
    '';
  };

  systemd.timers.cloudflare-ips-refresh = {
    description = "Daily Cloudflare address-set refresh";
    wantedBy = [ "timers.target" ];
    timerConfig = {
      OnBootSec = "5min";
      OnUnitActiveSec = "24h";
      RandomizedDelaySec = "30min";
      Persistent = true;
    };
  };
}
