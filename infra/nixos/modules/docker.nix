# Section 6 of harden-vm.sh. The host's only job is to run containers; the
# images themselves carry the hardening that matters (cap_drop, read-only root,
# non-root user — see infra/deploy/docker-compose.yml).
{ pkgs, ... }:
{
  virtualisation.docker = {
    enable = true;
    daemon.settings = {
      "log-driver" = "json-file";
      "log-opts" = {
        "max-size" = "10m";
        "max-file" = "3";
      };
      # Keep containers running across a daemon restart — a host rebuild should
      # not be an outage.
      "live-restore" = true;
      "no-new-privileges" = true;
      "userland-proxy" = false;
    };
    # Reclaim dangling images/volumes weekly. The app agent prunes images after
    # each rollout; this catches everything else.
    autoPrune = {
      enable = true;
      dates = "weekly";
    };
  };

  # dockerd creates its own NAT and filter rules and needs the binary to do it.
  # Without it on the unit's PATH it starts, logs nothing, and runs with no
  # firewall rules whatsoever: `nft list tables` shows no `ip nat` and no
  # `ip filter`, so nothing masquerades container traffic and nothing DNATs a
  # published port. Every container is then cut off --
  #
  #   container → 1.1.1.1:443        TIMEOUT
  #   container → managed postgres   TIMEOUT   ([migrate] failed: connect ETIMEDOUT)
  #   --network host → same postgres OPEN
  #
  # -- and with `userland-proxy = false` above, publishing a port depends on that
  # same DNAT, so nginx could not have reached the services either.
  #
  # This is separate from the `forward` chain in firewall.nix: docker's rules
  # live in the legacy `ip filter` table, ours in `inet filter`, and a packet has
  # to pass both.
  systemd.services.docker.path = [ pkgs.iptables ];

  environment.systemPackages = with pkgs; [
    docker-compose
    curl
    jq
  ];
}
