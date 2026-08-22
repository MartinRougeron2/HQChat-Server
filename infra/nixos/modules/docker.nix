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

  environment.systemPackages = with pkgs; [
    docker-compose
    curl
    jq
  ];
}
