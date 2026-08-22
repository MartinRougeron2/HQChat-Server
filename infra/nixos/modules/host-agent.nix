# Pull-based host updates: the machine follows a channel pointer in the R2
# binary cache and switches to whatever signed closure CI published.
#
# This is what makes the host declarative WITHOUT the machine ever holding
# source or running an evaluation — the two costs that usually come with NixOS
# on a small box. CI evaluates and builds once; every host substitutes the
# result. And because `nixos-rebuild switch` is an in-place atomic transition
# rather than a replacement, upgrading a host never touches its state: Docker
# volumes, EMQX's mnesia and /etc/hqcat all survive untouched, and the previous
# generation stays bootable for rollback.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.hqcat;

  hostAgent = pkgs.writeShellApplication {
    name = "hqcat-host-agent";
    runtimeInputs = with pkgs; [
      curl
      nix
      coreutils
    ];
    text = builtins.readFile ../hqcat-host-agent.sh;
  };
in
{
  nix.settings = {
    experimental-features = [
      "nix-command"
      "flakes"
    ];
    # Our cache first, then the public one for anything unmodified from nixpkgs.
    substituters = [
      cfg.cacheUrl
      "https://cache.nixos.org"
    ];
    trusted-public-keys = [
      cfg.cachePublicKey
      "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
    ];
    # A host must never compile a system closure; if the cache is missing a
    # path, fail loudly instead of melting a 2 GB droplet for an hour.
    max-jobs = 0;
    builders-use-substitutes = true;
  };

  # Reclaim store space; the host-agent also trims generations after a switch.
  nix.gc = {
    automatic = true;
    dates = "weekly";
    options = "--delete-older-than 30d";
  };
  nix.optimise = {
    automatic = true;
    dates = [ "weekly" ];
  };

  environment.systemPackages = [ hostAgent ];

  systemd.services.hqcat-host-agent = {
    description = "Pull and activate the published NixOS closure for this host";
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    environment = {
      CACHE_URL = cfg.cacheUrl;
      CHANNEL = cfg.stack;
    };
    serviceConfig = {
      Type = "oneshot";
      ExecStart = lib.getExe hostAgent;
      # A cold closure fetch on a small droplet can be slow; activation itself
      # is fast. Do not kill it midway through a switch.
      TimeoutStartSec = 1800;
    };
  };

  systemd.timers.hqcat-host-agent = {
    description = "Check for a new published host configuration";
    wantedBy = [ "timers.target" ];
    timerConfig = {
      # Far less often than the app agent: host config changes are rare, and
      # each check is one HTTP request against a static object.
      OnBootSec = "10min";
      OnUnitActiveSec = "30min";
      RandomizedDelaySec = "5min";
      Persistent = true;
      Unit = "hqcat-host-agent.service";
    };
  };

  systemd.tmpfiles.rules = [ "d /var/lib/hqcat-host 0700 root root -" ];

  # Fail at evaluation rather than shipping a host that trusts nothing (and so
  # can never substitute its own updates) or, worse, one whose operator assumed
  # signature checking was on.
  assertions = [
    {
      assertion = cfg.cachePublicKey != "REPLACE_ME_WITH_CACHE_PUBLIC_KEY";
      message = ''
        hqcat.cachePublicKey is still the placeholder. Generate the signing key
        pair (infra/nixos/README.md), put the private half in the GitHub secret
        NIX_CACHE_SIGNING_KEY, and set the public half here.
      '';
    }
  ];
}
