# The application deploy agent, as a NixOS service.
#
# This is the SAME agent as on a non-NixOS host (infra/deploy/agent/hqcat-agent):
# it watches a GHCR channel tag and rolls the compose stack over when the digest
# moves. NixOS owns the machine; the agent owns the app. They stay decoupled on
# purpose — shipping the app must not require a host rebuild, and vice versa.
#
# Two differences from install-agent.sh:
#   - the unit, timer and script come from the closure, so there is nothing to
#     install and nothing that can drift;
#   - DOMAIN is deliberately left unset, which is the agent's own signal to skip
#     its nginx step. nginx is declarative here (nginx.nix).
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.hqcat;

  agent = pkgs.writeShellApplication {
    name = "hqcat-agent";
    runtimeInputs = with pkgs; [
      docker
      docker-compose
      curl
      coreutils
      gnused
    ];
    text = builtins.readFile ../../deploy/agent/hqcat-agent;
    # The script sources /etc/hqcat/agent.env, so its variables are not
    # statically visible to shellcheck.
    excludeShellChecks = [ "SC1091" ];
  };
in
{
  environment.systemPackages = [ agent ];

  environment.etc."hqcat/agent.env" = {
    mode = "0600";
    text = ''
      # Managed by NixOS (infra/nixos/modules/app-agent.nix). Do not edit:
      # a rebuild overwrites it. GHCR credentials go in agent-auth.env.
      STACK=${cfg.stack}
      CHANNEL=${cfg.stack}
      IMAGE=${cfg.imageRepo}
      HEALTH_TIMEOUT=120
      # DOMAIN intentionally unset — nginx is declarative on this host, so the
      # agent must not try to render or reload it.
    '';
  };

  systemd.services.hqcat-agent = {
    description = "HQCAT application deploy agent (watches a GHCR channel tag)";
    after = [
      "docker.service"
      "network-online.target"
    ];
    wants = [ "network-online.target" ];
    requires = [ "docker.service" ];
    serviceConfig = {
      Type = "oneshot";
      ExecStart = lib.getExe agent;
      TimeoutStartSec = 900;
      # Read-only GHCR pull credentials, kept out of the world-readable store.
      # Optional: without it the agent works against a public package.
      EnvironmentFile = "-/etc/hqcat/agent-auth.env";
    };
  };

  systemd.timers.hqcat-agent = {
    description = "Poll GHCR for a new HQCAT release";
    wantedBy = [ "timers.target" ];
    timerConfig = {
      OnBootSec = "2min";
      OnUnitActiveSec = "2min";
      RandomizedDelaySec = "30s";
      AccuracySec = "15s";
      Unit = "hqcat-agent.service";
    };
  };

  # Per-stack state the agent expects. Secret VALUES are placed out of band and
  # are never in the closure — but every compose secret must exist as a FILE or
  # `docker compose up` refuses to start, so the empty placeholders are created
  # here. `f` creates only when absent; it never truncates a real secret.
  systemd.tmpfiles.rules = [
    "d /etc/hqcat 0700 root root -"
    "d /etc/hqcat/${cfg.stack} 0700 root root -"
    "d /etc/hqcat/${cfg.stack}/secrets 0700 root root -"
    "d /opt/hqcat/${cfg.stack} 0755 root root -"
    "d /var/lib/hqcat/${cfg.stack} 0700 root root -"
  ]
  # Owned by 1000:1000, not root. Compose bind-mounts each of these to
  # /run/secrets/<name> with the host's owner and mode intact, and every
  # container that reads one runs as uid 1000 -- `node` in the server image,
  # `emqx` in emqx/emqx:5.8, which happen to agree. Left as root:root the mode
  # is 0600 against a process that is not root, so the first thing the stack
  # does is:
  #
  #   config: DATABASE_URL_DIRECT_FILE=/run/secrets/database_url_direct could
  #   not be read: EACCES: permission denied
  #   [migrate] failed: DATABASE_URL_DIRECT (or DATABASE_URL) is required
  #
  # and the rollout halts on db-migrate. The mode stays 0600: this is ownership,
  # not a loosening. Root still reads them; the containers now can too, and
  # nothing else on the host runs as 1000 (there are no other users at all).
  ++ map (n: "f /etc/hqcat/${cfg.stack}/secrets/${n} 0600 1000 1000 -") [
    # The database credentials. On prod they come from `terraform output` in
    # infra/database; on pre-prod set-host-secrets.sh generates them for the
    # postgres container that stack runs. Empty placeholders only: `f` creates
    # when absent and never truncates, so a rebuild cannot wipe a real one — but
    # the files must EXIST or `docker compose up` refuses to start the stack.
    #
    # A host that boots with these empty gets a stack that fails its migration
    # step and stops, which is the correct outcome: better a rollout that halts
    # than one that comes up with no state.
    "database_url"
    "database_url_direct"
    "pg_ca_cert"
    "emqx_pg"
    # Pre-prod only (its postgres container reads it); harmless on prod, which
    # has no such service and never mounts it.
    "pg_local_password"
    "stripe_secret_key"
    "stripe_webhook_secret"
    "resend_api_key"
    "apns_key_p8"
    "otp_pepper"
  ]
  # `f` applies ownership only when it CREATES the file, and every secret on an
  # existing host was written root-owned by set-host-secrets.sh before this
  # changed. `z` adjusts what is already there, on every activation, so a host is
  # corrected by a rebuild instead of by someone remembering to chown.
  ++ map (n: "z /etc/hqcat/${cfg.stack}/secrets/${n} 0600 1000 1000 -") [
    "database_url"
    "database_url_direct"
    "pg_ca_cert"
    "emqx_pg"
    "pg_local_password"
    "stripe_secret_key"
    "stripe_webhook_secret"
    "resend_api_key"
    "apns_key_p8"
    "otp_pepper"
  ];

  # The OTP pepper is the one secret that must never be empty: without it a
  # database dump yields every pending subscription claim code. It also has no
  # external source — unlike the Stripe/APNs keys and the database URL it is ours
  # to generate — so the host makes its own rather than waiting for an operator
  # to remember.
  systemd.services.hqcat-otp-pepper = {
    description = "Generate the OTP pepper if this host does not have one";
    wantedBy = [ "multi-user.target" ];
    before = [ "hqcat-agent.service" ];
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
      f=/etc/hqcat/${cfg.stack}/secrets/otp_pepper
      if [ ! -s "$f" ]; then
        echo "generating a new OTP pepper for the ${cfg.stack} stack"
        ( umask 077; openssl rand -hex 32 > "$f" )
        chmod 0600 "$f"
      fi
    '';
  };
}
