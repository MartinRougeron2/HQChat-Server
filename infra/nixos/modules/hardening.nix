# Sections 2-5 of the old harden-vm.sh: SSH, fail2ban, automatic security
# updates, and kernel/network sysctls.
#
# The old script had a footgun that this file structurally cannot have. It wrote
# `KbdInteractiveAuthentication no` into a 99- drop-in that sorted last, so
# running it AFTER enrolling a deploy user in google-authenticator silently
# disabled the TOTP gate — order-dependent, invisible, and only discoverable by
# trying to log in. Here the final sshd config is a pure function of this file.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.hqcat;
in
{
  services.openssh = {
    enable = true;
    settings = {
      PermitRootLogin = "prohibit-password"; # key-only; nixos-anywhere needs root
      PasswordAuthentication = false;
      # TOTP rides on the keyboard-interactive channel, so this has to be ON for
      # a second factor to be possible at all. This is precisely the switch the
      # old harden-vm.sh flipped to `no` in a 99- drop-in that sorted last,
      # silently disabling 2FA for anyone who ran it after enrolling.
      KbdInteractiveAuthentication = cfg.admin.totp;
      PermitEmptyPasswords = false;
      X11Forwarding = false;
      MaxAuthTries = 3;
      LoginGraceTime = 30;
      ClientAliveInterval = 300;
      ClientAliveCountMax = 2;
    };
    # Host keys are machine state, not config — they must survive a rebuild, and
    # they must NOT come from the closure (it is world-readable in the cache).
    hostKeys = [
      {
        path = "/etc/ssh/ssh_host_ed25519_key";
        type = "ed25519";
      }
    ];
  };

  # The only way into this machine. Nothing automated uses SSH, so this is a
  # list of humans — normally one key on one laptop.
  users.users.root.openssh.authorizedKeys.keys = cfg.admin.sshKeys;

  # No password on root, at all: not "a hard one", none. `!` is not a valid hash,
  # so password authentication cannot succeed even if sshd config regressed or
  # someone reaches a console.
  users.users.root.hashedPassword = "!";

  services.openssh.extraConfig = lib.mkMerge [
    # Only root may log in. There are no other accounts, so this is belt-and-
    # braces against a future module adding a service user with a shell.
    "AllowUsers root\n"
    # Key AND code, not key OR code: `publickey,keyboard-interactive` requires
    # both to succeed in sequence.
    (lib.mkIf cfg.admin.totp "AuthenticationMethods publickey,keyboard-interactive:pam\n")
  ];

  # The TOTP prompt itself. `google-authenticator` must have been run for root
  # BEFORE this is enabled, or SSH becomes impossible — see the option's docs.
  security.pam.services.sshd.googleAuthenticator.enable = lib.mkIf cfg.admin.totp true;

  # The TOOL is installed unconditionally; only the PAM module above is gated on
  # the flag. Gating both created a deadlock with the enrolment order this very
  # file insists on: enrol first, prove a second session works, then enable --
  # because enabling before enrolling locks SSH. With the package behind the
  # same flag, `google-authenticator` did not exist until the switch that locks
  # you out had already been thrown.
  #
  # A secret generator sitting unused on disk grants nothing: without
  # `admin.totp` PAM never consults ~/.google_authenticator, and sshd does not
  # offer keyboard-interactive at all.
  environment.systemPackages = [ pkgs.google-authenticator ];

  assertions = [
    {
      assertion = cfg.admin.sshKeys != [ ];
      message = ''
        hqcat.admin.sshKeys is empty: this host would have no way in at all
        (no password, no other users). Add your public key in
        infra/nixos/hosts/<host>.nix.
      '';
    }
  ];

  services.fail2ban = {
    enable = true;
    maxretry = 5;
    bantime = "1h";
    bantime-increment.enable = true;
  };

  # Equivalent of unattended-upgrades. Only the *host* auto-updates here, from
  # our own cache — see host-agent.nix. Nixpkgs itself is pinned in flake.lock
  # and bumped deliberately, so there is no unreviewed package drift.
  system.autoUpgrade.enable = false;

  boot.kernel.sysctl = {
    "net.ipv4.conf.all.rp_filter" = 1;
    "net.ipv4.conf.default.rp_filter" = 1;
    "net.ipv4.conf.all.accept_redirects" = 0;
    "net.ipv6.conf.all.accept_redirects" = 0;
    "net.ipv4.conf.all.send_redirects" = 0;
    "net.ipv4.conf.all.accept_source_route" = 0;
    "net.ipv4.tcp_syncookies" = 1;
    "kernel.dmesg_restrict" = 1;
    "kernel.kptr_restrict" = 2;
  };

  # Nothing interactive should ever be needed on these boxes.
  security.sudo.execWheelOnly = true;
  users.mutableUsers = lib.mkDefault false;
}
