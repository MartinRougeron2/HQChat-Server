# The whole host, declared. Every one of these files replaces a section of the
# old imperative harden-vm.sh / install-agent.sh, with one difference that is
# the entire point: these are enforced on every rebuild, not applied once and
# then left to drift.
{ lib, ... }:
{
  imports = [
    ./options.nix
    ./hardware.nix
    ./hardening.nix
    ./firewall.nix
    ./docker.nix
    ./nginx.nix
    ./app-agent.nix
    ./host-agent.nix
  ];

  # UTC everywhere so log timestamps line up with GitHub Actions and Sentry.
  time.timeZone = lib.mkDefault "UTC";
  i18n.defaultLocale = "en_US.UTF-8";

  # No source code on these machines, and nothing that invites editing in
  # place: the app arrives as an OCI image, the host as a prebuilt closure.
  environment.defaultPackages = lib.mkForce [ ];
  documentation.nixos.enable = false;
}
