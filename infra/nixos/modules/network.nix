# Networking, declared. DigitalOcean does not run a DHCP server: a droplet gets
# its addressing from a cloud-init config drive (`vdb`, iso9660 "config-2"),
# which the stock Ubuntu image reads and NixOS does not. `hardware.nix` used to
# say `networking.useDHCP = true` on the strength of a comment claiming "DO gives
# every droplet a public v4/v6 via DHCP + RA" -- and the first host ever built
# from this config booted, printed a login prompt on the console, and answered
# nothing on the network, because nothing ever answered its DISCOVER.
#
# The addresses live in hosts/<name>.nix, read off each droplet with
# `ip route; ip -4 addr show`. That does duplicate what DigitalOcean, the
# Terraform state and the CI secrets already know, and duplication is how the
# hostname ended up wrong in fourteen places. It is deliberate for now: reading
# the config drive means running cloud-init, and cloud-init's user/SSH stages
# have opinions that this host's hardening (no root password, immutable users)
# would have to be reconciled with -- work worth doing when a host is reachable
# and a mistake costs a rebuild rather than a rescue ISO.
{ config, ... }:
let
  cfg = config.hqcat.net;
in
{
  networking.useDHCP = false;
  networking.useNetworkd = true;
  networking.nameservers = cfg.nameservers;

  # Matched by every name the interface can have. The droplet reports `eth0`
  # with altnames `ens3` and `enp0s3`; which of those NixOS's udev settles on
  # depends on the naming scheme in force, and a .network file that matches none
  # of them applies nothing at all -- failing exactly like no config, on a
  # machine with no other way in.
  systemd.network.networks."10-public" = {
    matchConfig.Name = "eth0 ens3 enp0s3";
    address = [
      cfg.publicV4
      cfg.anchorV4
    ];
    routes = [ { Gateway = cfg.gatewayV4; } ];
    linkConfig.RequiredForOnline = "routable";
  };

  # The VPC side. No gateway: it carries no default route, it exists so the
  # managed Postgres -- which admits the two droplets by private address and
  # nothing else -- is reachable at all.
  systemd.network.networks."20-vpc" = {
    matchConfig.Name = "eth1 ens4 enp0s4";
    address = [ cfg.vpcV4 ];
    linkConfig.RequiredForOnline = "no";
  };

  # IPv6 is deliberately absent. The droplets carry a v6 address, but Terraform
  # publishes no AAAA (`origin_ipv6` is null), so nothing reaches the origin over
  # it, and a v6 default route nobody verified is one more thing that can be
  # silently wrong on a host with no console login.
}
