# The disk layout, declared so `nixos-anywhere` can create it.
#
# hardware.nix used to declare `fileSystems."/" = /dev/vda1` and nothing else,
# which says how to MOUNT a partition that already exists — it does not create
# one. nixos-anywhere partitions from `disko.devices`, and with no disko config
# in the flake it stopped at:
#
#   error: flake ... does not provide attribute
#   '...nixosConfigurations."preprod".config.system.build.diskoScript'
#
# Legacy BIOS, not UEFI: DigitalOcean's droplets boot that way, and
# hardware.nix has always asked for `boot.loader.grub.device = "/dev/vda"`
# with no EFI support, so this matches what the rest of the config expects.
# GRUB on a GPT disk needs somewhere to put its core image, which is what the
# 1M EF02 partition is for — without it `grub-install` has nowhere to go and
# the machine comes back unbootable.
{
  disko.devices.disk.main = {
    device = "/dev/vda";
    type = "disk";
    content = {
      type = "gpt";
      partitions = {
        # No filesystem and no mountpoint: GRUB writes raw bytes here.
        boot = {
          size = "1M";
          type = "EF02";
        };
        root = {
          size = "100%";
          content = {
            type = "filesystem";
            format = "ext4";
            mountpoint = "/";
          };
        };
      };
    };
  };
}
