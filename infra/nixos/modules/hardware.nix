# DigitalOcean droplet basics. The DISK layout lives in ./disk.nix, which is what
# nixos-anywhere partitions and formats from; `fileSystems` is generated from it
# rather than written here, so the two cannot disagree about where root is.
{ modulesPath, ... }:
{
  imports = [ (modulesPath + "/profiles/qemu-guest.nix") ];

  # `devices` is NOT set here: disko already appends the parent disk to
  # `boot.loader.grub.devices` when it sees the EF02 partition (./disk.nix), and
  # NixOS counts `device` and `devices` into the same mirroredBoots list --
  # naming the disk in both is what produced
  #   Failed assertions:
  #   - You cannot have duplicated devices in mirroredBoots
  # The same mistake as the old `fileSystems."/"`: two declarations of one fact.
  boot.loader.grub.enable = true;
  boot.initrd.availableKernelModules = [
    "ata_piix"
    "uhci_hcd"
    "xen_blkfront"
    "virtio_pci"
    "virtio_scsi"
    "virtio_blk"
  ];

  # Droplets ship no swap. The stack is memory-capped in compose, but a Nix
  # closure substitution can spike; a little zram costs nothing.
  zramSwap.enable = true;

}
