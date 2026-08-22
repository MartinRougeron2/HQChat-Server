# DigitalOcean droplet basics. `nixos-anywhere` runs disko/nixos-install against
# this, so the disk layout has to be declared rather than discovered.
{ modulesPath, ... }:
{
  imports = [ (modulesPath + "/profiles/qemu-guest.nix") ];

  boot.loader.grub = {
    enable = true;
    device = "/dev/vda";
  };
  boot.initrd.availableKernelModules = [
    "ata_piix"
    "uhci_hcd"
    "xen_blkfront"
    "virtio_pci"
    "virtio_scsi"
    "virtio_blk"
  ];

  fileSystems."/" = {
    device = "/dev/vda1";
    fsType = "ext4";
  };

  # Droplets ship no swap. The stack is memory-capped in compose, but a Nix
  # closure substitution can spike; a little zram costs nothing.
  zramSwap.enable = true;

  # DO gives every droplet a public v4/v6 via DHCP + RA.
  networking.useDHCP = true;
}
