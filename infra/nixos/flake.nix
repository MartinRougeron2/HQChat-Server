{
  description = "HQCAT host configuration — the VMs that run the DissQus stack";

  # NixOS 26.05 "Yarara" (released 2026-05-30, supported to 2026-12-31).
  # Pinned by flake.lock; bump deliberately, never implicitly.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  # `nixos-anywhere` partitions and formats the target from `disko.devices`
  # (./modules/disk.nix). Without this input the install stops at
  #   does not provide attribute '...config.system.build.diskoScript'
  # which is what a flake that declares fileSystems but never declares a disk
  # layout looks like from the outside.
  inputs.disko.url = "github:nix-community/disko";
  inputs.disko.inputs.nixpkgs.follows = "nixpkgs";

  outputs =
    { self, nixpkgs, disko }:
    let
      system = "x86_64-linux";

      # A host is ./modules (identical everywhere) plus ./hosts/<name>.nix,
      # which carries only the facts that genuinely differ.
      mkHost =
        name:
        nixpkgs.lib.nixosSystem {
          inherit system;
          modules = [
            disko.nixosModules.disko
            ./modules
            ./admin.nix
            ./hosts/${name}.nix
            {
              networking.hostName = "dissqus-${name}";
              # Set at install time and never changed afterwards; read the NixOS
              # manual on system.stateVersion before touching it.
              system.stateVersion = "26.05";
            }
          ];
        };

      hosts = [
        "prod"
        "preprod"
      ];
    in
    {
      nixosConfigurations = nixpkgs.lib.genAttrs hosts mkHost;

      # What CI builds and pushes to the cache:
      #   nix build .#toplevel-prod
      packages.${system} = nixpkgs.lib.listToAttrs (
        map (n: {
          name = "toplevel-${n}";
          value = self.nixosConfigurations.${n}.config.system.build.toplevel;
        }) hosts
      );

      formatter.${system} = nixpkgs.legacyPackages.${system}.nixfmt-rfc-style;
    };
}
