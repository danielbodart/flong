{
  description = "Ephemeral systemd-nspawn containers that start in milliseconds";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      nixosModules.flong = ./module.nix;
      nixosModules.default = self.nixosModules.flong;

      checks = forAllSystems (system: {
        basic = nixpkgs.legacyPackages.${system}.testers.runNixOSTest {
          imports = [ ./tests/basic.nix ];
        };
      });

      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixpkgs-fmt);
    };
}
