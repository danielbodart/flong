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

      checks = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system}; in
        {
          basic = pkgs.testers.runNixOSTest {
            imports = [ ./tests/basic.nix ];
          };

          # A refusal happens at evaluation, so it is checked by evaluating: each
          # declaration below must trip the assertion it is about, and the
          # baseline must trip none of flong's. Evaluation only -- no system is
          # built, which is what keeps this in seconds.
          assertions =
            let
              lib = nixpkgs.lib;
              flongFailures = extra:
                let
                  config = (lib.nixosSystem {
                    inherit system;
                    modules = [
                      ./module.nix
                      {
                        boot.isContainer = true;
                        system.stateVersion = "24.05";
                        containers.box = {
                          privateNetwork = true;
                          config.system.stateVersion = "24.05";
                        };
                        flong.box = {
                          user = "root";
                          command = "set -- true";
                        };
                      }
                      extra
                    ];
                  }).config;
                in
                lib.filter (m: lib.hasPrefix "flong" m)
                  (map (a: lib.trim a.message)
                    (lib.filter (a: ! a.assertion) config.assertions));
              refused = what: extra: needle:
                let failures = flongFailures extra; in
                lib.any (lib.hasInfix needle) failures
                || throw "assertions: ${what} was not refused; flong said: ${builtins.toJSON failures}";
            in
            assert flongFailures { } == [ ]
              || throw "assertions: the baseline is refused: ${builtins.toJSON (flongFailures { })}";
            assert refused "--capability in extraFlags"
              { containers.box.extraFlags = [ "--capability=CAP_NET_ADMIN" ]; }
              "whose extraFlags ask";
            assert refused "--ambient-capability as two words"
              { containers.box.extraFlags = [ "--ambient-capability CAP_NET_RAW" ]; }
              "whose extraFlags ask";
            assert refused "-U in extraFlags"
              { containers.box.extraFlags = [ "-U" ]; }
              "whose extraFlags ask";
            assert refused "--private-users in extraFlags"
              { containers.box.extraFlags = [ "--private-users=pick" ]; }
              "whose extraFlags ask";
            pkgs.runCommand "assertions" { } "touch $out";

          # The version script decides what every release is called, so it is
          # gated by the same check that gates the release.
          shellcheck = pkgs.runCommand "shellcheck"
            { nativeBuildInputs = [ pkgs.shellcheck ]; }
            ''
              shellcheck ${./scripts/version.sh}
              touch $out
            '';
        });

      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixpkgs-fmt);
    };
}
