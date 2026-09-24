{
  description = "Ephemeral rootless containers that start in milliseconds";

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
        let
          pkgs = nixpkgs.legacyPackages.${system};
          native = import ./native.nix { inherit pkgs; };
        in
        # The Zig package's own checks (native.nix): native-test (unit,
        # property and test-libc, Debug and ReleaseSafe), native-lint (fdlint,
        # compile-fail, zig fmt), native-analyze (zwanzig), and on x86_64
        # cross-aarch64.
        native.checks //
        {
          # Every option that changes what a session sees, launched by a
          # lingering user with no sudo.
          basic = pkgs.testers.runNixOSTest {
            imports = [ ./tests/basic.nix ];
          };

          # The engine itself: identity, the gate, mounts, the lifecycle,
          # seccomp and the terminal, launched by a lingering user with no sudo.
          rootless = pkgs.testers.runNixOSTest {
            imports = [ ./tests/rootless.nix ];
          };

          # The seccomp stacks of two tiers, live in one VM: the filters
          # dumped and matched with the build's, and a syscall probe.
          parity = pkgs.testers.runNixOSTest {
            imports = [ ./tests/parity.nix ];
          };

          # The Zig port's proofs that need a kernel: a delegated user
          # manager, subordinate ids, a real pid 1 (ZIG.md, "Tests").
          native = pkgs.testers.runNixOSTest {
            imports = [ ./tests/native.nix ];
          };

          # Every derivation of tests/integration.nix, each
          # proof's build-sandbox assertions, never an output.
          integration = pkgs.linkFarm "integration"
            (import ./tests/integration.nix { inherit pkgs; });

          # The native launcher, built with -Werror.
          launcher = import ./launcher { inherit pkgs; };

          # The seccomp compiler, in Zig (native.nix's seccomp set).
          seccomp = import ./seccomp { inherit pkgs; };

          # flong's programs against cases recorded from the C, byte for
          # byte: stdout, stderr, status, and filters (tests/golden.nix).
          golden = import ./tests/golden.nix { inherit pkgs; };

          # The version script decides what every release is called, so it is
          # gated by the same check that gates the release.
          shellcheck = pkgs.runCommand "shellcheck"
            { nativeBuildInputs = [ pkgs.shellcheck ]; }
            ''
              shellcheck ${./scripts/version.sh}
              touch $out
            '';
        }
        # The refusals, evaluated in eight shards (tests/assertions.nix).
        # x86_64 alone: the module's logic does not depend on the
        # architecture, and the cases are two minutes of evaluation a system.
        // nixpkgs.lib.optionalAttrs (system == "x86_64-linux")
          (import ./tests/assertions.nix { inherit nixpkgs pkgs system; }));

      # Launch times, in one VM: built on
      # demand (`nix build .#bench`), never by `nix flake check`, because a
      # time is a number to report and not a test. The result holds
      # numbers.md.
      packages = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system}; in
        {
          bench = pkgs.testers.runNixOSTest {
            imports = [ ./tests/bench.nix ];
          };
        });

      # golden-update rewrites tests/golden's .bpf files and LIBSECCOMP
      # after a libseccomp bump, and refuses anything else: run it from the
      # repository's root (tests/golden.nix says when it may be used). The
      # .bpf files are x86_64's filters, so it is x86_64's alone.
      apps.x86_64-linux.golden-update = {
        type = "app";
        program = "${self.checks.x86_64-linux.golden.update}/bin/golden-update";
        meta.description = "Rewrite tests/golden's filters after a libseccomp bump";
      };

      # zig 0.15, libseccomp (found through NIX_LDFLAGS, as in the build)
      # and strace, for `zig build` in the repository (build.zig lists the
      # steps; -Ddev=true fetches the lazy dependencies).
      devShells = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system}; in
        {
          default = pkgs.mkShell {
            packages = [ pkgs.zig_0_15 pkgs.strace ];
            buildInputs = [ pkgs.libseccomp ];
          };
        });

      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixpkgs-fmt);
    };
}
