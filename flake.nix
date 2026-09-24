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
          vmTestPart = file: part: pkgs.testers.runNixOSTest {
            imports = [ file ];
            inherit part;
          };
        in
        # The Zig package's own checks (native.nix): native-test-debug and
        # native-test-release (unit, property and test-libc), native-lint (fdlint,
        # compile-fail, zig fmt), native-analyze (zwanzig), and on x86_64
        # cross-aarch64.
        native.checks //
        {
          # Every option that changes what a session sees, launched by a
          # lingering user with no sudo: tests/basic.nix, in two parts, each
          # its own VM with about half the subtests (tests/parts.nix).
          basic-a = vmTestPart ./tests/basic.nix "a";
          basic-b = vmTestPart ./tests/basic.nix "b";

          # The engine itself: identity, the gate, mounts, the lifecycle,
          # seccomp and the terminal, launched by a lingering user with no
          # sudo: tests/rootless.nix, in two parts as basic's are.
          rootless-a = vmTestPart ./tests/rootless.nix "a";
          rootless-b = vmTestPart ./tests/rootless.nix "b";

          # The seccomp stacks of two tiers, live in one VM: the filters
          # dumped and matched with the build's, and a syscall probe.
          parity = pkgs.testers.runNixOSTest {
            imports = [ ./tests/parity.nix ];
          };

          # What the native code needs a kernel for: a delegated user
          # manager, subordinate ids, a real pid 1 (DESIGN.md, "The build").
          native = pkgs.testers.runNixOSTest {
            imports = [ ./tests/native.nix ];
          };

          # Every derivation of tests/integration.nix, each
          # proof's build-sandbox assertions, never an output.
          integration = pkgs.linkFarm "integration"
            (import ./tests/integration.nix { inherit pkgs; });

          # The native launcher set: flong, one binary whose subcommands are
          # launch, init and sweeper, Zig, static, without libc (native.nix).
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
      apps.x86_64-linux = let
        pkgs = nixpkgs.legacyPackages.x86_64-linux;
      in {
        golden-update = {
          type = "app";
          program = "${self.checks.x86_64-linux.golden.update}/bin/golden-update";
          meta.description = "Rewrite tests/golden's filters after a libseccomp bump";
        };

        # The local gate, `nix run .#gate` from the repository's root: every
        # x86_64 check, evaluated by nix-fast-build's parallel workers and
        # each built as its evaluation finishes, where `nix flake check`
        # evaluates them one after another before it builds any. Checks
        # already in a binary cache are skipped (--skip-cached); a check
        # that fails to evaluate or build makes the exit status non-zero.
        # A worker takes up to about 3 GB (rootless-b; each assertion shard
        # about 2 GB, tests/assertions.nix) and is restarted past 6 GiB, so
        # there is one worker per 10 GiB of the host's memory, at least one:
        # the rest is room for the builds and their VMs. Memory, not cores,
        # is what runs out: a fixed six once froze a 32 GB host without
        # swap. GATE_EVAL_WORKERS overrides the count; the arguments are
        # nix-fast-build's (--select to run some checks, say).
        gate = {
          type = "app";
          program = pkgs.lib.getExe (pkgs.writeShellApplication {
            name = "flong-gate";
            runtimeInputs = [ pkgs.nix-fast-build pkgs.gawk ];
            text = ''
              kib=$(awk '/^MemTotal:/ { print $2 }' /proc/meminfo)
              workers=$((kib / (10 * 1024 * 1024)))
              if ((workers < 1)); then workers=1; fi
              exec nix-fast-build --flake ".#checks.x86_64-linux" --skip-cached --no-nom \
                --eval-workers "''${GATE_EVAL_WORKERS:-$workers}" --eval-max-memory-size 6144 "$@"
            '';
          });
          meta.description = "Build every x86_64 check in parallel, skipping what a cache has";
        };

        # aarch64's checks evaluated, not built (this host cannot run them):
        # each must instantiate, which is what catches an aarch64-only
        # evaluation error. `nix run .#gate-aarch64`; a check that fails to
        # evaluate is printed and makes the exit status non-zero.
        gate-aarch64 = {
          type = "app";
          program = pkgs.lib.getExe (pkgs.writeShellApplication {
            name = "flong-gate-aarch64";
            runtimeInputs = [ pkgs.nix-eval-jobs pkgs.jq pkgs.gawk ];
            text = ''
              # One worker per 10 GiB, as the gate's.
              kib=$(awk '/^MemTotal:/ { print $2 }' /proc/meminfo)
              workers=$((kib / (10 * 1024 * 1024)))
              if ((workers < 1)); then workers=1; fi
              out=$(mktemp)
              trap 'rm -f "$out"' EXIT
              nix-eval-jobs --flake ".#checks.aarch64-linux" \
                --workers "''${GATE_EVAL_WORKERS:-$workers}" --max-memory-size 6144 > "$out"
              jq -r 'if .error then "error: \(.attr): \(.error)" else "ok: \(.attr) \(.drvPath)" end' "$out"
              # The control: the checks were listed at all.
              [[ -s $out ]] || { echo "gate-aarch64: no checks evaluated"; exit 1; }
              if jq -e 'select(.error)' "$out" > /dev/null; then exit 1; fi
            '';
          });
          meta.description = "Evaluate every aarch64 check without building it";
        };
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
