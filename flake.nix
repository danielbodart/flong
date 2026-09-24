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

          # Phase 6's transition: the C fixtures, built in the check, against
          # the Zig ones where the build sandbox can run them
          # (tests/fixtures-transition.nix); the VM tests run the rest.
          fixtures-transition = import ./tests/fixtures-transition.nix { inherit pkgs; };

          # flong's programs against cases recorded from the C, byte for
          # byte: stdout, stderr, status, and filters (tests/golden.nix).
          golden = import ./tests/golden.nix { inherit pkgs; };

          # A refusal happens at evaluation, so it is checked by evaluating: each
          # declaration below must trip the assertion it is about, and the
          # baseline must trip none of flong's. Evaluation only -- no system is
          # built, which is what keeps this in seconds.
          assertions =
            let
              lib = nixpkgs.lib;
              configWith = extra:
                (lib.nixosSystem {
                  inherit system;
                  modules = [
                    ./module.nix
                    {
                      boot.isContainer = true;
                      system.stateVersion = "24.05";
                      # A user with declared ids, which a session needs.
                      containers.box = {
                        privateNetwork = true;
                        config = {
                          system.stateVersion = "24.05";
                          users.users.u = { isNormalUser = true; uid = 1000; group = "users"; };
                          users.groups.users.gid = 100;
                        };
                      };
                      flong.box = {
                        user = "u";
                        command = [ "true" ];
                      };
                    }
                    extra
                  ];
                }).config;
              flongFailures = extra:
                let config = configWith extra; in
                lib.filter (m: lib.hasPrefix "flong" m)
                  (map (a: lib.trim a.message)
                    (lib.filter (a: ! a.assertion) config.assertions));
              accepted = what: extra:
                flongFailures extra == [ ]
                || throw "assertions: ${what} was refused: ${builtins.toJSON (flongFailures extra)}";
              flongWarnings = extra:
                lib.filter (lib.hasPrefix "flong") (map lib.trim (configWith extra).warnings);

              # A message with its line breaks and indentation as single
              # spaces, so that a needle does not depend on where a message
              # happens to wrap.
              words = s: lib.concatStringsSep " "
                (lib.filter (w: builtins.isString w && w != "") (builtins.split "[[:space:]]+" s));
              refused = what: extra: needle:
                let failures = flongFailures extra; in
                lib.any (m: lib.hasInfix needle (words m)) failures
                || throw "assertions: ${what} was not refused; flong said: ${builtins.toJSON failures}";
              warned = what: extra: needle:
                let warnings = flongWarnings extra; in
                lib.any (m: lib.hasInfix needle (words m)) warnings
                || throw "assertions: ${what} was not warned about; flong said: ${builtins.toJSON warnings}";
              # An option value its type refuses, which stops evaluation
              # rather than failing an assertion.
              untyped = extra: path:
                ! (builtins.tryEval (builtins.deepSeq (lib.getAttrFromPath path (configWith extra)) true)).success;
            in
            # The baseline, the strict tier with every fixed filter, trips
            # nothing and warns about nothing.
            assert flongFailures { } == [ ]
              || throw "assertions: the baseline is refused: ${builtins.toJSON (flongFailures { })}";
            assert flongWarnings { } == [ ]
              || throw "assertions: the baseline warns ${builtins.toJSON (flongWarnings { })}";
            assert refused "the declaration's own forwardPorts"
              { containers.box.forwardPorts = [ { hostPort = 8080; } ]; }
              "static per container";
            assert accepted "a network on a private container" { flong.box.network.hostPorts = [ 5432 ]; };
            # With no tier there is no allow-list filter for a policy to act
            # on. debug and errno have nothing to act on either, but are
            # harmless, so they are accepted.
            assert refused "seccomp.allow with no tier"
              { flong.box.seccomp = { tier = null; allow = [ "ptrace" ]; }; }
              "no filter";
            assert refused "seccomp.deny with no tier"
              { flong.box.seccomp = { tier = null; deny = [ "ptrace" ]; }; }
              "no filter";
            assert refused "seccomp.log with no tier"
              { flong.box.seccomp = { tier = null; log = true; }; }
              "no filter";
            assert refused "a seccompPolicy with no tier"
              {
                flong.box.seccomp.tier = null;
                flong.box.seccompPolicy = "echo allow ptrace";
              }
              "no filter";
            assert accepted "debug and errno with no tier"
              { flong.box.seccomp = { tier = null; debug = true; errno = "EACCES"; }; };
            assert warned "no tier"
              { flong.box.seccomp.tier = null; }
              "only the audit, tty and namespace masks";
            assert warned "log = true"
              { flong.box.seccomp.log = true; }
              "for learning a policy, not for untrusted payloads";
            assert accepted "every tier setting and loosening together"
              {
                flong.box.seccomp = {
                  tier = "parity";
                  debug = true;
                  nestedSandbox = true;
                  allow = [ "@keyring" "userfaultfd" ];
                  deny = [ "ptrace" "@swap" ];
                  errno = "ENOSYS";
                };
                flong.box.seccompPolicy = "echo allow ptrace";
              };
            # A name is a syscall or a group, in the form systemd lists them.
            assert untyped { flong.box.seccomp.allow = [ "Ptrace" ]; } [ "flong" "box" "seccomp" "allow" ]
              || throw "assertions: an upper-case seccomp name was accepted";
            assert untyped { flong.box.seccomp.deny = [ "@ keyring" ]; } [ "flong" "box" "seccomp" "deny" ]
              || throw "assertions: a seccomp name with a blank was accepted";
            assert untyped { flong.box.seccomp.errno = "EINVAL"; } [ "flong" "box" "seccomp" "errno" ]
              || throw "assertions: an errno outside EPERM, EACCES and ENOSYS was accepted";
            assert lib.any (lib.hasInfix "consistency check and not a gate")
              (flongWarnings { flong.box.guard = "true"; })
              || throw "assertions: a guard is not warned about";
            assert refused "a container name beginning with a dot"
              {
                containers.".box" = { privateNetwork = true; config.system.stateVersion = "24.05"; };
                flong.box.container = ".box";
              }
              "not start with `.`";
            assert refused "extraFlags"
              { containers.box.extraFlags = [ "--private-network" ]; }
              "whose extraFlags are nspawn flags";
            assert refused "a networkNamespace"
              {
                containers.box.networkNamespace = "/run/netns/other";
                containers.box.privateNetwork = lib.mkForce false;
              }
              "names a networkNamespace";
            assert refused "scopeConfig"
              { flong.box.scopeConfig.MemoryMax = "1G"; }
              "sets scopeConfig";
            assert refused "a tmpfs option there is no field for"
              { containers.box.tmpfs = [ "/scratch:nosuid" ]; }
              "names options it cannot honour";
            assert refused "a tmpfs owned by a third user"
              { containers.box.tmpfs = [ "/scratch:uid=5,gid=5" ]; }
              "names options it cannot honour";
            assert refused "a tmpfs uid without its gid"
              { containers.box.tmpfs = [ "/scratch:uid=0" ]; }
              "names options it cannot honour";
            assert refused "a forwarded port below 1024"
              { flong.box.network.forwardPorts = [ { hostPort = 80; } ]; }
              "below net.ipv4.ip_unprivileged_port_start";
            assert refused "a bind of flong's state"
              { containers.box.bindMounts."/state".hostPath = "/run/user/1000/flong"; }
              "reaches flong's state";
            assert refused "a bind of the user manager's socket, spelt through /var/run"
              { containers.box.bindMounts."/bus".hostPath = "/var/run/user/1000//bus"; }
              "reaches flong's state";
            assert refused "a bind containing /proc"
              { containers.box.bindMounts."/host".hostPath = "/"; }
              "reaches flong's state";
            assert refused "an overlay lower inside a protected path"
              {
                flong.box.protect = [ "/srv/gate" ];
                flong.box.overlays."/data" = "/srv/gate/data";
              }
              "reaches flong's state";
            assert refused "a mask two levels below a writable bind"
              {
                containers.box.bindMounts."/srv/shared" = { hostPath = "/srv/shared"; isReadOnly = false; };
                flong.box.masks = [ "/srv/shared/a/token" ];
              }
              "two or more levels below";
            assert refused "a mask whose host path is deep in another writable bind"
              {
                containers.box.bindMounts."/ro" = { hostPath = "/srv/shared/a"; isReadOnly = true; };
                containers.box.bindMounts."/rw" = { hostPath = "/srv/shared"; isReadOnly = false; };
                flong.box.masks = [ "/ro/token" ];
              }
              "/ro/token (in the writable bind of /srv/shared)";
            assert refused "a device outside /dev"
              { containers.box.allowedDevices = [ { node = "/srv/null"; modifier = "rw"; } ]; }
              "allowedDevices has /srv/null rw";
            assert refused "a read-only device"
              { containers.box.allowedDevices = [ { node = "/dev/null"; modifier = "r"; } ]; }
              "allowedDevices has /dev/null r";
            assert refused "a bind of a device"
              { containers.box.bindMounts."/dev/snd".hostPath = "/dev/snd"; }
              "A plain bind is nodev";
            assert refused "a shared host network"
              { containers.box.privateNetwork = lib.mkForce false; }
              "does not set privateNetwork = true";
            assert refused "a user the container does not have"
              { flong.box.user = lib.mkForce "nobody-here"; }
              "nobody-here is not a user in containers.box";
            # A container declared by `path` alone is refused too, but is not
            # tested here: the container module's own assertions read every
            # container's `config`, so such a host does not evaluate at all.
            assert refused "a user without a declared uid"
              {
                containers.box.config.users.users.v = { isNormalUser = true; group = "users"; };
                flong.box.user = lib.mkForce "v";
              }
              "is not declared";
            assert refused "a user beyond the container's ids"
              {
                containers.box.config.users.users.w = { isNormalUser = true; uid = 70000; group = "users"; };
                flong.box.user = lib.mkForce "w";
              }
              "outside the container's ids";
            assert refused "an unclean mask"
              { flong.box.masks = [ "/srv/../etc/shadow" ]; }
              "is not a clean absolute path";
            assert refused "an unclean protect entry"
              { flong.box.protect = [ "/srv/gate/" ]; }
              "is not a clean absolute path";
            assert refused "a mask on a bind's own destination"
              {
                containers.box.bindMounts."/srv/b".hostPath = "/srv/b";
                flong.box.masks = [ "/srv/b" ];
              }
              "twice";
            assert refused "a device that is also bound"
              {
                containers.box.allowedDevices = [ { node = "/dev/snd"; modifier = "rw"; } ];
                containers.box.bindMounts."/dev/snd".hostPath = "/dev/snd";
              }
              "at /dev/snd twice";
            assert refused "autoStart"
              { containers.box.autoStart = true; }
              "has autoStart enabled";
            assert refused "a host without user namespaces"
              { security.allowUserNamespaces = false; }
              "security.allowUserNamespaces is false";
            assert refused "a host without newuidmap"
              { security.wrappers.newuidmap.enable = lib.mkForce false; }
              "does not install";
            assert accepted "odd bind and tmpfs paths"
              {
                containers.box.bindMounts."/in side:colon\\slash".hostPath = "/out side:colon\\slash";
                containers.box.tmpfs = [ "/tmp/with space" ];
              };
            assert accepted "a mask one level below a writable bind"
              {
                containers.box.bindMounts."/srv/shared" = { hostPath = "/srv/shared"; isReadOnly = false; };
                flong.box.masks = [ "/srv/shared/masked" ];
              };
            # The depth rule is for masks below writable binds only: a tmpfs or
            # an overlay deep below one, and a mask deep below a read-only
            # one, are allowed.
            assert accepted "a tmpfs and an overlay deep below a writable bind"
              {
                containers.box.bindMounts."/srv/shared" = { hostPath = "/srv/shared"; isReadOnly = false; };
                containers.box.tmpfs = [ "/srv/shared/a/cache" ];
                flong.box.overlays."/srv/shared/b/state" = "/var/empty";
              };
            assert accepted "a mask deep below a read-only bind"
              {
                containers.box.bindMounts."/srv/ref" = { hostPath = "/srv/ref"; isReadOnly = true; };
                flong.box.masks = [ "/srv/ref/a/token" ];
              };
            assert accepted "a forwarded port at 1024"
              { flong.box.network.forwardPorts = [ { hostPort = 1024; } ]; };
            assert accepted "a bind of a directory in the runtime directory"
              { containers.box.bindMounts."/run/cc-socks".hostPath = "/run/user/1000/cc-socks"; };
            assert accepted "a tmpfs with a mode and a size"
              { containers.box.tmpfs = [ "/scratch:mode=1777,size=10M" "/rootish:uid=0,gid=0" "/mine:uid=1000,gid=100" ]; };
            assert accepted "a device with rwm"
              { containers.box.allowedDevices = [ { node = "/dev/null"; modifier = "rwm"; } ]; };
            assert accepted "a directory device without a bind"
              { containers.box.allowedDevices = [ { node = "/dev/snd"; modifier = "rw"; } ]; };
            assert accepted "the container's root as the user"
              { flong.box.user = lib.mkForce "root"; };
            # The holder unit exists once there is a declaration, and is
            # delegated, in app.slice, with the sweeper as its process.
            assert (let
                units = (configWith { }).systemd.user.units;
                text = units."flong-sessions.service".text or "";
              in
              lib.all (l: lib.hasInfix l text) [
                "Type=exec" "Slice=app.slice" "Delegate=yes" "DelegateSubgroup=supervisor"
                "OOMPolicy=continue" "/bin/flong-sweeper %t/flong"
              ]) || throw "assertions: the holder unit is missing or wrong";
            assert ! (configWith { flong = lib.mkForce { }; }).systemd.user.units ? "flong-sessions.service"
              || throw "assertions: the holder unit exists with no declaration";
            # `command` is an argument list: neither a shell string nor an
            # empty list evaluates.
            assert ! (builtins.tryEval (builtins.deepSeq
              (configWith { flong.box.command = lib.mkForce "set -- true"; }).flong.box.command
              true)).success
              || throw "assertions: a string command was accepted";
            assert ! (builtins.tryEval (builtins.deepSeq
              (configWith { flong.box.command = lib.mkForce [ ]; }).flong.box.command
              true)).success
              || throw "assertions: an empty command was accepted";
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
