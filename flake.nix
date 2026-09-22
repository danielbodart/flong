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

          # The rootless engine's native launcher, built with -Werror.
          launcher = import ./launcher { inherit pkgs; };

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
                      containers.box = {
                        privateNetwork = true;
                        config.system.stateVersion = "24.05";
                      };
                      flong.box = {
                        user = "root";
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
              refused = what: extra: needle:
                let failures = flongFailures extra; in
                lib.any (lib.hasInfix needle) failures
                || throw "assertions: ${what} was not refused; flong said: ${builtins.toJSON failures}";
              accepted = what: extra:
                flongFailures extra == [ ]
                || throw "assertions: ${what} was refused: ${builtins.toJSON (flongFailures extra)}";

              # The same declaration on the rootless engine, as a user with
              # declared ids, which that engine needs.
              rootless = extra: {
                imports = [ extra ];
                flong.box = {
                  engine = "rootless";
                  user = lib.mkOverride 90 "u";
                };
                containers.box.config = {
                  users.users.u = { isNormalUser = true; uid = 1000; group = "users"; };
                  users.groups.users.gid = 100;
                };
              };
              flongWarnings = extra:
                lib.filter (lib.hasPrefix "flong") (map lib.trim (configWith extra).warnings);
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
            assert refused "network without privateNetwork"
              {
                containers.box.privateNetwork = nixpkgs.lib.mkForce false;
                flong.box.network = { };
              }
              "gives a session a network of its own";
            assert refused "the declaration's own forwardPorts"
              { containers.box.forwardPorts = [ { hostPort = 8080; } ]; }
              "static per container";
            assert flongFailures { flong.box.network.hostPorts = [ 5432 ]; } == [ ]
              || throw "assertions: a network on a private container is refused";
            # limits are the rootless engine's; nspawn's are scopeConfig.
            assert refused "limits under nspawn"
              { flong.box.limits.MemoryMax = "1G"; }
              "only the rootless engine writes";
            assert refused "oomGroup under nspawn"
              { flong.box.limits.oomGroup = true; }
              "limits.oomGroup";
            # THE ROOTLESS ENGINE. Its baseline trips nothing, and warns only
            # that it has no seccomp filter yet.
            assert accepted "the rootless baseline" (rootless { });
            assert (let w = flongWarnings (rootless { }); in
              lib.length w == 1 && lib.hasInfix "no seccomp filter" (lib.head w))
              || throw "assertions: the rootless baseline warns ${builtins.toJSON (flongWarnings (rootless { }))}";
            assert lib.any (lib.hasInfix "consistency check and not a gate")
              (flongWarnings (rootless { flong.box.guard = "true"; }))
              || throw "assertions: a rootless guard is not warned about";
            assert refused "an nspawn-hostile container name"
              (rootless {
                containers.".box" = { privateNetwork = true; config.system.stateVersion = "24.05"; };
                flong.box.container = ".box";
              })
              "not start with `.`";
            assert refused "extraFlags under rootless"
              (rootless { containers.box.extraFlags = [ "--private-network" ]; })
              "whose extraFlags\nare nspawn flags";
            assert refused "networkNamespace under rootless"
              (rootless {
                containers.box.networkNamespace = "/run/netns/other";
                containers.box.privateNetwork = lib.mkForce false;
              })
              "names a\nnetworkNamespace";
            assert refused "scopeConfig under rootless"
              (rootless { flong.box.scopeConfig.MemoryMax = "1G"; })
              "sets scopeConfig";
            assert refused "a tmpfs option there is no field for"
              (rootless { containers.box.tmpfs = [ "/scratch:nosuid" ]; })
              "names options it cannot honour";
            assert refused "a tmpfs owned by a third user"
              (rootless { containers.box.tmpfs = [ "/scratch:uid=5,gid=5" ]; })
              "names options it cannot honour";
            assert refused "a tmpfs uid without its gid"
              (rootless { containers.box.tmpfs = [ "/scratch:uid=0" ]; })
              "names options it cannot honour";
            assert refused "a forwarded port below 1024"
              (rootless { flong.box.network.forwardPorts = [ { hostPort = 80; } ]; })
              "below net.ipv4.ip_unprivileged_port_start";
            assert refused "a bind of flong's state"
              (rootless { containers.box.bindMounts."/state".hostPath = "/run/user/1000/flong"; })
              "reaches\nflong's state";
            assert refused "a bind of the user manager's socket, spelt through /var/run"
              (rootless { containers.box.bindMounts."/bus".hostPath = "/var/run/user/1000//bus"; })
              "reaches\nflong's state";
            assert refused "a bind containing /proc"
              (rootless { containers.box.bindMounts."/host".hostPath = "/"; })
              "reaches\nflong's state";
            assert refused "an overlay lower inside a protected path"
              (rootless {
                flong.box.protect = [ "/srv/gate" ];
                flong.box.overlays."/data" = "/srv/gate/data";
              })
              "reaches\nflong's state";
            assert refused "a mask two levels below a writable bind"
              (rootless {
                containers.box.bindMounts."/srv/shared" = { hostPath = "/srv/shared"; isReadOnly = false; };
                flong.box.masks = [ "/srv/shared/a/token" ];
              })
              "two or more\nlevels below";
            assert refused "a mask whose host path is deep in another writable bind"
              (rootless {
                containers.box.bindMounts."/ro" = { hostPath = "/srv/shared/a"; isReadOnly = true; };
                containers.box.bindMounts."/rw" = { hostPath = "/srv/shared"; isReadOnly = false; };
                flong.box.masks = [ "/ro/token" ];
              })
              "/ro/token (in the writable bind of /srv/shared)";
            assert refused "a device outside /dev"
              (rootless { containers.box.allowedDevices = [ { node = "/srv/null"; modifier = "rw"; } ]; })
              "allowedDevices has /srv/null rw";
            assert refused "a read-only device"
              (rootless { containers.box.allowedDevices = [ { node = "/dev/null"; modifier = "r"; } ]; })
              "allowedDevices has /dev/null r";
            assert refused "a bind of a device"
              (rootless { containers.box.bindMounts."/dev/snd".hostPath = "/dev/snd"; })
              "A plain bind is nodev";
            assert refused "a shared host network under rootless"
              (rootless { containers.box.privateNetwork = lib.mkForce false; })
              "does not\nset privateNetwork = true";
            assert refused "a user the container does not have"
              (rootless { flong.box.user = lib.mkForce "nobody-here"; })
              "nobody-here is not a user in containers.box";
            # A container declared by `path` alone is refused too, but is not
            # tested here: the container module's own assertions read every
            # container's `config`, so such a host does not evaluate at all.
            assert refused "a user without a declared uid"
              (rootless {
                containers.box.config.users.users.v = { isNormalUser = true; group = "users"; };
                flong.box.user = lib.mkForce "v";
              })
              "is not declared";
            assert refused "a user beyond the container's ids"
              (rootless {
                containers.box.config.users.users.w = { isNormalUser = true; uid = 70000; group = "users"; };
                flong.box.user = lib.mkForce "w";
              })
              "outside the container's ids";
            assert refused "an unclean mask"
              (rootless { flong.box.masks = [ "/srv/../etc/shadow" ]; })
              "is not a clean absolute path";
            assert refused "an unclean protect entry"
              (rootless { flong.box.protect = [ "/srv/gate/" ]; })
              "is not a clean absolute path";
            assert refused "a mask on a bind's own destination"
              (rootless {
                containers.box.bindMounts."/srv/b".hostPath = "/srv/b";
                flong.box.masks = [ "/srv/b" ];
              })
              "twice";
            assert refused "a device that is also bound"
              (rootless {
                containers.box.allowedDevices = [ { node = "/dev/snd"; modifier = "rw"; } ];
                containers.box.bindMounts."/dev/snd".hostPath = "/dev/snd";
              })
              "at /dev/snd twice";
            assert refused "autoStart under rootless"
              (rootless { containers.box.autoStart = true; })
              "contrary to engine = \"rootless\"";
            assert refused "a host without user namespaces"
              (rootless { security.allowUserNamespaces = false; })
              "security.allowUserNamespaces is false";
            assert refused "a host without newuidmap"
              (rootless { security.wrappers.newuidmap.enable = lib.mkForce false; })
              "does not\ninstall";
            assert accepted "odd bind and tmpfs paths under rootless"
              (rootless {
                containers.box.bindMounts."/in side:colon\\slash".hostPath = "/out side:colon\\slash";
                containers.box.tmpfs = [ "/tmp/with space" ];
              });
            assert accepted "a mask one level below a writable bind"
              (rootless {
                containers.box.bindMounts."/srv/shared" = { hostPath = "/srv/shared"; isReadOnly = false; };
                flong.box.masks = [ "/srv/shared/masked" ];
              });
            # The depth rule is for masks below writable binds only: a tmpfs or
            # an overlay deep below one, and a mask deep below a read-only
            # one, are allowed.
            assert accepted "a tmpfs and an overlay deep below a writable bind"
              (rootless {
                containers.box.bindMounts."/srv/shared" = { hostPath = "/srv/shared"; isReadOnly = false; };
                containers.box.tmpfs = [ "/srv/shared/a/cache" ];
                flong.box.overlays."/srv/shared/b/state" = "/var/empty";
              });
            assert accepted "a mask deep below a read-only bind"
              (rootless {
                containers.box.bindMounts."/srv/ref" = { hostPath = "/srv/ref"; isReadOnly = true; };
                flong.box.masks = [ "/srv/ref/a/token" ];
              });
            assert accepted "a forwarded port at 1024"
              (rootless { flong.box.network.forwardPorts = [ { hostPort = 1024; } ]; });
            assert accepted "a bind of a directory in the runtime directory"
              (rootless { containers.box.bindMounts."/run/cc-socks".hostPath = "/run/user/1000/cc-socks"; });
            assert accepted "a tmpfs with a mode and a size"
              (rootless { containers.box.tmpfs = [ "/scratch:mode=1777,size=10M" "/rootish:uid=0,gid=0" "/mine:uid=1000,gid=100" ]; });
            assert accepted "a device with rwm"
              (rootless { containers.box.allowedDevices = [ { node = "/dev/null"; modifier = "rwm"; } ]; });
            assert accepted "a directory device without a bind"
              (rootless { containers.box.allowedDevices = [ { node = "/dev/snd"; modifier = "rw"; } ]; });
            assert accepted "the container's root as the user"
              (rootless { flong.box.user = lib.mkForce "root"; });
            # The holder unit exists once a declaration runs rootless, and is
            # delegated, in app.slice, with the sweeper as its process.
            assert (let
                units = (configWith (rootless { })).systemd.user.units;
                text = units."flong-sessions.service".text or "";
              in
              lib.all (l: lib.hasInfix l text) [
                "Type=exec" "Slice=app.slice" "Delegate=yes" "DelegateSubgroup=supervisor"
                "OOMPolicy=continue" "/bin/flong-sweeper %t/flong"
              ]) || throw "assertions: the holder unit is missing or wrong";
            assert ! (configWith { }).systemd.user.units ? "flong-sessions.service"
              || throw "assertions: the holder unit exists with no rootless declaration";
            # nspawn expresses any path once it is escaped, and flong passes
            # the declaration's binds as data, so none is refused.
            assert flongFailures
              {
                containers.box.bindMounts."/in side:colon\\slash".hostPath = "/out side:colon\\slash";
                containers.box.tmpfs = [ "/tmp/with space" ];
              } == [ ]
              || throw "assertions: a bind or tmpfs path holding whitespace, ':' or '\\' is refused";
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

      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixpkgs-fmt);
    };
}
