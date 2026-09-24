# The refusals of module.nix, checked by evaluating: each declaration below
# must trip the assertion it is about, and the baseline must trip none of
# flong's. Evaluation only; no system is built.
#
# Each case is a full NixOS evaluation of about two seconds, about two
# minutes for all of them in one evaluator, so they are dealt round-robin
# into `shards` checks, assertions-0 to assertions-<shards - 1> (flake.nix's
# checks). A shard is a derivation whose evaluation forces its cases, so
# parallel evaluators (nix-fast-build's workers, CI's matrix legs) split
# the work, and a case that fails fails its shard alone, with the case's
# own message. A case is an expression that is true or throws a message
# that names it.
{
  nixpkgs,
  pkgs,
  system,
  shards ? 8,
}:
let
  lib = nixpkgs.lib;
  configWith = extra:
    (lib.nixosSystem {
      inherit system;
      modules = [
        ../module.nix
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

  cases = [
      # The baseline, the strict tier with every fixed filter, trips
      # nothing and warns about nothing.
      (flongFailures { } == [ ]
        || throw "assertions: the baseline is refused: ${builtins.toJSON (flongFailures { })}")
      (flongWarnings { } == [ ]
        || throw "assertions: the baseline warns ${builtins.toJSON (flongWarnings { })}")
      (refused "the declaration's own forwardPorts"
        { containers.box.forwardPorts = [ { hostPort = 8080; } ]; }
        "static per container")
      (accepted "a network on a private container" { flong.box.network.hostPorts = [ 5432 ]; })
      # With no tier there is no allow-list filter for a policy to act
      # on. debug and errno have nothing to act on either, but are
      # harmless, so they are accepted.
      (refused "seccomp.allow with no tier"
        { flong.box.seccomp = { tier = null; allow = [ "ptrace" ]; }; }
        "no filter")
      (refused "seccomp.deny with no tier"
        { flong.box.seccomp = { tier = null; deny = [ "ptrace" ]; }; }
        "no filter")
      (refused "seccomp.log with no tier"
        { flong.box.seccomp = { tier = null; log = true; }; }
        "no filter")
      (refused "a seccompPolicy with no tier"
        {
          flong.box.seccomp.tier = null;
          flong.box.seccompPolicy = "echo allow ptrace";
        }
        "no filter")
      (accepted "debug and errno with no tier"
        { flong.box.seccomp = { tier = null; debug = true; errno = "EACCES"; }; })
      (warned "no tier"
        { flong.box.seccomp.tier = null; }
        "only the audit, tty and namespace masks")
      (warned "log = true"
        { flong.box.seccomp.log = true; }
        "for learning a policy, not for untrusted payloads")
      (accepted "every tier setting and loosening together"
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
        })
      # A name is a syscall or a group, in the form systemd lists them.
      (untyped { flong.box.seccomp.allow = [ "Ptrace" ]; } [ "flong" "box" "seccomp" "allow" ]
        || throw "assertions: an upper-case seccomp name was accepted")
      (untyped { flong.box.seccomp.deny = [ "@ keyring" ]; } [ "flong" "box" "seccomp" "deny" ]
        || throw "assertions: a seccomp name with a blank was accepted")
      (untyped { flong.box.seccomp.errno = "EINVAL"; } [ "flong" "box" "seccomp" "errno" ]
        || throw "assertions: an errno outside EPERM, EACCES and ENOSYS was accepted")
      (lib.any (lib.hasInfix "consistency check and not a gate")
        (flongWarnings { flong.box.guard = "true"; })
        || throw "assertions: a guard is not warned about")
      (refused "a container name beginning with a dot"
        {
          containers.".box" = { privateNetwork = true; config.system.stateVersion = "24.05"; };
          flong.box.container = ".box";
        }
        "not start with `.`")
      (refused "extraFlags"
        { containers.box.extraFlags = [ "--private-network" ]; }
        "whose extraFlags are nspawn flags")
      (refused "a networkNamespace"
        {
          containers.box.networkNamespace = "/run/netns/other";
          containers.box.privateNetwork = lib.mkForce false;
        }
        "names a networkNamespace")
      (refused "scopeConfig"
        { flong.box.scopeConfig.MemoryMax = "1G"; }
        "sets scopeConfig")
      (refused "a tmpfs option there is no field for"
        { containers.box.tmpfs = [ "/scratch:nosuid" ]; }
        "names options it cannot honour")
      (refused "a tmpfs owned by a third user"
        { containers.box.tmpfs = [ "/scratch:uid=5,gid=5" ]; }
        "names options it cannot honour")
      (refused "a tmpfs uid without its gid"
        { containers.box.tmpfs = [ "/scratch:uid=0" ]; }
        "names options it cannot honour")
      (refused "a forwarded port below 1024"
        { flong.box.network.forwardPorts = [ { hostPort = 80; } ]; }
        "below net.ipv4.ip_unprivileged_port_start")
      (refused "a bind of flong's state"
        { containers.box.bindMounts."/state".hostPath = "/run/user/1000/flong"; }
        "reaches flong's state")
      (refused "a bind of the user manager's socket, spelt through /var/run"
        { containers.box.bindMounts."/bus".hostPath = "/var/run/user/1000//bus"; }
        "reaches flong's state")
      (refused "a bind containing /proc"
        { containers.box.bindMounts."/host".hostPath = "/"; }
        "reaches flong's state")
      (refused "an overlay lower inside a protected path"
        {
          flong.box.protect = [ "/srv/gate" ];
          flong.box.overlays."/data" = "/srv/gate/data";
        }
        "reaches flong's state")
      (refused "a mask two levels below a writable bind"
        {
          containers.box.bindMounts."/srv/shared" = { hostPath = "/srv/shared"; isReadOnly = false; };
          flong.box.masks = [ "/srv/shared/a/token" ];
        }
        "two or more levels below")
      (refused "a mask whose host path is deep in another writable bind"
        {
          containers.box.bindMounts."/ro" = { hostPath = "/srv/shared/a"; isReadOnly = true; };
          containers.box.bindMounts."/rw" = { hostPath = "/srv/shared"; isReadOnly = false; };
          flong.box.masks = [ "/ro/token" ];
        }
        "/ro/token (in the writable bind of /srv/shared)")
      (refused "a device outside /dev"
        { containers.box.allowedDevices = [ { node = "/srv/null"; modifier = "rw"; } ]; }
        "allowedDevices has /srv/null rw")
      (refused "a read-only device"
        { containers.box.allowedDevices = [ { node = "/dev/null"; modifier = "r"; } ]; }
        "allowedDevices has /dev/null r")
      (refused "a bind of a device"
        { containers.box.bindMounts."/dev/snd".hostPath = "/dev/snd"; }
        "A plain bind is nodev")
      (refused "a shared host network"
        { containers.box.privateNetwork = lib.mkForce false; }
        "does not set privateNetwork = true")
      (refused "a user the container does not have"
        { flong.box.user = lib.mkForce "nobody-here"; }
        "nobody-here is not a user in containers.box")
      # A container declared by `path` alone is refused too, but is not
      # tested here: the container module's own assertions read every
      # container's `config`, so such a host does not evaluate at all.
      (refused "a user without a declared uid"
        {
          containers.box.config.users.users.v = { isNormalUser = true; group = "users"; };
          flong.box.user = lib.mkForce "v";
        }
        "is not declared")
      (refused "a user beyond the container's ids"
        {
          containers.box.config.users.users.w = { isNormalUser = true; uid = 70000; group = "users"; };
          flong.box.user = lib.mkForce "w";
        }
        "outside the container's ids")
      (refused "an unclean mask"
        { flong.box.masks = [ "/srv/../etc/shadow" ]; }
        "is not a clean absolute path")
      (refused "an unclean protect entry"
        { flong.box.protect = [ "/srv/gate/" ]; }
        "is not a clean absolute path")
      (refused "a mask on a bind's own destination"
        {
          containers.box.bindMounts."/srv/b".hostPath = "/srv/b";
          flong.box.masks = [ "/srv/b" ];
        }
        "twice")
      (refused "a device that is also bound"
        {
          containers.box.allowedDevices = [ { node = "/dev/snd"; modifier = "rw"; } ];
          containers.box.bindMounts."/dev/snd".hostPath = "/dev/snd";
        }
        "at /dev/snd twice")
      (refused "autoStart"
        { containers.box.autoStart = true; }
        "has autoStart enabled")
      (refused "a host without user namespaces"
        { security.allowUserNamespaces = false; }
        "security.allowUserNamespaces is false")
      (refused "a host without newuidmap"
        { security.wrappers.newuidmap.enable = lib.mkForce false; }
        "does not install")
      (accepted "odd bind and tmpfs paths"
        {
          containers.box.bindMounts."/in side:colon\\slash".hostPath = "/out side:colon\\slash";
          containers.box.tmpfs = [ "/tmp/with space" ];
        })
      (accepted "a mask one level below a writable bind"
        {
          containers.box.bindMounts."/srv/shared" = { hostPath = "/srv/shared"; isReadOnly = false; };
          flong.box.masks = [ "/srv/shared/masked" ];
        })
      # The depth rule is for masks below writable binds only: a tmpfs or
      # an overlay deep below one, and a mask deep below a read-only
      # one, are allowed.
      (accepted "a tmpfs and an overlay deep below a writable bind"
        {
          containers.box.bindMounts."/srv/shared" = { hostPath = "/srv/shared"; isReadOnly = false; };
          containers.box.tmpfs = [ "/srv/shared/a/cache" ];
          flong.box.overlays."/srv/shared/b/state" = "/var/empty";
        })
      (accepted "a mask deep below a read-only bind"
        {
          containers.box.bindMounts."/srv/ref" = { hostPath = "/srv/ref"; isReadOnly = true; };
          flong.box.masks = [ "/srv/ref/a/token" ];
        })
      (accepted "a forwarded port at 1024"
        { flong.box.network.forwardPorts = [ { hostPort = 1024; } ]; })
      (accepted "a bind of a directory in the runtime directory"
        { containers.box.bindMounts."/run/cc-socks".hostPath = "/run/user/1000/cc-socks"; })
      (accepted "a tmpfs with a mode and a size"
        { containers.box.tmpfs = [ "/scratch:mode=1777,size=10M" "/rootish:uid=0,gid=0" "/mine:uid=1000,gid=100" ]; })
      (accepted "a device with rwm"
        { containers.box.allowedDevices = [ { node = "/dev/null"; modifier = "rwm"; } ]; })
      (accepted "a directory device without a bind"
        { containers.box.allowedDevices = [ { node = "/dev/snd"; modifier = "rw"; } ]; })
      (accepted "the container's root as the user"
        { flong.box.user = lib.mkForce "root"; })
      # The holder unit exists once there is a declaration, and is
      # delegated, in app.slice, with the sweeper as its process.
      ((let
          units = (configWith { }).systemd.user.units;
          text = units."flong-sessions.service".text or "";
        in
        lib.all (l: lib.hasInfix l text) [
          "Type=exec" "Slice=app.slice" "Delegate=yes" "DelegateSubgroup=supervisor"
          "OOMPolicy=continue" "/bin/flong sweeper %t/flong"
        ]) || throw "assertions: the holder unit is missing or wrong")
      (! (configWith { flong = lib.mkForce { }; }).systemd.user.units ? "flong-sessions.service"
        || throw "assertions: the holder unit exists with no declaration")
      # `command` is an argument list: neither a shell string nor an
      # empty list evaluates.
      (! (builtins.tryEval (builtins.deepSeq
        (configWith { flong.box.command = lib.mkForce "set -- true"; }).flong.box.command
        true)).success
        || throw "assertions: a string command was accepted")
      (! (builtins.tryEval (builtins.deepSeq
        (configWith { flong.box.command = lib.mkForce [ ]; }).flong.box.command
        true)).success
        || throw "assertions: an empty command was accepted")
  ];

  # Case i is in shard i mod shards. Every case is forced before the
  # shard's derivation exists; the count in $out is the control that the
  # shard held cases at all.
  shard = n:
    let
      # By index, so another shard's cases stay unevaluated.
      mine = map (builtins.elemAt cases)
        (lib.filter (i: lib.mod i shards == n) (lib.range 0 (builtins.length cases - 1)));
    in
    assert builtins.length mine > 0 || throw "assertions-${toString n}: the shard has no cases";
    assert lib.all (c: c) mine || throw "assertions-${toString n}: a case is false without saying why";
    pkgs.runCommand "assertions-${toString n}" { } ''
      echo ${toString (builtins.length mine)} > $out
    '';
in
lib.listToAttrs (map (n: lib.nameValuePair "assertions-${toString n}" (shard n)) (lib.range 0 (shards - 1)))
