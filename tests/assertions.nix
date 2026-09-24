# The refusals of module.nix, checked by evaluating: each declaration below
# must trip the assertion it is about, and the baseline must trip none of
# flong's. Evaluation only; no system is built.
#
# These are the refusals only NixOS can make, of containers.<name>, the
# host and the options' types. What the declaration file says is flong
# check's to judge (src/check.zig), in the file's own build, and its cases
# are tests/golden/decl/'s; assertions-decl below holds that the file's
# build is where a refusal surfaces.
#
# Each case is a full NixOS evaluation of about two seconds, about a
# minute and a half for all of them in one evaluator, so they are dealt
# round-robin into `shards` checks, assertions-0 to assertions-<shards - 1>
# (flake.nix's checks), eight cases or fewer each. A shard is a derivation
# whose evaluation forces its cases, so parallel evaluators
# (nix-fast-build's workers, CI's matrix legs) split the work, and a case
# that fails fails its shard alone, with the case's own message. A case is
# an expression that is true or throws a message that names it.
{
  nixpkgs,
  pkgs,
  system,
  shards ? 6,
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
      (warned "no tier"
        { flong.box.seccomp.tier = null; }
        "only the audit, tty and namespace masks")
      (warned "log = true"
        { flong.box.seccomp.log = true; }
        "for learning a policy, not for untrusted payloads")
      # A name is a syscall or a group, in the form systemd lists them.
      (untyped { flong.box.seccomp.allow = [ "Ptrace" ]; } [ "flong" "box" "seccomp" "allow" ]
        || throw "assertions: an upper-case seccomp name was accepted")
      (untyped { flong.box.seccomp.deny = [ "@ keyring" ]; } [ "flong" "box" "seccomp" "deny" ]
        || throw "assertions: a seccomp name with a blank was accepted")
      (untyped { flong.box.seccomp.errno = "EINVAL"; } [ "flong" "box" "seccomp" "errno" ]
        || throw "assertions: an errno outside EPERM, EACCES and ENOSYS was accepted")
      (lib.any (lib.hasInfix "consistency check and not a gate")
        (flongWarnings { flong.box.guard = [ [ "true" ] ]; })
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
      (refused "autoStart"
        { containers.box.autoStart = true; }
        "has autoStart enabled")
      (refused "a host without user namespaces"
        { security.allowUserNamespaces = false; }
        "security.allowUserNamespaces is false")
      (refused "a host without newuidmap"
        { security.wrappers.newuidmap.enable = lib.mkForce false; }
        "does not install")
      (accepted "a forwarded port at 1024"
        { flong.box.network.forwardPorts = [ { hostPort = 1024; } ]; })
      (accepted "a tmpfs with a mode and a size"
        { containers.box.tmpfs = [ "/scratch:mode=1777,size=10M" "/rootish:uid=0,gid=0" "/mine:uid=1000,gid=100" ]; })
      # Declared ids for root, whose uid and gid the container module
      # gives.
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
      # Every hook is a list of commands, and `workspace` one command or
      # null: a shell string, the type they had, does not evaluate, and
      # neither does an empty command.
      (untyped { flong.box.guard = "true"; } [ "flong" "box" "guard" ]
        || throw "assertions: a guard as a shell string was accepted")
      (untyped { flong.box.guard = [ [ ] ]; } [ "flong" "box" "guard" ]
        || throw "assertions: an empty guard command was accepted")
      (untyped { flong.box.binds = [ "printf" "/srv" ]; } [ "flong" "box" "binds" ]
        || throw "assertions: binds as one command rather than a list of them was accepted")
      (untyped { flong.box.postStart = "true"; } [ "flong" "box" "postStart" ]
        || throw "assertions: a postStart as a shell string was accepted")
      (untyped { flong.box.postStop = [ "true" ]; } [ "flong" "box" "postStop" ]
        || throw "assertions: a postStop of bare strings was accepted")
      (untyped { flong.box.seccompPolicy = "echo allow ptrace"; } [ "flong" "box" "seccompPolicy" ]
        || throw "assertions: a seccompPolicy as a shell string was accepted")
      (untyped { flong.box.workspace = "pwd"; } [ "flong" "box" "workspace" ]
        || throw "assertions: a workspace as a shell string was accepted")
      (untyped { flong.box.workspace = [ ]; } [ "flong" "box" "workspace" ]
        || throw "assertions: an empty workspace command was accepted")
      # The hooks merge in order, mkBefore and mkAfter included, as a
      # consumer layering onto another's declaration relies on.
      ((configWith {
          flong.box.guard = lib.mkMerge [
            (lib.mkAfter [ [ "c" ] ])
            [ [ "b" "x" ] ]
            (lib.mkBefore [ [ "a" ] ])
          ];
        }).flong.box.guard == [ [ "a" ] [ "b" "x" ] [ "c" ] ]
        || throw "assertions: guard's commands did not merge in mkOrder order")
      # The generated options keep the types they had where the
      # declaration did not change them.
      (untyped { flong.box.limits.CPUWeight = 0; } [ "flong" "box" "limits" "CPUWeight" ]
        || throw "assertions: a CPUWeight of 0 was accepted")
      (untyped { flong.box.limits.MemoryMax = "8X"; } [ "flong" "box" "limits" "MemoryMax" ]
        || throw "assertions: a MemoryMax of 8X was accepted")
      (untyped { flong.box.limits.TasksMax = 0; } [ "flong" "box" "limits" "TasksMax" ]
        || throw "assertions: a TasksMax of 0 was accepted")
      (untyped { flong.box.network.forwardPorts = "all"; } [ "flong" "box" "network" "forwardPorts" ]
        || throw "assertions: forwardPorts = \"all\" was accepted")
      (accepted "every limit spelling"
        { flong.box.limits = { MemoryMax = "infinity"; MemoryHigh = 1073741824; MemorySwapMax = "2G"; TasksMax = "infinity"; CPUQuota = "150%"; CPUWeight = 10000; }; })
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

  # A declaration flong check refuses evaluates, and its file,
  # /etc/flong/box.zon (module.nix's declFileOf), fails to build with flong
  # check's words. The file is in the system's closure, through
  # environment.etc, so the same declaration fails nixos-rebuild's build
  # with them. The baseline's file builds: the control.
  declFile = extra: (configWith extra).environment.etc."flong/box.zon".source;
  refusedDecl = {
    containers.box.bindMounts."/state".hostPath = "/run/user/1000/flong";
    containers.box.allowedDevices = [ { node = "/dev/null"; modifier = "r"; } ];
    flong.box.masks = [ "/state" ];
    flong.box.seccomp = { tier = null; log = true; };
  };
  decl =
    assert flongFailures refusedDecl == [ ]
      || throw "assertions-decl: module.nix refused what flong check is to: ${builtins.toJSON (flongFailures refusedDecl)}";
    pkgs.runCommand "assertions-decl"
      {
        refused = pkgs.testers.testBuildFailure (declFile refusedDecl);
        baseline = declFile { };
      }
      ''
        log=$refused/testBuildFailure.log
        cat "$log"
        grep -q '^flong check: .*: flong.box drives containers.box, and would bind /run/user/1000/flong into a session\.' "$log"
        grep -q '^flong check: .*: flong.box drives containers.box, whose allowedDevices has /dev/null r\.' "$log"
        grep -q '^flong check: .*: flong.box drives containers.box, and mounts something at /state twice:' "$log"
        grep -q '^flong check: .*: flong.box sets seccomp.tier = null and seccomp.log,' "$log"
        [ "$(cat $refused/testBuildFailure.exit)" = 1 ]
        grep -q '^\.{' $baseline
        touch $out
      '';
in
lib.listToAttrs (map (n: lib.nameValuePair "assertions-${toString n}" (shard n)) (lib.range 0 (shards - 1)))
// { assertions-decl = decl; }
