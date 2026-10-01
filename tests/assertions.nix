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
      # A guard is a consistency check as the launcher's other checks are,
      # and like them it is not warned about.
      (! lib.any (lib.hasInfix "guard")
        (flongWarnings { flong.box.guard = [ [ "true" ] ]; })
        || throw "assertions: a guard is warned about")
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
      # The payload is `command` or `exec`, one and only one: flong check's
      # rule, in the file's build (assertions-decl below). Here, `exec`
      # alone evaluates.
      (accepted "exec in place of command"
        { flong.box.command = lib.mkForce null; flong.box.exec = [ "/bin/exec" "--tier" ]; })
      (untyped { flong.box.exec = [ ]; } [ "flong" "box" "exec" ]
        || throw "assertions: an empty exec command was accepted")
      # The container's /etc/set-environment, computed without a shell:
      # what only a shell could say is refused, naming its line.
      (refused "a command substitution in a variable"
        { containers.box.config.environment.variables.WHO = "$(id -un)"; }
        "`export WHO=\"$(id -un)\"` holds `$(id -un)`, which only a shell could read")
      (refused "a default in a variable"
        { containers.box.config.environment.variables.STATE = "\${XDG_STATE_HOME:-$HOME/.local/state}"; }
        "which only a shell could read")
      (refused "a line of extraInit that is not an export"
        { containers.box.config.environment.extraInit = "alias ll='ls -l'"; }
        "`alias ll='ls -l'` is not an `export NAME=VALUE` flong can read without a shell")
      (refused "a variable bash sets for itself"
        { containers.box.config.environment.variables.HERE = "$PWD"; }
        "refers to $PWD, which bash sets for itself")
      (refused "a variable only the launch knows"
        { containers.box.config.environment.variables.T = "$TERM"; }
        "refers to $TERM, which only the launch knows")
      (accepted "what the launch expands, a PATH built on the file's own, and an unset name"
        {
          containers.box.config.environment = {
            variables.MINE = "$HOME/x:\${USER}";
            variables.UNSET = "a\${NOBODY_SETS_THIS}b";
            homeBinInPath = true;
            extraInit = "export ALSO=\"$MINE/y\"";
          };
        })
      # What the file becomes, the declaration's `environment` read as the
      # value the file was rendered from: the launch's references kept, an
      # earlier line's value put in, an unset name nothing, a name set again
      # its last value (MINE) while a line that read it before keeps the
      # value it read (ALSO), each name once, and the lines that set
      # nothing -- terminfo's `export TERM=$TERM`, nix-channel's block --
      # no entry, and nothing in NIX_PATH.
      ((let
          entries = (declFile {
            containers.box.config.environment = {
              variables.MINE = "$HOME/x:\${USER}";
              variables.UNSET = "a\${NOBODY_SETS_THIS}b";
              homeBinInPath = true;
              extraInit = ''
                export ALSO="$MINE/y"
                export MINE="z:$MINE"
              '';
            };
          }).declaration.environment;
          env = lib.listToAttrs (map (e: lib.nameValuePair e.name e.value) entries);
          got = lib.getAttrs [ "MINE" "ALSO" "UNSET" "PATH" ] env;
          want = {
            MINE = "z:\${HOME}/x:\${USER}";
            ALSO = "\${HOME}/x:\${USER}/y";
            UNSET = "ab";
            PATH = lib.concatStringsSep ":" [
              "\${HOME}/bin" "/run/wrappers/bin" "\${HOME}/.nix-profile/bin" "/nix/profile/bin"
              "\${HOME}/.local/state/nix/profile/bin" "/etc/profiles/per-user/\${USER}/bin"
              "/nix/var/nix/profiles/default/bin" "/run/current-system/sw/bin"
            ];
          };
        in
        (got == want
          || throw "assertions: the container's environment was computed as ${builtins.toJSON got}, not ${builtins.toJSON want}")
        && (builtins.length entries == builtins.length (lib.attrNames env)
          || throw "assertions: the container's environment sets a name twice: ${builtins.toJSON entries}")
        && (! env ? TERM && ! lib.hasInfix ".nix-defexpr" (env.NIX_PATH or "")
          || throw "assertions: a line that sets nothing made an entry: ${builtins.toJSON entries}")))
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
      # Where forwarded ports bind: what pasta could read as more than an
      # address or a name is refused at evaluation, and any address or
      # interface else is the declaration's to give, a loopback one or not.
      (untyped { flong.box.network.forwardAddress = "127.0.0.1/8"; } [ "flong" "box" "network" "forwardAddress" ]
        || throw "assertions: a forwardAddress with a / was accepted")
      (untyped { flong.box.network.forwardInterface = "eth0,1"; } [ "flong" "box" "network" "forwardInterface" ]
        || throw "assertions: a forwardInterface with a , was accepted")
      (accepted "a forwarded port's address and interface"
        { flong.box.network = { forwardPorts = "auto"; forwardAddress = "192.0.2.1"; forwardInterface = "eth0"; }; })
      (let n = (declFile { flong.box.network = { forwardPorts = "auto"; forwardAddress = "127.9.9.9"; }; }).declaration.network; in
        (n.forwardAddress == "127.9.9.9" && n.forwardInterface == null)
        || throw "assertions: the declaration file has forwardAddress ${builtins.toJSON n.forwardAddress} and forwardInterface ${builtins.toJSON n.forwardInterface}")
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
    # Rules module.nix leaves to flong check, whole: a payload that is both
    # `command` and `exec`, and a container variable the launch sets.
    flong.box.exec = [ "/bin/exec" ];
    containers.box.config.environment.variables.TMPDIR = "/var/tmp";
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
        grep -q '^flong check: .*: flong.box has both `command` and `exec`\.' "$log"
        grep -q '^flong check: .*: flong.box.environment sets TMPDIR, which the launch sets for every session\.' "$log"
        [ "$(cat $refused/testBuildFailure.exit)" = 1 ]
        grep -q '^\.{' $baseline
        touch $out
      '';
in
lib.listToAttrs (map (n: lib.nameValuePair "assertions-${toString n}" (shard n)) (lib.range 0 (shards - 1)))
// { assertions-decl = decl; }
