{ config, lib, pkgs, ... }:

let
  cfg = config.flong;

  # THE PAYLOAD IS AN ARGUMENT LIST. `command` is data -- a program and its
  # arguments -- with the launcher's own arguments appended, and no word of
  # either is ever read as shell: a space, a `;` or a `$(...)` is that
  # character, in that argument, whichever list it came from.
  #
  # Exec'd THROUGH THE CONTAINER'S /etc/set-environment, which is what gives
  # the payload the container's PATH -- its per-user profile, its system
  # profile -- and every variable its declaration exports. So a bare name is
  # found where the container would find it, and an absolute path, such as
  # `lib.getExe` of a package, runs as it is.
  #
  # EXEC, so the payload becomes this process rather than a child of it, and
  # tini can signal it directly. set-environment is sourced inside a `bash -c`
  # because it expands unset variables, which would abort under the `set -u`
  # this script runs with. The command and the arguments reach that bash as
  # its positional parameters, never as its script.
  mkPayload = name: c: pkgs.writeShellApplication {
    name = "flong-payload-${name}";
    runtimeInputs = [ pkgs.coreutils ];
    text = ''
      workspace=$1
      shift
      cd "$workspace" || exit 1

      # `command` is quoted to survive THIS shell as data, so what shellcheck
      # would say about a '$' or a trailing backslash inside single quotes is
      # true and intended.
      # shellcheck disable=SC2016,SC1003
      exec bash -c '. /etc/set-environment
                    exec "$@"' \
           flong ${lib.escapeShellArgs c.command} "$@"
    '';
  };

  # postStart and postStop are ordered lists of commands, which the launch
  # runs in order, the first that fails ending the list (src/launch/hook.zig,
  # src/record.zig's poststop). Each command is run through the
  # declaration's hook program, the declaration's postStartProgram and
  # postStopProgram (src/decl.zig), which gives it the hook's environment
  # and then execs it, so it is the command's own process:
  #
  #   flong-<kind>-<name> WORD... [ARG...]
  #
  # `path` is on PATH for both, as it is for every hook, and a bare program
  # name is looked up there. postStart's arguments are the launcher's, after
  # the command's words. postStop's are the session's name alone, which the
  # launcher and the sweeper both append and pass as $machine: the program
  # drops it, so a postStop command gets no arguments of its own, since on
  # the sweeper's path the name is all that survives, and the environment
  # there is $machine and nothing else. The program is in the store, as a
  # postStop program must be.
  mkHookProgram = name: kind: c: pkgs.writeShellApplication {
    name = "flong-${kind}-${name}";
    runtimeInputs = [ pkgs.coreutils pkgs.util-linux ] ++ c.path;
    text = ''
      ${lib.optionalString (kind == "poststop") ''
        export machine=''${!#}
        set -- "''${@:1:$#-1}"
      ''}
      exec "$@"
    '';
  };

  # A declared tmpfs entry is written for the container module, which hands
  # it to nspawn as a --tmpfs argument: PATH[:OPTIONS], where the path may
  # escape a ':' or a '\' with a backslash. The path is needed on its own,
  # as the mount's destination, so it is read out here the way nspawn reads
  # it.
  tmpfsEntriesOf = declared: map
    (entry:
      let
        r = lib.foldl'
          (acc: ch:
            if acc.done then acc // { rest = acc.rest + ch; }
            else if acc.escaped then acc // { path = acc.path + ch; escaped = false; }
            else if ch == "\\" then acc // { escaped = true; }
            else if ch == ":" then acc // { done = true; }
            else acc // { path = acc.path + ch; })
          { path = ""; rest = ""; escaped = false; done = false; }
          (lib.stringToCharacters entry);
      in
      {
        inherit (r) path;
        # Empty when the entry names no options, and flong supplies them.
        options = r.rest;
      })
    declared.tmpfs;

  # The native launcher: flong, whose subcommands are launch, sweeper and
  # init, Zig, static and without libc (native.nix's launcher set). Built
  # from this nixpkgs, so its bubblewrap is the host's.
  flongLauncher = import ./launcher { inherit pkgs; };

  # A path as flong spells it to compare it (src/check.zig's norm, which
  # flong check and the launch's prologue use): /var/run is /run, and
  # repeated and trailing slashes go. Lexical only; the launcher
  # canonicalises at launch, and its check is the authority.
  norm = p:
    let q = "/" + lib.concatStringsSep "/" (lib.filter (x: x != "") (lib.splitString "/" p)); in
    if q == "/var/run" || lib.hasPrefix "/var/run/" q then "/run" + lib.removePrefix "/var/run" q else q;

  # Everything flong reads from a declaration, computed once and used by
  # the launcher and the checks alike, so they cannot read it differently.
  declarationOf = name: c:
    let
      declared = config.containers.${c.container};

      # A container declared by `path` has no configuration to read, and
      # reading it throws; that is refused below rather than propagated.
      cfgEval = builtins.tryEval declared.config;
      uEntry = if cfgEval.success then cfgEval.value.users.users.${c.user} or null else null;
      cuid = if uEntry == null then null else uEntry.uid;
      cgid = if uEntry == null then null
        else cfgEval.value.users.groups.${uEntry.group}.gid or null;

      src = m: if m.hostPath == null then m.mountPoint else m.hostPath;
      binds = lib.mapAttrsToList
        (_: m: { dest = m.mountPoint; src = norm (src m); rw = ! m.isReadOnly; })
        declared.bindMounts;

      # A declared tmpfs entry as the launcher's `mount tmpfs` takes it: a
      # mode, a size and an owner, which is the session's user or root. An
      # entry without options is the user's, 0755, so the payload can write
      # to it. Anything the launcher has no field for is `bad`, and refused.
      renderTmpfs = e:
        let
          opts = lib.filter (o: o != "") (lib.splitString "," e.options);
          value = key: let m = lib.filter (lib.hasPrefix "${key}=") opts; in
            if m == [ ] then null else lib.removePrefix "${key}=" (lib.last m);
          known = o: builtins.match "mode=[0-7]{3,4}|size=[0-9]+[kKmMgG%]?|uid=[0-9]+|gid=[0-9]+" o != null;
          uid = value "uid";
          gid = value "gid";
          owner =
            if uid == null && gid == null then (if opts == [ ] then "user" else "root")
            else if uid == null || gid == null then null
            else if cuid != null && cgid != null
              && lib.toIntBase10 uid == cuid && lib.toIntBase10 gid == cgid then "user"
            else if lib.toIntBase10 uid == 0 && lib.toIntBase10 gid == 0 then "root"
            else null;
        in
        {
          inherit (e) path;
          mode = if value "mode" == null then "0755" else value "mode";
          size = if value "size" == null then "" else value "size";
          owner = if owner == null then "root" else owner;
          bad = ! lib.all known opts || owner == null;
        };
      tmpfs = map renderTmpfs (tmpfsEntriesOf declared);

      devices = declared.allowedDevices;
      overlayDests = lib.attrNames c.overlays;

      # Every destination the declaration mounts something at, for the
      # launcher's header. The launcher refuses one twice, and flong check
      # refuses it first.
      dests = map (b: b.dest) binds ++ c.masks ++ map (t: t.path) tmpfs
        ++ overlayDests ++ map (d: d.node) devices;
    in
    {
      inherit declared cfgEval uEntry cuid cgid binds tmpfs devices overlayDests dests;
    };

  # THE DEPTH RULE, for masks. A mask hides one name, and a name two or more
  # levels below the root of a writable bind can be moved from under it: a
  # session that can write the host directory renames the masked file's
  # parent and puts a decoy in its place, and the mask then covers the decoy
  # while the real file is readable at the new name. It needs no symlink, and
  # no write through THIS session -- any session binding the same host
  # directory writable will do. One level down, the parent is the bind root
  # itself, which a session cannot rename.
  #
  # Masks only, and only below writable binds. A tmpfs or an overlay at any
  # depth is allowed, and unguarded: moving its parent only moves where the
  # session's writes land, which is the session's own business. A mask
  # below a read-only bind is allowed too, and unguarded in the same way:
  # the caller on the host, or another declaration binding the directory
  # writable, can still rename its parent, and this declaration cannot see
  # either.
  #
  # So for each mask whose nearest enclosing declared mount is a bind, its
  # host path is worked out, and it is refused if some writable bind of the
  # declaration has that host path two or more levels below its source.
  # Each refusal names those binds' sources, since a mask one level below a
  # read-only bind can still be deep in a writable one. flong check makes
  # that refusal, in each declaration's derivation (src/check.zig's depth).
  #
  # The launch repeats the rule against the caller's own writable binds,
  # which only exist then, with each mask's host path (src/check.zig's
  # maskHosts, src/launch/depth.zig).

  # The prepared root's two programs: flong-prepare-inner, which builds the
  # root as container root in the caller's own user namespace, and
  # flong-cache, the caller's side of it (cache.nix, where their comments
  # are). flong launch runs the cache tool by the path compiled into it
  # (native.nix's -Dcache), which is this one.
  inherit (import ./cache.nix { inherit pkgs; }) cacheTool;

  # The first eight hex digits of the cache tool's store path, which
  # references the prepare program: a change to either is a different root,
  # so it names a different cache.
  steps8 = builtins.substring 0 8
    (builtins.hashString "sha256" (builtins.unsafeDiscardStringContext "${cacheTool}"));

  # The host facts the launcher depends on, each read from where NixOS sets
  # it.
  sysctl = k: config.boot.kernel.sysctl.${k} or null;
  wrapperOn = w: config.security.enableWrappers
    && config.security.wrappers ? ${w} && config.security.wrappers.${w}.enable;

  # The seccomp pipeline: the compiler, the tiers expanded from this system's
  # own `systemd-analyze syscall-filter`, and the fixed filters; the same
  # compiler compiles a project's policy at launch (`flong-seccomp project`).
  # A filter's store path is named by its content, so declarations with
  # equal policies share it.
  seccompCompiler = import ./seccomp { inherit pkgs; };
  seccomp = import ./seccomp/policy.nix {
    inherit pkgs lib;
    systemd = config.systemd.package;
    compiler = seccompCompiler;
  };

  # A declaration's compiled seccomp filters, as store paths: the tier's (null
  # with no tier), the fixed ones in the order they are installed, and what
  # `flong-seccomp project` compiles a project's policy against (null with no
  # seccompPolicy, or no tier for it to act on, which an assertion refuses).
  # The wrapper's header and the rendered declaration both take them from
  # here.
  seccompFiltersOf = c:
    let s = c.seccomp; in
    {
      tier = if s.tier == null then null else "${seccomp.filterFor s}";
      fixed = map toString ([ seccomp.fixed.audit seccomp.fixed.tty ]
        ++ lib.optional (! s.nestedSandbox) seccomp.fixed.nsmask);
      project = if c.seccompPolicy == [ ] || s.tier == null then null else {
        dump = "${seccomp.dump}";
        names = "${seccomp.namesFor s}";
        deny = seccomp.deny s;
      };
    };

  # THE DECLARATION AS DATA: `flong.<name>` as the value src/decl.zig's
  # Declaration types, field for field under the option's own name, and the
  # computed fields beside them (Declaration.computed). Rendered to ZON by
  # nix/to-zon.nix and installed as /etc/flong/<name>.zon.
  toZon = import ./nix/to-zon.nix { inherit lib; };

  declValueOf = name: c:
    let
      d = declarationOf name c;
      inherit (d) declared;
      l = c.limits;
      f = seccompFiltersOf c;
      # decl.MemSize and decl.Tasks: `infinity` a tag, a number or a size
      # the union's other fields.
      memSize = v:
        if v == null then null
        else if v == "infinity" then toZon.tag "infinity"
        else if builtins.isInt v then { bytes = v; }
        else { size = v; };
      tasks = v:
        if v == null then null
        else if v == "infinity" then toZon.tag "infinity"
        else { count = v; };
    in
    {
      inherit (c) user command workspace binds guard postStart postStop masks protect seccompPolicy;
      network = if c.network == null then null else {
        forwardPorts =
          if c.network.forwardPorts == "auto" then toZon.tag "auto"
          else {
            ports = map (p: { inherit (p) protocol hostPort containerPort; }) c.network.forwardPorts;
          };
        inherit (c.network) hostLoopbackToSession hostPorts;
      };
      overlays = lib.mapAttrsToList (target: lower: { inherit target; lower = toString lower; }) c.overlays;
      limits = {
        MemoryMax = memSize l.MemoryMax;
        MemoryHigh = memSize l.MemoryHigh;
        MemorySwapMax = memSize l.MemorySwapMax;
        TasksMax = tasks l.TasksMax;
        inherit (l) CPUQuota CPUWeight oomGroup;
      };
      seccomp = { inherit (c.seccomp) tier debug nestedSandbox allow deny errno log; };

      # Computed.
      inherit (c) container;
      closure = "${declared.path}";
      inherit (d) cuid cgid;
      inherit steps8 name;
      containerMounts =
        lib.mapAttrsToList
          (_: m: {
            kind = if m.isReadOnly then "bind_ro" else "bind_rw";
            dest = m.mountPoint;
            src = if m.hostPath == null then m.mountPoint else m.hostPath;
          })
          declared.bindMounts
        ++ map
          (t: {
            kind = "tmpfs";
            dest = t.path;
            inherit (t) mode;
            size = if t.size == "" then null else t.size;
            ownerUser = t.owner == "user";
          })
          d.tmpfs
        ++ map (x: { kind = "dev"; dest = x.node; src = x.node; mode = x.modifier; }) d.devices;
      payload = lib.getExe (mkPayload name c);
      seccompTierFilter = f.tier;
      seccompFixedFilters = f.fixed;
      seccompProject = f.project;
      # `path` for the caller's commands, before the caller's own PATH, as
      # writeShellApplication's runtimeInputs put it; and the hook programs
      # each postStart and postStop command runs through.
      commandPath = lib.optionals (c.path != [ ]) (lib.splitString ":" (lib.makeBinPath c.path));
      postStartProgram = if c.postStart == [ ] then null
        else "${mkHookProgram name "poststart" c}/bin/flong-poststart-${name}";
      postStopProgram = if c.postStop == [ ] then null
        else "${mkHookProgram name "poststop" c}/bin/flong-poststop-${name}";
    };

  # The rendered file, /etc/flong/<name>.zon.
  declFileOf = name: c: pkgs.writeTextFile {
    name = "flong-${name}.zon";
    text = toZon.toZON toZon.enumPaths (declValueOf name c);
    # flong check judges the file as the launch will read it, so a
    # declaration flong refuses fails the build, with its line and column
    # or the refusal's own words (src/check.zig).
    checkPhase = ''
      ${flongLauncher}/bin/flong check "$target"
    '';
  };

  # THE LAUNCHER: a link NAME -> flong, and nothing else (STANDALONE.md, "The
  # declaration's command"). flong reads its argv[0]'s basename, finds no
  # subcommand by that name, and launches /etc/flong/NAME.zon, which
  # environment.etc installs from declFileOf: exactly what `flong launch
  # NAME -- ARGS` does.
  mkLauncher = name: pkgs.runCommand "flong-${name}" { meta.mainProgram = name; } ''
    mkdir -p $out/bin
    ln -s ${flongLauncher}/bin/flong $out/bin/${lib.escapeShellArg name}
  '';

  # Everything the container module or flong's options can say that a
  # session cannot honour, refused rather than dropped: most of these
  # declare LESS privilege than the default, and a container that is
  # silently not the one declared is worse than one that refuses to build.
  # Each message names the declaration.
  #
  # These are what only NixOS can say: facts of containers.<name>, of the
  # host and of options flong does not render. Whatever the declaration
  # file itself says -- clean paths, a destination twice, the depth rule,
  # sources and devices, the tier's settings, the container's ids -- flong
  # check judges, in declFileOf's build (src/check.zig), so there is one
  # validator of a declaration, and a refusal of it fails the system's
  # build with flong check's message rather than its evaluation.
  assertionsFor = n: c:
    let
      d = declarationOf n c;
      inherit (d) declared;
      portStart = let v = sysctl "net.ipv4.ip_unprivileged_port_start"; in
        if v == null then 1024 else lib.toInt (toString v);
      fixedPorts = if c.network != null && lib.isList c.network.forwardPorts then c.network.forwardPorts else [ ];
      lowPorts = map (p: p.hostPort) (lib.filter (p: p.hostPort < portStart) fixedPorts);

      # Each is fixed per declaration, and a declaration here is many
      # concurrent sessions: two of them would claim one address or one
      # host port. `network` is the per-session answer.
      needsInside = [
        (declared.hostBridge != null)
        (declared.forwardPorts != [ ])
        (declared.interfaces != [ ])
        (declared.macvlans != [ ])
        (declared.extraVeths != { })
        (declared.hostAddress != null)
        (declared.hostAddress6 != null)
        (declared.localAddress != null)
        (declared.localAddress6 != null)
        (declared.localMacAddress != null)
      ];

      badTmpfs = map (t: t.path) (lib.filter (t: t.bad) d.tmpfs);
    in
    [
      {
        assertion = declared.flake == null;
        message = ''
          flong.${n} drives containers.${c.container}, which is declared by
          `flake`. Such a container reports a per-container profile as its
          path, and only the container@ unit's start script ever creates
          one -- so there would be nothing to prepare a root from, and
          nothing is evaluated at launch to fix that. Declare it with
          `config`.
        '';
      }
      {
        assertion = builtins.match "[A-Za-z0-9_-][A-Za-z0-9_.-]{0,99}" c.container != null;
        message = ''
          flong.${n} drives containers.${c.container}, and the launcher names
          a session's cgroup and record after the container: the name must be
          letters, digits, `_`, `-` and `.`, not start with `.`, and be at
          most 100 characters, leaving room for the session's own suffix.
        '';
      }
      {
        assertion = declared.privateUsers == "no";
        message = ''
          flong.${n} drives containers.${c.container}, which asks for a uid
          namespace. A session always has flong's own, which maps the
          container's user onto the caller so the workspace stays theirs, and
          the rest onto the caller's subordinate range. There is no other to
          choose, so the option would declare nothing.
        '';
      }
      {
        assertion = declared.additionalCapabilities == [ ] && ! declared.enableTun;
        message = ''
          flong.${n} drives containers.${c.container}, which grants
          capabilities. Nothing in a session holds any: the payload's user
          namespace has an empty bounding set, so there is no process for a
          capability to belong to, and no CAP_NET_ADMIN to make enableTun's
          /dev/net/tun useful.
        '';
      }
      {
        assertion = declared.extraFlags == [ ];
        message = ''
          flong.${n} drives containers.${c.container}, whose extraFlags
          are nspawn flags. flong runs no nspawn to pass them to, and refuses
          them rather than drop them.
        '';
      }
      {
        assertion = ! lib.any (x: x) needsInside;
        message = ''
          flong.${n} drives containers.${c.container}, which declares a veth,
          a bridge, a macvlan, a moved interface, an address or a forwarded
          port. flong refuses them rather than dropping them: each is static
          per container, and flong runs many concurrent sessions from one
          declaration, which would claim the same address, interface or host
          port.

          What a session can have is `privateNetwork` alone (loopback and
          nothing else), or `privateNetwork` with flong.${n}.network (a real
          network through pasta, with its own forwardPorts and hostPorts).
        '';
      }
      {
        assertion = declared.privateNetwork;
        message = ''
          flong.${n} drives containers.${c.container}, which does not
          set privateNetwork = true. A session always has a network namespace
          of its own, so it cannot share the host's. Set privateNetwork =
          true, and give it flong.${n}.network = { } for a network --
          forwardPorts = "auto" and hostLoopbackToSession = true for a dev
          server reached from the host.
        '';
      }
      {
        assertion = declared.networkNamespace == null;
        message = ''
          flong.${n} drives containers.${c.container}, which names a
          networkNamespace. A namespace something else built is owned by the
          initial user namespace, and a caller cannot join it from a user
          namespace of their own. Use flong.${n}.network for a network.
        '';
      }
      {
        assertion = c.scopeConfig == { };
        message = ''
          flong.${n} sets scopeConfig, which flong no longer reads: a session
          has no scope unit. Set its limits in flong.${n}.limits.
          AllowedCPUs, the Device* and IPAddress* properties, SocketBind* and
          RestrictNetworkInterfaces have no equivalent at all.
        '';
      }
      {
        assertion = badTmpfs == [ ];
        message = ''
          flong.${n} drives containers.${c.container}, whose tmpfs
          ${lib.concatStringsSep ", " badTmpfs} names options it cannot honour.
          An entry may give mode=, size=, and uid= with gid= of either the
          session's user or root, and nothing else.
        '';
      }
      {
        assertion = lowPorts == [ ];
        message = ''
          flong.${n}.network forwards host port ${lib.concatMapStringsSep ", " toString lowPorts},
          below net.ipv4.ip_unprivileged_port_start (${toString portStart}).
          pasta binds it as the calling user, who may not. forwardPorts =
          "auto" never publishes a port below it either.
        '';
      }
      {
        assertion = d.uEntry != null;
        message =
          if ! d.cfgEval.success then ''
            flong.${n} drives containers.${c.container}, which is declared by
            path. flong needs its configuration, to read ${c.user}'s uid and
            gid at evaluation. Declare it with `config`.
          '' else ''
            flong.${n}: ${c.user} is not a user in containers.${c.container}.
          '';
      }
      {
        assertion = d.uEntry == null || (d.cuid != null && d.cgid != null);
        message = ''
          flong.${n} drives containers.${c.container} as ${c.user}, whose uid
          or primary group's gid is not declared. They decide the prepared
          root's cache and the caller's maps, before anything is prepared, so
          declare users.users.${c.user}.uid and the gid of its group in the
          container's configuration.
        '';
      }
      {
        assertion = ! declared.autoStart;
        message = ''
          flong.${n} drives containers.${c.container}, which has autoStart
          enabled: it would boot at every host boot as a systemd-nspawn
          machine run as root, which is what flong exists not to run. Set
          autoStart = false.
        '';
      }
    ];

  warningsFor = n: c:
    lib.optional (c.seccomp.tier == null) ''
      flong.${n} has seccomp.tier = null: no syscall allow-list, only the
      audit, tty and namespace masks.
    ''
    ++ lib.optional c.seccomp.log ''
      flong.${n} has seccomp.log = true, so it logs rather than refuses calls
      outside its tier: for learning a policy, not for untrusted payloads.
    ''
    ++ lib.optional (c.guard != [ ]) ''
      flong.${n} has a guard, which is a consistency check and not a gate:
      the caller can run flong launch directly, with any spec.
    '';

  # THE HOLDER: one user unit per caller, whose cgroup every session of
  # theirs lives under, delegated so the launcher can make a session's
  # cgroup, write its limits and kill it whole. Its one process is the
  # sweeper, which releases a SIGKILLed launcher's session within
  # milliseconds rather than at the next launch.
  #
  # Declared for every user's manager, and inert until one of them starts
  # it: nothing wants it, and the launcher starts it on demand
  # (holder-start) whenever its cgroup is absent.
  #
  # STOPPING IT STOPS EVERY SESSION. With the default KillMode=control-group,
  # anything that deactivates the unit kills its whole cgroup, sessions
  # included: `systemctl --user stop`, and the sweeper exiting, whether it
  # failed to start or crashed. So there is no Restart=, which is a stop
  # first, and a switch leaves it alone: switch-to-configuration re-executes
  # user managers rather than restarting their units, and the two flags below
  # say the same. After an upgrade the old sweeper goes on sweeping the new
  # launchers' records until the unit next starts, so the record format is a
  # contract between versions.
  #
  # No RuntimeDirectory=: stopping the unit would delete the records that
  # postStop needs. The launcher makes %t/flong before it starts the unit, so
  # the sweeper never starts against a missing directory.
  holderUnit = {
    description = "flong: holder of sessions and their sweeper";
    restartIfChanged = false;
    stopIfChanged = false;
    serviceConfig = {
      # Start returns once the sweeper has moved itself into supervisor/;
      # before that, enabling a limit's controller in the holder fails with
      # EBUSY.
      Type = "exec";
      # The launcher's `holder` names app.slice/flong-sessions.service, so
      # the slice is stated rather than left to a default.
      Slice = "app.slice";
      # A string, so it renders as Delegate=yes: a bool renders as true.
      Delegate = "yes";
      DelegateSubgroup = "supervisor";
      # One session's OOM kill must not stop the unit, and every session
      # with it.
      OOMPolicy = "continue";
      ExecStart = "${flongLauncher}/bin/flong sweeper %t/flong";
    };
  };

  # The host facts the launcher depends on, asserted once however many
  # declarations there are. The kernel's own minimum, Linux 6.13, is
  # documented (README.md; DESIGN.md, "The kernel floor") and not
  # asserted: the launcher fails loudly on an older one.
  hostAssertions = [
    {
      assertion = config.security.allowUserNamespaces;
      message = ''
        flong runs sessions in user namespaces, and
        security.allowUserNamespaces is false.
      '';
    }
    {
      assertion = ! lib.elem (sysctl "user.max_user_namespaces") [ 0 "0" ]
        && ! lib.elem (sysctl "kernel.unprivileged_userns_clone") [ false 0 "0" ];
      message = ''
        flong runs sessions in unprivileged user namespaces, and
        boot.kernel.sysctl sets user.max_user_namespaces to 0 or
        kernel.unprivileged_userns_clone off.
      '';
    }
    {
      assertion = wrapperOn "newuidmap" && wrapperOn "newgidmap";
      message = ''
        flong's launcher maps ids through /run/wrappers/bin/newuidmap and
        newgidmap, which this system does not
        install. security.shadow.enable = false removes them, and so does
        security.account-utils, which disables newuidmap.
      '';
    }
    {
      assertion = lib.versionAtLeast pkgs.bubblewrap.version "0.12";
      message = ''
        flong's launcher needs bubblewrap 0.12 or later (--overlay-src,
        --tmp-overlay, --add-seccomp-fd); this nixpkgs has
        ${pkgs.bubblewrap.version}.
      '';
    }
    {
      assertion = lib.versionAtLeast config.systemd.package.version "254";
      message = ''
        flong's holder unit needs systemd 254 or later for DelegateSubgroup=;
        this system has ${config.systemd.package.version}.
      '';
    }
  ];

  # A declaration's options: decl-options.json, `flong schema`'s walk of
  # src/decl.zig, read as options by nix/decl-options.nix. The file is
  # checked in, so this is no import from a derivation, and the flake's
  # decl-options-fresh check fails when it is stale (`nix run
  # .#update-options` rewrites it). The examples are Nix, so they are here.
  declOptions = import ./nix/decl-options.nix
    {
      inherit lib;
      examples = {
        command = lib.literalExpression ''[ (lib.getExe pkgs.hello) "--greeting=hello from a session" ]'';
        workspace = lib.literalExpression ''[ "''${pkgs.writeShellScript "repo-root" "git -C \"$PWD\" rev-parse --show-toplevel"}" ]'';
        binds = lib.literalExpression ''[ [ "''${pkgs.writeShellScript "shared-crates" "printf '%s:rw\\n' \"$workspace/../shared-crates\""}" ] ]'';
        postStart = lib.literalExpression ''[ [ "''${pkgs.writeShellScript "fence" "nsenter --user=\"$userns\" --net=\"$netns\" nft -f /etc/my-ruleset.nft"}" ] ]'';
        postStop = lib.literalExpression ''[ [ "''${pkgs.writeShellScript "release" "rm -f \"$XDG_RUNTIME_DIR/my-gate/$machine.sock\""}" ] ]'';
        seccompPolicy = lib.literalExpression ''[ [ "''${pkgs.writeShellScript "policy" "chase-envelope approve \"$workspace\" \"$machine\""}" ] ]'';
        network = lib.literalExpression ''
          {
            hostPorts = [ 5432 ];
            forwardPorts = [ { hostPort = 8080; containerPort = 80; } ];
          }
        '';
        "network.hostPorts" = [ 5432 ];
        overlays = lib.literalExpression ''{ "/home/alice/.state" = "/var/lib/state"; }'';
        masks = [ "/home/alice/.cache/tool/token" ];
        protect = [ "/run/frisket" ];
        limits = { MemoryMax = "8G"; TasksMax = 4096; CPUQuota = "400%"; };
        seccomp = { tier = "strict"; debug = true; };
        "seccomp.allow" = [ "@keyring" "userfaultfd" ];
        "seccomp.deny" = [ "@swap" ];
      };
    }
    (builtins.fromJSON (builtins.readFile ./decl-options.json));
in
{
  options.flong = lib.mkOption {
    default = { };
    description = ''
      Ephemeral sessions that run one foreground process as the calling
      user, through flong launch and bubblewrap, in user namespaces the
      caller owns, with no root anywhere. Each starts from a root prepared
      once and cached, rather than booted per session.

      Each entry drives an existing `containers.<name>` declaration, using it
      only as a closure builder; the `container@` unit it installs is never
      started.
    '';
    type = lib.types.attrsOf (lib.types.submodule ({ name, config, ... }: {
      # Every option the declaration has, from decl-options.json, which
      # `flong schema` writes from src/decl.zig; then the four that are
      # Nix's alone, written here.
      options = declOptions // {
        container = lib.mkOption {
          type = lib.types.str;
          default = name;
          description = ''
            The `containers.<name>` declaration this runs: its closure,
            `bindMounts`, `tmpfs` and `allowedDevices`, read as option values.
            It must set `privateNetwork = true`.
          '';
        };

        scopeConfig = lib.mkOption {
          type = lib.types.attrsOf lib.types.anything;
          default = { };
          visible = false;
          description = "Refused: a session has no scope unit. See `limits`.";
        };

        path = lib.mkOption {
          type = lib.types.listOf lib.types.package;
          default = [ ];
          description = ''
            Packages on `PATH` for every hook, all of which run on the host
            as the caller: `workspace`, `binds`, `guard`, `seccompPolicy`,
            `postStart` and `postStop`. Not for `command`, which runs inside
            the session with the container's own `PATH`: a tool the workload
            needs belongs in the container's `environment.systemPackages`.
          '';
        };

        launcher = lib.mkOption {
          type = lib.types.package;
          readOnly = true;
          description = ''
            The declaration's command: `bin/<name>`, a link to flong, which
            runs /etc/flong/<name>.zon as `flong launch <name> -- ARGS`
            would. Run it directly as the user whose session it is, never as
            root. It needs their subordinate ids in /etc/subuid and
            /etc/subgid (`users.users.<name>.subUidRanges`, or
            `autoSubUidGidRange`).

            Its checks -- `workspace`, `binds`, `guard`, the depth rule -- are
            consistency checks, not a boundary: the caller can run
            flong launch directly with any declaration. flong launch's own
            checks and the session's `seccomp` filter are the boundary
            against the payload, and the prepared root and the records are
            the caller's, as their `~/.bashrc` is. It exits with the
            payload's status, 128+n when a signal killed the payload, 125
            when the payload never ran, and 1 when it refused before
            anything was launched.
          '';
        };
      };

      config = {
        launcher = mkLauncher name;
      };
    }));
  };

  # boot.enableContainers is left to NixOS: containers.<name> and its closure
  # exist without it, and flong starts no container@ unit.
  config = lib.mkIf (cfg != { }) {
    # The sessions' holder, in every user's manager.
    systemd.user.services.flong-sessions = holderUnit;

    # Each declaration as src/decl.zig reads one: /etc/flong/<name>.zon.
    environment.etc = lib.mapAttrs'
      (n: c: lib.nameValuePair "flong/${n}.zon" { source = declFileOf n c; })
      cfg;

    warnings = lib.concatLists (lib.mapAttrsToList warningsFor cfg);

    assertions = lib.concatLists (lib.mapAttrsToList
      (n: c:
        if config.containers ? ${c.container} then assertionsFor n c
        else [{
          assertion = false;
          message = ''
            flong.${n}.container names containers.${c.container}, which is not
            declared.
          '';
        }])
      cfg)
    ++ hostAssertions;
  };
}
