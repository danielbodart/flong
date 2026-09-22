# The rootless engine: a declaration's launcher as the calling user, through
# flong-launch and bubblewrap, with no root anywhere. Kept apart from
# module.nix while both engines exist; it is folded back in, or deleted, when
# the nspawn engine goes.
#
# `config` is the module's, not a declaration's. `shared` holds what both
# engines use unchanged: the payload, the tmpfs parser, pasta's port words,
# the postStop program and the launcher package.
{ config, lib, pkgs, shared }:

let
  # A path as the launcher compares it for the checks below: /var/run is
  # /run, and repeated and trailing slashes go. Lexical only; the launcher
  # canonicalises at launch, and its check is the authority.
  norm = p:
    let q = "/" + lib.concatStringsSep "/" (lib.filter (x: x != "") (lib.splitString "/" p)); in
    if q == "/var/run" || lib.hasPrefix "/var/run/" q then "/run" + lib.removePrefix "/var/run" q else q;

  # What the launcher's spec parser accepts as a path (clean() in
  # flong-spec.c): absolute, not /, and every component present, not . or
  # .., and at most 255 bytes. A path it would refuse at launch is refused
  # here, where the declaration can still be read.
  clean = p:
    let parts = lib.splitString "/" (lib.removePrefix "/" p); in
    lib.hasPrefix "/" p && p != "/"
    && lib.all (x: x != "" && x != "." && x != ".." && lib.stringLength x <= 255) parts;

  # Either path lies inside the other, or they are the same.
  overlaps = a: b: a == b || lib.hasPrefix "${a}/" b || lib.hasPrefix "${b}/" a;

  # How many components REL has.
  depth = rel: lib.length (lib.filter (x: x != "") (lib.splitString "/" rel));

  # Everything the engine reads from a declaration, computed once and used by
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
      # mode, a size and an owner, which is the session's user or root.
      # nspawn's own default for an entry without options is the user's
      # 0755, and it stays that. Anything the launcher has no field for is
      # `bad`, and refused.
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
      tmpfs = map renderTmpfs (shared.tmpfsEntriesOf declared);

      devices = declared.allowedDevices;
      overlayDests = lib.attrNames c.overlays;

      # Every destination the declaration mounts something at. The launcher
      # refuses one twice, so the checks refuse it first.
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
  # read-only bind can still be deep in a writable one.
  #
  # The launch repeats the rule against the caller's own writable binds,
  # which only exist then, so it is given each mask's host path as well.
  maskHost = d: m:
    let
      under = lib.filter (x: x != m && lib.hasPrefix "${x}/" m) d.dests;
      nearest = lib.foldl' (a: x: if a == null || lib.stringLength x > lib.stringLength a then x else a) null under;
      b = if nearest == null then null else lib.findFirst (x: x.dest == nearest) null d.binds;
    in
    if b == null then null else b.src + "/" + lib.removePrefix "${nearest}/" m;

  deepMasks = d: masks:
    let
      over = h: if h == null then [ ] else
        map (w: w.src) (lib.filter (w: w.rw && lib.hasPrefix "${w.src}/" h && depth (lib.removePrefix "${w.src}/" h) >= 2) d.binds);
    in
    lib.concatMap (m: let ws = over (maskHost d m); in
      lib.optional (ws != [ ]) "${m} (in the writable bind of ${lib.concatStringsSep ", " (lib.unique ws)})") masks;

  # THE PREPARED ROOT, BUILT AS CONTAINER ROOT IN THE CALLER'S OWN USER
  # NAMESPACE. Run by the cache tool below, under `unshare --user --mount
  # --pid`, with the maps a session gets: the container's user onto the
  # caller, its primary group onto the caller's, and every other id from the
  # caller's subordinate range. So the root's files are owned by exactly the
  # ids a session later sees them as.
  #
  # nspawn's mounts are replaced by explicit ones -- proc, a tmpfs /dev with
  # the usual nodes bound in, tmpfs /run and /tmp, read-only /nix/store and
  # /nix/var/nix/db -- and the closure's activation and tmpfiles run chrooted,
  # as the nspawn engine's prepare does, and for the same reasons.
  #
  # One program for every declaration: its store path names the cache, so a
  # change to it is a new root everywhere.
  #
  # Each step's status goes to the log as it happens. activate and tmpfiles
  # are gated, as the nspawn engine's `activate && systemd-tmpfiles` is: a
  # root without them is quietly broken (nix-ld's /lib64 is a tmpfiles
  # rule). Rootless tmpfiles cannot set the immutable bit on /var/empty; it
  # logs that as ignored and still exits 0. The machine id is tolerated, as
  # it is there: an id is a nicety and a prepared root is not.
  prepareInner = pkgs.writeShellApplication {
    name = "flong-prepare-inner";
    runtimeInputs = [ pkgs.coreutils pkgs.util-linux ];
    text = ''
      staging=$1 closure=$2 user=$3

      # Never recreate a vanished staging directory: the cache's lock is held
      # across the prepare, so this is the second line, not the first.
      if [[ ! -d $staging ]]; then
        echo "flong-prepare-inner: $staging is gone" >&2
        exit 1
      fi

      # Container root owns the root and makes every mount point: a
      # caller-made skeleton fails tmpfiles with "unsafe path transition".
      chown 0:0 "$staging"
      chmod 0755 "$staging"
      mkdir -p "$staging"/{etc,proc,sys,dev,run,tmp,var/lib,usr/lib,nix/store,nix/var/nix/db}
      mount --make-rprivate /
      mount --bind "$staging" "$staging"
      mount -t proc proc "$staging/proc"
      mount -t tmpfs -o mode=755,nosuid tmpfs "$staging/dev"
      for d in null zero full random urandom tty; do
        touch "$staging/dev/$d"
        mount --bind "/dev/$d" "$staging/dev/$d"
      done
      mkdir -p "$staging/dev/pts" "$staging/dev/shm"
      mount -t tmpfs -o mode=755,nosuid,nodev tmpfs "$staging/run"
      mount -t tmpfs -o mode=1777,nosuid,nodev tmpfs "$staging/tmp"
      mount --rbind /nix/store "$staging/nix/store"
      mount -o remount,bind,ro "$staging/nix/store"
      mount --bind /nix/var/nix/db "$staging/nix/var/nix/db"
      mount -o remount,bind,ro "$staging/nix/var/nix/db"

      # In the root, with only the closure on PATH, as a boot would have it.
      inside() { env -i PATH="$closure/sw/bin" chroot "$staging" "$@"; }

      rc=0
      inside "$closure/activate" || rc=$?
      echo "ACTIVATE_RC=$rc"
      if ((rc != 0)); then exit 1; fi

      # --exclude-prefix=/dev: which devices a session sees is allowedDevices'
      # business. No --boot: a prepared root is an image, not a boot.
      rc=0
      inside "$closure/sw/bin/systemd-tmpfiles" --create --exclude-prefix=/dev || rc=$?
      echo "TMPFILES_RC=$rc"
      if ((rc != 0)); then exit 1; fi

      # The session gets its own resolv.conf when it has a network, and none
      # when it has nowhere to send a query.
      rm -f "$staging/etc/resolv.conf"

      rc=0
      "$closure/sw/bin/systemd-machine-id-setup" --root="$staging" || rc=$?
      echo "MACHINEID_RC=$rc"

      # The user's home, for a user declared with createHome = false, who
      # would otherwise arrive in a directory that is not there. Made inside
      # the root, so a symlink on the way resolves there and not on the host.
      uid="" gid="" home=""
      while IFS=: read -r n _ u g _ h _; do
        if [[ $n == "$user" ]]; then uid=$u gid=$g home=$h; break; fi
      done <"$staging/etc/passwd"
      rc=0
      if [[ -z $uid || -z $gid || $home != /* ]]; then
        echo "flong-prepare-inner: $user has no uid, gid or home in the prepared root" >&2
        rc=1
      else
        inside "$closure/sw/bin/mkdir" -p -- "$home" || rc=$?
        if ((rc == 0)); then inside "$closure/sw/bin/chown" "$uid:$gid" -- "$home" || rc=$?; fi
      fi
      echo "HOME_RC=$rc"
      if ((rc != 0)); then exit 1; fi
    '';
  };

  # The caller's side of the prepared root: making it, and removing one that
  # is no longer wanted. Its arguments are
  #
  #   flong-cache SUBCOMMAND MAPARG... -- ARG...
  #
  # where each MAPARG is an --map-users= or --map-groups= option for unshare,
  # built by the launcher from the caller's subordinate ranges. The launcher
  # holds the cache's locks around a prepare; this tool takes none of its own
  # there.
  #
  # A subordinate id's files cannot be removed by the caller, so every
  # removal is done as container root in the same user namespace, which maps
  # every id a root of this caller's can hold.
  cacheTool = pkgs.writeShellApplication {
    name = "flong-cache";
    runtimeInputs = [ pkgs.coreutils pkgs.util-linux ];
    text = ''
      sub=''${1:-}
      shift || true
      maps=()
      while (($# > 0)) && [[ $1 != -- ]]; do
        case $1 in
          --map-users=* | --map-groups=*) maps+=("$1") ;;
          *) echo "flong-cache: not a map: $1" >&2; exit 2 ;;
        esac
        shift
      done
      if (($# == 0)) || ((''${#maps[@]} == 0)); then
        echo "usage: flong-cache prepare|gc --map-users=... --map-groups=... -- ARG..." >&2
        exit 2
      fi
      shift

      # util-linux's unshare execs newuidmap and newgidmap from PATH, and only
      # the setuid wrappers can write a map beyond the caller's own id.
      asroot() {
        PATH=/run/wrappers/bin:$PATH unshare --user "''${maps[@]}" --setuid 0 --setgid 0 "$@"
      }

      case $sub in
        prepare)
          cache=$1 closure=$2 user=$3
          prepared=$cache/prepared
          # Any staging here is a SIGKILLed preparer's, which held the
          # launcher's lock until its orphaned prepare finished, so it goes.
          for st in "$cache"/.prepare.??????; do
            if [[ -d $st ]]; then asroot rm -rf -- "$st" "$st.log"; fi
          done
          staging=$(mktemp -d "$cache/.prepare.XXXXXX")
          if ! asroot --mount --pid --fork --kill-child \
              ${prepareInner}/bin/flong-prepare-inner "$staging" "$closure" "$user" \
              >"$staging.log" 2>&1; then
            echo "flong-cache: prepare failed, see $staging.log" >&2
            exit 1
          fi
          # The rename is the second line behind the lock: a loser's root
          # goes, through the namespace that owns it.
          if mv -T -- "$staging" "$prepared" 2>/dev/null; then
            mv -f -- "$staging.log" "$cache/prepare.log"
          elif [[ -d $prepared ]]; then
            asroot rm -rf -- "$staging" "$staging.log"
          else
            echo "flong-cache: could not install the prepared root in $cache" >&2
            exit 1
          fi
          ;;

        gc)
          # A superseded cache, or the trash a killed run left, when no
          # launcher holds it. Every launcher holds a shared flock on its
          # cache for its whole life, so an exclusive one here means no
          # session reads this root as its overlay's lower. Tried, never
          # waited for: a cache in use is kept for a later run.
          old=$1
          { exec {l}<"$old"; } 2>/dev/null || exit 0
          if ! flock -xn "$l"; then
            echo "flong-cache: $old is in use, kept" >&2
            exit 0
          fi
          # Locked what the name no longer names: somebody else has it in hand.
          if [[ ! $old -ef /proc/self/fd/$l ]]; then exit 0; fi
          # Renamed first, holding the lock, so a launcher that opened the
          # path before the rename and locks it after finds the path no
          # longer names what it locked, and relaunches. Renaming a live
          # overlay lower is harmless where deleting it is not.
          trash=$old
          if [[ ''${old##*/} != .trash.* ]]; then
            trash=''${old%/*}/.trash.''${old##*/}.$$
            mv -T -- "$old" "$trash" || exit 0
          fi
          # The lock stays held across the deletion, so another run that
          # finds this trash says "in use" rather than racing this one.
          asroot rm -rf -- "$trash"
          ;;

        *)
          echo "flong-cache: unknown subcommand: $sub" >&2
          exit 2
          ;;
      esac
    '';
  };

  # The first eight hex digits of the cache tool's store path, which
  # references the prepare program: a change to either is a different root,
  # so it names a different cache.
  steps8 = builtins.substring 0 8
    (builtins.hashString "sha256" (builtins.unsafeDiscardStringContext "${cacheTool}"));

  # The container runs as root on no host at all under rootless, so these
  # are the host facts the launcher needs, each from where NixOS sets it.
  sysctl = k: config.boot.kernel.sysctl.${k} or null;
  wrapperOn = w: config.security.enableWrappers
    && config.security.wrappers ? ${w} && config.security.wrappers.${w}.enable;

  # The seccomp pipeline: the compiler, the tiers expanded from this system's
  # own `systemd-analyze syscall-filter`, the fixed filters, and the tool that
  # compiles a project's policy at launch. A filter's store path is named by
  # its content, so declarations with equal policies share it.
  seccomp = import ./seccomp/policy.nix {
    inherit pkgs lib;
    systemd = config.systemd.package;
    compiler = import ./seccomp { inherit pkgs; };
  };

  # How many user namespaces a nestedSandbox session may make below its own.
  # A ceiling, not a need: Chromium's sandbox, `codex sandbox` and a nested
  # bwrap ran under 16.
  nestedUserNamespaces = 128;
in
{
  inherit declarationOf prepareInner cacheTool steps8 seccomp;

  # THE LAUNCHER: a header of assignments, generated here, then
  # rootless-wrapper.bash, the same text for every declaration. The header is
  # the only place a declaration reaches bash, and every value in it is
  # quoted, so a name, a path or a snippet is data there and never code. It
  # runs nothing and expands nothing; the body decides what runs.
  #
  # `c.path` is on PATH for the caller's snippets only. The body calls its
  # own tools by the store paths the header gives it.
  mkLauncher = name: c:
    let
      d = declarationOf name c;
      inherit (d) declared;
      q = lib.escapeShellArg;
      qs = lib.escapeShellArgs;
      closure = "${declared.path}";
      s = c.seccomp;

      # The hook programs. postStop is the nspawn engine's own program, since
      # it is given the same `machine` and nothing else. postStart is a
      # program rather than a snippet because the launcher runs it, with the
      # environment the launcher gives it: shellcheck cannot see where
      # $leader, $netns or $workspace come from, so SC2154 is off.
      postStartScript = pkgs.writeShellApplication {
        name = "flong-poststart-${name}";
        runtimeInputs = [ pkgs.coreutils pkgs.util-linux ] ++ c.path;
        excludeShellChecks = [ "SC2154" ];
        text = c.postStart;
      };
      postStopScript = shared.mkPostStopScript name c;

      # systemd's names for the limits, as the cgroup files they are written
      # to. systemd spells unlimited `infinity` and the kernel `max`.
      value = v: if v == "infinity" then "max" else toString v;
      limitTokens =
        let
          l = c.limits;
          plain = lib.concatLists (lib.mapAttrsToList
            (field: file: lib.optionals (l.${field} != null) [ "limit" file (value l.${field}) ])
            {
              MemoryMax = "memory.max";
              MemoryHigh = "memory.high";
              MemorySwapMax = "memory.swap.max";
              TasksMax = "pids.max";
              CPUWeight = "cpu.weight";
            });
          # A percentage of one CPU is that many thousandths of a 100 ms period.
          quota = lib.toIntBase10 (lib.removeSuffix "%" l.CPUQuota) * 1000;
        in
        plain
        ++ lib.optionals (l.CPUQuota != null) [ "limit" "cpu.max" "${toString quota} 100000" ]
        ++ lib.optionals l.oomGroup [ "limit" "memory.oom.group" "1" ];

      # Everything in the spec that does not depend on the launch, in the
      # launcher's own words. Its order does not matter: the launcher sorts
      # the mounts itself, parents first.
      staticTokens =
        [ "container" c.container "closure" closure ]
        ++ lib.concatLists (lib.mapAttrsToList
          (_: m: [ "mount" (if m.isReadOnly then "bind-ro" else "bind-rw") m.mountPoint
                   (if m.hostPath == null then m.mountPoint else m.hostPath) ])
          declared.bindMounts)
        ++ lib.concatMap (t: [ "mount" "tmpfs" t.path t.mode t.size t.owner ]) d.tmpfs
        ++ lib.concatMap (p: [ "mount" "overlay" p (toString c.overlays.${p}) ]) d.overlayDests
        ++ lib.concatMap (x: [ "mount" "dev" x.node x.node ]) d.devices
        ++ lib.concatMap (m: [ "mount" "mask" m ]) c.masks
        # The user manager's bus and systemd directory are the caller's
        # runtime directory's, which is known only at launch.
        ++ lib.concatMap (p: [ "protect" p ]) ([ "/proc" "/sys/fs/cgroup" ] ++ c.protect)
        ++ limitTokens
        ++ lib.optionals s.nestedSandbox [ "nested-userns" (toString nestedUserNamespaces) ]
        ++ [ "holder" "app.slice/flong-sessions.service" ]
        ++ lib.concatMap (a: [ "holder-start" a ])
          [ "/run/current-system/sw/bin/systemctl" "--user" "start" "flong-sessions.service" ]
        ++ lib.optionals (c.postStop != "")
          [ "post-stop" "${postStopScript}/bin/flong-poststop-${name}" ]
        ++ lib.optionals (c.network != null) ([ "network" ]
          ++ lib.concatMap (a: [ "pasta-arg" a ]) (shared.pastaPortArgs c.network ++ [ "--no-map-gw" ])
          # Fixed ports are bound on the host, so teardown waits for pasta to
          # let them go, and the next session can have them.
          ++ lib.optional (lib.isList c.network.forwardPorts && c.network.forwardPorts != [ ]) "pasta-wait");

      # Every name the header assigns. The header un-exports them all: an
      # assignment to a name the caller's environment exports keeps it
      # exported, into the launcher and the hooks.
      names = [
        "name" "container" "user" "closure" "cuid" "cgid" "closure8" "steps8"
        "static" "declared_dests" "declared_binds" "masks" "mask_hosts"
        "launcher" "cache_tool" "flock" "payload" "post_start"
        "network" "dns_forward4" "dns_forward6"
        "workspace_snippet" "binds_snippet" "guard_snippet"
        "seccomp_tier" "seccomp_fixed" "seccomp_project" "seccomp_policy_snippet"
      ];

      # One group, so one directive covers it: a `$`, a quote or a backslash
      # in a value is meant literally, which is what shellcheck warns of.
      header = ''
        # shellcheck disable=SC2016,SC2089,SC2090
        {
        name=${q name}
        container=${q c.container}
        user=${q c.user}
        closure=${q closure}
        cuid=${toString d.cuid}
        cgid=${toString d.cgid}
        closure8=${q (builtins.substring 0 8 (baseNameOf closure))}
        steps8=${q steps8}
        static=(${qs staticTokens})
        declared_dests=(${qs (map norm d.dests)})
        declared_binds=(${qs (map (b: norm b.dest) d.binds)})
        masks=(${qs c.masks})
        mask_hosts=(${qs (map (m: let h = maskHost d m; in if h == null then "" else h) c.masks)})
        launcher=${q "${shared.flongLauncher}/bin/flong-launch"}
        cache_tool=${q "${cacheTool}/bin/flong-cache"}
        flock=${q "${pkgs.util-linux}/bin/flock"}
        payload=${q (lib.getExe (shared.mkPayload name c))}
        post_start=${q (if c.postStart == "" then "" else "${postStartScript}/bin/flong-poststart-${name}")}
        network=${if c.network == null then "0" else "1"}
        dns_forward4=${q shared.dnsForward4}
        dns_forward6=${q shared.dnsForward6}
        workspace_snippet=${q (if lib.trim c.workspace == "pwd" then "" else c.workspace)}
        binds_snippet=${q c.binds}
        guard_snippet=${q c.guard}
        seccomp_tier=${q (if s.tier == null then "" else "${seccomp.filterFor s}")}
        seccomp_fixed=(${qs ([ seccomp.fixed.audit seccomp.fixed.tty ] ++ lib.optional (! s.nestedSandbox) seccomp.fixed.nsmask)})
        seccomp_project=(${qs (lib.optionals (c.seccompPolicy != "")
          [ "${seccomp.project}/bin/flong-seccomp-project" "${seccomp.namesFor s}" (seccomp.deny s) ])})
        seccomp_policy_snippet=${q c.seccompPolicy}
        export -n ${lib.concatStringsSep " " names}
        }
      '';
    in
    pkgs.writeShellApplication {
      inherit name;
      runtimeInputs = c.path;
      text = header + builtins.readFile ./rootless-wrapper.bash;
    };

  # Everything the container module or flong's options can say that the
  # rootless engine cannot honour, refused rather than dropped. Each message
  # names the declaration.
  assertionsFor = n: c:
    let
      d = declarationOf n c;
      inherit (d) declared;
      portStart = let v = sysctl "net.ipv4.ip_unprivileged_port_start"; in
        if v == null then 1024 else lib.toInt (toString v);
      fixedPorts = if c.network != null && lib.isList c.network.forwardPorts then c.network.forwardPorts else [ ];
      lowPorts = map (p: p.hostPort) (lib.filter (p: p.hostPort < portStart) fixedPorts);

      # The user manager's state and sockets, and flong's own, by the
      # lexical spelling a declaration would use.
      reachesManager = s:
        lib.elem s [ "/" "/run" "/run/user" ]
        || builtins.match "/run/user/[^/]+(/(flong|bus|systemd)(/.*)?)?" s != null;
      protected = [ "/proc" "/sys/fs/cgroup" ] ++ map norm c.protect;
      sources = map (b: b.src) d.binds ++ map (v: norm (toString v)) (lib.attrValues c.overlays);
      badSources = lib.filter (s: reachesManager s || lib.any (overlaps s) protected) sources;

      unclean = lib.filter (p: ! clean p) (lib.unique (
        map (b: b.dest) d.binds
        ++ lib.mapAttrsToList (_: m: if m.hostPath == null then m.mountPoint else m.hostPath) declared.bindMounts
        ++ map (t: t.path) d.tmpfs
        ++ d.overlayDests ++ map toString (lib.attrValues c.overlays)
        ++ c.masks ++ map (x: x.node) d.devices ++ c.protect));

      twice = lib.unique (lib.filter (x: lib.count (y: y == x) d.dests > 1) d.dests);
      deep = deepMasks d c.masks;
      badTmpfs = map (t: t.path) (lib.filter (t: t.bad) d.tmpfs);
      badDevices = map (x: "${x.node} ${x.modifier}")
        (lib.filter (x: ! lib.hasPrefix "/dev/" x.node || ! lib.elem x.modifier [ "rw" "rwm" ]) d.devices);
      devBinds = lib.filter (s: s == "/dev" || lib.hasPrefix "/dev/" s) (map (b: b.src) d.binds);

      # What acts on a tier's allow-list, so has nothing to act on without one.
      noTier = lib.optional (c.seccomp.allow != [ ]) "seccomp.allow"
        ++ lib.optional (c.seccomp.deny != [ ]) "seccomp.deny"
        ++ lib.optional c.seccomp.log "seccomp.log"
        ++ lib.optional (c.seccompPolicy != "") "seccompPolicy";
    in
    [
      {
        assertion = builtins.match "[A-Za-z0-9_-][A-Za-z0-9_.-]{0,99}" c.container != null;
        message = ''
          flong.${n} runs containers.${c.container} rootless, and the launcher
          names a session's cgroup and record after the container: the name
          must be letters, digits, `_`, `-` and `.`, not start with `.`, and be
          at most 100 characters, leaving room for the session's own suffix.
        '';
      }
      {
        assertion = declared.extraFlags == [ ];
        message = ''
          flong.${n} runs containers.${c.container} rootless, whose extraFlags
          are nspawn flags. There is no nspawn under rootless to pass them to,
          and flong refuses them rather than drop them.
        '';
      }
      {
        assertion = declared.networkNamespace == null;
        message = ''
          flong.${n} runs containers.${c.container} rootless, which names a
          networkNamespace. A namespace something else built is owned by the
          initial user namespace, and a caller cannot join it from a user
          namespace of their own. Use flong.${n}.network for a network.
        '';
      }
      {
        assertion = c.scopeConfig == { };
        message = ''
          flong.${n} sets scopeConfig, which is the nspawn engine's: a rootless
          session has no scope unit. Set its limits in flong.${n}.limits.
          AllowedCPUs, the Device* and IPAddress* properties, SocketBind* and
          RestrictNetworkInterfaces have no rootless equivalent at all.
        '';
      }
      {
        assertion = badTmpfs == [ ];
        message = ''
          flong.${n} runs containers.${c.container} rootless, whose tmpfs
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
        assertion = badSources == [ ];
        message = ''
          flong.${n} runs containers.${c.container} rootless, and would bind
          ${lib.concatStringsSep ", " badSources} into a session. That reaches
          flong's state, the user manager's bus or private socket, /proc,
          the cgroup filesystem or a path in flong.${n}.protect, any of which
          lets a session act as the caller outside it. The check here is
          lexical; the launcher's canonical one refuses the rest at launch.
        '';
      }
      {
        assertion = deep == [ ];
        message = ''
          flong.${n} masks ${lib.concatStringsSep ", " deep}, two or more
          levels below the root of a writable bind. A session that can write
          the host directory can rename the masked file's parent and leave a
          decoy for the mask to cover, and the file shows through at the new
          name. Mask at most one level below the root of the writable bind
          named, or make that bind read-only.
        '';
      }
      {
        assertion = badDevices == [ ];
        message = ''
          flong.${n} runs containers.${c.container} rootless, whose
          allowedDevices has ${lib.concatStringsSep ", " badDevices}. A device
          is bound read-write, so the node must be under /dev/ and the modifier
          "rw" or "rwm" (m means nothing for a bound node).
        '';
      }
      {
        assertion = devBinds == [ ];
        message = ''
          flong.${n} runs containers.${c.container} rootless, which binds
          ${lib.concatStringsSep ", " devBinds}. A plain bind is nodev, so the
          device would mount and then refuse every open. List it in
          allowedDevices instead, and drop the bind.
        '';
      }
      {
        assertion = declared.privateNetwork;
        message = ''
          flong.${n} runs containers.${c.container} rootless, which does not
          set privateNetwork = true. A rootless session always has a network
          namespace of its own, so it cannot share the host's. Set
          privateNetwork = true, and give it flong.${n}.network = { } for a
          network -- forwardPorts = "auto" and hostLoopbackToSession = true
          for a dev server reached from the host.
        '';
      }
      {
        assertion = d.uEntry != null;
        message =
          if ! d.cfgEval.success then ''
            flong.${n} runs containers.${c.container} rootless, which is
            declared by path. The rootless engine needs its configuration, to
            read ${c.user}'s uid and gid at evaluation. Declare it with
            `config`.
          '' else ''
            flong.${n}: ${c.user} is not a user in containers.${c.container}.
          '';
      }
      {
        assertion = d.uEntry == null || (d.cuid != null && d.cgid != null);
        message = ''
          flong.${n} runs containers.${c.container} rootless as ${c.user}, whose
          uid or primary group's gid is not declared. They decide the prepared
          root's cache and the caller's maps, before anything is prepared, so
          declare users.users.${c.user}.uid and the gid of its group in the
          container's configuration.
        '';
      }
      {
        assertion = d.cuid == null || d.cgid == null || (d.cuid <= 65535 && d.cgid <= 65535);
        message = ''
          flong.${n} runs containers.${c.container} rootless as ${c.user}
          (${toString d.cuid}:${toString d.cgid}), outside the container's ids
          0-65535.
        '';
      }
      {
        assertion = unclean == [ ];
        message = ''
          flong.${n} runs containers.${c.container} rootless, and
          ${lib.concatStringsSep ", " unclean} is not a clean absolute path:
          it is /, or has a trailing slash, an empty, . or .. component, or a
          component over 255 bytes. The launcher would refuse it at launch.
        '';
      }
      {
        assertion = twice == [ ];
        message = ''
          flong.${n} runs containers.${c.container} rootless, and mounts
          something at ${lib.concatStringsSep ", " twice} twice: as two of a
          bind, a mask, a tmpfs, an overlay or a device. The launcher mounts
          one thing at each path.
        '';
      }
      {
        assertion = c.seccomp.tier != null || noTier == [ ];
        message = ''
          flong.${n} sets seccomp.tier = null and ${lib.concatStringsSep ", " noTier},
          which change a tier's allow-list. With no tier there is no filter
          for them to act on. Set a tier, or drop them.
        '';
      }
      {
        assertion = ! declared.autoStart;
        message = ''
          flong.${n} runs containers.${c.container} rootless, which has
          autoStart enabled: it would boot at every host boot as a root
          systemd-nspawn machine, contrary to engine = "rootless". Set
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
    ++ lib.optional (c.guard != "") ''
      flong.${n} has a guard and runs rootless, where the guard is a
      consistency check and not a gate: the caller can run flong-launch
      directly, with any spec.
    '';

  # THE HOLDER: one user unit per caller, whose cgroup every rootless session
  # of theirs lives under, delegated so the launcher can make a session's
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
    description = "flong: holder of rootless sessions and their sweeper";
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
      ExecStart = "${shared.flongLauncher}/bin/flong-sweeper %t/flong";
    };
  };

  # The host facts the launcher depends on, asserted once however many
  # declarations are rootless. The kernel's own minimum is documented and
  # not asserted: the launcher fails loudly on an older one.
  hostAssertions = [
    {
      assertion = config.security.allowUserNamespaces;
      message = ''
        flong: a declaration runs rootless, which needs user namespaces, and
        security.allowUserNamespaces is false.
      '';
    }
    {
      assertion = ! lib.elem (sysctl "user.max_user_namespaces") [ 0 "0" ]
        && ! lib.elem (sysctl "kernel.unprivileged_userns_clone") [ false 0 "0" ];
      message = ''
        flong: a declaration runs rootless, which needs unprivileged user
        namespaces, and boot.kernel.sysctl sets user.max_user_namespaces to 0
        or kernel.unprivileged_userns_clone off.
      '';
    }
    {
      assertion = wrapperOn "newuidmap" && wrapperOn "newgidmap";
      message = ''
        flong: a declaration runs rootless, and the launcher maps ids through
        /run/wrappers/bin/newuidmap and newgidmap, which this system does not
        install. security.shadow.enable = false removes them, and so does
        security.account-utils, which disables newuidmap.
      '';
    }
    {
      assertion = lib.versionAtLeast pkgs.bubblewrap.version "0.12";
      message = ''
        flong: a declaration runs rootless, and the launcher needs bubblewrap
        0.12 or later (--overlay-src, --tmp-overlay, --add-seccomp-fd); this
        nixpkgs has ${pkgs.bubblewrap.version}.
      '';
    }
    {
      assertion = lib.versionAtLeast config.systemd.package.version "254";
      message = ''
        flong: a declaration runs rootless, and its holder unit needs systemd
        254 or later for DelegateSubgroup=; this system has
        ${config.systemd.package.version}.
      '';
    }
  ];
}
