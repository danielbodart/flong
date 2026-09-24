{ config, lib, pkgs, ... }:

let
  cfg = config.flong;

  # WHERE A NETWORKED SESSION SENDS ITS DNS, for pasta to take from there.
  # --dns-forward catches UDP and TCP to ports 53 and 853 at this address
  # and re-sends each query FROM THE HOST to the host's own first
  # nameserver. Re-originated there, so a stub resolver on the host's
  # loopback -- resolved's 127.0.0.53, a dnsmasq on 127.0.0.1 -- answers a
  # session that has no way to the host's loopback otherwise. That is why
  # this and not a copy of the host's resolv.conf: copied in, 127.0.0.53
  # names the SESSION's loopback, where nothing is listening.
  #
  # 169.254.1.1 is Podman's address for the same job -- `dnsForwardIpv4`
  # in go.podman.io/common's libnetwork/pasta -- followed deliberately.
  # It is IPv4 link-local, which no router forwards, so nothing beyond
  # the host's own link could answer it even without pasta in the way. A
  # LAN has it only through link-local autoconfiguration, and then all
  # the session loses is that one address's DNS ports. And it is well
  # clear of the addresses a cloud answers on -- metadata at
  # 169.254.169.254, AWS's resolver at 169.254.169.253, ECS at
  # 169.254.170.2 -- so no rule about those catches it, and nobody reading
  # a resolv.conf takes it for one of them. A steering hook's own service
  # address in the same namespace (frisket's, on `lo`) must be another
  # address again: on `lo`, it would take these queries before pasta ever
  # saw them.
  #
  # 100::1 for IPv6, which Podman does not forward at all. It is in
  # RFC 6666's discard-only block, which exists to be dropped: globally
  # unreachable, used by no LAN, and blackholed by the first router that
  # sees it. Link-local, the IPv4 answer, is no use in IPv6: an fe80::
  # nameserver needs a zone, and the interface inside is named after
  # whichever host interface pasta copied.
  dnsForward4 = "169.254.1.1";
  dnsForward6 = "100::1";

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

  # EVERY PORT CLASS IS SPELT OUT, "none" included, because -t, -u, -T and
  # -U all default to `auto` -- and `auto` forwards every port bound on the
  # other side, which for -T means everything listening on the host's
  # loopback. A session asks for what it gets, port by port.
  #
  # hostPorts go out as TCP and UDP both: a port on the host's loopback is
  # the thing named, and a resolver there is as likely a reason to name one
  # as a database.
  #
  # forwardPorts "auto" is pasta's own: every second it reads what is
  # listening in the session and publishes the same TCP port on the host,
  # for as long as it is listening.
  #
  # A list of words, each passed to the launcher as one pasta-arg.
  pastaPortArgs = net:
    let
      spec = ports: if ports == [ ] then "none" else lib.concatStringsSep "," ports;
      forwards = protocol: map
        (p: "${toString p.hostPort}:${toString (if p.containerPort == null then p.hostPort else p.containerPort)}")
        (lib.filter (p: p.protocol == protocol) net.forwardPorts);
      host = map toString net.hostPorts;
      auto = net.forwardPorts == "auto";
    in
    [ "-t" (if auto then "auto" else spec (forwards "tcp")) "-u" (if auto then "none" else spec (forwards "udp"))
      "-T" (spec host) "-U" (spec host) ]
    ++ lib.optional net.hostLoopbackToSession "--host-lo-to-ns-lo";

  # The native launcher: flong, whose subcommands are launch, sweeper and
  # init, Zig, static and without libc (native.nix's launcher set). Built
  # from this nixpkgs, so its bubblewrap is the host's.
  flongLauncher = import ./launcher { inherit pkgs; };

  # A path as the launcher compares it for the checks below: /var/run is
  # /run, and repeated and trailing slashes go. Lexical only; the launcher
  # canonicalises at launch, and its check is the authority.
  norm = p:
    let q = "/" + lib.concatStringsSep "/" (lib.filter (x: x != "") (lib.splitString "/" p)); in
    if q == "/var/run" || lib.hasPrefix "/var/run/" q then "/run" + lib.removePrefix "/var/run" q else q;

  # What the launcher's spec parser accepts as a path (spec.clean in
  # src/spec.zig; tests/golden/paths.txt holds the cases both must agree
  # on, and those meant to differ): absolute, not /, and every component
  # present, not . or .., and at most 255 bytes. A path it would refuse at launch is refused
  # here, where the declaration can still be read.
  clean = p:
    let parts = lib.splitString "/" (lib.removePrefix "/" p); in
    lib.hasPrefix "/" p && p != "/"
    && lib.all (x: x != "" && x != "." && x != ".." && lib.stringLength x <= 255) parts;

  # Either path lies inside the other, or they are the same.
  overlaps = a: b: a == b || lib.hasPrefix "${a}/" b || lib.hasPrefix "${b}/" a;

  # The destinations given more than once. The launcher mounts one thing at
  # each path, and refuses a destination twice (mount.sortRefusingTwice),
  # so the checks refuse it first.
  twiceIn = dests: lib.unique (lib.filter (x: lib.count (y: y == x) dests > 1) dests);

  # clean, overlaps and twiceIn mirror the launcher's checks
  # (src/spec.zig's clean, src/mount.zig's overlaps and duplicate refusal).
  # tests/golden/paths.txt declares, once, each case's verdict and whether
  # the mirror is meant to say the same or, lexical where the launcher is
  # canonical, the opposite; tests/zig/paths.zig holds the launcher to it,
  # and hostAssertions holds these. The cases that disagree, as lines of it.
  pathCaseMisses =
    let
      cases = lib.filter (l: l != "" && ! lib.hasPrefix "#" l)
        (lib.splitString "\n" (builtins.readFile ./tests/golden/paths.txt));
      miss = l:
        let
          f = lib.splitString "\t" l;
          field = builtins.elemAt f;
          check = field 0;
          said =
            if check == "clean" then clean (field 3)
            else if check == "overlaps" then overlaps (norm (field 3)) (norm (field 4))
            else if check == "twice" then twiceIn [ (field 3) (field 4) ] != [ ]
            else throw "tests/golden/paths.txt: unknown check ${check}";
          launcher = field 1 == "yes";
          want = if field 2 == "differs" then ! launcher else launcher;
        in
        lib.optional (said != want) l;
    in
    lib.concatMap miss cases;

  # How many components REL has.
  depth = rel: lib.length (lib.filter (x: x != "") (lib.splitString "/" rel));

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
  # The mounts a container's own boot would have -- proc, a tmpfs /dev with
  # the usual nodes bound in, tmpfs /run and /tmp, read-only /nix/store and
  # /nix/var/nix/db -- are made explicitly, and the closure's activation and
  # tmpfiles run chrooted.
  #
  # tmpfiles because a session never boots: the payload runs under tini, the
  # container's systemd is never pid 1 and no unit starts, so a config's
  # `systemd.tmpfiles.rules` would otherwise be carried in the closure and
  # do nothing. That is how programs.nix-ld comes to leave
  # /lib64/ld-linux-x86-64.so.2 absent, and a binary built for generic Linux
  # refuses to start with "required file not found". Paid here, once per
  # prepared root, rather than at every launch.
  #
  # One program for every declaration: its store path names the cache, so a
  # change to it is a new root everywhere.
  #
  # Each step's status goes to the log as it happens. activate and tmpfiles
  # are gated: a root without them is quietly broken. tmpfiles cannot set
  # the immutable bit on /var/empty from a user namespace; it logs that as
  # ignored and still exits 0. The machine id is tolerated, because an id is a
  # nicety and a prepared root is not.
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

  # How many user namespaces a nestedSandbox session may make below its own.
  # A ceiling, not a need: Chromium's sandbox, `codex sandbox` and a nested
  # bwrap ran under 16.
  nestedUserNamespaces = 128;

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

      # TEMPORARY (S2 chunk C; chunk D replaces it, with the wrapper running
      # the commands itself): the hooks are command lists now, and the
      # wrapper still takes shell. Each command becomes one line of it, run
      # with the arguments the snippet was (the launcher's, in "$@"; none
      # for postStop, whose `$1` is the machine) and under the snippet's
      # `set -euo pipefail`, so a failing one ends the rest, as a guard's or
      # a policy's must. The last is exec'd, so a one-command hook is the
      # process it was when it was the snippet. An empty list is an empty
      # snippet, which runs nothing, as "" did.
      hookScript = withArgs: cmds: lib.concatImapStrings
        (i: cmd: "${lib.optionalString (i == lib.length cmds) "exec "}${qs cmd}${lib.optionalString withArgs " \"$@\""}\n") cmds;

      # The hook programs, rather than snippets spliced into the wrapper,
      # because the launcher runs them with the environment it gives them:
      # shellcheck cannot see where postStart's $leader, $netns or
      # $workspace come from, so SC2154 is off there. postStop is not always
      # run by THIS launcher either: a SIGKILLed launcher's session is
      # released by the holder's sweeper, which runs the program the
      # session's record names -- a superseded generation's included, whose
      # code this launcher no longer carries.
      postStartScript = pkgs.writeShellApplication {
        name = "flong-poststart-${name}";
        runtimeInputs = [ pkgs.coreutils pkgs.util-linux ] ++ c.path;
        excludeShellChecks = [ "SC2154" ];
        text = hookScript true c.postStart;
      };
      postStopScript = pkgs.writeShellApplication {
        name = "flong-poststop-${name}";
        runtimeInputs = [ pkgs.coreutils pkgs.util-linux ] ++ c.path;
        text = ''
          # Exported, so a helper the snippet calls sees it as well.
          export machine=$1
          ${hookScript false c.postStop}
        '';
      };

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
        ++ lib.optionals (c.postStop != [ ])
          [ "post-stop" "${postStopScript}/bin/flong-poststop-${name}" ]
        ++ lib.optionals (c.network != null) ([ "network" ]
          ++ lib.concatMap (a: [ "pasta-arg" a ]) (pastaPortArgs c.network ++ [ "--no-map-gw" ])
          # Fixed ports are bound on the host, so teardown waits for pasta to
          # let them go, and the next session can have them.
          ++ lib.optional (lib.isList c.network.forwardPorts && c.network.forwardPorts != [ ]) "pasta-wait");

      # Every name the header assigns. The header un-exports them all: an
      # assignment to a name the caller's environment exports keeps it
      # exported, into the launcher and the hooks.
      names = [
        "name" "container" "user" "closure" "cuid" "cgid" "closure8" "steps8"
        "static" "declared_dests" "declared_binds" "masks" "mask_hosts"
        "launcher" "cache_tool" "flock" "mkdir" "payload" "post_start"
        "network" "dns_forward4" "dns_forward6"
        "workspace_snippet" "binds_snippet" "guard_snippet"
        "seccomp_tier" "seccomp_fixed" "seccomp_project" "seccomp_policy_snippet"
      ];

      # One group, so one directive covers it: a `$`, a quote, a backslash
      # or a comma in a value is meant literally, which is what shellcheck
      # warns of. Two host ports make pasta's `-T 18123,19999`, which
      # escapeShellArg leaves bare.
      header = ''
        # shellcheck disable=SC2016,SC2054,SC2089,SC2090
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
        launcher=${q "${flongLauncher}/bin/flong"}
        cache_tool=${q "${cacheTool}/bin/flong-cache"}
        flock=${q "${pkgs.util-linux}/bin/flock"}
        mkdir=${q "${pkgs.coreutils}/bin/mkdir"}
        payload=${q (lib.getExe (mkPayload name c))}
        post_start=${q (if c.postStart == [ ] then "" else "${postStartScript}/bin/flong-poststart-${name}")}
        network=${if c.network == null then "0" else "1"}
        dns_forward4=${q dnsForward4}
        dns_forward6=${q dnsForward6}
        workspace_snippet=${q (if c.workspace == null then "" else hookScript true [ c.workspace ])}
        binds_snippet=${q (hookScript true c.binds)}
        guard_snippet=${q (hookScript true c.guard)}
        seccomp_tier=${q (if s.tier == null then "" else "${seccomp.filterFor s}")}
        seccomp_fixed=(${qs ([ seccomp.fixed.audit seccomp.fixed.tty ] ++ lib.optional (! s.nestedSandbox) seccomp.fixed.nsmask)})
        seccomp_project=(${qs (lib.optionals (c.seccompPolicy != [ ])
          [ "${seccompCompiler}/bin/flong-seccomp" "project" "${seccomp.dump}" "${seccomp.namesFor s}" (seccomp.deny s) ])})
        seccomp_policy_snippet=${q (hookScript true c.seccompPolicy)}
        export -n ${lib.concatStringsSep " " names}
        }
      '';
    in
    pkgs.writeShellApplication {
      inherit name;
      runtimeInputs = c.path;
      text = header + builtins.readFile ./rootless-wrapper.bash;
    };

  # Everything the container module or flong's options can say that a
  # session cannot honour, refused rather than dropped: most of these
  # declare LESS privilege than the default, and a container that is
  # silently not the one declared is worse than one that refuses to build.
  # Each message names the declaration.
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

      twice = twiceIn d.dests;
      deep = deepMasks d c.masks;
      badTmpfs = map (t: t.path) (lib.filter (t: t.bad) d.tmpfs);
      badDevices = map (x: "${x.node} ${x.modifier}")
        (lib.filter (x: ! lib.hasPrefix "/dev/" x.node || ! lib.elem x.modifier [ "rw" "rwm" ]) d.devices);
      devBinds = lib.filter (s: s == "/dev" || lib.hasPrefix "/dev/" s) (map (b: b.src) d.binds);

      # What acts on a tier's allow-list, so has nothing to act on without one.
      noTier = lib.optional (c.seccomp.allow != [ ]) "seccomp.allow"
        ++ lib.optional (c.seccomp.deny != [ ]) "seccomp.deny"
        ++ lib.optional c.seccomp.log "seccomp.log"
        ++ lib.optional (c.seccompPolicy != [ ]) "seccompPolicy";
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
        assertion = badSources == [ ];
        message = ''
          flong.${n} drives containers.${c.container}, and would bind
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
          flong.${n} drives containers.${c.container}, whose
          allowedDevices has ${lib.concatStringsSep ", " badDevices}. A device
          is bound read-write, so the node must be under /dev/ and the
          modifier "rw" or "rwm" (m means nothing for a bound node).
        '';
      }
      {
        assertion = devBinds == [ ];
        message = ''
          flong.${n} drives containers.${c.container}, which binds
          ${lib.concatStringsSep ", " devBinds}. A plain bind is nodev, so the
          device would mount and then refuse every open. List it in
          allowedDevices instead, and drop the bind.
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
        assertion = d.cuid == null || d.cgid == null || (d.cuid <= 65535 && d.cgid <= 65535);
        message = ''
          flong.${n} drives containers.${c.container} as ${c.user}
          (${toString d.cuid}:${toString d.cgid}), outside the container's ids
          0-65535.
        '';
      }
      {
        assertion = unclean == [ ];
        message = ''
          flong.${n} drives containers.${c.container}, and
          ${lib.concatStringsSep ", " unclean} is not a clean absolute path:
          it is /, or has a trailing slash, an empty, . or .. component, or a
          component over 255 bytes. The launcher would refuse it at launch.
        '';
      }
      {
        assertion = twice == [ ];
        message = ''
          flong.${n} drives containers.${c.container}, and mounts something
          at ${lib.concatStringsSep ", " twice} twice: as two of a bind, a
          mask, a tmpfs, an overlay or a device. The launcher mounts one thing
          at each path.
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
      assertion = pathCaseMisses == [ ];
      message = ''
        flong's path checks in module.nix disagree with
        tests/golden/paths.txt, which the launcher is held to, at:
        ${lib.concatStringsSep "\n" pathCaseMisses}
      '';
    }
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
            The generated launcher, run directly as the user whose session it
            is, never as root. It needs their subordinate ids in /etc/subuid
            and /etc/subgid (`users.users.<name>.subUidRanges`, or
            `autoSubUidGidRange`).

            Its checks -- `workspace`, `binds`, `guard`, the depth rule -- are
            consistency checks, not a boundary: the caller can run
            flong launch directly with any spec. flong launch's own checks and
            the session's `seccomp` filter are the boundary against the
            payload, and the prepared root and the records are the caller's,
            as their `~/.bashrc` is. It exits with the payload's
            status, 128+n when a signal killed the payload, 125 when the
            payload never ran, and 75 when its prepared root was swept and it
            could not relaunch.
          '';
        };
      };

      config = {
        launcher = mkLauncher name config;
      };
    }));
  };

  # boot.enableContainers is left to NixOS: containers.<name> and its closure
  # exist without it, and flong starts no container@ unit.
  config = lib.mkIf (cfg != { }) {
    # The sessions' holder, in every user's manager.
    systemd.user.services.flong-sessions = holderUnit;

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
