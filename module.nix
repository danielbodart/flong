{ config, lib, pkgs, utils, ... }:

let
  cfg = config.flong;

  # nspawn 261 renamed --user to --uid; the launcher runs the host's nspawn, so
  # it speaks the host's systemd. See the comment at the nspawn invocation.
  uidFlag =
    if lib.versionAtLeast config.systemd.package.version "261"
    then "--uid" else "--user";

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

  # A path as nspawn's --bind, --tmpfs and --overlay read one. They split on
  # ':' and take a backslash as an escape for the character after it, so
  # "\:" is a colon inside a path and "\\" a backslash; every other
  # character, whitespace and newline included, is itself. So any path can be
  # expressed, provided it reaches nspawn as one argument.
  nspawnPath = lib.replaceStrings [ "\\" ":" ] [ "\\\\" "\\:" ];

  # extraFlags as the container module's unit uses them: every entry expanded
  # unquoted into the nspawn command line, so split on whitespace.
  extraFlagWords = declared: lib.concatMap
    (f: lib.filter (w: lib.isString w && w != "")
      (builtins.split "[[:space:]]+" f))
    declared.extraFlags;

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

  # A declared tmpfs entry is an nspawn --tmpfs argument, PATH[:OPTIONS],
  # where the path may escape a ':' or a '\' with a backslash. The path
  # is needed on its own, to make the mount point and to find the
  # runtime directory, so it is read out here the way nspawn reads it.
  # Both engines read the same declaration through it.
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
  # A list of words, one argument each: the nspawn launcher joins them
  # with spaces, and the rootless one passes each as a pasta-arg.
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

  # A script of its own, rather than a snippet spliced into the launcher,
  # because it is not always THIS launcher that runs it: the sweep runs
  # inside whichever launch of the container comes next, and several
  # launchers can drive one container. So each session records which
  # teardown is its own, and the sweep runs that one -- including a
  # superseded generation's, whose code this launcher no longer carries.
  mkPostStopScript = name: c: pkgs.writeShellApplication {
    name = "flong-poststop-${name}";
    runtimeInputs = [ pkgs.coreutils pkgs.util-linux ] ++ c.path;
    text = ''
      # Exported, so a helper the snippet calls sees it as well.
      export machine=$1
      ${c.postStop}
    '';
  };

  # The rootless engine's native launcher: flong-launch, flong-sweeper and
  # flong-init. Built from this nixpkgs, so its bubblewrap is the host's.
  flongLauncher = import ./launcher { inherit pkgs; };

  # The rootless engine, kept in a file of its own until the nspawn one is
  # deleted. It is given the module's config, not a declaration's, and the
  # helpers both engines share.
  rootless = import ./rootless.nix {
    inherit config lib pkgs;
    shared = { inherit mkPayload tmpfsEntriesOf pastaPortArgs mkPostStopScript flongLauncher dnsForward4 dnsForward6; };
  };

  # Whether any declaration runs rootless: the host checks and the holder
  # unit exist only then.
  anyRootless = lib.any (c: c.engine == "rootless") (lib.attrValues cfg);

  mkLauncher = name: c:
    let
      declared = config.containers.${c.container};
      closure = declared.path;

      # THE DECLARATION'S MOUNTS AND FLAGS, READ AS THE OPTIONS THEY ARE. The
      # container module renders these same values into a shell-sourced
      # string for its own unit; reading them here, as data, means every path
      # reaches nspawn as one argument, whatever it holds.
      #
      # Each bind is the declaration's own record -- hostPath null is the
      # mount point on both sides, isReadOnly true is --bind-ro -- spelt as
      # the container module spells it, with each path escaped for nspawn.
      declaredBindFlags = lib.mapAttrsToList
        (_: m: "--bind${lib.optionalString m.isReadOnly "-ro"}="
          + nspawnPath (if m.hostPath == null then m.mountPoint else m.hostPath)
          + ":" + nspawnPath m.mountPoint)
        declared.bindMounts;

      # Where the declaration's binds land, for make_dirs: nspawn makes a
      # bind's mount point, and the directories on the way to it, root's.
      declaredMountPoints = lib.mapAttrsToList (_: m: m.mountPoint) declared.bindMounts;

      # Over-mounted with an empty node nobody can read. nspawn's
      # --inaccessible; spelt as a path the way --bind's are.
      maskFlags = map (p: "--inaccessible=" + nspawnPath p) c.masks;

      # extraFlags means what it means to the container module, whose unit
      # expands the entries unquoted: each one is split on whitespace, so an
      # entry can carry several flags, or a flag and its value as two words.
      declaredFlags = declaredBindFlags ++ extraFlagWords declared;

      tmpfsEntries = tmpfsEntriesOf declared;

      # allowedDevices is a unit property rather than an nspawn flag, and is
      # translated here.
      deviceProps = lib.concatMapStringsSep " "
        (d: "--property=DeviceAllow=${lib.escapeShellArg "${d.node} ${d.modifier}"}")
        declared.allowedDevices;

      # The resource control the container module leaves to machine.slice.
      # Worth having per session because a session writes its root, its TMPDIR
      # and every overlay upper into /run -- which is RAM, so a payload that
      # fills one is the host's problem rather than its own.
      # Rendered as a unit file renders `serviceConfig`, so a value means here
      # what it would mean there: a bool is "true" or "false", and a list is
      # one assignment per element, which systemd-run appends for the
      # properties that take a list.
      scopeProps = lib.concatStringsSep " " (lib.concatLists (lib.mapAttrsToList
        (k: v: map
          (x: "--property=${lib.escapeShellArg "${k}=${utils.systemdUtils.lib.toOption x}"}")
          (lib.toList v))
        c.scopeConfig));

      # The kinds of network isolation that need nothing configured inside the
      # container, which is the only kind a session can have: nspawn drops to
      # `user` before pid 1, so there is no privileged moment in there to
      # bring an interface up or address it. A real network is pasta, attached
      # from the host once the namespace exists -- see `network`.
      networkFlags =
        lib.optionalString declared.privateNetwork "--private-network "
        + lib.optionalString (declared.networkNamespace != null)
          "--network-namespace-path=${lib.escapeShellArg declared.networkNamespace}";

      # OFF, SAID OUT LOUD, for a session whose resolv.conf flong writes. Under
      # --private-network `auto` already leaves the root's file alone, but
      # only by way of a rule about something else: were it ever to copy
      # instead, it would do so after the custom binds are mounted, opening
      # with O_TRUNC -- through whatever a bind had put at that path.
      resolvConfFlag = lib.optionalString (c.network != null) "--resolv-conf=off";

      # DEFENCE IN DEPTH, AND NOTHING MORE. A session whose namespace flong or
      # a hook has put something into loses CAP_NET_ADMIN from its bounding set
      # and gains NoNewPrivs, so no file-capability or setuid binary in the
      # closure can pick up the one capability that would reach for it.
      #
      # It is not what holds. `unshare -U` inside the sandbox makes a user
      # namespace with the full bounding set back again -- measured. What holds
      # is that the network namespace is owned by the INITIAL user namespace,
      # so a workload that is not its owner gets EPERM on every write, whatever
      # capabilities it appears to hold: it cannot list the ruleset, flush it,
      # change a route, an address or a link, write /proc/sys/net/*, or move an
      # interface into a namespace it has just created. Measured, all of it.
      # The flags are here so that a second failure is needed, not a first.
      steered = c.postStart != "" || c.network != null;
      capabilityFlags = lib.optionalString steered
        "--drop-capability=CAP_NET_ADMIN --no-new-privileges=yes";

      # Where a session's namespace is pinned for pasta. Beside the caches and
      # not in one, because a cache is swept whole and this is a mount.
      pinDir = "/run/flong/netns";

      overlayDir = p: ".overlay/" + lib.replaceStrings [ "/" ] [ "_" ] (lib.removePrefix "/" p);

      # XDG_RUNTIME_DIR is exported unconditionally, so the directory it names
      # has to exist, and only the launcher can arrange that: /run is nspawn's
      # own tmpfs, made fresh at every start, and nothing inside a session is
      # privileged enough to create a directory in it. It gets the payload's
      # ownership and 0700 because a root-owned 0755 runtime directory is
      # rejected by the things that look at one -- and failing that way is
      # quiet, which is how a session ends up with no keyring, no user bus and
      # no explanation.
      #
      # The tmpfs flags are built in the launcher, because the uid and gid an
      # entry without options is owned by come out of the prepared root's
      # passwd and are not known until then.

      # An explicit upper inside the session root, not nspawn's empty-string
      # form, which puts it under the host's /var/tmp and leaks it on SIGKILL.
      # $root is escaped in the launcher, as root_nspawn.
      overlayFlags = lib.concatMapStrings
        (p: ''
          overlay_flags+=(${lib.escapeShellArg "--overlay=${nspawnPath "${c.overlays.${p}}"}:"}"$root_nspawn"${lib.escapeShellArg "/${nspawnPath (overlayDir p)}:${nspawnPath p}"})
        '')
        (lib.attrNames c.overlays);
      # nspawn creates mount points for --bind but not for --overlay or
      # --tmpfs, so a target whose parent does not exist in the root fails the
      # launch. Made here, along with each overlay's upper layer; the tmpfs
      # mount points are made by the loop that builds their flags, since both
      # halves need the identity.
      mountpointMkdirs = lib.concatStringsSep "\n        " (
        lib.concatMap
          (p: [
            ''mkdir -p "$root"/${lib.escapeShellArg (overlayDir p)}''
            ''make_mount_point ${lib.escapeShellArg p}''
            # The upper layer receives the payload's writes, so it belongs to
            # the payload's user. Note the MERGED directory still takes its
            # ownership from the lower one.
            ''chown "$uid:$gid" "$root"/${lib.escapeShellArg (overlayDir p)}''
          ])
          (lib.attrNames c.overlays)
      );

      # By absolute path: sudo resets PATH to secure_path, and a copy from pkgs
      # would be a different systemd from the one running as pid 1.
      nspawn = "/run/current-system/sw/bin/systemd-nspawn";
      systemdRun = "/run/current-system/sw/bin/systemd-run";
      machinectl = "/run/current-system/sw/bin/machinectl";
      systemctl = "/run/current-system/sw/bin/systemctl";

      # WHO A SESSION RUNS AS IS READ, NOT DECLARED.
      #
      # `user` is the only half a consumer can usefully state: which account in
      # the container to be. The uid, the gid and the home are facts about that
      # account, and the container already carries them -- in the passwd its own
      # activation script wrote, which is the very file nspawn resolves --uid
      # against. Read them from there and there is nothing for a declaration to
      # disagree with.
      #
      # Declaring them meant keeping two copies in step, and a mismatch was an
      # error nowhere: nspawn resolved --uid in there while the launcher chowned
      # TMPDIR, the tmpfs entries and the overlay uppers to the other number,
      # leaving a session that could not write to its own home. Reading also
      # reaches where an assertion could not look -- a container declared by
      # `path` has no configuration to read, and a uid left unset in
      # `users.users.<name>` is allocated during activation, so evaluation never
      # knows it either.
      identityFrom = ''
        # Sets uid, gid and home from $1/etc/passwd. Deliberately not a
        # subshell: the exits below have to end the launch.
        read_identity() {
          local entry
          entry=$(grep "^${c.user}:" "$1/etc/passwd") || {
            echo "${name}: ${c.user} is not a user in containers.${c.container}" >&2
            exit 1
          }
          IFS=: read -ra passwd_field <<< "$entry"
          uid=''${passwd_field[2]}
          gid=''${passwd_field[3]}
          home=''${passwd_field[5]}
          [ -n "$uid" ] && [ -n "$gid" ] && [ -n "$home" ] || {
            echo "${name}: ${c.user} has no uid, gid or home in containers.${c.container}" >&2
            exit 1
          }
        }
      '';

      # Everything that shapes a prepared root, as one string. Deliberately
      # excludes the lines that name the cache itself, which would be circular.
      prepareSteps = ''
        # mktemp gives 0700, and this becomes the container's "/". A root the
        # user cannot traverse cannot reach /nix/store either.
        chmod 0755 "$staging"
        mkdir -p "$staging"/{etc,proc,sys,dev,run,tmp,var/lib,usr/lib,nix/store}

        # activate, then tmpfiles, because the second half is not optional and
        # nothing else here will ever do it. A container config's
        # `systemd.tmpfiles.rules` are applied by a unit at boot, and a session
        # never boots: the payload runs under tini, so the container's systemd
        # is never pid 1 and no unit starts. Without this the rules are
        # declared, carried in the closure, and silently do nothing -- which is
        # how programs.nix-ld comes to install its libraries and leave
        # /lib64/ld-linux-x86-64.so.2 absent, so a binary built for generic
        # Linux is present, readable and refuses to start with "cannot execute:
        # required file not found".
        #
        # Here rather than at launch because it needs root, and a session has
        # none after nspawn drops. It also means it is paid once per prepared
        # root, which is cached and copied per session.
        #
        # --exclude-prefix=/dev deliberately. The rules a distribution ships for
        # device nodes adjust ownership and mode on things like /dev/kvm and
        # /dev/snd, and which of those a container may see is decided by
        # `allowedDevices`, not by a prepare step reaching into nspawn's private
        # /dev.
        #
        # No --boot, equally deliberately. Boot-only rules assume a boot
        # sequence that will undo them: systemd-nologin writes the /run/nologin
        # that systemd-user-sessions later removes, and the R! rules delete
        # state on the same assumption. A prepared root is an image, not a boot.
        ${nspawn} -q --directory="$staging" --as-pid2 \
          --bind-ro=/nix/store --bind-ro=/nix/var/nix/db \
          --setenv=PATH=${closure}/sw/bin \
          ${closure}/sw/bin/bash -c \
          '${closure}/activate && systemd-tmpfiles --create --exclude-prefix=/dev' \
          >/dev/null 2>&1

        # Would otherwise pin this moment's DNS for the life of the boot. A
        # session on the host's network has nspawn bind a fresh one in, since
        # --resolv-conf defaults to auto; a session with `network` has one
        # written into its copy of the root at launch; and a private session
        # without one keeps none, having nowhere to send a query.
        rm -f "$staging/etc/resolv.conf"

        # A container's machine id is written by its init from the uuid nspawn
        # hands it, and a session has no init -- so without this the file is
        # absent and everything that reads one gets ENOENT. Per prepared root,
        # which is once per boot per closure: as stable as anything else here,
        # and it does not follow a session between boots the way a declared
        # container's would.
        #
        # Tolerated if it fails, deliberately: an id is a nicety and a prepared
        # root is not, so this must not be the step that stops one existing.
        ${closure}/sw/bin/systemd-machine-id-setup --root="$staging" \
          >/dev/null 2>&1 || true

        # Now that activate has written the passwd, the home can be made for the
        # account that will own it. Ordinarily activate has already done both --
        # update-users-groups creates a home and chowns it -- but not for a user
        # declared with createHome = false, who would otherwise arrive in a
        # directory that is not there.
        read_identity "$staging"
        mkdir -p "$staging$home"
        chown "$uid:$gid" "$staging$home"
      '';

      # Named for the closure AND for the steps above, because a root prepared
      # by an older flong is not a root this one would build. Keying on the
      # closure alone meant a change to prepare was silently ignored wherever a
      # cache was already warm -- found by fixing tmpfiles and watching the fix
      # do nothing, because the container's closure had not moved. Both hashes
      # rather than one over the pair, so a directory can still be matched to
      # its closure by eye.
      #
      # The identity reader is hashed in too, though it is not spliced into the
      # prepare block: the prepare steps call it to make the home, so a change
      # to how it reads passwd changes the root it produces.
      cache = "/run/flong/${c.container}-"
        + builtins.substring 0 8 (builtins.baseNameOf closure) + "-"
        + builtins.substring 0 8
          (builtins.hashString "sha256" (identityFrom + prepareSteps));

      payload = mkPayload name c;

      # A HOOKED SESSION'S PAYLOAD WAITS FOR THE HOOK. nspawn starts the
      # payload 58-65 ms after systemd-run returns, while `postStart` and pasta
      # can only begin once the namespace exists at 26-30 ms, and take what
      # they take. Left to race, a short payload finished first: measured,
      # once as a whole payload run against an empty route table with the
      # launcher then failing to pin a namespace that had gone, and once as a
      # hook failing with "nsenter: cannot open /proc/<pid>/ns/net" -- turning
      # a payload that SUCCEEDED into a launch that failed, at random.
      #
      # NOT A BOUNDARY. The ordering is that, and holds with or without this:
      # nothing here decides what the workload can reach, only whether what
      # the hook installs and the network it was promised are there yet when
      # it starts. So it is a marker, not a handshake -- a directory the
      # launcher makes from the host once the hook and pasta are done, in a /run
      # that is nspawn's own root-owned tmpfs, where nothing in the session
      # could make it first.
      #
      # Between tini and the payload, so `command` starts after it.
      #
      # NO TIMEOUT. However long the hook takes -- a person answering a
      # question in it, say -- is how long the payload waits. What ends a
      # session whose hook failed is the launcher's trap, at once, and a
      # launcher asked to stop stops its session first. The one case nothing
      # ends is a launcher SIGKILLed mid-hook: its payload never starts, so the
      # session sits idle with nothing running in it until it is terminated,
      # which is a leftover and not a hazard. A limit here would buy only that,
      # and cost every hook slower than it.
      gate = pkgs.writeShellApplication {
        name = "flong-gate";
        runtimeInputs = [ pkgs.coreutils ];
        text = ''
          until [ -d /run/flong-ready ]; do
            sleep 0.005
          done
          exec "$@"
        '';
      };
      gateCmd = lib.optionalString steered (lib.getExe gate);

      postStopScript = mkPostStopScript name c;
    in
    pkgs.writeShellApplication {
      inherit name;
      runtimeInputs = [ pkgs.coreutils pkgs.gnused pkgs.util-linux pkgs.e2fsprogs ]
        ++ lib.optional (c.network != null) pkgs.passt
        ++ c.path;
      text = ''
        ${identityFrom}
        # WORKSPACE FIRST, THEN GUARD.
        #
        # The gate has to judge the thing that actually gets mounted. When it
        # ran first it saw only $PWD, so a `guard` that cared about a
        # directory had to re-derive it -- duplicating a security-critical
        # step in every consumer, and agreeing with what got mounted only for
        # as long as both kept running the same incantation. Override
        # `workspace` with a monorepo root or a superproject and the two come
        # apart silently, with nothing to fail.
        #
        # So `workspace` is resolved and validated first, and `guard` runs
        # with $workspace in scope. Guards that only look at $PWD are
        # unaffected. What this costs is that caller-controlled shell runs
        # before the gate -- but it runs AS the caller, in their own cwd, so
        # it buys them nothing they could not have run themselves.

        # A TERMINAL IN RAW MODE DOES NOT RETURN THE CARRIAGE. nspawn puts
        # the caller's terminal into raw mode for the session's console, and
        # the hooks run while it is: every line they print -- postStart's,
        # postStop's, this script's own -- would start where the last one
        # ended, stepping across the screen. So each line written to a
        # terminal ends in a carriage return as well; on a terminal that is
        # not raw, \r\n looks exactly as \n does. Not for a file or a pipe,
        # which gets what was written.
        if [ -t 2 ]; then
          exec {flong_stderr}>&2
          exec 2> >(sed -u 's/$/\r/' >&"$flong_stderr")
        fi

        # `workspace` is the only place this script touches attacker-shaped
        # input: it runs a shell -- a consumer's, which may well run git -- in
        # a directory the caller chose. Its answer is the caller's to give
        # either way, so there is nothing to buy by deriving it as root and a
        # whole class of git-in-a-hostile-checkout escalation to avoid.
        #
        # sudo sets SUDO_UID itself, so a caller cannot suppress it to get the
        # root path back; run0 sets it too and pkexec sets PKEXEC_UID. Root is
        # the fallback for a launcher started from a unit, where there is no
        # unprivileged caller to drop to.
        caller=''${SUDO_UID:-''${PKEXEC_UID:-}}

        # Captured because "$@" inside a function is the function's own
        # arguments, and every snippet must see the launcher's.
        launcher_args=("$@")

        # Sets the variable named $1 to the path $2 as nspawn's --bind, --tmpfs
        # and --overlay read one: ':' and '\' escaped with a backslash, and
        # every other character itself. See nspawnPath.
        nspawn_path() {
          local bs=\\ value=$2
          value=''${value//"$bs"/"$bs$bs"}
          printf -v "$1" '%s' "''${value//:/"$bs:"}"
        }

        # One way to run a caller's snippet, shared by `workspace` and
        # `binds`, so they cannot drift in how much privilege they get.
        #
        # The gid comes from the passwd database rather than from SUDO_GID,
        # which pkexec does not set -- and defaulting it to the uid is only
        # right on a machine where those happen to match.
        #
        # `flong "$@"` after the snippet, so it sees the launcher's arguments
        # in both branches. Without it the two disagree about $@ depending on
        # whether there was a caller to drop to, which is not a difference
        # anyone would guess.
        run_as_caller() {
          if [ -n "$caller" ]; then
            setpriv --reuid="$caller" --regid="$(id -g "$caller")" \
              --init-groups -- ${pkgs.bashNonInteractive}/bin/bash -euo pipefail \
              -c "$1" flong ''${launcher_args[@]+"''${launcher_args[@]}"}
          else
            ${pkgs.bashNonInteractive}/bin/bash -euo pipefail \
              -c "$1" flong ''${launcher_args[@]+"''${launcher_args[@]}"}
          fi
        }

        # shellcheck disable=SC2016  # a snippet is data for `bash -c`, so it
        # is quoted to survive THIS shell rather than to run in it. Applies to
        # both call sites.
        workspace=$(run_as_caller ${lib.escapeShellArg c.workspace}) || exit 1

        # A trailing `:ro` binds the workspace read-only; `:rw`, the default,
        # may be said out loud. A trailing mode is always a mode, which is
        # unambiguous because a caller's path may not hold a ':' -- see below.
        case $workspace in
          *:ro) workspace_mode=ro; workspace=''${workspace%:ro} ;;
          *:rw) workspace_mode=rw; workspace=''${workspace%:rw} ;;
          *) workspace_mode=rw ;;
        esac

        # Resolved before it is checked, so what gets validated is what gets
        # mounted -- and so that `guard` below judges the same canonical path
        # nspawn will be handed, rather than whatever spelling the caller
        # happened to use.
        workspace=$(realpath -e -- "$workspace") || exit 1
        # nspawn could mount any path. What refuses a ':' or a newline here is
        # flong's own format: a caller's path travels as PATH:MODE, one per
        # line -- in what its hook prints, and in $binds and FLONG_BINDS,
        # which a guard and a payload read -- and either character would make
        # that ambiguous to anything that splits it naively, a guard
        # included. WHICH directory is allowed remains `guard`'s business.
        nl='
'
        case $workspace in
          *:* | *"$nl"*)
            echo "${name}: workspace contains ':' or a newline: $workspace" >&2
            exit 1
            ;;
        esac
        [ -d "$workspace" ] || {
          echo "${name}: workspace is not a directory: $workspace" >&2
          exit 1
        }

        # The caller's binds, resolved with $workspace already in scope so a
        # snippet can answer "what travels with THIS directory" -- which is
        # the question a consumer pairing repositories is actually asking.
        # Exported rather than passed, because the snippet runs in a bash of
        # its own under setpriv and would not otherwise inherit it.
        export workspace workspace_mode

        # Each line is PATH, bound read-only, or PATH:rw; PATH:ro says the
        # default out loud. The same treatment $workspace gets, for the same
        # reasons: resolved first so what is validated is what is mounted,
        # then refused if it names what the PATH:MODE lists cannot carry.
        # Directories only, because they are the caller's working set, which
        # the payload is told about for an agent's --add-dir. Deciding WHICH
        # directories are allowed remains `guard`'s business.
        #
        # The result has the mode on every line, so a guard reading it sees
        # what it is granting without knowing the default.
        #
        # `exit 1` inside the function lands in the command substitution's
        # subshell, so the caller needs its own `|| exit 1` -- a failure here
        # must abort the launch, not mount a shorter list.
        resolve_binds() {
          local line p mode out=""
          while IFS= read -r line; do
            [ -n "$line" ] || continue
            case $line in
              *:rw) mode=rw; p=''${line%:rw} ;;
              *:ro) mode=ro; p=''${line%:ro} ;;
              *) mode=ro; p=$line ;;
            esac
            p=$(realpath -e -- "$p") || exit 1
            case $p in
              *:* | *"$nl"*)
                echo "${name}: bind names ':' or a newline: $p" >&2
                exit 1
                ;;
            esac
            [ -d "$p" ] || {
              echo "${name}: bind is not a directory: $p" >&2
              exit 1
            }
            out=$out$p:$mode$nl
          done <<< "$1"
          printf '%s' "$out"
        }

        # Two steps, so a snippet that fails aborts the launch: a command
        # substitution inside an argument has its status thrown away.
        # shellcheck disable=SC2016
        binds_raw=$(run_as_caller ${lib.escapeShellArg c.binds}) || exit 1
        binds=$(resolve_binds "$binds_raw") || exit 1

        # `guard` decides entitlement, so it stays root. A gate the caller can
        # ptrace or preload is not a gate, and dropping it would hand the
        # decision to the process it exists to refuse. It reads $workspace --
        # absolute, resolved, and already refused if it held anything nspawn
        # cannot express, which makes it the better-sanitised of the two
        # caller-shaped values in scope here. The other is $PWD.
        #
        # $workspace_mode is in scope, and so is $binds: PATH:ro and PATH:rw
        # lines, resolved the same way. A container that grants more than its
        # caller had must judge THOSE as well: they are mounts the caller
        # named, and a gate that reads only $workspace would let a second
        # directory in unexamined.
        #
        # A SUBSHELL, so the guard's `exit` is its verdict and nothing more:
        # `exit 0` lets the launch go on rather than ending the launcher
        # successfully with nothing launched, and an assignment to $workspace
        # -- or to anything else the launcher goes on to use -- dies with the
        # subshell rather than changing what gets mounted after it was
        # judged. Non-zero lands in `set -e` and ends the launch. The `:` keeps
        # the subshell well-formed for a guard that is empty or all comments.
        (
          :
          ${c.guard}
        )

        # passwd, group and shadow are written by the activation script, not
        # carried in the closure, so a root assembled from the store alone
        # cannot resolve a username. Keyed by the closure hash so a rebuilt
        # container gets a different cache rather than a stale one.
        prepared=${cache}/prepared
        if [ ! -e "$prepared/etc/passwd" ]; then
          mkdir -p ${cache}
          staging=$(mktemp -d "${cache}/.prepare.XXXXXX")
          ${prepareSteps}
          # Atomic, and the race resolution: a loser discards its copy.
          #
          # chattr first, because tmpfiles above has made part of this root
          # undeletable: NixOS declares `h /var/empty - - - - +i`, and a
          # directory carrying the immutable attribute refuses rm even as
          # root. Only here -- a session root is `cp -a`'d from this one, and
          # cp does not carry inode flags, so the two sweeps below face an
          # ordinary directory tree.
          mv -T "$staging" "$prepared" 2>/dev/null || {
            chattr -R -i "$staging" 2>/dev/null || true
            rm -rf "$staging"
          }
        fi

        # Who this session runs as, out of the root nspawn is about to resolve
        # --uid against. Everything the launcher creates for the payload out
        # here -- TMPDIR, the tmpfs entries, the overlay uppers -- is owned from
        # these, so they cannot disagree with what the container thinks.
        read_identity "$prepared"

        # A session that ended cleanly took its own root and nspawn's mounts
        # with it. A SIGKILLed one left all of it, and the unix-export tmpfs
        # among it is refused rather than reused: the next nspawn to draw that
        # machine name dies with "Mount point ... exists already, refusing." No
        # trap survives SIGKILL, so what is left is swept on the way in.
        #
        # LIVE SESSIONS ARE LEFT ALONE, NOT STOPPED. This runs inside somebody
        # else's launch, and a launcher that terminates its neighbours is worse
        # than a leftover: the session it would kill is doing the work it was
        # started for, and its own trap will clear up after it. So the sweep
        # only ever touches what nothing owns any more.
        #
        # Which makes the liveness test the whole of it. `systemd-run --scope`
        # makes the workload a child of the SCOPE, not of the launcher, so
        # SIGKILLing a launcher leaves the scope active, nspawn alive and the
        # payload running -- and reading /proc for the launcher pid in the name
        # called exactly that dead, and deleted a running session's root out
        # from under it. Measured, in flong's own invocation shape.
        #
        # The launcher pid is still asked, and first, for a window nothing else
        # covers: between `cp -a` and `systemd-run` there is a root on disk with
        # no scope and no registration behind it, and a concurrent sweep would
        # otherwise take a session that is starting.
        # EVERYTHING A SESSION LEAVES OUTSIDE ITSELF, RELEASED FROM ONE PLACE,
        # because it is released from two: the cleanup trap, for a session
        # whose launcher is still here to run it, and the sweep below, for one
        # whose launcher was SIGKILLed. Given the machine name and the cache
        # it ran from, because on the sweep's path that is all that is left:
        # the session's root and the record of its own teardown are both
        # named for the machine, in that cache.
        #
        # Tolerant throughout: a leftover that will not go costs the host a
        # directory, where an abort here costs the caller their session -- or,
        # in the trap, the payload's exit status.
        release_session() {
          local machine=$1 dir=$2 root record post_stop pasta_pid
          root=$dir/s-$machine
          record=$dir/poststop-$machine
          # The consumer's postStop first, while nothing of flong's has gone
          # yet. Only a store path is run: the record is written by root into a
          # root-owned directory, and it is still not the place to take a
          # command from.
          if [ -e "$record" ]; then
            post_stop=$(cat "$record")
            case $post_stop in
              /nix/store/*) ;;
              *) post_stop="" ;;
            esac
            if [ -n "$post_stop" ] && [ -x "$post_stop" ]; then
              "$post_stop" "$machine" || echo "${name}: postStop failed for $machine" >&2
            else
              echo "${name}: no teardown left to run for $machine" >&2
            fi
            rm -f "$record"
          fi
          # The namespace pin and the pasta behind it, whichever launcher made
          # them -- so this is not conditional on THIS launcher having a
          # network, since the session being released may not be its own.
          #
          # umount -l, THEN rm, and nothing less. A plain umount is "target is
          # busy" for as long as pasta lives -- measured, with the container
          # alive and after it had gone -- so the `umount ... || true` used
          # everywhere else here would leak it without a word, and a leaked pin
          # keeps a dead session's whole namespace alive for as long as the
          # host runs. Removing the file is what pasta watches for: it exits
          # about 60 ms later, "Namespace ... is gone".
          #
          # Signalled as well, so the release does not rest on a watch -- but
          # only once the pid has been shown to be that pasta, because on the
          # sweep's path the file may be far older than the process that
          # holds its number now.
          if [ -e "${pinDir}/$machine" ]; then
            umount -l "${pinDir}/$machine" 2>/dev/null || true
            rm -f "${pinDir}/$machine"
          fi
          if [ -e "${pinDir}/$machine.pid" ]; then
            pasta_pid=$(cat "${pinDir}/$machine.pid" 2>/dev/null) || pasta_pid=""
            # A whole argument, not a substring: netless-100-5 is a prefix of
            # netless-100-55.
            if [ -n "$pasta_pid" ] && tr '\0' '\n' 2>/dev/null < "/proc/$pasta_pid/cmdline" \
                | grep -qxF "${pinDir}/$machine"; then
              kill "$pasta_pid" 2>/dev/null || true
            fi
            rm -f "${pinDir}/$machine.pid"
          fi

          # /run/systemd/nspawn/<machine>/unix-export, which is where nspawn
          # puts it: runtime_directory_make(scope, "systemd/nspawn", machine)
          # and then "unix-export" joined inside. Looking for the pre-257
          # spelling, /run/systemd/nspawn/unix-export/<machine>, matched
          # nothing, so every killed session leaked its tmpfs. The mount tunnel
          # next to it leaks the same way. nspawn removes both on a clean exit,
          # and neither exists by the time a clean session's trap runs.
          umount "/run/systemd/nspawn/$machine/unix-export" 2>/dev/null || true
          rm -rf "$root" "/run/systemd/nspawn/$machine" \
            "/run/systemd/nspawn/propagate/$machine" || true
        }

        session_live() {
          local m=$1 owner
          # Starting, or running with its launcher still waiting on it.
          owner=''${m#${c.container}-}; owner=''${owner%%-*}
          [ -d "/proc/$owner" ] && return 0
          # Running, launcher or no launcher. The scope is named for the
          # machine, because --unit="$machine" is what created it.
          ${systemctl} is-active --quiet "$m.scope" && return 0
          # Belt and braces, and the one that answers for an nspawn that
          # outlived its scope: machined still knows the machine.
          ${machinectl} show "$m" >/dev/null 2>&1 && return 0
          return 1
        }

        # EVERY CACHE THIS CONTAINER HAS HAD, not just the one this launch
        # uses. The cache is keyed on the closure hash, so a nixos-rebuild
        # strands the previous generation's sessions in a directory that a sweep
        # of this launch's own cache never looks at again -- and once a leftover
        # is a namespace pin or a pasta process rather than 48K of tmpfs,
        # nothing else is going to notice it either.
        #
        # Both hashes are spelt out as ????????-????????, and not as a bare *,
        # so a container whose name is a prefix of another's -- `demo` and
        # `demo-two` -- cannot sweep its neighbour's caches.
        #
        # DELIBERATELY NOT LOCKED. A launcher from a superseded generation has
        # no s-* directory of its own between its check for `prepared` and its
        # `cp -a`, so a sweep landing in that window takes the root it was
        # about to copy. The copy then fails and `set -e` ends that one launch,
        # which is loud and costs the caller a retry. The fix would be a flock
        # held across prepare-and-copy in every launcher, and a lock in the
        # launch path is the worse trade for a tool that advertises 117 ms.
        for dir in /run/flong/${c.container}-????????-????????; do
          [ -d "$dir" ] || continue
          live=0
          for d in "$dir"/s-*; do
            [ -e "$d" ] || continue
            m=''${d##*/}; m=''${m#s-}
            if session_live "$m"; then live=1; continue; fi
            release_session "$m" "$dir"
          done
          # A superseded closure's cache with nothing of it still running: the
          # prepared root it was keyed on goes too, since no launcher will ever
          # ask for that root again.
          [ "$dir" = "${cache}" ] && continue
          [ "$live" = 0 ] || continue
          # chattr first, because prepare ran tmpfiles in there and NixOS
          # declares `h /var/empty - - - - +i`: an immutable directory refuses
          # rm even as root. Only the prepared root needs it -- a session root
          # is `cp -a`'d from one, and cp does not carry inode flags.
          chattr -R -i "$dir" 2>/dev/null || true
          rm -rf "$dir" || true
        done

        # Tell the terminal what it is looking at, the way toolbox and distrobox
        # do. VTE keeps vte.container.name, .runtime and .uid as termprops, so a
        # terminal that reads them can say "container" in its own chrome instead
        # of inferring it from a command line it happens to recognise -- which is
        # how a session that reached root through sudo gets coloured "privileged"
        # instead, a different and less accurate statement about where the typing
        # is going.
        #
        # ST-terminated, not BEL: OSC 666 is a vte-only sequence and rejects the
        # BEL form outright, silently. Written \033\134 rather than \033\\ only
        # because shellcheck reads the latter as an escaped quote.
        #
        # Only when stdout is a terminal: otherwise these bytes land in whatever
        # the caller redirected to. Reset in the trap below, so a launch that
        # fails does not leave a terminal claiming a container that is not there.
        if [ -t 1 ]; then
          printf '\033]666;vte.container.name=%s;vte.container.runtime=systemd-nspawn;vte.container.uid=%s\033\134' \
            ${lib.escapeShellArg c.container} "$uid"
        fi

        # Unique per invocation, not per workspace, so two sessions in one
        # directory do not collide either.
        machine=${c.container}-$$-''${RANDOM}
        root=${cache}/s-$machine
        cp -a "$prepared" "$root"
        ${lib.optionalString (c.postStop != "") ''
        # Which postStop is this session's, for whoever ends up releasing it.
        # Beside the root and not in it, since the root is the container's "/".
        # Written before anything a postStop would release can exist.
        echo ${postStopScript}/bin/flong-poststop-${name} > ${cache}/poststop-"$machine"
        ''}

        # An inherited TMPDIR names a host path that is absent or root-owned in
        # there, so the payload gets one of its own. Made out here, in the
        # session's root, because nothing inside the container is ever root:
        # the launcher is the only privileged thing in a session, and it is on
        # this side of nspawn.
        mkdir -p "$root$home/tmp"
        chown "$uid:$gid" "$root$home/tmp"
        chmod 0700 "$root$home/tmp"

        # THE WAY TO A MOUNT POINT IS THE PAYLOAD'S, INSIDE ITS HOME. A mount
        # whose parent the root does not have gets one made for it -- by
        # nspawn for a bind, by this launcher for the rest -- and made as
        # root, so a bind at ~/.cache/tool/data left ~/.cache/tool, and
        # ~/.cache if that was missing too, where the payload could write
        # nothing: every program keeping state beside the bound directory was
        # refused. Each directory missing on the way is made here instead, in
        # the session's root, and inside $home given to the payload. It is
        # the session's own and goes with it, as the root does. Outside $home
        # nothing changes: root's there is the container's to decide.
        #
        # Component by component, and never through a symlink: this runs as
        # root on the host side of nspawn, where a link in the root resolves
        # against the host's filesystem. Meeting one is a failure, and each
        # caller says what that means.
        make_dirs() {
          local cur part
          case $1/ in
            "$home"/*) ;;
            *) return 0 ;;
          esac
          cur=$root$home
          IFS=/ read -ra parts <<< "''${1#"$home"}"
          for part in "''${parts[@]}"; do
            [ -n "$part" ] || continue
            cur=$cur/$part
            if [ -L "$cur" ]; then
              return 1
            elif [ ! -e "$cur" ]; then
              mkdir "$cur"
              chown "$uid:$gid" "$cur"
            fi
          done
        }
        # A tmpfs or an overlay: this launcher makes its mount point, so a
        # symlink on the way ends the launch -- `mkdir -p` would follow it out
        # of the root. Outside $home, as before: the root is the closure's.
        make_mount_point() {
          make_dirs "$1" || {
            echo "${name}: a symlink in the session root is on the way to $1" >&2
            # Before the cleanup trap is armed, so released here.
            release_session "$machine" ${cache}
            exit 1
          }
          mkdir -p "$root$1"
        }
        # A bind's parents. nspawn makes its mount point, resolving inside the
        # root, so a symlink here only means those are left to nspawn.
        for path in ${lib.escapeShellArgs declaredMountPoints}; do
          make_dirs "''${path%/*}" || true
        done
        ${mountpointMkdirs}
        overlay_flags=()
        ${lib.optionalString (c.overlays != { }) ''
        root_nspawn=""
        nspawn_path root_nspawn "$root"
        ${overlayFlags}
        ''}
        ${lib.optionalString (c.network != null) ''
        # A NETWORKED SESSION'S RESOLVER IS PASTA, and this is the file that
        # says so. Written into the session's copy of the root, so nothing of
        # the host's is touched, and before nspawn, which is told
        # --resolv-conf=off rather than left to arrive there from `auto`.
        #
        # One synthetic nameserver per family the host's resolv.conf names a
        # nameserver in, in the host's order, each with its --dns-forward.
        # pasta sends a family's queries to the host's first nameserver of
        # that family, and for a family with none it has only the unspecified
        # address to send them to -- which Linux, asked to connect there,
        # takes as its own loopback. Measured, with a host naming 127.0.0.1
        # alone and 100::1 forwarded anyway: a TCP query to 100::1 was
        # answered by the resolver on the host's ::1, a port `hostPorts` never
        # named, and the same the other way round; UDP timed out. So a family
        # pasta has nowhere to send is neither forwarded nor listed. `search`, `domain` and `options` come
        # across as they are, so a short name means in here what it means
        # out there.
        #
        # Read once, here, as pasta reads it once a moment later: a host that
        # moves networks keeps a live session on the old resolver.
        dns_forward=()
        forward4="" forward6=""
        resolv_conf="# flong: pasta forwards queries sent here to the host's resolver.$nl"
        while read -r key value rest || [ -n "$key" ]; do
          case $key in
            nameserver)
              case $value in
                *:*) [ -z "$forward6" ] || continue; forward6=${dnsForward6}; ns=$forward6 ;;
                *.*) [ -z "$forward4" ] || continue; forward4=${dnsForward4}; ns=$forward4 ;;
                *) continue ;;
              esac
              dns_forward+=(--dns-forward "$ns")
              resolv_conf+="nameserver $ns$nl"
              ;;
            search | domain | options)
              resolv_conf+="$key $value''${rest:+ $rest}$nl"
              ;;
          esac
        done < <(cat /etc/resolv.conf 2>/dev/null || true)
        rm -f "$root/etc/resolv.conf"
        printf '%s' "$resolv_conf" > "$root/etc/resolv.conf"
        chmod 0644 "$root/etc/resolv.conf"
        ''}

        # A bare --tmpfs mounts root-owned 0755, which the unprivileged payload
        # cannot write to -- and fails quietly on, most programs treating an
        # unwritable cache as a missing one. So each entry is given the payload's
        # ownership unless it names options of its own as PATH:opts.
        #
        # /run/user/$uid is one of these whether it was asked for or not:
        # XDG_RUNTIME_DIR names it, /run is nspawn's own tmpfs made fresh at
        # every start, and nothing inside a session can create a directory in
        # it. Skipped if the declaration's `tmpfs` already names that path, so
        # its options remain the declaration's to override.
        #
        # nspawn creates the mount point for a --tmpfs, but a mkdir here as well
        # keeps a nested bind -- a socket carved out of a masked runtime
        # directory -- from depending on which of the two nspawn makes first.
        tmpfs_paths=(${lib.escapeShellArgs (map (e: e.path) tmpfsEntries)})
        tmpfs_options=(${lib.escapeShellArgs (map (e: e.options) tmpfsEntries)})
        tmpfs_flags=()
        path_nspawn=""
        runtime_dir=/run/user/$uid
        want_runtime_dir=1
        for i in "''${!tmpfs_paths[@]}"; do
          path=''${tmpfs_paths[i]}
          options=''${tmpfs_options[i]}
          [ "$path" = "$runtime_dir" ] && want_runtime_dir=0
          nspawn_path path_nspawn "$path"
          tmpfs_flags+=("--tmpfs=$path_nspawn:''${options:-mode=0755,uid=$uid,gid=$gid}")
          make_mount_point "$path"
        done
        if [ "$want_runtime_dir" = 1 ]; then
          tmpfs_flags+=("--tmpfs=$runtime_dir:mode=0700,uid=$uid,gid=$gid")
          mkdir -p "$root$runtime_dir"
        fi

        ${lib.optionalString steered ''
        # Set before the trap is armed rather than beside the launch, because
        # the trap runs for every exit after this line and reads it.
        ready=0
        ''}

        # NOT exec: that would replace the shell and discard the trap with it.
        # shellcheck disable=SC2329  # invoked by the trap, not by name.
        cleanup() {
          if [ -t 1 ]; then
            printf '\033]666;vte.container.\033\134'
          fi
          ${lib.optionalString steered ''
          # A SESSION WHOSE HOOK NEVER FINISHED MUST NOT BE LEFT RUNNING.
          # `postStart` is the whole security property, and it is an ordering:
          # what it installs is in place before anything gives the namespace
          # egress.
          # A session that gets past it without it -- a hook that exited
          # non-zero, a leader that never appeared, a launcher killed in
          # between -- is a session with nothing installed and nothing left to
          # install it, so it goes; and so is one whose network was asked for
          # and not attached, which is broken rather than unsafe but has no
          # business carrying on as if it worked.
          if [ "$ready" = 0 ]; then
            ${systemctl} kill -s KILL "$machine.scope" 2>/dev/null || true
          fi
          ''}
          # THE LAUNCHER OWNS ITS SESSION, so a launcher asked to stop -- SIGTERM,
          # SIGINT, SIGHUP, anything bash still gets to run this trap for --
          # stops the session FIRST, and waits for it, and only then releases
          # what the session depends on. Releasing first ran `postStop`, pulled
          # the network pin and deleted the root under a session that was still
          # running. On the ordinary path the payload has already exited and
          # been waited for, $session is empty, and there is nothing to stop.
          #
          # The scope is stopped, and nspawn is signalled as well: $session is
          # systemd-run until it has registered the scope and exec'd nspawn, so
          # a signal in that window finds no scope to stop. SIGKILL runs no
          # trap at all, and a session outliving its launcher that way is left
          # to its own devices and then to the sweep, which does not stop live
          # sessions -- that part is unchanged.
          if [ -n "''${session:-}" ]; then
            ${systemctl} stop "$machine.scope" 2>/dev/null || true
            kill -TERM "$session" 2>/dev/null || true
            wait "$session" 2>/dev/null || true
          fi
          release_session "$machine" ${cache}
        }
        trap cleanup EXIT
        # Explicitly, rather than trusting bash to run the EXIT trap from inside
        # its fatal-signal handler: trapped, a signal interrupts `wait` and the
        # trap above runs as ordinary code, with the usual 128+n status.
        trap 'exit 129' HUP
        trap 'exit 130' INT
        trap 'exit 143' TERM

        # The declaration's binds and extraFlags, one argument each.
        declared_flags=(${lib.escapeShellArgs declaredFlags})
        mask_flags=(${lib.escapeShellArgs maskFlags})

        # The binds computed at launch, in an array for the same reason:
        # these are runtime values, and word-splitting a path is how a
        # directory with a space in it becomes two broken mounts.
        bind_flags=()
        # MODE PATH, bound at its own path.
        add_bind() {
          local flag path=""
          case $1 in
            ro) flag=--bind-ro ;;
            rw) flag=--bind ;;
            *)
              echo "${name}: a bind's mode is neither ro nor rw: $1" >&2
              exit 1
              ;;
          esac
          make_dirs "''${2%/*}" || true
          nspawn_path path "$2"
          bind_flags+=("$flag=$path:$path")
        }
        add_bind "$workspace_mode" "$workspace"
        while IFS= read -r b; do
          [ -n "$b" ] || continue
          add_bind "''${b##*:}" "''${b%:*}"
        done <<< "$binds"

        # --keep-unit, or nspawn makes a scope of its own and these properties
        # apply to nothing. tini rather than --as-pid2, whose stub reaps
        # orphans but does not forward SIGTERM to the payload.
        #
        # --uid, so nspawn drops before it starts pid 1: tini, the payload
        # script and `command` with it all run as `user`, and no process
        # inside the container is ever root. It resolves the name against the
        # container's own passwd -- which is what preparing the root produces
        # -- and initialises the supplementary groups from its group file, so
        # a user declared into `audio` arrives in it.
        #
        # --uid where the host's systemd has it (261 and later, which
        # deprecates --user and warns about it on every launch), --user where
        # it does not: the launcher runs the HOST'S nspawn, so the flag has to
        # be the host's. Chosen at evaluation from config.systemd.package, the
        # package that nspawn comes from -- no probe at launch. A 260 host
        # given --uid refuses to start a session at all ("unrecognized option
        # '--uid=…'"), which is how this was found, on nixos-26.05. Both
        # spellings resolve a name the same way: nspawn execs `getent passwd` INSIDE the container root, so a
        # prepared root that cannot run getent cannot name its user. flong
        # satisfies that today only through --bind-ro=$closure:/run/current-system
        # and a PATH naming /run/current-system/sw/bin -- accidental, and a hard
        # failure the day a closure stops carrying one.
        #
        # /run is nspawn's own tmpfs, made fresh at every start, so the
        # symlink `activate` wrote when the root was prepared is already gone,
        # and every search path the system exports is relative to it. The
        # closure is bound over the mount point nspawn makes for it rather
        # than a symlink being written from inside, which nothing unprivileged
        # could do.
        #
        # machine.slice, where the container@ unit would have put it, so a
        # limit set on the slice reaches every session and `systemd-cgls
        # machine.slice` shows what is running. --slice on nspawn itself is
        # ignored under --keep-unit, so it belongs on the scope.
        #
        # --console=autopipe, because the default is `interactive` from a
        # terminal and `read-only` otherwise -- and read-only propagates output
        # while never reading input, so a launcher in a pipeline or a script
        # gets an empty stdin and no indication of it. autopipe keeps the pty
        # whenever there is a terminal on stdin to keep it for, and otherwise
        # passes the descriptors straight through, which is what makes `echo
        # prompt | launcher` mean what it says. The cost is that in the second
        # case the payload holds the caller's own stdout and stderr rather than
        # a pty, so a session can write escape sequences at a terminal it is
        # sharing -- no more than any program the caller runs themselves, and
        # the price of a pipeline working at all.
        #
        # --hostname, because the machine name carries a pid and a random
        # number to keep concurrent sessions apart, and nspawn would otherwise
        # use it as the hostname -- so a session would see a different hostname
        # every time, where a declared container sees networking.hostName.
        #
        # STARTED IN THE BACKGROUND, AND WAITED FOR AT THE END. The launcher
        # used to block here for the whole session, which left no moment in
        # which to touch the namespace nspawn had just made -- and that moment
        # is precisely what `postStart` needs: after the namespace exists, before
        # the workload can reach anything through it.
        #
        # stdin is handed over explicitly because bash gives an asynchronous
        # command /dev/null for stdin "in the absence of any explicit
        # redirections", which would silently empty `echo prompt | launcher` --
        # the case --console=autopipe is here for.
        #
        # --expand-environment=no, because systemd-run otherwise expands
        # "$NAME" and "''${NAME}" in the command it is given, as ExecStart=
        # does -- under --scope too, in systemd 261, where systemd-run does it
        # itself, against the LAUNCHER's environment, which is root's. Every
        # argument here is data: measured, a launcher argument of
        # `$(touch ...)` did not reach the payload at all, and a `$HOME` would
        # have arrived as root's home. A workspace or bind path holding a `$`
        # is on this command line too.
        #
        # A script has no job control, so `&` does not put this in a process
        # group of its own: nspawn stays in the launcher's, which is the
        # terminal's foreground group, so an interactive session still reads
        # the keyboard instead of stopping on SIGTTIN.
        exec 3<&0
        ${systemdRun} --scope --quiet --expand-environment=no \
          --unit="$machine" --slice=machine.slice \
          --property=DevicePolicy=closed ${deviceProps} ${scopeProps} -- \
          ${nspawn} -q --keep-unit --directory="$root" --machine="$machine" \
            --hostname=${lib.escapeShellArg c.container} \
            --console=autopipe \
            ${networkFlags} ${resolvConfFlag} ${capabilityFlags} \
            --kill-signal=SIGTERM \
            --bind-ro=/nix/store --bind-ro=/nix/var/nix/db \
            --bind-ro=${closure}:/run/current-system \
            ''${declared_flags[@]+"''${declared_flags[@]}"} \
            ''${bind_flags[@]+"''${bind_flags[@]}"} \
            ''${tmpfs_flags[@]+"''${tmpfs_flags[@]}"} \
            ''${overlay_flags[@]+"''${overlay_flags[@]}"} \
            ''${mask_flags[@]+"''${mask_flags[@]}"} \
            ${uidFlag}=${c.user} \
            --setenv=PATH=${closure}/sw/bin \
            --setenv=TMPDIR="$home/tmp" \
            --setenv=XDG_RUNTIME_DIR="$runtime_dir" \
            --setenv=FLONG_BINDS="$binds" \
            ${pkgs.tini}/bin/tini -g -- ${gateCmd} \
            ${lib.getExe payload} "$workspace" "$@" <&3 &
        session=$!

        ${lib.optionalString steered ''
        # THE LEADER IS POLLED FOR, NOT ASSUMED. systemd-run returns as soon as
        # the scope is started, which is before nspawn has unshared anything:
        # measured, a leader appears 26-30 ms after it returns, against a
        # payload that starts at 58-65 ms. Reading once and giving up would
        # therefore fail most of the time, and reading once and trusting the
        # answer would hand the hook the pid of something that is not in a
        # namespace of its own yet.
        #
        # Which is why both answers are checked the same way rather than
        # trusted: the leader is pid 1 of a pid namespace one level below the
        # launcher's own, which NSpid in /proc/<pid>/status spells out -- the
        # pid at every level from this one down.
        #
        # Not "a pid whose net namespace is not the host's", which is the test
        # that suggests itself: a container without privateNetwork shares the
        # host's, so that would find no leader at all there. And not "any pid
        # in a namespace of its own" either: the payload is one too, and a
        # workload that runs `unshare -Upf` makes a namespace of its own whose
        # pid 1 is two levels down, not one. A hook handed THAT pid would
        # steer a namespace the workload built for the purpose.
        own_depth=$(grep '^NSpid:' /proc/self/status)
        read -ra own_ids <<< "''${own_depth#NSpid:}"
        own_depth=''${#own_ids[@]}
        is_leader() {
          local line ids
          [ -n "''${1:-}" ] || return 1
          line=$(grep '^NSpid:' "/proc/$1/status" 2>/dev/null) || return 1
          read -ra ids <<< "''${line#NSpid:}"
          [ "''${#ids[@]}" -eq "$((own_depth + 1))" ] && [ "''${ids[-1]}" = 1 ]
        }

        # machinectl is the primary: nspawn registers its own leader with
        # machined, so there is nothing to derive. The cgroup walk behind it
        # answers for the window before that registration lands, and it has to
        # RECURSE -- under --keep-unit the scope's own cgroup.procs is EMPTY,
        # because nspawn puts its supervisor in supervisor/ and pid 1 in
        # payload/, so a reader of the scope's own file finds nothing at all and
        # concludes there is no session.
        find_leader() {
          local pid cg f seen=0 try
          for ((try = 0; try < 1000; try++)); do
            pid=$(${machinectl} show "$machine" --property=Leader --value 2>/dev/null) || pid=""
            if is_leader "$pid"; then printf '%s' "$pid"; return 0; fi
            cg=$(${systemctl} show --property=ControlGroup --value "$machine.scope" 2>/dev/null) || cg=""
            if [ -n "$cg" ]; then
              seen=1
              for f in "/sys/fs/cgroup$cg"/cgroup.procs \
                       "/sys/fs/cgroup$cg"/*/cgroup.procs \
                       "/sys/fs/cgroup$cg"/*/*/cgroup.procs; do
                [ -e "$f" ] || continue
                while IFS= read -r pid; do
                  if is_leader "$pid"; then
                    printf '%s' "$pid"; return 0
                  fi
                done < "$f"
              done
            elif [ "$seen" = 1 ]; then
              # The scope was there and is not any more: a session that failed
              # to start, rather than one still starting. Waiting out the rest
              # of the timeout would only make the failure slower.
              return 1
            fi
            sleep 0.005
          done
          return 1
        }

        leader=$(find_leader) || {
          echo "${name}: $machine started no namespace to attach to" >&2
          exit 1
        }
        netns=/proc/$leader/ns/net
        # Exported for the reason $workspace is: a hook that reaches for a
        # helper rather than doing the work inline needs them in its
        # environment, and which of the two it wants is its business. nspawn
        # passes only what --setenv names, so this reaches the host side and
        # stops there.
        export leader netns

        # THE HOOK, AND THE ORDERING THAT IS ITS WHOLE POINT. Whatever this
        # installs into the namespace is in place before anything provisions
        # egress: with --private-network the namespace has `lo` up and an empty
        # route table, so until egress exists the workload has nowhere to go and
        # nothing to race. Everything flong attaches itself -- pasta, for one --
        # is attached after this returns, and a consumer that provisions egress
        # of its own before installing anything has given the property away.
        ${lib.optionalString (c.postStart != "") ''
        # A subshell, so that the hook's own `exit` is the hook's verdict and
        # not the launcher's: `exit 0` ends the hook rather than skipping
        # straight past the wait below, and anything non-zero lands in the trap
        # through `set -e`, which kills the scope because $ready is still 0.
        (
          :
          ${c.postStart}
        )
        ''}
        ${lib.optionalString (c.network != null) ''
        # PASTA, AND ONLY NOW. This is the egress, so it is attached after the
        # hook and never before: until this line the namespace has `lo` and an
        # empty route table, and whatever the hook installed is in place before
        # there is anywhere for the workload to go.
        #
        # Through a pin, because pasta cannot attach by pid as root: it drops
        # to `nobody` in isolate_user() before pasta_open_ns() calls setns(),
        # and never sets PR_SET_KEEPCAPS, so every by-pid form fails with
        # "Permission denied" -- measured, in this invocation shape. A
        # bind-mounted namespace plus --runas 0 is the form that works, and a
        # pin is also what pasta watches: when it goes, pasta goes.
        #
        # --no-map-gw, because otherwise the gateway address IS the host's
        # loopback -- measured: a listener on 127.0.0.1:18123 answered from
        # inside with every port list set to none. --config-net, so pasta
        # addresses and routes the namespace itself; nothing inside could.
        #
        # --dns-forward, for each family the session's resolv.conf names --
        # see where that was written.
        #
        # pasta forks once it is ready and its parent exits 0, having written
        # the daemon's pid -- so this returns when there is a network, and
        # leaves a pid the release can check before it signals.
        pin=${pinDir}/$machine
        mkdir -p ${pinDir}
        touch "$pin"
        mount --bind "$netns" "$pin"
        pasta --quiet --config-net --netns "$pin" --runas 0 --pid "$pin.pid" \
          ${lib.concatStringsSep " " (pastaPortArgs c.network)} --no-map-gw \
          ''${dns_forward[@]+"''${dns_forward[@]}"}
        ''}

        # The payload is waiting on this. Through the leader's own root, since
        # the /run it names is the session's and not the host's.
        #
        # MKDIR, AND NEVER TOUCH. Whatever is walked beneath /proc/<pid>/root
        # is the session's, and an ABSOLUTE symlink met on that walk resolves
        # against the CALLER's root -- so a /run/flong-ready planted as
        # `-> /etc/something` would have root on the host create or touch that
        # host path: the class of runc's /proc/self/exe escape. Today nothing
        # in a session can write /run, since it is nspawn's root-owned tmpfs;
        # this does not lean on that staying true. mkdir never follows its
        # final component and fails with EEXIST on anything already there, a
        # dangling symlink included -- and a failure here fails the launch, and
        # the trap kills the session, rather than carrying on without a marker.
        mkdir "/proc/$leader/root/run/flong-ready" || {
          echo "${name}: could not mark $machine ready; something is already at /run/flong-ready" >&2
          exit 1
        }
        ready=1
        ''}

        rc=0
        wait "$session" || rc=$?
        # Waited for, so the trap has nothing to stop -- and a reaped pid is not
        # one to go signalling, since its number can now belong to anyone.
        session=""
        exit "$rc"
      '';
    };
in
{
  options.flong = lib.mkOption {
    default = { };
    description = ''
      Ephemeral systemd-nspawn containers that run one foreground process,
      started from a root prepared once per boot rather than booted per
      session.

      Each entry drives an existing `containers.<name>` declaration, using it
      only as a closure builder; the `container@` unit it installs is never
      started.
    '';
    type = lib.types.attrsOf (lib.types.submodule ({ name, config, ... }: {
      options = {
        container = lib.mkOption {
          type = lib.types.str;
          default = name;
          description = ''
            The `containers.<name>` declaration this runs: its closure,
            `bindMounts`, `tmpfs`, `extraFlags`, `allowedDevices` and network
            isolation, read as option values.
          '';
        };

        engine = lib.mkOption {
          type = lib.types.enum [ "nspawn" "rootless" ];
          default = "nspawn";
          description = ''
            Which engine runs this declaration's sessions. Temporary: the
            option goes when the nspawn engine does.

            `nspawn`, the default, is systemd-nspawn run as root. `rootless`
            runs as the calling user through flong-launch and bubblewrap, in
            user namespaces the caller owns, with no sudo and no root
            anywhere.

            Its wrapper's checks -- `workspace`, `binds`, `guard`, the depth
            rule -- are consistency checks, not a boundary: the caller can
            run flong-launch directly with any spec. The launcher's own
            checks and the session's `seccomp` filter are the boundary
            against the payload, and the prepared root and the records are
            the caller's, as their `~/.bashrc` is.

            Stop a declaration's running sessions before switching its engine.
            An nspawn session's postStop record and network pin under
            /run/flong are swept only by an nspawn launcher of the same
            container.
          '';
        };

        user = lib.mkOption {
          type = lib.types.str;
          description = ''
            User inside the container. nspawn drops to it before it starts
            pid 1, so everything in the session runs as this user.

            The only half of the identity worth declaring: the uid, the gid and
            the home are facts about that account, and are read at launch out of
            the container's own `/etc/passwd` -- the file nspawn resolves this
            name against. So there is nothing to keep in step, and nothing an
            unset `users.users.<name>.uid` or a container declared by `path`
            could hide from an assertion.

            Under `engine = "rootless"` the user's uid and the gid of its
            primary group must be declared in the container's `config`, and
            the container cannot be declared by `path`: they name the
            prepared root's cache and the caller's id maps, which are needed
            before anything is prepared. The launch refuses a prepared
            `/etc/passwd` that disagrees, and the home still comes from it.
            The uid need not be the caller's: the session's user is mapped
            onto the caller whatever its uid.
          '';
        };

        workspace = lib.mkOption {
          type = lib.types.lines;
          default = "pwd";
          example = ''git -C "$PWD" rev-parse --show-toplevel'';
          description = ''
            Shell printing the directory to bind into the container at its own
            path and start in: `PATH`, bound read-write, or `PATH:ro`, bound
            read-only. The default is the directory the launcher was started
            in; a consumer that wants a repository's root asks git for it. Runs on the host before launch, with the launcher's
            arguments in "$@"; a non-zero exit aborts.

            Runs *before* `guard`, so that the gate can judge the directory
            this resolves to rather than re-deriving one of its own.

            Runs as the *invoking* user rather than as root -- it reads a
            directory the caller chose, which is the one piece of
            attacker-shaped input the launcher handles, and its answer is the
            caller's to give either way. Root only when there is no
            unprivileged caller to drop to, as when a unit starts the
            launcher directly. Under `engine = "rootless"` everything runs as
            the caller, so there is nothing to drop from.

            What it prints is resolved with `realpath`, must be a directory,
            and is refused if it names a `:` or a newline: a caller's path
            travels as `PATH:MODE` lines, which either would make ambiguous.
            Later hooks see the path as `$workspace` and the mode as
            `$workspace_mode` (`ro` or `rw`). Deciding *which* directory is
            allowed is `guard`'s job, not this one's.
          '';
        };

        binds = lib.mkOption {
          type = lib.types.lines;
          default = "";
          example = ''
            printf '%s:rw\n' "$workspace/../shared-crates"
            printf '%s\n' /srv/reference
          '';
          description = ''
            Shell printing more of the caller's directories to bind, one per
            line, each at its own path inside the container: `PATH`, bound
            read-only, or `PATH:rw`, bound read-write. Empty output binds
            nothing, which is the default.

            Runs after `workspace`, with `$workspace` and `$workspace_mode`
            exported, so it can answer "what travels with THIS directory"
            rather than having to name a fixed set. Runs as the invoking user
            and sees the launcher's arguments in "$@", exactly as `workspace`
            does; a non-zero exit aborts.

            Every path is resolved with `realpath`, must be a directory, and is
            refused if it names a `:` or a newline, as the workspace is.
            Deciding *which* directories are allowed is `guard`'s job: it sees
            them as `$binds`, one `PATH:ro` or `PATH:rw` per line, with the
            mode always spelt out. The payload sees the same list as
            `$FLONG_BINDS`, to pass on to an agent's `--add-dir`.

            Read-only is not a boundary on its own -- it stops writes, not
            execution -- so it is for directories a session should read rather
            than edit, not for making an untrusted one safe.
          '';
        };

        guard = lib.mkOption {
          type = lib.types.lines;
          default = "";
          description = ''
            Shell run on the host before launch, to establish that this
            launcher is entitled to run. Needed whenever the container grants
            more than its caller already had: the launcher runs as root, and
            whatever you put in front of it is reachable directly by anyone
            who can run it, so a wrapper is a convenience rather than a gate.

            Runs as root, unlike `workspace`, and deliberately: this is the
            gate, and a gate the caller could ptrace or preload would be
            handing the decision to the process it exists to refuse.

            Runs *after* `workspace` and `binds`, with their answers in scope:
            `$workspace`, absolute and symlink-resolved, `$workspace_mode`,
            and `$binds`, one `PATH:ro` or `PATH:rw` per line. Judge those
            rather than re-deriving a directory from `$PWD` -- they are
            exactly what will be bound, where anything a guard works out for
            itself agrees with the mounts only by coincidence.

            Runs in a subshell, so a non-zero exit refuses the launch, `exit 0`
            allows it, and nothing the guard assigns reaches the launcher: it
            judges `$workspace` and cannot change it.

            Under `engine = "rootless"` it runs as the caller, and it is a
            consistency check, not a gate: the session grants nothing the
            caller did not already have, and the caller can run flong-launch
            directly with any spec. It runs again when the launcher relaunches
            itself, which it does when the prepared root it found was swept
            before it could lock it, so a guard that asks a question can ask
            it twice.
          '';
        };

        command = lib.mkOption {
          type = lib.types.nonEmptyListOf lib.types.str;
          example = lib.literalExpression ''[ (lib.getExe pkgs.hello) "--greeting=hello from a session" ]'';
          description = ''
            The payload, as an argument list: the program, then its fixed
            arguments. The launcher's own arguments are appended, and it is
            exec'd as `user` in the workspace. No element of either list is
            read by a shell, so a space, a `;` or a `$` in one is passed as it
            is.

            It is exec'd after the container's `/etc/set-environment` has been
            sourced, so a bare name is looked up on the container's `PATH` --
            its `environment.systemPackages`, the user's `packages` -- and
            the payload inherits every variable the container exports. An
            absolute path, such as `lib.getExe` of a package, is run as it
            is. Anything that needs a script is a package of its own, named
            here by `lib.getExe`.
          '';
        };

        postStart = lib.mkOption {
          type = lib.types.lines;
          default = "";
          example = ''
            nsenter --net="$netns" nft -f /etc/my-ruleset.nft
          '';
          description = ''
            Shell run on the host as root, once per session, as soon as the
            session's namespaces exist -- **before** `network` is attached and
            **before** the payload starts. The payload waits for it.

            `$leader` is the session's pid 1 as seen from the host and `$netns`
            its network namespace (`/proc/$leader/ns/net`), both exported.
            `$machine`, `$root`, `$uid`, `$gid`, `$home`, `$workspace`,
            `$workspace_mode` and `$binds` are in scope too. Without
            `privateNetwork` a session shares the host's network namespace,
            and `$netns` names *that*: a hook that installs a ruleset there is
            steering the host.

            **The ordering is the contract, and it is the security property.**
            Whatever this installs into the namespace is in place before
            anything gives it egress: a `privateNetwork` namespace starts with
            `lo` up and an empty route table, so until egress exists the
            workload has nowhere to go and there is no window to race. flong
            attaches `network` only after this returns. A consumer that
            provisions egress of its own first -- from `guard`, or from the top
            of this hook -- has given the property away without any error.

            A non-zero exit ends the session: the scope is killed and the
            launcher exits non-zero. So does a leader that never appears.
            Runs in a subshell, so `exit 0` ends this hook and not the launch.

            Unlike systemd's `ExecStartPost`, the main process is not yet
            running: it is held until this hook and any `network` have
            finished.

            Under `engine = "rootless"` it is a program of its own, run by the
            launcher as the caller, with `path` on `PATH` and the launcher's
            arguments in "$@". `$leader`, `$machine`, `$uid`, `$gid`, `$home`,
            `$workspace`, `$workspace_mode` and `$binds` are exported as
            above, and so is `$userns`, the session's user namespace. `$netns`
            is `/proc/<launcher>/fd/<n>`, a descriptor the launcher holds,
            and not `/proc/$leader/ns/net`. There is no `$root`: the session's
            root exists only in its own mount namespace, reached as
            `/proc/$leader/root`, and a hook that names `$root` fails. The
            hook enters the session as its root, with every capability over
            it and none over the host:
            `nsenter --user="$userns" --net="$netns" nft -f ruleset.nft`.
          '';
        };

        postStop = lib.mkOption {
          type = lib.types.lines;
          default = "";
          example = ''rm -f "/run/my-gate/$machine.sock"'';
          description = ''
            Shell run on the host as root after a session ends, to release
            whatever `postStart` made outside it. `$machine` is set,
            exported, and nothing else is.

            It runs on two paths: from the launcher's exit trap once the
            session has stopped, and -- for a session whose launcher was
            SIGKILLed -- from the sweep of a later launch of the same
            container, where the machine name is all that survives. Each
            session records its own `postStop`, so the sweep runs the one
            belonging to the session it releases, even when another launcher
            or a rebuilt one does the sweeping.

            So it must depend on `$machine` alone and succeed when what it
            releases is already gone. It runs under `set -euo pipefail` with
            `path` on `PATH`; a non-zero exit is reported and otherwise
            ignored, because flong's own release follows it.

            Under `engine = "rootless"` it runs as the caller, and a killed
            launcher's session is released by the caller's holder unit
            within moments, rather than at the next launch.
          '';
        };

        network = lib.mkOption {
          default = null;
          example = lib.literalExpression ''
            {
              hostPorts = [ 5432 ];
              forwardPorts = [ { hostPort = 8080; containerPort = 80; } ];
            }
          '';
          description = ''
            A real network for a `privateNetwork` session, provided by
            [pasta](https://passt.top): present or absent, with no `enable` --
            `network = { };` is a session that can reach the outside world and
            no port on the host. Requires
            `containers.<name>.privateNetwork = true`.

            pasta rather than a veth, because flong runs many concurrent
            sessions from one declaration: a veth needs an address per session,
            forwarding, NAT and host firewall rules, and gives the sandbox
            packet-level access to spoof with. pasta needs no host interface
            and no host configuration, and hands the sandbox sockets rather than
            packets.

            Attached after `postStart` returns, never before, which is what
            makes the hook's ordering hold. A session with a network also has a
            namespace pin under /run/flong/netns and a pasta process outside
            its scope, both released by the cleanup trap and, for a killed
            session, by the next launch's sweep. A session without one has
            neither.

            Always passed, and not options: `--no-map-gw`, because otherwise
            the gateway address reaches the host's loopback; an explicit
            `none` for every port class not listed here, because each defaults
            to `auto`, which forwards every bound port on the other side; and
            `--config-net`. A hooked session's capability flags apply here too.

            DNS goes through pasta as well, and is not an option either. The
            session's /etc/resolv.conf is written at launch naming
            ${dnsForward4} -- and ${dnsForward6}, where the host names an IPv6
            nameserver -- with the host's `search`, `domain` and `options`
            carried over. pasta catches a query sent there and re-sends it
            from the host to the host's own first nameserver, so a stub
            resolver on the host's loopback answers it. Both read the host's
            file once, at launch: a host that moves networks keeps a live
            session on the old resolver.

            Under `engine = "rootless"` pasta runs as the caller, so a fixed
            `forwardPorts` host port below the host's
            `net.ipv4.ip_unprivileged_port_start` is refused, and there is no
            namespace pin under /run/flong: the launcher holds the namespace.
          '';
          type = lib.types.nullOr (lib.types.submodule {
            options = {
              forwardPorts = lib.mkOption {
                type = lib.types.either (lib.types.enum [ "auto" ]) (lib.types.listOf (lib.types.submodule {
                  options = {
                    protocol = lib.mkOption {
                      type = lib.types.enum [ "tcp" "udp" ];
                      default = "tcp";
                      description = "The protocol forwarded.";
                    };
                    hostPort = lib.mkOption {
                      type = lib.types.port;
                      description = "Port on the host, on every address.";
                    };
                    containerPort = lib.mkOption {
                      type = lib.types.nullOr lib.types.port;
                      default = null;
                      description = "Port in the session; `hostPort` if null.";
                    };
                  };
                }));
                default = [ ];
                description = ''
                  Ports on the host forwarded into the session, shaped exactly
                  like `containers.<name>.forwardPorts`, bound on every host
                  address -- the host's firewall still decides who reaches them.

                  A host port is one session's at a time. A second concurrent
                  session asking for the same one fails to attach its network,
                  and is ended rather than left running without it.

                  `"auto"`: whatever TCP port the session listens on is
                  published on the host at the same port, while it listens --
                  a dev server started inside is reached from the host's
                  browser. A port another session already publishes is not,
                  and that session is not ended for it.
                '';
              };
              hostLoopbackToSession = lib.mkOption {
                type = lib.types.bool;
                default = false;
                description = ''
                  A forwarded connection from the host's loopback arrives on
                  the session's loopback, rather than from the session's own
                  address -- pasta's --host-lo-to-ns-lo. A dev server
                  listening on 127.0.0.1 inside is then reached at
                  localhost on the host. It also reaches anything else the
                  session listens on only on its loopback, which is why pasta
                  no longer does it by default; a connection from anywhere
                  but the host's loopback is unaffected.
                '';
              };
              hostPorts = lib.mkOption {
                type = lib.types.listOf lib.types.port;
                default = [ ];
                example = [ 5432 ];
                description = ''
                  Ports on the host's loopback the session may reach, at the
                  same port on its own loopback: the database the host is
                  running, say. TCP and UDP both. Nothing else on the host's
                  loopback is reachable, the gateway address included.
                '';
              };
            };
          });
        };

        overlays = lib.mkOption {
          type = lib.types.attrsOf lib.types.path;
          default = { };
          example = lib.literalExpression ''{ "/home/alice/.state" = "/var/lib/state"; }'';
          description = ''
            Paths mounted as an overlay of `{ target = lower; }`: the lower
            directory is readable and every write goes to an upper layer that
            dies with the container.

            overlayfs reports changing device and inode numbers as a file is
            written, so this must not cover a path holding a sqlite database.

            Under `engine = "rootless"` an overlay below a bind, at any depth,
            is allowed: a session that renames its parent on the host only
            moves where its own writes land.
          '';
        };

        masks = lib.mkOption {
          type = lib.types.listOf (lib.types.strMatching "/.*");
          default = [ ];
          example = [ "/home/alice/.cache/tool/token" ];
          description = ''
            Paths in the session replaced by an empty node of the same kind
            that nobody can read -- nspawn's `--inaccessible`. For carving one
            file out of a directory a bind brings in whole.

            USE WITH CARE. Prefer binding only what the session needs to
            binding everything and masking the rest:

            - A mask is a denylist. Whatever it does not name is in, so a file
              the host's tool starts keeping beside the masked one next
              release -- a second token, a refresh token -- is visible from
              the day it appears.
            - The path must exist when the session starts, or the launch
              fails. A file that is written later, on the host, into a
              directory that is bound through is not masked.
            - It masks the file, not the name. A host program that replaces
              the file by renaming a new one over it -- as many write a
              credential -- detaches the mask in every running session, and
              the new file shows through.

            Under `engine = "rootless"` a mask may lie at most one level
            below the root of a writable bind: deeper, a session that can
            write the host directory renames the masked file's parent, leaves
            a decoy for the mask, and reads the file at the new name. A
            declared writable bind is checked at evaluation, and the
            workspace and `binds` at launch. A mask below a read-only bind,
            and a declared `tmpfs` or an overlay at any depth, is not
            checked.
          '';
        };

        scopeConfig = lib.mkOption {
          type = lib.types.attrsOf utils.systemdUtils.unitOptions.unitOption;
          default = { };
          example = { MemoryMax = "8G"; CPUQuota = "400%"; };
          description = ''
            Settings for the session's scope unit, as `serviceConfig` takes
            them for a service: a bool is written `true` or `false`, and a list
            is one assignment per element. Passed to `systemd-run --scope` as
            `--property=NAME=VALUE`, after flong's own `DevicePolicy=closed`
            and the declaration's `allowedDevices`. See
            {manpage}`systemd.resource-control(5)`.

            A session's root, its TMPDIR and every overlay upper layer live
            under /run, which is RAM: `MemoryMax` makes a payload that fills
            them the session's problem rather than the host's.

            `engine = "nspawn"` only: there is no scope under rootless, whose
            limits are `limits`.
          '';
        };

        limits =
          let
            # A size as systemd writes one, and as the kernel's memparse reads
            # it: bytes, or a number with K, M, G or T.
            memSize = lib.types.either lib.types.ints.unsigned
              (lib.types.strMatching "[0-9]+[KMGT]|infinity");
            limit = type: description: lib.mkOption {
              type = lib.types.nullOr type;
              default = null;
              inherit description;
            };
          in
          lib.mkOption {
            default = { };
            example = { MemoryMax = "8G"; TasksMax = 4096; CPUQuota = "400%"; };
            description = ''
              Opt-in resource limits for a rootless session, written into its
              own cgroup, which the caller's user manager delegates to the
              holder unit. Named and spelt as systemd's, and unset means
              unlimited, as it does there.

              `engine = "rootless"` only. Under nspawn a limit is refused and
              `scopeConfig` is the way. Only the controllers a user manager is
              delegated are offered -- memory, pids and cpu -- so there is no
              `IOWeight`: with no io controller below `user@.service`, it
              would have nothing to write to.

              A session's root, its TMPDIR and every overlay upper layer are
              tmpfs, which is RAM: `MemoryMax` makes a payload that fills
              them the session's problem rather than the host's.
            '';
            type = lib.types.submodule {
              options = {
                MemoryMax = limit memSize "`memory.max`: the hard limit.";
                MemoryHigh = limit memSize "`memory.high`: the throttling limit.";
                MemorySwapMax = limit memSize "`memory.swap.max`.";
                TasksMax = limit
                  (lib.types.either lib.types.ints.positive (lib.types.enum [ "infinity" ]))
                  "`pids.max`: processes and threads together.";
                CPUQuota = limit (lib.types.strMatching "[1-9][0-9]*%")
                  "`cpu.max`: a share of one CPU, as `N%`; `200%` is two.";
                CPUWeight = limit (lib.types.ints.between 1 10000)
                  "`cpu.weight`, against the caller's other processes.";
                oomGroup = lib.mkOption {
                  type = lib.types.bool;
                  default = false;
                  description = ''
                    `memory.oom.group`: an OOM kill takes the whole session
                    rather than one process of it.
                  '';
                };
              };
            };
          };

        seccomp =
          let
            # A syscall's name or a systemd group's, as `systemd-analyze
            # syscall-filter` lists them. The build refuses one it does not
            # list.
            syscallName = lib.types.strMatching "@?[a-z0-9_-]+";
          in
          lib.mkOption {
            default = { };
            example = { tier = "strict"; debug = true; };
            description = ''
              The session's syscall filter. A tier is an allow-list: the calls
              it names are allowed, the rest of systemd's `@known` get
              `errno`, and a call outside `@known` gets ENOSYS. It applies on
              x86_64, i386 and x32 alike.

              Three fixed filters are stacked behind it and are not options:
              the audit mask (`socket(AF_NETLINK, ..., NETLINK_AUDIT)` gets
              EAFNOSUPPORT), the tty filter (`ioctl` TIOCSTI, TIOCLINUX,
              TIOCSETD and TIOCCONS get EPERM, in every tier and under any
              project policy) and, unless `nestedSandbox`, the namespace mask
              (clone and unshare with a `CLONE_NEW*` flag, and setns, get
              EPERM, and clone3 ENOSYS).

              `engine = "rootless"` only. Under nspawn anything but the
              defaults is refused, since nspawn installs its own filter.
            '';
            type = lib.types.submodule {
              options = {
                tier = lib.mkOption {
                  type = lib.types.nullOr (lib.types.enum [ "parity" "strict" ]);
                  default = "strict";
                  description = ''
                    `parity` is exactly the allow-list nspawn installs for a
                    flong session. `strict` is parity without `@keyring`,
                    `userfaultfd`, `@mount`, `io_uring_*`, `ptrace` and
                    `process_vm_*`, which ordinary tools do without; strace
                    and gdb need `debug`. `null` installs no allow-list, only
                    the fixed filters, and warns.
                  '';
                };
                debug = lib.mkOption {
                  type = lib.types.bool;
                  default = false;
                  description = ''
                    Adds `ptrace`, for strace and gdb. Its reach is the
                    session's own pid namespace.
                  '';
                };
                nestedSandbox = lib.mkOption {
                  type = lib.types.bool;
                  default = false;
                  description = ''
                    For a payload that sandboxes its own children, such as
                    Chromium's sandbox, `codex sandbox` or a nested bwrap: the
                    session may make user namespaces of its own, the namespace
                    mask goes and `@mount` is allowed. All three are needed
                    together. The payload still cannot reach the session's
                    network namespace.
                  '';
                };
                allow = lib.mkOption {
                  type = lib.types.listOf syscallName;
                  default = [ ];
                  example = [ "@keyring" "userfaultfd" ];
                  description = "Syscall names or `@groups` added to the tier.";
                };
                deny = lib.mkOption {
                  type = lib.types.listOf syscallName;
                  default = [ ];
                  example = [ "@swap" ];
                  description = ''
                    Syscall names or `@groups` removed, after the tier, the
                    loosenings and `allow`, which it overrides.
                  '';
                };
                errno = lib.mkOption {
                  type = lib.types.enum [ "EPERM" "EACCES" "ENOSYS" ];
                  default = "EPERM";
                  description = ''
                    What a call in `@known` that the filter does not allow
                    returns. ENOSYS makes a program fall back as it would on
                    an older kernel.
                  '';
                };
                log = lib.mkOption {
                  type = lib.types.bool;
                  default = false;
                  description = ''
                    Allows the calls `errno` would refuse and has the kernel
                    log each (audit `type=1326`, with `syscall=NR`), to learn
                    a policy. `scmp_sys_resolver -a x86_64 NR` names a number;
                    the names become `allow` entries or `seccompPolicy` lines.
                    Not for untrusted payloads, and it warns.
                  '';
                };
              };
            };
          };

        seccompPolicy = lib.mkOption {
          type = lib.types.lines;
          default = "";
          example = ''chase-envelope approve "$workspace"'';
          description = ''
            A project's own changes to the `seccomp` filter, for a policy that
            is only known at launch. Runs as the caller after `guard`, with
            the launcher's arguments, the caller's stdin and stderr, and
            `$workspace`, `$workspace_mode`, `$binds` and `$machine` in
            scope, and prints lines of `allow X...` or `deny X...`, where
            each X is a syscall name or an `@group`. `#` comments and blank
            lines are skipped. A non-zero exit refuses the launch, and so
            does a line it cannot read or a name systemd does not list.

            `$machine` is the session's name, the one `postStart` and
            `postStop` see, so anything it approves for them can be staged
            per launch rather than per checkout.

            The project's lines apply to the declaration's allow-list: its
            allows are added and then its denies removed. The fixed filters
            stay, the tty filter included. The result is compiled at launch
            and cached under `$XDG_RUNTIME_DIR/flong/seccomp` by the hash of
            what is compiled, so a policy already seen costs a hash. Printing
            nothing compiles nothing. A relaunch runs it again.

            It needs a tier to act on, and it is a consistency check in the
            way `guard` is: the caller can run flong-launch with any filter.
            `engine = "rootless"` only.
          '';
        };

        protect = lib.mkOption {
          type = lib.types.listOf (lib.types.strMatching "/.*");
          default = [ ];
          example = [ "/run/frisket" ];
          description = ''
            Host paths no mount of a session may reach: no source may equal,
            lie inside or contain one. For a directory whose contents steer
            sessions from outside, such as a daemon's control socket.

            `engine = "rootless"` only, and ignored under nspawn, so a module
            can set it before the engine changes. The wrapper protects
            `/proc`, `/sys/fs/cgroup` and the user manager's `bus` and
            `systemd` sockets as well, and the launcher its own state and
            the holder's cgroup.
          '';
        };

        path = lib.mkOption {
          type = lib.types.listOf lib.types.package;
          default = [ ];
          description = ''
            Packages on `PATH` for every hook that runs on the host: the
            caller-run `workspace` and `binds`, and `guard`, `postStart` and
            `postStop`, which run as root under nspawn and as the caller
            under `engine = "rootless"`. Not for `command`, which runs inside
            the session with the container's own `PATH`: a tool the workload
            needs belongs in the container's `environment.systemPackages`.
          '';
        };

        launcher = lib.mkOption {
          type = lib.types.package;
          readOnly = true;
          description = ''
            The generated launcher. Under `engine = "nspawn"` it must be run
            as root; how you arrange that -- sudo, doas, run0, a systemd unit
            -- is deliberately not this module's business.

            Under `engine = "rootless"` it is run directly, as the user whose
            session it is, and needs their subordinate ids in /etc/subuid and
            /etc/subgid (`users.users.<name>.subUidRanges`, or
            `autoSubUidGidRange`). Its checks are consistency checks; the
            launcher's own are the boundary. It exits with the payload's
            status, 128+n when a signal killed the payload, 125 when the
            payload never ran, and 75 when its prepared root was swept and it
            could not relaunch.
          '';
        };
      };

      config.launcher =
        if config.engine == "rootless" then rootless.mkLauncher name config
        else mkLauncher name config;
    }));
  };

  # Required rather than chosen: without the NixOS container machinery there is
  # no containers.<name> to drive.
  config = lib.mkIf (cfg != { }) {
    boot.enableContainers = true;

    # The rootless sessions' holder, in every user's manager, for as long as
    # any declaration runs rootless.
    systemd.user.services.flong-sessions = lib.mkIf anyRootless rootless.holderUnit;

    warnings = lib.concatLists (lib.mapAttrsToList
      (n: c:
        let declared = config.containers.${c.container} or null; in
        # Under rootless an autoStart container is refused, not warned about.
        lib.optionals (c.engine == "rootless") (rootless.warningsFor n c)
        ++ lib.optional (c.engine == "nspawn" && declared != null && declared.autoStart) ''
          flong.${n} drives containers.${c.container}, which has autoStart
          enabled: systemd boots that container at every host boot, which is
          the second and a bit a flong exists in order not to pay, and it holds
          the declaration's state directory for as long as it runs. Set
          autoStart = false unless you want the long-running container too.
        '')
      cfg);

    # Everything the container module would honour and flong cannot, refused
    # here rather than dropped quietly. Most of these declare LESS privilege
    # than the default, and a container that is silently not the one you
    # declared is worse than one that refuses to build.
    assertions = lib.concatLists (lib.mapAttrsToList
      (n: c:
        let
          declared = config.containers.${c.container} or null;
          # One entry can carry several flags, and a flag and its value can be
          # two words -- see extraFlagWords.
          privilegedFlags = lib.filter
            (w: w == "-U" || lib.any (flag: w == flag || lib.hasPrefix "${flag}=" w)
              [ "--capability" "--ambient-capability" "--private-users" ])
            (extraFlagWords declared);
          isRootless = c.engine == "rootless";
          # The limits a declaration sets: anything not left null or false.
          setLimits = lib.attrNames (lib.filterAttrs (_: v: v != null && v != false) c.limits);
          # The seccomp settings a declaration changes from their defaults.
          seccompDefaults = {
            tier = "strict"; debug = false; nestedSandbox = false;
            allow = [ ]; deny = [ ]; errno = "EPERM"; log = false;
          };
          setSeccomp = lib.attrNames (lib.filterAttrs (k: v: seccompDefaults ? ${k} && seccompDefaults.${k} != v) c.seccomp)
            ++ lib.optional (c.seccompPolicy != "") "seccompPolicy";
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
        in
        [{
          assertion = declared != null;
          message = ''
            flong.${n}.container names containers.${c.container}, which is not
            declared.
          '';
        }]
        ++ lib.optionals (declared != null) [
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
            assertion = declared.privateUsers == "no";
            message = if isRootless then ''
              flong.${n} drives containers.${c.container}, which asks for a uid
              namespace. A rootless session always has flong's own, which maps
              the container's user onto the caller so the workspace stays
              theirs, and the rest onto the caller's subordinate range. There is
              no other to choose, so the option would declare nothing.
            '' else ''
              flong.${n} drives containers.${c.container}, which asks for a uid
              namespace. flong cannot give it one: a bind-mounted file owned by
              a host uid maps to an unmapped uid inside, so the session cannot
              read the workspace it was started for. Leaving the option set
              would declare an isolation the session does not get.
            '';
          }
          {
            assertion = declared.additionalCapabilities == [ ] && ! declared.enableTun;
            message = if isRootless then ''
              flong.${n} drives containers.${c.container}, which grants
              capabilities. Nothing in a rootless session holds any: the
              payload's user namespace has an empty bounding set, so there is
              no process for a capability to belong to, and no CAP_NET_ADMIN to
              make enableTun's /dev/net/tun useful.
            '' else ''
              flong.${n} drives containers.${c.container}, which grants
              capabilities. Nothing in a session holds any, and that one is
              structural rather than unwritten: nspawn drops to ${c.user} before
              it starts pid 1, so there is no process for a capability to belong
              to. enableTun's /dev/net/tun follows from it -- there is no
              CAP_NET_ADMIN in there to create an interface with, and a tun that
              a session should have is one the launcher makes on the host and
              moves in.

              extraFlags is not a way round this: --capability,
              --ambient-capability and --private-users are refused there as
              well.
            '';
          }
          {
            # Under rootless every extraFlags entry is refused, by the
            # rootless checks below.
            assertion = isRootless || privilegedFlags == [ ];
            message = ''
              flong.${n} drives containers.${c.container}, whose extraFlags ask
              for ${lib.concatStringsSep " " privilegedFlags}. flong passes
              extraFlags through, and refuses these rather than pass them: each
              gives a session back something flong keeps from it on purpose --
              a capability in the bounding set, an ambient one, or a user
              namespace of the container's own, which would make IT the owner
              of the session's network namespace instead of the initial user
              namespace. That ownership is what actually stops a workload
              undoing what a hook installed, and none of this belongs in a
              flag string where nobody reviewing the hook would look for it.
            '';
          }
          {
            assertion = ! lib.any (x: x) needsInside;
            message = if isRootless then ''
              flong.${n} drives containers.${c.container}, which declares a
              veth, a bridge, a macvlan, a moved interface, an address or a
              forwarded port. flong refuses them rather than dropping them:
              each is static per container, and flong runs many concurrent
              sessions from one declaration, which would claim the same
              address, interface or host port.

              What a session can have is `privateNetwork` alone (loopback and
              nothing else), or `privateNetwork` with flong.${n}.network (a
              real network through pasta, with its own forwardPorts and
              hostPorts).
            '' else ''
              flong.${n} drives containers.${c.container}, which declares a
              veth, a bridge, a macvlan, a moved interface, an address or a
              forwarded port. flong refuses them rather than dropping them,
              because a declaration that quietly does not happen is worse than
              a build that stops.

              They are refused because each is static per container, and flong
              runs many concurrent sessions from one declaration: two sessions
              would claim the same address, the same interface or the same host
              port, and the host cannot route one address to two of them.

              What a session can have is `privateNetwork` alone (loopback and
              nothing else), `privateNetwork` with flong.${n}.network (a real
              network through pasta, with its own forwardPorts and hostPorts),
              or `networkNamespace`, pointed at a namespace something else
              already built.
            '';
          }
          {
            assertion = c.network == null || declared.privateNetwork;
            message = ''
              flong.${n}.network gives a session a network of its own, and
              containers.${c.container} does not have privateNetwork = true --
              so the session would share the host's namespace, and pasta would
              be pointed at the host's own network. Set privateNetwork = true.
            '';
          }
          {
            assertion = c.engine != "nspawn" || setLimits == [ ];
            message = ''
              flong.${n} sets limits.${lib.concatStringsSep ", limits." setLimits}, which
              only the rootless engine writes. Under nspawn a session's limits
              are its scope's: set them in scopeConfig.
            '';
          }
          {
            assertion = c.engine != "nspawn" || setSeccomp == [ ];
            message = ''
              flong.${n} sets ${lib.concatStringsSep ", " (map (k: if k == "seccompPolicy" then k else "seccomp.${k}") setSeccomp)},
              which only the rootless engine reads. nspawn installs its own
              filter, and flong does not change it.
            '';
          }
        ]
        ++ lib.optionals (declared != null && isRootless) (rootless.assertionsFor n c))
      cfg)
    ++ lib.optionals anyRootless rootless.hostAssertions;
  };
}
