{ config, lib, pkgs, utils, ... }:

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

  mkPayload = name: c: pkgs.writeShellApplication {
    name = "flong-payload-${name}";
    runtimeInputs = [ pkgs.coreutils ];
    text = ''
      workspace=$1
      shift
      cd "$workspace" || exit 1

      # Leaves the command to run in "$@".
      ${c.command}

      # EXEC, so the payload becomes this process rather than a child of it,
      # and tini can signal it directly. set-environment is sourced inside a
      # `bash -c` because it expands unset variables, which would abort under
      # the `set -u` this script runs with.
      exec bash -c '. /etc/set-environment
                    exec "$@"' \
           flong "$@"
    '';
  };

  mkLauncher = name: c:
    let
      declared = config.containers.${c.container};
      closure = declared.path;
      declaredConf = config.environment.etc."nixos-containers/${c.container}.conf".source;

      # allowedDevices is a unit property rather than an nspawn flag, so it is
      # not in that file and is translated here.
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

      # EVERY PORT CLASS IS SPELT OUT, "none" included, because -t, -u, -T and
      # -U all default to `auto` -- and `auto` forwards every port bound on the
      # other side, which for -T means everything listening on the host's
      # loopback. A session asks for what it gets, port by port.
      #
      # hostPorts go out as TCP and UDP both: a port on the host's loopback is
      # the thing named, and a resolver there is as likely a reason to name one
      # as a database.
      pastaPorts = net:
        let
          spec = ports: if ports == [ ] then "none" else lib.concatStringsSep "," ports;
          forwards = protocol: map
            (p: "${toString p.hostPort}:${toString (if p.containerPort == null then p.hostPort else p.containerPort)}")
            (lib.filter (p: p.protocol == protocol) net.forwardPorts);
          host = map toString net.hostPorts;
        in
        "-t ${spec (forwards "tcp")} -u ${spec (forwards "udp")} -T ${spec host} -U ${spec host}";

      overlayDir = p: ".overlay/" + lib.replaceStrings [ "/" ] [ "_" ] (lib.removePrefix "/" p);

      # An entry may name its own options as PATH:opts, so the path is the head.
      tmpfsPath = p: lib.head (lib.splitString ":" p);

      # The container's own `tmpfs` list means what flong's means -- the
      # container module passes it to nspawn as --tmpfs, and flong is the thing
      # calling nspawn -- so it is merged in rather than silently dropped.
      # flong's entry wins where both name a path, which is how a consumer adds
      # options to something the container asked for.
      #
      # XDG_RUNTIME_DIR is exported unconditionally, so the directory it names
      # has to exist, and only the launcher can arrange that: /run is nspawn's
      # own tmpfs, made fresh at every start, and nothing inside a session is
      # privileged enough to create a directory in it. It gets the payload's
      # ownership and 0700 because a root-owned 0755 runtime directory is
      # rejected by the things that look at one -- and failing that way is
      # quiet, which is how a session ends up with no keyring, no user bus and
      # no explanation.
      #
      # The list is settled here and turned into flags in the launcher, because
      # the uid and gid they are owned by come out of the prepared root's passwd
      # and are not known until then.
      tmpfsEntries = c.tmpfs ++ lib.filter
        (p: ! lib.elem (tmpfsPath p) (map tmpfsPath c.tmpfs))
        declared.tmpfs;

      # An explicit upper inside the session root, not nspawn's empty-string
      # form, which puts it under the host's /var/tmp and leaks it on SIGKILL.
      overlayFlags = lib.concatMapStringsSep " "
        (p: ''--overlay=${c.overlays.${p}}:"$root"/${overlayDir p}:${p}'')
        (lib.attrNames c.overlays);
      # nspawn creates mount points for --bind but not for --overlay or
      # --tmpfs, so a target whose parent does not exist in the root fails the
      # launch. Made here, along with each overlay's upper layer; the tmpfs
      # mount points are made by the loop that builds their flags, since both
      # halves need the identity.
      mountpointMkdirs = lib.concatStringsSep "\n        " (
        lib.concatMap
          (p: [
            ''mkdir -p "$root"/${overlayDir p} "$root"${p}''
            # The upper layer receives the payload's writes, so it belongs to
            # the payload's user. Note the MERGED directory still takes its
            # ownership from the lower one.
            ''chown "$uid:$gid" "$root"/${overlayDir p}''
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
      # Between tini and everything else, so a wrapper, `command` and the
      # workload all start after it.
      gate = pkgs.writeShellApplication {
        name = "flong-gate";
        runtimeInputs = [ pkgs.coreutils ];
        text = ''
          for ((try = 0; try < 2000; try++)); do
            [ -d /run/flong-ready ] && exec "$@"
            sleep 0.005
          done
          echo "flong: the session never became ready" >&2
          exit 1
        '';
      };
      gateCmd = lib.optionalString steered (lib.getExe gate);

      # A script of its own, rather than a snippet spliced into the launcher,
      # because it is not always THIS launcher that runs it: the sweep runs
      # inside whichever launch of the container comes next, and several
      # launchers can drive one container. So each session records which
      # teardown is its own, and the sweep runs that one -- including a
      # superseded generation's, whose code this launcher no longer carries.
      postStopScript = pkgs.writeShellApplication {
        name = "flong-poststop-${name}";
        runtimeInputs = [ pkgs.coreutils pkgs.util-linux ] ++ c.path;
        text = ''
          # Exported, so a helper the snippet calls sees it as well.
          export machine=$1
          ${c.postStop}
        '';
      };
    in
    pkgs.writeShellApplication {
      inherit name;
      runtimeInputs = [ pkgs.git pkgs.coreutils pkgs.util-linux pkgs.e2fsprogs ]
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

        # `workspace` is the only place this script touches attacker-shaped
        # input: it runs a shell -- by default git -- in a directory the
        # caller chose. Its answer is the caller's to give either way, so
        # there is nothing to buy by deriving it as root and a whole class of
        # git-in-a-hostile-checkout escalation to avoid.
        #
        # sudo sets SUDO_UID itself, so a caller cannot suppress it to get the
        # root path back; run0 sets it too and pkexec sets PKEXEC_UID. Root is
        # the fallback for a launcher started from a unit, where there is no
        # unprivileged caller to drop to.
        caller=''${SUDO_UID:-''${PKEXEC_UID:-}}

        # Captured because "$@" inside a function is the function's own
        # arguments, and every snippet must see the launcher's.
        launcher_args=("$@")

        # One way to run a consumer's snippet, shared by `workspace` and the
        # two bind lists, so they cannot drift in how much privilege they get.
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
        # all three call sites.
        workspace=$(run_as_caller ${lib.escapeShellArg c.workspace}) || exit 1

        # Resolved before it is checked, so what gets validated is what gets
        # mounted -- and so that `guard` below judges the same canonical path
        # nspawn will be handed, rather than whatever spelling the caller
        # happened to use.
        workspace=$(realpath -e -- "$workspace") || exit 1
        # nspawn splits --bind on ':', and a newline would corrupt the flag
        # string it is spliced into, so a workspace naming either cannot be
        # expressed as a mount and is refused rather than mounted wrongly.
        # WHICH directory is allowed remains `guard`'s business, not this.
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

        # The extra binds, resolved with $workspace already in scope so a
        # snippet can answer "what travels with THIS directory" -- which is
        # the question a consumer pairing repositories is actually asking.
        # Exported rather than passed, because the snippet runs in a bash of
        # its own under setpriv and would not otherwise inherit it.
        export workspace

        # Same treatment $workspace gets, for the same reasons, applied to
        # every line: resolved first so what is validated is what is mounted,
        # then refused if it names anything --bind cannot express. Deciding
        # WHICH directories are allowed remains `guard`'s business.
        #
        # `exit 1` inside the function lands in the command substitution's
        # subshell, so every caller needs its own `|| exit 1` -- a failure
        # here must abort the launch, not mount a shorter list.
        resolve_binds() {
          local raw=$1 p out=""
          while IFS= read -r p; do
            [ -n "$p" ] || continue
            p=$(realpath -e -- "$p") || exit 1
            case $p in
              *:* | *"$nl"*)
                echo "${name}: extra bind names ':' or a newline: $p" >&2
                exit 1
                ;;
            esac
            [ -d "$p" ] || {
              echo "${name}: extra bind is not a directory: $p" >&2
              exit 1
            }
            out=$out$p$nl
          done <<< "$raw"
          printf '%s' "$out"
        }

        # shellcheck disable=SC2016
        extra_binds=$(resolve_binds "$(run_as_caller ${lib.escapeShellArg c.extraBinds})") || exit 1
        # shellcheck disable=SC2016
        extra_binds_ro=$(resolve_binds "$(run_as_caller ${lib.escapeShellArg c.extraBindsRo})") || exit 1

        # `guard` decides entitlement, so it stays root. A gate the caller can
        # ptrace or preload is not a gate, and dropping it would hand the
        # decision to the process it exists to refuse. It reads $workspace --
        # absolute, resolved, and already refused if it held anything nspawn
        # cannot express, which makes it the better-sanitised of the two
        # caller-shaped values in scope here. The other is $PWD.
        #
        # $extra_binds and $extra_binds_ro are in scope too, newline
        # separated and resolved the same way. A container that grants more
        # than its caller had must judge THOSE as well: they are mounts the
        # caller named, and a gate that reads only $workspace would let a
        # second directory in unexamined.
        ${c.guard}

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
        ${mountpointMkdirs}
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
        # it. Skipped if an entry already names that path, so the options remain
        # a consumer's to override.
        #
        # nspawn creates the mount point for a --tmpfs, but a mkdir here as well
        # keeps a nested bind -- a socket carved out of a masked runtime
        # directory -- from depending on which of the two nspawn makes first.
        tmpfs_entries=(${lib.escapeShellArgs tmpfsEntries})
        tmpfs_flags=()
        runtime_dir=/run/user/$uid
        want_runtime_dir=1
        for entry in ''${tmpfs_entries[@]+"''${tmpfs_entries[@]}"}; do
          path=''${entry%%:*}
          [ "$path" = "$runtime_dir" ] && want_runtime_dir=0
          case $entry in
            *:*) tmpfs_flags+=("--tmpfs=$entry") ;;
            *)   tmpfs_flags+=("--tmpfs=$entry:mode=0755,uid=$uid,gid=$gid") ;;
          esac
          mkdir -p "$root$path"
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

        # Deliberately word-split: it is a flag string.
        read -ra binds < <(sed -n 's/^EXTRA_NSPAWN_FLAGS="\(.*\)"$/\1/p' ${declaredConf})

        # An array rather than a string, unlike the line above: these are
        # runtime values, and word-splitting a path is how a directory with a
        # space in it becomes two broken mounts.
        extra_flags=()
        while IFS= read -r b; do
          [ -n "$b" ] || continue
          extra_flags+=("--bind=$b:$b")
        done <<< "$extra_binds"
        while IFS= read -r b; do
          [ -n "$b" ] || continue
          extra_flags+=("--bind-ro=$b:$b")
        done <<< "$extra_binds_ro"

        # Handed to `command` too, so a consumer can tell whatever it starts
        # about the directories -- both agents this was built for take an
        # --add-dir, and a mount the process does not know about is only half
        # of what the caller asked for. ':' separated, which is unambiguous
        # precisely because a path naming one was refused above.
        joined() {
          local out="" b
          while IFS= read -r b; do
            [ -n "$b" ] || continue
            out=''${out:+$out:}$b
          done <<< "$1"
          printf '%s' "$out"
        }

        # THE HOOK'S OWN BINDS, which extraBinds cannot carry: that takes
        # directories only, binds each at its own path, is resolved as the
        # caller, and is advertised to the payload. These are the launcher's
        # plumbing -- a socket, a single file -- bound from a host path of the
        # hook's choosing to a fixed path inside, and not the workload's
        # business to be told about.
        #
        # Resolved here, as root, after the trap is armed and the machine name
        # exists, so a source can be made per session and released by
        # `postStop` if a later step fails. Not from `postStart`: a bind mount is an
        # argument to nspawn, and by the time there is a namespace the mount
        # table has been made.
        attach_binds=""
        ${lib.optionalString (c.attachBinds != "") ''
        # SOURCE:DESTINATION, one per line, refused -- not guessed at -- if
        # either side names a ':' or a newline, which is the refusal
        # resolve_binds makes and for the same reason: --bind has no escaping
        # to fall back on. The source is resolved and must exist, and it may be
        # any kind of file; the destination is a path inside and must be
        # absolute.
        resolve_attach_binds() {
          local line src dest out=""
          while IFS= read -r line; do
            [ -n "$line" ] || continue
            src=''${line%%:*}
            dest=''${line#*:}
            case $line in
              *:*:* | *"$nl"*)
                echo "${name}: attach bind names ':' or a newline: $line" >&2
                exit 1
                ;;
              *:*) ;;
              *)
                echo "${name}: attach bind is not SOURCE:DESTINATION: $line" >&2
                exit 1
                ;;
            esac
            src=$(realpath -e -- "$src") || exit 1
            # Again after resolving, because a symlink can lead somewhere the
            # line itself did not name.
            case $src in
              *:* | *"$nl"*)
                echo "${name}: attach bind names ':' or a newline: $src" >&2
                exit 1
                ;;
            esac
            case $dest in
              /*) ;;
              *)
                echo "${name}: attach bind destination is not absolute: $dest" >&2
                exit 1
                ;;
            esac
            out=$out$src:$dest$nl
          done <<< "$1"
          printf '%s' "$out"
        }

        attach_binds_raw=$(
          ${c.attachBinds}
        ) || exit 1
        attach_binds=$(resolve_attach_binds "$attach_binds_raw") || exit 1
        ''}
        # Onto the nspawn command line and nowhere else: not joined into
        # FLONG_EXTRA_BINDS, which is how the payload learns what the CALLER
        # asked to have mounted.
        while IFS= read -r b; do
          [ -n "$b" ] || continue
          extra_flags+=("--bind=$b")
        done <<< "$attach_binds"

        # The command the payload is exec'd through, empty unless a consumer
        # named one. An array rather than a string, for the reason the extra
        # binds are one: a word with a space in it is a word, not two.
        wrap=()
        ${lib.optionalString (c.attachWrap != "") ''
        # Resolved out here, as root, and spliced onto the nspawn command line
        # before the payload -- which is the only place a wrapper can go. The
        # consumer's `command` is already inside the sandbox and already
        # running as ${c.user}, so anything expressed there is something the
        # workload's own shell could have declined to run.
        wrap_words=$(
          ${c.attachWrap}
        ) || exit 1
        while IFS= read -r wrap_word; do
          [ -n "$wrap_word" ] || continue
          wrap+=("$wrap_word")
        done <<< "$wrap_words"
        ''}

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
        # --uid rather than --user, which systemd 261 deprecates and warns
        # about on every single launch. Both spellings resolve a name the same
        # way: nspawn execs `getent passwd` INSIDE the container root, so a
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
        # A script has no job control, so `&` does not put this in a process
        # group of its own: nspawn stays in the launcher's, which is the
        # terminal's foreground group, so an interactive session still reads
        # the keyboard instead of stopping on SIGTTIN.
        exec 3<&0
        ${systemdRun} --scope --quiet --unit="$machine" --slice=machine.slice \
          --property=DevicePolicy=closed ${deviceProps} ${scopeProps} -- \
          ${nspawn} -q --keep-unit --directory="$root" --machine="$machine" \
            --hostname=${lib.escapeShellArg c.container} \
            --console=autopipe \
            ${networkFlags} ${resolvConfFlag} ${capabilityFlags} \
            --kill-signal=SIGTERM \
            --bind-ro=/nix/store --bind-ro=/nix/var/nix/db \
            --bind-ro=${closure}:/run/current-system \
            ''${binds[@]+"''${binds[@]}"} \
            --bind="$workspace:$workspace" \
            ''${extra_flags[@]+"''${extra_flags[@]}"} \
            ''${tmpfs_flags[@]+"''${tmpfs_flags[@]}"} ${overlayFlags} \
            --uid=${c.user} \
            --setenv=PATH=${closure}/sw/bin \
            --setenv=TMPDIR="$home/tmp" \
            --setenv=XDG_RUNTIME_DIR="$runtime_dir" \
            --setenv=FLONG_EXTRA_BINDS="$(joined "$extra_binds")" \
            --setenv=FLONG_EXTRA_BINDS_RO="$(joined "$extra_binds_ro")" \
            ${pkgs.tini}/bin/tini -g -- ${gateCmd} \
            ''${wrap[@]+"''${wrap[@]}"} \
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
          ${pastaPorts c.network} --no-map-gw \
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
            The `containers.<name>` whose closure, bind mounts and
            allowedDevices this drives.
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
          '';
        };

        workspace = lib.mkOption {
          type = lib.types.lines;
          default = ''git -C "$PWD" rev-parse --show-toplevel'';
          description = ''
            Shell printing the directory to bind into the container and cd
            into. Runs on the host before launch, with the launcher's
            arguments in "$@"; a non-zero exit aborts.

            Runs *before* `guard`, so that the gate can judge the directory
            this resolves to rather than re-deriving one of its own.

            Runs as the *invoking* user rather than as root -- it reads a
            directory the caller chose, which is the one piece of
            attacker-shaped input the launcher handles, and its answer is the
            caller's to give either way. Root only when there is no
            unprivileged caller to drop to, as when a unit starts the
            launcher directly.

            What it prints is resolved with `realpath` and then refused if it
            names a `:` or a newline, neither of which nspawn's `--bind` can
            express. Deciding *which* directory is allowed is `guard`'s job,
            not this one's.
          '';
        };

        extraBinds = lib.mkOption {
          type = lib.types.lines;
          default = "";
          example = ''printf '%s\n' "$HOME/Projects/finance-api"'';
          description = ''
            Shell printing further directories to bind read-write, one per
            line, each at its own path inside the container. Empty output
            binds nothing, which is the default.

            Runs after `workspace`, with `$workspace` exported, so it can
            answer "what travels with THIS directory" rather than having to
            name a fixed set -- which is the question a consumer pairing
            repositories is actually asking.

            Runs as the invoking user and sees the launcher's arguments in
            "$@", exactly as `workspace` does, and every line it prints is
            resolved with `realpath` and then refused if it names a `:` or a
            newline. Deciding *which* directories are allowed is `guard`'s
            job: it receives them in `$extra_binds`, newline separated.

            Also reaches `command` as `$FLONG_EXTRA_BINDS`, `:` separated.
          '';
        };

        extraBindsRo = lib.mkOption {
          type = lib.types.lines;
          default = "";
          description = ''
            As `extraBinds`, but bound read-only, reaching `guard` as
            `$extra_binds_ro` and `command` as `$FLONG_EXTRA_BINDS_RO`.

            Read-only is not a boundary on its own -- it stops writes, not
            execution -- so this is for directories a session should read
            rather than edit, not for making an untrusted one safe.
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

            Runs *after* `workspace`, with `$workspace` in scope: absolute,
            symlink-resolved, and already refused if it held anything nspawn
            cannot express. Judge that rather than re-deriving a directory
            from `$PWD` -- what `$workspace` holds is exactly what will be
            bound, where anything a guard works out for itself agrees with
            the mount only by coincidence.
          '';
        };

        command = lib.mkOption {
          type = lib.types.lines;
          description = ''
            Shell run as `user` inside the container with the launcher's
            arguments in "$@". Must leave the command to run in "$@", normally
            by ending in a `set -- ...`, which is then exec'd.
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
            `$extra_binds`, `$extra_binds_ro` and `$attach_binds` are in scope
            too. Without `privateNetwork` a session
            shares the host's network namespace, and `$netns` names *that*: a
            hook that installs a ruleset there is steering the host.

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
          '';
        };

        attachBinds = lib.mkOption {
          type = lib.types.lines;
          default = "";
          example = ''printf '%s\n' "/run/my-gate/$machine.sock:/run/gate.sock"'';
          description = ''
            Shell printing `SOURCE:DESTINATION` lines, each bound read-write
            into the session: a host path of the hook's choosing, at a path
            inside of the hook's choosing. This is how `postStart` gets a socket
            or a single file into the sandbox, which `extraBinds` cannot do --
            that takes directories only, binds each at its own path, is
            resolved as the caller, and is announced to the payload.

            Runs on the host as root, after `guard`, once the session has a
            machine name and its cleanup trap is armed, with `$machine`,
            `$root`, `$uid`, `$gid`, `$home` and `$workspace` in scope -- so a
            source can be made for this session alone, and `postStop` will be
            called to release it even if the launch fails after this point.
            It runs before nspawn and not from `postStart`, because a bind mount
            is an argument to nspawn: by the time there is a namespace, the
            mount table has been made. A source that must exist before the
            session starts -- a listening socket -- is this snippet's to create.

            The source is resolved with `realpath` and must exist; it may be
            any kind of file. The destination must be absolute. A line naming
            a `:` or a newline on either side is refused, as `extraBinds`
            refuses one. Bind the specific path and never a shared parent:
            with a whole directory bound, a workload can list and write its
            neighbours' entries.

            Not advertised to the payload: nothing here reaches
            `FLONG_EXTRA_BINDS`, which says what the *caller* asked for.
          '';
        };

        attachWrap = lib.mkOption {
          type = lib.types.lines;
          default = "";
          example = ''printf '%s\n' /run/current-system/sw/bin/my-gate --session "$machine"'';
          description = ''
            Shell printing a command, one argument per line, that the payload
            is exec'd through inside the session. Empty output -- the default
            -- execs the payload directly.

            Runs on the host as root, before nspawn, with `$machine`, `$root`,
            `$uid`, `$gid`, `$home` and `$workspace` in scope. What it prints
            is a path *inside* the container and its arguments, spliced onto
            the nspawn command line between `tini` and the payload.

            That position is the point of it. `command` is already inside the
            sandbox and already running as `user`, so a gate expressed there is
            one the workload could have declined to run; this one is between
            the workload and its own pid 1.

            It starts after `postStart` has finished, like the rest of the
            payload, so it is not needed to close any window: use it for a
            launcher that wants to *be* the workload's parent.
          '';
        };

        postStop = lib.mkOption {
          type = lib.types.lines;
          default = "";
          example = ''rm -f "/run/my-gate/$machine.sock"'';
          description = ''
            Shell run on the host as root after a session ends, to release
            whatever the other root hooks made outside it. `$machine` is set,
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

            Attached after `postStart` returns, never before, which is what makes
            the hook's ordering hold. A session with a network also has a
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
          '';
          type = lib.types.nullOr (lib.types.submodule {
            options = {
              forwardPorts = lib.mkOption {
                type = lib.types.listOf (lib.types.submodule {
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
                });
                default = [ ];
                description = ''
                  Ports on the host forwarded into the session, shaped exactly
                  like `containers.<name>.forwardPorts`, bound on every host
                  address -- the host's firewall still decides who reaches them.

                  A host port is one session's at a time. A second concurrent
                  session asking for the same one fails to attach its network,
                  and is ended rather than left running without it.
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

        tmpfs = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [ ];
          example = [ "/home/alice/.cache" ];
          description = ''
            Paths made container-local and empty. Applied after the
            container's own bind mounts, so this carves a subdirectory out of
            a read-write bind.
          '';
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
          '';
        };

        path = lib.mkOption {
          type = lib.types.listOf lib.types.package;
          default = [ ];
          description = ''
            Packages on `PATH` for every hook that runs on the host: the
            caller-run `workspace`, the root-run `guard`, `postStart` and
            `postStop`. Not for `command`, which runs inside the session with
            the container's own `PATH`: a tool the workload needs belongs in
            the container's `environment.systemPackages`.
          '';
        };

        launcher = lib.mkOption {
          type = lib.types.package;
          readOnly = true;
          description = ''
            The generated launcher. Must be run as root; how you arrange that
            -- sudo, doas, run0, a systemd unit -- is deliberately not this
            module's business.
          '';
        };
      };

      config.launcher = mkLauncher name config;
    }));
  };

  # Required rather than chosen: without the NixOS container machinery there is
  # no containers.<name> to drive.
  config = lib.mkIf (cfg != { }) {
    boot.enableContainers = true;

    warnings = lib.concatLists (lib.mapAttrsToList
      (n: c:
        let declared = config.containers.${c.container} or null; in
        lib.optional (declared != null && declared.autoStart) ''
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
          # Each extraFlags entry is spliced into EXTRA_NSPAWN_FLAGS and
          # word-split, so one entry can carry several flags, and a flag and its
          # value can be two words.
          extraWords = lib.concatMap
            (f: lib.filter (w: lib.isString w && w != "")
              (builtins.split "[[:space:]]+" f))
            declared.extraFlags;
          privilegedFlags = lib.filter
            (w: w == "-U" || lib.any (flag: w == flag || lib.hasPrefix "${flag}=" w)
              [ "--capability" "--ambient-capability" "--private-users" ])
            extraWords;
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
        ++ lib.optionals (declared != null) ([
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
            message = ''
              flong.${n} drives containers.${c.container}, which asks for a uid
              namespace. flong cannot give it one: a bind-mounted file owned by
              a host uid maps to an unmapped uid inside, so the session cannot
              read the workspace it was started for. Leaving the option set
              would declare an isolation the session does not get.
            '';
          }
          {
            assertion = declared.additionalCapabilities == [ ] && ! declared.enableTun;
            message = ''
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
            assertion = privilegedFlags == [ ];
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
            message = ''
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
        ]
        # Bind mounts are recovered by word-splitting EXTRA_NSPAWN_FLAGS, which
        # the NixOS container module writes unescaped. A path holding whitespace
        # does not fail that parse -- it splits into two flags that are each
        # valid and neither correct, so the container silently gets mounts
        # nobody declared. A colon is the same story one level down, inside
        # --bind's own SRC:DEST. Refused at eval, because there is no way to
        # notice it at runtime.
        ++ lib.concatMap
          (m: map
            # hostPath is null when the mount takes the container's own path on
            # both sides, and then there is only the one path to judge.
            (p: {
              assertion = ! lib.any (bad: lib.hasInfix bad p) [ " " "\t" "\n" ":" ];
              message = ''
                flong: containers.${c.container} has a bind mount path that
                cannot survive EXTRA_NSPAWN_FLAGS: "${p}". Whitespace and ':'
                are not expressible there; rename the path.
              '';
            })
            (lib.filter (p: p != null) [ m.hostPath m.mountPoint ]))
          (lib.attrValues declared.bindMounts)))
      cfg);
  };
}
