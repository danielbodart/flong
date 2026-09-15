{ config, lib, pkgs, ... }:

let
  cfg = config.flong;

  mkPayload = name: c: pkgs.writeShellApplication {
    name = "flong-payload-${name}";
    runtimeInputs = [ pkgs.coreutils ] ++ c.payloadInputs;
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
      resourceProps = lib.concatMapStringsSep " "
        (k: "--property=${lib.escapeShellArg "${k}=${c.properties.${k}}"}")
        (lib.attrNames c.properties);

      # The two kinds of network isolation that need nothing configured inside
      # the container, which is the only kind a session can have: nspawn drops
      # to `user` before pid 1, so there is no privileged moment in there to
      # bring an interface up or address it. A veth, a bridge, a macvlan or a
      # moved interface needs exactly that, and is refused at evaluation.
      networkFlags =
        lib.optionalString declared.privateNetwork "--private-network "
        + lib.optionalString (declared.networkNamespace != null)
          "--network-namespace-path=${lib.escapeShellArg declared.networkNamespace}";

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

      # WHO A SESSION RUNS AS IS READ, NOT DECLARED.
      #
      # `user` is the only half a consumer can usefully state: which account in
      # the container to be. The uid, the gid and the home are facts about that
      # account, and the container already carries them -- in the passwd its own
      # activation script wrote, which is the very file nspawn resolves --user
      # against. Read them from there and there is nothing for a declaration to
      # disagree with.
      #
      # Declaring them meant keeping two copies in step, and a mismatch was an
      # error nowhere: nspawn resolved --user in there while the launcher chowned
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

        # Would otherwise pin this moment's DNS for the life of the boot.
        # nspawn binds a fresh one in per session instead, since --resolv-conf
        # defaults to auto and a session shares the host's network.
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
    in
    pkgs.writeShellApplication {
      inherit name;
      runtimeInputs = [ pkgs.git pkgs.coreutils pkgs.util-linux pkgs.e2fsprogs ] ++ c.launcherInputs;
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
        # --user against. Everything the launcher creates for the payload out
        # here -- TMPDIR, the tmpfs entries, the overlay uppers -- is owned from
        # these, so they cannot disagree with what the container thinks.
        read_identity "$prepared"

        # nspawn removes its own unix-export mount on a clean exit; a SIGKILL
        # leaves it and the next run refuses to start. No trap survives
        # SIGKILL, so this is swept on the way in instead.
        #
        # Liveness is the owning pid, which is in the name and alive from
        # before the directory exists. Asking machined is racy: a session that
        # has copied its root but not yet started nspawn is not registered, and
        # a concurrent launch would delete it.
        for d in ${cache}/s-*; do
          [ -e "$d" ] || continue
          stale=''${d##*/s-}
          owner=''${stale#${c.container}-}; owner=''${owner%%-*}
          [ -d "/proc/$owner" ] && continue
          ${machinectl} show "$stale" >/dev/null 2>&1 && continue
          umount "/run/systemd/nspawn/unix-export/$stale" 2>/dev/null || true
          rm -rf "$d" "/run/systemd/nspawn/unix-export/$stale"
        done

        # Unique per invocation, not per workspace, so two sessions in one
        # directory do not collide either.
        machine=${c.container}-$$-''${RANDOM}
        root=${cache}/s-$machine
        cp -a "$prepared" "$root"

        # An inherited TMPDIR names a host path that is absent or root-owned in
        # there, so the payload gets one of its own. Made out here, in the
        # session's root, because nothing inside the container is ever root:
        # the launcher is the only privileged thing in a session, and it is on
        # this side of nspawn.
        mkdir -p "$root$home/tmp"
        chown "$uid:$gid" "$root$home/tmp"
        chmod 0700 "$root$home/tmp"
        ${mountpointMkdirs}

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

        # NOT exec: that would replace the shell and discard the trap with it.
        # shellcheck disable=SC2329  # invoked by the trap, not by name.
        cleanup() {
          umount "/run/systemd/nspawn/unix-export/$machine" 2>/dev/null || true
          rm -rf "$root" "/run/systemd/nspawn/unix-export/$machine"
        }
        trap cleanup EXIT

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

        # --keep-unit, or nspawn makes a scope of its own and these properties
        # apply to nothing. tini rather than --as-pid2, whose stub reaps
        # orphans but does not forward SIGTERM to the payload.
        #
        # --user, so nspawn drops before it starts pid 1: tini, the payload
        # script and `command` with it all run as `user`, and no process
        # inside the container is ever root. It resolves the name against the
        # container's own passwd -- which is what preparing the root produces
        # -- and initialises the supplementary groups from its group file, so
        # a user declared into `audio` arrives in it.
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
        rc=0
        ${systemdRun} --scope --quiet --unit="$machine" --slice=machine.slice \
          --property=DevicePolicy=closed ${deviceProps} ${resourceProps} -- \
          ${nspawn} -q --keep-unit --directory="$root" --machine="$machine" \
            --hostname=${lib.escapeShellArg c.container} \
            --console=autopipe \
            ${networkFlags} \
            --kill-signal=SIGTERM \
            --bind-ro=/nix/store --bind-ro=/nix/var/nix/db \
            --bind-ro=${closure}:/run/current-system \
            ''${binds[@]+"''${binds[@]}"} \
            --bind="$workspace:$workspace" \
            ''${extra_flags[@]+"''${extra_flags[@]}"} \
            ''${tmpfs_flags[@]+"''${tmpfs_flags[@]}"} ${overlayFlags} \
            --user=${c.user} \
            --setenv=PATH=${closure}/sw/bin \
            --setenv=TMPDIR="$home/tmp" \
            --setenv=XDG_RUNTIME_DIR="$runtime_dir" \
            --setenv=FLONG_EXTRA_BINDS="$(joined "$extra_binds")" \
            --setenv=FLONG_EXTRA_BINDS_RO="$(joined "$extra_binds_ro")" \
            ${pkgs.tini}/bin/tini -g -- \
            ${lib.getExe payload} "$workspace" "$@" || rc=$?
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

        properties = lib.mkOption {
          type = lib.types.attrsOf lib.types.str;
          default = { };
          example = { MemoryMax = "8G"; CPUQuota = "400%"; };
          description = ''
            systemd properties applied to the session's scope, as
            `--property=NAME=VALUE`. See
            {manpage}`systemd.resource-control(5)`.

            Worth setting because a session's root, its TMPDIR and every
            overlay upper live under /run, which is RAM: `MemoryMax` is what
            makes a payload that fills one the session's problem rather than
            the host's.
          '';
        };

        launcherInputs = lib.mkOption {
          type = lib.types.listOf lib.types.package;
          default = [ ];
          description = "Extra packages on PATH for `guard` and `workspace`.";
        };
        payloadInputs = lib.mkOption {
          type = lib.types.listOf lib.types.package;
          default = [ ];
          description = "Extra packages on PATH for `command`.";
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
          # Only meaningful with a network namespace to configure, and each one
          # needs an interface brought up and addressed from inside the
          # container -- which a session has no privileged moment to do.
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

              If a file-capability binary in the closure genuinely needs one in
              the bounding set, ask for it deliberately with
              containers.${c.container}.extraFlags = [ "--capability=..." ],
              which flong passes through.
            '';
          }
          {
            assertion = ! lib.any (x: x) needsInside;
            message = ''
              flong.${n} drives containers.${c.container}, which declares a
              veth, a bridge, a macvlan, a moved interface or a forwarded port.
              flong does not build those yet. It refuses them rather than
              dropping them, because a declaration that quietly does not happen
              is worse than a build that stops.

              Not impossible, only unwritten, and by a different mechanism than
              the container module uses: each of these leaves an interface for
              the container's own init to bring up, and a session has none --
              but the launcher is root on the host, and a namespace can be
              built, addressed and routed out there before nspawn is called.
              See PLAN.md.

              What works today is `privateNetwork` (loopback and nothing else)
              or `networkNamespace`, pointed at a namespace something else
              already built.
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
