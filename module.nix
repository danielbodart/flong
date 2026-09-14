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
      closure = config.containers.${c.container}.path;
      declaredConf = config.environment.etc."nixos-containers/${c.container}.conf".source;

      # allowedDevices is a unit property rather than an nspawn flag, so it is
      # not in that file and is translated here.
      deviceProps = lib.concatMapStringsSep " "
        (d: "--property=DeviceAllow=${lib.escapeShellArg "${d.node} ${d.modifier}"}")
        config.containers.${c.container}.allowedDevices;

      overlayDir = p: ".overlay/" + lib.replaceStrings [ "/" ] [ "_" ] (lib.removePrefix "/" p);

      # A bare --tmpfs mounts root-owned 0755, which the unprivileged payload
      # cannot write to. Default it to the container's user; an entry that
      # names its own options (PATH:opts) is passed through untouched.
      tmpfsFlags = lib.concatMapStringsSep " "
        (p:
          if lib.hasInfix ":" p then "--tmpfs=${p}"
          else "--tmpfs=${p}:mode=0755,uid=${toString c.uid},gid=${toString c.gid}")
        c.tmpfs;
      # An explicit upper inside the session root, not nspawn's empty-string
      # form, which puts it under the host's /var/tmp and leaks it on SIGKILL.
      overlayFlags = lib.concatMapStringsSep " "
        (p: ''--overlay=${c.overlays.${p}}:"$root"/${overlayDir p}:${p}'')
        (lib.attrNames c.overlays);
      # nspawn creates mount points for --bind but not for --overlay or
      # --tmpfs, so a target whose parent does not exist in the root fails the
      # launch. Made here, along with each overlay's upper layer.
      mountpointMkdirs = lib.concatStringsSep "\n        " (
        lib.concatMap
          (p: [
            ''mkdir -p "$root"/${overlayDir p} "$root"${p}''
            # The upper layer receives the payload's writes, so it belongs to
            # the payload's user. Note the MERGED directory still takes its
            # ownership from the lower one.
            ''chown ${toString c.uid}:${toString c.gid} "$root"/${overlayDir p}''
          ])
          (lib.attrNames c.overlays)
        ++ map (p: ''mkdir -p "$root"${lib.head (lib.splitString ":" p)}'') c.tmpfs
      );

      # By absolute path: sudo resets PATH to secure_path, and a copy from pkgs
      # would be a different systemd from the one running as pid 1.
      nspawn = "/run/current-system/sw/bin/systemd-nspawn";
      systemdRun = "/run/current-system/sw/bin/systemd-run";
      machinectl = "/run/current-system/sw/bin/machinectl";

      cache = "/run/flong/${c.container}-"
        + builtins.substring 0 8 (builtins.baseNameOf closure);

      payload = mkPayload name c;
    in
    pkgs.writeShellApplication {
      inherit name;
      runtimeInputs = [ pkgs.git pkgs.coreutils pkgs.util-linux ] ++ c.launcherInputs;
      text = ''
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
          # mktemp gives 0700, and this becomes the container's "/". A root the
          # user cannot traverse cannot reach /nix/store either.
          chmod 0755 "$staging"
          mkdir -p "$staging"/{etc,proc,sys,dev,run,tmp,var/lib,usr/lib,nix/store}
          mkdir -p "$staging/${lib.removePrefix "/" c.home}"
          ${nspawn} -q --directory="$staging" --as-pid2 \
            --bind-ro=/nix/store --bind-ro=/nix/var/nix/db \
            --setenv=PATH=${closure}/sw/bin \
            ${closure}/sw/bin/bash -c ${closure}/activate >/dev/null 2>&1
          # Would otherwise pin this moment's DNS for the life of the boot.
          rm -f "$staging/etc/resolv.conf"
          # Atomic, and the race resolution: a loser discards its copy.
          mv -T "$staging" "$prepared" 2>/dev/null || rm -rf "$staging"
        fi

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
        mkdir -p "$root${c.home}/tmp"
        chown ${toString c.uid}:${toString c.gid} "$root${c.home}/tmp"
        chmod 0700 "$root${c.home}/tmp"
        ${mountpointMkdirs}

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
        rc=0
        ${systemdRun} --scope --quiet --unit="$machine" \
          --property=DevicePolicy=closed ${deviceProps} -- \
          ${nspawn} -q --keep-unit --directory="$root" --machine="$machine" \
            --kill-signal=SIGTERM \
            --bind-ro=/nix/store --bind-ro=/nix/var/nix/db \
            --bind-ro=${closure}:/run/current-system \
            ''${binds[@]+"''${binds[@]}"} \
            --bind="$workspace:$workspace" \
            ''${extra_flags[@]+"''${extra_flags[@]}"} \
            ${tmpfsFlags} ${overlayFlags} \
            --user=${c.user} \
            --setenv=PATH=${closure}/sw/bin \
            --setenv=TMPDIR=${c.home}/tmp \
            --setenv=XDG_RUNTIME_DIR=/run/user/${toString c.uid} \
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
          '';
        };
        uid = lib.mkOption {
          type = lib.types.int;
          description = "That user's uid, which must match the container's.";
        };
        gid = lib.mkOption {
          type = lib.types.int;
          description = "That user's primary gid.";
        };
        home = lib.mkOption {
          type = lib.types.str;
          description = "That user's home inside the container.";
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

    # Bind mounts are recovered by word-splitting EXTRA_NSPAWN_FLAGS, which the
    # NixOS container module writes unescaped. A path holding whitespace does
    # not fail that parse -- it splits into two flags that are each valid and
    # neither correct, so the container silently gets mounts nobody declared.
    # A colon is the same story one level down, inside --bind's own SRC:DEST.
    # Refused at eval, because there is no way to notice it at runtime.
    assertions = lib.concatMap
      (c: lib.concatMap
        (m: map
          (p: {
            assertion = ! lib.any (bad: lib.hasInfix bad p) [ " " "\t" "\n" ":" ];
            message = ''
              flong: containers.${c.container} has a bind mount path that
              cannot survive EXTRA_NSPAWN_FLAGS: "${p}". Whitespace and ':'
              are not expressible there; rename the path.
            '';
          })
          [ m.hostPath m.mountPoint ])
        (lib.attrValues config.containers.${c.container}.bindMounts))
      (lib.attrValues cfg);
  };
}
