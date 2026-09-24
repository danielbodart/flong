# The prepared root's two programs, moved out of module.nix unchanged so
# that native.nix can compile the cache tool's path into flong (-Dcache,
# DESIGN.md, "The native launcher") while module.nix names the same store
# paths: steps8, the cache's name, is a hash of cacheTool's path.
#
# pkgs defaults to the flake's locked nixpkgs, as native.nix's does.
{
  pkgs ?
    let
      locked = (builtins.fromJSON (builtins.readFile ./flake.lock)).nodes.nixpkgs.locked;
    in
    import (fetchTarball {
      url = "https://github.com/${locked.owner}/${locked.repo}/archive/${locked.rev}.tar.gz";
      sha256 = locked.narHash;
    }) { },
}:
let
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
in
{
  inherit prepareInner cacheTool;
}
