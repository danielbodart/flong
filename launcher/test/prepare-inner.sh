#!/bin/sh
# prepare-inner.sh STAGING CLOSURE: build a prepared root in STAGING.
#
# Runs as container root in the keep-id namespace, with a mount and a pid
# namespace of its own (launch.sh starts it under asroot). nspawn's mounts are
# replaced by explicit ones: proc, a tmpfs /dev with the usual nodes bound in,
# tmpfs /run and /tmp, read-only /nix/store and /nix/var/nix/db. Then the
# closure's activation and tmpfiles run chrooted, as trunk's prepare does.
set -u
staging=$1 closure=$2

# Never recreate a vanished staging directory: a sweep that renamed the cache
# mid-prepare would otherwise get a cache owned by container root back, which
# locks every later launch out of it. launch.sh holds the cache's shared lock
# across the prepare, so this is the second line.
[ -d "$staging" ] || { echo "prepare-inner: $staging is gone" >&2; exit 1; }

# Container root owns the root and makes every mount point: a caller-made
# skeleton fails tmpfiles with "unsafe path transition" (exit 73).
chown 0:0 "$staging"; chmod 0755 "$staging"
mkdir -p "$staging"/etc "$staging"/proc "$staging"/sys "$staging"/dev "$staging"/run "$staging"/tmp \
	"$staging"/var/lib "$staging"/usr/lib "$staging"/nix/store "$staging"/nix/var/nix/db
mount --make-rprivate /
mount --bind "$staging" "$staging"
mount -t proc proc "$staging/proc"
mount -t tmpfs -o mode=755,nosuid tmpfs "$staging/dev"
for d in null zero full random urandom tty; do touch "$staging/dev/$d"; mount --bind /dev/$d "$staging/dev/$d"; done
mkdir -p "$staging/dev/pts" "$staging/dev/shm"
mount -t tmpfs -o mode=755,nosuid,nodev tmpfs "$staging/run"
mount -t tmpfs -o mode=1777,nosuid,nodev tmpfs "$staging/tmp"
mount --rbind /nix/store "$staging/nix/store"; mount -o remount,bind,ro "$staging/nix/store"
mount --bind /nix/var/nix/db "$staging/nix/var/nix/db"; mount -o remount,bind,ro "$staging/nix/var/nix/db"
env -i PATH="$closure/sw/bin" chroot "$staging" "$closure/sw/bin/bash" -c \
	"$closure/activate; echo ACTIVATE_RC=\$?; systemd-tmpfiles --create --exclude-prefix=/dev; echo TMPFILES_RC=\$?"
# The session gets its own resolv.conf, bound over this path when it has a network.
rm -f "$staging/etc/resolv.conf"
"$closure/sw/bin/systemd-machine-id-setup" --root="$staging"; echo MACHINEID_RC=$?
