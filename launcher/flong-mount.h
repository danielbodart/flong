/* flong-mount.h: every flong-level mount, through an fd walker.
 *
 * bwrap resolves nested destinations by path and follows symlinks a payload
 * planted: under a concurrent session swapping a directory for a symlink it
 * escaped 60-65 of 200 launches. So bwrap mounts only fixed destinations in
 * fresh filesystems, and everything else (declared binds, tmpfs, overlays,
 * masks, devices, the workspace, caller binds, ~/tmp, /sys) is mounted here,
 * after bwrap has built the root and before the gate opens. The walker
 * escaped 0 of 400.
 *
 * The helper is a forked child of flong-launch, created with fl_fork in the
 * session's sandbox leaf. In order:
 *   1. Opens the leader's mnt, net and cgroup namespaces through its pidfd
 *      (PIDFD_GET_*_NAMESPACE), as the caller, before it joins U1.
 *   2. Joins U1 and becomes its root: it owns U1, so it has every capability
 *      over the session's namespaces and none over anything else.
 *   3. Unshares a mount namespace of its own (owned by U1), a copy of the
 *      host's, and prepares every source there, with fsuid and fsgid set to
 *      the payload's ids so a source is reached with the caller's own reach:
 *      a source opened by the caller's rules is cloned with
 *      open_tree(OPEN_TREE_CLONE|AT_RECURSIVE) from its fd; an exact source
 *      (caller binds, the workspace) is opened with openat2 from / with
 *      RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS, so a symlink met now is a
 *      race and ends the launch; an overlay is built detached, its upper and
 *      work directories on a detached tmpfs, the upper the payload's. Every
 *      source's canonical path (readlink of /proc/self/fd/N) is checked
 *      against the protected paths.
 *      All this overlaps bwrap's own setup.
 *   4. Reads the ready byte. EOF means bwrap failed before its child was
 *      ready: the helper fails.
 *   5. Joins the session's mount namespace. /sys first: joins the
 *      session's network and cgroup namespaces (the payload's own, rooted
 *      at the sandbox leaf, which holds the limits), mounts a fresh
 *      read-only sysfs on /sys and a read-only cgroup2 on its fs/cgroup,
 *      then detaches and removes /.hostsys, the host sysfs bwrap bound there
 *      only because the kernel refuses a fresh sysfs unless one is already
 *      visible. It comes before the declared mounts, so one under /sys lands
 *      on the session's sysfs (or fails: sysfs is read-only and has no room
 *      for a new directory) instead of being covered by it.
 *   6. Walks each destination from the root, one component at a time, with
 *      openat2(RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_BENEATH),
 *      mkdirat on the parent fd for what is missing, and attaches with
 *      move_mount(MOVE_MOUNT_T_EMPTY_PATH) onto the final O_PATH fd. Nothing
 *      is resolved by name twice. Mounts go in destination order, parents
 *      first; the same destination twice is refused.
 *   7. Makes /run read-only, last, because declarations bind under /run.
 *
 * Walk rule: a symlink anywhere on the way, the last component included,
 * ends the launch with "a symlink is on the way to <dest>". Directories made
 * on the way: on the session's own mounts (its root, and each tmpfs and
 * overlay made here) as container root, chowned to the payload inside home;
 * on a host bind, with setfsuid/setfsgid set to the payload's ids, so the
 * kernel checks the write as the caller's and the directory is the caller's
 * on the host. A file source gets a file made at its destination.
 *
 * Masks: a mode-0 read-only node of the target's kind (a directory: an empty
 * tmpfs; a file: a mode-0 file on a tmpfs, bound alone), noexec, owned by
 * U1's mount namespace, so the payload in U2 gets EPERM on umount. The target
 * must exist.
 */
#ifndef FLONG_MOUNT_H
#define FLONG_MOUNT_H

#include <sys/types.h>
#include "flong-spec.h"

struct fl_mount_job {
	int u1;                       /* U1, from ns_create */
	int leader_pidfd;             /* pidfd of bwrap's child, the session's pid 1 */
	int ready;                    /* read end of the ready pipe */
	const struct fl_mount *mounts;
	size_t nmounts;
	uid_t uid;                    /* the payload, as ids inside the container */
	gid_t gid;
	const char *home;
	const char *const *protect;   /* the spec's protect paths plus the state
	                                 directory and the holder's cgroup, each
	                                 made canonical by the launcher (realpath)
	                                 before the fork */
	size_t nprotect;
};

/* The mount helper's whole life. Runs in the forked child (setns into a user
 * namespace is one-way, so it cannot run in the launcher) and returns its
 * exit status: 0 when every mount, /sys and /run are done, 1 after printing
 * why not. The launcher calls _exit(mount_run(&job)) and waits for the
 * helper's pidfd; the gate opens only on 0. */
int mount_run(const struct fl_mount_job *job);
_Noreturn void flong_mount_main(const struct fl_mount_job *job, int tracing);

#endif
