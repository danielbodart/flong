/* flong-mount.c: the mount helper. The specification is flong-mount.h.
 *
 * Everything here runs in one forked, single-threaded child that exits when
 * mount_run returns, so a descriptor left open on a failure path goes with the
 * process: the launcher owns every cleanup that outlives it.
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/mount.h>
#include <linux/openat2.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/pidfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "flong-mount.h"
#include "flong-util.h"

/* Every lookup in the session refuses a symlink, the last component
 * included, and never leaves the directory it starts from. */
#define WALK_RESOLVE (RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_BENEATH)

/* One mount, from its spec to the detached tree that is attached in the
 * session. */
struct src {
	const struct fl_mount *m;
	int tree;                     /* a detached mount; -1 for a mask, made at attach */
	unsigned long long id;        /* the tree's unique mount id, once made */
	int host;                     /* 1: a bind of something on the host (binds, devices) */
};

/* What the walker needs to know about the session. */
struct walker {
	const struct fl_mount_job *job;
	int root;                     /* O_PATH fd of the session's / */
	unsigned long long root_id;
	const struct src *srcs;       /* to tell a host bind from the session's own mounts */
	size_t nsrcs;
};

static int openat2_fd(int dirfd, const char *path, int flags, unsigned long long resolve)
{
	struct open_how how = { .flags = (unsigned long long)(flags | O_CLOEXEC), .resolve = resolve };
	return (int)syscall(SYS_openat2, dirfd, path, &how, sizeof how);
}

/* The unique mount id of the mount fd is on; it is never reused, unlike the
 * old one, and a detached tree keeps it when it is attached. */
static int mount_id(int fd, unsigned long long *id)
{
	struct statx st;
	if (statx(fd, "", AT_EMPTY_PATH, STATX_MNT_ID_UNIQUE, &st) < 0)
		return fl_err("statx");
	*id = st.stx_mnt_id;
	return 0;
}

/* File access as the payload, which U1 maps onto the caller, or as U1 root.
 * setfsuid clears the file capabilities (DAC override among them) while the
 * fsuid is not 0, so a source is reached with the caller's own reach, not
 * with container root's over every subordinate id. setfsuid reports the old
 * value, not failure, so the new one is read back. */
static int fs_ids(uid_t uid, gid_t gid)
{
	setfsgid(gid);
	setfsuid(uid);
	if ((uid_t)setfsuid((uid_t)-1) != uid || (gid_t)setfsgid((gid_t)-1) != gid)
		return fl_errx("cannot take file ids %u:%u", (unsigned)uid, (unsigned)gid);
	return 0;
}

/* ---- sources, in a mount namespace of the helper's own ---- */

/* Whether a and b are the same path or one lies inside the other. Both are
 * canonical. */
static int overlaps(const char *a, const char *b)
{
	size_t la = strlen(a), lb = strlen(b), n = la < lb ? la : lb;
	if (!strcmp(a, "/") || !strcmp(b, "/"))
		return 1;
	if (strncmp(a, b, n))
		return 0;
	return la == lb || (la < lb ? b[la] : a[lb]) == '/';
}

/* Condition 4: no source reaches flong's state, the holder's cgroup or
 * frisket's socket. The path is the one the kernel resolved the fd to, so a
 * symlink or a bind cannot hide where a source really is. */
static int check_protected(const struct fl_mount_job *job, int fd, const char *src)
{
	char link[64], path[PATH_MAX];
	snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
	ssize_t n = readlink(link, path, sizeof path - 1);
	if (n < 0)
		return fl_err("readlink %s", src);
	path[n] = '\0';
	for (size_t i = 0; i < job->nprotect; i++)
		if (overlaps(path, job->protect[i]))
			return fl_errx("the mount source %s is, holds or lies inside %s, which no session may reach",
				       src, job->protect[i]);
	return 0;
}

/* Opens a bind's or an overlay's source as the payload. An exact source is
 * canonical, so a symlink on it now is a race and ends the launch; any other
 * follows symlinks, as its author intended. */
static int open_source(const struct fl_mount_job *job, const struct fl_mount *m, int flags)
{
	int exact = m->kind == FL_BIND_RO_EXACT || m->kind == FL_BIND_RW_EXACT;
	if (fs_ids(job->uid, job->gid) < 0)
		return -1;
	int fd = exact ? openat2_fd(AT_FDCWD, m->src, flags, RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)
		       : open(m->src, flags | O_CLOEXEC);
	int err = errno;
	if (fs_ids(0, 0) < 0) {
		if (fd >= 0)
			close(fd);
		return -1;
	}
	errno = err;
	if (fd < 0 && exact && errno == ELOOP)
		return fl_errx("a symlink is on the way to %s", m->src);
	if (fd < 0)
		return fl_err("mount source %s", m->src);
	if (check_protected(job, fd, m->src) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

/* A bind or a device: a recursive clone of the source, nosuid, nodev unless
 * it is a device, read-only when asked. */
static int prepare_bind(const struct fl_mount_job *job, struct src *s)
{
	const struct fl_mount *m = s->m;
	int fd = open_source(job, m, O_PATH);
	if (fd < 0)
		return -1;
	s->tree = open_tree(fd, "", OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_EMPTY_PATH | AT_RECURSIVE);
	close(fd);
	if (s->tree < 0)
		return fl_err("cannot clone %s", m->src);
	struct mount_attr attr = { .attr_set = MOUNT_ATTR_NOSUID };
	if (m->kind != FL_DEV)
		attr.attr_set |= MOUNT_ATTR_NODEV;
	if (m->kind == FL_BIND_RO || m->kind == FL_BIND_RO_EXACT)
		attr.attr_set |= MOUNT_ATTR_RDONLY;
	if (mount_setattr(s->tree, "", AT_EMPTY_PATH | AT_RECURSIVE, &attr, sizeof attr) < 0)
		return fl_err("cannot restrict %s", m->src);
	s->host = 1;
	return 0;
}

/* A fresh filesystem of type, configured by (key, value) pairs ending in
 * NULL, detached with attrs. */
static int make_fs(const char *type, const char *const *opts, unsigned attrs)
{
	int fs = fsopen(type, FSOPEN_CLOEXEC);
	if (fs < 0)
		return fl_err("fsopen %s", type);
	for (; opts[0]; opts += 2)
		if (fsconfig(fs, FSCONFIG_SET_STRING, opts[0], opts[1], 0) < 0) {
			fl_err("%s %s=%s", type, opts[0], opts[1]);
			close(fs);
			return -1;
		}
	int mnt = -1;
	if (fsconfig(fs, FSCONFIG_CMD_CREATE, NULL, NULL, 0) < 0)
		fl_err("%s", type);
	else if ((mnt = fsmount(fs, FSMOUNT_CLOEXEC, attrs)) < 0)
		fl_err("fsmount %s", type);
	close(fs);
	return mnt;
}

static int prepare_tmpfs(const struct fl_mount_job *job, struct src *s)
{
	const struct fl_mount *m = s->m;
	char uid[16], gid[16];
	const char *opts[10], **o = opts;
	snprintf(uid, sizeof uid, "%u", (unsigned)job->uid);
	snprintf(gid, sizeof gid, "%u", (unsigned)job->gid);
	*o++ = "mode", *o++ = m->mode;
	if (m->size)
		*o++ = "size", *o++ = m->size;
	if (m->owner_user)
		*o++ = "uid", *o++ = uid, *o++ = "gid", *o++ = gid;
	*o = NULL;
	s->tree = make_fs("tmpfs", opts, MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV);
	return s->tree < 0 ? -1 : 0;
}

/* An overlay whose writes go with the session: the lower is read with the
 * payload's reach, the upper and work directories sit on one detached tmpfs
 * that nothing names, and the upper is the payload's. Every layer is passed
 * as a descriptor, so nothing is resolved by name. The overlay itself is
 * made as U1 root, whose credentials it keeps for its own writes. */
static int prepare_overlay(const struct fl_mount_job *job, struct src *s, int *scratch, size_t i)
{
	const struct fl_mount *m = s->m;
	static const char *const scratch_opts[] = { "mode", "0700", NULL };
	char upper[32], work[32];
	int lower = -1, up = -1, wk = -1, fs = -1;

	if (*scratch < 0 && (*scratch = make_fs("tmpfs", scratch_opts, MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV)) < 0)
		return -1;
	snprintf(upper, sizeof upper, "upper%zu", i);
	snprintf(work, sizeof work, "work%zu", i);
	if (mkdirat(*scratch, upper, 0755) < 0 || mkdirat(*scratch, work, 0700) < 0
	    || fchownat(*scratch, upper, job->uid, job->gid, AT_SYMLINK_NOFOLLOW) < 0)
		return fl_err("overlay %s: its upper directory", m->dest);
	if ((lower = open_source(job, m, O_RDONLY | O_DIRECTORY)) < 0)
		return -1;
	if ((up = openat(*scratch, upper, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) < 0
	    || (wk = openat(*scratch, work, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) < 0
	    || (fs = fsopen("overlay", FSOPEN_CLOEXEC)) < 0
	    || fsconfig(fs, FSCONFIG_SET_FD, "lowerdir+", NULL, lower) < 0
	    || fsconfig(fs, FSCONFIG_SET_FD, "upperdir", NULL, up) < 0
	    || fsconfig(fs, FSCONFIG_SET_FD, "workdir", NULL, wk) < 0
	    || fsconfig(fs, FSCONFIG_SET_FLAG, "userxattr", NULL, 0) < 0
	    || fsconfig(fs, FSCONFIG_CMD_CREATE, NULL, NULL, 0) < 0
	    || (s->tree = fsmount(fs, FSMOUNT_CLOEXEC, MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV)) < 0)
		fl_err("overlay %s", m->dest);
	fl_close(&lower);
	fl_close(&up);
	fl_close(&wk);
	fl_close(&fs);
	return s->tree < 0 ? -1 : 0;
}

/* ---- the walk, in the session's mount namespace ---- */

/* Whether the mount fd is on belongs to a host bind: its own tree, or a
 * submount the bind brought along. Climbs parents until it meets a mount made
 * here or the session's root: bwrap's fixed mounts (/run, /tmp) and the root
 * are the session's own. */
static int on_host_bind(const struct walker *w, int fd)
{
	unsigned long long id = 0;
	if (mount_id(fd, &id) < 0)
		return -1;
	for (;;) {
		if (id == w->root_id)
			return 0;
		for (size_t i = 0; i < w->nsrcs; i++)
			if (w->srcs[i].tree >= 0 && w->srcs[i].id == id)
				return w->srcs[i].host;
		struct mnt_id_req req = { .size = MNT_ID_REQ_SIZE_VER0, .mnt_id = id, .param = STATMOUNT_MNT_BASIC };
		struct statmount sm;
		if (syscall(SYS_statmount, &req, &sm, sizeof sm, 0) < 0)
			return fl_err("statmount");
		if (sm.mnt_parent_id == id)
			return 0;
		id = sm.mnt_parent_id;
	}
}

enum want { WANT_FILE, WANT_DIR, WANT_ANY };

/* Makes the missing name in dir, the component of dest that ends at end.
 * On a host bind as the payload, so the kernel checks the write as the
 * caller's and the result is the caller's on the host; on the session's own
 * mounts as container root. Returns 1 when this call made it on the
 * session's own mounts, 2 when it made it on a host bind, 0 when it already
 * existed (a concurrent session made it first), -1 on error. */
static int make_missing(const struct walker *w, int dir, const char *name, int is_dir,
			const char *dest, size_t end)
{
	const struct fl_mount_job *job = w->job;
	int host = on_host_bind(w, dir), r;
	if (host < 0 || (host && fs_ids(job->uid, job->gid) < 0))
		return -1;
	if (is_dir)
		r = mkdirat(dir, name, 0755);
	else if ((r = openat(dir, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644)) >= 0)
		r = close(r);
	int err = errno;
	if (host && fs_ids(0, 0) < 0)
		return -1;
	errno = err;
	if (r == 0)
		return host ? 2 : 1;
	if (errno == EEXIST)
		return 0;
	return fl_err("cannot make %.*s", (int)end, dest);
}

/* Whether dest[0..end) is the payload's home or lies inside it. */
static int in_home(const char *home, const char *dest, size_t end)
{
	size_t hl = strlen(home);
	return end >= hl && !strncmp(dest, home, hl) && (end == hl || dest[hl] == '/');
}

/* Walks dest from the session's root one component at a time and returns an
 * O_PATH fd on it. With create, a missing component is made: a directory on
 * the way, and the last one of the kind wanted. */
static int walk(const struct walker *w, const char *dest, enum want want, int create)
{
	char buf[PATH_MAX];
	if (strlen(dest) >= sizeof buf)
		return fl_errx("%s: the path is too long", dest);
	memcpy(buf, dest, strlen(dest) + 1);

	int cur = dup(w->root);
	if (cur < 0)
		return fl_err("dup");
	for (char *name = buf + 1, *next; name; name = next) {
		next = strchr(name, '/');
		if (next)
			*next++ = '\0';
		int is_dir = next || want == WANT_DIR;
		int flags = O_PATH | (is_dir ? O_DIRECTORY : 0);
		size_t end = (size_t)(name - buf) + strlen(name);
		int fd = openat2_fd(cur, name, flags, WALK_RESOLVE);
		if (fd < 0 && errno == ENOENT && create) {
			int made = make_missing(w, cur, name, is_dir, dest, end);
			if (made < 0) {
				close(cur);
				return -1;
			}
			fd = openat2_fd(cur, name, flags, WALK_RESOLVE);
			/* Made as container root on the session's own mounts:
			 * inside home it is the payload's. Nothing but this
			 * helper can reach those mounts before the gate. */
			if (fd >= 0 && made == 1 && in_home(w->job->home, dest, end)
			    && fchownat(fd, "", w->job->uid, w->job->gid, AT_EMPTY_PATH) < 0) {
				fl_err("cannot give %.*s to the payload", (int)end, dest);
				close(fd);
				close(cur);
				return -1;
			}
		}
		fl_close(&cur);
		if (fd < 0 && errno == ELOOP)
			return fl_errx("a symlink is on the way to %s", dest);
		if (fd < 0 && errno == ENOTDIR && next)
			return fl_errx("%.*s, on the way to %s, is not a directory", (int)end, dest, dest);
		if (fd < 0 && errno == ENOTDIR)
			return fl_errx("%s is not a directory", dest);
		if (fd < 0)
			return fl_err("%s", dest);
		cur = fd;
	}

	struct stat st;
	if (fstat(cur, &st) < 0) {
		fl_err("%s", dest);
		close(cur);
		return -1;
	}
	if (want == WANT_FILE && S_ISDIR(st.st_mode)) {
		close(cur);
		return fl_errx("%s is a directory and its source is not", dest);
	}
	return cur;
}

/* A mask: a mode-0 read-only node of the destination's own kind, so the
 * payload can neither read what it covers nor write to it. A directory gets
 * an empty tmpfs; anything else a mode-0 file on a tmpfs, bound alone. */
static int make_mask(int is_dir)
{
	static const char *const dir_opts[] = { "mode", "0000", NULL };
	static const char *const file_opts[] = { "mode", "0755", NULL };
	unsigned attrs = MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV;
	if (is_dir)
		return make_fs("tmpfs", dir_opts, attrs);

	/* The tmpfs stays writable until the file is on it; the clone that is
	 * bound gets the mask's flags. */
	int fs = make_fs("tmpfs", file_opts, MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV);
	if (fs < 0)
		return -1;
	int f = openat(fs, "mask", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0);
	if (f < 0) {
		fl_err("mask file");
		fl_close(&fs);
		return -1;
	}
	fl_close(&f);
	struct mount_attr attr = { .attr_set = attrs };
	int tree = open_tree(fs, "mask", OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
	if (tree < 0)
		fl_err("open_tree mask file");
	else if (mount_setattr(tree, "", AT_EMPTY_PATH, &attr, sizeof attr) < 0) {
		fl_err("mask file");
		fl_close(&tree);
	}
	fl_close(&fs);
	return tree;
}

/* Attaches one prepared mount at its destination. */
static int attach(const struct walker *w, struct src *s)
{
	const struct fl_mount *m = s->m;
	enum want want = WANT_DIR;
	int create = 1;
	struct stat st;

	if (m->kind == FL_MASK) {
		/* The target must exist: a mask over nothing hides nothing and
		 * would make a node where the declaration expected one. */
		want = WANT_ANY;
		create = 0;
	} else if (s->host) {
		if (fstat(s->tree, &st) < 0)
			return fl_err("%s", m->src);
		want = S_ISDIR(st.st_mode) ? WANT_DIR : WANT_FILE;
	}
	int dest = walk(w, m->dest, want, create);
	if (dest < 0)
		return -1;
	if (m->kind == FL_MASK) {
		if (fstat(dest, &st) < 0 || (s->tree = make_mask(S_ISDIR(st.st_mode))) < 0
		    || mount_id(s->tree, &s->id) < 0) {
			close(dest);
			return -1;
		}
	}
	int r = move_mount(s->tree, "", dest, "", MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH);
	if (r < 0)
		fl_err("cannot mount on %s", m->dest);
	close(dest);
	return r;
}

/* ---- /sys and /run ---- */

/* A fresh read-only filesystem of type at dest. */
static int mount_fresh(const struct walker *w, const char *type, const char *dest, int create)
{
	unsigned attrs = MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC;
	int mnt = make_fs(type, (const char *const[]){ NULL }, attrs), fd, r = -1;
	if (mnt < 0)
		return -1;
	if ((fd = walk(w, dest, WANT_DIR, create)) >= 0) {
		if ((r = move_mount(mnt, "", fd, "", MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH)) < 0)
			fl_err("cannot mount %s on %s", type, dest);
		close(fd);
	}
	close(mnt);
	return r;
}

/* The kernel refuses a fresh sysfs unless one is fully visible in the mount
 * namespace, so bwrap bound the host's at /.hostsys. A sysfs made in the
 * session's network namespace shows only the session's interfaces. cgroup2
 * is mounted from the payload's own cgroup namespace, which bwrap rooted at
 * the sandbox leaf, so the mount's root is the cgroup /proc/self/cgroup
 * names, "/": Go uses a cgroup2 mount only when its root is a prefix of that
 * path, and it, nproc, Node and Java read the declared limits there. The
 * leaf is the namespace's root, whose files nsdelegate keeps the payload from
 * writing. */
static int mount_sys(const struct walker *w, int net, int cgns)
{
	if (setns(net, CLONE_NEWNET) < 0)
		return fl_err("setns the session's network namespace");
	if (setns(cgns, CLONE_NEWCGROUP) < 0)
		return fl_err("setns the session's cgroup namespace");
	/* /sys may be missing from the root; /sys/fs/cgroup is sysfs's own and
	 * cannot be made. */
	if (mount_fresh(w, "sysfs", "/sys", 1) < 0 || mount_fresh(w, "cgroup2", "/sys/fs/cgroup", 0) < 0)
		return -1;
	/* /.hostsys is on the root, which only this helper can change before
	 * the gate, so it is named by path. */
	if (umount2("/.hostsys", MNT_DETACH | UMOUNT_NOFOLLOW) < 0)
		return fl_err("cannot detach /.hostsys");
	if (unlinkat(w->root, ".hostsys", AT_REMOVEDIR) < 0)
		return fl_err("cannot remove /.hostsys");
	return 0;
}

/* /run read-only, the tmpfs itself only: the mounts under it keep their own
 * flags, and /run/user/<uid> stays writable. */
static int run_readonly(const struct walker *w)
{
	struct mount_attr attr = { .attr_set = MOUNT_ATTR_RDONLY };
	int fd = walk(w, "/run", WANT_DIR, 0);
	if (fd < 0)
		return -1;
	int r = mount_setattr(fd, "", AT_EMPTY_PATH, &attr, sizeof attr);
	if (r < 0)
		fl_err("cannot make /run read-only");
	close(fd);
	return r;
}

/* ---- the helper ---- */

static int by_dest(const void *a, const void *b)
{
	return strcmp(((const struct src *)a)->m->dest, ((const struct src *)b)->m->dest);
}

/* Blocks until flong-init writes its byte, which it does once bwrap has
 * built the whole root. EOF means bwrap failed before its child was ready. */
static int await_ready(int fd)
{
	char c;
	ssize_t n;
	while ((n = read(fd, &c, 1)) < 0 && errno == EINTR)
		;
	if (n < 0)
		return fl_err("the ready pipe");
	if (n == 0)
		return fl_errx("the sandbox never became ready");
	return 0;
}

static int helper(const struct fl_mount_job *job)
{
	struct walker w = { .job = job, .root = -1 };
	struct src *srcs = calloc(job->nmounts ? job->nmounts : 1, sizeof *srcs);
	int mnt, net, cgns, scratch = -1;

	if (!srcs)
		return fl_err("calloc");
	/* Directories made on the way are 0755 whatever the caller's umask:
	 * a 0700 root-owned /srv would hide a bind below it from the payload. */
	umask(022);

	/* Parents first, and the same destination twice is refused. Checked
	 * before any work so a bad spec costs nothing; spec_parse has already
	 * made each destination an absolute path of plain components. */
	for (size_t i = 0; i < job->nmounts; i++)
		srcs[i] = (struct src){ .m = &job->mounts[i], .tree = -1 };
	qsort(srcs, job->nmounts, sizeof *srcs, by_dest);
	for (size_t i = 1; i < job->nmounts; i++)
		if (!strcmp(srcs[i - 1].m->dest, srcs[i].m->dest))
			return fl_errx("%s is mounted twice", srcs[i].m->dest);

	/* 1. The leader's namespaces, through the pidfd the launcher opened at
	 *    child-pid: the process is never looked up by its number again,
	 *    and only the caller may ask. */
	if ((mnt = ioctl(job->leader_pidfd, PIDFD_GET_MNT_NAMESPACE, 0)) < 0)
		return fl_err("the session's mount namespace");
	if ((net = ioctl(job->leader_pidfd, PIDFD_GET_NET_NAMESPACE, 0)) < 0)
		return fl_err("the session's network namespace");
	if ((cgns = ioctl(job->leader_pidfd, PIDFD_GET_CGROUP_NAMESPACE, 0)) < 0)
		return fl_err("the session's cgroup namespace");

	/* 2. U1 root: every capability over the session's namespaces, none
	 *    over anything the caller could not already touch. */
	if (setns(job->u1, CLONE_NEWUSER) < 0)
		return fl_err("setns U1");
	if (setresgid(0, 0, 0) < 0 || setresuid(0, 0, 0) < 0)
		return fl_err("cannot become U1's root");

	/* 3. A copy of the host's mount namespace, owned by U1, where the
	 *    sources are opened and cloned while bwrap builds the root. */
	if (unshare(CLONE_NEWNS) < 0)
		return fl_err("unshare a mount namespace");
	for (size_t i = 0; i < job->nmounts; i++) {
		struct src *s = &srcs[i];
		int r = 0;
		switch (s->m->kind) {
		case FL_BIND_RO:
		case FL_BIND_RW:
		case FL_BIND_RO_EXACT:
		case FL_BIND_RW_EXACT:
		case FL_DEV:
			r = prepare_bind(job, s);
			break;
		case FL_TMPFS:
			r = prepare_tmpfs(job, s);
			break;
		case FL_OVERLAY:
			r = prepare_overlay(job, s, &scratch, i);
			break;
		case FL_MASK:
			break;
		}
		if (r < 0 || (s->tree >= 0 && mount_id(s->tree, &s->id) < 0))
			return -1;
	}

	/* 4. Nothing touches the session's mount namespace before bwrap has
	 *    finished it. */
	if (await_ready(job->ready) < 0)
		return -1;
	fl_trace("sandbox-ready");

	/* 5. The session's mount namespace, and /sys first: a declaration
	 *    under /sys then lands on the session's own sysfs, or fails, where
	 *    a fresh sysfs mounted after it would cover it without a word. */
	if (setns(mnt, CLONE_NEWNS) < 0)
		return fl_err("setns the session's mount namespace");
	if ((w.root = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC)) < 0)
		return fl_err("the session's root");
	if (mount_id(w.root, &w.root_id) < 0)
		return -1;
	if (mount_sys(&w, net, cgns) < 0)
		return -1;

	/* 6. The mounts, parents first. */
	w.srcs = srcs;
	w.nsrcs = job->nmounts;
	for (size_t i = 0; i < job->nmounts; i++)
		if (attach(&w, &srcs[i]) < 0)
			return -1;

	/* 7. /run read-only, last, because declarations bind under /run. */
	return run_readonly(&w);
}

int mount_run(const struct fl_mount_job *job)
{
	return helper(job) < 0 ? 1 : 0;
}
