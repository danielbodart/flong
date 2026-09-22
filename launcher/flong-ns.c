/* flong-ns.c: the two user namespaces, U1 and U2.
 *
 * Each namespace is made by a process that unshares it and then waits, so
 * the namespace lives while it is opened and mapped. That process is ours
 * and unreaped until we have the namespace open, so its pid cannot name
 * anyone else when we open /proc/<pid>/ns/user.
 *
 * Every helper blocks only on pipes whose other end the launcher or another
 * helper holds, and ends when it reads EOF. So the launcher releases helpers
 * by closing its pipe ends, on success and on failure alike, and a launcher
 * that dies releases them the same way. Every wait in the launcher is an
 * fl_await, so a terminating signal aborts the launch at any step.
 */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "flong-ns.h"
#include "flong-util.h"

/* The longest decimal an unsigned long can print, with its NUL. */
#define DIGITS 21

/* Reaps a helper that closed its pipe before it was done. A helper that
 * failed has said why and exited 125; any other status (a signal, say) is
 * reported here, so a failure is never silent. */
static void helper_failed(int *pidfd, const char *what)
{
	int st = fl_reap(*pidfd);

	if (st < 0)
		return;
	fl_close(pidfd);
	if (st != 125)
		fl_errx("%s ended with status %d before it was done", what, st);
}

/* Reads len bytes a helper sends in one write (at most PIPE_BUF, so they
 * arrive together). Returns 1 when they came, 0 on EOF (the helper ended
 * first), -1 on error or a terminating signal. */
static int await_msg(int fd, void *buf, size_t len)
{
	ssize_t n;

	if (fl_await(fd, POLLIN) < 0)
		return -1;
	n = read(fd, buf, len);
	if (n < 0)
		return fl_err("read from a namespace helper");
	return (size_t)n == len;
}

/* newuidmap's or newgidmap's argv: the program, U1's pid, then each
 * extent's inside, outside and count. One allocation holds the pointers and
 * the digits, so the caller frees it with one free. */
static char **map_argv(const char *prog, pid_t pid, const struct fl_idmap *m, size_t n)
{
	size_t nargs = 2 + 3 * n;
	char **v = malloc((nargs + 1) * sizeof *v + (1 + 3 * n) * DIGITS);
	char *d;

	if (!v) {
		fl_err("malloc");
		return NULL;
	}
	d = (char *)(v + nargs + 1);
	v[0] = (char *)prog;
	v[1] = d;
	d += snprintf(d, DIGITS, "%d", (int)pid) + 1;
	for (size_t i = 0; i < n; i++) {
		unsigned long f[3] = { m[i].inside, m[i].outside, m[i].count };
		for (int j = 0; j < 3; j++) {
			v[2 + 3 * i + j] = d;
			d += snprintf(d, DIGITS, "%lu", f[j]) + 1;
		}
	}
	v[nargs] = NULL;
	return v;
}

/* U2's map text: U1's extents with each outside id replaced by the inside
 * one. U2's ids are then U1's ids unchanged. It must follow U1's extents:
 * the kernel wants each U2 extent inside a single U1 extent, so one
 * "0 0 65536" is EPERM. */
static char *identity_map(const struct fl_idmap *m, size_t n)
{
	char *t = malloc(n * 3 * DIGITS + 1), *p = t;

	if (!t) {
		fl_err("malloc");
		return NULL;
	}
	*p = '\0';
	for (size_t i = 0; i < n; i++)
		p += sprintf(p, "%lu %lu %lu\n", m[i].inside, m[i].inside, m[i].count);
	return t;
}

/* U1's child: unshares, says so, and holds U1 until the launcher closes
 * the hold pipe. */
static _Noreturn void u1_child(int up, int hold)
{
	char c;
	ssize_t n;

	if (unshare(CLONE_NEWUSER) < 0)
		fl_die("unshare a user namespace (U1)");
	if (write(up, "u", 1) != 1)
		_exit(125);
	n = read(hold, &c, 1);
	_exit(n < 0 ? 125 : 0);
}

/* Starts one map program for U1's child. */
static int spawn_map(const char *prog, pid_t pid, const struct fl_idmap *m, size_t n, int *pidfd)
{
	char **argv = map_argv(prog, pid, m, n);
	struct fl_spawn sp = { .argv = argv, .envp = NULL, .cgroup = -1, .stdio = NULL,
	                       .keep = NULL, .nkeep = 0, .dir = NULL };

	if (!argv)
		return -1;
	*pidfd = fl_spawn(&sp, NULL);
	free(argv);
	return *pidfd < 0 ? -1 : 0;
}

/* Reports a map program that failed. 127 is an exec failure, which the
 * spawned child has already reported. */
static void map_failed(const char *prog, int st, const char *file, const char *option)
{
	if (st != 127)
		fl_errx("%s failed (status %d): the caller needs a range of at least 65536 ids "
		        "in %s (users.users.<name>.%s)", prog, st, file, option);
}

/* The user namespace pid is in, held by a descriptor, or -1. */
static int open_userns(pid_t pid)
{
	char path[64];
	snprintf(path, sizeof path, "/proc/%d/ns/user", (int)pid);
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		fl_err("open %s", path);
	return fd;
}

static int make_u1(const struct fl_spec *s, int *u1)
{
	int up[2] = { -1, -1 }, hold[2] = { -1, -1 };
	int child = -1, umap = -1, gmap = -1, fd = -1, keep[2], su, sg, rc = -1;
	char c;
	pid_t pid;

	if (pipe2(up, O_CLOEXEC) < 0 || pipe2(hold, O_CLOEXEC) < 0) {
		fl_err("pipe");
		goto out;
	}
	keep[0] = up[1];
	keep[1] = hold[0];
	pid = fl_fork(-1, keep, 2, &child);
	if (pid < 0)
		goto out;
	if (pid == 0)
		u1_child(up[1], hold[0]);
	fl_close(&up[1]);
	fl_close(&hold[0]);

	switch (await_msg(up[0], &c, 1)) {
	case -1:
		goto out;
	case 0:
		helper_failed(&child, "U1's child");
		goto out;
	}

	/* newuidmap and newgidmap run together: each is a setuid program that
	 * reads /etc/subuid or /etc/subgid, and neither needs the other. */
	if (spawn_map(FLONG_NEWUIDMAP, pid, s->uidmap, s->nuidmap, &umap) < 0 ||
	    spawn_map(FLONG_NEWGIDMAP, pid, s->gidmap, s->ngidmap, &gmap) < 0)
		goto out;
	if ((su = fl_reap(umap)) < 0)
		goto out;
	fl_close(&umap);
	if ((sg = fl_reap(gmap)) < 0)
		goto out;
	fl_close(&gmap);
	if (su)
		map_failed("newuidmap", su, "/etc/subuid", "subUidRanges");
	if (sg)
		map_failed("newgidmap", sg, "/etc/subgid", "subGidRanges");
	if (su || sg)
		goto out;

	fd = open_userns(pid);
	if (fd < 0)
		goto out;
	fl_close(&hold[1]);
	if (fl_reap(child) < 0)
		goto out;
	fl_close(&child);
	*u1 = fd;
	fd = -1;
	rc = 0;
	fl_trace("U1-mapped");
out:
	fl_close(&fd);
	fl_close(&up[0]);
	fl_close(&up[1]);
	fl_close(&hold[0]);
	fl_close(&hold[1]);
	fl_reap_now(&umap, 1);
	fl_reap_now(&gmap, 1);
	fl_reap_now(&child, 0);
	return rc;
}

/* Ends U2's helper when U2's child is not done: reaps the child, so no
 * orphan is left, and exits 125. With report, the child ended by itself and
 * its status is reported unless it said why itself (125). Without, the
 * helper has reported its own failure and closed the child's pipe, which
 * ends the child. The helper has no signalfd, so the reap waits only for
 * the child's pidfd. */
static _Noreturn void u2_end(int *gfd, int report)
{
	if (report)
		helper_failed(gfd, "U2's child");
	else
		fl_reap_now(gfd, 0);
	_exit(125);
}

/* U2's child: unshares U2 from inside U1, waits for its maps, then limits
 * nested user namespaces. The limit is U2's own user.max_user_namespaces,
 * which only a process in U2 with its capabilities can write, and this
 * process has them as U2's creator. It then holds U2 until the launcher
 * closes the release pipe. */
static _Noreturn void u2_child(int up, int maps, int rel, unsigned long maxns)
{
	char c, n[DIGITS];
	ssize_t r;

	if (unshare(CLONE_NEWUSER) < 0)
		fl_die("unshare a user namespace (U2)");
	if (write(up, "u", 1) != 1 || read(maps, &c, 1) != 1)
		_exit(125);
	snprintf(n, sizeof n, "%lu", maxns);
	if (fl_write_at(AT_FDCWD, "/proc/sys/user/max_user_namespaces", n) < 0)
		_exit(125);
	if (write(up, "n", 1) != 1)
		_exit(125);
	r = read(rel, &c, 1);
	_exit(r < 0 ? 125 : 0);
}

/* U2's helper, in U1. Writing a namespace's maps needs a process in its
 * parent namespace with CAP_SETUID and CAP_SETGID there: U1's owner has
 * every capability in U1 once it joins it, and the launcher stays outside.
 * The helper sends U2's child's pid and then waits for that child, so the
 * pid stays the child's, even a dead one's, until the launcher has opened
 * U2 and released it. */
static _Noreturn void u2_helper(int u1, int rep, int rel, unsigned long maxns,
                                const char *uidmap, const char *gidmap)
{
	int a[2], b[2], keep[3], gfd;
	char path[64], c;
	pid_t g;

	if (setns(u1, CLONE_NEWUSER) < 0)
		fl_die("join U1");
	if (pipe2(a, O_CLOEXEC) < 0 || pipe2(b, O_CLOEXEC) < 0)
		fl_die("pipe");
	keep[0] = a[1];
	keep[1] = b[0];
	keep[2] = rel;
	g = fl_fork(-1, keep, 3, &gfd);
	if (g < 0)
		_exit(125);
	if (g == 0)
		u2_child(a[1], b[0], rel, maxns);
	close(a[1]);
	close(b[0]);
	close(rel);

	if (read(a[0], &c, 1) != 1)
		u2_end(&gfd, 1);
	snprintf(path, sizeof path, "/proc/%d/uid_map", (int)g);
	if (fl_write_at(AT_FDCWD, path, uidmap) < 0)
		goto fail;
	snprintf(path, sizeof path, "/proc/%d/gid_map", (int)g);
	if (fl_write_at(AT_FDCWD, path, gidmap) < 0)
		goto fail;
	if (write(b[1], "m", 1) != 1) {
		fl_err("release U2's child");
		goto fail;
	}
	if (read(a[0], &c, 1) != 1)
		u2_end(&gfd, 1);
	/* The launcher ends the child by closing the release pipe, also when
	 * this write fails because it has given up. */
	if (write(rep, &g, sizeof g) != (ssize_t)sizeof g)
		fl_err("send U2's pid");
	_exit(fl_reap(gfd) == 0 ? 0 : 125);
fail:
	close(b[1]);
	u2_end(&gfd, 0);
}

static int make_u2(const struct fl_spec *s, int u1, int *u2)
{
	int rep[2] = { -1, -1 }, rel[2] = { -1, -1 };
	int helper = -1, fd = -1, keep[3], st, rc = -1;
	char *uidmap = identity_map(s->uidmap, s->nuidmap);
	char *gidmap = identity_map(s->gidmap, s->ngidmap);
	pid_t pid, g;

	if (!uidmap || !gidmap)
		goto out;
	if (pipe2(rep, O_CLOEXEC) < 0 || pipe2(rel, O_CLOEXEC) < 0) {
		fl_err("pipe");
		goto out;
	}
	keep[0] = u1;
	keep[1] = rep[1];
	keep[2] = rel[0];
	pid = fl_fork(-1, keep, 3, &helper);
	if (pid < 0)
		goto out;
	if (pid == 0)
		u2_helper(u1, rep[1], rel[0], s->nested_userns, uidmap, gidmap);
	fl_close(&rep[1]);
	fl_close(&rel[0]);

	switch (await_msg(rep[0], &g, sizeof g)) {
	case -1:
		goto out;
	case 0:
		helper_failed(&helper, "U2's helper");
		goto out;
	}
	fd = open_userns(g);
	if (fd < 0)
		goto out;
	fl_close(&rel[1]);
	if ((st = fl_reap(helper)) < 0)
		goto out;
	fl_close(&helper);
	if (st) {
		fl_errx("U2's helper ended with status %d after U2 was made", st);
		goto out;
	}
	*u2 = fd;
	fd = -1;
	rc = 0;
	fl_trace("U2-made");
out:
	fl_close(&fd);
	fl_close(&rep[0]);
	fl_close(&rep[1]);
	fl_close(&rel[0]);
	fl_close(&rel[1]);
	fl_reap_now(&helper, 0);
	free(uidmap);
	free(gidmap);
	return rc;
}

int ns_create(const struct fl_spec *s, struct fl_userns *ns)
{
	ns->u1 = -1;
	ns->u2 = -1;
	if (make_u1(s, &ns->u1) < 0)
		return -1;
	if (make_u2(s, ns->u1, &ns->u2) < 0) {
		fl_close(&ns->u1);
		return -1;
	}
	return 0;
}
