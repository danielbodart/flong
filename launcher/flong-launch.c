/* flong-launch: one session, from the wrapper's spec to the payload's exit.
 *
 * The wrapper execs this with the whole spec as arguments (DESIGN.md,
 * "The input contract"). main does the steps of a launch in the order of
 * DESIGN.md's "The launch, in order": sweep, record, U1 and U2, cgroup, bwrap,
 * child-pid, the mount helper after the ready byte, the hook, pasta, the gate,
 * the wait, the teardown. Each step is a call into a module; this file owns
 * the order, bwrap's argv, the hook's and pasta's argv, the gate and the one
 * teardown path.
 *
 * Every resource lives in one struct launch, each descriptor -1 and each pid
 * 0 until it exists. run() returns at the first failure; teardown() looks at
 * what exists and undoes it, whatever stage was reached. The payload runs
 * only once the gate byte is written, and the gate is written only after
 * every earlier step succeeded: flong-init reads EOF otherwise and exits 125.
 *
 * No wait here has a timeout. Each is on a pipe, a pidfd or cgroup.events,
 * through fl_await, and a terminating signal ends it as an event, through
 * fl_sigfd.
 */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <time.h>
#include <unistd.h>

#include "flong-cgroup.h"
#include "flong-mount.h"
#include "flong-ns.h"
#include "flong-record.h"
#include "flong-spec.h"
#include "flong-tty.h"
#include "flong-util.h"

/* Exit statuses of a launch that did not reach its payload (DESIGN.md,
 * "Exit codes"). */
enum { EXIT_NOT_RUN = 125, EXIT_SWEPT = 75 };

/* Everything a launch holds. Descriptors are -1 and pids 0 until they exist,
 * and a pidfd goes back to -1 once its process is reaped, so teardown can
 * tell what is left to undo. */
struct launch {
	struct fl_spec s;

	int state_fd;           /* $XDG_RUNTIME_DIR/flong */
	int sessions_fd;        /* its sessions/ */
	int cache_fd;           /* the cache, locked shared for the launcher's life */
	struct fl_tty tty;
	struct fl_holder holder;
	struct fl_record rec;
	struct fl_userns ns;
	struct fl_cgroup cg;

	const char **protect;   /* the spec's protect paths, the state directory
	                           and the holder, made canonical */
	size_t nprotect;

	int *seccomp;           /* one descriptor per seccomp file, until bwrap has them */
	int info;               /* read end of bwrap's --info-fd, open until exit */
	int ready;              /* read end of flong-init's ready pipe, until the helper has it */
	int gate;               /* write end of the gate */
	int bwrap;              /* bwrap's pidfd */
	pid_t leader;           /* bwrap's child: flong-init, the session's pid 1 */
	int leader_fd;          /* its pidfd */
	int netns;              /* the session's network namespace */
	int helper;             /* the mount helper's pidfd */
	int hook;               /* the postStart hook's pidfd */
	int pasta;              /* the spawned pasta's pidfd; its daemon lives on in the pasta leaf */
	int pasta_pid_file;     /* the memfd pasta writes its pid into */

	int gate_opened;        /* the payload may have run: its status is the launch's */
};

static void launch_init(struct launch *l)
{
	memset(l, 0, sizeof *l);
	l->state_fd = l->sessions_fd = l->cache_fd = -1;
	l->holder.fd = -1;
	l->rec.dirfd = l->rec.fd = -1;
	l->ns.u1 = l->ns.u2 = -1;
	l->cg = (struct fl_cgroup)FL_CGROUP_NONE;
	l->info = l->ready = l->gate = -1;
	l->bwrap = l->leader_fd = l->netns = -1;
	l->helper = l->hook = l->pasta = l->pasta_pid_file = -1;
}

/* ---- small helpers ---- */

/* A formatted string for an argv or the environment, allocated for the
 * life of the process: the argv it goes into is used once and never freed.
 * NULL after reporting the failure; push treats a NULL as a failed push. */
static __attribute__((format(printf, 1, 2))) char *str(const char *fmt, ...)
{
	char *p;
	va_list ap;
	va_start(ap, fmt);
	int n = vasprintf(&p, fmt, ap);
	va_end(ap);
	if (n < 0) {
		fl_err("asprintf");
		return NULL;
	}
	return p;
}

/* A growable argv. Every push is checked once, by argv_done. */
struct argvb {
	char **v;
	size_t n, cap;
	int failed;
};

static void push(struct argvb *a, const char *arg)
{
	if (a->failed)
		return;
	if (!arg) {
		a->failed = 1;
		return;
	}
	if (a->n + 2 > a->cap) {
		size_t cap = a->cap ? a->cap * 2 : 64;
		char **v = realloc(a->v, cap * sizeof *v);
		if (!v) {
			fl_err("realloc");
			a->failed = 1;
			return;
		}
		a->v = v;
		a->cap = cap;
	}
	a->v[a->n++] = (char *)arg;
	a->v[a->n] = NULL;
}

static void push_all(struct argvb *a, const struct fl_argv *v)
{
	for (size_t i = 0; i < v->n; i++)
		push(a, v->v[i]);
}

static char *const *argv_done(struct argvb *a)
{
	return a->failed ? NULL : a->v;
}

/* ---- step 4: the cache ---- */

/* A sweep took the cache away before the lock was granted, so the root this
 * launch was prepared against is going away, or what the path names now is a
 * cache another wrapper made in its place and is still preparing. The wrapper,
 * run again, prepares afresh or waits for that preparer's lock; there is no
 * count, because each turn follows a sweep's rename, an event. The mask and
 * SIGPIPE's disposition survive exec, so they are put back first. */
static int relaunch(const struct launch *l, const sigset_t *oldmask)
{
	if (l->s.relaunch.n == 0) {
		fl_errx("the cache %s was swept before this launch locked it", l->s.cache);
		return EXIT_SWEPT;
	}
	fl_errx("the cache %s was swept before this launch locked it; relaunching", l->s.cache);
	signal(SIGPIPE, SIG_DFL);
	sigprocmask(SIG_SETMASK, oldmask, NULL);
	execv(l->s.relaunch.v[0], l->s.relaunch.v);
	fl_err("exec %s", l->s.relaunch.v[0]);
	return EXIT_NOT_RUN;
}

/* ---- the protected paths ---- */

/* A protected path in the form the mount helper compares sources with: the
 * canonical path, so a bind through a symlink to it is still caught. A path
 * that does not exist yet (a socket directory made later) is canonical up to
 * its longest prefix that exists, with the rest appended as given: a bind of
 * a directory that will contain it must still be caught, and the sources the
 * helper compares are the kernel's resolved paths. */
static const char *canonical(const char *path)
{
	char *p = realpath(path, NULL);
	if (p)
		return p;
	if (errno != ENOENT)
		goto fail;

	/* The prefix is cut at each '/' from the right until it resolves;
	 * "/" always does, so the walk ends. */
	char *prefix = strdup(path);
	if (!prefix) {
		fl_err("strdup");
		return NULL;
	}
	for (;;) {
		char *slash = strrchr(prefix, '/');
		if (!slash) {
			free(prefix);
			errno = ENOENT;
			goto fail;
		}
		*slash = '\0';
		p = realpath(slash == prefix ? "/" : prefix, NULL);
		if (p)
			break;
		if (errno != ENOENT) {
			free(prefix);
			goto fail;
		}
	}
	const char *rest = path + (strlen(prefix) + 1);
	char *joined;
	int n = asprintf(&joined, "%s%s%s", p, strcmp(p, "/") == 0 ? "" : "/", rest);
	free(prefix);
	free(p);
	if (n < 0) {
		fl_err("asprintf");
		return NULL;
	}
	return joined;
fail:
	fl_err("realpath %s", path);
	return NULL;
}

/* The spec's protect paths, plus the state directory (records make the sweep
 * run programs) and the holder's cgroup (cgroup.kill), which the launcher
 * adds itself: condition 4 of the plan. */
static int protect_paths(struct launch *l)
{
	size_t n = l->s.nprotect + 2;
	l->protect = calloc(n, sizeof *l->protect);
	if (!l->protect)
		return fl_err("calloc");
	for (size_t i = 0; i < l->s.nprotect; i++)
		if (!(l->protect[l->nprotect++] = canonical(l->s.protect[i])))
			return -1;
	if (!(l->protect[l->nprotect++] = canonical(l->s.state)))
		return -1;
	if (!(l->protect[l->nprotect++] = canonical(l->holder.path)))
		return -1;
	return 0;
}

/* ---- step 12: bwrap ---- */

/* flong-init's <groups> argument: comma-separated gids, or "-". */
static char *groups_arg(const struct fl_spec *s)
{
	if (s->ngroups == 0)
		return "-";
	size_t size = s->ngroups * 12;
	char *out = malloc(size), *p = out;
	if (!out) {
		fl_err("malloc");
		return NULL;
	}
	for (size_t i = 0; i < s->ngroups; i++)
		p += snprintf(p, size - (size_t)(p - out), "%s%lu", i ? "," : "",
			      (unsigned long)s->groups[i]);
	return out;
}

/* bwrap's argv, in DESIGN.md's order ("The input contract"): the fixed
 * part, the wrapper's bwrap-args, then flong-init and its protocol. The
 * fixed part comes first so nothing the wrapper adds can undo it, and
 * flong-init's protocol is its argv, after everything, so a --clearenv among
 * the wrapper's options cannot drop it. */
static char *const *bwrap_argv(const struct launch *l, int info_w, int ready_w, int gate_r)
{
	const struct fl_spec *s = &l->s;
	struct argvb a = { 0 };
	char *run_user = str("/run/user/%lu", (unsigned long)s->uid);

	push(&a, FLONG_BWRAP);
	push(&a, "--userns"); push(&a, str("%d", l->ns.u1));
	push(&a, "--userns2"); push(&a, str("%d", l->ns.u2));
	/* nestedSandbox gives U2 user namespaces of its own; bwrap would
	 * refuse them otherwise. */
	if (s->nested_userns == 0)
		push(&a, "--assert-userns-disabled");
	push(&a, "--unshare-net"); push(&a, "--unshare-pid"); push(&a, "--unshare-ipc");
	push(&a, "--unshare-uts"); push(&a, "--unshare-cgroup");
	push(&a, "--die-with-parent"); push(&a, "--as-pid-1");
	push(&a, "--info-fd"); push(&a, str("%d", info_w));
	/* Only a relayed pty gets a session of its own: in passthrough a new
	 * session would break ^C, SIGWINCH and job control on the caller's
	 * terminal. */
	if (l->tty.relay)
		push(&a, "--new-session");
	for (size_t i = 0; i < s->nseccomp; i++) {
		push(&a, "--add-seccomp-fd"); push(&a, str("%d", l->seccomp[i]));
	}
	/* For flong-init's setgroups and capability drop, which leaves the
	 * payload with none. */
	push(&a, "--cap-add"); push(&a, "CAP_SETGID");
	push(&a, "--cap-add"); push(&a, "CAP_SETPCAP");
	push(&a, "--uid"); push(&a, str("%lu", (unsigned long)s->uid));
	push(&a, "--gid"); push(&a, str("%lu", (unsigned long)s->gid));
	push(&a, "--overlay-src"); push(&a, str("%s/prepared", s->cache)); push(&a, "--tmp-overlay"); push(&a, "/");
	push(&a, "--ro-bind"); push(&a, "/nix/store"); push(&a, "/nix/store");
	push(&a, "--ro-bind"); push(&a, "/nix/var/nix/db"); push(&a, "/nix/var/nix/db");
	push(&a, "--proc"); push(&a, "/proc");
	push(&a, "--dev"); push(&a, "/dev");
	push(&a, "--perms"); push(&a, "0755"); push(&a, "--tmpfs"); push(&a, "/run");
	push(&a, "--ro-bind"); push(&a, s->closure); push(&a, "/run/current-system");
	push(&a, "--perms"); push(&a, "0755"); push(&a, "--dir"); push(&a, "/run/user");
	push(&a, "--perms"); push(&a, "0700"); push(&a, "--tmpfs"); push(&a, run_user);
	push(&a, "--perms"); push(&a, "1777"); push(&a, "--tmpfs"); push(&a, "/tmp");
	/* The kernel mounts a fresh sysfs only where one is already visible.
	 * The mount helper mounts the session's own /sys and detaches this. */
	push(&a, "--ro-bind"); push(&a, "/sys"); push(&a, "/.hostsys");

	push_all(&a, &s->bwrap_args);

	push(&a, "--");
	push(&a, FLONG_INIT);
	push(&a, str("%d", gate_r));
	push(&a, str("%d", ready_w));
	push(&a, groups_arg(s));
	push(&a, l->tty.relay ? "ctty" : "-");
	push(&a, s->trace ? "trace" : "-");
	push(&a, s->chdir);
	push(&a, "--");
	push_all(&a, &s->command);
	return argv_done(&a);
}

/* Opens the seccomp files, makes the info, ready and gate pipes and spawns
 * bwrap in the sandbox leaf. bwrap inherits U1, U2, its ends of the three
 * pipes, the seccomp descriptors and the wrapper's keep-fds, and nothing
 * else; the launcher then closes its copies of what bwrap alone needs. */
static int spawn_bwrap(struct launch *l)
{
	const struct fl_spec *s = &l->s;
	int info[2] = { -1, -1 }, ready[2] = { -1, -1 }, gate[2] = { -1, -1 };
	int *keep = NULL, rc = -1;
	size_t nkeep = 0;

	l->seccomp = malloc((s->nseccomp + 1) * sizeof *l->seccomp);
	if (!l->seccomp)
		return fl_err("malloc");
	for (size_t i = 0; i < s->nseccomp; i++)
		l->seccomp[i] = -1;
	for (size_t i = 0; i < s->nseccomp; i++)
		if ((l->seccomp[i] = open(s->seccomp[i], O_RDONLY | O_CLOEXEC)) < 0) {
			fl_err("open seccomp program %s", s->seccomp[i]);
			goto out;
		}

	if (pipe2(info, O_CLOEXEC) || pipe2(ready, O_CLOEXEC) || pipe2(gate, O_CLOEXEC)) {
		fl_err("pipe");
		goto out;
	}
	l->info = info[0];
	l->ready = ready[0];
	l->gate = gate[1];

	keep = malloc((5 + s->nseccomp + s->nkeep_fds) * sizeof *keep);
	if (!keep) {
		fl_err("malloc");
		goto out;
	}
	keep[nkeep++] = l->ns.u1;
	keep[nkeep++] = l->ns.u2;
	keep[nkeep++] = info[1];
	keep[nkeep++] = ready[1];
	keep[nkeep++] = gate[0];
	for (size_t i = 0; i < s->nseccomp; i++)
		keep[nkeep++] = l->seccomp[i];
	for (size_t i = 0; i < s->nkeep_fds; i++)
		keep[nkeep++] = s->keep_fds[i];

	char *const *argv = bwrap_argv(l, info[1], ready[1], gate[0]);
	if (!argv)
		goto out;
	struct fl_spawn sp = {
		.argv = argv,
		.envp = NULL,
		.cgroup = l->cg.leaf[FL_LEAF_SANDBOX],
		.stdio = tty_stdio(&l->tty),
		.keep = keep,
		.nkeep = nkeep,
		.dir = NULL,
	};
	l->bwrap = fl_spawn(&sp, NULL);
	if (l->bwrap < 0)
		goto out;
	tty_spawned(&l->tty);
	rc = 0;
out:
	/* bwrap has its own copies. The launcher's copies of the child ends
	 * would hide bwrap's death from the info and ready readers, and a
	 * copy of the gate's read end would never let flong-init see EOF. */
	fl_close(&info[1]);
	fl_close(&ready[1]);
	fl_close(&gate[0]);
	for (size_t i = 0; i < s->nseccomp; i++)
		fl_close(&l->seccomp[i]);
	fl_close(&l->ns.u2);
	for (size_t i = 0; i < s->nkeep_fds; i++)
		fl_close(&s->keep_fds[i]);
	free(keep);
	return rc;
}

/* ---- steps 13 and 14: waits that bwrap's death also ends ---- */

/* Waits until fd is readable, or until bwrap exits first. bwrap's child can
 * outlive bwrap until it has execed flong-init: a session was seen with bwrap
 * gone and its child, reparented, still holding the write ends of the info
 * and ready pipes, so neither pipe reported EOF. bwrap's pidfd is therefore
 * watched too, and bwrap's exit ends the wait as an event of its own.
 * Returns 1 when fd is ready, 0 when bwrap exited first, -1 on error or on a
 * terminating signal (fl_await). */
static int await_or_bwrap(const struct launch *l, int fd)
{
	int rc = -1, ep = epoll_create1(EPOLL_CLOEXEC);
	if (ep < 0)
		return fl_err("epoll_create1");
	struct epoll_event ev = { .events = EPOLLIN, .data.fd = fd };
	struct epoll_event bw = { .events = EPOLLIN, .data.fd = l->bwrap };
	if (epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev) || epoll_ctl(ep, EPOLL_CTL_ADD, l->bwrap, &bw)) {
		fl_err("epoll_ctl");
		goto out;
	}
	if (fl_await(ep, POLLIN) < 0)
		goto out;
	struct epoll_event got[2];
	int n = epoll_wait(ep, got, 2, -1);
	if (n < 0) {
		fl_err("epoll_wait");
		goto out;
	}
	/* fd first: what bwrap did before it exited still counts. */
	rc = 0;
	for (int i = 0; i < n; i++)
		if (got[i].data.fd == fd)
			rc = 1;
out:
	close(ep);
	return rc;
}

/* ---- step 13: child-pid ---- */

/* The pid in bwrap's info JSON ({"child-pid": N, ...}) once it is whole:
 * the digits are followed by something else, or the pipe is at EOF.
 * Returns the pid, 0 when more is needed, -1 when it is malformed. */
static pid_t child_pid(const char *buf, int eof)
{
	const char *p = strstr(buf, "\"child-pid\"");
	if (!p)
		return 0;
	p += strlen("\"child-pid\"");
	p += strspn(p, " \t\n");
	if (*p == '\0')
		return 0;
	if (*p != ':')
		return -1;
	p++;
	p += strspn(p, " \t\n");
	size_t digits = strspn(p, "0123456789");
	if (p[digits] == '\0' && !eof)
		return 0;
	if (digits == 0 || digits > 9)
		return -1;
	return (pid_t)strtol(p, NULL, 10);
}

/* Reads --info-fd until it names bwrap's child. EOF first means bwrap failed
 * before it made the sandbox, and bwrap has said why on stderr. Then holds
 * the leader's pidfd and network namespace, and records it.
 *
 * The read end stays open until the launcher exits. bwrap writes its JSON in
 * several writes (the child-pid, each namespace id, the closing brace) and
 * would die of SIGPIPE, silently, at the next one after the reader closed:
 * seen in 1 launch of 100 under load. What it writes after the pid is never
 * read, and fits in the pipe. */
static int wait_child_pid(struct launch *l)
{
	char buf[4096];
	size_t got = 0;
	pid_t pid = 0;

	while (pid == 0) {
		int ready = await_or_bwrap(l, l->info);
		if (ready < 0)
			return -1;
		if (ready == 0)
			return fl_errx("bwrap failed before it made the sandbox");
		ssize_t r = read(l->info, buf + got, sizeof buf - 1 - got);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return fl_err("read bwrap's info");
		}
		got += (size_t)r;
		buf[got] = '\0';
		pid = child_pid(buf, r == 0);
		if (pid < 0 || (pid == 0 && (r == 0 || got == sizeof buf - 1))) {
			if (r == 0 && got == 0)
				return fl_errx("bwrap failed before it made the sandbox");
			return fl_errx("bwrap reported no child pid: %s", buf);
		}
	}
	l->leader = pid;

	l->leader_fd = fl_pidfd_open(pid);
	if (l->leader_fd < 0)
		return fl_err("the session's pid 1 (%d)", (int)pid);
	char path[64];
	snprintf(path, sizeof path, "/proc/%d/ns/net", (int)pid);
	l->netns = open(path, O_RDONLY | O_CLOEXEC);
	if (l->netns < 0)
		return fl_err("open %s", path);
	return rec_set_leader(&l->rec, pid);
}

/* ---- step 14: the mount helper ---- */

/* Forks the mount helper into the sandbox leaf at child-pid, so it
 * prepares every source while bwrap is still building the root; it touches
 * the session's mount namespace only after the ready byte, which it reads
 * itself. It keeps U1, the ready pipe and the leader's pidfd and nothing
 * else: a copy of the record's lock there would keep a dead session alive
 * for the sweep. */
static int start_mount_helper(struct launch *l)
{
	const struct fl_spec *s = &l->s;
	struct fl_mount_job job = {
		.u1 = l->ns.u1,
		.leader_pidfd = l->leader_fd,
		.ready = l->ready,
		.mounts = s->mounts,
		.nmounts = s->nmounts,
		.uid = s->uid,
		.gid = s->gid,
		.home = s->home,
		.protect = l->protect,
		.nprotect = l->nprotect,
	};
	int keep[] = { l->ns.u1, l->ready, l->leader_fd };
	pid_t pid = fl_fork(l->cg.leaf[FL_LEAF_SANDBOX], keep, sizeof keep / sizeof *keep, &l->helper);
	if (pid < 0)
		return -1;
	if (pid == 0)
		_exit(mount_run(&job));
	/* The helper holds the only read end now, so it alone sees the ready
	 * byte, or EOF when bwrap dies first. */
	fl_close(&l->ready);
	return 0;
}

/* Waits for the helper. The gate opens only when every mount, /sys and
 * /run's read-only remount are done; the helper said why when not. */
static int wait_mount_helper(struct launch *l)
{
	int ready = await_or_bwrap(l, l->helper);
	if (ready < 0)
		return -1;
	if (ready == 0)
		return fl_errx("bwrap exited before the session was ready; the payload does not run");
	int st = fl_reap(l->helper);
	if (st < 0)
		return -1;
	fl_close(&l->helper);
	if (st != 0)
		return fl_errx("the session's mounts failed; the payload does not run");
	fl_trace("mounts-done");
	return 0;
}

/* ---- step 15: postStart ---- */

/* The hook runs as the caller in the hooks leaf, so whatever it leaves
 * running dies with the session, with the launcher's stdio, working
 * directory and environment plus $leader, $userns, $netns and $machine.
 * It runs after the mounts, so a hook that enters the mount namespace sees
 * the finished root, and before pasta, so it sees no route. */
static int run_hook(struct launch *l)
{
	if (l->s.post_start.n == 0)
		return 0;
	/* /proc/<launcher>/fd/<fd>: a namespace the launcher holds, named
	 * with nothing on disk. */
	char *leader = str("%d", (int)l->leader);
	char *userns = str("/proc/%d/fd/%d", (int)getpid(), l->ns.u1);
	char *netns = str("/proc/%d/fd/%d", (int)getpid(), l->netns);
	if (!leader || !userns || !netns)
		return -1;
	if (setenv("leader", leader, 1) || setenv("userns", userns, 1) ||
	    setenv("netns", netns, 1) || setenv("machine", l->s.machine, 1))
		return fl_err("setenv");
	struct fl_spawn sp = {
		.argv = l->s.post_start.v,
		.envp = NULL,
		.cgroup = l->cg.leaf[FL_LEAF_HOOKS],
		.stdio = NULL,
		.keep = NULL,
		.nkeep = 0,
		.dir = NULL,
	};
	l->hook = fl_spawn(&sp, NULL);
	if (l->hook < 0)
		return -1;
	int st = fl_reap(l->hook);
	if (st < 0)
		return -1;
	fl_close(&l->hook);
	if (st != 0)
		return fl_errx("postStart failed (status %d); the payload does not run", st);
	fl_trace("hook-done");
	return 0;
}

/* ---- step 16: pasta ---- */

/* pasta in the pasta leaf, as the caller. --userns names U1, the network
 * namespace's owner (U2 is EPERM). The spawned pasta exits 0 once the
 * namespace is configured and its daemon is running; a host port it cannot
 * bind (in use, or below ip_unprivileged_port_start) fails it at once, and
 * the launch fails closed. The pid file is a memfd the launcher holds:
 * nothing on disk, and a path in pasta's cmdline unique to this session.
 * The launcher never signals pasta by pid; cgroup.kill ends it. */
static int start_pasta(struct launch *l)
{
	if (!l->s.network)
		return 0;
	l->pasta_pid_file = memfd_create("pasta.pid", MFD_CLOEXEC);
	if (l->pasta_pid_file < 0)
		return fl_err("memfd_create");
	struct argvb a = { 0 };
	push(&a, FLONG_PASTA);
	push(&a, "--quiet");
	push(&a, "--config-net");
	push(&a, "--userns"); push(&a, str("/proc/%d/fd/%d", (int)getpid(), l->ns.u1));
	push(&a, "--netns"); push(&a, str("/proc/%d/ns/net", (int)l->leader));
	push(&a, "--pid"); push(&a, str("/proc/%d/fd/%d", (int)getpid(), l->pasta_pid_file));
	push_all(&a, &l->s.pasta_args);
	char *const *argv = argv_done(&a);
	if (!argv)
		return -1;

	int devnull = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (devnull < 0)
		return fl_err("open /dev/null");
	int stdio[3] = { devnull, -1, -1 };
	struct fl_spawn sp = {
		.argv = argv,
		.envp = NULL,
		.cgroup = l->cg.leaf[FL_LEAF_PASTA],
		.stdio = stdio,
		.keep = NULL,
		.nkeep = 0,
		.dir = NULL,
	};
	l->pasta = fl_spawn(&sp, NULL);
	fl_close(&devnull);
	if (l->pasta < 0)
		return -1;
	int st = fl_reap(l->pasta);
	if (st < 0)
		return -1;
	fl_close(&l->pasta);
	if (st != 0)
		return fl_errx("pasta failed (status %d); the payload does not run", st);
	fl_trace("pasta-up");
	return 0;
}

/* ---- step 17: the gate ---- */

/* A terminating signal that arrived since the last wait is still queued on
 * the signalfd. Before the gate it aborts the launch, as it would have
 * during a wait; after the gate, tty_wait would forward it to a payload that
 * had only just started. fl_take_signal takes it off the queue, which costs
 * no wait, so the teardown's waits end only on a signal that comes later.
 * A SIGWINCH taken there or in any earlier wait was dropped, so the window
 * size is copied once more after it: a resize from here on is tty_wait's. */
static int open_gate(struct launch *l)
{
	if (tty_start(&l->tty, l->leader_fd) < 0)
		return -1;
	if (fl_take_signal(0) < 0)
		return -1;
	tty_resize(&l->tty);
	ssize_t w;
	do
		w = write(l->gate, "g", 1);
	while (w < 0 && errno == EINTR);
	if (w != 1)
		return fl_err("open the gate");
	fl_close(&l->gate);
	l->gate_opened = 1;
	fl_trace("gate-open");
	return 0;
}

/* ---- the launch ---- */

/* Steps 6 to 18 of DESIGN.md, "The launch, in order". Returns bwrap's
 * status once the gate has opened, or -1 at the first failure. */
static int run(struct launch *l)
{
	struct fl_spec *s = &l->s;

	if (tty_prepare(&l->tty, s->container, s->uid) < 0)
		return -1;

	if (cg_check_nsdelegate() < 0 ||
	    cg_holder_find(&l->holder, s->holder, &s->holder_start, s->nlimits > 0) < 0)
		return -1;

	if (rec_sweep(l->sessions_fd, &l->holder) < 0)
		return -1;
	fl_trace("swept");

	/* The path goes into l->cg.path, where cg_session_create writes the
	 * same string again; teardown goes by l->cg.fd, not the path. */
	if (cg_session_path(l->cg.path, sizeof l->cg.path, &l->holder, s->container, s->machine) < 0 ||
	    rec_create(&l->rec, l->sessions_fd, &l->holder, s->machine, s->post_stop,
		       l->cg.path) < 0)
		return -1;
	fl_trace("recorded");

	if (ns_create(s, &l->ns) < 0)
		return -1;

	if (cg_session_create(&l->cg, &l->holder, s->container, s->machine,
			      s->limits, s->nlimits) < 0)
		return -1;
	fl_trace("cgroup-made");

	/* Before bwrap, so nothing between child-pid and the helper's fork
	 * but the fork itself. */
	if (protect_paths(l) < 0)
		return -1;

	if (spawn_bwrap(l) < 0)
		return -1;

	if (wait_child_pid(l) < 0)
		return -1;
	fl_trace("bwrap-child");

	if (start_mount_helper(l) < 0 || wait_mount_helper(l) < 0)
		return -1;

	if (run_hook(l) < 0 || start_pasta(l) < 0)
		return -1;

	if (open_gate(l) < 0)
		return -1;

	/* tty_wait leaves bwrap unreaped; the teardown reaps it with the rest. */
	int st = tty_wait(&l->tty, l->bwrap, l->leader_fd);
	if (st < 0)
		return -1;
	fl_trace("bwrap-exited");
	return st;
}

/* Reaps a child we spawned or forked, if it has not been. Returns 0, or -1
 * when a signal or an error cut the wait short. */
static int reap(int *pidfd)
{
	if (*pidfd < 0)
		return 0;
	int st = fl_reap(*pidfd);
	fl_close(pidfd);
	return st < 0 ? -1 : 0;
}

/* The one teardown path, whatever stage the launch reached (DESIGN.md,
 * "Teardown"). Each step happens only for what exists. When a wait is cut
 * short (a signal during teardown), the session may not be empty yet: then
 * postStop does not run here and the record is closed, not removed, so the
 * sweeper, woken by that close, kills, waits, runs postStop and removes. */
static int teardown(struct launch *l, int status)
{
	int settled = 1;

	/* Hooks and postStop then print to a cooked terminal. */
	tty_finish(&l->tty);

	/* flong-init reads EOF and exits 125: the payload never runs. */
	fl_close(&l->gate);

	if (l->cg.fd >= 0) {
		if (cg_kill(&l->cg) < 0)
			settled = 0;
		if (reap(&l->bwrap) < 0 || reap(&l->helper) < 0 ||
		    reap(&l->hook) < 0 || reap(&l->pasta) < 0)
			settled = 0;
		for (int leaf = FL_LEAF_SANDBOX; settled && leaf <= FL_LEAF_HOOKS; leaf++)
			if (cg_wait_empty(l->cg.leaf[leaf]) < 0)
				settled = 0;
	}

	if (l->rec.fd >= 0 && settled && l->s.post_stop) {
		/* A failing postStop is reported and does not change the status.
		 * An aborted one keeps poststop= in the record, which is closed,
		 * so the sweeper runs it again. */
		if (fl_poststop(l->s.post_stop, l->s.machine) < 0 ||
		    rec_poststop_done(&l->rec) < 0)
			settled = 0;
		else
			fl_trace("poststop-done");
	}

	/* Fixed forwardPorts bind host ports: pasta must have let them go
	 * before the next launch binds them again. Nothing else waits for
	 * pasta, which takes 20-40 ms to remove its tap device. */
	if (l->cg.fd >= 0 && settled && l->s.pasta_wait) {
		if (cg_wait_empty(l->cg.leaf[FL_LEAF_PASTA]) < 0)
			settled = 0;
		else
			fl_trace("pasta-gone");
	}

	int removed = 1;
	if (l->cg.fd >= 0)
		removed = settled && cg_remove(&l->cg) == 0;
	if (l->rec.fd >= 0) {
		if (removed)
			rec_remove(&l->rec);
		else
			rec_close(&l->rec);
	}
	if (l->cg.fd >= 0 || l->rec.fd >= 0)
		fl_trace("released");
	cg_close(&l->cg);

	if (l->gate_opened && status >= 0)
		return status;
	if (fl_abort_signal)
		return 128 + fl_abort_signal;
	return EXIT_NOT_RUN;
}

int main(int argc, char **argv)
{
	struct launch l;
	struct timespec start;
	sigset_t block, oldmask;

	clock_gettime(CLOCK_REALTIME, &start);
	fl_prog = "flong-launch";
	launch_init(&l);

	/* Step 1. Signals are read from a signalfd, so every wait can end on
	 * one as an event, and none interrupts a step half done. They are
	 * blocked now and stay queued; the signalfd is made after the spec is
	 * read (below), so that its number is never one a keep-fd names: a
	 * keep-fd the wrapper does not hold would otherwise pass as open. */
	sigemptyset(&block);
	sigaddset(&block, SIGTERM);
	sigaddset(&block, SIGHUP);
	sigaddset(&block, SIGINT);
	sigaddset(&block, SIGQUIT);
	sigaddset(&block, SIGWINCH);
	sigaddset(&block, SIGCONT);
	if (sigprocmask(SIG_BLOCK, &block, &oldmask)) {
		fl_err("sigprocmask");
		return EXIT_NOT_RUN;
	}
	signal(SIGPIPE, SIG_IGN);
	/* An ignored SIGCHLD survives execve, and under it the kernel reaps our
	 * children itself: waitid would then say ECHILD, and a helper's or a
	 * hook's failure would be lost. */
	signal(SIGCHLD, SIG_DFL);

	/* Step 2. */
	if (spec_parse(argc, argv, &l.s) < 0)
		return EXIT_NOT_RUN;
	fl_sigfd = signalfd(-1, &block, SFD_CLOEXEC | SFD_NONBLOCK);
	if (fl_sigfd < 0) {
		fl_err("signalfd");
		return EXIT_NOT_RUN;
	}
	fl_tracing = l.s.trace;
	/* The trace flag is known only now; the stage is when main began. */
	fl_trace_at(&start, "launcher-start");

	/* Step 3. */
	if (state_open(l.s.state, &l.state_fd, &l.sessions_fd) < 0)
		return EXIT_NOT_RUN;

	/* Step 4, before inherited descriptors are closed: a cold wrapper's
	 * own shared lock on the cache must not go before this one is held. */
	switch (cache_lock(l.s.cache, &l.cache_fd)) {
	case 0:
		break;
	case 1:
		return relaunch(&l, &oldmask);
	default:
		/* A terminating signal ends the wait for a cache being swept,
		 * and the launch then exits the way teardown would say. */
		return fl_abort_signal ? 128 + fl_abort_signal : EXIT_NOT_RUN;
	}
	fl_trace("cache-locked");

	/* Step 5: whatever the wrapper held that bwrap-args do not name. */
	size_t nkeep = l.s.nkeep_fds + 4;
	int *keep = malloc(nkeep * sizeof *keep);
	if (!keep) {
		fl_err("malloc");
		return EXIT_NOT_RUN;
	}
	memcpy(keep, l.s.keep_fds, l.s.nkeep_fds * sizeof *keep);
	keep[l.s.nkeep_fds] = fl_sigfd;
	keep[l.s.nkeep_fds + 1] = l.state_fd;
	keep[l.s.nkeep_fds + 2] = l.sessions_fd;
	keep[l.s.nkeep_fds + 3] = l.cache_fd;
	int closed = fl_close_from(3, keep, nkeep);
	free(keep);
	if (closed < 0)
		return EXIT_NOT_RUN;

	int status = run(&l);
	return teardown(&l, status);
}
