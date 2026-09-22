/* flong-util.c: messages, descriptors, waiting and spawning.
 *
 * Every wait here is a poll with no timeout, on a descriptor that turns
 * ready when the awaited thing happens, alongside fl_sigfd so that a
 * terminating signal can end it. Nothing here sleeps or counts.
 */
#include "flong-util.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/pidfd.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <linux/sched.h>

const char *fl_prog = "flong";
int fl_tracing;
int fl_sigfd = -1;
volatile int fl_abort_signal;

extern char **environ;

/* ---- messages ---- */

/* Writes one message to stderr in as few writes as the pipe allows, so the
 * lines of the launcher and its helpers do not interleave mid-line. A
 * failure to write to stderr leaves nowhere to report it, so it is dropped. */
static void say(const char *msg, size_t len)
{
	while (len > 0) {
		ssize_t n = write(2, msg, len);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return;
		msg += n;
		len -= (size_t)n;
	}
}

/* Appends to a message being built in buf, which keeps one byte free for
 * the newline: a message longer than the buffer is cut, not dropped. */
static void append(char *buf, size_t *len, size_t cap, const char *fmt, va_list ap)
{
	int n = vsnprintf(buf + *len, cap - *len, fmt, ap);
	if (n > 0)
		*len += (size_t)n < cap - *len ? (size_t)n : cap - *len - 1;
}

static void appendf(char *buf, size_t *len, size_t cap, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	append(buf, len, cap, fmt, ap);
	va_end(ap);
}

/* Says "prog: <message>[: <strerror(err)>]" as one line. */
static void vmessage(int err, const char *fmt, va_list ap)
{
	char buf[1024];
	size_t len = 0, cap = sizeof buf - 1;
	appendf(buf, &len, cap, "%s: ", fl_prog);
	append(buf, &len, cap, fmt, ap);
	if (err)
		appendf(buf, &len, cap, ": %s", strerror(err));
	buf[len++] = '\n';
	say(buf, len);
}

int fl_err(const char *fmt, ...)
{
	int err = errno;
	va_list ap;
	va_start(ap, fmt);
	vmessage(err, fmt, ap);
	va_end(ap);
	errno = err;
	return -1;
}

int fl_errx(const char *fmt, ...)
{
	int err = errno;
	va_list ap;
	va_start(ap, fmt);
	vmessage(0, fmt, ap);
	va_end(ap);
	errno = err;
	return -1;
}

void fl_die(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vmessage(errno, fmt, ap);
	va_end(ap);
	_exit(125);
}

void fl_trace_at(const struct timespec *t, const char *stage)
{
	char buf[256];
	if (!fl_tracing)
		return;
	int n = snprintf(buf, sizeof buf, "T %lld %s\n",
			 (long long)t->tv_sec * 1000000LL + t->tv_nsec / 1000, stage);
	if (n > 0)
		say(buf, (size_t)n < sizeof buf ? (size_t)n : sizeof buf - 1);
}

void fl_trace(const char *stage)
{
	struct timespec t;
	if (!fl_tracing)
		return;
	clock_gettime(CLOCK_REALTIME, &t);
	fl_trace_at(&t, stage);
}

/* ---- file descriptors ---- */

void fl_close(int *fd)
{
	int err = errno;
	if (*fd >= 0)
		close(*fd);
	*fd = -1;
	errno = err;
}

/* The smallest descriptor in keep that is >= low, or -1. keep is short and
 * in any order, so it is scanned rather than sorted. */
static int next_kept(int low, const int *keep, size_t nkeep)
{
	int best = -1;
	for (size_t i = 0; i < nkeep; i++)
		if (keep[i] >= low && (best < 0 || keep[i] < best))
			best = keep[i];
	return best;
}

int fl_close_from(int low, const int *keep, size_t nkeep)
{
	for (;;) {
		int kept = next_kept(low, keep, nkeep);
		unsigned int last = kept < 0 ? ~0U : (unsigned int)kept - 1;
		if (kept != low && close_range((unsigned int)low, last, 0) < 0)
			return fl_err("close_range %d", low);
		if (kept < 0)
			return 0;
		low = kept + 1;
	}
}

int fl_write_at(int dirfd, const char *path, const char *s)
{
	int fd = openat(dirfd, path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return fl_err("open %s", path);
	size_t len = strlen(s);
	while (len > 0) {
		ssize_t n = write(fd, s, len);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0) {
			fl_err("write %s to %s", s, path);
			fl_close(&fd);
			return -1;
		}
		s += n;
		len -= (size_t)n;
	}
	fl_close(&fd);
	return 0;
}

/* Reads fd until EOF or until size-1 bytes are in buf, and NUL-terminates
 * them. Returns the length, or -1 with errno set and nothing printed. */
static ssize_t read_all(int fd, char *buf, size_t size)
{
	size_t len = 0;
	while (len < size - 1) {
		ssize_t n = read(fd, buf + len, size - 1 - len);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0)
			return -1;
		if (n == 0)
			break;
		len += (size_t)n;
	}
	buf[len] = '\0';
	return (ssize_t)len;
}

ssize_t fl_read_at(int dirfd, const char *path, char *buf, size_t size)
{
	int fd = openat(dirfd, path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return fl_err("open %s", path);
	ssize_t len = read_all(fd, buf, size);
	if (len < 0)
		fl_err("read %s", path);
	fl_close(&fd);
	return len;
}

/* ---- names ---- */

int fl_is_name(const char *s, size_t len)
{
	if (len == 0 || len > FL_NAME_MAX || s[0] == '.')
		return 0;
	for (size_t i = 0; i < len; i++) {
		char c = s[i];
		if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		      (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'))
			return 0;
	}
	return 1;
}

/* ---- the caller ---- */

int fl_refuse_root(void)
{
	if (getuid() == 0 || geteuid() == 0)
		return fl_errx("refusing to run as root: flong runs as its caller, never as root");
	return 0;
}

/* ---- signals and waiting ---- */

int fl_terminating(int sig)
{
	return sig == SIGTERM || sig == SIGHUP || sig == SIGINT || sig == SIGQUIT;
}

int fl_abort(int sig)
{
	fl_abort_signal = sig;
	errno = EINTR;
	return -1;
}

int fl_next_signal(void)
{
	struct signalfd_siginfo si;
	ssize_t n;
	while ((n = read(fl_sigfd, &si, sizeof si)) < 0 && errno == EINTR)
		;
	if (n < 0 && errno == EAGAIN)
		return 0;
	if (n != (ssize_t)sizeof si)
		return fl_err("read signalfd");
	return (int)si.ssi_signo;
}

int fl_take_signal(int want)
{
	for (;;) {
		int sig = fl_next_signal();
		if (sig <= 0)
			return sig;
		if (sig == want)
			return 1;
		if (fl_terminating(sig))
			return fl_abort(sig);
	}
}

int fl_await(int fd, short events)
{
	struct pollfd p[2] = {
		{ .fd = fd, .events = events },
		{ .fd = fl_sigfd, .events = POLLIN },
	};
	nfds_t n = fl_sigfd >= 0 ? 2 : 1;
	for (;;) {
		if (poll(p, n, -1) < 0) {
			if (errno == EINTR)
				continue;
			return fl_err("poll");
		}
		/* The signal is looked at first: once a terminating signal has
		 * arrived, the launch is aborted whatever else became ready. */
		if (n == 2 && p[1].revents) {
			if (p[1].revents & POLLNVAL) {
				errno = EBADF;
				return fl_err("poll signalfd");
			}
			/* One signal per wake-up: any behind it make the next
			 * poll return at once. */
			int sig = fl_next_signal();
			if (sig < 0)
				return -1;
			if (fl_terminating(sig))
				return fl_abort(sig);
		}
		if (p[0].revents & POLLNVAL) {
			errno = EBADF;
			return fl_err("poll %d", fd);
		}
		/* A pipe whose writers are gone reports POLLHUP, not POLLIN:
		 * that is the EOF a caller is waiting to read, so it counts as
		 * ready, as does POLLERR, which the caller's next call reports. */
		if (p[0].revents & (events | POLLHUP | POLLERR))
			return 1;
	}
}

/* ---- processes ---- */

int fl_pidfd_open(pid_t pid)
{
	int fd = pidfd_open(pid, 0);
	/* A process that is gone is an answer, not a failure: the liveness
	 * check asks exactly that. */
	if (fd < 0 && errno != ESRCH)
		return fl_err("pidfd_open %d", (int)pid);
	return fd;
}

int fl_reap(int pidfd)
{
	siginfo_t si;
	if (fl_await(pidfd, POLLIN) < 0)
		return -1;
	memset(&si, 0, sizeof si);
	while (waitid((idtype_t)P_PIDFD, (id_t)pidfd, &si, WEXITED) < 0)
		if (errno != EINTR)
			return fl_err("waitid");
	return fl_status(&si);
}

void fl_reap_now(int *pidfd, int kill)
{
	siginfo_t si;
	if (*pidfd < 0)
		return;
	if (kill)
		pidfd_send_signal(*pidfd, SIGKILL, NULL, 0);
	while (waitid((idtype_t)P_PIDFD, (id_t)*pidfd, &si, WEXITED) < 0 && errno == EINTR)
		;
	fl_close(pidfd);
}

unsigned long long fl_starttime(pid_t pid)
{
	char path[64], buf[4096];
	snprintf(path, sizeof path, "/proc/%d/stat", (int)pid);
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	ssize_t len = read_all(fd, buf, sizeof buf);
	fl_close(&fd);
	if (len <= 0)
		return 0;
	/* The command name, field 2, is in parentheses and may hold spaces and
	 * parentheses of its own, so the fields are counted from its last ')'.
	 * Field 3 follows it after one space; field 22 is 19 spaces further. */
	char *s = strrchr(buf, ')');
	if (!s)
		return 0;
	s++;
	for (int field = 2; field < 22; field++) {
		s = strchr(s, ' ');
		if (!s)
			return 0;
		s++;
	}
	return strtoull(s, NULL, 10);
}

/* clone3 with CLONE_PIDFD, and CLONE_INTO_CGROUP when cgroup >= 0. Returns
 * what clone3 does: 0 in the child, the pid in the parent, -1 on error.
 * The pidfd is close-on-exec, as every pidfd is. */
static pid_t clone_into(int cgroup, int *pidfd)
{
	struct clone_args ca = {
		.flags = CLONE_PIDFD,
		.pidfd = (unsigned long long)(unsigned long)pidfd,
		.exit_signal = SIGCHLD,
	};
	if (cgroup >= 0) {
		ca.flags |= CLONE_INTO_CGROUP;
		ca.cgroup = (unsigned long long)cgroup;
	}
	return (pid_t)syscall(SYS_clone3, &ca, sizeof ca);
}

/* The child's half of fl_spawn. It reports a failure on stderr, which by
 * then is the program's own, and exits 127 as a shell does. */
static _Noreturn void spawn_child(const struct fl_spawn *s)
{
	struct sigaction dfl = { .sa_handler = SIG_DFL };
	sigset_t none;
	int moved[3] = { -1, -1, -1 };

	/* exec resets handled signals but keeps ignored ones and the mask, and
	 * the launcher ignores SIGPIPE and blocks the ones it reads from its
	 * signalfd. The program gets the defaults a shell would give it. */
	for (int sig = 1; sig < NSIG; sig++)
		sigaction(sig, &dfl, NULL);
	sigemptyset(&none);
	sigprocmask(SIG_SETMASK, &none, NULL);

	/* Each stdio source is first copied above 2, so that one source that is
	 * another's target (stdout onto 0, say) is not overwritten before it is
	 * used. The copies are then close-on-exec like everything else. */
	for (int i = 0; s->stdio && i < 3; i++)
		if (s->stdio[i] >= 0 &&
		    (moved[i] = fcntl(s->stdio[i], F_DUPFD_CLOEXEC, 3)) < 0) {
			fl_err("dup %d", s->stdio[i]);
			_exit(127);
		}
	for (int i = 0; i < 3; i++)
		if (moved[i] >= 0 && dup2(moved[i], i) < 0) {
			fl_err("dup2 %d", i);
			_exit(127);
		}

	if (close_range(3, ~0U, CLOSE_RANGE_CLOEXEC) < 0) {
		fl_err("close_range");
		_exit(127);
	}
	for (size_t i = 0; i < s->nkeep; i++)
		if (fcntl(s->keep[i], F_SETFD, 0) < 0) {
			fl_err("keep %d", s->keep[i]);
			_exit(127);
		}

	if (s->dir && chdir(s->dir) < 0) {
		fl_err("chdir %s", s->dir);
		_exit(127);
	}
	execve(s->argv[0], s->argv, s->envp ? s->envp : environ);
	fl_err("exec %s", s->argv[0]);
	_exit(127);
}

int fl_spawn(const struct fl_spawn *s, pid_t *pid)
{
	int pidfd = -1;
	pid_t p = clone_into(s->cgroup, &pidfd);
	if (p < 0)
		return fl_err("clone3 %s", s->argv[0]);
	if (p == 0)
		spawn_child(s);
	if (pid)
		*pid = p;
	return pidfd;
}

pid_t fl_fork(int cgroup, const int *keep, size_t nkeep, int *pidfd)
{
	*pidfd = -1;
	pid_t p = clone_into(cgroup, pidfd);
	if (p < 0)
		return fl_err("clone3");
	if (p == 0) {
		if (fl_close_from(3, keep, nkeep) < 0)
			_exit(125);
		/* The launcher's signalfd is gone unless the helper kept it,
		 * and fl_await must not poll a number that may be reused. */
		if (fl_sigfd >= 0 && next_kept(fl_sigfd, keep, nkeep) != fl_sigfd)
			fl_sigfd = -1;
	}
	return p;
}

int fl_lock_wait(int fd, int op)
{
	/* A lock that is free costs no fork. */
	if (flock(fd, op | LOCK_NB) == 0)
		return 0;
	if (errno != EWOULDBLOCK)
		return fl_err("lock");
	int pidfd;
	pid_t pid = fl_fork(-1, &fd, 1, &pidfd);
	if (pid < 0)
		return -1;
	if (pid == 0) {
		while (flock(fd, op) < 0)
			if (errno != EINTR)
				fl_die("lock");
		_exit(0);
	}
	int st = fl_reap(pidfd);
	if (st < 0) {
		fl_reap_now(&pidfd, 1);
		return -1;
	}
	fl_close(&pidfd);
	/* 125 is fl_die's: the helper has said why. */
	if (st == 125)
		return -1;
	if (st != 0)
		return fl_errx("the lock helper ended with status %d", st);
	return 0;
}
