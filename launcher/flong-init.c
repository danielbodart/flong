/* flong-init: the first program inside the session. bwrap execs it as pid 1
 * (--as-pid-1), so it runs before anything of the payload's and is the gate:
 * bwrap's own --block-fd is fail-open, this one is fail-closed.
 *
 *   flong-init GATE READY GROUPS TTY TRACE DIR -- COMMAND...
 *
 * GATE and READY are descriptor numbers, GROUPS is comma-separated gids or
 * "-", TTY is "ctty" or "-", TRACE is "trace" or "-", DIR is absolute. The
 * protocol is argv, not the environment, so the wrapper's --clearenv cannot
 * drop it and nothing has to be unset before the payload sees its
 * environment. In order it:
 *
 * 1. calls setgroups. bwrap never does, so without this the caller's host
 *    groups (wheel, docker, kvm) would stay effective. bwrap gives it
 *    CAP_SETGID for this and CAP_SETPCAP for the next step, and nothing else.
 * 2. drops the bounding set, clears the ambient set and zeroes the others, so
 *    the payload holds no capability and can gain none.
 * 3. with "ctty", takes fd 0, the relay's pty, as its controlling terminal:
 *    bwrap's --new-session made it a session leader, and tini -g needs the
 *    terminal to hand the payload the foreground.
 * 4. resets SIGINT and SIGQUIT to their default and empties the signal mask:
 *    a bash "&" hands bwrap both ignored, and tini passes that on.
 * 5. writes one byte on READY: bwrap has finished the root, so the launcher
 *    may run the mount helper and hooks that enter the mount namespace.
 * 6. reads one byte from GATE. EOF means the launcher failed or died before
 *    the helper, the hooks and pasta had all succeeded: exit 125, the payload
 *    never runs.
 * 7. changes to DIR. The workspace is a helper mount made after bwrap built
 *    the root, so this has to follow the gate; bwrap's --chdir would name the
 *    directory underneath it.
 * 8. closes every descriptor above stderr (bwrap leaks its namespace fds),
 *    and execs tini -g -- COMMAND.
 *
 * Every failure before the exec exits 125, the code the launcher reports as
 * "the session did not start". It links nothing but libc. */

#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <linux/capability.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef FLONG_TINI
#error "FLONG_TINI must name tini's store path"
#endif

#define FAILED 125

/* "flong-init: <message>", then exit 125. */
static _Noreturn void vfail(int err, const char *fmt, va_list ap)
{
	fputs("flong-init: ", stderr);
	vfprintf(stderr, fmt, ap);
	if (err)
		fprintf(stderr, ": %s", strerror(err));
	fputc('\n', stderr);
	exit(FAILED);
}

/* A failed call: the message and errno's text. */
static _Noreturn __attribute__((format(printf, 1, 2))) void fail(const char *fmt, ...)
{
	int err = errno;
	va_list ap;
	va_start(ap, fmt);
	vfail(err, fmt, ap);
}

/* A refusal: the message alone. */
static _Noreturn __attribute__((format(printf, 1, 2))) void failx(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfail(0, fmt, ap);
}

/* s whole as a decimal number: no sign, no blanks, no more than max.
 * Returns -1 when s is not one. */
static int decimal(const char *s, unsigned long max, unsigned long *out)
{
	char *end;
	if (*s < '0' || *s > '9')
		return -1;
	errno = 0;
	unsigned long v = strtoul(s, &end, 10);
	if (errno || *end || v > max)
		return -1;
	*out = v;
	return 0;
}

/* A descriptor argument. 0 to 2 are the payload's stdio, never a pipe of the
 * protocol, so naming one is a launcher bug. */
static int fd_arg(const char *s, const char *which)
{
	unsigned long v;
	if (decimal(s, INT_MAX, &v) || v < 3)
		failx("%s descriptor is not a number above 2: %s", which, s);
	return (int)v;
}

/* "-" or comma-separated gids, each a whole decimal number. A gid of
 * (gid_t)-1 is not a group, so it refuses like any other malformed field. */
static gid_t *groups_arg(char *s, size_t *n)
{
	*n = 0;
	if (!strcmp(s, "-"))
		return NULL;
	size_t count = 1;
	for (const char *p = s; *p; p++)
		count += *p == ',';
	if (count > NGROUPS_MAX)
		failx("more supplementary groups than the kernel allows");
	gid_t *gids = calloc(count, sizeof *gids);
	if (!gids)
		fail("groups");
	char *save, *tok;
	for (tok = strtok_r(s, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
		unsigned long v;
		if (decimal(tok, (gid_t)-2, &v))
			failx("not a group id: %s", tok);
		gids[(*n)++] = (gid_t)v;
	}
	/* strtok_r skips empty fields, so ",,1" or "1," would pass silently:
	 * every comma must separate two gids. */
	if (*n != count)
		failx("an empty field in the group list");
	return gids;
}

/* One of two words, the second meaning "no". */
static int flag_arg(const char *s, const char *yes)
{
	if (!strcmp(s, yes))
		return 1;
	if (!strcmp(s, "-"))
		return 0;
	failx("expected %s or -, got %s", yes, s);
}

static void drop_capabilities(void)
{
	/* PR_CAPBSET_READ answers EINVAL past the running kernel's last
	 * capability, which may be newer than this program's headers. */
	for (int cap = 0; prctl(PR_CAPBSET_READ, cap, 0, 0, 0) >= 0; cap++)
		if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0))
			fail("dropping the bounding set");
	if (errno != EINVAL)
		fail("reading the bounding set");
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0))
		fail("clearing the ambient set");
	struct __user_cap_header_struct header = { _LINUX_CAPABILITY_VERSION_3, 0 };
	struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3] = { { 0 } };
	if (syscall(SYS_capset, &header, data))
		fail("capset");
}

static void reset_signals(void)
{
	struct sigaction dfl = { .sa_handler = SIG_DFL };
	sigemptyset(&dfl.sa_mask);
	if (sigaction(SIGINT, &dfl, NULL) || sigaction(SIGQUIT, &dfl, NULL))
		fail("resetting SIGINT and SIGQUIT");
	sigset_t none;
	sigemptyset(&none);
	if (sigprocmask(SIG_SETMASK, &none, NULL))
		fail("emptying the signal mask");
}

int main(int argc, char **argv)
{
	if (argc < 9 || strcmp(argv[7], "--"))
		failx("usage: flong-init GATE READY GROUPS TTY TRACE DIR -- COMMAND...");
	int gate = fd_arg(argv[1], "gate");
	int ready = fd_arg(argv[2], "ready");
	if (gate == ready)
		failx("the gate and ready descriptors are the same");
	size_t ngroups;
	gid_t *groups = groups_arg(argv[3], &ngroups);
	int ctty = flag_arg(argv[4], "ctty");
	int trace = flag_arg(argv[5], "trace");
	const char *dir = argv[6];
	if (dir[0] != '/')
		failx("the working directory is not absolute");

	if (setgroups(ngroups, groups))
		fail("setgroups");
	free(groups);
	drop_capabilities();
	if (ctty && ioctl(0, TIOCSCTTY, 0))
		fail("taking the terminal (TIOCSCTTY)");
	reset_signals();

	/* No handler is installed, so EINTR cannot arrive; a write or read
	 * that ends any other way than with its one byte is the launcher
	 * gone. */
	if (write(ready, "r", 1) != 1)
		fail("telling the launcher the root is built");
	if (close(ready))
		fail("closing the ready pipe");
	char byte;
	ssize_t got = read(gate, &byte, 1);
	if (got < 0)
		fail("waiting at the gate");
	if (got == 0)
		failx("the gate closed without opening: not starting the payload");

	if (chdir(dir))
		fail("changing to %s", dir);
	if (close_range(3, ~0U, 0))
		fail("closing inherited descriptors");

	/* COMMAND is argv[8] onward. The list is tini's three words, COMMAND
	 * and the NULL calloc leaves at the end. */
	char **exec_argv = calloc(3 + (argc - 8) + 1, sizeof *exec_argv);
	if (!exec_argv)
		fail("tini's arguments");
	exec_argv[0] = "tini";
	exec_argv[1] = "-g";
	exec_argv[2] = "--";
	memcpy(exec_argv + 3, argv + 8, (argc - 8) * sizeof *exec_argv);

	if (trace) {
		struct timespec now;
		clock_gettime(CLOCK_REALTIME, &now);
		fprintf(stderr, "T %lld payload-exec\n", (long long)now.tv_sec * 1000000LL + now.tv_nsec / 1000);
	}
	execv(FLONG_TINI, exec_argv);
	fail("executing %s", FLONG_TINI);
}
