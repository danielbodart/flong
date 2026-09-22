/* flong-tty.c: the caller's terminal, and the launcher's wait for bwrap.
 *
 * Two modes, chosen once in tty_prepare. In a relay the payload has a pty of
 * its own, the caller's terminal is raw while the payload runs, and the
 * launcher copies bytes both ways. In passthrough the payload uses the
 * caller's descriptors 0-2 directly, and tini -g takes the terminal's
 * foreground for the payload's group, so the launcher has to give it back
 * afterwards. Either way the caller's modes are restored when the session
 * ends, by the launcher or, when the launcher was killed, by the watchdog.
 *
 * Every wait here is on an event with no timeout: a signal on fl_sigfd, a
 * pidfd, a readable descriptor, a byte or EOF on a pipe. The one clock read
 * is the ^]^]^] check, which compares keystrokes and waits for nothing.
 */
#include "flong-tty.h"

#include "flong-util.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/pidfd.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* nspawn's escape: this key three times within a second ends the session. */
#define ESCAPE_KEY 0x1d
#define ESCAPE_PRESSES 3
#define ESCAPE_WINDOW_NS 1000000000LL

/* Whether SIGTTOU would stop this process: it does only with the default
 * action and while unblocked. A caller that ignores it lets a background
 * process use the terminal, so there is nothing to wait for. */
static int ttou_stops(void)
{
	struct sigaction cur;
	sigset_t mask;
	if (sigaction(SIGTTOU, NULL, &cur) < 0 || sigprocmask(SIG_BLOCK, NULL, &mask) < 0)
		return 0;
	return cur.sa_handler == SIG_DFL && !sigismember(&mask, SIGTTOU);
}

/* Waits until the launcher's group has the terminal's foreground, the way a
 * job that needs the terminal does: SIGTTOU stops the group until the
 * caller's shell brings it to the foreground and continues it. The SIGCONT
 * that continues it stays queued on fl_sigfd, which tells a stop from a
 * discard: the kernel drops SIGTTOU for an orphaned group, whose shell is
 * gone and would never continue it. Such a group could not make the
 * terminal raw or read from it either, so the launch gives up at once,
 * before any session state exists.
 * Returns 0, or -1 (refused, or a terminating signal aborts the launch). */
static int wait_foreground(void)
{
	if (!ttou_stops())
		return 0;
	for (;;) {
		pid_t fg = tcgetpgrp(0);
		/* Not our controlling terminal, or already ours. */
		if (fg < 0 || fg == getpgrp())
			return 0;
		/* A SIGCONT from before this stop says nothing about it. */
		if (fl_take_signal(SIGCONT) < 0)
			return -1;
		if (kill(0, SIGTTOU) < 0)
			return fl_err("SIGTTOU");
		int continued = fl_take_signal(SIGCONT);
		if (continued < 0)
			return -1;
		if (continued == 0)
			return fl_errx("the launcher's job is in the background of its terminal, and orphaned: "
				       "no shell will bring it to the foreground");
	}
}

/* Runs a terminal call with SIGTTOU ignored, so that a launcher in the
 * background of its terminal (in passthrough the payload's group has the
 * foreground by now) can still restore the modes and take the foreground
 * back instead of being stopped. */
static struct sigaction ttou_ignore(void)
{
	struct sigaction ign = { .sa_handler = SIG_IGN }, old;
	sigemptyset(&ign.sa_mask);
	sigaction(SIGTTOU, &ign, &old);
	return old;
}

/* The caller's terminal, raw, from the modes saved at tty_start. */
static int make_raw(const struct fl_tty *t)
{
	struct termios raw = t->modes;
	cfmakeraw(&raw);
	return tcsetattr(0, TCSANOW, &raw);
}

static void restore_modes(const struct termios *modes)
{
	struct sigaction old = ttou_ignore();
	tcsetattr(0, TCSAFLUSH, modes);
	sigaction(SIGTTOU, &old, NULL);
}

/* Gives the terminal's foreground back to the launcher's group, the
 * caller's job. */
static void take_foreground(void)
{
	struct sigaction old = ttou_ignore();
	if (tcgetpgrp(0) != getpgrp())
		tcsetpgrp(0, getpgrp());
	sigaction(SIGTTOU, &old, NULL);
}

int tty_prepare(struct fl_tty *t)
{
	*t = (struct fl_tty){ .master = -1, .slave = -1, .out = -1, .stdio = { -1, -1, -1 },
			      .guard = -1 };

	if (isatty(0)) {
		if (wait_foreground() < 0)
			return -1;
		t->was_fg = tcgetpgrp(0) == getpgrp();
	}
	if (!isatty(0) || !isatty(1))
		return 0;

	/* The master is non-blocking so the relay never stalls on a payload
	 * that is not reading its input while it still has output to drain. */
	char name[64];
	struct termios modes;
	struct winsize ws;
	t->master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC | O_NONBLOCK);
	if (t->master < 0)
		return fl_err("open /dev/ptmx");
	if (grantpt(t->master) < 0 || unlockpt(t->master) < 0 ||
	    ptsname_r(t->master, name, sizeof name) != 0) {
		fl_err("unlock the pty");
		goto fail;
	}
	t->slave = open(name, O_RDWR | O_NOCTTY | O_CLOEXEC);
	if (t->slave < 0) {
		fl_err("open %s", name);
		goto fail;
	}
	/* The payload starts with the caller's modes and window size. */
	if (tcgetattr(0, &modes) < 0 || tcsetattr(t->slave, TCSANOW, &modes) < 0) {
		fl_err("copy the terminal's modes");
		goto fail;
	}
	if (ioctl(0, TIOCGWINSZ, &ws) == 0 && ioctl(t->slave, TIOCSWINSZ, &ws) < 0) {
		fl_err("copy the terminal's size");
		goto fail;
	}
	/* The relay's output goes to the caller's terminal through a
	 * descriptor of its own, non-blocking, so a terminal that stops
	 * draining never blocks the relay in a write while signals and the
	 * escape wait. Opening it again makes a new open file description:
	 * O_NONBLOCK on fd 1 itself would change the caller's shell's too. A
	 * terminal the caller cannot open (after su, say) is written through
	 * fd 1 as it is, only when poll says it takes output. */
	t->out = open("/proc/self/fd/1", O_WRONLY | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
	t->relay = 1;
	t->stdio[0] = t->stdio[1] = t->slave;
	/* A redirected stderr stays where the caller sent it. */
	t->stdio[2] = isatty(2) ? t->slave : -1;
	return 0;
fail:
	fl_close(&t->slave);
	fl_close(&t->master);
	return -1;
}

const int *tty_stdio(const struct fl_tty *t)
{
	return t->relay ? t->stdio : NULL;
}

void tty_spawned(struct fl_tty *t)
{
	if (!t->relay)
		return;
	fl_close(&t->slave);
	t->stdio[0] = t->stdio[1] = t->stdio[2] = -1;
}

/* The watchdog's life: it holds the caller's terminal as fd 0, the read end
 * of a pipe only the launcher writes, and the leader's pidfd. A "done" byte
 * means the launcher restored everything itself. EOF without it means the
 * launcher was killed: the modes are put back, and in passthrough the
 * foreground is taken back once the payload's group is gone, which it is
 * when the leader's pidfd is readable (the session's pid namespace dies with
 * its pid 1). It only takes the foreground from a group with no process left,
 * so a caller's shell that took it back first keeps it.
 *
 * It keeps the caller's stdout and stderr until it exits. A launcher killed
 * in a pipeline (`launcher | cat`) ends its job only when every writer of
 * the pipe is gone; were the watchdog not one of them, the caller's shell
 * could resume, and save the terminal's modes while they are still raw,
 * before the watchdog had restored them. It outlives the launcher only as
 * long as the payload does, which holds the same pipe. */
static _Noreturn void watchdog(const struct fl_tty *t, int pipe_r, int leader_pidfd)
{
	ttou_ignore();
	prctl(PR_SET_NAME, "flong-ttyguard");

	char c;
	ssize_t n;
	while ((n = read(pipe_r, &c, 1)) < 0 && errno == EINTR)
		;
	if (n != 0)
		_exit(0);

	if (t->relay) {
		tcsetattr(0, TCSAFLUSH, &t->modes);
		_exit(0);
	}
	/* Passthrough: the payload may set modes until it is gone. */
	struct pollfd p = { .fd = leader_pidfd, .events = POLLIN };
	while (poll(&p, 1, -1) < 0 && errno == EINTR)
		;
	tcsetattr(0, TCSAFLUSH, &t->modes);
	if (t->was_fg) {
		pid_t fg = tcgetpgrp(0);
		if (fg > 0 && fg != getpgrp() && kill(-fg, 0) < 0 && errno == ESRCH)
			tcsetpgrp(0, getpgrp());
	}
	_exit(0);
}

void tty_resize(const struct fl_tty *t)
{
	struct winsize ws;
	/* A terminal that reports no size leaves the pty's as it is. */
	if (t->relay && t->master >= 0 && ioctl(0, TIOCGWINSZ, &ws) == 0)
		ioctl(t->master, TIOCSWINSZ, &ws);
}

int tty_start(struct fl_tty *t, int leader_pidfd)
{
	/* Nothing to restore when stdin is not a terminal. */
	if (!isatty(0))
		return 0;
	if (tcgetattr(0, &t->modes) < 0)
		return fl_err("read the terminal's modes");
	t->saved = 1;

	/* The watchdog comes first, so the terminal is never raw without one
	 * to restore it: a launcher SIGKILLed at any point after make_raw
	 * leaves a watchdog that reads EOF and puts the saved modes back. */
	int p[2];
	if (pipe2(p, O_CLOEXEC) < 0)
		return fl_err("pipe");
	int keep[] = { p[0], leader_pidfd };
	int pidfd;
	pid_t pid = fl_fork(-1, keep, sizeof keep / sizeof *keep, &pidfd);
	if (pid == 0)
		watchdog(t, p[0], leader_pidfd);
	fl_close(&p[0]);
	if (pid < 0) {
		fl_close(&p[1]);
		return -1;
	}
	/* tty_finish reaps it by pid: it is our child, so the pid is its own
	 * until then. */
	fl_close(&pidfd);
	t->guard = p[1];
	t->guard_pid = pid;

	if (t->relay) {
		/* From the background this stops the launcher with SIGTTOU until
		 * the caller's shell brings it back, as any job's would. */
		if (make_raw(t) < 0)
			return fl_err("make the terminal raw");
		t->raw = 1;
	}
	return 0;
}

/* Writes all of buf to fd, waiting with poll while a non-blocking one is
 * full. Only for the drain after bwrap has exited, when there is nothing
 * left to forward a signal to. Returns 0, or -1 when the terminal has gone
 * (nothing printed: that is a hang-up, not an error). */
static int write_all(int fd, const char *buf, size_t len)
{
	while (len > 0) {
		ssize_t n = write(fd, buf, len);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0 && errno == EAGAIN) {
			struct pollfd p = { .fd = fd, .events = POLLOUT };
			if (poll(&p, 1, -1) < 0 && errno != EINTR)
				return -1;
			continue;
		}
		if (n <= 0)
			return -1;
		buf += n;
		len -= (size_t)n;
	}
	return 0;
}

/* bwrap's status, from a pidfd that is readable. WNOWAIT leaves it to the
 * teardown to reap, as it reaps everything the launcher started. */
static int exit_status(int pidfd)
{
	siginfo_t si = { 0 };
	while (waitid(P_PIDFD, (id_t)pidfd, &si, WEXITED | WNOWAIT) < 0)
		if (errno != EINTR)
			return fl_err("wait for bwrap");
	return fl_status(&si);
}

/* Whether this ^] completes the escape. Any other key starts it over, and
 * so does a ^] more than a second after the first of the run. */
static int escape_pressed(int *presses, struct timespec *first)
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	long long since = (now.tv_sec - first->tv_sec) * 1000000000LL + (now.tv_nsec - first->tv_nsec);
	if (*presses == 0 || since > ESCAPE_WINDOW_NS) {
		*presses = 0;
		*first = now;
	}
	return ++*presses == ESCAPE_PRESSES;
}

int tty_wait(struct fl_tty *t, int bwrap_pidfd, int leader_pidfd)
{
	enum { BWRAP, SIGNALS, MASTER, STDIN, STDOUT };
	char out[65536], in[4096];
	/* Each direction has one buffer, filled by one read and emptied by as
	 * many writes as the other side takes. Its source is not read again
	 * until it is empty, so a side that does not drain holds the other
	 * back and never the loop: every write is to a descriptor poll has
	 * reported writable. */
	size_t out_len = 0, out_off = 0, in_len = 0, in_off = 0;
	int out_fd = t->out >= 0 ? t->out : 1;
	/* master_open: the relay copies between the terminal and the pty. It
	 * ends when every slave is closed (EIO) or when the caller's terminal
	 * goes and the session is hung up by closing the master. */
	int master_open = t->relay && t->master >= 0;
	int presses = 0;
	struct timespec first = { 0 };

	for (;;) {
		struct pollfd p[5] = {
			[BWRAP] = { .fd = bwrap_pidfd, .events = POLLIN },
			[SIGNALS] = { .fd = fl_sigfd, .events = POLLIN },
			/* Left out while it has nothing to take and output
			 * waits: a hung-up master reports POLLHUP whatever the
			 * events asked, and would wake the loop until the
			 * caller's terminal drained. */
			[MASTER] = { .fd = master_open && (out_len == 0 || in_len > 0) ? t->master : -1,
				     .events = (out_len == 0 ? POLLIN : 0) |
					       (in_len > 0 ? POLLOUT : 0) },
			[STDIN] = { .fd = master_open && in_len == 0 ? 0 : -1, .events = POLLIN },
			[STDOUT] = { .fd = out_len > 0 ? out_fd : -1, .events = POLLOUT },
		};
		if (poll(p, 5, -1) < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return fl_err("poll");
		}
		for (int i = 0; i < 5; i++)
			if (p[i].revents & POLLNVAL) {
				errno = EBADF;
				return fl_err("poll");
			}

		if (p[SIGNALS].revents & POLLIN) {
			int sig = fl_next_signal();
			if (sig < 0)
				return -1;
			/* tini -g passes it on to the payload's group. The
			 * pidfd never names another process once the leader
			 * is gone: then the send fails, and bwrap's exit is
			 * next. */
			if (fl_terminating(sig))
				pidfd_send_signal(leader_pidfd, sig, NULL, 0);
			else if (sig == SIGWINCH)
				tty_resize(t);
			else if (sig == SIGCONT && t->raw) {
				/* The caller's shell may have put its own modes
				 * back while the launcher was stopped. */
				make_raw(t);
			}
		}

		if (out_len == 0 && (p[MASTER].revents & (POLLIN | POLLHUP | POLLERR))) {
			ssize_t n = read(t->master, out, sizeof out);
			if (n > 0) {
				out_len = (size_t)n;
			} else if (n == 0 || (errno != EINTR && errno != EAGAIN)) {
				/* EIO: every slave is closed. */
				master_open = 0;
			}
		}

		if (p[STDOUT].revents & (POLLOUT | POLLHUP | POLLERR)) {
			ssize_t n = write(out_fd, out + out_off, out_len - out_off);
			if (n > 0) {
				out_off += (size_t)n;
				if (out_off == out_len)
					out_len = out_off = 0;
			} else if (n < 0 && errno != EINTR && errno != EAGAIN) {
				/* The caller's terminal has gone: hang the
				 * session up, and drop what it cannot show. */
				fl_close(&t->master);
				master_open = 0;
				out_len = out_off = 0;
			}
		}

		if (master_open && in_len > 0 && (p[MASTER].revents & (POLLOUT | POLLHUP | POLLERR))) {
			ssize_t n = write(t->master, in + in_off, in_len - in_off);
			if (n > 0) {
				in_off += (size_t)n;
				if (in_off == in_len)
					in_len = in_off = 0;
			} else if (n < 0 && errno != EINTR && errno != EAGAIN) {
				/* EIO: every slave is closed, and nothing will
				 * read the input. The master is still read
				 * until it says so itself, for the output. */
				in_len = in_off = 0;
			}
		}

		if (master_open && (p[STDIN].revents & (POLLIN | POLLHUP | POLLERR))) {
			ssize_t n = read(0, in, sizeof in);
			if (n > 0) {
				in_len = (size_t)n;
				for (ssize_t i = 0; i < n; i++) {
					if (in[i] != ESCAPE_KEY)
						presses = 0;
					else if (escape_pressed(&presses, &first)) {
						pidfd_send_signal(leader_pidfd, SIGKILL, NULL, 0);
						pidfd_send_signal(bwrap_pidfd, SIGKILL, NULL, 0);
					}
				}
			} else if (n == 0 || (errno != EINTR && errno != EAGAIN)) {
				/* The caller's terminal hung up: hang the session up. */
				fl_close(&t->master);
				master_open = 0;
			}
		}

		if (p[BWRAP].revents & POLLIN)
			break;
	}

	/* bwrap is gone, and with it every process of the session: what the
	 * payload wrote last is in the out buffer and the master. A
	 * non-blocking read flushes the pty's pending buffer before it reports
	 * EIO or EAGAIN, so this drains everything without waiting for the
	 * session. A terminal that does not drain delays only the teardown. */
	if (out_len > 0 && write_all(out_fd, out + out_off, out_len - out_off) < 0)
		master_open = 0;
	while (master_open) {
		ssize_t n = read(t->master, out, sizeof out);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0 || write_all(out_fd, out, (size_t)n) < 0)
			master_open = 0;
	}
	return exit_status(bwrap_pidfd);
}

void tty_finish(struct fl_tty *t)
{
	if (t->saved) {
		restore_modes(&t->modes);
		t->saved = 0;
		t->raw = 0;
	}
	if (t->guard_pid > 0) {
		/* The watchdog exits on this byte, at once. */
		ssize_t n;
		while ((n = write(t->guard, "d", 1)) < 0 && errno == EINTR)
			;
		fl_close(&t->guard);
		while (waitpid(t->guard_pid, NULL, 0) < 0 && errno == EINTR)
			;
		t->guard_pid = 0;
	}
	if (t->was_fg && !t->relay) {
		take_foreground();
		t->was_fg = 0;
	}
	if (t->relay) {
		fl_close(&t->slave);
		fl_close(&t->master);
		fl_close(&t->out);
	}
}
