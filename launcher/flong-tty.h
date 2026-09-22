/* flong-tty.h: the caller's terminal, and the launcher's wait for bwrap.
 *
 * When stdin and stdout are both terminals (--console=autopipe's condition on
 * trunk), the payload gets a pty of its own, allocated on the host devpts
 * before bwrap, and the launcher relays. bwrap then gets --new-session and
 * flong-init takes the pty as its controlling terminal. The caller's terminal
 * is raw only between gate-open and payload exit. Otherwise fds 0-2 pass
 * straight through, so `echo prompt | launcher` keeps working, and afterwards
 * the launcher hands the foreground back and restores termios. Passthrough
 * has no --new-session: it breaks ^C, SIGWINCH and job control.
 *
 * Both modes have a watchdog: a forked child holding nothing but the
 * caller's stdio, a pipe only the launcher writes, and the leader's pidfd.
 * EOF on the pipe without a "done" byte means the launcher was killed; the
 * watchdog restores the saved modes and, in passthrough, waits for the
 * leader's pidfd (the session's pid namespace is gone when it is readable)
 * and takes the foreground back for the caller's group, and only then lets
 * the caller's stdout and stderr go. No clock is involved.
 */
#ifndef FLONG_TTY_H
#define FLONG_TTY_H

#include <sys/types.h>
#include <termios.h>

struct fl_tty {
	int relay;              /* 1: a pty is relayed; 0: fds 0-2 pass through */
	int master;             /* relay: the pty master, O_CLOEXEC; else -1 */
	int slave;              /* relay: the pty slave until bwrap has it; else -1 */
	int out;                /* relay: the caller's terminal opened again,
	                         * O_NONBLOCK, for output; -1 to use fd 1 */
	int stdio[3];           /* relay: bwrap's 0-2 (stderr only when it is a tty) */
	int was_fg;             /* stdin is a terminal whose foreground we had */
	int saved;              /* 1 when modes holds the caller's termios */
	struct termios modes;
	int raw;                /* 1 while the caller's terminal is raw */
	int guard;              /* the watchdog pipe's write end, or -1 */
	pid_t guard_pid;
};

/* First thing after the spec is parsed. When stdin is a terminal and the
 * launcher was started in the background, stops itself with SIGTTOU (as a
 * job that needs the terminal does) until the caller's shell brings it to
 * the foreground; when the group is orphaned the kernel discards the SIGTTOU,
 * no shell will ever continue it, and the launch is refused. Then decides
 * the mode; for a relay opens the pty and gives the slave the caller's
 * termios and window size. Returns 0 or -1. */
int tty_prepare(struct fl_tty *t);

/* bwrap's stdio: NULL in passthrough, t->stdio in relay. */
const int *tty_stdio(const struct fl_tty *t);

/* The launcher has spawned bwrap: close its copy of the slave, so the relay
 * sees EIO once every process in the session has let the pty go. */
void tty_spawned(struct fl_tty *t);

/* Just before the gate opens: saves the caller's modes, starts the watchdog
 * with the leader's pidfd, and only then makes the terminal raw (relay), so
 * the terminal is never raw without a watchdog. The watchdog is forked with
 * fl_fork keeping only 0-2, its pipe and leader_pidfd: a copy of the pty
 * master there would keep the session's terminal from hanging up.
 * Returns 0 or -1. */
int tty_start(struct fl_tty *t, int leader_pidfd);

/* In a relay, copies the caller's window size to the pty. tty_prepare copies
 * it once, and every wait before the gate takes a SIGWINCH and drops it,
 * having no payload to tell, so the gate copies it again once it has taken
 * the signals queued; tty_wait copies it at each SIGWINCH after that. */
void tty_resize(const struct fl_tty *t);

/* The launcher's wait, from gate-open until bwrap exits, in both modes.
 * Polls bwrap's pidfd, fl_sigfd and, in relay, the master and stdin, all
 * with -1. SIGTERM, SIGHUP, SIGINT and SIGQUIT are forwarded to the leader
 * through leader_pidfd, never by its pid, which bwrap may have reaped and
 * the kernel given to another process (tini -g passes them to the payload's
 * group). SIGWINCH copies the window size to the pty; SIGCONT puts raw mode
 * back. EINTR and EAGAIN are retried. Each direction of the relay is a
 * buffer written only when poll says its target takes bytes, so a caller's
 * terminal that stops draining never keeps a signal or the escape waiting.
 * Three ^] within a second (nspawn's escape, a check of the clock at each
 * keystroke, not a wait) SIGKILL the leader and bwrap. Stdin at EOF hangs the
 * session up by closing the master. Returns bwrap's status (0-255, or 128+n
 * when a signal killed it), or -1 on error. bwrap is left unreaped (WNOWAIT)
 * for the teardown, which reaps everything the launcher started. */
int tty_wait(struct fl_tty *t, int bwrap_pidfd, int leader_pidfd);

/* Restores the caller's modes, tells the watchdog it is done, hands the
 * foreground back (passthrough, when we had it: tini -g gave it to the
 * payload's group, which is gone), closes the master. Idempotent; called
 * from the one teardown path whatever stage the launch reached, including
 * before tty_prepare, on a struct that is all zeros. */
void tty_finish(struct fl_tty *t);

#endif
