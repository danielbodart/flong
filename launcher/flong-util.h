/* flong-util.h: what every part of the launcher shares.
 *
 * Messages, file descriptors, waiting and spawning. Every wait here is on an
 * event and none has a timeout: a process's exit is a pidfd polled with -1, a
 * byte is a blocking read on a pipe. A terminating signal is the only thing
 * that ends a wait early, and it does so as an event too, through the
 * launcher's signalfd.
 *
 * Error convention, for this file and every module: a function that can fail
 * prints why, once, at the point of failure, prefixed with the program's name,
 * and returns -1 (or a negative value). Its caller unwinds without printing
 * again. Functions returning a descriptor return it (>= 0) or -1.
 */
#ifndef FLONG_UTIL_H
#define FLONG_UTIL_H

#include <signal.h>
#include <stddef.h>
#include <sys/types.h>
#include <time.h>

/* ---- messages ---- */

/* The prefix of every message: "flong-launch" or "flong-sweeper", set first
 * thing in main. */
extern const char *fl_prog;

/* "prog: <message>: <strerror(errno)>" on stderr. Returns -1, so a failing
 * path can end in `return fl_err(...)`. errno is preserved. */
int fl_err(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* The same without strerror, for refusals that are not a failed call
 * ("a symlink is on the way to /x"). Returns -1. */
int fl_errx(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* fl_err, then _exit(125). Only for a forked child that has nothing to undo:
 * the parent owns every cleanup. */
_Noreturn void fl_die(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* Nonzero when the spec said `trace`. fl_trace then prints
 * "T <CLOCK_REALTIME in microseconds> <stage>" on stderr, the format the
 * spikes' benches parse and that bash's EPOCHREALTIME can be compared with. */
extern int fl_tracing;
void fl_trace(const char *stage);

/* fl_trace for a moment taken earlier: main takes the time first thing and
 * learns only from the spec whether to print it. */
void fl_trace_at(const struct timespec *t, const char *stage);

/* ---- file descriptors ---- */

/* Closes *fd if it is open and sets it to -1. errno is preserved, so it can
 * run on an error path before the error is reported. */
void fl_close(int *fd);

/* Closes every descriptor >= low except those in keep (any order). One
 * close_range per gap. Used at launcher start (inherited descriptors), and by
 * fl_fork's child. */
int fl_close_from(int low, const int *keep, size_t nkeep);

/* Writes all of s to path under dirfd (AT_FDCWD for an absolute path),
 * opened O_WRONLY|O_CLOEXEC|O_NOFOLLOW. For cgroup and /proc files. */
int fl_write_at(int dirfd, const char *path, const char *s);

/* Reads at most size-1 bytes of path under dirfd and NUL-terminates them.
 * Returns the length, or -1. */
ssize_t fl_read_at(int dirfd, const char *path, char *buf, size_t size);

/* ---- names ---- */

/* The longest machine or container name. */
#define FL_NAME_MAX 128

/* Nonzero when the len bytes at s are a machine's or a container's name:
 * [A-Za-z0-9_-][A-Za-z0-9_.-]{0,FL_NAME_MAX-1}. A name becomes a record's file name and
 * a cgroup's, so it holds no '/', and it never starts with '.', which rules
 * out "." and ".." and keeps it clear of dot files. */
int fl_is_name(const char *s, size_t len);

/* ---- the caller ---- */

/* No root anywhere includes the caller: root has no subordinate range, a
 * session made by root would hold host root's reach, and a sweeper run as
 * root would run the postStop programs records name as host root. Returns
 * 0, or -1 (said why) when the real or effective uid is 0. */
int fl_refuse_root(void);

/* ---- signals and waiting ---- */

/* The launcher blocks SIGTERM, SIGHUP, SIGINT, SIGQUIT, SIGWINCH and SIGCONT
 * at start and reads them from this signalfd (-1 in a program without one).
 * SIGPIPE is ignored, so a write to a closed pipe is EPIPE, not death. */
extern int fl_sigfd;

/* The terminating signal that aborted a wait, or 0. Set by fl_await; main
 * turns it into exit status 128+n after the teardown. */
extern volatile int fl_abort_signal;

/* Nonzero for the signals that end a launch before the gate and are
 * forwarded to the payload after it: TERM, HUP, INT and QUIT. */
int fl_terminating(int sig);

/* Records sig as the signal that aborted the launch and returns -1 with
 * errno EINTR, nothing printed: how every wait reports a terminating signal. */
int fl_abort(int sig);

/* Reads one signal from fl_sigfd, which is non-blocking. Returns it, 0 when
 * none is queued, -1 on error. */
int fl_next_signal(void);

/* Takes the signals queued on fl_sigfd, without waiting, until want comes
 * off it (want 0: until none is left). A terminating one on the way aborts
 * (fl_abort); the others are dropped, as fl_await drops them. Returns 1 when
 * want was taken, 0 when the queue ran out first, -1 on an error or a
 * terminating signal. A signal that arrived between two waits is taken here,
 * so the wait after it is not ended by the same signal again. */
int fl_take_signal(int want);

/* Waits, with no timeout, until fd reports one of events, or a terminating
 * signal (TERM, HUP, INT, QUIT) arrives on fl_sigfd. Non-terminating signals
 * (WINCH, CONT) are consumed and ignored here: before the gate there is no
 * payload to tell. EINTR is retried.
 * Returns 1 when fd is ready; -1 on error or on a terminating signal, which
 * is recorded in fl_abort_signal (errno EINTR, nothing printed). */
int fl_await(int fd, short events);

/* ---- processes ---- */

/* A pidfd for pid (pidfd_open). -1 with errno ESRCH when it is gone. */
int fl_pidfd_open(pid_t pid);

/* A child's status from its siginfo, the way a shell reports it: the exit
 * code, or 128+n for a signal. For CLD_EXITED si_status is already the
 * 8-bit code. */
static inline int fl_status(const siginfo_t *si)
{
	return si->si_code == CLD_EXITED ? si->si_status : 128 + si->si_status;
}

/* Waits (fl_await on POLLIN) for our child behind pidfd to exit, reaps it
 * with waitid(P_PIDFD), and closes nothing. Returns fl_status; -1 on error
 * or on a terminating signal (see fl_await). A status the kernel did not
 * keep (ECHILD: a caller left SIGCHLD ignored, and an ignored SIGCHLD
 * survives execve) is an error, not a success: a helper's failure must
 * never open the gate. main resets SIGCHLD first thing for that reason. */
int fl_reap(int pidfd);

/* Kills (when kill is set) and reaps a child on a cleanup path, then closes
 * *pidfd. The wait blocks and ignores signals: it runs after an abort, and
 * after SIGKILL it is short. Nothing when *pidfd is -1. */
void fl_reap_now(int *pidfd, int kill);

/* Field 22 of /proc/<pid>/stat (start time in clock ticks), or 0 when the
 * process is gone. With the pid it names one process for its whole life. */
unsigned long long fl_starttime(pid_t pid);

/* How to start a program. Every field is read; set cgroup to -1 when the
 * program belongs in the launcher's own cgroup. */
struct fl_spawn {
	char *const *argv;   /* argv[0] is absolute: execve, no PATH search */
	char *const *envp;   /* NULL: the launcher's own environment */
	int cgroup;          /* O_PATH fd of the cgroup to create it in, or -1 */
	const int *stdio;    /* NULL: inherit 0-2; else 3 fds, -1 inherits that one */
	const int *keep;     /* descriptors >= 3 it inherits, at their numbers */
	size_t nkeep;
	const char *dir;     /* chdir before exec, or NULL */
};

/* Starts s->argv with clone3(CLONE_PIDFD, plus CLONE_INTO_CGROUP when
 * s->cgroup >= 0), so the program is created in its cgroup and never
 * migrated. In the child, before exec: every signal disposition the launcher
 * set is reset and the signal mask is emptied; stdio is dup2'd; every
 * descriptor >= 3 is marked close-on-exec with close_range(CLOSE_RANGE_CLOEXEC)
 * and only s->keep are cleared again. This is the "close_range before every
 * spawn" rule: nothing the wrapper or the launcher holds (a record lock, the
 * pty master, a namespace fd) reaches a hook, pasta or bwrap by accident.
 * Returns the pidfd (close-on-exec) and stores the pid in *pid when pid is
 * not NULL; -1 on error. An exec failure is reported by the child and shows
 * as exit status 127. */
int fl_spawn(const struct fl_spawn *s, pid_t *pid);

/* fork for a helper that runs launcher code rather than a program (the U1 and
 * U2 helpers, the mount helper, the terminal watchdog). Created with clone3
 * into cgroup when cgroup >= 0. In the child every descriptor >= 3 not in
 * keep is closed at once, because a fork keeps descriptors whatever their
 * close-on-exec flag says: a helper holding the record's lock would keep the
 * session alive for the sweep. The child keeps the launcher's signal mask
 * and must end in _exit.
 * Returns 0 in the child; in the parent the pid, with the pidfd in *pidfd;
 * -1 on error. */
pid_t fl_fork(int cgroup, const int *keep, size_t nkeep, int *pidfd);

/* Takes flock(op) on fd, op LOCK_SH or LOCK_EX, waiting for the holders to
 * let it go. A free lock is taken at once, with LOCK_NB. A held one is
 * waited for by a helper: flock is not a descriptor that can be polled, so a
 * helper forked with fd alone takes the lock in the launcher's stead and
 * exits. The lock belongs to the open file description the two share, and
 * stays held by fd. The launcher waits for the helper's pidfd, so a
 * terminating signal still ends the wait (the helper is then killed).
 * Returns 0 with the lock held; -1 on error or on a terminating signal. */
int fl_lock_wait(int fd, int op);

#endif
