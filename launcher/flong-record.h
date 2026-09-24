/* flong-record.h: the lifecycle. State directory, cache lock, session
 * records, liveness, the sweep, postStop.
 *
 * A record is $XDG_RUNTIME_DIR/flong/sessions/<machine>, one per session and
 * per user, so any launch sweeps any dead session. Its lock (flock, held
 * only by the launcher) says the launcher is alive. A session is dead only
 * when its lock is free and its recorded pid 1 has exited: a lock alone is
 * granted 1-1.5 ms before the session's last process is gone.
 *
 * Records are the caller's files, so anything running as the caller can
 * write one. The sweep is defensive about them: it validates the cgroup and
 * the postStop path, chdirs to /, gives postStop /dev/null and a fixed
 * environment. Condition 4 of the plan (no bind reaches the state directory)
 * is the first line; this is the second.
 *
 * Record format, one "key=value" per line, keys in this order:
 *   poststop=<a /nix/store program>   absent when none, and once it has run
 *   cgroup=<absolute session cgroup path>
 *   leader=<pid>:<starttime>          appended once bwrap reports its child
 */
#ifndef FLONG_RECORD_H
#define FLONG_RECORD_H

#include <sys/types.h>
#include "flong-cgroup.h"

/* ---- the state directory and the cache ---- */

/* Opens state (the caller's, mode exactly 0700, a directory, not a symlink)
 * and its sessions/ subdirectory (made 0700 when absent, checked the same).
 * Refuses anything else: the records there make the sweep run programs.
 * Returns 0 with both descriptors (O_RDONLY|O_DIRECTORY|O_CLOEXEC), or -1. */
int state_open(const char *state, int *state_fd, int *sessions_fd);

/* Takes a shared flock on the cache directory, waiting with fl_lock_wait
 * (the only exclusive holder is a sweep of a superseded cache, which keeps
 * the lock while it renames the cache away and deletes it), then checks that
 * the path still names the inode it locked and that the inode holds the
 * prepared root.
 * Returns 0 with *fd holding the lock for the launcher's life; 1 when the
 * cache was swept (absent, renamed before the lock was granted, or made
 * afresh in its place by a wrapper that is still preparing it); -1 on
 * error. Called before the launcher closes inherited descriptors, so a cold
 * wrapper's own shared lock is never released before this one is held. */
int cache_lock(const char *cache, int *fd);

/* ---- the launcher's own record ---- */

struct fl_record {
	int dirfd;           /* sessions/, not owned */
	int fd;              /* the record, O_RDWR|O_CLOEXEC, flock'd LOCK_EX; -1 */
	const char *name;    /* the machine name */
	int linked;          /* 1 once it is in the directory */
};

/* Creates the record already locked: O_TMPFILE in sessions/, flock, write
 * poststop= (when post_stop is not NULL) and cgroup=, then linkat it into
 * place as <machine>. A record is never seen unlocked or half-written.
 * A name already taken (EEXIST) is a refusal while that session runs: it
 * has no leader= yet, or its leader is alive. When its leader has exited,
 * the session is ending, and whoever holds its lock (its launcher's
 * teardown, or a sweep waiting for pasta) is releasing it: rec_create waits
 * for the lock, releases the session itself if it is still there (with h,
 * as the sweep does), and links the name then. Called after the inline
 * sweep, before U1: the record exists before the cgroup and before the hook,
 * so postStop runs even for a launcher killed mid-hook. Returns 0 or -1. */
int rec_create(struct fl_record *r, int sessions_fd, const struct fl_holder *h,
	       const char *machine, const char *post_stop, const char *cgroup_path);

/* Appends leader=<pid>:<starttime>. Called once, at child-pid. */
int rec_set_leader(struct fl_record *r, pid_t leader);

/* Rewrites the record without poststop=, once postStop has run, so a sweep
 * of a record left behind (below) does not run it again. */
int rec_poststop_done(struct fl_record *r);

/* Unlinks the record and closes it, releasing the lock. The last step of a
 * teardown whose cgroup is gone. */
void rec_remove(struct fl_record *r);

/* Closes the record without unlinking it: its cgroup could not be removed
 * yet (pasta still exiting), and the sweep will finish the job. Also what
 * happens to a record, implicitly, when the launcher is killed. */
void rec_close(struct fl_record *r);

/* ---- postStop ---- */

/* Runs a postStop program for machine and waits for it, the same way from
 * the launcher's teardown and from the sweep: only when path starts with
 * /nix/store/, holds no ".." component and is executable; argv {path,
 * machine}; environment exactly {"machine=<machine>"}; stdin /dev/null,
 * stdout and stderr inherited; working directory /; in the caller's cgroup.
 * Returns 0 once postStop has run: a failure prints "postStop failed for
 * <machine>" and never changes the launch's exit status. Returns -1 when a
 * terminating signal ended the wait (fl_abort_signal set): postStop is then
 * killed and reaped, has not finished, and the caller keeps poststop= in
 * the record so the sweep runs it again (postStop is idempotent). */
int fl_poststop(const char *path, const char *machine);

/* ---- the sweep ---- */

/* Releases every dead session in sessions/. For each record whose lock is
 * free (LOCK_EX|LOCK_NB) and that is still the linked inode it opened (ten
 * concurrent sweepers run a dead session's postStop exactly once):
 *   validate cgroup= (cg_session_open) and leader=; a record that fails is
 *   reported and unlinked, since nothing it names can be trusted; a record
 *   whose session is under another holder is left, unreported, for that
 *   holder's sweep;
 *   cgroup.kill; wait for the whole session cgroup to empty;
 *   wait for the leader's pidfd when its starttime matches (poll -1);
 *   postStop, if poststop= is present; remove the cgroup; unlink the record.
 * Runs inline at launch start (20 us when there is nothing to do) and in the
 * sweeper. Returns the number released, or -1 when sessions/ cannot be read;
 * a record that cannot be released is reported and skipped. */
int rec_sweep(int sessions_fd, const struct fl_holder *h);

/* The sweeper's loop, in the holder unit's process: one rec_sweep, then
 * inotify on sessions/ for IN_CLOSE_WRITE (a launcher's last close of its
 * record, on any exit, SIGKILL included), and a sweep for each batch of
 * events. So a killed launcher's postStop and hook daemons do not wait for
 * the next launch. The kernel queues IN_CLOSE_WRITE before it drops the
 * closed descriptor's lock, so that sweep waits for the lock of each record
 * a launcher's close names (its O_TMPFILE name, "#<inode>"), where rec_sweep
 * tries it once. A close under a record's name is a sweep's own writable
 * open and is never waited on. After IN_Q_OVERFLOW, when such a close may
 * have been dropped, the sweep waits for the lock of every record whose
 * pid 1 has exited. Returns only on error (-1). Nothing calls it since the
 * C sweeper was deleted (ZIG.md, phase 5 (b)): src/record.zig's `watch` is
 * the one the sweeper runs. */
int rec_watch(int sessions_fd, const struct fl_holder *h);

#endif
