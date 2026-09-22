/* flong-record.c: the state directory, the cache lock, records, liveness,
 * the sweep and postStop.
 *
 * A record's lock is the launcher's life, and a record is only ever seen
 * locked: it is made unnamed with O_TMPFILE, locked and filled, and only
 * then linked into sessions/. The sweep releases a record once it holds the
 * lock itself, the name still names the inode it locked, and the session's
 * pid 1 has exited. Every wait is on an event: a held flock (through
 * fl_lock_wait, a pidfd), a pidfd, a cgroup's cgroup.events, an inotify
 * descriptor.
 *
 * The sweep opens records read-only. inotify reports IN_CLOSE_WRITE only for
 * a descriptor that was open for writing, so the sweeper wakes when a
 * launcher's record is closed, and its own looks at live records do not wake
 * it again. A launcher's close is reported under the O_TMPFILE name
 * "#<inode>", and only that close makes the sweep wait for a lock. A sweep's
 * one writable open, to drop poststop= from a dead session's record, is
 * reported by the record's name; it wakes the sweeper once more, to a sweep
 * that tries every lock with LOCK_NB and finds nothing to do.
 */
#include "flong-record.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

#include "flong-util.h"

/* A record holds two paths and a pid; anything longer is not one of ours. */
#define REC_MAX (2 * PATH_MAX + 64)

/* ---- the state directory and the cache ---- */

/* Refuses a directory that is not the caller's or not mode 0700. Anything
 * running as another user that could write here could make the sweep run
 * its choice of program as the caller. */
static int check_private(int fd, const char *path, const char *sub)
{
	struct stat st;
	if (fstat(fd, &st) < 0)
		return fl_err("stat %s%s", path, sub);
	if (st.st_uid != getuid() || (st.st_mode & 07777) != 0700)
		return fl_errx("%s%s must be a directory of the caller's with mode 0700 "
			       "(it is uid %u, mode %04o)", path, sub, (unsigned)st.st_uid,
			       (unsigned)(st.st_mode & 07777));
	return 0;
}

int state_open(const char *state, int *state_fd, int *sessions_fd)
{
	*state_fd = *sessions_fd = -1;
	int sfd = open(state, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (sfd < 0)
		return fl_err("state directory %s", state);
	if (check_private(sfd, state, "") < 0)
		goto fail;

	/* The umask may take bits away from mkdir's mode but never adds any,
	 * so a sessions/ made here is at most 0700; check_private catches one
	 * made narrower, or one that was already there and wider. */
	if (mkdirat(sfd, "sessions", 0700) < 0 && errno != EEXIST) {
		fl_err("mkdir %s/sessions", state);
		goto fail;
	}
	int dfd = openat(sfd, "sessions", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (dfd < 0) {
		fl_err("open %s/sessions", state);
		goto fail;
	}
	if (check_private(dfd, state, "/sessions") < 0) {
		fl_close(&dfd);
		goto fail;
	}
	*state_fd = sfd;
	*sessions_fd = dfd;
	return 0;
fail:
	fl_close(&sfd);
	return -1;
}

int cache_lock(const char *cache, int *fd)
{
	struct stat locked, named, root;
	int rc = -1;
	*fd = -1;
	int cfd = open(cache, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (cfd < 0) {
		if (errno == ENOENT)
			return 1;
		return fl_err("cache %s", cache);
	}
	/* The one exclusive holder is a sweep of a superseded cache, which
	 * holds the lock while it renames the cache away and deletes it, as
	 * long as that deletion takes. So the wait goes through fl_lock_wait,
	 * which a terminating signal ends. */
	if (fl_lock_wait(cfd, LOCK_SH) < 0)
		goto out;
	/* The lock is on what was opened. If a sweep renamed the cache away
	 * before the lock was granted, the path names another directory now, or
	 * nothing, and this launch must start over from the wrapper. */
	if (fstat(cfd, &locked) < 0) {
		fl_err("stat %s", cache);
		goto out;
	}
	if (stat(cache, &named) < 0) {
		if (errno == ENOENT)
			rc = 1;
		else
			fl_err("stat %s", cache);
		goto out;
	}
	if (named.st_dev != locked.st_dev || named.st_ino != locked.st_ino) {
		rc = 1;
		goto out;
	}
	/* The path naming what was locked is not enough. A sweep may have taken
	 * the cache this launch was prepared against away and another launch's
	 * wrapper made a cache of its own in its place: that one's shared lock
	 * is granted beside this one, and its prepared/ appears only once it has
	 * finished preparing, so the recheck above passes over an empty cache
	 * and bwrap then finds no --overlay-src. A cache without the root is
	 * answered as a swept one is: the wrapper, run again, waits for the
	 * preparer's lock and finds the root made. Once the root is seen under
	 * this shared lock it stays, since a sweep must hold the lock
	 * exclusively to take the cache away. */
	if (fstatat(cfd, "prepared", &root, 0) < 0) {
		if (errno == ENOENT)
			rc = 1;
		else
			fl_err("stat %s/prepared", cache);
		goto out;
	}
	*fd = cfd;
	rc = 0;
out:
	if (rc != 0)
		fl_close(&cfd);
	return rc;
}

/* ---- reading and writing records ---- */

/* Writes all of buf at the descriptor's offset. A regular file takes a small
 * write whole, so a short write is an error, not something to continue. */
static int write_record(int fd, const char *buf, size_t len, const char *name)
{
	ssize_t n;
	while ((n = write(fd, buf, len)) < 0 && errno == EINTR)
		;
	if (n < 0)
		return fl_err("write the record of %s", name);
	if ((size_t)n != len) {
		errno = EIO;
		return fl_err("write the record of %s", name);
	}
	return 0;
}

/* Reads a whole record into buf (REC_MAX + 1 bytes) and NUL-terminates it.
 * Returns the length, or -1 when it cannot be read or is too long to be a
 * record. Prints nothing: the caller says what the record was for. */
static ssize_t read_record(int fd, char *buf)
{
	size_t len = 0;
	for (;;) {
		ssize_t n = pread(fd, buf + len, REC_MAX + 1 - len, (off_t)len);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0)
			return -1;
		if (n == 0)
			break;
		len += (size_t)n;
		if (len > REC_MAX) {
			errno = EFBIG;
			return -1;
		}
	}
	buf[len] = '\0';
	return (ssize_t)len;
}

/* Blanks the poststop= line, which is always the first, with newlines, in
 * one write of at most a line: the record is then exactly what it was without
 * the key, and a launcher or sweeper killed at any moment leaves either the
 * old record or the new one, never half of each. buf holds the record. */
static int blank_poststop(int fd, const char *buf, const char *name)
{
	if (strncmp(buf, "poststop=", 9) != 0)
		return 0;
	size_t len = strcspn(buf, "\n") + 1;
	char blank[PATH_MAX + 16];
	if (len > sizeof blank) {
		errno = EFBIG;
		return fl_err("drop poststop= from the record of %s", name);
	}
	memset(blank, '\n', len);
	ssize_t n;
	while ((n = pwrite(fd, blank, len, 0)) < 0 && errno == EINTR)
		;
	if (n < 0 || (size_t)n != len) {
		if (n >= 0)
			errno = EIO;
		return fl_err("drop poststop= from the record of %s", name);
	}
	return 0;
}

/* What a record says, once it has been checked to be well formed. */
struct rec_fields {
	char poststop[PATH_MAX];   /* "" when absent */
	char cgroup[PATH_MAX];
	pid_t leader;              /* 0 when absent */
	unsigned long long starttime;
};

/* Copies a value of len bytes into out, NUL-terminated. */
static int take_value(char *out, const char *v, size_t len)
{
	if (len == 0 || len >= PATH_MAX)
		return -1;
	memcpy(out, v, len);
	out[len] = '\0';
	return 0;
}

/* Parses "<pid>:<starttime>", both decimal. A starttime of 0 means bwrap's
 * child was already gone when it was recorded, which no live process can
 * match. */
static int take_leader(struct rec_fields *f, const char *v, size_t len)
{
	char tmp[64], *end;
	if (len == 0 || len >= sizeof tmp)
		return -1;
	memcpy(tmp, v, len);
	tmp[len] = '\0';
	if (tmp[0] < '1' || tmp[0] > '9')
		return -1;
	errno = 0;
	long pid = strtol(tmp, &end, 10);
	if (errno || *end != ':' || pid > INT_MAX)
		return -1;
	char *st = end + 1;
	if (*st < '0' || *st > '9')
		return -1;
	unsigned long long start = strtoull(st, &end, 10);
	if (errno || *end != '\0')
		return -1;
	f->leader = (pid_t)pid;
	f->starttime = start;
	return 0;
}

/* Checks a record's form: "key=value" lines, poststop= then cgroup= then
 * leader=, each at most once, cgroup= required, and nothing else but empty
 * lines (a blanked poststop=). Returns 0, or -1 with *why saying what is
 * wrong. What the values name is checked by the sweep. */
static int parse_record(const char *buf, size_t len, struct rec_fields *f, const char **why)
{
	static const char *const keys[] = { "poststop=", "cgroup=", "leader=" };
	int next = 0;
	memset(f, 0, sizeof *f);
	if (memchr(buf, '\0', len) || (len > 0 && buf[len - 1] != '\n')) {
		*why = "it is not lines of text";
		return -1;
	}
	for (const char *line = buf; line < buf + len;) {
		const char *nl = memchr(line, '\n', (size_t)(buf + len - line));
		size_t n = (size_t)(nl - line);
		const char *at = line;
		line = nl + 1;
		if (n == 0)
			continue;
		int k = next;
		while (k < 3 && strncmp(at, keys[k], strlen(keys[k])) != 0)
			k++;
		if (k == 3) {
			*why = "it has an unknown, repeated or misplaced line";
			return -1;
		}
		size_t kl = strlen(keys[k]);
		const char *v = at + kl;
		int bad = k == 0 ? take_value(f->poststop, v, n - kl)
			: k == 1 ? take_value(f->cgroup, v, n - kl)
			: take_leader(f, v, n - kl);
		if (bad) {
			*why = k == 2 ? "its leader= is not <pid>:<starttime>"
				      : "a path in it is empty or too long";
			return -1;
		}
		next = k + 1;
	}
	if (!f->cgroup[0]) {
		*why = "it has no cgroup=";
		return -1;
	}
	return 0;
}

/* ---- the launcher's own record ---- */

/* How sweep_one takes a record's lock. */
enum lock_mode {
	LOCK_TRY,          /* LOCK_NB: a held lock is a live launcher */
	LOCK_WAIT,         /* wait for it: its launcher is known to be gone */
	LOCK_WAIT_ENDED,   /* wait for it only when the recorded pid 1 has exited */
};

/* sweep_one's answers besides release's. */
enum { SWEEP_GONE = 2, SWEEP_RUNNING = 3 };

static int sweep_one(int dfd, const char *name, const struct fl_holder *h, enum lock_mode mode);

int rec_create(struct fl_record *r, int sessions_fd, const struct fl_holder *h,
	       const char *machine, const char *post_stop, const char *cgroup_path)
{
	char buf[REC_MAX], proc[64];
	r->dirfd = sessions_fd;
	r->fd = -1;
	r->name = machine;
	r->linked = 0;

	/* A newline in a value would be a line of its own choosing. */
	if ((post_stop && strchr(post_stop, '\n')) || strchr(cgroup_path, '\n'))
		return fl_errx("a newline is in the postStop path or the cgroup path of %s",
			       machine);
	int n = snprintf(buf, sizeof buf, "%s%s%scgroup=%s\n",
			 post_stop ? "poststop=" : "", post_stop ? post_stop : "",
			 post_stop ? "\n" : "", cgroup_path);
	if (n < 0 || (size_t)n >= sizeof buf)
		return fl_errx("the record of %s is too long", machine);

	int fd = openat(sessions_fd, ".", O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
	if (fd < 0)
		return fl_err("make the record of %s", machine);
	/* Nobody else can see an unnamed file, so the lock is granted at once. */
	if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
		fl_err("lock the record of %s", machine);
		goto fail;
	}
	if (write_record(fd, buf, (size_t)n, machine) < 0)
		goto fail;
	/* linkat through /proc names the unnamed file without the capability
	 * AT_EMPTY_PATH needs, and refuses a name that exists: the O_EXCL. */
	snprintf(proc, sizeof proc, "/proc/self/fd/%d", fd);
	while (linkat(AT_FDCWD, proc, sessions_fd, machine, AT_SYMLINK_FOLLOW) < 0) {
		if (errno != EEXIST) {
			fl_err("record %s", machine);
			goto fail;
		}
		/* The name is taken. A session that has ended keeps it until it
		 * is released: by its launcher's teardown, or by a sweep, which
		 * holds the lock while it waits for pasta to go and runs
		 * postStop, and which the inline sweep therefore took for a live
		 * launcher. Running the same machine again right after it exits
		 * waits for that release, on the lock, and takes the name once
		 * it is free. There is no count: each turn follows the release
		 * of the session that held the name, and a running one refuses. */
		switch (sweep_one(sessions_fd, machine, h, LOCK_WAIT_ENDED)) {
		case 1:
		case SWEEP_GONE:
			continue;
		case SWEEP_RUNNING:
			fl_errx("a session named %s is already running", machine);
			goto fail;
		case 0:
			fl_errx("a session named %s has ended but cannot be released yet", machine);
			goto fail;
		default:
			goto fail;
		}
	}
	r->fd = fd;
	r->linked = 1;
	return 0;
fail:
	fl_close(&fd);
	return -1;
}

int rec_set_leader(struct fl_record *r, pid_t leader)
{
	char buf[64];
	int n = snprintf(buf, sizeof buf, "leader=%d:%llu\n", (int)leader,
			 fl_starttime(leader));
	/* One append, which a SIGKILL cannot split. */
	return write_record(r->fd, buf, (size_t)n, r->name);
}

int rec_poststop_done(struct fl_record *r)
{
	char buf[REC_MAX + 1];
	if (read_record(r->fd, buf) < 0)
		return fl_err("read the record of %s", r->name);
	return blank_poststop(r->fd, buf, r->name);
}

void rec_remove(struct fl_record *r)
{
	/* Unlinked first, then unlocked: a sweep that opened the record before
	 * the unlink and is granted the lock after the close finds it has no
	 * links and leaves it. */
	if (r->linked && unlinkat(r->dirfd, r->name, 0) < 0)
		fl_err("remove the record of %s", r->name);
	r->linked = 0;
	fl_close(&r->fd);
}

void rec_close(struct fl_record *r)
{
	r->linked = 0;
	fl_close(&r->fd);
}

/* ---- postStop ---- */

/* Nonzero when path has a ".." component. */
static int has_dotdot(const char *path)
{
	for (const char *p = path; (p = strstr(p, "..")) != NULL; p += 2)
		if ((p == path || p[-1] == '/') && (p[2] == '\0' || p[2] == '/'))
			return 1;
	return 0;
}

int fl_poststop(const char *path, const char *machine)
{
	char real[PATH_MAX], env[sizeof "machine=" + FL_NAME_MAX];
	int pidfd, rc;

	/* A symlink in the store may point anywhere, so the target is checked
	 * and run, with the same test as the path the record names. */
	if (strncmp(path, "/nix/store/", 11) != 0 || has_dotdot(path) ||
	    !realpath(path, real) || strncmp(real, "/nix/store/", 11) != 0 ||
	    access(real, X_OK) < 0) {
		fl_errx("postStop failed for %s: %s is not a program in /nix/store",
			machine, path);
		return 0;
	}
	/* machine is a name (fl_is_name), so it fits. */
	snprintf(env, sizeof env, "machine=%s", machine);

	int null = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (null < 0) {
		fl_err("postStop failed for %s: open /dev/null", machine);
		return 0;
	}
	char *argv[] = { real, (char *)machine, NULL };
	char *envp[] = { env, NULL };
	int stdio[3] = { null, -1, -1 };
	struct fl_spawn s = {
		.argv = argv, .envp = envp, .cgroup = -1, .stdio = stdio,
		.keep = NULL, .nkeep = 0, .dir = "/",
	};
	pidfd = fl_spawn(&s, NULL);
	fl_close(&null);
	/* fl_spawn has said why when it fails. */
	if (pidfd < 0)
		return 0;
	rc = fl_reap(pidfd);
	if (rc < 0) {
		/* fl_await's abort is the one failure that leaves errno EINTR
		 * (waitid's is retried). An aborted postStop has not finished,
		 * so the caller must leave the record able to run it again, and
		 * it is killed now, not left behind to overlap that rerun. */
		int aborted = errno == EINTR;
		fl_reap_now(&pidfd, 1);
		return aborted ? -1 : 0;
	}
	fl_close(&pidfd);
	if (rc)
		fl_errx("postStop failed for %s (status %d)", machine, rc);
	return 0;
}

/* ---- the sweep ---- */

/* A pidfd for the session's recorded pid 1 while it runs. The starttime is
 * read after the pidfd is open, so a pid reused since names another process
 * and does not match, and a match is the pidfd's own process. Returns the
 * pidfd; -1 with errno ESRCH when the recorded process is gone (or there is
 * no leader= yet: the caller decides what that means); -1 on error. */
static int open_leader(const struct rec_fields *f)
{
	if (!f->leader) {
		errno = ESRCH;
		return -1;
	}
	int pidfd = fl_pidfd_open(f->leader);
	if (pidfd < 0)
		return -1;
	if (fl_starttime(f->leader) != f->starttime) {
		fl_close(&pidfd);
		errno = ESRCH;
		return -1;
	}
	return pidfd;
}

/* Waits for the session's recorded pid 1 to exit. Returns 0 once it is
 * gone, -1 on error or a terminating signal. */
static int wait_leader(const struct rec_fields *f)
{
	int pidfd = open_leader(f);
	if (pidfd < 0)
		return errno == ESRCH ? 0 : -1;
	int rc = fl_await(pidfd, POLLIN) < 0 ? -1 : 0;
	fl_close(&pidfd);
	return rc;
}

/* Releases one dead session, whose record's lock the sweep holds (fd, read
 * only). Returns 1 when released; 0 when it was reported and left, was
 * another holder's and left for that holder's sweep, or was not a
 * launcher's record and is removed; -1 when a terminating signal ends the
 * sweep. */
static int release(int dfd, const char *name, int fd, const struct fl_holder *h)
{
	char buf[REC_MAX + 1];
	struct rec_fields f;
	struct fl_cgroup cg = FL_CGROUP_NONE;
	const char *why;
	int have_cg = 0, rc = 0;

	ssize_t len = read_record(fd, buf);
	if (len < 0) {
		fl_err("read the record of %s", name);
		return 0;
	}
	/* A record that is not well formed, or does not name a session's
	 * cgroup, was not written by a launcher: nothing it says is acted on. */
	if (parse_record(buf, (size_t)len, &f, &why) < 0) {
		fl_errx("the record of %s is removed: %s", name, why);
		goto drop;
	}
	have_cg = cg_session_open(&cg, h, f.cgroup, name);
	/* A session under another holder (another unit's launch, or one with
	 * and one without a user manager) is that holder's to release: its
	 * cgroup is not ours to kill, and its postStop must still run. */
	if (have_cg == FL_CG_OTHER_HOLDER)
		goto left;
	if (have_cg == FL_CG_REFUSED) {
		fl_errx("the record of %s is removed: its cgroup is refused", name);
		goto drop;
	}
	/* A cgroup that could not be opened may be opened by the next sweep
	 * (EMFILE, ENOMEM): the record is the only trace of what is left in
	 * it, so it stays. */
	if (have_cg < 0)
		goto left;

	if (have_cg && (cg_kill(&cg) < 0 || cg_wait_empty(cg.fd) < 0))
		goto left;
	if (wait_leader(&f) < 0)
		goto left;

	if (f.poststop[0]) {
		/* An aborted postStop keeps poststop=, for the next sweep. */
		if (fl_poststop(f.poststop, name) < 0)
			goto left;
		/* postStop runs once, even if the sweep dies before the unlink:
		 * the record loses poststop= through a writable descriptor of its
		 * own, which the sweep closes at once. */
		char proc[64];
		snprintf(proc, sizeof proc, "/proc/self/fd/%d", fd);
		int wfd = open(proc, O_WRONLY | O_CLOEXEC);
		if (wfd < 0) {
			fl_err("drop poststop= from the record of %s", name);
			goto left;
		}
		int bad = blank_poststop(wfd, buf, name);
		fl_close(&wfd);
		if (bad)
			goto left;
	}
	if (have_cg) {
		int busy = cg_remove(&cg);
		if (busy < 0)
			goto left;
		if (busy > 0) {
			fl_errx("the cgroup of %s is still busy; left for the next sweep", name);
			goto left;
		}
	}
	rc = 1;
drop:
	if (unlinkat(dfd, name, 0) < 0) {
		fl_err("remove the record of %s", name);
		rc = 0;
	}
left:
	cg_close(&cg);
	return fl_abort_signal ? -1 : rc;
}

/* Whether a record's session is still running, as far as its leader= says:
 * a session with no leader= yet is starting, and one whose leader is the
 * recorded process is running. An error to ask counts as running, so the
 * answer never ends a live session. */
static int leader_running(const struct rec_fields *f)
{
	if (!f->leader)
		return 1;
	int pidfd = open_leader(f);
	if (pidfd < 0)
		return errno != ESRCH;
	fl_close(&pidfd);
	return 1;
}

/* Whether the record behind fd has ended: its lock is held, but its leader=
 * says the session's pid 1 has exited, so the holder is a launcher in its
 * teardown or a sweep releasing it, and will let go. */
static int record_ended(int fd)
{
	char buf[REC_MAX + 1];
	struct rec_fields f;
	const char *why;
	ssize_t len = read_record(fd, buf);
	return len >= 0 && parse_record(buf, (size_t)len, &f, &why) == 0 && !leader_running(&f);
}

/* Takes the lock of the record name and releases its session when the name
 * still names the inode it locked. A lock granted is a dead launcher's only
 * then: another sweeper may have released the record, and a new session
 * taken the name, between the open and the lock.
 * Returns release's answer (1 released, 0 left, -1 a terminating signal),
 * SWEEP_GONE when the name is gone or names another record now, and
 * SWEEP_RUNNING when the lock is held and mode does not wait for it. A
 * failure to open or lock is reported, and the record left (0). */
static int sweep_one(int dfd, const char *name, const struct fl_holder *h, enum lock_mode mode)
{
	struct stat a, b;
	int r = 0;
	/* O_NONBLOCK: a FIFO planted here must not hang the open. */
	int fd = openat(dfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOENT)
			return SWEEP_GONE;
		/* A symlink is not a record. */
		if (errno != ELOOP)
			fl_err("open the record of %s", name);
		return 0;
	}
	if (fstat(fd, &a) < 0 || !S_ISREG(a.st_mode))
		goto out;
	if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
		if (errno != EWOULDBLOCK) {
			fl_err("lock the record of %s", name);
			goto out;
		}
		r = SWEEP_RUNNING;
		if (mode == LOCK_TRY || (mode == LOCK_WAIT_ENDED && !record_ended(fd)))
			goto out;
		r = 0;
		if (fl_lock_wait(fd, LOCK_EX) < 0) {
			if (fl_abort_signal)
				r = -1;
			goto out;
		}
	}
	r = SWEEP_GONE;
	if (fstat(fd, &a) < 0 || a.st_nlink == 0 ||
	    fstatat(dfd, name, &b, AT_SYMLINK_NOFOLLOW) < 0 ||
	    a.st_dev != b.st_dev || a.st_ino != b.st_ino)
		goto out;
	r = release(dfd, name, fd, h);
out:
	fl_close(&fd);
	return r;
}

/* rec_sweep, waiting for the lock of each record whose inode is in waits
 * (rec_watch's: records a launcher has just let go). Every other record is
 * tried once with rest: LOCK_TRY, or LOCK_WAIT_ENDED when rec_watch may have
 * missed a close. */
static int sweep_dir(int sessions_fd, const struct fl_holder *h,
		     const ino_t *waits, size_t nwaits, enum lock_mode rest)
{
	int released = 0;
	/* A descriptor of its own, so each sweep reads from the start and the
	 * caller's sessions_fd keeps no offset. */
	int dfd = openat(sessions_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dfd < 0)
		return fl_err("open sessions");
	DIR *d = fdopendir(dfd);
	if (!d) {
		fl_err("read sessions");
		fl_close(&dfd);
		return -1;
	}
	for (;;) {
		errno = 0;
		struct dirent *e = readdir(d);
		if (!e) {
			if (errno) {
				fl_err("read sessions");
				released = -1;
			}
			break;
		}
		/* Anything but a machine's name is not one of ours and is left
		 * alone. */
		if (!fl_is_name(e->d_name, strlen(e->d_name)))
			continue;
		enum lock_mode mode = rest;
		for (size_t i = 0; i < nwaits; i++)
			if (waits[i] == e->d_ino)
				mode = LOCK_WAIT;
		int r = sweep_one(dirfd(d), e->d_name, h, mode);
		if (r < 0) {
			released = -1;
			break;
		}
		released += r == 1;
	}
	closedir(d);
	return released;
}

int rec_sweep(int sessions_fd, const struct fl_holder *h)
{
	return sweep_dir(sessions_fd, h, NULL, 0, LOCK_TRY);
}

/* The inode of the record whose lock an IN_CLOSE_WRITE event says is being
 * let go, or 0. A launcher's record was made with O_TMPFILE, and its
 * descriptor keeps the name the kernel gave the unnamed file, "#<inode>",
 * whatever name it was linked under since: that is the name its final close
 * reports. Any other name is a sweep's writable open, the sweeper's own or
 * another launcher's, closed after it blanked poststop=. That sweep held
 * the lock and has nothing to hand on, and by the time the event is read
 * the name may already be a relaunch's live record, so it is not resolved:
 * the event still wakes a sweep, which tries every record with LOCK_NB. */
static ino_t closed_inode(const char *name)
{
	if (name[0] != '#')
		return 0;
	char *end;
	errno = 0;
	unsigned long long ino = strtoull(name + 1, &end, 10);
	return errno || end == name + 1 || *end != '\0' ? 0 : (ino_t)ino;
}

int rec_watch(int sessions_fd, const struct fl_holder *h)
{
	char proc[64];
	char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
	/* A batch of events names at most this many records: each takes more
	 * than 16 bytes of buf. */
	ino_t waits[sizeof buf / sizeof(struct inotify_event)];
	size_t nwaits = 0;
	enum lock_mode rest = LOCK_TRY;

	int ifd = inotify_init1(IN_CLOEXEC);
	if (ifd < 0)
		return fl_err("inotify");
	/* The watch comes before the first sweep, so a record closed between
	 * the two is not missed. */
	snprintf(proc, sizeof proc, "/proc/self/fd/%d", sessions_fd);
	if (inotify_add_watch(ifd, proc, IN_CLOSE_WRITE | IN_ONLYDIR) < 0) {
		fl_err("watch sessions");
		fl_close(&ifd);
		return -1;
	}
	for (;;) {
		int n = sweep_dir(sessions_fd, h, waits, nwaits, rest);
		if (n < 0)
			break;
		if (n > 0)
			fl_errx("released %d dead session%s", n, n == 1 ? "" : "s");
		ssize_t got;
		while ((got = read(ifd, buf, sizeof buf)) < 0 && errno == EINTR)
			;
		if (got <= 0) {
			fl_err("read inotify");
			break;
		}
		/* The kernel queues IN_CLOSE_WRITE in __fput before it drops the
		 * descriptor's flock, so a sweep that answers the event can find
		 * the lock still held, and no later event would come for that
		 * record. A close reported under "#<inode>" is a launcher's last
		 * descriptor of its record, so that lock is being let go: the
		 * sweep waits for it, an event with no timeout, instead of trying
		 * once. It waits only for that inode, never for whatever the
		 * record's name names by then, which may be a relaunch that is
		 * running. */
		nwaits = 0;
		rest = LOCK_TRY;
		for (char *p = buf; p < buf + got;) {
			struct inotify_event *ev = (struct inotify_event *)p;
			/* IN_Q_OVERFLOW: events were dropped, and a launcher's
			 * "#<inode>" close may be among them. The next sweep then
			 * waits for the lock of every record whose pid 1 has
			 * exited, since only a holder that is letting go keeps
			 * such a lock; a record whose session runs is tried once. */
			if (ev->mask & IN_Q_OVERFLOW)
				rest = LOCK_WAIT_ENDED;
			/* IN_IGNORED: sessions/ itself is gone, and nothing will
			 * be recorded in it again. */
			if (ev->mask & IN_IGNORED) {
				fl_errx("sessions/ was removed");
				fl_close(&ifd);
				return -1;
			}
			ino_t ino;
			if ((ev->mask & IN_CLOSE_WRITE) && ev->len &&
			    (ino = closed_inode(ev->name)) != 0)
				waits[nwaits++] = ino;
			p += sizeof *ev + ev->len;
		}
	}
	fl_close(&ifd);
	return -1;
}
