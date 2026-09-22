/* flong-cgroup.c: the session cgroup. See flong-cgroup.h.
 *
 * Everything here is reached from descriptors once the holder is open:
 * the container level, the session and its leaves are each opened with one
 * path component under their parent, with O_NOFOLLOW, and removed the same
 * way. cgroupfs has no symlinks of its own and cgroup2 cannot rename a
 * cgroup, so a descriptor keeps naming the directory it was opened on.
 */
#include "flong-cgroup.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "flong-util.h"

#define CGROOT "/sys/fs/cgroup"

static const char *const leaf_name[FL_NLEAVES] = { "sandbox", "hooks", "pasta" };

/* ---- the nsdelegate check ---- */

/* Nonzero when item is one of the items in list, separated by sep: the
 * options of a mount, the controllers of a cgroup. */
static int has_item(const char *list, const char *item, char sep)
{
	size_t len = strlen(item);
	for (const char *p = list; p; p = strchr(p, sep)) {
		if (*p == sep)
			p++;
		if (strncmp(p, item, len) == 0 && (p[len] == sep || p[len] == '\0'))
			return 1;
	}
	return 0;
}

int cg_check_nsdelegate(void)
{
	FILE *f = fopen("/proc/self/mountinfo", "re");
	if (!f)
		return fl_err("open /proc/self/mountinfo");

	/* A mountinfo line is "id parent dev root mountpoint options
	 * [optional...] - fstype source superoptions", its fields separated by
	 * single spaces (a space inside a field is written \040). nsdelegate
	 * is a superblock option. The last mount on /sys/fs/cgroup is the one
	 * on top, the one a path reaches. */
	char *line = NULL;
	size_t cap = 0;
	int is_cgroup2 = 0, delegated = 0;
	while (getline(&line, &cap, f) > 0) {
		line[strcspn(line, "\n")] = '\0';
		char *field[5], *save = NULL, *p = line;
		int n = 0;
		for (; n < 5 && (field[n] = strtok_r(p, " ", &save)); n++)
			p = NULL;
		if (n < 5 || strcmp(field[4], CGROOT) != 0)
			continue;
		char *rest = strtok_r(NULL, "", &save);
		char *sep = rest ? strstr(rest, " - ") : NULL;
		if (!sep)
			continue;
		char *fstype = strtok_r(sep + 3, " ", &save);
		strtok_r(NULL, " ", &save);
		char *super = strtok_r(NULL, " ", &save);
		is_cgroup2 = fstype && strcmp(fstype, "cgroup2") == 0;
		delegated = is_cgroup2 && super && has_item(super, "nsdelegate", ',');
	}
	int failed = ferror(f);
	free(line);
	fclose(f);
	if (failed)
		return fl_err("read /proc/self/mountinfo");

	if (!is_cgroup2)
		return fl_errx("cgroup2 is not mounted at " CGROOT ": sessions need the unified hierarchy");
	if (!delegated)
		return fl_errx("cgroup2 at " CGROOT " is not mounted with nsdelegate: "
			       "a session could move out of the cgroup that reaps it");
	return 0;
}

/* ---- finding the holder ---- */

/* Reads the launcher's own cgroup, the "0::" line of /proc/self/cgroup, into
 * out as an absolute path under /sys/fs/cgroup. */
static int own_cgroup(char *out, size_t size)
{
	char buf[PATH_MAX + 64];
	ssize_t len = fl_read_at(AT_FDCWD, "/proc/self/cgroup", buf, sizeof buf);
	if (len < 0)
		return -1;
	if ((size_t)len == sizeof buf - 1)
		return fl_errx("/proc/self/cgroup is too long");
	char *p = buf;
	while (strncmp(p, "0::", 3) != 0) {
		p = strchr(p, '\n');
		if (!p)
			return fl_errx("no cgroup2 entry in /proc/self/cgroup");
		p++;
	}
	p += 3;
	p[strcspn(p, "\n")] = '\0';
	if (p[0] != '/')
		return fl_errx("an unexpected cgroup in /proc/self/cgroup: %s", p);
	/* The root cgroup is "/", which would give ".../cgroup/". */
	if ((size_t)snprintf(out, size, CGROOT "%s", strcmp(p, "/") == 0 ? "" : p) >= size)
		return fl_errx("the launcher's cgroup path is too long");
	return 0;
}

/* Opens path under dirfd as a cgroup directory: an absolute path with
 * AT_FDCWD, or one component under a cgroup already open. O_NOFOLLOW refuses
 * a symlink as the last component. Returns the descriptor, or -1 with errno
 * set and nothing printed: the callers decide what an absent one means. */
static int open_cgroup(int dirfd, const char *path)
{
	return openat(dirfd, path, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}

/* The uid that owns the cgroup behind fd, or (uid_t)-1 when fstat fails. */
static uid_t owner(int fd)
{
	struct stat st;
	return fstat(fd, &st) == 0 ? st.st_uid : (uid_t)-1;
}

/* Cuts path at its last '/', leaving its parent. Refuses to go above the
 * cgroup2 root. */
static int cut_parent(char *path)
{
	char *slash = strrchr(path, '/');
	if (!slash || (size_t)(slash - path) < strlen(CGROOT))
		return fl_errx("%s has no parent cgroup of its own", path);
	*slash = '\0';
	return 0;
}

/* Makes h the cgroup at path, already open as fd, when the caller owns it.
 * Takes fd either way. */
static int holder_take(struct fl_holder *h, const char *path, int fd)
{
	if (owner(fd) != getuid()) {
		fl_close(&fd);
		return fl_errx("the holder's cgroup %s is not delegated to you", path);
	}
	snprintf(h->path, sizeof h->path, "%s", path);
	h->fd = fd;
	return 0;
}

/* The refusal when there is nowhere to put a session's cgroup. */
static int refuse_no_manager(void)
{
	struct passwd *pw = getpwuid(getuid());
	if (pw)
		return fl_errx("no user manager for %s: set users.users.%s.linger = true",
			       pw->pw_name, pw->pw_name);
	return fl_errx("no user manager for uid %u: set users.users.<name>.linger = true",
		       (unsigned)getuid());
}

/* Case 1: the user manager is there. Opens <manager>/<rel>, starting the
 * holder unit first when its cgroup is absent. */
static int holder_under_manager(struct fl_holder *h, const char *manager,
				const char *rel, const struct fl_argv *start_argv)
{
	char path[PATH_MAX];
	if ((size_t)snprintf(path, sizeof path, "%s/%s", manager, rel) >= sizeof path)
		return fl_errx("the holder's cgroup path is too long");

	/* The warm path: the holder is running, and this is one open. */
	int fd = open_cgroup(AT_FDCWD, path);
	if (fd >= 0)
		return holder_take(h, path, fd);
	if (errno != ENOENT)
		return fl_err("open the holder's cgroup %s", path);
	if (start_argv->n == 0)
		return fl_errx("the holder's cgroup %s does not exist, and there is no way to start it", path);

	struct fl_spawn s = {
		.argv = start_argv->v, .envp = NULL, .cgroup = -1,
		.stdio = NULL, .keep = NULL, .nkeep = 0, .dir = NULL,
	};
	int pidfd = fl_spawn(&s, NULL);
	if (pidfd < 0)
		return -1;
	int status = fl_reap(pidfd);
	fl_close(&pidfd);
	if (status < 0)
		return -1;
	if (status != 0)
		return fl_errx("starting the holder failed (%s exited %d)", start_argv->v[0], status);

	fd = open_cgroup(AT_FDCWD, path);
	if (fd < 0 && errno == ENOENT)
		return fl_errx("the holder's cgroup %s does not exist after starting it", path);
	if (fd < 0)
		return fl_err("open the holder's cgroup %s", path);
	return holder_take(h, path, fd);
}

/* Case 2: no user manager. The launcher's own cgroup, when a system unit
 * with User= and Delegate=yes gave it to the caller; its parent when limits
 * need controllers, since a cgroup with processes in it cannot enable any
 * for its children. */
static int holder_delegated(struct fl_holder *h, const char *own, int have_limits)
{
	int fd = open_cgroup(AT_FDCWD, own);
	if (fd < 0)
		return fl_err("open the launcher's cgroup %s", own);
	if (owner(fd) != getuid()) {
		fl_close(&fd);
		return refuse_no_manager();
	}
	if (!have_limits)
		return holder_take(h, own, fd);
	fl_close(&fd);

	char parent[PATH_MAX];
	snprintf(parent, sizeof parent, "%s", own);
	if (cut_parent(parent) < 0)
		return -1;
	fd = open_cgroup(AT_FDCWD, parent);
	if (fd < 0 || owner(fd) != getuid()) {
		fl_close(&fd);
		return fl_errx("limits need a delegated cgroup with no process in it, "
			       "and %s is not yours: run the launcher's unit with DelegateSubgroup=", parent);
	}
	return holder_take(h, parent, fd);
}

int cg_holder_find(struct fl_holder *h, const char *rel,
		   const struct fl_argv *start_argv, int have_limits)
{
	h->fd = -1;
	char own[PATH_MAX];
	if (own_cgroup(own, sizeof own) < 0)
		return -1;

	/* The user manager's cgroup: the launcher's own cgroup up to its
	 * user@UID.service component, when the launcher runs under the
	 * manager; its fixed place otherwise (a login session's scope). */
	char unit[64], manager[PATH_MAX];
	snprintf(unit, sizeof unit, "user@%u.service", (unsigned)getuid());
	size_t ulen = strlen(unit);
	const char *hit = NULL;
	for (const char *p = own + strlen(CGROOT); (p = strchr(p, '/')); p++)
		if (strncmp(p + 1, unit, ulen) == 0 && (p[1 + ulen] == '/' || p[1 + ulen] == '\0')) {
			hit = p + 1 + ulen;
			break;
		}
	if (hit)
		snprintf(manager, sizeof manager, "%.*s", (int)(hit - own), own);
	else
		snprintf(manager, sizeof manager, CGROOT "/user.slice/user-%u.slice/%s",
			 (unsigned)getuid(), unit);

	int fd = open_cgroup(AT_FDCWD, manager);
	if (fd >= 0) {
		uid_t o = owner(fd);
		fl_close(&fd);
		if (o != getuid())
			return fl_errx("the user manager's cgroup %s is not yours", manager);
		return holder_under_manager(h, manager, rel, start_argv);
	}
	if (errno != ENOENT)
		return fl_err("open the user manager's cgroup %s", manager);
	return holder_delegated(h, own, have_limits);
}

int cg_holder_self(struct fl_holder *h)
{
	h->fd = -1;
	char own[PATH_MAX];
	if (own_cgroup(own, sizeof own) < 0)
		return -1;
	/* The sweeper releases only the sessions under its holder, so a
	 * sweeper started anywhere but the holder unit's leaf must not guess
	 * one. */
	const char *leaf = strrchr(own, '/');
	if (strcmp(leaf, "/supervisor") != 0)
		return fl_errx("not in a holder unit's supervisor cgroup (in %s): "
			       "run the sweeper in a unit with DelegateSubgroup=supervisor", own);
	if (cut_parent(own) < 0)
		return -1;
	int fd = open_cgroup(AT_FDCWD, own);
	if (fd < 0)
		return fl_err("open the holder's cgroup %s", own);
	return holder_take(h, own, fd);
}

/* ---- the session cgroup ---- */

int cg_session_path(char *out, size_t size, const struct fl_holder *h,
		    const char *container, const char *machine)
{
	if ((size_t)snprintf(out, size, "%s/%s/%s", h->path, container, machine) >= size)
		return fl_errx("the session's cgroup path is too long");
	return 0;
}

/* Enables in the cgroup behind dirfd (named by the first len bytes of path,
 * for messages) the controllers the limits need. A controller is the limit
 * file's name up to its dot. One the level does not have, because systemd did
 * not delegate it, is refused by name rather than by the ENOENT the write
 * would give. The write itself is EBUSY while the level has a process of its
 * own, which is why the holder's process lives in its supervisor leaf. */
static int enable_controllers(int dirfd, const char *path, int len,
			      const struct fl_limit *limits, size_t nlimits)
{
	if (nlimits == 0)
		return 0;
	char have[256];
	if (fl_read_at(dirfd, "cgroup.controllers", have, sizeof have) < 0)
		return -1;
	have[strcspn(have, "\n")] = '\0';
	for (size_t i = 0; i < nlimits; i++) {
		char name[32];
		snprintf(name, sizeof name, "%.*s", (int)strcspn(limits[i].file, "."), limits[i].file);
		if (!has_item(have, name, ' '))
			return fl_errx("the limit %s needs the %s controller, which %.*s does not have",
				       limits[i].file, name, len, path);
		char plus[34];
		snprintf(plus, sizeof plus, "+%s", name);
		if (fl_write_at(dirfd, "cgroup.subtree_control", plus) < 0)
			return -1;
	}
	return 0;
}

int cg_session_create(struct fl_cgroup *cg, const struct fl_holder *h,
		      const char *container, const char *machine,
		      const struct fl_limit *limits, size_t nlimits)
{
	*cg = (struct fl_cgroup)FL_CGROUP_NONE;
	if (cg_session_path(cg->path, sizeof cg->path, h, container, machine) < 0)
		return -1;

	/* The container level is shared by every session of the container and
	 * never removed: another launch may be making its session in it right
	 * now. */
	if (mkdirat(h->fd, container, 0755) < 0 && errno != EEXIST)
		return fl_err("mkdir %s/%s", h->path, container);
	int cfd = open_cgroup(h->fd, container);
	if (cfd < 0)
		return fl_err("open %s/%s", h->path, container);

	/* A controller must be enabled on every level above the cgroup whose
	 * file sets the limit: the holder, the container level and the
	 * session, above the sandbox leaf. */
	int clen = (int)(strrchr(cg->path, '/') - cg->path);
	if (enable_controllers(h->fd, h->path, (int)strlen(h->path), limits, nlimits) < 0 ||
	    enable_controllers(cfd, cg->path, clen, limits, nlimits) < 0) {
		fl_close(&cfd);
		return -1;
	}

	if (mkdirat(cfd, machine, 0755) < 0) {
		if (errno == EEXIST)
			fl_errx("a session named %s is already running (%s exists)", machine, cg->path);
		else
			fl_err("mkdir %s", cg->path);
		fl_close(&cfd);
		return -1;
	}
	cg->fd = open_cgroup(cfd, machine);
	if (cg->fd < 0) {
		fl_err("open %s", cg->path);
		goto undo;
	}
	if (enable_controllers(cg->fd, cg->path, (int)strlen(cg->path), limits, nlimits) < 0)
		goto undo;
	for (int i = 0; i < FL_NLEAVES; i++) {
		if (mkdirat(cg->fd, leaf_name[i], 0755) < 0) {
			fl_err("mkdir %s/%s", cg->path, leaf_name[i]);
			goto undo;
		}
		cg->leaf[i] = open_cgroup(cg->fd, leaf_name[i]);
		if (cg->leaf[i] < 0) {
			fl_err("open %s/%s", cg->path, leaf_name[i]);
			goto undo;
		}
	}
	/* The payload's cgroup namespace is rooted at the sandbox leaf, and a
	 * program reads its limits from its own cgroup (Go reads cpu.max
	 * there and nowhere above), so the limits go on the leaf. */
	for (size_t i = 0; i < nlimits; i++)
		if (fl_write_at(cg->leaf[FL_LEAF_SANDBOX], limits[i].file, limits[i].value) < 0)
			goto undo;
	fl_close(&cfd);
	return 0;

undo:
	/* Nothing has run in the session yet, so every directory made here
	 * is empty and goes at once. */
	for (int i = FL_NLEAVES - 1; i >= 0; i--) {
		fl_close(&cg->leaf[i]);
		if (cg->fd >= 0)
			unlinkat(cg->fd, leaf_name[i], AT_REMOVEDIR);
	}
	fl_close(&cg->fd);
	unlinkat(cfd, machine, AT_REMOVEDIR);
	fl_close(&cfd);
	return -1;
}

/* Where a record's path names its container level, when the path spells a
 * session cgroup: /sys/fs/cgroup/<holder...>/<container>/<machine>, every
 * component non-empty and neither "." nor "..", the container a name, and
 * the last component the record's own machine. NULL when it does not. */
static const char *session_form(const char *path, const char *machine)
{
	const char *p = path + strlen(CGROOT), *last = NULL, *before = NULL;
	int n = 0;
	if (strncmp(path, CGROOT "/", strlen(CGROOT) + 1) != 0)
		return NULL;
	while (*p == '/') {
		const char *c = p + 1;
		size_t len = strcspn(c, "/");
		if (len == 0 || (len == 1 && c[0] == '.') || (len == 2 && c[0] == '.' && c[1] == '.'))
			return NULL;
		before = last;
		last = c;
		n++;
		p = c + len;
	}
	/* A holder, a container and a machine at least. */
	if (n < 3 || strcmp(last, machine) != 0 || !fl_is_name(machine, strlen(machine)) ||
	    !fl_is_name(before, (size_t)(last - 1 - before)))
		return NULL;
	return before;
}

int cg_session_open(struct fl_cgroup *cg, const struct fl_holder *h,
		    const char *path, const char *machine)
{
	*cg = (struct fl_cgroup)FL_CGROUP_NONE;

	/* The record is the caller's file, so the path in it is checked to be
	 * a session's before anything is opened, and exactly
	 * <holder>/<container>/<machine> before anything is killed: a record
	 * naming any other cgroup would get that cgroup killed. */
	const char *rest = session_form(path, machine);
	if (!rest) {
		fl_errx("the record %s does not name a session's cgroup: %s", machine, path);
		return FL_CG_REFUSED;
	}
	size_t hlen = strlen(h->path);
	if ((size_t)(rest - path) != hlen + 1 || strncmp(path, h->path, hlen) != 0)
		return FL_CG_OTHER_HOLDER;
	if ((size_t)snprintf(cg->path, sizeof cg->path, "%s", path) >= sizeof cg->path) {
		fl_errx("the record %s names a cgroup path that is too long", machine);
		return FL_CG_REFUSED;
	}

	char container[FL_NAME_MAX + 1];
	snprintf(container, sizeof container, "%.*s", (int)strcspn(rest, "/"), rest);
	int cfd = open_cgroup(h->fd, container);
	if (cfd < 0 && errno == ENOENT)
		return 0;
	if (cfd < 0)
		return fl_err("open %s/%s", h->path, container);
	cg->fd = open_cgroup(cfd, machine);
	fl_close(&cfd);
	if (cg->fd < 0 && errno == ENOENT)
		return 0;
	if (cg->fd < 0)
		return fl_err("open %s", cg->path);
	for (int i = 0; i < FL_NLEAVES; i++) {
		cg->leaf[i] = open_cgroup(cg->fd, leaf_name[i]);
		if (cg->leaf[i] < 0 && errno != ENOENT) {
			fl_err("open %s/%s", cg->path, leaf_name[i]);
			cg_close(cg);
			return -1;
		}
	}
	return 1;
}

/* ---- ending a session ---- */

int cg_kill(const struct fl_cgroup *cg)
{
	return fl_write_at(cg->fd, "cgroup.kill", "1");
}

int cg_wait_empty(int cgfd)
{
	int ev = openat(cgfd, "cgroup.events", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (ev < 0)
		return fl_err("open cgroup.events");

	/* The kernel flags cgroup.events with POLLPRI when it changes after
	 * the last read, so each read arms the next wait and a change between
	 * the read and the poll is never missed. */
	int rc = -1;
	for (;;) {
		char buf[256];
		ssize_t len = pread(ev, buf, sizeof buf - 1, 0);
		if (len < 0 && errno == EINTR)
			continue;
		if (len < 0) {
			fl_err("read cgroup.events");
			break;
		}
		buf[len] = '\0';
		char *pop = strstr(buf, "populated ");
		if (!pop) {
			fl_errx("cgroup.events has no populated line");
			break;
		}
		if (pop[10] == '0') {
			rc = 0;
			break;
		}
		if (fl_await(ev, POLLPRI) < 0)
			break;
	}
	fl_close(&ev);
	return rc;
}

/* Removes the cgroup name under parent and every cgroup below it. A leaf
 * normally has none and goes with one rmdir; a payload allowed nested
 * namespaces can make cgroups of its own inside its leaf, and cgroup.kill has
 * already ended whatever ran in them. rmdir says EBUSY both for a cgroup with
 * processes and for one with children, so on EBUSY the children are removed
 * and the rmdir is tried once more: a cgroup with no children left that is
 * still busy has processes in it. Returns 0 when gone, 1 when a cgroup is
 * still populated, -1 on error. */
static int remove_tree(int parent, const char *name, const char *path)
{
	if (unlinkat(parent, name, AT_REMOVEDIR) == 0 || errno == ENOENT)
		return 0;
	if (errno != EBUSY)
		return fl_err("rmdir %s", path);

	int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return fl_err("open %s", path);
	DIR *d = fdopendir(fd);
	if (!d) {
		fl_err("open %s", path);
		fl_close(&fd);
		return -1;
	}
	int rc = 0, children = 0;
	struct dirent *e;
	while (rc == 0 && (e = readdir(d))) {
		if (e->d_type != DT_DIR || strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
			continue;
		char sub[PATH_MAX];
		snprintf(sub, sizeof sub, "%s/%s", path, e->d_name);
		rc = remove_tree(dirfd(d), e->d_name, sub);
		children = 1;
	}
	closedir(d);
	if (rc != 0)
		return rc;
	if (!children)
		return 1;
	if (unlinkat(parent, name, AT_REMOVEDIR) == 0 || errno == ENOENT)
		return 0;
	if (errno == EBUSY)
		return 1;
	return fl_err("rmdir %s", path);
}

int cg_remove(struct fl_cgroup *cg)
{
	for (int i = 0; i < FL_NLEAVES; i++) {
		char path[PATH_MAX + 16];
		snprintf(path, sizeof path, "%s/%s", cg->path, leaf_name[i]);
		int rc = remove_tree(cg->fd, leaf_name[i], path);
		if (rc != 0)
			return rc;
	}

	/* The session is removed from its parent, the container level, which
	 * the session's descriptor reaches as "..". */
	int cfd = open_cgroup(cg->fd, "..");
	if (cfd < 0)
		return fl_err("open the parent of %s", cg->path);
	int rc = remove_tree(cfd, strrchr(cg->path, '/') + 1, cg->path);
	fl_close(&cfd);
	return rc;
}

void cg_close(struct fl_cgroup *cg)
{
	for (int i = 0; i < FL_NLEAVES; i++)
		fl_close(&cg->leaf[i]);
	fl_close(&cg->fd);
}
