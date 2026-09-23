/* flong-spec.c: argv tokens into struct fl_spec, and every check that needs
 * nothing but the spec.
 *
 * Parsing takes two passes over the same arities. The first reads only the
 * shape: each keyword is known, has its fields, appears as often as it may,
 * and "--" comes before a command. It counts every keyword, so the second
 * pass can fill arrays allocated once at their final size. The second pass
 * checks each field's meaning. Checks that relate fields of different
 * keywords (a map covering the payload's ids, a keep-fd named by a
 * bwrap-arg) run last, once everything is filled.
 *
 * A field is positional: "--" in a field's place is that field's value (the
 * wrapper's own argv, passed through `relaunch`, may hold one). Only "--" in
 * a keyword's place ends the spec.
 *
 * Every refusal names the keyword and the field, in the words the wrapper
 * used, because a refusal here is a wrapper bug or a declaration the module
 * let through, and whoever reads it has the spec in front of them.
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "flong-spec.h"
#include "flong-util.h"

enum kw {
	KW_MACHINE, KW_CONTAINER, KW_STATE, KW_CACHE, KW_RELAUNCH, KW_CLOSURE,
	KW_UIDMAP, KW_GIDMAP, KW_USER, KW_GROUP, KW_CHDIR, KW_MOUNT, KW_PROTECT,
	KW_SECCOMP, KW_NESTED_USERNS, KW_HOLDER, KW_HOLDER_START, KW_LIMIT,
	KW_POST_START, KW_POST_STOP, KW_NETWORK, KW_PASTA_ARG, KW_PASTA_WAIT,
	KW_BWRAP_ARG, KW_KEEP_FD, KW_TRACE, KW_N
};

#define ONCE     1  /* at most once */
#define REQUIRED 2  /* at least once */

/* The keywords and how many fields follow each. mount's count depends on its
 * kind, the first field, and is read from mount_kinds. */
static const struct {
	const char *name;
	int nfields;
	int flags;
} keywords[KW_N] = {
	[KW_MACHINE]       = { "machine",       1, REQUIRED | ONCE },
	[KW_CONTAINER]     = { "container",     1, REQUIRED | ONCE },
	[KW_STATE]         = { "state",         1, REQUIRED | ONCE },
	[KW_CACHE]         = { "cache",         1, REQUIRED | ONCE },
	[KW_RELAUNCH]      = { "relaunch",      1, 0 },
	[KW_CLOSURE]       = { "closure",       1, REQUIRED | ONCE },
	[KW_UIDMAP]        = { "uidmap",        3, REQUIRED },
	[KW_GIDMAP]        = { "gidmap",        3, REQUIRED },
	[KW_USER]          = { "user",          3, REQUIRED | ONCE },
	[KW_GROUP]         = { "group",         1, 0 },
	[KW_CHDIR]         = { "chdir",         1, ONCE },
	[KW_MOUNT]         = { "mount",        -1, 0 },
	[KW_PROTECT]       = { "protect",       1, 0 },
	[KW_SECCOMP]       = { "seccomp",       1, 0 },
	[KW_NESTED_USERNS] = { "nested-userns", 1, ONCE },
	[KW_HOLDER]        = { "holder",        1, REQUIRED | ONCE },
	[KW_HOLDER_START]  = { "holder-start",  1, 0 },
	[KW_LIMIT]         = { "limit",         2, 0 },
	[KW_POST_START]    = { "post-start",    1, 0 },
	[KW_POST_STOP]     = { "post-stop",     1, ONCE },
	[KW_NETWORK]       = { "network",       0, ONCE },
	[KW_PASTA_ARG]     = { "pasta-arg",     1, 0 },
	[KW_PASTA_WAIT]    = { "pasta-wait",    0, ONCE },
	[KW_BWRAP_ARG]     = { "bwrap-arg",     1, 0 },
	[KW_KEEP_FD]       = { "keep-fd",       1, 0 },
	[KW_TRACE]         = { "trace",         0, ONCE },
};

/* Each mount kind and how many fields follow the kind. */
static const struct {
	const char *name;
	enum fl_mount_kind kind;
	int nfields;
} mount_kinds[] = {
	{ "bind-ro",       FL_BIND_RO,       2 },  /* DEST SRC */
	{ "bind-rw",       FL_BIND_RW,       2 },
	{ "bind-ro-exact", FL_BIND_RO_EXACT, 2 },
	{ "bind-rw-exact", FL_BIND_RW_EXACT, 2 },
	{ "dev",           FL_DEV,           2 },
	{ "tmpfs",         FL_TMPFS,         4 },  /* DEST MODE SIZE OWNER */
	{ "overlay",       FL_OVERLAY,       2 },  /* DEST LOWER */
	{ "mask",          FL_MASK,          1 },  /* DEST */
};
#define NMOUNT_KINDS (sizeof mount_kinds / sizeof mount_kinds[0])

/* The limits a spec may set: the opt-in ones module.nix types. Anything else
 * in a cgroup (cgroup.procs, cgroup.kill, cgroup.subtree_control) is the
 * launcher's own machinery, not a limit. */
static const char *const limit_files[] = {
	"memory.max", "memory.high", "memory.swap.max", "memory.oom.group",
	"pids.max", "cpu.max", "cpu.weight", "io.weight",
};
#define NLIMIT_FILES (sizeof limit_files / sizeof limit_files[0])

/* The largest id a map may name: (uid_t)-1 is "no id" to the kernel. */
#define ID_MAX 4294967294UL

static int keyword(const char *word)
{
	for (int k = 0; k < KW_N; k++)
		if (strcmp(word, keywords[k].name) == 0)
			return k;
	return -1;
}

static int mount_kind(const char *word)
{
	for (size_t m = 0; m < NMOUNT_KINDS; m++)
		if (strcmp(word, mount_kinds[m].name) == 0)
			return (int)m;
	return -1;
}

/* How many fields follow keyword k at argv[i], or -1 when they run out or a
 * mount's kind is unknown. Both passes use it, so they agree on every
 * arity. */
static int arity(int argc, char **argv, int i, int k)
{
	int n = keywords[k].nfields;

	if (k == KW_MOUNT) {
		if (i + 1 >= argc)
			return fl_errx("spec: mount: the kind is missing");
		int m = mount_kind(argv[i + 1]);
		if (m < 0)
			return fl_errx("spec: mount: unknown kind '%s'", argv[i + 1]);
		n = 1 + mount_kinds[m].nfields;
	}
	if (argc - 1 - i < n) {
		if (k == KW_MOUNT)
			return fl_errx("spec: mount %s: %d field%s expected", argv[i + 1],
				       n - 1, n == 2 ? "" : "s");
		return fl_errx("spec: %s: %d field%s expected", keywords[k].name, n, n == 1 ? "" : "s");
	}
	return n;
}

/* ---- field checks: each prints its refusal and returns -1, or returns 0 ---- */

/* A decimal number of at most max: digits only, so no sign, no space and no
 * base prefix slip through as they would with strtoul alone. */
static int number(const char *what, const char *v, unsigned long max, unsigned long *out)
{
	unsigned long n = 0;

	if (*v == '\0')
		return fl_errx("spec: %s is empty", what);
	for (const char *p = v; *p; p++) {
		if (*p < '0' || *p > '9')
			return fl_errx("spec: %s is not a decimal number: '%s'", what, v);
		if (n > (max - (unsigned long)(*p - '0')) / 10)
			return fl_errx("spec: %s is larger than %lu: '%s'", what, max, v);
		n = n * 10 + (unsigned long)(*p - '0');
	}
	*out = n;
	return 0;
}

/* A permission mode: octal digits, at most 07777. */
static int octal(const char *what, const char *v)
{
	unsigned long n = 0;

	if (*v == '\0' || strlen(v) > 5)
		return fl_errx("spec: %s is not an octal mode: '%s'", what, v);
	for (const char *p = v; *p; p++) {
		if (*p < '0' || *p > '7')
			return fl_errx("spec: %s is not an octal mode: '%s'", what, v);
		n = n * 8 + (unsigned long)(*p - '0');
	}
	if (n > 07777)
		return fl_errx("spec: %s is larger than 07777: '%s'", what, v);
	return 0;
}

/* A machine or container name (fl_is_name). */
static int name(const char *what, const char *v)
{
	if (fl_is_name(v, strlen(v)))
		return 0;
	return fl_errx("spec: %s '%s' is not a name: 1 to %d of A-Z a-z 0-9 _ - ., not starting with .",
		       what, v, FL_NAME_MAX);
}

/* An absolute path that fits PATH_MAX. */
static int absolute(const char *what, const char *v)
{
	if (v[0] != '/')
		return fl_errx("spec: %s is not an absolute path: '%s'", what, v);
	if (strlen(v) >= PATH_MAX)
		return fl_errx("spec: %s is longer than PATH_MAX", what);
	return 0;
}

/* A path taken one component at a time, by the walker or in cgroupfs: every
 * component is non-empty, neither "." nor "..", and at most NAME_MAX bytes.
 * With abs it is absolute and is not "/" alone; without, it is relative.
 * A canonical path from realpath passes, and so does nothing that would
 * name a different place than it spells. */
static int clean(const char *what, const char *v, int abs)
{
	const char *p = v;

	if (abs) {
		if (absolute(what, v) < 0)
			return -1;
		p++;
	} else if (v[0] == '/') {
		return fl_errx("spec: %s is not a relative path: '%s'", what, v);
	}
	for (;;) {
		size_t n = strcspn(p, "/");
		if (n == 0 || (n == 1 && p[0] == '.') || (n == 2 && p[0] == '.' && p[1] == '.'))
			return fl_errx("spec: %s has an empty, '.' or '..' component: '%s'", what, v);
		if (n > NAME_MAX)
			return fl_errx("spec: %s has a component longer than NAME_MAX", what);
		if (p[n] == '\0')
			return 0;
		p += n + 1;
	}
}

/* A path under /nix/store/, spelled without an empty, '.' or '..'
 * component that could climb back out. */
static int store_path(const char *what, const char *v)
{
	if (strncmp(v, "/nix/store/", 11) != 0 || v[11] == '\0')
		return fl_errx("spec: %s is not under /nix/store/: '%s'", what, v);
	return clean(what, v, 1);
}

/* The container's toplevel, which bwrap binds at /run/current-system by
 * path, following symlinks, outside the walker and its protected-path check.
 * It must lead into the store, whose paths never change once made, so it
 * can never put the state directory or the holder's cgroup in the
 * payload's view. */
static int closure(const char *v)
{
	char real[PATH_MAX];
	if (store_path("closure", v) < 0)
		return -1;
	if (!realpath(v, real))
		return fl_err("spec: closure '%s'", v);
	if (strncmp(real, "/nix/store/", 11) != 0 || real[11] == '\0')
		return fl_errx("spec: closure '%s' leads out of /nix/store/, to '%s'", v, real);
	return 0;
}

/* tmpfs's size= value: a number with at most one unit suffix, as tmpfs
 * reads it. Nothing else, so the value cannot carry a second option. */
static int tmpfs_size(const char *v)
{
	size_t n = strspn(v, "0123456789");

	if (n == 0 || (v[n] != '\0' && (strchr("kKmMgGtTpPeE%", v[n]) == NULL || v[n + 1] != '\0')))
		return fl_errx("spec: mount tmpfs size is not a number with an optional k, m, g, t, p, e or %% suffix: '%s'",
			       v);
	return 0;
}

/* One extent of a map. None reaches host id 0: container root is a subuid on
 * the host, never host root, whatever the wrapper computed. */
static int idmap(const char *what, char **f, struct fl_idmap *e)
{
	if (number(what, f[0], ID_MAX, &e->inside) < 0 ||
	    number(what, f[1], ID_MAX, &e->outside) < 0 ||
	    number(what, f[2], ID_MAX, &e->count) < 0)
		return -1;
	if (e->count == 0)
		return fl_errx("spec: %s %s %s %s: the count is 0", what, f[0], f[1], f[2]);
	if (e->count > ID_MAX + 1 - e->inside || e->count > ID_MAX + 1 - e->outside)
		return fl_errx("spec: %s %s %s %s: the extent runs past id %lu", what, f[0], f[1], f[2], ID_MAX);
	if (e->outside == 0)
		return fl_errx("spec: %s %s %s %s reaches host id 0: flong never maps host root",
			       what, f[0], f[1], f[2]);
	return 0;
}

/* The kernel refuses extents that overlap on either side; saying so here
 * names the extents, where newuidmap would say only EINVAL. */
static int idmap_disjoint(const char *what, const struct fl_idmap *m, size_t n)
{
	for (size_t i = 0; i < n; i++)
		for (size_t j = i + 1; j < n; j++)
			if ((m[i].inside < m[j].inside + m[j].count && m[j].inside < m[i].inside + m[i].count) ||
			    (m[i].outside < m[j].outside + m[j].count && m[j].outside < m[i].outside + m[i].count))
				return fl_errx("spec: %s extents %lu %lu %lu and %lu %lu %lu overlap", what,
					       m[i].inside, m[i].outside, m[i].count,
					       m[j].inside, m[j].outside, m[j].count);
	return 0;
}

/* Whether id, inside the container, is in one of m's extents: an unmapped
 * id is one bwrap and setgroups would fail on after the session is built. */
static int idmap_covers(const struct fl_idmap *m, size_t n, unsigned long id)
{
	for (size_t i = 0; i < n; i++)
		if (id >= m[i].inside && id - m[i].inside < m[i].count)
			return 1;
	return 0;
}

/* An environment variable's name, for --setenv and --unsetenv. */
static int env_name(const char *v)
{
	if (*v == '\0' || strchr(v, '=') != NULL)
		return fl_errx("spec: bwrap-arg: '%s' is not a variable name", v);
	return 0;
}

/* A calloc that gives NULL for n == 0 (an empty array, as fl_argv wants it)
 * and clears *ok when the allocation fails. */
static void *table(size_t n, size_t size, int *ok)
{
	void *p;

	if (n == 0)
		return NULL;
	p = calloc(n, size);
	if (p == NULL)
		*ok = 0;
	return p;
}

/* Room for n arguments and the NULL after them. */
static void argv_table(struct fl_argv *a, size_t n, int *ok)
{
	a->v = table(n ? n + 1 : 0, sizeof *a->v, ok);
	a->n = 0;
}

/* The bwrap options a spec may pass, and how many arguments follow each. */
enum { OPT_CLEARENV, OPT_SETENV, OPT_UNSETENV, OPT_HOSTNAME, OPT_PERMS, OPT_RO_BIND_DATA, NOPTS };
static const struct {
	const char *name;
	size_t need;
} bwrap_options[NOPTS] = {
	[OPT_CLEARENV]     = { "--clearenv",     0 },
	[OPT_SETENV]       = { "--setenv",       2 },  /* VAR VALUE */
	[OPT_UNSETENV]     = { "--unsetenv",     1 },  /* VAR */
	[OPT_HOSTNAME]     = { "--hostname",     1 },  /* NAME */
	[OPT_PERMS]        = { "--perms",        1 },  /* OCTAL, before --ro-bind-data */
	[OPT_RO_BIND_DATA] = { "--ro-bind-data", 2 },  /* FD DEST */
};

/* Walks the bwrap-args with their arities and refuses anything outside the
 * allow-list. Every flong-level mount goes through the walker (condition 1),
 * so a path mount here is a wrapper bug; --ro-bind-data writes a fixed file
 * in the fresh root from a keep-fd, before the payload runs. used[i] is set
 * for each keep-fd a --ro-bind-data names. */
static int bwrap_allowed(const struct fl_spec *s, char *used)
{
	char *const *a = s->bwrap_args.v;
	size_t n = s->bwrap_args.n;

	for (size_t i = 0; i < n;) {
		const char *opt = a[i];
		int o;

		for (o = 0; o < NOPTS && strcmp(opt, bwrap_options[o].name) != 0; o++)
			;
		if (o == NOPTS)
			return fl_errx("spec: bwrap-arg '%s' is not allowed: flong passes bwrap only --clearenv, "
				       "--setenv, --unsetenv, --hostname and --perms before --ro-bind-data", opt);
		size_t need = bwrap_options[o].need;
		if (n - i - 1 < need)
			return fl_errx("spec: bwrap-arg %s: %zu argument%s expected", opt, need,
				       need == 1 ? "" : "s");

		switch (o) {
		case OPT_CLEARENV:
			break;
		case OPT_SETENV:
		case OPT_UNSETENV:
			if (env_name(a[i + 1]) < 0)
				return -1;
			break;
		case OPT_HOSTNAME:
			if (a[i + 1][0] == '\0')
				return fl_errx("spec: bwrap-arg --hostname is empty");
			break;
		case OPT_PERMS:
			if (octal("bwrap-arg --perms", a[i + 1]) < 0)
				return -1;
			if (i + 2 >= n || strcmp(a[i + 2], bwrap_options[OPT_RO_BIND_DATA].name) != 0)
				return fl_errx("spec: bwrap-arg --perms is allowed only before --ro-bind-data");
			break;
		case OPT_RO_BIND_DATA: {
			unsigned long fd;
			size_t k;

			if (number("bwrap-arg --ro-bind-data's descriptor", a[i + 1], INT_MAX, &fd) < 0)
				return -1;
			for (k = 0; k < s->nkeep_fds && s->keep_fds[k] != (int)fd; k++)
				;
			if (k == s->nkeep_fds)
				return fl_errx("spec: bwrap-arg --ro-bind-data names descriptor %lu, which is no keep-fd", fd);
			used[k] = 1;
			if (clean("bwrap-arg --ro-bind-data's destination", a[i + 2], 1) < 0)
				return -1;
			break;
		}
		}
		i += 1 + need;
	}
	return 0;
}

int spec_parse(int argc, char **argv, struct fl_spec *s)
{
	size_t count[KW_N] = { 0 };
	int end, rc, ok = 1;
	char *used;

	if (fl_refuse_root() < 0)
		return -1;

	/* Pass 1: the shape. */
	for (end = 1; end < argc && strcmp(argv[end], "--") != 0;) {
		int k = keyword(argv[end]), n;

		if (k < 0)
			return fl_errx("spec: unknown keyword '%s'", argv[end]);
		if ((n = arity(argc, argv, end, k)) < 0)
			return -1;
		if (++count[k] > 1 && (keywords[k].flags & ONCE))
			return fl_errx("spec: %s given more than once", keywords[k].name);
		end += 1 + n;
	}
	if (end >= argc)
		return fl_errx("spec: no '--' before the command");
	if (end + 1 == argc)
		return fl_errx("spec: the command after '--' is empty");
	for (int k = 0; k < KW_N; k++)
		if ((keywords[k].flags & REQUIRED) && count[k] == 0)
			return fl_errx("spec: %s is missing", keywords[k].name);

	memset(s, 0, sizeof *s);
	s->chdir = "/";
	/* argv[argc] is NULL, so the command is argv's own tail. */
	s->command.v = argv + end + 1;
	s->command.n = (size_t)(argc - end - 1);

	argv_table(&s->relaunch, count[KW_RELAUNCH], &ok);
	argv_table(&s->holder_start, count[KW_HOLDER_START], &ok);
	argv_table(&s->post_start, count[KW_POST_START], &ok);
	argv_table(&s->pasta_args, count[KW_PASTA_ARG], &ok);
	argv_table(&s->bwrap_args, count[KW_BWRAP_ARG], &ok);
	s->uidmap = table(count[KW_UIDMAP], sizeof *s->uidmap, &ok);
	s->gidmap = table(count[KW_GIDMAP], sizeof *s->gidmap, &ok);
	s->groups = table(count[KW_GROUP], sizeof *s->groups, &ok);
	s->mounts = table(count[KW_MOUNT], sizeof *s->mounts, &ok);
	s->protect = table(count[KW_PROTECT], sizeof *s->protect, &ok);
	s->seccomp = table(count[KW_SECCOMP], sizeof *s->seccomp, &ok);
	s->limits = table(count[KW_LIMIT], sizeof *s->limits, &ok);
	s->keep_fds = table(count[KW_KEEP_FD], sizeof *s->keep_fds, &ok);
	if (!ok) {
		errno = ENOMEM;
		return fl_err("spec");
	}

	/* Pass 2: the meaning of each field. */
	for (int i = 1; i < end;) {
		int k = keyword(argv[i]);
		int n = arity(argc, argv, i, k);
		char **f = argv + i + 1;
		unsigned long v;

		switch (k) {
		case KW_MACHINE:
			if (name("machine", f[0]) < 0)
				return -1;
			s->machine = f[0];
			break;
		case KW_CONTAINER:
			if (name("container", f[0]) < 0)
				return -1;
			s->container = f[0];
			break;
		case KW_STATE:
			if (absolute("state", f[0]) < 0)
				return -1;
			s->state = f[0];
			break;
		case KW_CACHE:
			if (absolute("cache", f[0]) < 0)
				return -1;
			s->cache = f[0];
			break;
		case KW_RELAUNCH:
			s->relaunch.v[s->relaunch.n++] = f[0];
			break;
		case KW_CLOSURE:
			if (closure(f[0]) < 0)
				return -1;
			s->closure = f[0];
			break;
		case KW_UIDMAP:
			if (idmap("uidmap", f, &s->uidmap[s->nuidmap++]) < 0)
				return -1;
			break;
		case KW_GIDMAP:
			if (idmap("gidmap", f, &s->gidmap[s->ngidmap++]) < 0)
				return -1;
			break;
		case KW_USER:
			if (number("user's uid", f[0], ID_MAX, &v) < 0)
				return -1;
			s->uid = (uid_t)v;
			if (number("user's gid", f[1], ID_MAX, &v) < 0)
				return -1;
			s->gid = (gid_t)v;
			/* The helper decides what lies inside home by its
			 * components, so home spells its place exactly. */
			if (clean("user's home", f[2], 1) < 0)
				return -1;
			s->home = f[2];
			break;
		case KW_GROUP:
			if (number("group", f[0], ID_MAX, &v) < 0)
				return -1;
			s->groups[s->ngroups++] = (gid_t)v;
			break;
		case KW_CHDIR:
			if (absolute("chdir", f[0]) < 0)
				return -1;
			s->chdir = f[0];
			break;
		case KW_MOUNT: {
			const char *kind = f[0];
			struct fl_mount *m = &s->mounts[s->nmounts++];
			char what[64];

			m->kind = mount_kinds[mount_kind(kind)].kind;
			m->dest = f[1];
			snprintf(what, sizeof what, "mount %s destination", kind);
			if (clean(what, m->dest, 1) < 0)
				return -1;
			snprintf(what, sizeof what, "mount %s source", kind);
			switch (m->kind) {
			case FL_BIND_RO_EXACT:
			case FL_BIND_RW_EXACT:
				/* The source is canonical: the helper opens it
				 * with RESOLVE_NO_SYMLINKS, and a '..' would
				 * walk it somewhere its spelling does not say. */
				if (clean(what, f[2], 1) < 0)
					return -1;
				m->src = f[2];
				break;
			case FL_BIND_RO:
			case FL_BIND_RW:
			case FL_DEV:
			case FL_OVERLAY:
				if (absolute(what, f[2]) < 0)
					return -1;
				m->src = f[2];
				break;
			case FL_TMPFS:
				if (octal("mount tmpfs mode", f[2]) < 0)
					return -1;
				m->mode = f[2];
				if (f[3][0] != '\0') {
					if (tmpfs_size(f[3]) < 0)
						return -1;
					m->size = f[3];
				}
				if (strcmp(f[4], "user") == 0)
					m->owner_user = 1;
				else if (strcmp(f[4], "root") != 0)
					return fl_errx("spec: mount tmpfs owner is neither root nor user: '%s'", f[4]);
				break;
			case FL_MASK:
				break;
			}
			break;
		}
		case KW_PROTECT:
			/* clean: a part that does not exist yet is compared as
			 * spelled, so it must not spell a ".." there. */
			if (clean("protect", f[0], 1) < 0)
				return -1;
			s->protect[s->nprotect++] = f[0];
			break;
		case KW_SECCOMP:
			if (absolute("seccomp", f[0]) < 0)
				return -1;
			s->seccomp[s->nseccomp++] = f[0];
			break;
		case KW_NESTED_USERNS:
			/* 0 would mean nested namespaces off while dropping
			 * --assert-userns-disabled: off is the absence of the
			 * keyword, never a number. */
			if (number("nested-userns", f[0], INT_MAX, &s->nested_userns) < 0)
				return -1;
			if (s->nested_userns == 0)
				return fl_errx("spec: nested-userns is 0: leave it out to keep nested namespaces off");
			break;
		case KW_HOLDER:
			if (clean("holder", f[0], 0) < 0)
				return -1;
			s->holder = f[0];
			break;
		case KW_HOLDER_START:
			s->holder_start.v[s->holder_start.n++] = f[0];
			break;
		case KW_LIMIT: {
			size_t l;

			for (l = 0; l < NLIMIT_FILES && strcmp(f[0], limit_files[l]) != 0; l++)
				;
			if (l == NLIMIT_FILES)
				return fl_errx("spec: limit '%s' is not one of memory.max memory.high memory.swap.max "
					       "memory.oom.group pids.max cpu.max cpu.weight io.weight", f[0]);
			for (size_t j = 0; j < s->nlimits; j++)
				if (strcmp(s->limits[j].file, f[0]) == 0)
					return fl_errx("spec: limit %s given more than once", f[0]);
			if (f[1][0] == '\0')
				return fl_errx("spec: limit %s has an empty value", f[0]);
			s->limits[s->nlimits].file = f[0];
			s->limits[s->nlimits++].value = f[1];
			break;
		}
		case KW_POST_START:
			s->post_start.v[s->post_start.n++] = f[0];
			break;
		case KW_POST_STOP:
			/* The sweep runs it as the caller from a record the
			 * caller can edit, so only a store path, spelled
			 * without a '..' that could climb back out. Where a
			 * symlink leads is checked when it runs (fl_poststop),
			 * since the sweep reads the path from the record. */
			if (store_path("post-stop", f[0]) < 0)
				return -1;
			s->post_stop = f[0];
			break;
		case KW_NETWORK:
			s->network = 1;
			break;
		case KW_PASTA_ARG:
			s->pasta_args.v[s->pasta_args.n++] = f[0];
			break;
		case KW_PASTA_WAIT:
			s->pasta_wait = 1;
			break;
		case KW_BWRAP_ARG:
			s->bwrap_args.v[s->bwrap_args.n++] = f[0];
			break;
		case KW_KEEP_FD:
			/* 0 to 2 are stdio, which bwrap gets from tty_stdio. */
			if (number("keep-fd", f[0], INT_MAX, &v) < 0)
				return -1;
			if (v < 3)
				return fl_errx("spec: keep-fd %lu is stdio", v);
			for (size_t j = 0; j < s->nkeep_fds; j++)
				if (s->keep_fds[j] == (int)v)
					return fl_errx("spec: keep-fd %lu given more than once", v);
			if (fcntl((int)v, F_GETFD) < 0)
				return fl_err("spec: keep-fd %lu", v);
			s->keep_fds[s->nkeep_fds++] = (int)v;
			break;
		case KW_TRACE:
			s->trace = 1;
			break;
		}
		i += 1 + n;
	}

	/* Across keywords. */
	if (idmap_disjoint("uidmap", s->uidmap, s->nuidmap) < 0 ||
	    idmap_disjoint("gidmap", s->gidmap, s->ngidmap) < 0)
		return -1;
	if (!idmap_covers(s->uidmap, s->nuidmap, s->uid))
		return fl_errx("spec: user's uid %lu is in no uidmap extent", (unsigned long)s->uid);
	if (!idmap_covers(s->gidmap, s->ngidmap, s->gid))
		return fl_errx("spec: user's gid %lu is in no gidmap extent", (unsigned long)s->gid);
	for (size_t j = 0; j < s->ngroups; j++)
		if (!idmap_covers(s->gidmap, s->ngidmap, s->groups[j]))
			return fl_errx("spec: group %lu is in no gidmap extent", (unsigned long)s->groups[j]);
	/* fl_spawn execs without a PATH search. relaunch is exec'd from the
	 * wrapper's own working directory, so its "$0" may be relative. */
	if (s->holder_start.n && s->holder_start.v[0][0] != '/')
		return fl_errx("spec: holder-start's program is not an absolute path: '%s'", s->holder_start.v[0]);
	if (s->post_start.n && s->post_start.v[0][0] != '/')
		return fl_errx("spec: post-start's program is not an absolute path: '%s'", s->post_start.v[0]);
	if (!s->network && (s->pasta_args.n || s->pasta_wait))
		return fl_errx("spec: pasta-arg or pasta-wait without network");
	/* used[j] is set when a --ro-bind-data names keep-fd j. */
	used = table(s->nkeep_fds, 1, &ok);
	if (!ok) {
		errno = ENOMEM;
		return fl_err("spec");
	}
	rc = bwrap_allowed(s, used);
	/* bwrap passes whatever it inherits on to the payload, so a keep-fd
	 * that no option consumes would reach the payload open. */
	for (size_t j = 0; rc == 0 && j < s->nkeep_fds; j++)
		if (!used[j])
			rc = fl_errx("spec: keep-fd %d is named by no bwrap-arg --ro-bind-data", s->keep_fds[j]);
	free(used);
	return rc;
}
