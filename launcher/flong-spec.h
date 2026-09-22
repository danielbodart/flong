/* flong-spec.h: what a launch is asked to do, parsed from argv.
 *
 * The wrapper passes the whole spec as flong-launch's arguments: a sequence
 * of keywords, each followed by a fixed number of fields, then "--" and the
 * payload's command. An argument is a NUL-terminated string, so a path may
 * hold a tab, a newline or anything else but NUL, and bash builds the list
 * with builtins alone (an array and exec), which a spec file or a pipe would
 * not allow without a fork on the warm path. The grammar is in CONTRACT.md,
 * "The input contract".
 *
 * Every string in struct fl_spec points into argv; nothing is copied.
 * Arrays are allocated once by spec_parse and live as long as the process.
 */
#ifndef FLONG_SPEC_H
#define FLONG_SPEC_H

#include <stddef.h>
#include <sys/types.h>

/* One extent of U1's uid_map or gid_map, in newuidmap's order. */
struct fl_idmap {
	unsigned long inside, outside, count;
};

/* The kinds of mount the walker makes, one per `mount` keyword. */
enum fl_mount_kind {
	FL_BIND_RO,        /* declared bindMounts: the source follows symlinks, as its author intended */
	FL_BIND_RW,
	FL_BIND_RO_EXACT,  /* caller binds and the workspace: the source is canonical and is */
	FL_BIND_RW_EXACT,  /* opened with RESOLVE_NO_SYMLINKS, so a symlink met now is a race */
	FL_DEV,            /* allowedDevices: a read-write bind that is not nodev */
	FL_TMPFS,
	FL_OVERLAY,        /* a lower directory under a writable layer that is thrown away */
	FL_MASK,           /* a mode-0 read-only node of the destination's own kind */
};

struct fl_mount {
	enum fl_mount_kind kind;
	const char *dest;  /* absolute, inside the session */
	const char *src;   /* binds and dev: the host source; overlay: the lower; else NULL */
	const char *mode;  /* tmpfs: octal digits ("0700"); else NULL */
	const char *size;  /* tmpfs: tmpfs's size= value, or NULL for none */
	int owner_user;    /* tmpfs: 1 when its root is the payload's, 0 container root's */
};

/* One opt-in cgroup limit: a file in the sandbox leaf and what to write. */
struct fl_limit {
	const char *file;  /* memory.max memory.high memory.swap.max memory.oom.group
	                      pids.max cpu.max cpu.weight io.weight: nothing else */
	const char *value;
};

/* A NULL-terminated argument vector; v[n] == NULL. Empty: n == 0, v NULL. */
struct fl_argv {
	char **v;
	size_t n;
};

struct fl_spec {
	/* the session */
	const char *machine;      /* its name: record, leaf cgroup, $machine */
	const char *container;    /* the cgroup level between the holder and sessions */
	const char *state;        /* $XDG_RUNTIME_DIR/flong: the caller's, mode 0700 */
	const char *cache;        /* the cache directory; the root is <cache>/prepared */
	struct fl_argv relaunch;  /* run when the cache was swept; empty: exit 75 */
	const char *closure;      /* bound at /run/current-system */

	/* identity */
	struct fl_idmap *uidmap;  /* U1's maps; U2's are derived from them */
	size_t nuidmap;
	struct fl_idmap *gidmap;
	size_t ngidmap;
	uid_t uid;                /* the payload, as ids inside the container */
	gid_t gid;
	const char *home;
	gid_t *groups;            /* supplementary groups, from the container's /etc/group */
	size_t ngroups;
	const char *chdir;        /* where the payload starts; "/" unless given */

	/* mounts */
	struct fl_mount *mounts;  /* in the order given; the helper sorts */
	size_t nmounts;
	const char **protect;     /* no mount source may equal, lie inside or contain these */
	size_t nprotect;

	/* lockdown */
	const char **seccomp;     /* compiled BPF programs, each an --add-seccomp-fd, in order */
	size_t nseccomp;
	unsigned long nested_userns; /* U2's user.max_user_namespaces; 0: nested namespaces off */

	/* containment */
	const char *holder;       /* the holder unit's cgroup, relative to user@UID.service */
	struct fl_argv holder_start; /* run when the holder's cgroup is absent */
	struct fl_limit *limits;
	size_t nlimits;

	/* hooks and network */
	struct fl_argv post_start;   /* empty: no hook */
	const char *post_stop;       /* a /nix/store program, or NULL */
	int network;                 /* start pasta */
	struct fl_argv pasta_args;   /* ports, --dns-forward, --no-map-gw ... */
	int pasta_wait;              /* fixed forwardPorts bind host ports: wait for pasta's exit */

	/* bwrap */
	struct fl_argv bwrap_args;   /* only the options CONTRACT.md allows */
	int *keep_fds;               /* descriptors those options name (--ro-bind-data 9 ...) */
	size_t nkeep_fds;

	int trace;
	struct fl_argv command;      /* what tini runs; never empty */
};

/* Parses argv[1..argc-1] into s. Refuses an unknown keyword, a missing field,
 * a singleton keyword given twice, a missing required keyword, a relative
 * path, a bad name, a limit file not in the list above, a map that reaches
 * host id 0, a post-stop outside /nix/store/, a keep-fd that is not open and a
 * bwrap-arg outside the allowed options. Prints the first problem and
 * returns -1; 0 on success. */
int spec_parse(int argc, char **argv, struct fl_spec *s);

#endif
