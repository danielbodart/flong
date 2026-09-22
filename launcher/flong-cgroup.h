/* flong-cgroup.h: the session cgroup.
 *
 * Every session gets its own cgroup, <holder>/<container>/<machine>, with
 * three leaves: sandbox (bwrap, everything in the session, and the mount
 * helper for the moment it runs), hooks (postStart and whatever it leaves
 * running) and pasta. Each process is created in its leaf with
 * clone3(CLONE_INTO_CGROUP) and never migrated; the session cgroup itself
 * holds no process, so controllers can be enabled below it.
 *
 * That is mechanism, not policy: it is how a hook's daemon and pasta die
 * with the session, and how the sweep finds what a dead session left. No
 * limit is written unless the spec declares one, and a controller is enabled
 * (in the holder's, the container level's and the session's
 * cgroup.subtree_control) only when a declared limit needs it. Limits are
 * written on the sandbox leaf, the payload's own cgroup and the root of its
 * cgroup namespace, which is where the payload's programs read them.
 */
#ifndef FLONG_CGROUP_H
#define FLONG_CGROUP_H

#include <limits.h>
#include "flong-spec.h"

/* The delegated cgroup sessions are made under. */
struct fl_holder {
	char path[PATH_MAX];  /* absolute: "/sys/fs/cgroup/user.slice/..." */
	int fd;               /* O_PATH|O_DIRECTORY|O_CLOEXEC */
};

/* Refuses to go on unless cgroup2 is mounted at /sys/fs/cgroup with
 * nsdelegate (read from /proc/self/mountinfo). Without it a payload could
 * move out of the cgroup that reaps it. Returns 0 or -1. */
int cg_check_nsdelegate(void);

/* Finds the holder for a launch, in this order:
 * rel is the spec's holder, a relative path of plain components that
 * spec_parse has already checked.
 *  1. The user manager's cgroup is the prefix of /proc/self/cgroup up to and
 *     including "user@UID.service", or, when the launcher runs outside it
 *     (a login session scope), /user.slice/user-UID.slice/user@UID.service.
 *     If that exists, the holder is <it>/<rel>. When the holder is absent,
 *     start_argv is spawned and waited for (it is `systemctl --user start
 *     flong-sessions.service` in the module), and the holder must then exist.
 *     The unit is Type=exec: systemd forks its process into the holder's own
 *     cgroup and the process moves itself to the supervisor leaf just before
 *     its exec, so only a start that waits for the exec returns once the
 *     holder has no process of its own and can enable controllers.
 *     The warm path is a stat, not `systemctl show`: a stat costs
 *     microseconds, a systemctl call about 7 ms.
 *  2. With no user manager: the launcher's own cgroup, when it is the
 *     caller's (a system unit with User= and Delegate=yes). With limits it
 *     must be the parent of the launcher's cgroup, and that parent the
 *     caller's too (DelegateSubgroup=); otherwise the launch is refused,
 *     naming DelegateSubgroup=.
 *  3. Otherwise refused loudly, naming users.users.<name>.linger.
 * Returns 0 with h filled, or -1. */
int cg_holder_find(struct fl_holder *h, const char *rel,
		   const struct fl_argv *start_argv, int have_limits);

/* The sweeper's holder: the parent of its own cgroup, since the holder unit
 * runs it in its DelegateSubgroup=supervisor leaf. Returns 0 or -1. */
int cg_holder_self(struct fl_holder *h);

enum fl_leaf { FL_LEAF_SANDBOX, FL_LEAF_HOOKS, FL_LEAF_PASTA, FL_NLEAVES };

struct fl_cgroup {
	char path[PATH_MAX];     /* <holder>/<container>/<machine>, absolute */
	int fd;                  /* the session cgroup, O_PATH|O_DIRECTORY|O_CLOEXEC */
	int leaf[FL_NLEAVES];    /* each leaf, the same; -1 when absent */
};

/* A struct fl_cgroup that holds nothing, which cg_close leaves alone. */
#define FL_CGROUP_NONE { .fd = -1, .leaf = { [0 ... FL_NLEAVES - 1] = -1 } }

/* The path the session cgroup will have, for the record, which is written
 * before the cgroup exists. Fails only when it does not fit PATH_MAX. */
int cg_session_path(char *out, size_t size, const struct fl_holder *h,
		    const char *container, const char *machine);

/* Makes the session cgroup: mkdir <container> (EEXIST is fine; it is
 * shared and never removed, since another session may be making a child in
 * it), enable the controllers the limits need down to the session, mkdir
 * <machine> (EEXIST is a refusal: a duplicate session), mkdir the three
 * leaves, open them all and write each limit into the sandbox leaf. The
 * limits bound the payload and bwrap, not the hooks or pasta; the /sys view
 * the payload sees is rooted at the leaf, so nproc, Go, Node and Java read
 * them. On failure, removes what it made. Returns 0 or -1. */
int cg_session_create(struct fl_cgroup *cg, const struct fl_holder *h,
		      const char *container, const char *machine,
		      const struct fl_limit *limits, size_t nlimits);

/* cg_session_open's answers for a record whose session is under another
 * holder, and for one whose path does not spell a session's cgroup. -1 is
 * kept for a failure to open what the path names, which may pass (EMFILE,
 * ENOMEM): only a refusal lets the sweep drop the record. */
#define FL_CG_OTHER_HOLDER (-2)
#define FL_CG_REFUSED (-3)

/* For the sweep: opens an existing session cgroup named by a record.
 * path must spell a session cgroup, <some holder>/<container>/<machine>,
 * with machine equal to the record's name and no "." or ".." component
 * (records are the caller's files now, so they are not trusted to name
 * anything else); it is opened only when that holder is h, one component at
 * a time and never through a symlink. Leaves that do not exist are left at
 * -1. Returns 1 when opened; 0 when the session cgroup does not exist (a
 * launcher that died before making it); FL_CG_OTHER_HOLDER, printing
 * nothing, when the session is under another holder (two units of the
 * caller's, or a launch with and one without a user manager, share the
 * state directory); FL_CG_REFUSED, printing why, when path is refused; -1
 * on error. */
int cg_session_open(struct fl_cgroup *cg, const struct fl_holder *h,
		    const char *path, const char *machine);

/* cg_kill, cg_wait_empty and cg_remove take an open session (or leaf):
 * cg_session_create opens the session and every leaf or nothing, and each
 * caller acts only on a session it has. */

/* Writes "1" to the session's cgroup.kill: every process in every leaf. */
int cg_kill(const struct fl_cgroup *cg);

/* Waits, with no timeout, until the cgroup behind cgfd (a session or a
 * leaf) reports "populated 0" in cgroup.events, polling it for POLLPRI.
 * Returns 0, or -1 (fl_abort_signal set when a signal ended it). */
int cg_wait_empty(int cgfd);

/* Removes the leaves, then the session cgroup. A leaf still populated (pasta
 * exits 20-40 ms after the kill, and is waited for only with fixed
 * forwardPorts) makes it stop there.
 * Returns 0 when everything is gone, 1 when something is still busy (the
 * record is then kept for the sweep), -1 on error. */
int cg_remove(struct fl_cgroup *cg);

/* Closes the descriptors; removes nothing. */
void cg_close(struct fl_cgroup *cg);

#endif
