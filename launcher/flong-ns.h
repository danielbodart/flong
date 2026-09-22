/* flong-ns.h: the two user namespaces.
 *
 * U1 is keep-id and owned by the caller. It owns every other namespace of the
 * session: network, mount, ipc, uts, pid, cgroup. U2 is a child of U1 and
 * holds the payload, with no capabilities and, by default, no user namespaces
 * of its own. So the payload holds no capability over its network namespace,
 * even in principle.
 */
#ifndef FLONG_NS_H
#define FLONG_NS_H

#include "flong-spec.h"

struct fl_userns {
	int u1;  /* /proc/<pid>/ns/user of U1, O_RDONLY|O_CLOEXEC */
	int u2;  /* the same for U2 */
};

/* Makes U1 and U2 and returns a descriptor for each in ns.
 *
 * U1: a forked child unshares a user namespace; newuidmap and newgidmap
 * (FLONG_NEWUIDMAP, FLONG_NEWGIDMAP) write s->uidmap and s->gidmap in
 * parallel, both spawned with fl_spawn; the child exits once U1 is open.
 *
 * U2: a helper joins U1 (it owns U1, so it has every capability there), a
 * grandchild unshares U2, the helper writes U2's maps and the grandchild
 * writes U2's user.max_user_namespaces (s->nested_userns, 0 by default).
 * U2's maps are the identity split along U1's extents: each U1 extent
 * (inside, outside, count) becomes (inside, inside, count). A single
 * "0 0 65536" extent is refused with EPERM; the split is what the kernel
 * accepts, and with it container-root files read as root inside.
 *
 * Every handshake is a byte on a pipe, and every wait an fl_await. Called
 * once, after the record exists and before the session cgroup is made. On
 * failure nothing is left: helpers reaped, descriptors closed. A newuidmap
 * failure names /etc/subuid and subUidRanges in its message.
 * Returns 0, or -1 (fl_abort_signal set when a signal ended it). */
int ns_create(const struct fl_spec *s, struct fl_userns *ns);

#endif
