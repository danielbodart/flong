/* cmount-shim.c: flong_mount_main for flong-launch-cmount, the C launcher
 * with the C mount helper, built only for phase 4 (a)'s transition subtest
 * (ZIG.md, "The mount-helper shim"; native.nix, `cmount`). It is what
 * flong-launch.c:553 did before it called the Zig helper: the trace flag,
 * then mount_run's status as the process's. Deleted with flong-mount.c in
 * phase 4 (b). */
#include <unistd.h>

#include "flong-mount.h"
#include "flong-util.h"

_Noreturn void flong_mount_main(const struct fl_mount_job *job, int tracing)
{
	fl_tracing = tracing;
	_exit(mount_run(job));
}
