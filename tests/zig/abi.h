/* What tests/zig/abi.zig checks flong's structs and constants against: the
 * uapi headers bundled with Zig (lib/libc/include/any-linux-any, kernel
 * 6.13.4, and the per-arch <arch>-linux-any for asm/), translated per
 * target by build.zig's `abi` step (spike/proofs/p4/src/abi.h, archived).
 * linux/fcntl.h first: linux/mount.h defines OPEN_TREE_CLOEXEC as O_CLOEXEC
 * but does not include it. */
#include <linux/version.h>
#include <linux/fcntl.h>
#include <linux/magic.h>
#include <linux/mount.h>
#include <linux/openat2.h>
#include <linux/sched.h>
#include <linux/pidfd.h>
#include <linux/stat.h>
#include <linux/uio.h>
#include <linux/capability.h>
#include <linux/prctl.h>
#include <linux/limits.h>
#include <asm/ioctls.h>
#include <asm/signal.h>
#include <asm/unistd.h>
