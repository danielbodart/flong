/* What P4 checks src/abi.zig against: the uapi headers bundled with Zig
 * (lib/libc/include/any-linux-any, kernel 6.13.4, and the per-arch
 * <arch>-linux-any for asm/), translated per target by addTranslateC.
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
#include <asm/unistd.h>
