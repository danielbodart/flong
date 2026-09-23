/* What tests/zig/libc_mount.zig checks src/hybrid/mount_c.zig against: the
 * mount helper's header, as the C launcher includes it (launcher/, on the
 * include path; glibc's sys/types.h); and glibc's sys/mount.h, for the
 * umount2 flags, which no uapi header defines. */
#include <sys/mount.h>
#include "flong-mount.h"
