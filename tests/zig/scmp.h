/* What tests/zig/libc_scmp.zig checks src/seccomp/scmp.zig against, and
 * stdlib.h for free, which bpfdump gives libseccomp's names to. The
 * arch tokens are or-ed macros translate-c cannot type (it reads
 * AUDIT_ARCH_X86_64 as an int, and 0x80000000 overflows one), so they are
 * given here as C evaluates them. */
#include <seccomp.h>
#include <stdlib.h>

static const unsigned int flong_arch_x86_64 = SCMP_ARCH_X86_64;
static const unsigned int flong_arch_x86 = SCMP_ARCH_X86;
static const unsigned int flong_arch_x32 = SCMP_ARCH_X32;
