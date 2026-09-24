/* mountinfo_c.c: the C's nsdelegate check over a text of the test's, for
 * test-libc's differential (tests/zig/libc_launch.zig): flong-cgroup.c is
 * included whole and compiled as the launcher compiles it, with its fopen
 * of /proc/self/mountinfo answered by fmemopen of the text, and its
 * refusals (fl_errx) kept for the test to read instead of printed. Also
 * glibc's O_TMPFILE, for sys.O_TMPFILE. flong-util.c links beside.
 * Deleted with the C launcher (ZIG.md, phase 7, L5). */
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>

static const char *mi_text;
static size_t mi_len;
static char mi_said[1024];

/* fmemopen refuses a buffer of no bytes; an empty text reads as a one-byte
 * buffer holding NUL would not, so an empty file is a stream with nothing
 * in it, which /dev/null is. */
static FILE *mi_open(void)
{
	if (mi_len == 0)
		return fopen("/dev/null", "re");
	return fmemopen((void *)mi_text, mi_len, "r");
}

/* flong-util.h declares fl_errx; this renames that declaration and every
 * call in flong-cgroup.c to c_errx. */
#define fl_errx c_errx
#define fopen(path, mode) mi_open()
#include "flong-cgroup.c"
#undef fopen
#undef fl_errx

int c_errx(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(mi_said, sizeof mi_said, fmt, ap);
	va_end(ap);
	return -1;
}

/* cg_check_nsdelegate over text: 0, or -1 with what it said in *said. */
int c_check_nsdelegate(const char *text, size_t len, const char **said)
{
	mi_text = text;
	mi_len = len;
	mi_said[0] = '\0';
	int rc = cg_check_nsdelegate();
	*said = mi_said;
	return rc;
}

unsigned c_o_tmpfile(void)
{
	return O_TMPFILE;
}

/* has_item (flong-cgroup.c:30-42), static there: for the differential of
 * cgroup.hasItem, over superoptions (',') and cgroup.controllers (' '). */
int c_has_item(const char *list, const char *item, char sep)
{
	return has_item(list, item, sep);
}
