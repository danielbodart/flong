/* record_c.c: the C sweep's pure parts, exposed for test-libc's
 * differential (tests/zig/libc_record.zig): parse_record, closed_inode
 * (flong-record.c:264-308, 736-753) and session_form (flong-cgroup.c:
 * 415-440), each static there, so the files are included whole and
 * compiled as the launcher compiles them; flong-util.c is linked beside.
 * Deleted with the C launcher (ZIG.md, phase 7, L5). */
#include "flong-record.c"
#include "flong-cgroup.c"

int c_parse(const char *buf, size_t len, char *poststop, char *cgroup,
	    int *leader, unsigned long long *start, const char **why)
{
	struct rec_fields f;
	*why = NULL;
	int rc = parse_record(buf, len, &f, why);
	if (rc == 0) {
		strcpy(poststop, f.poststop);
		strcpy(cgroup, f.cgroup);
		*leader = (int)f.leader;
		*start = f.starttime;
	}
	return rc;
}

long c_session_form(const char *path, const char *machine)
{
	const char *r = session_form(path, machine);
	return r ? (long)(r - path) : -1;
}

unsigned long long c_closed_inode(const char *name)
{
	return (unsigned long long)closed_inode(name);
}
