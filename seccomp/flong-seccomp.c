/* flong-seccomp.c: compiles a policy on stdin to one BPF program on stdout.
 *
 *   default N|allow           first directive, once: the action for any call
 *                             no rule names, ERRNO(N) or ALLOW
 *   allow NAME [CMP...]       ALLOW
 *   errno N NAME [CMP...]     ERRNO(N), N from 1 to 4095
 *   log NAME [CMP...]         allowed, and logged by the kernel
 *   CMP is aI:OP:VALUE, OP one of eq ne lt le gt ge, or aI:masked_eq:VALUE:MASK
 *
 * libseccomp keeps the first of two unconditional rules for one call and
 * lets an unconditional rule swallow conditional ones, silently. Both are
 * refused here instead, so the filter says what the policy says. Nothing
 * reaches stdout unless the whole policy is accepted: the export is the
 * last step.
 */
#include <errno.h>
#include <seccomp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE 4095
#define MAX_WORDS 16
#define MAX_CMPS 6
#define MAX_NR 4096

/* seen[nr] bits: the call has an unconditional rule, or a conditional one. */
#define UNCONDITIONAL 1
#define CONDITIONAL 2

struct policy {
	scmp_filter_ctx ctx;
	unsigned line;
	unsigned rules;
	unsigned unknown;
	unsigned char seen[MAX_NR];
};

static const struct {
	const char *name;
	enum scmp_compare op;
} ops[] = {
	{ "eq", SCMP_CMP_EQ },
	{ "ne", SCMP_CMP_NE },
	{ "lt", SCMP_CMP_LT },
	{ "le", SCMP_CMP_LE },
	{ "gt", SCMP_CMP_GT },
	{ "ge", SCMP_CMP_GE },
	{ "masked_eq", SCMP_CMP_MASKED_EQ },
};

/* The kernel reads these arguments as 32-bit ints, while a filter compares
 * all 64 bits: a comparison that looks at bits 32-63 is bypassed by setting
 * them. So they are compared only with masked_eq under a 32-bit mask. The
 * value is a bitmask of argument indices. */
static const struct {
	const char *name;
	unsigned args;
} int_args[] = {
	{ "ioctl", 0x03 },
	{ "fcntl", 0x03 },
	{ "socket", 0x07 },
	{ "socketpair", 0x07 },
	{ "setns", 0x03 },
	{ "prctl", 0x01 },
	{ "personality", 0x01 },
	{ "kill", 0x03 },
	{ "tgkill", 0x07 },
};

static int refuse(const struct policy *p, const char *what, const char *word)
{
	if (word)
		fprintf(stderr, "flong-seccomp: line %u: %s: %s\n", p->line, what, word);
	else
		fprintf(stderr, "flong-seccomp: line %u: %s\n", p->line, what);
	return -1;
}

/* libseccomp returns a negated errno. */
static int failed(const struct policy *p, const char *what, const char *word, int rc)
{
	fprintf(stderr, "flong-seccomp: line %u: %s%s%s: %s\n", p->line, what,
		word ? " " : "", word ? word : "", strerror(-rc));
	return -1;
}

/* Reads a decimal errno from 1 to 4095, the range SCMP_ACT_ERRNO carries. */
static int parse_errno(const char *s, uint32_t *n)
{
	uint32_t v = 0;

	if (!*s)
		return -1;
	for (; *s; s++) {
		if (*s < '0' || *s > '9')
			return -1;
		v = v * 10 + (uint32_t)(*s - '0');
		if (v > 4095)
			return -1;
	}
	if (v < 1)
		return -1;
	*n = v;
	return 0;
}

/* Reads a whole unsigned number in any base strtoull takes. strtoull also
 * takes a sign and leading blanks, and wraps a negative number, so the first
 * character must be a digit. */
static int parse_number(const char *s, uint64_t *v)
{
	char *end;

	if (*s < '0' || *s > '9')
		return -1;
	errno = 0;
	*v = strtoull(s, &end, 0);
	return errno || *end ? -1 : 0;
}

/* Parses aI:OP:VALUE or aI:masked_eq:VALUE:MASK, in a copy of the word so
 * that a refusal can quote it whole. */
static int parse_cmp(const char *word, struct scmp_arg_cmp *c)
{
	char buf[MAX_LINE + 1], *op, *value, *mask;
	size_t i;

	if (strlen(word) > MAX_LINE)
		return -1;
	strcpy(buf, word);
	if (buf[0] != 'a' || buf[1] < '0' || buf[1] > '5' || buf[2] != ':')
		return -1;
	c->arg = (unsigned)(buf[1] - '0');
	op = buf + 3;
	value = strchr(op, ':');
	if (!value)
		return -1;
	*value++ = '\0';
	mask = strchr(value, ':');
	if (mask)
		*mask++ = '\0';
	for (i = 0; i < sizeof ops / sizeof *ops; i++)
		if (!strcmp(ops[i].name, op))
			break;
	if (i == sizeof ops / sizeof *ops)
		return -1;
	c->op = ops[i].op;
	if (c->op == SCMP_CMP_MASKED_EQ) {
		/* libseccomp takes the mask first and the value second. */
		if (!mask || parse_number(mask, &c->datum_a) || parse_number(value, &c->datum_b))
			return -1;
	} else {
		if (mask || parse_number(value, &c->datum_a))
			return -1;
		c->datum_b = 0;
	}
	return 0;
}

static unsigned int_args_of(const char *name)
{
	size_t i;

	for (i = 0; i < sizeof int_args / sizeof *int_args; i++)
		if (!strcmp(int_args[i].name, name))
			return int_args[i].args;
	return 0;
}

/* Starts the filter from `default N|allow`. The x86_64 filter covers i386
 * and x32 too, because a payload can enter the kernel through either ABI
 * and nspawn's own filter covers all three. */
static int start(struct policy *p, char **w, int n)
{
	uint32_t action, err;
	int rc;

	if (n != 2)
		return refuse(p, "the first directive must be `default N|allow`", NULL);
	if (!strcmp(w[1], "allow"))
		action = SCMP_ACT_ALLOW;
	else if (!parse_errno(w[1], &err))
		action = SCMP_ACT_ERRNO(err);
	else
		return refuse(p, "default is neither allow nor an errno from 1 to 4095", w[1]);
	p->ctx = seccomp_init(action);
	if (!p->ctx)
		return refuse(p, "libseccomp could not start a filter", NULL);
	if (seccomp_arch_native() == SCMP_ARCH_X86_64) {
		rc = seccomp_arch_add(p->ctx, SCMP_ARCH_X86);
		if (rc)
			return failed(p, "libseccomp could not add the i386 arch", NULL, rc);
		rc = seccomp_arch_add(p->ctx, SCMP_ARCH_X32);
		if (rc)
			return failed(p, "libseccomp could not add the x32 arch", NULL, rc);
	}
	rc = seccomp_attr_set(p->ctx, SCMP_FLTATR_CTL_OPTIMIZE, 2);
	if (rc)
		return failed(p, "libseccomp could not set the binary-tree optimisation", NULL, rc);
	return 0;
}

static int rule(struct policy *p, char **w, int n)
{
	struct scmp_arg_cmp cmp[MAX_CMPS];
	unsigned ints, ncmp = 0;
	uint32_t action, err;
	const char *name;
	int k, i, nr, rc;

	if (!strcmp(w[0], "allow")) {
		action = SCMP_ACT_ALLOW;
		k = 1;
	} else if (!strcmp(w[0], "log")) {
		action = SCMP_ACT_LOG;
		k = 1;
	} else if (!strcmp(w[0], "errno")) {
		if (n < 2)
			return refuse(p, "errno has no number", NULL);
		if (parse_errno(w[1], &err))
			return refuse(p, "errno is not a number from 1 to 4095", w[1]);
		action = SCMP_ACT_ERRNO(err);
		k = 2;
	} else if (!strcmp(w[0], "default")) {
		return refuse(p, "default appears again", NULL);
	} else {
		return refuse(p, "unknown directive", w[0]);
	}
	if (k >= n)
		return refuse(p, "missing syscall name", NULL);
	name = w[k];
	ints = int_args_of(name);
	for (i = k + 1; i < n; i++) {
		if (ncmp == MAX_CMPS)
			return refuse(p, "more than 6 argument comparisons", w[i]);
		if (parse_cmp(w[i], &cmp[ncmp]))
			return refuse(p, "bad argument comparison", w[i]);
		if (ints & 1u << cmp[ncmp].arg &&
		    (cmp[ncmp].op != SCMP_CMP_MASKED_EQ || cmp[ncmp].datum_a > 0xffffffffu))
			return refuse(p, "an int argument needs masked_eq with a mask of at most 0xffffffff", w[i]);
		ncmp++;
	}

	/* systemd lists names libseccomp does not know yet; nspawn skips them
	 * too, and the count shows the skew. */
	nr = seccomp_syscall_resolve_name(name);
	if (nr == __NR_SCMP_ERROR) {
		p->unknown++;
		return 0;
	}
	/* Only native numbers are tracked: libseccomp 2.6.1 gives two ppc-only
	 * names one negative pseudo number. */
	if (nr >= 0 && nr < MAX_NR) {
		if (p->seen[nr] & UNCONDITIONAL || (ncmp == 0 && p->seen[nr]))
			return refuse(p, "named twice, and one rule is unconditional", name);
		p->seen[nr] |= ncmp ? CONDITIONAL : UNCONDITIONAL;
	}
	rc = seccomp_rule_add_array(p->ctx, action, nr, ncmp, cmp);
	/* libseccomp refuses a rule that would change nothing. */
	if (rc == -EACCES)
		return refuse(p, "the rule's action is the default's", name);
	if (rc)
		return failed(p, "libseccomp refused the rule for", name, rc);
	p->rules++;
	return 0;
}

/* Splits one line on blanks and applies it. */
static int directive(struct policy *p, char *line)
{
	char *w[MAX_WORDS], *t;
	int n = 0;

	t = strtok(line, " \t\r\n");
	/* A comment is prose, so the word limit does not apply to it. */
	if (!t || t[0] == '#')
		return 0;
	for (; t; t = strtok(NULL, " \t\r\n")) {
		if (n == MAX_WORDS)
			return refuse(p, "more than 16 words", NULL);
		w[n++] = t;
	}
	if (!p->ctx) {
		if (strcmp(w[0], "default"))
			return refuse(p, "the first directive must be `default N|allow`", w[0]);
		return start(p, w, n);
	}
	return rule(p, w, n);
}

static int compile(struct policy *p)
{
	char *line = NULL;
	size_t cap = 0;
	ssize_t len;
	int rc = 0;

	while (rc == 0 && (len = getline(&line, &cap, stdin)) >= 0) {
		p->line++;
		if (len > 0 && line[len - 1] == '\n')
			line[--len] = '\0';
		if (len > MAX_LINE)
			rc = refuse(p, "longer than 4095 bytes", NULL);
		else
			rc = directive(p, line);
	}
	free(line);
	if (rc)
		return -1;
	if (ferror(stdin)) {
		fprintf(stderr, "flong-seccomp: reading the policy: %s\n", strerror(errno));
		return -1;
	}
	if (!p->ctx)
		return refuse(p, "empty policy: no default", NULL);
	rc = seccomp_export_bpf(p->ctx, 1);
	if (rc) {
		fprintf(stderr, "flong-seccomp: libseccomp could not export the filter: %s\n", strerror(-rc));
		return -1;
	}
	fprintf(stderr, "flong-seccomp: %u rules, %u names libseccomp does not know\n", p->rules, p->unknown);
	return 0;
}

int main(int argc, char **argv)
{
	static struct policy p;
	int rc;

	(void)argv;
	if (argc != 1) {
		fprintf(stderr, "usage: flong-seccomp < POLICY > FILTER.bpf\n");
		return 2;
	}
	rc = compile(&p);
	if (p.ctx)
		seccomp_release(p.ctx);
	return rc ? 1 : 0;
}
