/* bpfdump.c: a live process's seccomp filters, and what a stack of them does.
 *
 *   bpfdump dump PID PREFIX
 *       Writes every filter attached to PID as PREFIX.N.bpf, N = 0 the most
 *       recently attached, and prints the count. Needs CAP_SYS_ADMIN in the
 *       initial namespace, and a caller that is not itself filtered.
 *
 *   bpfdump eval [-k F.bpf]... F.bpf...
 *       Runs the stack of filters, with the kernel's precedence, over every
 *       syscall number 0..1023 of x86_64, x32 and i386 with all arguments 0,
 *       and prints one line each. Where that run read an argument, it sweeps
 *       them: every (slot, K) with and without bit 32 set, and every pair of
 *       slots with constants, for every constant K any program compares an
 *       argument with. A sweep prints a line only where the result differs
 *       from the all-zero one. A run that read no argument took a path no
 *       argument can change, so its line is the call's whole answer.
 *       -k adds a file's constants to the sweep without running it, so that
 *       two stacks evaluated apart are swept with the same values and their
 *       output can be compared line for line.
 *
 * The output is sorted and diffable. The interpreter covers the classic BPF
 * libseccomp and systemd emit, and stops on anything else.
 */
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PTRACE_SECCOMP_GET_FILTER
#define PTRACE_SECCOMP_GET_FILTER 0x420c
#endif

#define MAX_PROGS 16
#define MAX_CONSTS 4096

/* The first byte of seccomp_data's args: a load at or past it reads one. */
#define ARGS_OFFSET offsetof(struct seccomp_data, args)

static int dump(pid_t pid, const char *prefix)
{
	int status, n;

	if (ptrace(PTRACE_SEIZE, pid, 0, 0) != 0) {
		perror("PTRACE_SEIZE");
		return 1;
	}
	if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) != 0) {
		perror("PTRACE_INTERRUPT");
		return 1;
	}
	if (waitpid(pid, &status, __WALL) != pid) {
		perror("waitpid");
		return 1;
	}
	for (n = 0;; n++) {
		long len = ptrace(PTRACE_SECCOMP_GET_FILTER, pid, (void *)(long)n, NULL);
		struct sock_filter *f;
		char path[4096];
		FILE *out;

		if (len < 0) {
			if (errno != ENOENT) {
				perror("PTRACE_SECCOMP_GET_FILTER");
				return 1;
			}
			break;
		}
		f = calloc(len, sizeof *f);
		if (f == NULL || ptrace(PTRACE_SECCOMP_GET_FILTER, pid, (void *)(long)n, f) != len) {
			perror("PTRACE_SECCOMP_GET_FILTER");
			return 1;
		}
		snprintf(path, sizeof path, "%s.%d.bpf", prefix, n);
		out = fopen(path, "w");
		if (out == NULL || fwrite(f, sizeof *f, len, out) != (size_t)len || fclose(out) != 0) {
			perror(path);
			return 1;
		}
		printf("filter %d: %ld instructions -> %s\n", n, len, path);
		free(f);
	}
	ptrace(PTRACE_DETACH, pid, 0, 0);
	printf("filters: %d\n", n);
	return 0;
}

struct prog {
	struct sock_filter *f;
	size_t n;
};

/* One program over D, as the kernel runs it. *READ is set when it loads an
 * argument. */
static uint32_t run(const struct prog *p, const struct seccomp_data *d, int *read)
{
	uint32_t a = 0, x = 0, mem[BPF_MEMWORDS] = { 0 };
	const unsigned char *data = (const unsigned char *)d;

	for (size_t pc = 0; pc < p->n; pc++) {
		const struct sock_filter *i = &p->f[pc];
		uint32_t k = i->k;

		switch (i->code) {
		case BPF_LD | BPF_W | BPF_ABS:
			if (k + 4 > sizeof *d)
				return SECCOMP_RET_KILL_PROCESS;
			if (k >= ARGS_OFFSET)
				*read = 1;
			memcpy(&a, data + k, 4);
			break;
		case BPF_LD | BPF_W | BPF_LEN: a = sizeof *d; break;
		case BPF_LDX | BPF_W | BPF_LEN: x = sizeof *d; break;
		case BPF_LD | BPF_IMM: a = k; break;
		case BPF_LDX | BPF_IMM: x = k; break;
		case BPF_LD | BPF_MEM: a = mem[k]; break;
		case BPF_LDX | BPF_MEM: x = mem[k]; break;
		case BPF_ST: mem[k] = a; break;
		case BPF_STX: mem[k] = x; break;
		case BPF_MISC | BPF_TAX: x = a; break;
		case BPF_MISC | BPF_TXA: a = x; break;
		case BPF_RET | BPF_K: return k;
		case BPF_RET | BPF_A: return a;
		case BPF_JMP | BPF_JA: pc += k; break;
		case BPF_JMP | BPF_JEQ | BPF_K: pc += (a == k) ? i->jt : i->jf; break;
		case BPF_JMP | BPF_JGT | BPF_K: pc += (a > k) ? i->jt : i->jf; break;
		case BPF_JMP | BPF_JGE | BPF_K: pc += (a >= k) ? i->jt : i->jf; break;
		case BPF_JMP | BPF_JSET | BPF_K: pc += (a & k) ? i->jt : i->jf; break;
		case BPF_JMP | BPF_JEQ | BPF_X: pc += (a == x) ? i->jt : i->jf; break;
		case BPF_JMP | BPF_JGT | BPF_X: pc += (a > x) ? i->jt : i->jf; break;
		case BPF_JMP | BPF_JGE | BPF_X: pc += (a >= x) ? i->jt : i->jf; break;
		case BPF_JMP | BPF_JSET | BPF_X: pc += (a & x) ? i->jt : i->jf; break;
		case BPF_ALU | BPF_ADD | BPF_K: a += k; break;
		case BPF_ALU | BPF_SUB | BPF_K: a -= k; break;
		case BPF_ALU | BPF_AND | BPF_K: a &= k; break;
		case BPF_ALU | BPF_OR | BPF_K: a |= k; break;
		case BPF_ALU | BPF_LSH | BPF_K: a <<= k; break;
		case BPF_ALU | BPF_RSH | BPF_K: a >>= k; break;
		case BPF_ALU | BPF_AND | BPF_X: a &= x; break;
		case BPF_ALU | BPF_OR | BPF_X: a |= x; break;
		case BPF_ALU | BPF_NEG: a = -a; break;
		default:
			fprintf(stderr, "bpfdump: unsupported opcode 0x%x at %zu\n", i->code, pc);
			exit(3);
		}
	}
	return SECCOMP_RET_KILL_PROCESS;
}

/* The stack's answer: every program runs, and the kernel keeps the lowest
 * action, compared as a signed value. */
static uint32_t stack(const struct prog *ps, int np, const struct seccomp_data *d, int *read)
{
	uint32_t ret = SECCOMP_RET_ALLOW;

	for (int i = 0; i < np; i++) {
		uint32_t r = run(&ps[i], d, read);

		if ((int32_t)(r & SECCOMP_RET_ACTION_FULL) < (int32_t)(ret & SECCOMP_RET_ACTION_FULL))
			ret = r;
	}
	return ret;
}

static const char *action(uint32_t r, char *b, size_t size)
{
	uint32_t a = r & SECCOMP_RET_ACTION_FULL, v = r & SECCOMP_RET_DATA;
	const char *e;

	switch (a) {
	case SECCOMP_RET_ALLOW: return "ALLOW";
	case SECCOMP_RET_LOG: return "LOG";
	case SECCOMP_RET_KILL_PROCESS: return "KILL_PROCESS";
	case SECCOMP_RET_KILL_THREAD: return "KILL_THREAD";
	case SECCOMP_RET_TRAP: return "TRAP";
	case SECCOMP_RET_TRACE: return "TRACE";
	case SECCOMP_RET_USER_NOTIF: return "USER_NOTIF";
	case SECCOMP_RET_ERRNO:
		e = strerrorname_np(v);
		if (e != NULL)
			snprintf(b, size, "ERRNO(%s)", e);
		else
			snprintf(b, size, "ERRNO(%u)", v);
		return b;
	}
	snprintf(b, size, "0x%08x", r);
	return b;
}

static int load(const char *path, struct prog *p)
{
	FILE *f = fopen(path, "r");
	long size;

	if (f == NULL || fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) < 0) {
		perror(path);
		return -1;
	}
	rewind(f);
	if (size == 0 || size % sizeof(struct sock_filter) != 0) {
		fprintf(stderr, "bpfdump: %s is not a BPF program\n", path);
		return -1;
	}
	p->n = size / sizeof(struct sock_filter);
	p->f = malloc(size);
	if (p->f == NULL || fread(p->f, 1, size, f) != (size_t)size) {
		perror(path);
		return -1;
	}
	fclose(f);
	return 0;
}

/* The constants P compares an argument with: those of a conditional jump
 * whose accumulator was last loaded from the arguments. */
static void constants(const struct prog *p, uint32_t *k, int *nk)
{
	uint32_t last = 0;

	for (size_t j = 0; j < p->n; j++) {
		uint16_t c = p->f[j].code;

		if (c == (BPF_LD | BPF_W | BPF_ABS))
			last = p->f[j].k;
		if (BPF_CLASS(c) == BPF_JMP && BPF_SRC(c) == BPF_K && BPF_OP(c) != BPF_JA
		    && last >= ARGS_OFFSET) {
			int seen = 0;

			for (int q = 0; q < *nk; q++)
				if (k[q] == p->f[j].k)
					seen = 1;
			if (!seen) {
				if (*nk == MAX_CONSTS) {
					fputs("bpfdump: too many constants\n", stderr);
					exit(3);
				}
				k[(*nk)++] = p->f[j].k;
			}
		}
	}
}

static int eval(int argc, char **argv)
{
	static uint32_t k[MAX_CONSTS];
	struct prog ps[MAX_PROGS], extra;
	int np = 0, nk = 0;
	static const struct {
		const char *name;
		uint32_t arch, sarch, bias;
	} arches[] = {
		{ "x86_64", AUDIT_ARCH_X86_64, SCMP_ARCH_X86_64, 0 },
		{ "x32", AUDIT_ARCH_X86_64, SCMP_ARCH_X32, 0x40000000 },
		{ "i386", AUDIT_ARCH_I386, SCMP_ARCH_X86, 0 },
	};
	char b1[32], b2[32];

	for (int i = 0; i < argc; i++) {
		if (strcmp(argv[i], "-k") == 0) {
			if (++i == argc || load(argv[i], &extra) != 0)
				return 2;
			constants(&extra, k, &nk);
			free(extra.f);
			continue;
		}
		if (np == MAX_PROGS) {
			fputs("bpfdump: too many programs\n", stderr);
			return 2;
		}
		if (load(argv[i], &ps[np]) != 0)
			return 2;
		constants(&ps[np], k, &nk);
		np++;
	}
	if (np == 0) {
		fputs("bpfdump: no program to evaluate\n", stderr);
		return 2;
	}

	for (unsigned a = 0; a < sizeof arches / sizeof *arches; a++) {
		for (int nr = 0; nr < 1024; nr++) {
			struct seccomp_data d = { .nr = nr + arches[a].bias, .arch = arches[a].arch };
			int read = 0, ignored = 0;
			uint32_t base = stack(ps, np, &d, &read);
			char *resolved = seccomp_syscall_resolve_num_arch(arches[a].sarch, nr + arches[a].bias);
			const char *name = resolved ? resolved : "-";

			printf("%s %4d %-24s %s\n", arches[a].name, nr, name, action(base, b1, sizeof b1));
			for (int s = 0; read && s < 6; s++)
			for (int q = 0; q < nk; q++)
			for (int hi = 0; hi < 2; hi++)
			for (int t = s; t < 6; t++)
			for (int w = 0; w < (t == s ? 1 : nk); w++) {
				struct seccomp_data e = d;
				uint32_t r;

				e.args[s] = k[q] | (hi ? 0x100000000ULL : 0);
				if (t != s)
					e.args[t] = k[w];
				r = stack(ps, np, &e, &ignored);
				if (r == base)
					continue;
				printf("%s %4d %-24s a%d=0x%llx", arches[a].name, nr, name, s,
				       (unsigned long long)e.args[s]);
				if (t != s)
					printf(" a%d=0x%llx", t, (unsigned long long)e.args[t]);
				printf(" %s (base %s)\n", action(r, b2, sizeof b2), action(base, b1, sizeof b1));
			}
			free(resolved);
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (argc == 4 && strcmp(argv[1], "dump") == 0)
		return dump(atoi(argv[2]), argv[3]);
	if (argc >= 3 && strcmp(argv[1], "eval") == 0)
		return eval(argc - 2, argv + 2);
	fputs("usage: bpfdump dump PID PREFIX | eval [-k F.bpf]... F.bpf...\n", stderr);
	return 2;
}
