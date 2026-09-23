/* P5's C half: a program built as the launcher is (launcher/default.nix:31-47's
 * cflags, the cc-wrapper's hardening), forking as fl_fork does
 * (flong-util.c:390-402, 467-482) and calling the Zig library's one symbol
 * in the child, as flong-launch.c:553 will call flong_mount_main.
 *
 *   p5-hybrid ok      the child adopts three descriptors, prints one line
 *                     and exits 0
 *   p5-hybrid panic   the child panics after adopting them and exits 125
 *                     with one line on stderr
 *
 * The parent checks the child's status against the mode and that its own
 * heap, a malloc'd canary written before the fork, is intact after it; it
 * exits 0 only if both hold. P5_TRACE set passes tracing = 1.
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/pidfd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/sched.h>

struct p5_job {
	int userns;
	int pipe_r;
	int pidfd;
	int closed;
	int mode;
};

_Noreturn void proof_main(const struct p5_job *job, int tracing);

#define CANARY_LEN (1u << 20)

static int die(const char *what)
{
	fprintf(stderr, "p5: %s: %s\n", what, strerror(errno));
	return 1;
}

/* flong-util.c:145-165, unchanged. */
static int next_kept(int low, const int *keep, size_t nkeep)
{
	int best = -1;
	for (size_t i = 0; i < nkeep; i++)
		if (keep[i] >= low && (best < 0 || keep[i] < best))
			best = keep[i];
	return best;
}

static int close_from(int low, const int *keep, size_t nkeep)
{
	for (;;) {
		int kept = next_kept(low, keep, nkeep);
		unsigned int last = kept < 0 ? ~0U : (unsigned int)kept - 1;
		if (kept != low && close_range((unsigned int)low, last, 0) < 0)
			return -1;
		if (kept < 0)
			return 0;
		low = kept + 1;
	}
}

/* flong-util.c:390-402 with cgroup -1, then fl_fork's child half. */
static pid_t fork_like_fl(const int *keep, size_t nkeep, int *pidfd)
{
	struct clone_args ca = {
		.flags = CLONE_PIDFD,
		.pidfd = (unsigned long long)(unsigned long)pidfd,
		.exit_signal = SIGCHLD,
	};
	*pidfd = -1;
	pid_t p = (pid_t)syscall(SYS_clone3, &ca, sizeof ca);
	if (p == 0 && close_from(3, keep, nkeep) < 0)
		_exit(125);
	return p;
}

static unsigned char canary_byte(size_t i)
{
	return (unsigned char)((i * 131u) ^ 0x5a);
}

int main(int argc, char **argv)
{
	int mode;
	if (argc == 2 && strcmp(argv[1], "ok") == 0)
		mode = 0;
	else if (argc == 2 && strcmp(argv[1], "panic") == 0)
		mode = 1;
	else {
		fprintf(stderr, "usage: p5-hybrid ok|panic\n");
		return 2;
	}
	int want = mode == 0 ? 0 : 125;

	/* The parent's heap: a canary, and a copy of it by memcpy and a clear
	 * by memset, so the C takes both from glibc. */
	unsigned char *canary = malloc(CANARY_LEN);
	unsigned char *copy = malloc(CANARY_LEN);
	if (!canary || !copy)
		return die("malloc");
	for (size_t i = 0; i < CANARY_LEN; i++)
		canary[i] = canary_byte(i);
	size_t len = CANARY_LEN - (size_t)argc;
	memcpy(copy, canary, len);
	memset(copy + len, 0, CANARY_LEN - len);

	char word[16];
	snprintf(word, sizeof word, "%s", "zigflong");

	struct p5_job job = { .mode = mode };
	int p[2];
	job.userns = open("/proc/self/ns/user", O_RDONLY | O_CLOEXEC);
	if (job.userns < 0)
		return die("open /proc/self/ns/user");
	if (pipe2(p, O_CLOEXEC) < 0)
		return die("pipe2");
	job.pipe_r = p[0];
	job.pidfd = pidfd_open(getpid(), 0);
	if (job.pidfd < 0)
		return die("pidfd_open");
	job.closed = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (job.closed < 0)
		return die("open /dev/null");

	int keep[3] = { job.userns, job.pipe_r, job.pidfd };
	int tracing = getenv("P5_TRACE") != NULL;
	fflush(NULL);
	int child;
	pid_t pid = fork_like_fl(keep, 3, &child);
	if (pid < 0)
		return die("clone3");
	if (pid == 0)
		proof_main(&job, tracing);

	close(p[0]);
	size_t wlen = strlen(word);
	if (write(p[1], word, wlen) != (ssize_t)wlen)
		return die("write");
	close(p[1]);

	siginfo_t si = { 0 };
	while (waitid(P_PIDFD, (id_t)child, &si, WEXITED) < 0)
		if (errno != EINTR)
			return die("waitid");
	if (si.si_code != CLD_EXITED) {
		fprintf(stderr, "p5: child killed by signal %d\n", si.si_status);
		return 1;
	}
	if (si.si_status != want) {
		fprintf(stderr, "p5: child exited %d, want %d\n", si.si_status, want);
		return 1;
	}

	for (size_t i = 0; i < CANARY_LEN; i++)
		if (canary[i] != canary_byte(i) || (i < len && copy[i] != canary[i])) {
			fprintf(stderr, "p5: parent heap changed at %zu\n", i);
			return 1;
		}
	/* The allocator still works after the child ran. */
	void *more = malloc(3 * CANARY_LEN);
	if (!more)
		return die("malloc after the child");
	free(more);
	free(copy);
	free(canary);
	printf("p5: parent: child exited %d as wanted, heap intact\n", si.si_status);
	return 0;
}
