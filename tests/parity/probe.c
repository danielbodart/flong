/* syscall-probe: the calls a filter or the session's privileges decide, one line
 * each, the call's name and OK or the errno's name. Run as the payload of
 * each session, so that their outputs compare line for line.
 *
 * The namespace calls run in a child, so that one that succeeds does not
 * change what the probes after it run in.
 */
#include <errno.h>
#include <linux/bpf.h>
#include <linux/io_uring.h>
#include <linux/keyctl.h>
#include <linux/netlink.h>
#include <linux/perf_event.h>
#include <linux/sched.h>
#include <linux/userfaultfd.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static long in_child(int flags)
{
	int pipefd[2], e = 0;
	pid_t c;

	if (pipe(pipefd) != 0)
		return -1;
	c = fork();
	if (c == 0) {
		e = unshare(flags) != 0 ? errno : 0;
		_exit(write(pipefd[1], &e, sizeof e) == sizeof e ? 0 : 1);
	}
	close(pipefd[1]);
	if (read(pipefd[0], &e, sizeof e) != sizeof e)
		e = EIO;
	close(pipefd[0]);
	waitpid(c, NULL, 0);
	if (e != 0) {
		errno = e;
		return -1;
	}
	return 0;
}

static void report(const char *name, long r)
{
	printf("%-28s %s\n", name, r >= 0 ? "OK" : strerrorname_np(errno));
	fflush(stdout);
}

int main(void)
{
	static char page[4096];
	union bpf_attr attr = { 0 };
	struct perf_event_attr pa = { 0 };
	struct io_uring_params up = { 0 };
	struct clone_args ca = { 0 };
	long c3;
	pid_t p;

	attr.map_type = BPF_MAP_TYPE_ARRAY;
	attr.key_size = 4;
	attr.value_size = 4;
	attr.max_entries = 1;
	report("bpf(MAP_CREATE)", syscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof attr));

	pa.size = sizeof pa;
	pa.type = PERF_TYPE_SOFTWARE;
	pa.config = PERF_COUNT_SW_TASK_CLOCK;
	pa.exclude_kernel = 1;
	pa.exclude_hv = 1;
	report("perf_event_open(self,user)", syscall(SYS_perf_event_open, &pa, 0, -1, -1, 0));
	pa.exclude_kernel = 0;
	report("perf_event_open(self,kern)", syscall(SYS_perf_event_open, &pa, 0, -1, -1, 0));

	report("io_uring_setup", syscall(SYS_io_uring_setup, 4, &up));
	report("userfaultfd(0)", syscall(SYS_userfaultfd, 0));
	report("userfaultfd(USER_MODE_ONLY)", syscall(SYS_userfaultfd, UFFD_USER_MODE_ONLY));
	report("keyctl(GET_KEYRING_ID)", syscall(SYS_keyctl, KEYCTL_GET_KEYRING_ID, KEY_SPEC_SESSION_KEYRING, 0));

	p = fork();
	if (p == 0) {
		pause();
		_exit(0);
	}
	report("ptrace(ATTACH child)", ptrace(PTRACE_ATTACH, p, 0, 0));
	kill(p, SIGKILL);
	waitpid(p, NULL, 0);
	report("process_vm_readv(self)", syscall(SYS_process_vm_readv, getpid(), NULL, 0, NULL, 0, 0));

	report("unshare(NEWUSER)", in_child(CLONE_NEWUSER));
	report("unshare(NEWNS)", in_child(CLONE_NEWNS));
	report("unshare(NEWNET)", in_child(CLONE_NEWNET));
	report("unshare(NEWUSER|NEWNS)", in_child(CLONE_NEWUSER | CLONE_NEWNS));
	report("mount(tmpfs)", mount("none", "/tmp", "tmpfs", 0, NULL));
	report("chroot(/)", chroot("/"));

	ca.exit_signal = SIGCHLD;
	c3 = syscall(SYS_clone3, &ca, sizeof ca);
	if (c3 == 0)
		_exit(0);
	if (c3 > 0)
		waitpid(c3, NULL, 0);
	report("clone3(plain)", c3);

	report("socket(NETLINK_AUDIT)", socket(AF_NETLINK, SOCK_RAW, NETLINK_AUDIT));
	report("socket(NETLINK_ROUTE)", socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE));
	report("socket(AF_INET,STREAM)", socket(AF_INET, SOCK_STREAM, 0));
	report("swapoff (not @known-allowed)", syscall(SYS_swapoff, "/nonexistent"));
	report("listns (470, @known)", syscall(470, 0, 0, 0, 0));
	report("rseq_slice_yield (471)", syscall(471));
	report("syscall 500 (unassigned)", syscall(500));
	report("reboot(CAD_OFF)", syscall(SYS_reboot, 0xfee1dead, 672274793, 0, 0));
	report("vhangup", syscall(SYS_vhangup));
	report("open_by_handle_at", syscall(SYS_open_by_handle_at, -1, 0, 0));
	report("mlock", syscall(SYS_mlock, page, sizeof page));
	report("futex_waitv (449)", syscall(449, NULL, 0, 0, NULL, 0));
	report("map_shadow_stack (453)", syscall(453, 0, 0, 0));
	report("setns(-1)", syscall(SYS_setns, -1, 0));
	report("pivot_root", syscall(SYS_pivot_root, "/x", "/y"));
	report("syslog(READ_ALL)", syscall(SYS_syslog, 3, page, 16));
	report("settimeofday(NULL)", syscall(SYS_settimeofday, NULL, NULL));
	report("add_key", syscall(SYS_add_key, "user", "k", "v", 1, -3));
	report("pidfd_open(self)", syscall(SYS_pidfd_open, getpid(), 0));
	report("memfd_secret (447)", syscall(447, 0));
	report("landlock_create_ruleset", syscall(444, NULL, 0, 1));
	report("fanotify_init", syscall(SYS_fanotify_init, 0, 0));
	/* AF_NETLINK and NETLINK_AUDIT with bit 32 set, which the kernel drops. */
	report("socket(NETLINK_AUDIT) hi", syscall(SYS_socket, 16 | (1UL << 32), SOCK_RAW, 9));
	return 0;
}
