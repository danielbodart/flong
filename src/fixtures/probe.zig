//! syscall-probe: the calls a filter or the session's privileges decide,
//! one line each, the call's name and OK or the errno's name. Run as the
//! payload of each session, so that their outputs compare line for line
//! (ZIG.md, "Phase 6"). tests/parity/probe.c, line by line: each call is
//! made as glibc makes it there, number and arguments, and each line is
//! written as it is printed, stdout flushed after each (probe.c:52-57).
//! The C was deleted in phase 6 (b), and its line numbers here are those
//! of b82b18c.
//!
//! The namespace calls run in a child, so that one that succeeds does not
//! change what the probes after it run in.
//!
//! Static, no libc. A fork is glibc's clone, flags and all (only the tid
//! pointer's value differs). Descriptors a call opens stay open, as in the
//! C.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const sys = @import("sys");
const errno = @import("errno");
const msg = @import("msg");

pub const std_options: std.Options = .{
    .enable_segfault_handler = false,
    .keep_sigpipe = true,
};

pub const panic = std.debug.FullPanic(msg.onPanic(125));

/// The sizes of the structs as the C was compiled against them (the locked
/// nixpkgs' linux headers, 7.2): the kernel reads `size` bytes and wants
/// what it does not know zero, so the size decides nothing a filter or the
/// kernel answers, but the call stays the C's.
const bpf_attr_size = 168;
const perf_event_attr_size = 144;
const io_uring_params_size = 120;
const clone_args_size = 88;

/// A call's raw return: the value, or -errno.
const Ret = usize;

fn report(name: []const u8, r: Ret) void {
    // printf("%-28s %s\n"): a name of 28 bytes or more is not cut.
    var line: [128]u8 = undefined;
    const e = linux.E.init(r);
    const what: []const u8 = if (e == .SUCCESS)
        "OK"
    else
        // strerrorname_np's NULL, which glibc's printf prints so.
        errno.name(e) orelse "(null)";
    const text = std.fmt.bufPrint(&line, "{s:<28} {s}\n", .{ name, what }) catch unreachable; // proven: the longest name is 28 bytes
    var rest = text;
    while (rest.len > 0) {
        switch (sys.write(1, rest)) {
            .ok => |n| rest = rest[n..],
            .err => return,
        }
    }
}

/// The tid glibc's fork has the kernel write in the child and clear when it
/// exits (the child's copy; the parent's is never touched).
var child_tid: i32 = 0;

/// fork(): the child's 0, the child's pid, or -errno. glibc's arch_fork:
/// clone(CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD, 0, NULL,
/// &tid, 0), the tid pointer fifth where the arch puts tls fourth.
fn forkChild() Ret {
    const flags = linux.CLONE.CHILD_SETTID | linux.CLONE.CHILD_CLEARTID | linux.SIG.CHLD;
    const tid = @intFromPtr(&child_tid);
    return switch (builtin.cpu.arch) {
        .x86_64 => linux.syscall5(.clone, flags, 0, 0, tid, 0),
        else => linux.syscall5(.clone, flags, 0, 0, 0, tid),
    };
}

fn waitpid(pid: Ret) void {
    var status: u32 = 0;
    _ = linux.syscall4(.wait4, pid, @intFromPtr(&status), 0, 0);
}

/// probe.c:27-50: unshare(flags) in a child, its errno back through a pipe.
fn inChild(flags: usize) Ret {
    var pipefd: [2]i32 = undefined;
    const piped = linux.pipe(&pipefd);
    if (linux.E.init(piped) != .SUCCESS) return piped;
    const c = forkChild();
    if (c == 0) {
        const e: i32 = @intFromEnum(linux.E.init(linux.unshare(flags)));
        const wrote = linux.write(pipefd[1], std.mem.asBytes(&e), @sizeOf(i32));
        sys.exitGroup(if (wrote == @sizeOf(i32)) 0 else 1);
    }
    _ = linux.close(pipefd[1]);
    var e: i32 = 0;
    if (linux.read(pipefd[0], std.mem.asBytes(&e), @sizeOf(i32)) != @sizeOf(i32)) e = @intFromEnum(linux.E.IO);
    _ = linux.close(pipefd[0]);
    // A failed fork's -1 makes it waitpid(-1): any child.
    waitpid(if (linux.E.init(c) == .SUCCESS) c else s(-1));
    if (e != 0) return errRet(@enumFromInt(e));
    return 0;
}

fn errRet(e: linux.E) Ret {
    return @bitCast(-@as(isize, @intFromEnum(e)));
}

fn s(x: isize) usize {
    return @bitCast(x);
}

/// A negative int the C passes through syscall(2)'s varargs: its compiler
/// loads it with a 32-bit move, which zeroes the register's upper half, so
/// the kernel and the filters see -1 as 0xffffffff (probe.c:78, 80, 85,
/// 121, 125, 129; the calls themselves take an int and drop the upper half).
fn int(x: i32) usize {
    return @as(u32, @bitCast(x));
}

pub fn main() noreturn {
    msg.prog = "syscall-probe";
    msg.mode = .whole;
    const S = linux.SYS;
    const Static = struct {
        var page: [4096]u8 = [_]u8{0} ** 4096;
    };

    // union bpf_attr: map_type, key_size, value_size, max_entries.
    var attr = [_]u8{0} ** bpf_attr_size;
    std.mem.writeInt(u32, attr[0..4], 2, .little); // BPF_MAP_TYPE_ARRAY
    std.mem.writeInt(u32, attr[4..8], 4, .little);
    std.mem.writeInt(u32, attr[8..12], 4, .little);
    std.mem.writeInt(u32, attr[12..16], 1, .little);
    report("bpf(MAP_CREATE)", linux.syscall3(.bpf, 0, @intFromPtr(&attr), attr.len));

    // struct perf_event_attr: type, size, config, and the flag bits at 40
    // (exclude_kernel bit 5, exclude_hv bit 6).
    var pa = [_]u8{0} ** perf_event_attr_size;
    std.mem.writeInt(u32, pa[0..4], 1, .little); // PERF_TYPE_SOFTWARE
    std.mem.writeInt(u32, pa[4..8], perf_event_attr_size, .little);
    std.mem.writeInt(u64, pa[8..16], 1, .little); // PERF_COUNT_SW_TASK_CLOCK
    std.mem.writeInt(u64, pa[40..48], 0x20 | 0x40, .little);
    report("perf_event_open(self,user)", linux.syscall5(.perf_event_open, @intFromPtr(&pa), 0, int(-1), int(-1), 0));
    std.mem.writeInt(u64, pa[40..48], 0x40, .little);
    report("perf_event_open(self,kern)", linux.syscall5(.perf_event_open, @intFromPtr(&pa), 0, int(-1), int(-1), 0));

    var up = [_]u8{0} ** io_uring_params_size;
    report("io_uring_setup", linux.syscall2(.io_uring_setup, 4, @intFromPtr(&up)));
    report("userfaultfd(0)", linux.syscall1(.userfaultfd, 0));
    report("userfaultfd(USER_MODE_ONLY)", linux.syscall1(.userfaultfd, 1));
    // KEYCTL_GET_KEYRING_ID, KEY_SPEC_SESSION_KEYRING.
    report("keyctl(GET_KEYRING_ID)", linux.syscall3(.keyctl, 0, int(-3), 0));

    const p = forkChild();
    if (p == 0) {
        // pause(), which glibc makes ppoll where there is no pause.
        if (@hasField(S, "pause")) {
            _ = linux.syscall0(.pause);
        } else {
            _ = linux.syscall4(.ppoll, 0, 0, 0, 0);
        }
        sys.exitGroup(0);
    }
    report("ptrace(ATTACH child)", linux.syscall4(.ptrace, 16, p, 0, 0)); // PTRACE_ATTACH
    _ = linux.syscall2(.kill, p, linux.SIG.KILL);
    waitpid(p);
    report("process_vm_readv(self)", linux.syscall6(.process_vm_readv, @intCast(linux.getpid()), 0, 0, 0, 0, 0));

    report("unshare(NEWUSER)", inChild(linux.CLONE.NEWUSER));
    report("unshare(NEWNS)", inChild(linux.CLONE.NEWNS));
    report("unshare(NEWNET)", inChild(linux.CLONE.NEWNET));
    report("unshare(NEWUSER|NEWNS)", inChild(linux.CLONE.NEWUSER | linux.CLONE.NEWNS));
    report("mount(tmpfs)", linux.syscall5(.mount, @intFromPtr("none"), @intFromPtr("/tmp"), @intFromPtr("tmpfs"), 0, 0));
    report("chroot(/)", linux.syscall1(.chroot, @intFromPtr("/")));

    // struct clone_args, exit_signal at 32.
    var ca: [clone_args_size]u8 align(8) = [_]u8{0} ** clone_args_size;
    std.mem.writeInt(u64, ca[32..40], linux.SIG.CHLD, .little);
    const c3 = linux.syscall2(.clone3, @intFromPtr(&ca), ca.len);
    if (c3 == 0) sys.exitGroup(0);
    if (linux.E.init(c3) == .SUCCESS) waitpid(c3);
    report("clone3(plain)", c3);

    // AF_NETLINK 16, SOCK_RAW 3, NETLINK_AUDIT 9, NETLINK_ROUTE 0; AF_INET
    // 2, SOCK_STREAM 1.
    report("socket(NETLINK_AUDIT)", linux.syscall3(.socket, 16, 3, 9));
    report("socket(NETLINK_ROUTE)", linux.syscall3(.socket, 16, 3, 0));
    report("socket(AF_INET,STREAM)", linux.syscall3(.socket, 2, 1, 0));
    report("swapoff (not @known-allowed)", linux.syscall1(.swapoff, @intFromPtr("/nonexistent")));
    report("listns (470, @known)", raw(470, .{ 0, 0, 0, 0 }));
    report("rseq_slice_yield (471)", raw(471, .{}));
    report("syscall 500 (unassigned)", raw(500, .{}));
    report("reboot(CAD_OFF)", linux.syscall4(.reboot, 0xfee1dead, 672274793, 0, 0));
    report("vhangup", linux.syscall0(.vhangup));
    report("open_by_handle_at", linux.syscall3(.open_by_handle_at, int(-1), 0, 0));
    report("mlock", linux.syscall2(.mlock, @intFromPtr(&Static.page), Static.page.len));
    report("futex_waitv (449)", raw(449, .{ 0, 0, 0, 0, 0 }));
    report("map_shadow_stack (453)", raw(453, .{ 0, 0, 0 }));
    report("setns(-1)", linux.syscall2(.setns, int(-1), 0));
    report("pivot_root", linux.syscall2(.pivot_root, @intFromPtr("/x"), @intFromPtr("/y")));
    report("syslog(READ_ALL)", linux.syscall3(.syslog, 3, @intFromPtr(&Static.page), 16));
    report("settimeofday(NULL)", linux.syscall2(.settimeofday, 0, 0));
    report("add_key", linux.syscall5(.add_key, @intFromPtr("user"), @intFromPtr("k"), @intFromPtr("v"), 1, int(-3)));
    report("pidfd_open(self)", linux.syscall2(.pidfd_open, @intCast(linux.getpid()), 0));
    report("memfd_secret (447)", raw(447, .{0}));
    report("landlock_create_ruleset", raw(444, .{ 0, 0, 1 }));
    report("fanotify_init", linux.syscall2(.fanotify_init, 0, 0));
    // AF_NETLINK and NETLINK_AUDIT with bit 32 set, which the kernel drops.
    report("socket(NETLINK_AUDIT) hi", linux.syscall3(.socket, 16 | (1 << 32), 3, 9));
    sys.exitGroup(0);
}

/// syscall(nr, args...) by number, for the calls std.os.linux's
/// syscall enum does not name (470, 471, 500): the arguments not given are
/// 0, where glibc's syscall passes whatever its registers held, which the
/// kernel ignores.
fn raw(nr: usize, args: anytype) Ret {
    var a = [_]usize{0} ** 6;
    inline for (args, 0..) |x, i| a[i] = x;
    return switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("syscall"
            : [ret] "={rax}" (-> usize),
            : [number] "{rax}" (nr),
              [arg1] "{rdi}" (a[0]),
              [arg2] "{rsi}" (a[1]),
              [arg3] "{rdx}" (a[2]),
              [arg4] "{r10}" (a[3]),
              [arg5] "{r8}" (a[4]),
              [arg6] "{r9}" (a[5]),
            : .{ .rcx = true, .r11 = true, .memory = true }),
        .aarch64 => asm volatile ("svc #0"
            : [ret] "={x0}" (-> usize),
            : [number] "{x8}" (nr),
              [arg1] "{x0}" (a[0]),
              [arg2] "{x1}" (a[1]),
              [arg3] "{x2}" (a[2]),
              [arg4] "{x3}" (a[3]),
              [arg5] "{x4}" (a[4]),
              [arg6] "{x5}" (a[5]),
            : .{ .memory = true }),
        else => @compileError("syscall-probe: x86_64 and aarch64 only"),
    };
}

comptime {
    // Numbers the C names by the x86_64 table (probe.c:120-135).
    if (builtin.cpu.arch == .x86_64) std.debug.assert(@intFromEnum(linux.SYS.process_vm_readv) == 310);
}
