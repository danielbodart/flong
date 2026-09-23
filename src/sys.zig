//! sys.zig: the syscall layer. Every raw call flong makes goes through here,
//! on std.os.linux alone (ZIG.md, "The syscall layer").
//!
//! Not std.posix: it turns errnos a caller must see into `unreachable`
//! (posix.zig:5478-5481, 6949 and others), which in ReleaseSafe is a panic
//! and in a caller's hands a lost refusal. Here every wrapper returns a
//! `Result(T)`, the value or the kernel's errno, and the caller decides.
//! EINTR is retried where the C retries it; every read and write in the C
//! does (flong-util.c:42, 175, 196; flong-record.c:158, 783).
//!
//! This file imports none of flong's modules. It grows only as far as the
//! program being ported needs it: phase 1 needs reads and writes of 0-2,
//! argv, and the exit; phase 2 the opens and closes of fd.zig, the calls on
//! a directory (mkdirat, unlinkat, renameat, fstatat, fchmodat,
//! getdents64), pread, pwrite, fstat, flock, and getrandom for the project
//! tool's temp names; phase 3 what flong-init calls (setgroups, prctl,
//! capset, the TIOCSCTTY ioctl, rt_sigaction, rt_sigprocmask, chdir,
//! close_range, execve), each as glibc makes it (flong-init.c:195-238).

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

/// The kernel's errno. Non-exhaustive: a number the enum does not name is
/// still a value (errno.zig describes it as glibc does).
pub const E = linux.E;

/// What a wrapper returns: the value, or the errno the kernel gave.
pub fn Result(comptime T: type) type {
    return union(enum) { ok: T, err: E };
}

pub const fd_t = linux.fd_t;
pub const timespec = linux.timespec;
pub const mode_t = linux.mode_t;
/// open(2)'s flags, std's packed struct of them.
pub const O = linux.O;
pub const AT = linux.AT;
pub const Stat = linux.Stat;
pub const S = linux.S;
/// flock(2)'s operations (asm-generic/fcntl.h; std.os.linux has none, and
/// std.posix's is banned).
pub const LOCK = struct {
    pub const SH: i32 = 1;
    pub const EX: i32 = 2;
    pub const NB: i32 = 4;
    pub const UN: i32 = 8;
};
/// struct linux_dirent64, as getdents64 fills a buffer with them.
pub const Dirent64 = linux.dirent64;

/// PATH_MAX, the kernel's bound on a path it will take.
pub const path_max = linux.PATH_MAX;

/// One piece of a writev: struct iovec, as the kernel reads it.
pub const Iovec = extern struct {
    base: [*]const u8,
    len: usize,
};

comptime {
    std.debug.assert(@sizeOf(Iovec) == 2 * @sizeOf(usize));
    std.debug.assert(@offsetOf(Iovec, "len") == @sizeOf(usize));
}

/// The kernel's argv. The lint allows it in the roots and proc.zig only, so
/// nothing deeper reads the command line behind its caller's back.
pub fn argv() []const [*:0]const u8 {
    const a = std.os.argv;
    return @ptrCast(a);
}

/// The environment the process started with (the lint confines it as argv).
pub fn environ() []const [*:0]const u8 {
    const e = std.os.environ;
    return @ptrCast(e);
}

/// Ends the process, every thread of it. A normal return from a
/// single-threaded `main` ends in `exit`, not `exit_group` (ZIG.md,
/// "Measured"), so every root ends here instead.
pub fn exitGroup(status: u8) noreturn {
    linux.exit_group(status);
}

/// The kernel's argv as the process may rewrite it: the pointer slots are
/// the kernel's own, null-terminated past the last (argv[argc] == NULL), so
/// a tail of it is an exec argv as it stands (flong-init.c:222-237). The
/// strings are not written. Confined to the roots as `argv` is.
pub fn argvSlots() [][*:0]const u8 {
    const a = std.os.argv;
    return @ptrCast(a);
}

fn result(comptime T: type, rc: usize) Result(T) {
    return switch (E.init(rc)) {
        .SUCCESS => .{ .ok = if (T == void) {} else @intCast(rc) },
        else => |e| .{ .err = e },
    };
}

/// read(2), EINTR retried. 0 is the end of the file.
pub fn read(fd: fd_t, buf: []u8) Result(usize) {
    while (true) {
        const r = result(usize, linux.read(fd, buf.ptr, buf.len));
        if (r == .err and r.err == .INTR) continue;
        return r;
    }
}

/// write(2), EINTR retried. It may write less than all of `bytes`.
pub fn write(fd: fd_t, bytes: []const u8) Result(usize) {
    while (true) {
        const r = result(usize, linux.write(fd, bytes.ptr, bytes.len));
        if (r == .err and r.err == .INTR) continue;
        return r;
    }
}

/// writev(2), EINTR retried. It may write less than all of `iov`.
pub fn writev(fd: fd_t, iov: []const Iovec) Result(usize) {
    while (true) {
        const r = result(usize, linux.syscall3(.writev, @bitCast(@as(isize, fd)), @intFromPtr(iov.ptr), iov.len));
        if (r == .err and r.err == .INTR) continue;
        return r;
    }
}

/// openat(2). fd.zig is its only caller, and adds O_CLOEXEC to every open.
/// EINTR is retried: an open of a FIFO can be interrupted.
pub fn openat(dir: fd_t, path: [*:0]const u8, flags: O, mode: mode_t) Result(fd_t) {
    while (true) {
        const r = result(fd_t, linux.openat(dir, path, flags, mode));
        if (r == .err and r.err == .INTR) continue;
        return r;
    }
}

/// close(2). The descriptor is gone whatever it returns, EINTR included
/// (close(2), "Dealing with error returns"), so it is never retried and
/// its errno is dropped, as fl_close drops it (flong-util.c:134-141).
pub fn close(fd: fd_t) void {
    _ = linux.close(fd);
}

pub fn mkdirat(dir: fd_t, path: [*:0]const u8, mode: mode_t) Result(void) {
    return result(void, linux.mkdirat(dir, path, mode));
}

/// unlinkat(2); `flags` is 0 or AT.REMOVEDIR.
pub fn unlinkat(dir: fd_t, path: [*:0]const u8, flags: u32) Result(void) {
    return result(void, linux.unlinkat(dir, path, flags));
}

/// renameat(2), or renameat2 with no flags where there is no renameat
/// (aarch64).
pub fn renameat(old_dir: fd_t, old: [*:0]const u8, new_dir: fd_t, new: [*:0]const u8) Result(void) {
    return result(void, linux.renameat(old_dir, old, new_dir, new));
}

/// fstatat(2); `flags` takes AT.SYMLINK_NOFOLLOW and AT.EMPTY_PATH.
pub fn fstatat(dir: fd_t, path: [*:0]const u8, flags: u32) Result(Stat) {
    var st: Stat = undefined;
    return switch (result(void, linux.fstatat(dir, path, &st, flags))) {
        .ok => .{ .ok = st },
        .err => |e| .{ .err = e },
    };
}

pub fn fstat(fd: fd_t) Result(Stat) {
    var st: Stat = undefined;
    return switch (result(void, linux.fstat(fd, &st))) {
        .ok => .{ .ok = st },
        .err => |e| .{ .err = e },
    };
}

/// fchmodat(2), which follows a final symlink (the kernel takes no flags).
pub fn fchmodat(dir: fd_t, path: [*:0]const u8, mode: mode_t) Result(void) {
    return result(void, linux.fchmodat(dir, path, mode, 0));
}

/// getdents64(2) into `buf`, which must be aligned for Dirent64. 0 is the
/// end of the directory.
pub fn getdents64(fd: fd_t, buf: []align(8) u8) Result(usize) {
    return result(usize, linux.getdents64(fd, buf.ptr, buf.len));
}

/// pread(2), EINTR retried.
pub fn pread(fd: fd_t, buf: []u8, offset: u64) Result(usize) {
    while (true) {
        const r = result(usize, linux.pread(fd, buf.ptr, buf.len, @bitCast(offset)));
        if (r == .err and r.err == .INTR) continue;
        return r;
    }
}

/// pwrite(2), EINTR retried.
pub fn pwrite(fd: fd_t, bytes: []const u8, offset: u64) Result(usize) {
    while (true) {
        const r = result(usize, linux.pwrite(fd, bytes.ptr, bytes.len, @bitCast(offset)));
        if (r == .err and r.err == .INTR) continue;
        return r;
    }
}

/// flock(2), EINTR retried, as fl_lock_wait retries it
/// (flong-util.c:484-513).
pub fn flock(fd: fd_t, op: i32) Result(void) {
    while (true) {
        const r = result(void, linux.flock(fd, op));
        if (r == .err and r.err == .INTR) continue;
        return r;
    }
}

/// getrandom(2) from the urandom pool: fills all of `buf`, which is at most
/// 256 bytes, so one call does unless a signal interrupts it (getrandom(2),
/// "Interruption by a signal handler"), when it is retried.
pub fn getrandom(buf: []u8) Result(void) {
    std.debug.assert(buf.len <= 256);
    while (true) {
        switch (result(usize, linux.getrandom(buf.ptr, buf.len, 0))) {
            .ok => |n| if (n == buf.len) return .{ .ok = {} },
            .err => |e| if (e != .INTR) return .{ .err = e },
        }
    }
}

/// CLOCK_REALTIME, as fl_trace stamps a stage (flong-util.c:127). It cannot
/// fail with a valid clock and pointer; the vDSO answers when there is one.
pub fn clockRealtime() timespec {
    var t: timespec = undefined;
    _ = linux.clock_gettime(.REALTIME, &t);
    return t;
}

// ---- flong-init (flong-init.c:195-238) ----

/// NGROUPS_MAX (linux/limits.h): the most supplementary groups setgroups
/// takes.
pub const ngroups_max = 65536;

/// setgroups(2), the 32-bit gid call on both arches. `list` null is the C's
/// setgroups(0, NULL) (flong-init.c:116-117, 195); strace shows the pointer.
pub fn setgroups(list: ?[]const u32) Result(void) {
    const n = if (list) |l| l.len else 0;
    const ptr = if (list) |l| @intFromPtr(l.ptr) else 0;
    return result(void, linux.syscall2(.setgroups, n, ptr));
}

/// prctl(2)'s options flong-init uses (linux/prctl.h).
pub const PR = struct {
    pub const CAPBSET_READ = 23;
    pub const CAPBSET_DROP = 24;
    pub const CAP_AMBIENT = 47;
    pub const CAP_AMBIENT_CLEAR_ALL = 4;
};

/// prctl(2) with glibc's five arguments, the unused ones 0. The value is
/// the call's (PR_CAPBSET_READ answers 0 or 1).
pub fn prctl(option: u32, arg2: usize) Result(usize) {
    return result(usize, linux.syscall5(.prctl, option, arg2, 0, 0, 0));
}

/// struct __user_cap_header_struct (linux/capability.h). Not std's
/// cap_user_header_t, whose pid is a usize where the kernel has an int.
pub const CapHeader = extern struct {
    version: u32,
    pid: i32,
};

/// struct __user_cap_data_struct (linux/capability.h).
pub const CapData = extern struct {
    effective: u32,
    permitted: u32,
    inheritable: u32,
};

/// _LINUX_CAPABILITY_VERSION_3, and its _LINUX_CAPABILITY_U32S_3 data
/// structs.
pub const cap_version_3 = 0x20080522;
pub const cap_u32s_3 = 2;

comptime {
    std.debug.assert(@sizeOf(CapHeader) == 8);
    std.debug.assert(@sizeOf(CapData) == 12);
}

/// capset(2) of the calling thread (pid 0): every set to `data`.
pub fn capset(data: *const [cap_u32s_3]CapData) Result(void) {
    var header: CapHeader = .{ .version = cap_version_3, .pid = 0 };
    return result(void, linux.syscall2(.capset, @intFromPtr(&header), @intFromPtr(data)));
}

/// TIOCSCTTY (asm-generic/ioctls.h, x86_64's and aarch64's).
pub const TIOCSCTTY = 0x540E;

/// ioctl(2) with an integer argument.
pub fn ioctl(fd: fd_t, request: u32, arg: usize) Result(void) {
    return result(void, linux.syscall3(.ioctl, @bitCast(@as(isize, fd)), request, arg));
}

/// The kernel's struct sigaction for rt_sigaction (asm-generic/signal.h's
/// order, x86_64's and aarch64's): the handler, flags, the restorer, then a
/// 64-bit mask.
pub const KSigaction = extern struct {
    handler: usize,
    flags: c_ulong,
    restorer: usize,
    mask: u64,
};

pub const SIG = struct {
    pub const DFL = 0;
    pub const INT = 2;
    pub const QUIT = 3;
    pub const SETMASK = 2;
};

/// SA_RESTORER, which glibc sets on x86_64 with its __restore_rt, the
/// kernel needing it there to return from a handler; glibc's aarch64 sets
/// none, the kernel using the vDSO's (glibc sysdeps/unix/sysv/linux/
/// x86_64/libc_sigaction.c, SET_SA_RESTORER).
pub const sa_restorer = 0x04000000;

/// rt_sigaction(2) resetting `sig` to SIG_DFL with an empty mask and no
/// old action, as glibc's sigaction makes the call (flong-init.c:169-172):
/// on x86_64 with SA_RESTORER and std's restore_rt, which a default
/// disposition never calls, so the call is the C's argument for argument.
/// Not std's sigaction, which asserts on SIGKILL and SIGSTOP
/// (linux.zig:1857-1861).
pub fn sigDefault(sig: u6) Result(void) {
    const x86 = builtin.cpu.arch == .x86_64;
    const act: KSigaction = .{
        .handler = SIG.DFL,
        .flags = if (x86) sa_restorer else 0,
        .restorer = if (x86) @intFromPtr(&linux.restore_rt) else 0,
        .mask = 0,
    };
    return result(void, linux.syscall4(.rt_sigaction, sig, @intFromPtr(&act), 0, @sizeOf(u64)));
}

/// rt_sigprocmask(SIG_SETMASK, {}, NULL): an empty signal mask.
pub fn emptyMask() Result(void) {
    const none: u64 = 0;
    return result(void, linux.syscall4(.rt_sigprocmask, SIG.SETMASK, @intFromPtr(&none), 0, @sizeOf(u64)));
}

/// close(2) whose errno the caller reads, as flong-init.c:208 does. Not
/// retried: the descriptor is gone whatever it returns.
pub fn closeChecked(fd: fd_t) Result(void) {
    return result(void, linux.close(fd));
}

pub fn chdir(path: [*:0]const u8) Result(void) {
    return result(void, linux.chdir(path));
}

/// close_range(2); `last` ~0 is every descriptor from `first` on.
pub fn closeRange(first: u32, last: u32, flags: u32) Result(void) {
    return result(void, linux.syscall3(.close_range, first, last, flags));
}

/// execve(2). It returns only on failure, with the errno.
pub fn execve(path: [*:0]const u8, argv_: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8) E {
    return E.init(linux.execve(path, argv_, envp));
}

test "read and write carry the errno" {
    const r = read(-1, &.{});
    try std.testing.expectEqual(Result(usize){ .err = .BADF }, r);
    const w = write(-1, "x");
    try std.testing.expectEqual(Result(usize){ .err = .BADF }, w);
    const v = writev(-1, &.{.{ .base = "x", .len = 1 }});
    try std.testing.expectEqual(Result(usize){ .err = .BADF }, v);
}

test "an empty write succeeds and writes nothing" {
    try std.testing.expectEqual(Result(usize){ .ok = 0 }, write(2, ""));
    try std.testing.expectEqual(Result(usize){ .ok = 0 }, writev(2, &.{}));
}

test "the directory calls carry the errno" {
    try std.testing.expectEqual(Result(fd_t){ .err = .NOENT }, openat(AT.FDCWD, "/nonexistent/x", .{}, 0));
    try std.testing.expectEqual(Result(void){ .err = .NOENT }, mkdirat(AT.FDCWD, "/nonexistent/x", 0o700));
    try std.testing.expectEqual(Result(void){ .err = .NOENT }, unlinkat(AT.FDCWD, "/nonexistent/x", 0));
    try std.testing.expectEqual(Result(void){ .err = .NOENT }, renameat(AT.FDCWD, "/nonexistent/x", AT.FDCWD, "/nonexistent/y"));
    try std.testing.expect(fstatat(AT.FDCWD, "/nonexistent/x", 0) == .err);
    try std.testing.expect(fstatat(AT.FDCWD, "/", 0) == .ok);
    try std.testing.expectEqual(Result(void){ .err = .BADF }, flock(-1, LOCK.SH));
}

test "getrandom fills the buffer" {
    var a: [32]u8 = @splat(0);
    var b: [32]u8 = @splat(0);
    try std.testing.expectEqual(Result(void){ .ok = {} }, getrandom(&a));
    try std.testing.expectEqual(Result(void){ .ok = {} }, getrandom(&b));
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}

test "argv is the process's" {
    try std.testing.expect(argv().len >= 1);
}
