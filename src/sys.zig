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
//! close_range, execve), each as glibc makes it (flong-init.c:195-238);
//! phase 4 the mount helper's (flong-mount.c): openat2, the mount API,
//! statx's unique mount id and statmount, setns and unshare, the fs and res
//! ids, fchownat, umask, readlinkat, umount2 and the pidfd namespace ioctls;
//! phase 5 the process layer's (flong-util.c:244-513): clone3, waitid on a
//! pidfd, pidfd_open and pidfd_send_signal, poll, pipe2, the signal mask,
//! signalfd4 and dispositions, fcntl and dup2 for Spawn's child, inotify,
//! the real and effective uid, and faccessat for postStop's X_OK; phase 7
//! the launch's records (flong-record.c:343-356): O_TMPFILE and linkat;
//! phase 7's L3 the terminal's (flong-tty.c): the termios, window size and
//! foreground ioctls, the pty's unlock and number, cfmakeraw, SIGTTOU's
//! disposition, getpgrp, kill and the monotonic clock.

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
/// In a library (the mount helper's, linked into the C launcher) it is the
/// syscall: std's vDSO lookup would ask getauxval, which a library leaves
/// to its host's libc (std/os/linux.zig:515-525), one more name the C link
/// would have to resolve (ZIG.md, "The mount-helper shim").
pub fn clockRealtime() timespec {
    var t: timespec = undefined;
    if (builtin.output_mode == .Lib) {
        _ = linux.syscall2(.clock_gettime, @intFromEnum(linux.CLOCK.REALTIME), @intFromPtr(&t));
    } else {
        _ = linux.clock_gettime(.REALTIME, &t);
    }
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
pub fn sigDefault(sig: u7) Result(void) {
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

// ---- the mount helper (flong-mount.c) ----

/// openat2's `how` (linux/openat2.h), OPEN_HOW_SIZE_VER0.
pub const OpenHow = extern struct {
    flags: u64,
    mode: u64,
    resolve: u64,
};

/// openat2's resolve flags (linux/openat2.h).
pub const RESOLVE = struct {
    pub const NO_XDEV: u64 = 0x01;
    pub const NO_MAGICLINKS: u64 = 0x02;
    pub const NO_SYMLINKS: u64 = 0x04;
    pub const BENEATH: u64 = 0x08;
    pub const IN_ROOT: u64 = 0x10;
};

/// openat2(2), as flong-mount.c:49-53 makes it: `how` passed whole, its
/// size the struct's. Not retried: the C does not, and no open here is of
/// a FIFO. fd.zig is its only caller, and adds O_CLOEXEC.
pub fn openat2(dir: fd_t, path: [*:0]const u8, how: *const OpenHow) Result(fd_t) {
    return result(fd_t, linux.syscall4(.openat2, @bitCast(@as(isize, dir)), @intFromPtr(path), @intFromPtr(how), @sizeOf(OpenHow)));
}

/// mount_setattr's attributes (linux/mount.h, `struct mount_attr`),
/// MOUNT_ATTR_SIZE_VER0.
pub const MountAttr = extern struct {
    attr_set: u64 = 0,
    attr_clr: u64 = 0,
    propagation: u64 = 0,
    userns_fd: u64 = 0,
};

/// The mount attributes (linux/mount.h), for fsmount's and mount_setattr's
/// flags.
pub const MOUNT_ATTR = struct {
    pub const RDONLY: u32 = 0x01;
    pub const NOSUID: u32 = 0x02;
    pub const NODEV: u32 = 0x04;
    pub const NOEXEC: u32 = 0x08;
};

/// open_tree(2)'s flags (linux/mount.h); OPEN_TREE_CLOEXEC is O_CLOEXEC,
/// the same bit on x86_64 and aarch64.
pub const OPEN_TREE_CLONE: u32 = 1;
pub const OPEN_TREE_CLOEXEC: u32 = 0o2000000;
/// AT_RECURSIVE (linux/fcntl.h): the whole tree, submounts included.
pub const AT_RECURSIVE: u32 = 0x8000;

/// move_mount(2)'s flags (linux/mount.h).
pub const MOVE_MOUNT_F_EMPTY_PATH: u32 = 0x04;
pub const MOVE_MOUNT_T_EMPTY_PATH: u32 = 0x40;

/// fsopen(2) and fsmount(2)'s close-on-exec flags (linux/mount.h).
pub const FSOPEN_CLOEXEC: u32 = 0x01;
pub const FSMOUNT_CLOEXEC: u32 = 0x01;

/// fsconfig(2)'s commands (linux/mount.h, `enum fsconfig_command`).
pub const FSCONFIG = struct {
    pub const SET_FLAG: u32 = 0;
    pub const SET_STRING: u32 = 1;
    pub const SET_FD: u32 = 5;
    pub const CMD_CREATE: u32 = 6;
};

/// umount2(2)'s flags (sys/mount.h).
pub const MNT_DETACH: u32 = 2;
pub const UMOUNT_NOFOLLOW: u32 = 8;

pub fn openTree(dir: fd_t, path: [*:0]const u8, flags: u32) Result(fd_t) {
    return result(fd_t, linux.syscall3(.open_tree, @bitCast(@as(isize, dir)), @intFromPtr(path), flags));
}

pub fn moveMount(from_dir: fd_t, from: [*:0]const u8, to_dir: fd_t, to: [*:0]const u8, flags: u32) Result(void) {
    return result(void, linux.syscall5(.move_mount, @bitCast(@as(isize, from_dir)), @intFromPtr(from), @bitCast(@as(isize, to_dir)), @intFromPtr(to), flags));
}

pub fn fsopen(name: [*:0]const u8, flags: u32) Result(fd_t) {
    return result(fd_t, linux.syscall2(.fsopen, @intFromPtr(name), flags));
}

/// fsconfig(2): `key` and `value` null where the command takes none, as
/// the C passes NULL (flong-mount.c:177, 226-230).
pub fn fsconfig(fd: fd_t, cmd: u32, key: ?[*:0]const u8, value: ?[*:0]const u8, aux: i32) Result(void) {
    return result(void, linux.syscall5(.fsconfig, @bitCast(@as(isize, fd)), cmd, @intFromPtr(key), @intFromPtr(value), @bitCast(@as(isize, aux))));
}

pub fn fsmount(fd: fd_t, flags: u32, attrs: u32) Result(fd_t) {
    return result(fd_t, linux.syscall3(.fsmount, @bitCast(@as(isize, fd)), flags, attrs));
}

/// mount_setattr(2), `attr` passed whole, its size the struct's.
pub fn mountSetattr(dir: fd_t, path: [*:0]const u8, flags: u32, attr: *const MountAttr) Result(void) {
    return result(void, linux.syscall5(.mount_setattr, @bitCast(@as(isize, dir)), @intFromPtr(path), flags, @intFromPtr(attr), @sizeOf(MountAttr)));
}

pub fn umount2(path: [*:0]const u8, flags: u32) Result(void) {
    return result(void, linux.umount2(path, flags));
}

/// STATX_MNT_ID_UNIQUE (linux/stat.h): the unique mount id, never reused,
/// kept by a detached tree once attached (flong-mount.c:55-64).
pub const STATX_MNT_ID_UNIQUE: u32 = 0x4000;

/// statx(2) of the file `fd` is on (AT_EMPTY_PATH), for its unique mount
/// id, which std's Statx holds at 0x90 as __pad2[0] (tests/zig/abi.zig).
pub fn mountId(fd: fd_t) Result(u64) {
    var st: linux.Statx = undefined;
    return switch (result(void, linux.statx(fd, "", AT.EMPTY_PATH, STATX_MNT_ID_UNIQUE, &st))) {
        .ok => .{ .ok = st.__pad2[0] },
        .err => |e| .{ .err = e },
    };
}

/// statmount's and listmount's request (linux/mount.h, `struct
/// mnt_id_req`), VER0: the header's fifth field, mnt_ns_id, is VER1 (kernel
/// 6.11), and the kernel reads `size` bytes.
pub const MntIdReq = extern struct {
    size: u32 = mnt_id_req_size_ver0,
    spare: u32 = 0,
    mnt_id: u64,
    param: u64,
};
pub const mnt_id_req_size_ver0 = 24;

/// statmount's mask bits (linux/mount.h).
pub const STATMOUNT_MNT_BASIC: u64 = 0x02;

/// statmount's fixed part (linux/mount.h, `struct statmount`), up to its
/// variable `str[]`: 512 bytes, all a STATMOUNT_MNT_BASIC answer fills.
pub const StatMount = extern struct {
    size: u32,
    mnt_opts: u32,
    mask: u64,
    sb_dev_major: u32,
    sb_dev_minor: u32,
    sb_magic: u64,
    sb_flags: u32,
    fs_type: u32,
    mnt_id: u64,
    mnt_parent_id: u64,
    mnt_id_old: u32,
    mnt_parent_id_old: u32,
    mnt_attr: u64,
    mnt_propagation: u64,
    mnt_peer_group: u64,
    mnt_master: u64,
    propagate_from: u64,
    mnt_root: u32,
    mnt_point: u32,
    mnt_ns_id: u64,
    fs_subtype: u32,
    sb_source: u32,
    opt_num: u32,
    opt_array: u32,
    opt_sec_num: u32,
    opt_sec_array: u32,
    __spare2: [46]u64,
};

/// statmount(2) of `req` into `buf`, its size the struct's
/// (flong-mount.c:257-260).
pub fn statmount(req: *const MntIdReq, buf: *StatMount) Result(void) {
    return result(void, linux.syscall4(.statmount, @intFromPtr(req), @intFromPtr(buf), @sizeOf(StatMount), 0));
}

comptime {
    std.debug.assert(@sizeOf(OpenHow) == 24);
    std.debug.assert(@sizeOf(MountAttr) == 32);
    std.debug.assert(@sizeOf(MntIdReq) == mnt_id_req_size_ver0);
    std.debug.assert(@sizeOf(StatMount) == 512);
    std.debug.assert(@offsetOf(linux.Statx, "__pad2") == 0x90);
}

/// The namespaces setns and unshare name (linux/sched.h).
pub const CLONE = struct {
    pub const NEWNS: u32 = 0x00020000;
    pub const NEWCGROUP: u32 = 0x02000000;
    pub const NEWUSER: u32 = 0x10000000;
    pub const NEWNET: u32 = 0x40000000;
};

/// setns(2); std wraps none (ZIG.md, "Measured": P3).
pub fn setns(fd: fd_t, nstype: u32) Result(void) {
    return result(void, linux.syscall2(.setns, @bitCast(@as(isize, fd)), nstype));
}

pub fn unshare(flags: u32) Result(void) {
    return result(void, linux.unshare(flags));
}

/// setresuid(2) and setresgid(2): the 32-bit id calls, x86_64's and
/// aarch64's only ones, as glibc makes them in a single-threaded process.
pub fn setresuid(r: u32, e: u32, s: u32) Result(void) {
    return result(void, linux.syscall3(.setresuid, r, e, s));
}

pub fn setresgid(r: u32, e: u32, s: u32) Result(void) {
    return result(void, linux.syscall3(.setresgid, r, e, s));
}

/// setfsuid(2) and setfsgid(2): each answers the id before the call, never
/// an error, so a caller reads the new one back with an invalid id (-1),
/// as flong-mount.c:71-78 does. x86_64 and aarch64 have the 32-bit calls
/// under these names; the 16-bit ones' 32-bit successors (setfsuid32) are
/// the 32-bit arches', which flong does not build for.
pub fn setfsuid(uid: u32) u32 {
    return @truncate(linux.syscall1(.setfsuid, uid));
}

pub fn setfsgid(gid: u32) u32 {
    return @truncate(linux.syscall1(.setfsgid, gid));
}

/// fchownat(2); `flags` takes AT.SYMLINK_NOFOLLOW and AT.EMPTY_PATH.
pub fn fchownat(dir: fd_t, path: [*:0]const u8, uid: u32, gid: u32, flags: u32) Result(void) {
    return result(void, linux.syscall5(.fchownat, @bitCast(@as(isize, dir)), @intFromPtr(path), uid, gid, flags));
}

/// umask(2): the old mask; it cannot fail.
pub fn umask(mask: mode_t) mode_t {
    return @truncate(linux.syscall1(.umask, mask));
}

/// readlinkat(2) into `buf`: the length, never NUL-terminated, cut at
/// `buf.len` as the kernel cuts it.
pub fn readlinkat(dir: fd_t, path: [*:0]const u8, buf: []u8) Result(usize) {
    return result(usize, linux.readlinkat(dir, path, buf.ptr, buf.len));
}

/// The pidfd namespace ioctls (linux/pidfd.h, _IO(PIDFS_IOCTL_MAGIC, n)),
/// each answering a new descriptor on the pidfd's process's namespace;
/// only a caller with the process's ptrace access may ask (kernel 6.11).
pub const PIDFD_GET_CGROUP_NAMESPACE: u32 = 0xff01;
pub const PIDFD_GET_MNT_NAMESPACE: u32 = 0xff03;
pub const PIDFD_GET_NET_NAMESPACE: u32 = 0xff04;

/// ioctl(2) with an integer argument, whose value is a new descriptor.
pub fn ioctlFd(fd: fd_t, request: u32, arg: usize) Result(fd_t) {
    return result(fd_t, linux.syscall3(.ioctl, @bitCast(@as(isize, fd)), request, arg));
}

// ---- processes and signals (flong-util.c:244-513) ----

pub const pid_t = linux.pid_t;
pub const uid_t = linux.uid_t;

/// struct clone_args (linux/sched.h), CLONE_ARGS_SIZE_VER2: every field a
/// __aligned_u64, the same on x86_64 and aarch64. The kernel takes the size
/// as clone3's second argument (ZIG.md, "Measured": P3, P4).
pub const CloneArgs = extern struct {
    flags: u64 = 0,
    pidfd: u64 = 0,
    child_tid: u64 = 0,
    parent_tid: u64 = 0,
    exit_signal: u64 = 0,
    stack: u64 = 0,
    stack_size: u64 = 0,
    tls: u64 = 0,
    set_tid: u64 = 0,
    set_tid_size: u64 = 0,
    cgroup: u64 = 0,
};

comptime {
    std.debug.assert(@sizeOf(CloneArgs) == 88);
    std.debug.assert(@offsetOf(CloneArgs, "exit_signal") == 32);
    std.debug.assert(@offsetOf(CloneArgs, "cgroup") == 80);
}

/// clone3's flags (linux/sched.h): the pidfd, and the cgroup the child is
/// created in (flong-util.c:390-402).
pub const CLONE_PIDFD: u64 = linux.CLONE.PIDFD;
pub const CLONE_INTO_CGROUP: u64 = linux.CLONE.INTO_CGROUP;

/// clone3(2) with no stack and no CLONE_VM: a fork, 0 in the child, the
/// pid in the parent. std wraps none (ZIG.md, "Measured": P3).
pub fn clone3(args: *CloneArgs) Result(pid_t) {
    return result(pid_t, linux.syscall2(.clone3, @intFromPtr(args), @sizeOf(CloneArgs)));
}

/// The signals by number (asm-generic/signal.h, x86_64's and aarch64's).
pub const SIGHUP = 1;
pub const SIGINT = 2;
pub const SIGQUIT = 3;
pub const SIGKILL = 9;
pub const SIGUSR1 = 10;
pub const SIGPIPE = 13;
pub const SIGTERM = 15;
pub const SIGCHLD = 17;
pub const SIGCONT = 18;
pub const SIGWINCH = 28;
/// glibc's NSIG: the signals are 1 to 64.
pub const nsig = 65;

/// The bit of `sig` (1-64) in a kernel sigset, a u64 on both arches.
pub fn sigBit(sig: u7) u64 {
    return @as(u64, 1) << @as(u6, @intCast(sig - 1));
}

/// waitid(2)'s options (linux/wait.h).
pub const WEXITED = linux.W.EXITED;
pub const WNOWAIT = linux.W.NOWAIT;
pub const WNOHANG = linux.W.NOHANG;
/// si_code of a child that exited, rather than was killed (asm-generic/siginfo.h).
pub const CLD_EXITED = 1;

/// What waitid says of a child: its si_code and si_status, and si_pid,
/// which WNOHANG leaves 0 when the child has not exited.
pub const ChildInfo = struct {
    code: i32,
    status: i32,
    pid: pid_t,
};

/// waitid(P_PIDFD, pidfd, &si, flags), EINTR retried as flong-util.c:342
/// and :355 retry it. The siginfo starts zeroed (:341).
pub fn waitidPidfd(pidfd: fd_t, flags: u32) Result(ChildInfo) {
    var si: linux.siginfo_t = std.mem.zeroes(linux.siginfo_t);
    while (true) {
        switch (result(void, linux.waitid(.PIDFD, pidfd, &si, flags))) {
            .ok => return .{ .ok = .{
                .code = si.code,
                .status = si.fields.common.second.sigchld.status,
                .pid = si.fields.common.first.piduid.pid,
            } },
            .err => |e| if (e != .INTR) return .{ .err = e },
        }
    }
}

/// pidfd_open(2). ESRCH, the process gone, is an answer the caller reads
/// (flong-util.c:326-334).
pub fn pidfdOpen(pid: pid_t) Result(fd_t) {
    return result(fd_t, linux.pidfd_open(pid, 0));
}

/// pidfd_send_signal(2) with no siginfo, as flong-util.c:354 sends SIGKILL.
pub fn pidfdSendSignal(pidfd: fd_t, sig: i32) Result(void) {
    return result(void, linux.pidfd_send_signal(pidfd, sig, null, 0));
}

pub const pollfd = linux.pollfd;
pub const POLL = linux.POLL;

/// poll(2) with no timeout (-1) or one; EINTR is the caller's, as fl_await
/// retries it itself (flong-util.c:292-296).
pub fn poll(fds: []pollfd, timeout_ms: i32) Result(usize) {
    return result(usize, linux.poll(fds.ptr, fds.len, timeout_ms));
}

/// close_range(2)'s flag that marks the range close-on-exec instead of
/// closing it (linux/close_range.h), as Spawn's child uses it
/// (flong-util.c:435).
pub const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;

/// pipe2(2), both ends O_CLOEXEC.
pub fn pipe2(fds: *[2]fd_t) Result(void) {
    return result(void, linux.pipe2(fds, .{ .CLOEXEC = true }));
}

/// rt_sigprocmask(2)'s `how` (asm-generic/signal-defs.h).
pub const SIG_BLOCK = 0;
pub const SIG_SETMASK = 2;

/// rt_sigprocmask(how, &set, &old): the mask before the call.
pub fn sigprocmask(how: u32, set: u64) Result(u64) {
    var old: u64 = 0;
    return switch (result(void, linux.syscall4(.rt_sigprocmask, how, @intFromPtr(&set), @intFromPtr(&old), @sizeOf(u64)))) {
        .ok => .{ .ok = old },
        .err => |e| .{ .err = e },
    };
}

/// SA_RESTART (asm-generic/signal-defs.h), which glibc's signal() sets.
pub const sa_restart = 0x10000000;
/// SIG_IGN, the handler value.
pub const sig_ign = 1;

/// signal(sig, handler) as glibc's signal() makes the call, BSD semantics
/// (glibc signal/signal.c, __bsd_signal): the signal itself masked while
/// its handler runs, SA_RESTART, and SA_RESTORER with its restorer on
/// x86_64 as sigDefault sets it. `handler` is SIG_DFL or SIG_IGN. The old
/// action is asked for, as glibc asks, and dropped.
pub fn signal(sig: u7, handler: usize) Result(void) {
    const x86 = builtin.cpu.arch == .x86_64;
    const act: KSigaction = .{
        .handler = handler,
        .flags = sa_restart | (if (x86) sa_restorer else 0),
        .restorer = if (x86) @intFromPtr(&linux.restore_rt) else 0,
        .mask = sigBit(sig),
    };
    var old: KSigaction = undefined;
    return result(void, linux.syscall4(.rt_sigaction, sig, @intFromPtr(&act), @intFromPtr(&old), @sizeOf(u64)));
}

/// signalfd4(2)'s flags (linux/signalfd.h): O_CLOEXEC's and O_NONBLOCK's
/// bits, as fl_sigfd is made (flong-launch.c:881).
pub const SFD_CLOEXEC: u32 = 0o2000000;
pub const SFD_NONBLOCK: u32 = 0o4000;

/// signalfd4(-1, mask, flags): a new descriptor reading `mask`'s signals.
pub fn signalfd(mask: u64, flags: u32) Result(fd_t) {
    const none: isize = -1;
    return result(fd_t, linux.syscall4(.signalfd4, @bitCast(none), @intFromPtr(&mask), @sizeOf(u64), flags));
}

/// struct signalfd_siginfo (linux/signalfd.h): 128 bytes, ssi_signo first.
pub const SignalfdSiginfo = linux.signalfd_siginfo;

comptime {
    std.debug.assert(@sizeOf(SignalfdSiginfo) == 128);
    std.debug.assert(@offsetOf(SignalfdSiginfo, "signo") == 0);
}

/// fcntl(2)'s commands Spawn's child makes (flong-util.c:425, 440).
pub const F_SETFD = 2;
pub const F_DUPFD_CLOEXEC = 1030;

/// fcntl(2) with an integer argument: its value, a descriptor for
/// F_DUPFD_CLOEXEC.
pub fn fcntl(fd: fd_t, cmd: i32, arg: usize) Result(fd_t) {
    return result(fd_t, linux.fcntl(fd, cmd, arg));
}

/// dup2(2); aarch64 has only dup3, which glibc's dup2 calls when the two
/// differ, and Spawn's child never passes two that are the same (a copy
/// above 2 onto 0-2, flong-util.c:429-433).
pub fn dup2(old: fd_t, new: fd_t) Result(void) {
    std.debug.assert(old != new);
    return result(void, linux.dup2(old, new));
}

pub fn getuid() uid_t {
    return linux.getuid();
}

pub fn geteuid() uid_t {
    return linux.geteuid();
}

/// getpid(2): the launcher names a descriptor it holds to the postStart
/// hook and to pasta as /proc/<its pid>/fd/N, a path that works in another
/// process (flong-launch.c:590-591, 622-624).
pub fn getpid() pid_t {
    return linux.getpid();
}

/// MFD_CLOEXEC (linux/memfd.h), memfd_create's close-on-exec flag.
pub const MFD_CLOEXEC: u32 = linux.MFD.CLOEXEC;

/// memfd_create(2): a file with nothing on disk, pasta's pid file
/// (flong-launch.c:616).
pub fn memfdCreate(name: [*:0]const u8, flags: u32) Result(fd_t) {
    return result(fd_t, linux.memfd_create(name, flags));
}

/// X_OK, access(2)'s execute bit.
pub const X_OK = linux.X_OK;

/// access(path, mode) as glibc's aarch64 access makes it,
/// faccessat(AT_FDCWD, path, mode), on both arches: the real ids decide.
pub fn access(path: [*:0]const u8, mode: u32) Result(void) {
    return result(void, linux.syscall3(.faccessat, @bitCast(@as(isize, AT.FDCWD)), @intFromPtr(path), mode));
}

/// inotify's event bits and init flag (linux/inotify.h).
pub const IN = linux.IN;

pub fn inotifyInit1(flags: u32) Result(fd_t) {
    return result(fd_t, linux.inotify_init1(flags));
}

/// inotify_add_watch(2): the watch descriptor.
pub fn inotifyAddWatch(fd: fd_t, path: [*:0]const u8, mask: u32) Result(i32) {
    return result(i32, linux.inotify_add_watch(fd, path, mask));
}

// ---- records (flong-record.c:343-356) ----

/// O_TMPFILE as the kernel and glibc spell it, __O_TMPFILE|O_DIRECTORY
/// (asm-generic/fcntl.h): std's O.TMPFILE is the one bit __O_TMPFILE
/// (linux.zig:333, 474), and an open with it alone is EINVAL. O_DIRECTORY
/// differs by arch, so this does too (x86_64 0o20200000, aarch64
/// 0o20040000; tests/zig/abi.zig holds both).
pub const O_TMPFILE: O = .{ .TMPFILE = true, .DIRECTORY = true };

/// linkat(2): `flags` takes AT.SYMLINK_FOLLOW, which a link through
/// /proc/self/fd/N needs to name the file and not the magic link.
pub fn linkat(old_dir: fd_t, old: [*:0]const u8, new_dir: fd_t, new: [*:0]const u8, flags: u32) Result(void) {
    return result(void, linux.linkat(old_dir, old, new_dir, new, @intCast(flags)));
}

// ---- the terminal (flong-tty.c; phase 7 L3) ----

/// The kernel's struct termios (asm-generic/termbits.h, x86_64's and
/// aarch64's): four flag words, the line discipline and 19 control
/// characters, 36 bytes, what TCGETS fills and TCSETS reads. Not std's
/// linux.termios, which is glibc's (32 characters and two speeds, 60
/// bytes). glibc's tcgetattr and tcsetattr convert to and from their own
/// struct around the ioctls; the launcher saves only modes the kernel gave
/// and hands them back, changed by cfmakeraw alone (flong-tty.c:94-107,
/// 188), so the kernel's struct is all it needs.
pub const Termios = extern struct {
    iflag: u32,
    oflag: u32,
    cflag: u32,
    lflag: u32,
    line: u8,
    cc: [nccs]u8,
};
pub const nccs = 19;

comptime {
    std.debug.assert(@sizeOf(Termios) == 36);
    std.debug.assert(@offsetOf(Termios, "cc") == 17);
}

/// struct winsize (asm-generic/termios.h), as TIOCGWINSZ and TIOCSWINSZ
/// take it.
pub const Winsize = extern struct {
    row: u16,
    col: u16,
    xpixel: u16,
    ypixel: u16,
};

/// The terminal ioctls (asm-generic/ioctls.h, x86_64's and aarch64's; the
/// generic branch of std's T, linux.zig:5090-5139).
pub const TCGETS: u32 = 0x5401;
pub const TCSETS: u32 = 0x5402;
pub const TCSETSF: u32 = 0x5404;
pub const TIOCGPGRP: u32 = 0x540F;
pub const TIOCSPGRP: u32 = 0x5410;
pub const TIOCGWINSZ: u32 = 0x5413;
pub const TIOCSWINSZ: u32 = 0x5414;
/// _IOR('T', 0x30, unsigned int) and _IOW('T', 0x31, int).
pub const TIOCGPTN: u32 = 0x80045430;
pub const TIOCSPTLCK: u32 = 0x40045431;

/// tcsetattr's action: TCSANOW is TCSETS, TCSAFLUSH TCSETSF, as glibc's
/// tcsetattr maps them.
pub const Tcsa = enum { now, flush };

/// The termios bits cfmakeraw clears and sets (asm-generic/termbits.h).
pub const IGNBRK: u32 = 0o1;
pub const BRKINT: u32 = 0o2;
pub const PARMRK: u32 = 0o10;
pub const ISTRIP: u32 = 0o40;
pub const INLCR: u32 = 0o100;
pub const IGNCR: u32 = 0o200;
pub const ICRNL: u32 = 0o400;
pub const IXON: u32 = 0o2000;
pub const OPOST: u32 = 0o1;
pub const ISIG: u32 = 0o1;
pub const ICANON: u32 = 0o2;
pub const ECHO: u32 = 0o10;
pub const ECHONL: u32 = 0o100;
pub const IEXTEN: u32 = 0o100000;
pub const CSIZE: u32 = 0o60;
pub const CS8: u32 = 0o60;
pub const PARENB: u32 = 0o400;
/// Indices into `cc`.
pub const VTIME = 5;
pub const VMIN = 6;

/// cfmakeraw(3) with glibc's bits (glibc termios/cfmakeraw.c; held to
/// glibc's by tests/zig/libc_tty.zig): no input or output processing, no
/// echo, canonical mode, signal keys or extensions, eight bits without
/// parity, and a read that returns once one byte is there.
pub fn cfmakeraw(t: *Termios) void {
    t.iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
    t.oflag &= ~OPOST;
    t.lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    t.cflag &= ~(CSIZE | PARENB);
    t.cflag |= CS8;
    t.cc[VMIN] = 1;
    t.cc[VTIME] = 0;
}

/// tcgetattr(3): TCGETS.
pub fn tcgetattr(fd: fd_t) Result(Termios) {
    var t: Termios = undefined;
    return switch (result(void, linux.syscall3(.ioctl, @bitCast(@as(isize, fd)), TCGETS, @intFromPtr(&t)))) {
        .ok => .{ .ok = t },
        .err => |e| .{ .err = e },
    };
}

/// tcsetattr(3): TCSETS or TCSETSF. Not retried: a background caller is
/// stopped by SIGTTOU inside it, and the kernel restarts it on SIGCONT, as
/// it restarted glibc's.
pub fn tcsetattr(fd: fd_t, when: Tcsa, t: *const Termios) Result(void) {
    const request = switch (when) {
        .now => TCSETS,
        .flush => TCSETSF,
    };
    return result(void, linux.syscall3(.ioctl, @bitCast(@as(isize, fd)), request, @intFromPtr(t)));
}

/// isatty(3): TCGETS succeeding, the question glibc's asks.
pub fn isatty(fd: fd_t) bool {
    return tcgetattr(fd) == .ok;
}

pub fn getWinsize(fd: fd_t) Result(Winsize) {
    var ws: Winsize = undefined;
    return switch (result(void, linux.syscall3(.ioctl, @bitCast(@as(isize, fd)), TIOCGWINSZ, @intFromPtr(&ws)))) {
        .ok => .{ .ok = ws },
        .err => |e| .{ .err = e },
    };
}

pub fn setWinsize(fd: fd_t, ws: *const Winsize) Result(void) {
    return result(void, linux.syscall3(.ioctl, @bitCast(@as(isize, fd)), TIOCSWINSZ, @intFromPtr(ws)));
}

/// tcgetpgrp(3): TIOCGPGRP, the terminal's foreground process group.
pub fn tcgetpgrp(fd: fd_t) Result(pid_t) {
    var pgrp: pid_t = 0;
    return switch (result(void, linux.syscall3(.ioctl, @bitCast(@as(isize, fd)), TIOCGPGRP, @intFromPtr(&pgrp)))) {
        .ok => .{ .ok = pgrp },
        .err => |e| .{ .err = e },
    };
}

/// tcsetpgrp(3): TIOCSPGRP.
pub fn tcsetpgrp(fd: fd_t, pgrp: pid_t) Result(void) {
    return result(void, linux.syscall3(.ioctl, @bitCast(@as(isize, fd)), TIOCSPGRP, @intFromPtr(&pgrp)));
}

/// unlockpt(3): TIOCSPTLCK with 0.
pub fn unlockpt(fd: fd_t) Result(void) {
    const unlock: i32 = 0;
    return result(void, linux.syscall3(.ioctl, @bitCast(@as(isize, fd)), TIOCSPTLCK, @intFromPtr(&unlock)));
}

/// TIOCGPTN: the pty's number, the N of /dev/pts/N (glibc's ptsname_r).
pub fn ptyNumber(fd: fd_t) Result(u32) {
    var n: u32 = 0;
    return switch (result(void, linux.syscall3(.ioctl, @bitCast(@as(isize, fd)), TIOCGPTN, @intFromPtr(&n)))) {
        .ok => .{ .ok = n },
        .err => |e| .{ .err = e },
    };
}

/// getpgrp(2) as getpgid(0), which both arches have (aarch64 has no
/// getpgrp). It cannot fail.
pub fn getpgrp() pid_t {
    return @bitCast(@as(u32, @truncate(linux.syscall1(.getpgid, 0))));
}

/// kill(2): `pid` 0 is the caller's process group, -N the group N; `sig`
/// 0 only asks whether it could be sent.
pub fn kill(pid: pid_t, sig: i32) Result(void) {
    return result(void, linux.kill(pid, sig));
}

pub const SIGTTOU = 22;

/// rt_sigaction(sig, act, old), either pointer null as the C passes NULL:
/// `old` receives the action before the call, which a caller may put back
/// as it is (flong-tty.c:45, 86-92).
pub fn sigaction(sig: u7, act: ?*const KSigaction, old: ?*KSigaction) Result(void) {
    return result(void, linux.syscall4(.rt_sigaction, sig, @intFromPtr(act), @intFromPtr(old), @sizeOf(u64)));
}

/// SIG_IGN, an empty mask and no flags, as `{ .sa_handler = SIG_IGN }`
/// reaches the kernel through glibc's sigaction: with SA_RESTORER and a
/// restorer on x86_64 (sigDefault's).
pub fn ignoreAction() KSigaction {
    const x86 = builtin.cpu.arch == .x86_64;
    return .{
        .handler = sig_ign,
        .flags = if (x86) sa_restorer else 0,
        .restorer = if (x86) @intFromPtr(&linux.restore_rt) else 0,
        .mask = 0,
    };
}

/// The signal mask, read with rt_sigprocmask(SIG_BLOCK, NULL, &old).
pub fn sigmask() Result(u64) {
    var old: u64 = 0;
    return switch (result(void, linux.syscall4(.rt_sigprocmask, SIG_BLOCK, 0, @intFromPtr(&old), @sizeOf(u64)))) {
        .ok => .{ .ok = old },
        .err => |e| .{ .err = e },
    };
}

/// PR_SET_NAME (linux/prctl.h): the thread's name, /proc's comm.
pub const PR_SET_NAME = 15;

/// CLOCK_MONOTONIC in nanoseconds, the ^] escape's clock
/// (flong-tty.c:362-372). It cannot fail with a valid clock and pointer.
pub fn clockMonotonic() i64 {
    var t: timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &t);
    return @as(i64, t.sec) * std.time.ns_per_s + t.nsec;
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
