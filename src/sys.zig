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
//! argv, and the exit.

const std = @import("std");
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

fn result(comptime T: type, rc: usize) Result(T) {
    return switch (E.init(rc)) {
        .SUCCESS => .{ .ok = @intCast(rc) },
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

/// CLOCK_REALTIME, as fl_trace stamps a stage (flong-util.c:127). It cannot
/// fail with a valid clock and pointer; the vDSO answers when there is one.
pub fn clockRealtime() timespec {
    var t: timespec = undefined;
    _ = linux.clock_gettime(.REALTIME, &t);
    return t;
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

test "argv is the process's" {
    try std.testing.expect(argv().len >= 1);
}
