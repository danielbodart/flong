//! P3's process layer: clone3 with CLONE_PIDFD and CLONE_INTO_CGROUP, a
//! fork whose body cannot return, and a Child that is awaited through its
//! pidfd. On std.os.linux only (ZIG.md, "Build mode": no std.posix).
//!
//! This is the shape of ZIG.md's `proc.fork` ("Signals and processes") with
//! raw descriptor numbers where the plan has `Fd(.cgroup)` and `Fd(.pidfd)`:
//! the descriptor table is the spike's question, not this proof's. The C it
//! replaces is `clone_into` and `fl_fork` (launcher/flong-util.c:387-402,
//! 467-482).

const std = @import("std");
const linux = std.os.linux;

/// `struct clone_args` (include/uapi/linux/sched.h, CLONE_ARGS_SIZE_VER2):
/// every field a __aligned_u64, so the layout is the same on x86_64 and
/// aarch64. The kernel takes the size as clone3's second argument and
/// rejects a size it does not know, so a wrong layout fails loudly (E2BIG or
/// EINVAL) rather than reading the wrong field.
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
    std.debug.assert(@sizeOf(CloneArgs) == 88); // CLONE_ARGS_SIZE_VER2
    std.debug.assert(@offsetOf(CloneArgs, "exit_signal") == 32);
    std.debug.assert(@offsetOf(CloneArgs, "cgroup") == 80);
}

/// A syscall's outcome: the value, or the errno it failed with.
pub const Result = union(enum) { ok: usize, err: linux.E };

fn result(rc: usize) Result {
    return switch (linux.E.init(rc)) {
        .SUCCESS => .{ .ok = rc },
        else => |e| .{ .err = e },
    };
}

/// clone3 with no stack and no CLONE_VM: a fork, returning twice on the
/// caller's stack, 0 in the child. The child has its own copy of memory, so
/// the second return is as safe as fork's.
pub fn clone3(args: *CloneArgs) Result {
    return result(linux.syscall2(.clone3, @intFromPtr(args), @sizeOf(CloneArgs)));
}

/// setns(fd, nstype); std.os.linux has no wrapper in 0.15.2.
pub fn setns(fd: i32, nstype: u32) Result {
    return result(linux.syscall2(.setns, @as(usize, @bitCast(@as(isize, fd))), nstype));
}

/// One line on stderr, "p3-proc: <what>: <errno name>", one write.
pub fn report(what: []const u8, e: linux.E) void {
    var buf: [256]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, "p3-proc: {s}: {s}\n", .{ what, @tagName(e) }) catch return;
    _ = linux.write(2, line.ptr, line.len);
}

pub const Child = struct {
    pidfd: i32,
    pid: linux.pid_t,

    /// Waits for the child through its pidfd, closes the pidfd, and returns
    /// its status: the exit code, or 128 + the signal (as `fl_await`,
    /// flong-util.c:336-346).
    pub fn await(self: Child) error{Reported}!u8 {
        defer _ = linux.close(self.pidfd);
        var info: linux.siginfo_t = undefined;
        while (true) {
            switch (result(linux.waitid(.PIDFD, self.pidfd, &info, linux.W.EXITED))) {
                .ok => break,
                .err => |e| if (e != .INTR) {
                    report("waitid", e);
                    return error.Reported;
                },
            }
        }
        const status: u8 = @truncate(@as(u32, @bitCast(info.fields.common.second.sigchld.status)));
        const CLD_EXITED = 1;
        return if (info.code == CLD_EXITED) status else 128 +| status;
    }
};

pub const Opts = struct {
    /// A cgroup directory, typically opened O_PATH: the child starts in it
    /// (CLONE_INTO_CGROUP) and is never migrated.
    cgroup: ?i32 = null,
};

/// Forks a child that runs `body(ctx)`. `body` is `noreturn`, so the child
/// never comes back into this frame or any caller's: no parent `defer` or
/// `errdefer` runs in it, and a body that can return does not compile (the
/// type of the parameter says so; probes/body_returns.zig). The child keeps
/// the signal mask and dispositions (flong-util.h:187).
pub fn fork(opts: Opts, ctx: anytype, comptime body: fn (@TypeOf(ctx)) noreturn) error{Reported}!Child {
    var pidfd: i32 = -1;
    var args: CloneArgs = .{
        .flags = linux.CLONE.PIDFD,
        .pidfd = @intFromPtr(&pidfd),
        .exit_signal = linux.SIG.CHLD,
    };
    if (opts.cgroup) |cg| {
        args.flags |= linux.CLONE.INTO_CGROUP;
        args.cgroup = @intCast(cg);
    }
    switch (clone3(&args)) {
        .err => |e| {
            report("clone3", e);
            return error.Reported;
        },
        .ok => |pid| {
            if (pid == 0) body(ctx);
            return .{ .pidfd = pidfd, .pid = @intCast(pid) };
        },
    }
}
