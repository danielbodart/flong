//! proc.zig: children (ZIG.md, "Signals and processes"): flong-util.c's
//! fork, spawn, reap, lock wait and starttime (:236-242, 324-513).
//!
//! Every child is made by clone3 with CLONE_PIDFD, and CLONE_INTO_CGROUP
//! when it has a cgroup, so it is created in its cgroup and never migrated
//! (flong-util.c:387-402). Its pidfd's slot in the descriptor table is
//! reserved before clone3, so a full table is found before the child
//! exists (quirk 26).
//!
//!   fork   a helper running flong's code: `body` is `noreturn`, so the
//!          child never returns into its parent's frames, and no parent
//!          `defer` runs in it; a body that can return does not compile.
//!          The child keeps only its keep list (fd.retainOnly), the signal
//!          mask and the dispositions (flong-util.h:182-191).
//!   Spawn  a program: everything it takes (argv, envp, stdio, the kept
//!          descriptors, dir, cgroup) is built before clone3, and the child
//!          is spawn_child step for step (flong-util.c:404-452), a failure
//!          printed, then 127.
//!   Child  ends once: `await`, `reapNow(.kill | .wait)` or `release`
//!          (closed unreaped). No implicit kill (quirk 25). `peek` is
//!          WNOWAIT and ends nothing.
//!
//! A fork child's failure to close is printed, `close_range N: <text>`,
//! and exits 125; a spawned child's, 127 (quirk 24: the spike's were
//! silent). Every root is `pub fn main() noreturn` and ends in `exit`,
//! exit_group, as every fork body does: a returning single-threaded main
//! ends in exit, not exit_group (ZIG.md, "Measured").

const std = @import("std");
const sys = @import("sys");
const fdt = @import("fd");
const msg = @import("msg");
const sig = @import("sig");
const num = @import("num");

/// exit_group(2): how every root and fork body ends.
pub const exit = sys.exitGroup;

/// fl_refuse_root (flong-util.c:237-242): no root anywhere includes the
/// caller, real or effective.
pub fn refuseRoot() msg.Error!void {
    if (sys.getuid() == 0 or sys.geteuid() == 0)
        return msg.refuse("refusing to run as root: flong runs as its caller, never as root", .{});
}

/// A child of ours, through its pidfd.
pub const Child = struct {
    pidfd: fdt.Fd(.pidfd),
    pid: sys.pid_t,

    pub const How = enum { kill, wait };

    /// fl_reap (flong-util.c:336-346): waits (sig.awaitFd, POLLIN) for the
    /// child to exit, reaps it and closes the pidfd. Its status is the exit
    /// code, or 128+n for a signal (flong-util.h:135-138). On an error, a
    /// terminating signal (Aborted) included, the child is still the
    /// caller's, to `reapNow` or `release`.
    pub fn await(self: Child) sig.Error!u8 {
        try sig.awaitFd(self.pidfd, sys.POLL.IN);
        const info = try msg.check(self.pidfd.waitid(sys.WEXITED), "waitid", .{});
        self.pidfd.close();
        return status(info);
    }

    /// fl_reap_now (flong-util.c:348-358): on a cleanup path, SIGKILL
    /// (`.kill`) and a blocking reap that ignores signals, then the close.
    pub fn reapNow(self: Child, how: How) void {
        if (how == .kill) _ = self.pidfd.sendSignal(sys.SIGKILL);
        _ = self.pidfd.waitid(sys.WEXITED);
        self.pidfd.close();
    }

    /// Closes the pidfd without reaping: the child is left to exit on its
    /// own and be reaped by whoever waits (quirk 8, flong-cgroup.c:195-198).
    pub fn release(self: Child) void {
        self.pidfd.close();
    }

    /// The status of an exited child, leaving it to be reaped
    /// (WEXITED|WNOWAIT, flong-tty.c:351-358). The caller says what failed.
    pub fn peek(self: Child) sys.Result(u8) {
        return switch (self.pidfd.waitid(sys.WEXITED | sys.WNOWAIT)) {
            .ok => |info| .{ .ok = status(info) },
            .err => |e| .{ .err = e },
        };
    }
};

/// fl_status (flong-util.h:135-138): the exit code, or 128+n for a signal.
fn status(info: sys.ChildInfo) u8 {
    const s: u8 = @truncate(@as(u32, @bitCast(info.status)));
    return if (info.code == sys.CLD_EXITED) s else 128 +% s;
}

/// clone_into's arguments (flong-util.c:390-402): the pidfd into `pidfd`,
/// SIGCHLD at exit, and the cgroup when there is one.
fn cloneArgs(pidfd: *sys.fd_t, cgroup: ?fdt.Fd(.cgroup)) sys.CloneArgs {
    var args: sys.CloneArgs = .{
        .flags = sys.CLONE_PIDFD,
        .pidfd = @intFromPtr(pidfd),
        .exit_signal = sys.SIGCHLD,
    };
    if (cgroup) |cg| {
        args.flags |= sys.CLONE_INTO_CGROUP;
        args.cgroup = @intCast(cg.raw());
    }
    return args;
}

pub const ForkOpts = struct {
    /// the cgroup the child is created in; null: the caller's own
    cgroup: ?fdt.Fd(.cgroup) = null,
    /// the descriptors from 3 up the child keeps, at their numbers
    keep: []const fdt.AnyFd = &.{},
};

/// fl_fork (flong-util.c:467-482): a helper that runs `body(ctx)` and must
/// end in `exit` (the type says so: a body that can return does not
/// compile). The child first closes every descriptor from 3 up but `keep`
/// (fd.retainOnly), printing `close_range N: <text>` and exiting 125 when
/// it cannot; every handle it did not keep is stale in it, the signalfd's
/// included. It keeps the caller's signal mask and dispositions. Nothing
/// with a side effect may be deferred across it. Every handle in `keep` is
/// checked live here, in the caller.
pub fn fork(opts: ForkOpts, ctx: anytype, comptime body: fn (@TypeOf(ctx)) noreturn) msg.Error!Child {
    for (opts.keep) |h| _ = h.raw();
    const slot = fdt.reserve() catch return msg.refuse("clone3: too many open descriptors", .{});
    var raw: sys.fd_t = -1;
    var args = cloneArgs(&raw, opts.cgroup);
    switch (sys.clone3(&args)) {
        .err => |e| {
            slot.cancel();
            return msg.fail(e, "clone3", .{});
        },
        .ok => |pid| {
            if (pid == 0) {
                if (fdt.retainOnly(opts.keep)) |f| msg.die(f.err, "close_range {d}", .{f.low});
                body(ctx);
            }
            return .{ .pidfd = slot.fill(.pidfd, raw), .pid = pid };
        },
    }
}

/// A program to start (struct fl_spawn, flong-util.h:157-167). Its argv
/// lives in the caller's allocator (bwrap's runs past 100 words); the only
/// way to name a descriptor in it is `passFd`, which keeps that descriptor
/// at that number, so an argv number the program does not hold, or a kept
/// descriptor argv does not name, cannot be written.
pub const Spawn = struct {
    gpa: std.mem.Allocator,
    /// argv, always ending in its null
    argv: std.ArrayList(?[*:0]const u8) = .empty,
    keep: std.ArrayList(fdt.AnyFd) = .empty,
    /// keep's numbers, resolved in `start`
    keep_raw: std.ArrayList(sys.fd_t) = .empty,
    /// passFd's number texts, which argv points into
    texts: std.ArrayList([:0]u8) = .empty,
    /// what becomes 0, 1 and 2; null inherits that one
    stdio: [3]?fdt.AnyFd = .{ null, null, null },
    /// the environment; null: this process's own
    envp: ?[*:null]const ?[*:0]const u8 = null,
    /// the directory it starts in; null: this process's
    dir: ?[*:0]const u8 = null,
    /// the cgroup it is created in; null: this process's
    cgroup: ?fdt.Fd(.cgroup) = null,

    /// `program` is absolute: execve, no PATH search.
    pub fn init(gpa: std.mem.Allocator, program: [*:0]const u8) std.mem.Allocator.Error!Spawn {
        var s: Spawn = .{ .gpa = gpa };
        try s.argv.appendSlice(gpa, &.{ program, null });
        return s;
    }

    /// Frees what init and the appends allocated (a caller with an arena
    /// need not).
    pub fn deinit(self: *Spawn) void {
        for (self.texts.items) |t| self.gpa.free(t);
        self.texts.deinit(self.gpa);
        self.argv.deinit(self.gpa);
        self.keep.deinit(self.gpa);
        self.keep_raw.deinit(self.gpa);
    }

    pub fn arg(self: *Spawn, a: [*:0]const u8) std.mem.Allocator.Error!void {
        try self.argv.insert(self.gpa, self.argv.items.len - 1, a);
    }

    /// Appends `h`'s number to argv and keeps `h` at that number in the
    /// program. The number's text is the caller allocator's.
    pub fn passFd(self: *Spawn, h: anytype) std.mem.Allocator.Error!void {
        if (@TypeOf(h) == fdt.Stdio)
            @compileError("passFd of Stdio: 0-2 are the program's stdio, set in Spawn.stdio, not a descriptor to pass");
        const text = try std.fmt.allocPrintSentinel(self.gpa, "{d}", .{h.raw()}, 0);
        self.texts.append(self.gpa, text) catch |err| {
            self.gpa.free(text);
            return err;
        };
        try self.keepAny(h.any());
        try self.arg(text.ptr);
    }

    /// Keeps a descriptor the caller handed over, at its number, which the
    /// caller's own argv already names (flong-launch.c:407-408).
    pub fn keepInherited(self: *Spawn, h: fdt.Fd(.inherited)) std.mem.Allocator.Error!void {
        try self.keepAny(h.any());
    }

    fn keepAny(self: *Spawn, h: fdt.AnyFd) std.mem.Allocator.Error!void {
        try self.keep.append(self.gpa, h);
        try self.keep_raw.append(self.gpa, -1);
    }

    /// fl_spawn (flong-util.c:454-465): starts the program and returns its
    /// Child. A failure to start it is printed here ("clone3 <argv0>"); one
    /// in the child before the exec is printed there and shows as status
    /// 127. Every handle it names is resolved here, before clone3, so the
    /// child touches no table.
    pub fn start(self: *Spawn) msg.Error!Child {
        const argv0 = self.argv.items[0].?;
        for (self.keep.items, self.keep_raw.items) |h, *r| r.* = h.raw();
        var p: Prepared = .{
            .argv = @ptrCast(self.argv.items.ptr),
            .envp = self.envp orelse @ptrCast(sys.environ().ptr),
            .keep = self.keep_raw.items,
            .dir = self.dir,
        };
        for (self.stdio, 0..) |s, i| {
            if (s) |h| p.stdio[i] = h.raw();
        }
        const slot = fdt.reserve() catch return msg.refuse("clone3 {s}: too many open descriptors", .{argv0});
        var raw: sys.fd_t = -1;
        var args = cloneArgs(&raw, self.cgroup);
        switch (sys.clone3(&args)) {
            .err => |e| {
                slot.cancel();
                return msg.fail(e, "clone3 {s}", .{argv0});
            },
            .ok => |pid| {
                if (pid == 0) spawnChild(&p);
                return .{ .pidfd = slot.fill(.pidfd, raw), .pid = pid };
            },
        }
    }
};

/// What the spawned child needs, in numbers and pointers only.
const Prepared = struct {
    argv: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
    stdio: [3]sys.fd_t = .{ -1, -1, -1 },
    keep: []const sys.fd_t,
    dir: ?[*:0]const u8,
};

/// Prints why, then 127, as a shell says a program could not start.
fn fail127(e: sys.E, comptime fmt: []const u8, args: anytype) noreturn {
    msg.sayErrno(e, fmt, args);
    sys.exitGroup(127);
}

/// spawn_child (flong-util.c:404-452), step for step. It reports a failure
/// on stderr, which by then is the program's own, and exits 127.
fn spawnChild(p: *const Prepared) noreturn {
    // exec resets handled signals but keeps ignored ones and the mask, and
    // the launcher ignores SIGPIPE and blocks the ones it reads from its
    // signalfd. The program gets the defaults a shell would give it: every
    // signal but the two glibc's sigaction refuses without a call (32 and
    // 33, its SIGCANCEL and SIGSETXID), as the C made the calls; KILL and
    // STOP answer EINVAL, unread (:415-418).
    var s: u7 = 1;
    while (s < sys.nsig) : (s += 1) {
        if (s == 32 or s == 33) continue;
        _ = sys.sigDefault(s);
    }
    _ = sys.emptyMask();

    // Each stdio source is first copied above 2, so that one source that is
    // another's target (stdout onto 0, say) is not overwritten before it is
    // used. The copies are then close-on-exec like everything else
    // (:420-433).
    var moved = [3]sys.fd_t{ -1, -1, -1 };
    for (p.stdio, 0..) |src, i| {
        if (src < 0) continue;
        moved[i] = switch (sys.fcntl(src, sys.F_DUPFD_CLOEXEC, 3)) {
            .ok => |n| n,
            .err => |e| fail127(e, "dup {d}", .{src}),
        };
    }
    for (moved, 0..) |m, i| {
        if (m < 0) continue;
        switch (sys.dup2(m, @intCast(i))) {
            .ok => {},
            .err => |e| fail127(e, "dup2 {d}", .{i}),
        }
    }

    // Everything from 3 up close-on-exec, then only the kept ones cleared
    // (:435-443).
    switch (sys.closeRange(3, std.math.maxInt(u32), sys.CLOSE_RANGE_CLOEXEC)) {
        .ok => {},
        .err => |e| fail127(e, "close_range", .{}),
    }
    for (p.keep) |k| {
        switch (sys.fcntl(k, sys.F_SETFD, 0)) {
            .ok => {},
            .err => |e| fail127(e, "keep {d}", .{k}),
        }
    }

    if (p.dir) |d| switch (sys.chdir(d)) {
        .ok => {},
        .err => |e| fail127(e, "chdir {s}", .{d}),
    };
    const argv0 = p.argv[0].?;
    fail127(sys.execve(argv0, p.argv, p.envp), "exec {s}", .{argv0});
}

/// fl_pidfd_open (flong-util.c:326-334): a pidfd for `pid`, or null when
/// the process is gone (ESRCH), which is an answer, not a failure.
pub fn pidfdOpen(pid: sys.pid_t) msg.Error!?fdt.Fd(.pidfd) {
    const r = fdt.pidfdOpen(pid) catch return msg.refuse("pidfd_open {d}: too many open descriptors", .{pid});
    return switch (r) {
        .ok => |h| h,
        .err => |e| if (e == .SRCH) null else msg.fail(e, "pidfd_open {d}", .{pid}),
    };
}

/// fl_lock_wait (flong-util.c:484-513): takes flock(op) on `h` (a file or
/// directory), op LOCK.SH or LOCK.EX, waiting for the holders to let go. A
/// free lock is taken at once, with LOCK_NB. A held one is waited for by a
/// helper forked with `h` alone, which takes it in the caller's stead and
/// exits: the lock is the open file description's, which the two share.
/// The wait is on the helper's pidfd, so a terminating signal ends it (the
/// helper is then killed).
pub fn lockWait(h: anytype, op: i32) sig.Error!void {
    switch (h.flock(op | sys.LOCK.NB)) {
        .ok => return,
        .err => |e| if (e != .AGAIN) return msg.fail(e, "lock", .{}),
    }
    const Helper = LockHelper(@TypeOf(h));
    const child = try fork(.{ .keep = &.{h.any()} }, Helper{ .h = h, .op = op }, Helper.body);
    const st = child.await() catch |err| {
        child.reapNow(.kill);
        return err;
    };
    // 125 is msg.die's: the helper has said why.
    if (st == 125) return error.Reported;
    if (st != 0) return msg.refuse("the lock helper ended with status {d}", .{st});
}

fn LockHelper(comptime H: type) type {
    return struct {
        h: H,
        op: i32,

        fn body(self: @This()) noreturn {
            // sys.flock retries EINTR (flong-util.c:496-498).
            switch (self.h.flock(self.op)) {
                .ok => sys.exitGroup(0),
                .err => |e| msg.die(e, "lock", .{}),
            }
        }
    };
}

/// fl_starttime (flong-util.c:360-385): field 22 of /proc/<pid>/stat, the
/// start time in clock ticks, or 0 when the process is gone. With the pid
/// it names one process for its whole life.
pub fn starttime(pid: sys.pid_t) u64 {
    var path_buf: [64]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buf, "/proc/{d}/stat", .{pid}) catch unreachable; // proven: 17 + 11 < 64
    const r = fdt.openFile(fdt.cwd, path, .{}, 0) catch return 0;
    const f = switch (r) {
        .ok => |f| f,
        .err => return 0,
    };
    defer f.close();
    // read_all (flong-util.c:191-206): to the end, or 4095 bytes.
    var buf: [4096]u8 = undefined;
    var len: usize = 0;
    while (len < buf.len - 1) {
        switch (f.read(buf[len .. buf.len - 1])) {
            .ok => |n| {
                if (n == 0) break;
                len += n;
            },
            .err => return 0,
        }
    }
    if (len == 0) return 0;
    return statStarttime(buf[0..len]);
}

/// Field 22 of a /proc/<pid>/stat text (flong-util.c:371-384), read as the
/// C reads its NUL-terminated buffer: the command name, field 2, is in
/// parentheses and may hold spaces and parentheses of its own, so the
/// fields are counted from its last ')'; field 3 follows it after one space,
/// field 22 is 19 spaces further, read by strtoull. 0 when a field is
/// missing. Any bytes are read without a panic.
pub fn statStarttime(text: []const u8) u64 {
    const c = text[0 .. std.mem.indexOfScalar(u8, text, 0) orelse text.len];
    var s = (std.mem.lastIndexOfScalar(u8, c, ')') orelse return 0) + 1;
    var field: u32 = 2;
    while (field < 22) : (field += 1) {
        s = (std.mem.indexOfScalarPos(u8, c, s, ' ') orelse return 0) + 1;
    }
    return num.strtoull10(c[s..]).value;
}

// ---- tests ----

const testing = std.testing;

test "statStarttime reads field 22 after the last parenthesis" {
    const line = "1234 (a) b) (c) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 424242 20 21\n";
    try testing.expectEqual(@as(u64, 424242), statStarttime(line));
    try testing.expectEqual(@as(u64, 0), statStarttime("1 (x) S 1 2 3"));
    try testing.expectEqual(@as(u64, 0), statStarttime("no parenthesis"));
    try testing.expectEqual(@as(u64, 0), statStarttime(""));
    // The C string ends at a NUL: a ')' after it is not seen.
    try testing.expectEqual(@as(u64, 0), statStarttime("1 (x\x00) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 99"));
}

test "starttime of this process is its stat's, and of no process 0" {
    const st = starttime(std.os.linux.getpid());
    try testing.expect(st > 0);
    // pid_max is at most 2^22: this pid is never one.
    try testing.expectEqual(@as(u64, 0), starttime(1 << 23));
}
