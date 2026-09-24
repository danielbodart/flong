//! proc.zig and sig.zig from outside (minish, the `test` step; DESIGN.md,
//! "Tests"): fork and its keep list, Spawn against the spawn probe
//! (`flong-proc probe`, tests/zig/procdriver.zig), Child's endings,
//! lockWait, the signalfd, awaitFd's POLLHUP and POLLERR, the pidfd's slot
//! reserved before clone3, and the spike's model property grown to forks
//! and spawns: after any sequence the table, a model of it and the kernel's
//! /proc/self/fd agree, and each child holds what it was given. Each test
//! is one of the port's planted mutations' catcher (DESIGN.md, "Tests"); the list is in its name.

const std = @import("std");
const linux = std.os.linux;
const minish = @import("minish");
const sys = @import("sys");
const fd = @import("fd");
const sig = @import("sig");
const proc = @import("proc");
const options = @import("options");
const testing = std.testing;

/// flong-proc, built beside this test: its path as the build gives it,
/// relative to the test's working directory, made absolute once, since a
/// Spawn may change directory before its exec.
var driver_buf: [std.fs.max_path_bytes:0]u8 = undefined;
var driver: [:0]const u8 = "";

fn findDriver() void {
    if (driver.len > 0) return;
    const p = std.fs.cwd().realpath(options.driver, &driver_buf) catch @panic("flong-proc not found");
    driver_buf[p.len] = 0;
    driver = driver_buf[0..p.len :0];
}

// Any file every Linux has, the Nix build sandbox included (found in
// the port's phase 0).
const test_file = "/etc/passwd";

fn opened(r: anytype) !@FieldType(@typeInfo(@TypeOf(r)).error_union.payload, "ok") {
    return switch (try r) {
        .ok => |h| h,
        .err => error.TestUnexpectedResult,
    };
}

fn newPipe() !fd.Pipe {
    return opened(fd.pipe());
}

/// Reads `r` to its end into `buf`.
fn drain(r: fd.Fd(.pipe_r), buf: []u8) ![]u8 {
    var n: usize = 0;
    while (n < buf.len) {
        const got = switch (r.read(buf[n..])) {
            .ok => |g| g,
            .err => return error.TestUnexpectedResult,
        };
        if (got == 0) break;
        n += got;
    }
    return buf[0..n];
}

/// The value of probe line `key` ("key: value").
fn field(text: []const u8, key: []const u8) ![]const u8 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |l| {
        if (std.mem.startsWith(u8, l, key) and l.len > key.len and l[key.len] == ':')
            return std.mem.trimLeft(u8, l[key.len + 1 ..], " ");
    }
    std.debug.print("no {s} line in:\n{s}\n", .{ key, text });
    return error.TestUnexpectedResult;
}

// ---- the kernel's view ----

const KernelFds = struct {
    fds: [2048]i32 = undefined,
    n: usize = 0,

    fn slice(self: *const KernelFds) []const i32 {
        return self.fds[0..self.n];
    }

    fn contains(self: *const KernelFds, v: i32) bool {
        return std.mem.indexOfScalar(i32, self.slice(), v) != null;
    }

    fn read() !KernelFds {
        const rc = linux.open("/proc/self/fd", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
        if (linux.E.init(rc) != .SUCCESS) return error.ProcFd;
        const dir: i32 = @intCast(rc);
        defer _ = linux.close(dir);
        var k: KernelFds = .{};
        var buf: [4096]u8 align(8) = undefined;
        while (true) {
            const got = linux.getdents64(dir, &buf, buf.len);
            if (linux.E.init(got) != .SUCCESS) return error.ProcFd;
            if (got == 0) break;
            var it: fd.Entries = .{ .buf = buf[0..got] };
            while (it.next()) |e| {
                const v = std.fmt.parseInt(i32, e.name, 10) catch continue;
                if (v == dir) continue;
                k.fds[k.n] = v;
                k.n += 1;
            }
        }
        std.mem.sort(i32, k.fds[0..k.n], {}, std.sort.asc(i32));
        return k;
    }
};

fn expectKernelMatches(baseline: *const KernelFds) !void {
    var buf: [fd.capacity]sys.fd_t = undefined;
    const live = fd.snapshot(&buf);
    var want: KernelFds = baseline.*;
    for (live) |n| {
        want.fds[want.n] = n;
        want.n += 1;
    }
    std.mem.sort(i32, want.fds[0..want.n], {}, std.sort.asc(i32));
    const kernel = try KernelFds.read();
    try testing.expectEqualSlices(i32, want.slice(), kernel.slice());
}

// ---- running the probe ----

/// Starts `s` with its stdout on a pipe and returns what it printed; its
/// status must be `want`.
fn runCapture(s: *proc.Spawn, buf: []u8, want: u8) ![]u8 {
    const p = try newPipe();
    defer p.r.close();
    s.stdio[1] = p.w.any();
    const child = s.start() catch |err| {
        p.w.close();
        return err;
    };
    p.w.close();
    const text = try drain(p.r, buf);
    const st = child.await() catch |err| {
        child.reapNow(.kill);
        return err;
    };
    if (st != want) {
        std.debug.print("status {d}, not {d}; said:\n{s}\n", .{ st, want, text });
        return error.TestUnexpectedResult;
    }
    return text;
}

/// A Spawn of the probe, with `args`.
fn probeSpawn(gpa: std.mem.Allocator) !proc.Spawn {
    findDriver();
    var s = try proc.Spawn.init(gpa, driver);
    try s.arg("probe");
    return s;
}

// ---- fork ----

var kept_for_child: fd.File = undefined;
var dropped_for_child: fd.Dir = undefined;
var pipe_for_child: fd.Pipe = undefined;

const KeepCheck = struct {
    fn body(_: KeepCheck) noreturn {
        if (!kept_for_child.isLive()) proc.exit(1);
        if (dropped_for_child.isLive()) proc.exit(2);
        if (pipe_for_child.r.isLive() or pipe_for_child.w.isLive()) proc.exit(3);
        const k = KernelFds.read() catch proc.exit(4);
        for (k.slice()) |n| {
            if (n >= 3 and n != kept_for_child.raw()) proc.exit(5);
        }
        if (!k.contains(kept_for_child.raw())) proc.exit(6);
        proc.exit(0);
    }
};

test "fork: the child holds only its keep list, and every other handle is stale in it (a child ignoring the keep list; retainOnly without its final close_range or skipping it)" {
    // The kept one below the others, so a missing last close_range leaves
    // them open in the child.
    kept_for_child = try opened(fd.openFile(fd.cwd, test_file, .{}, 0));
    defer kept_for_child.close();
    dropped_for_child = try opened(fd.openDir(fd.cwd, "/"));
    defer dropped_for_child.close();
    pipe_for_child = try newPipe();
    defer pipe_for_child.r.close();
    defer pipe_for_child.w.close();
    const start = fd.liveCount();
    const child = try proc.fork(.{ .keep = &.{kept_for_child.any()} }, KeepCheck{}, KeepCheck.body);
    try testing.expectEqual(start + 1, fd.liveCount()); // the pidfd, in its reserved slot
    try testing.expectEqual(@as(u8, 0), try child.await());
    try testing.expectEqual(start, fd.liveCount());
}

const Once = struct {
    w: fd.Fd(.pipe_w),

    fn body(self: Once) noreturn {
        _ = self.w.write("c");
        proc.exit(7);
    }
};

test "fork: the body runs once, in the child; the caller's defer once, in the caller" {
    const p = try newPipe();
    defer p.r.close();
    var defers: u32 = 0;
    {
        defer defers += 1;
        const child = try proc.fork(.{ .keep = &.{p.w.any()} }, Once{ .w = p.w }, Once.body);
        p.w.close();
        try testing.expectEqual(@as(u8, 7), try child.await());
    }
    var buf: [8]u8 = undefined;
    try testing.expectEqualStrings("c", try drain(p.r, &buf));
    try testing.expectEqual(@as(u32, 1), defers);
}

test "fork: a panicking body says one line and exits 125, and the parent goes on (flong-proc fork-panic)" {
    findDriver();
    for ([_]struct { [:0]const u8, u8, []const u8 }{
        .{ "fork", 7, "child exited 7" },
        .{ "fork-panic", 125, "child exited 125" },
    }) |c| {
        var mem: [1024]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&mem);
        var s = try proc.Spawn.init(fba.allocator(), driver);
        try s.arg(c[0]);
        const err = try newPipe();
        defer err.r.close();
        s.stdio[2] = err.w.any();
        var buf: [4096]u8 = undefined;
        const text = runCapture(&s, &buf, 0) catch |e| {
            err.w.close();
            return e;
        };
        err.w.close();
        var ebuf: [4096]u8 = undefined;
        const said = try drain(err.r, &ebuf);
        try testing.expect(std.mem.indexOf(u8, text, c[2]) != null);
        try testing.expect(std.mem.startsWith(u8, text, "child ran: ") or c[1] == 125);
        try testing.expect(std.mem.endsWith(u8, text, "\n") and std.mem.indexOf(u8, text, "parent defer ran: ") != null);
        try testing.expectEqualStrings(if (c[1] == 125) "flong-proc: internal error: planted\n" else "", said);
    }
}

test "fork: the pidfd's slot is reserved before clone3, so a full table makes no child (quirk 26)" {
    var lim: linux.rlimit = undefined;
    _ = linux.getrlimit(.NOFILE, &lim);
    const want = fd.capacity + 64;
    if (lim.max < want) return error.SkipZigTest;
    const old = lim;
    if (lim.cur < want) {
        lim.cur = want;
        _ = linux.setrlimit(.NOFILE, &lim);
    }
    defer _ = linux.setrlimit(.NOFILE, &old);
    const start = fd.liveCount();
    var all: [fd.capacity]fd.File = undefined;
    var n: usize = 0;
    while (true) {
        const r = fd.openFile(fd.cwd, test_file, .{}, 0) catch break;
        all[n] = switch (r) {
            .ok => |f| f,
            .err => return error.TestUnexpectedResult,
        };
        n += 1;
    }
    defer for (all[0..n]) |f| f.close();
    try testing.expectEqual(@as(usize, fd.capacity), fd.liveCount());
    try testing.expectError(error.Reported, proc.fork(.{}, KeepCheck{}, KeepCheck.body));
    var s = try proc.Spawn.init(testing.allocator, "/nonexistent/never-started");
    defer s.deinit();
    try testing.expectError(error.Reported, s.start());
    // No child was made: none to wait for.
    var si: linux.siginfo_t = undefined;
    try testing.expectEqual(linux.E.CHILD, linux.E.init(linux.waitid(.ALL, 0, &si, linux.W.EXITED | linux.W.NOHANG)));
    try testing.expectEqual(start + n, fd.liveCount());
}

// ---- Child ----

const Exits = struct {
    code: u8,
    fn body(self: Exits) noreturn {
        proc.exit(self.code);
    }
};

const Killed = struct {
    fn body(_: Killed) noreturn {
        _ = linux.kill(linux.getpid(), linux.SIG.KILL);
        proc.exit(1);
    }
};

const Blocks = struct {
    r: fd.Fd(.pipe_r),
    fn body(self: Blocks) noreturn {
        var b: [1]u8 = undefined;
        _ = self.r.read(&b);
        proc.exit(0);
    }
};

test "Child: await's status and 128+n; peek leaves it; reapNow kills and reaps; release closes unreaped" {
    try testing.expectEqual(@as(u8, 7), try (try proc.fork(.{}, Exits{ .code = 7 }, Exits.body)).await());
    try testing.expectEqual(@as(u8, 128 + 9), try (try proc.fork(.{}, Killed{}, Killed.body)).await());

    const peeked = try proc.fork(.{}, Exits{ .code = 3 }, Exits.body);
    try testing.expectEqual(sys.Result(u8){ .ok = 3 }, peeked.peek());
    try testing.expectEqual(@as(u8, 3), try peeked.await());

    // A child blocked for good, killed and reaped: its pid is gone.
    const p = try newPipe();
    defer p.w.close();
    const blocked = try proc.fork(.{ .keep = &.{p.r.any()} }, Blocks{ .r = p.r }, Blocks.body);
    p.r.close();
    const pid = blocked.pid;
    blocked.reapNow(.kill);
    try testing.expectEqual(linux.E.SRCH, linux.E.init(linux.pidfd_open(pid, 0)));

    // Released: the pidfd closed, the child still ours to reap by pid.
    const start = fd.liveCount();
    const released = try proc.fork(.{}, Exits{ .code = 0 }, Exits.body);
    const rpid = released.pid;
    released.release();
    try testing.expectEqual(start, fd.liveCount());
    var si: linux.siginfo_t = undefined;
    try testing.expectEqual(linux.E.SUCCESS, linux.E.init(linux.waitid(.PID, rpid, &si, linux.W.EXITED)));
}

// ---- Spawn ----

test "Spawn: argv names exactly what the program holds (passFd, keepInherited)" {
    var gpa_buf: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&gpa_buf);
    const a = try opened(fd.openFile(fd.cwd, test_file, .{}, 0));
    defer a.close();
    const b = try opened(fd.openDir(fd.cwd, "/"));
    defer b.close();
    const not_passed = try opened(fd.openPath(fd.cwd, "/etc", .{}));
    defer not_passed.close();
    // A descriptor handed over, at a number the caller's own argv names.
    const rc = linux.open(test_file, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.E.init(rc));
    const inherited = try fd.adoptInherited(@intCast(rc));
    defer inherited.close();
    var s = try probeSpawn(fba.allocator());
    try s.passFd(a);
    try s.passFd(b);
    try s.keepInherited(inherited);
    var buf: [65536]u8 = undefined;
    const text = try runCapture(&s, &buf, 0);
    var sorted: [3]i32 = .{ a.raw(), b.raw(), inherited.raw() };
    std.mem.sort(i32, &sorted, {}, std.sort.asc(i32));
    var want_buf: [64]u8 = undefined;
    try testing.expectEqualStrings(try std.fmt.bufPrint(&want_buf, "0 1 2 {d} {d} {d}", .{ sorted[0], sorted[1], sorted[2] }), try field(text, "fds"));
    try testing.expectEqualStrings(try std.fmt.bufPrint(&want_buf, "{d} {d}", .{ a.raw(), b.raw() }), try field(text, "argv"));
}

/// The bits of a /proc/self/status mask line, "Key:\t<hex>".
fn statusMask(key: []const u8) !u64 {
    var buf: [65536]u8 = undefined;
    const rc = linux.open("/proc/self/status", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.E.init(rc) != .SUCCESS) return error.TestUnexpectedResult;
    const f: i32 = @intCast(rc);
    defer _ = linux.close(f);
    const got = linux.read(f, &buf, buf.len);
    if (linux.E.init(got) != .SUCCESS) return error.TestUnexpectedResult;
    const at = std.mem.indexOf(u8, buf[0..got], key) orelse return error.TestUnexpectedResult;
    const v = buf[at + key.len + 2 ..][0..16];
    return std.fmt.parseInt(u64, v, 16);
}

test "Spawn resets every disposition and the mask (Spawn skipping the signal reset)" {
    const old = switch (sys.sigprocmask(sys.SIG_BLOCK, sys.sigBit(sys.SIGTERM) | sys.sigBit(sys.SIGWINCH))) {
        .ok => |m| m,
        .err => return error.TestUnexpectedResult,
    };
    defer _ = sys.sigprocmask(sys.SIG_SETMASK, old);
    _ = sys.signal(sys.SIGUSR1, sys.sig_ign);
    defer _ = sys.signal(sys.SIGUSR1, sys.SIG.DFL);
    sig.ignorePipe();
    defer sig.defaultPipe();
    // The control: this process has them.
    const blk = sys.sigBit(sys.SIGTERM) | sys.sigBit(sys.SIGWINCH);
    const ign = sys.sigBit(sys.SIGUSR1) | sys.sigBit(sys.SIGPIPE);
    try testing.expectEqual(blk, try statusMask("SigBlk") & blk);
    try testing.expectEqual(ign, try statusMask("SigIgn") & ign);

    var mem: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&mem);
    var s = try probeSpawn(fba.allocator());
    var buf: [65536]u8 = undefined;
    const text = try runCapture(&s, &buf, 0);
    try testing.expectEqualStrings("0000000000000000", try field(text, "sigblk"));
    try testing.expectEqualStrings("0000000000000000", try field(text, "sigign"));
    try testing.expectEqualStrings("0000000000000000", try field(text, "sigcgt"));
}

test "Spawn: envp, dir, and the environment by default" {
    var mem: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&mem);
    var s = try probeSpawn(fba.allocator());
    const envp = [_:null]?[*:0]const u8{ "machine=demo", "B=2" };
    s.envp = &envp;
    s.dir = "/";
    var buf: [65536]u8 = undefined;
    var text = try runCapture(&s, &buf, 0);
    try testing.expectEqualStrings("machine=demo|B=2", try field(text, "env"));
    try testing.expectEqualStrings("/", try field(text, "cwd"));

    fba.reset();
    var d = try probeSpawn(fba.allocator());
    text = try runCapture(&d, &buf, 0);
    var want: [65536]u8 = undefined;
    var n: usize = 0;
    for (std.os.environ, 0..) |e, i| {
        // As the probe writes it: a newline in a value as "\\n".
        var it = std.mem.splitScalar(u8, std.mem.span(e), '\n');
        n += (try std.fmt.bufPrint(want[n..], "{s}{s}", .{ if (i == 0) "" else "|", it.first() })).len;
        while (it.next()) |more| n += (try std.fmt.bufPrint(want[n..], "\\n{s}", .{more})).len;
    }
    try testing.expectEqualStrings(want[0..n], try field(text, "env"));
}

test "Spawn: a child that cannot exec or chdir says why and exits 127" {
    findDriver();
    for ([_]struct { [*:0]const u8, ?[*:0]const u8, []const u8 }{
        .{ "/nonexistent/prog", null, "flong: exec /nonexistent/prog: No such file or directory\n" },
        .{ driver, "/nonexistent", "flong: chdir /nonexistent: No such file or directory\n" },
    }) |c| {
        var mem: [1024]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&mem);
        var s = try proc.Spawn.init(fba.allocator(), c[0]);
        s.dir = c[1];
        const err = try newPipe();
        defer err.r.close();
        s.stdio[2] = err.w.any();
        var buf: [256]u8 = undefined;
        _ = runCapture(&s, &buf, 127) catch |e| {
            err.w.close();
            return e;
        };
        err.w.close();
        var ebuf: [256]u8 = undefined;
        try testing.expectEqualStrings(c[2], try drain(err.r, &ebuf));
    }
}

/// The permutations of 0, 1, 2.
const perms = [_][3]u2{ .{ 0, 1, 2 }, .{ 0, 2, 1 }, .{ 1, 0, 2 }, .{ 1, 2, 0 }, .{ 2, 0, 1 }, .{ 2, 1, 0 } };

const Remap = struct {
    /// In a child whose 0-2 are three other files, every permutation of
    /// them as the probe's stdio, and each one alone with the rest
    /// inherited: the probe's 0-2 are what was asked.
    fn body(_: Remap) noreturn {
        for (0..3) |i| _ = linux.close(@intCast(i));
        const files = [3]fd.AnyFd{
            (opened(fd.openFile(fd.cwd, test_file, .{}, 0)) catch proc.exit(20)).any(),
            (opened(fd.openFile(fd.cwd, "/dev/null", .{}, 0)) catch proc.exit(20)).any(),
            (opened(fd.openDir(fd.cwd, "/")) catch proc.exit(20)).any(),
        };
        var ids: [3][2]u64 = undefined;
        for (files, 0..) |h, i| {
            if (h.raw() != i) proc.exit(21);
            // Stdio is not close-on-exec, as every open here is.
            _ = linux.fcntl(h.raw(), linux.F.SETFD, 0);
            var st: linux.Stat = undefined;
            _ = linux.fstat(h.raw(), &st);
            ids[i] = .{ st.dev, st.ino };
        }
        for (perms, 0..) |perm, k| {
            if (check(files, ids, .{ perm[0], perm[1], perm[2] }) catch proc.exit(22)) {} else proc.exit(@intCast(k + 1));
        }
        // One remapped, the others inherited.
        for (0..3) |i| {
            var want: [3]?u2 = .{ null, null, null };
            want[i] = @intCast((i + 1) % 3);
            if (check(files, ids, want) catch proc.exit(23)) {} else proc.exit(@intCast(10 + i));
        }
        proc.exit(0);
    }

    fn check(files: [3]fd.AnyFd, ids: [3][2]u64, want: [3]?u2) !bool {
        var mem: [1024]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&mem);
        var s = try proc.Spawn.init(fba.allocator(), driver);
        try s.arg("probe");
        try s.arg("--out");
        const p = try newPipe();
        defer p.r.close();
        try s.passFd(p.w);
        for (want, 0..) |w, i| s.stdio[i] = if (w) |j| files[j] else null;
        const child = s.start() catch {
            p.w.close();
            return error.Start;
        };
        p.w.close();
        var buf: [65536]u8 = undefined;
        const text = try drain(p.r, &buf);
        if ((try child.await()) != 0) return false;
        const line = try field(text, "stdio");
        var it = std.mem.tokenizeScalar(u8, line, ' ');
        for (0..3) |i| {
            const src = want[i] orelse @as(u2, @intCast(i));
            var exp: [64]u8 = undefined;
            const e = try std.fmt.bufPrint(&exp, "{d}:{d}", .{ ids[src][0], ids[src][1] });
            if (!std.mem.eql(u8, e, it.next() orelse return false)) return false;
        }
        return true;
    }
};

test "Spawn: stdio over every permutation of three sources at 0-2 (dup2 without staging)" {
    findDriver();
    const child = try proc.fork(.{}, Remap{}, Remap.body);
    try testing.expectEqual(@as(u8, 0), try child.await());
}

// ---- lockWait ----

const Locker = struct {
    path: [:0]const u8,
    ready: fd.Fd(.pipe_w),
    /// null: hold the lock 100 ms; else until this pipe's writers go
    hold: ?fd.Fd(.pipe_r),

    fn body(self: Locker) noreturn {
        const f = opened(fd.openFile(fd.cwd, self.path, .{}, 0)) catch proc.exit(1);
        if (f.flock(sys.LOCK.EX) != .ok) proc.exit(2);
        _ = self.ready.write("r");
        if (self.hold) |r| {
            var b: [1]u8 = undefined;
            _ = r.read(&b);
        } else {
            const ts: linux.timespec = .{ .sec = 0, .nsec = 100 * std.time.ns_per_ms };
            _ = linux.nanosleep(&ts, null);
        }
        proc.exit(0);
    }
};

fn lockFile(buf: []u8) ![:0]const u8 {
    const name = try std.fmt.bufPrintZ(buf, "proc-test-lock-{d}", .{linux.getpid()});
    const f = try opened(fd.openFile(fd.cwd, name, .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o600));
    f.close();
    return name;
}

test "lockWait: a free lock at once, a held one waited for, a terminating signal ends the wait" {
    var name_buf: [64]u8 = undefined;
    const name = try lockFile(&name_buf);
    defer _ = sys.unlinkat(sys.AT.FDCWD, name, 0);
    const mine = try opened(fd.openFile(fd.cwd, name, .{}, 0));
    defer mine.close();

    // Free: taken at once.
    try proc.lockWait(mine, sys.LOCK.EX);
    try testing.expect(mine.flock(sys.LOCK.UN) == .ok);

    // Held by another open for 100 ms: waited for.
    {
        const ready = try newPipe();
        defer ready.r.close();
        const holder = try proc.fork(.{ .keep = &.{ready.w.any()} }, Locker{ .path = name, .ready = ready.w, .hold = null }, Locker.body);
        ready.w.close();
        var b: [1]u8 = undefined;
        try testing.expect(ready.r.read(&b) == .ok);
        try testing.expect(mine.flock(sys.LOCK.EX | sys.LOCK.NB) == .err);
        try proc.lockWait(mine, sys.LOCK.EX);
        try testing.expectEqual(@as(u8, 0), try holder.await());
        // Taken, not just waited for: another open of the file is refused
        // it (a helper that exits without the lock returns here too).
        const other = try opened(fd.openFile(fd.cwd, name, .{}, 0));
        defer other.close();
        try testing.expect(other.flock(sys.LOCK.EX | sys.LOCK.NB) == .err);
        try testing.expect(mine.flock(sys.LOCK.UN) == .ok);
    }

    // Held for good; SIGTERM queued on the signalfd: the wait is aborted,
    // the helper killed and reaped.
    {
        const old = try sig.block();
        defer sig.setMask(old);
        try sig.openSignalfd();
        defer {
            sig.fd.?.close();
            sig.fd = null;
            sig.abort_signal = 0;
        }
        const ready = try newPipe();
        defer ready.r.close();
        const hold = try newPipe();
        const holder = try proc.fork(.{ .keep = &.{ ready.w.any(), hold.r.any() } }, Locker{ .path = name, .ready = ready.w, .hold = hold.r }, Locker.body);
        ready.w.close();
        hold.r.close();
        var b: [1]u8 = undefined;
        try testing.expect(ready.r.read(&b) == .ok);
        _ = linux.kill(linux.getpid(), linux.SIG.TERM);
        const start = fd.liveCount();
        try testing.expectError(error.Aborted, proc.lockWait(mine, sys.LOCK.EX));
        try testing.expectEqual(@as(u8, sys.SIGTERM), sig.abort_signal);
        try testing.expectEqual(start, fd.liveCount());
        // Killed, not released by closing `hold`: a holder that kept more
        // than it was given would never see that EOF.
        hold.w.close();
        holder.reapNow(.kill);
    }
}

// ---- signals ----

test "sig: the signalfd; take drops what it does not want and aborts on a terminating one; awaitFd looks at a signal first" {
    const old = try sig.block();
    defer sig.setMask(old);
    try sig.openSignalfd();
    defer {
        sig.fd.?.close();
        sig.fd = null;
        sig.abort_signal = 0;
    }
    try testing.expectEqual(false, try sig.take(0));
    _ = linux.kill(linux.getpid(), linux.SIG.WINCH);
    try testing.expectEqual(false, try sig.take(0));
    _ = linux.kill(linux.getpid(), linux.SIG.CONT);
    _ = linux.kill(linux.getpid(), linux.SIG.WINCH);
    try testing.expectEqual(true, try sig.take(sys.SIGWINCH));
    _ = linux.kill(linux.getpid(), linux.SIG.HUP);
    try testing.expectError(error.Aborted, sig.take(0));
    try testing.expectEqual(@as(u8, sys.SIGHUP), sig.abort_signal);
    sig.abort_signal = 0;

    // A ready descriptor and a terminating signal: the signal wins.
    const p = try newPipe();
    defer p.r.close();
    defer p.w.close();
    _ = p.w.write("x");
    _ = linux.kill(linux.getpid(), linux.SIG.INT);
    try testing.expectError(error.Aborted, sig.awaitFd(p.r, sys.POLL.IN));
    try testing.expectEqual(@as(u8, sys.SIGINT), sig.abort_signal);
    // And without one, the descriptor.
    try sig.awaitFd(p.r, sys.POLL.IN);
}

var signalfd_for_child: ?fd.Fd(.signalfd) = null;

const DropsSignalfd = struct {
    r: fd.Fd(.pipe_r),
    keeps: bool,

    fn body(self: DropsSignalfd) noreturn {
        if (sig.fd.?.isLive() != self.keeps) proc.exit(1);
        sig.awaitFd(self.r, sys.POLL.IN) catch proc.exit(2);
        proc.exit(0);
    }
};

test "a fork child drops a signalfd it does not keep, and its waits poll without it (a fork child keeping a stale signalfd)" {
    const old = try sig.block();
    defer sig.setMask(old);
    try sig.openSignalfd();
    defer {
        sig.fd.?.close();
        sig.fd = null;
    }
    const p = try newPipe();
    defer p.r.close();
    _ = p.w.write("x");
    p.w.close();
    for ([_]bool{ false, true }) |keeps| {
        const keep: []const fd.AnyFd = if (keeps) &.{ p.r.any(), sig.fd.?.any() } else &.{p.r.any()};
        const child = try proc.fork(.{ .keep = keep }, DropsSignalfd{ .r = p.r, .keeps = keeps }, DropsSignalfd.body);
        try testing.expectEqual(@as(u8, 0), try child.await());
    }
}

// ---- awaitFd's POLLHUP and POLLERR, bounded ----

/// A child's status within `ms` milliseconds, or error.Hung after it is
/// killed and reaped: the bound on a wait that a broken awaitFd would never
/// end (DESIGN.md, "Tests": the harness's kill bounds the hang).
fn awaitWithin(child: proc.Child, ms: i32) !u8 {
    var p = [1]sys.pollfd{.{ .fd = child.pidfd.raw(), .events = sys.POLL.IN, .revents = 0 }};
    const n = switch (sys.poll(&p, ms)) {
        .ok => |n| n,
        .err => return error.TestUnexpectedResult,
    };
    if (n == 0) {
        child.reapNow(.kill);
        return error.Hung;
    }
    return child.await();
}

const AwaitsEnd = struct {
    r: ?fd.Fd(.pipe_r) = null,
    w: ?fd.Fd(.pipe_w) = null,

    fn body(self: AwaitsEnd) noreturn {
        if (self.r) |r| sig.awaitFd(r, sys.POLL.IN) catch proc.exit(1);
        if (self.w) |w| sig.awaitFd(w, sys.POLL.IN) catch proc.exit(1);
        proc.exit(0);
    }
};

test "awaitFd: a pipe whose writers are gone (POLLHUP) and one whose readers are (POLLERR) are ready (awaitFd ignoring POLLHUP or POLLERR)" {
    {
        const p = try newPipe();
        p.w.close();
        const child = try proc.fork(.{ .keep = &.{p.r.any()} }, AwaitsEnd{ .r = p.r }, AwaitsEnd.body);
        p.r.close();
        try testing.expectEqual(@as(u8, 0), try awaitWithin(child, 10_000));
    }
    {
        const p = try newPipe();
        p.r.close();
        const child = try proc.fork(.{ .keep = &.{p.w.any()} }, AwaitsEnd{ .w = p.w }, AwaitsEnd.body);
        p.w.close();
        try testing.expectEqual(@as(u8, 0), try awaitWithin(child, 10_000));
    }
}

// ---- the property ----

const Held = union(enum) {
    file: fd.File,
    dir: fd.Dir,
    path: fd.Fd(.path),
    r: fd.Fd(.pipe_r),
    w: fd.Fd(.pipe_w),

    fn any(self: Held) fd.AnyFd {
        return switch (self) {
            inline else => |h| h.any(),
        };
    }
    fn close(self: Held) void {
        switch (self) {
            inline else => |h| h.close(),
        }
    }
    fn isLive(self: Held) bool {
        return switch (self) {
            inline else => |h| h.isLive(),
        };
    }
};

const Model = struct {
    held: [48]Held = undefined,
    nheld: usize = 0,
    dead: [256]Held = undefined,
    ndead: usize = 0,

    fn add(m: *Model, h: Held) void {
        m.held[m.nheld] = h;
        m.nheld += 1;
    }

    fn closeAt(m: *Model, i: usize) void {
        const h = m.held[i];
        if (m.ndead < m.dead.len) {
            m.dead[m.ndead] = h;
            m.ndead += 1;
        }
        h.close();
        m.held[i] = m.held[m.nheld - 1];
        m.nheld -= 1;
    }

    /// The handles bit i of `mask` picks, among the first eight held.
    fn pick(m: *const Model, mask: u16, out: []fd.AnyFd) []fd.AnyFd {
        var n: usize = 0;
        for (0..@min(m.nheld, 8)) |i| {
            if (mask & (@as(u16, 1) << @intCast(i)) != 0) {
                out[n] = m.held[i].any();
                n += 1;
            }
        }
        return out[0..n];
    }
};

var prop_baseline: KernelFds = undefined;
var prop_model: Model = .{};

const ForkCheck = struct {
    /// In the child: the kept ones are live, every other held one is
    /// stale, and the kernel holds nothing else from 3 up.
    fn body(_: ForkCheck) noreturn {
        const k = KernelFds.read() catch proc.exit(10);
        var kept: usize = 0;
        for (prop_model.held[0..prop_model.nheld]) |h| {
            if (h.isLive()) {
                kept += 1;
                if (!k.contains(h.any().raw())) proc.exit(11);
            }
        }
        var above: usize = 0;
        for (k.slice()) |n| above += @intFromBool(n >= 3);
        proc.exit(if (above == kept and fd.liveCount() == kept) 0 else 12);
    }
};

fn step(m: *Model, op: u16) !void {
    const arg = op / 8;
    switch (op % 8) {
        0 => if (m.nheld < m.held.len) m.add(.{ .file = try opened(fd.openFile(fd.cwd, test_file, .{}, 0)) }),
        1 => if (m.nheld < m.held.len) m.add(.{ .dir = try opened(fd.openDir(fd.cwd, "/")) }),
        2 => if (m.nheld < m.held.len) m.add(.{ .path = try opened(fd.openPath(fd.cwd, "/etc", .{})) }),
        3 => if (m.nheld + 2 <= m.held.len) {
            const p = try newPipe();
            m.add(.{ .r = p.r });
            m.add(.{ .w = p.w });
        },
        4, 5 => if (m.nheld > 0) m.closeAt(arg % m.nheld),
        6 => {
            var buf: [8]fd.AnyFd = undefined;
            const keep = m.pick(arg, &buf);
            const child = try proc.fork(.{ .keep = keep }, ForkCheck{}, ForkCheck.body);
            try testing.expectEqual(@as(u8, 0), try child.await());
        },
        7 => {
            var buf: [8]fd.AnyFd = undefined;
            const keep = m.pick(arg, &buf);
            var mem: [2048]u8 = undefined;
            var fba = std.heap.FixedBufferAllocator.init(&mem);
            var s = try probeSpawn(fba.allocator());
            for (keep) |h| try s.passFd(h);
            var out: [65536]u8 = undefined;
            const text = try runCapture(&s, &out, 0);
            // Held from 3 up: exactly what argv names.
            var held = std.mem.tokenizeScalar(u8, try field(text, "fds"), ' ');
            var above: [16]i32 = undefined;
            var na: usize = 0;
            while (held.next()) |t| {
                const v = try std.fmt.parseInt(i32, t, 10);
                if (v >= 3) {
                    above[na] = v;
                    na += 1;
                }
            }
            var named: [16]i32 = undefined;
            var nn: usize = 0;
            var words = std.mem.tokenizeScalar(u8, try field(text, "argv"), ' ');
            while (words.next()) |t| {
                named[nn] = try std.fmt.parseInt(i32, t, 10);
                nn += 1;
            }
            std.mem.sort(i32, named[0..nn], {}, std.sort.asc(i32));
            try testing.expectEqualSlices(i32, named[0..nn], above[0..na]);
        },
        else => unreachable,
    }
}

fn prop(ops: []const u16) !void {
    prop_model = .{};
    const m = &prop_model;
    const start = fd.liveCount();
    defer {
        while (m.nheld > 0) m.closeAt(m.nheld - 1);
        std.debug.assert(fd.liveCount() == start);
    }
    for (ops) |op| {
        try step(m, op);
        try expectKernelMatches(&prop_baseline);
        try testing.expectEqual(start + m.nheld, fd.liveCount());
        for (m.held[0..m.nheld]) |h| try testing.expect(h.isLive());
        for (m.dead[0..m.ndead]) |h| try testing.expect(!h.isLive());
    }
}

test "property: after any sequence of opens, closes, forks and spawns, table, model, kernel and children agree" {
    prop_baseline = try KernelFds.read();
    try testing.expectEqual(@as(usize, 0), fd.liveCount());
    try minish.check(testing.allocator, minish.gen.list(u16, minish.gen.int(u16), 0, 40), prop, .{ .num_runs = 150, .seed = 0x5105 });
    var seed: [8]u8 = undefined;
    _ = linux.getrandom(&seed, seed.len, 0);
    try minish.check(testing.allocator, minish.gen.list(u16, minish.gen.int(u16), 0, 40), prop, .{ .num_runs = 150, .seed = std.mem.readInt(u64, &seed, .little) });
    try expectKernelMatches(&prop_baseline);
}
