//! src/launch/prologue.zig from outside (the `test` step): canonical() over
//! a tree of directories, symlinks and missing tails, and its refusals;
//! protectPaths' order; cacheLock on a missing cache, one without
//! prepared/, one it locks, and one swept or replaced while it waits for a
//! sweep's exclusive lock (flong-record.c:91-149); relaunch's three ends,
//! its exec reaching the spawn probe (flong-proc, built for it) with
//! SIGPIPE default, the old mask and the inherited descriptors (quirk 2);
//! closeUntracked keeping the table's descriptors and nothing else.
//!
//! What would touch the test process's own descriptors, signals or stderr
//! runs in a forked child, its stdout and stderr on pipes.

const std = @import("std");
const linux = std.os.linux;
const sys = @import("sys");
const fd = @import("fd");
const msg = @import("msg");
const sig = @import("sig");
const proc = @import("proc");
const prologue = @import("prologue");
const options = @import("options");
const testing = std.testing;

// ---- helpers ----

fn opened(r: anytype) !@FieldType(@typeInfo(@TypeOf(r)).error_union.payload, "ok") {
    return switch (try r) {
        .ok => |h| h,
        .err => error.TestUnexpectedResult,
    };
}

fn ok(r: anytype) !void {
    switch (r) {
        .ok => {},
        .err => |e| {
            std.debug.print("unexpected errno {s}\n", .{@tagName(e)});
            return error.TestUnexpectedResult;
        },
    }
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

/// What a child printed, and its status.
const Captured = struct {
    status: u8,
    out: []const u8,
    err: []const u8,
    out_buf: [8192]u8 = undefined,
    err_buf: [8192]u8 = undefined,
};

fn InChild(comptime C: type, comptime body: fn (C) noreturn) type {
    return struct {
        ctx: C,
        out: fd.Fd(.pipe_w),
        err: fd.Fd(.pipe_w),

        fn run(self: @This()) noreturn {
            if (linux.E.init(linux.dup2(self.out.raw(), 1)) != .SUCCESS) proc.exit(99);
            if (linux.E.init(linux.dup2(self.err.raw(), 2)) != .SUCCESS) proc.exit(99);
            self.out.close();
            self.err.close();
            msg.prog = "flong-launch";
            msg.mode = .cut;
            body(self.ctx);
        }
    };
}

/// Runs `body(ctx)` in a forked child whose stdout and stderr are pipes,
/// as flong-launch (msg.prog), and returns what it printed and its status.
fn capture(c: *Captured, ctx: anytype, comptime body: fn (@TypeOf(ctx)) noreturn) !void {
    const o = try opened(fd.pipe());
    defer o.r.close();
    const e = try opened(fd.pipe());
    defer e.r.close();
    const W = InChild(@TypeOf(ctx), body);
    const child = proc.fork(.{ .keep = &.{ o.w.any(), e.w.any() } }, W{ .ctx = ctx, .out = o.w, .err = e.w }, W.run) catch |err| {
        o.w.close();
        e.w.close();
        return err;
    };
    o.w.close();
    e.w.close();
    c.out = try drain(o.r, &c.out_buf);
    c.err = try drain(e.r, &c.err_buf);
    c.status = child.await() catch |err| {
        child.reapNow(.kill);
        return err;
    };
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

/// A scratch directory under the test's own working directory, and its
/// absolute, canonical name (the kernel's, from /proc/self/cwd).
const Scratch = struct {
    rel: [:0]const u8,
    abs: [:0]const u8,
    rel_buf: [64]u8 = undefined,
    abs_buf: [4096]u8 = undefined,

    fn make(s: *Scratch, what: []const u8) !void {
        s.rel = try std.fmt.bufPrintZ(&s.rel_buf, "prologue-{s}-{d}", .{ what, linux.getpid() });
        try ok(sys.mkdirat(sys.AT.FDCWD, s.rel, 0o700));
        var cwd: [4096]u8 = undefined;
        const n = linux.readlink("/proc/self/cwd", &cwd, cwd.len);
        if (linux.E.init(n) != .SUCCESS) return error.TestUnexpectedResult;
        s.abs = try std.fmt.bufPrintZ(&s.abs_buf, "{s}/{s}", .{ cwd[0..n], s.rel });
    }

    /// `rel` under the scratch directory, relative to the working
    /// directory.
    fn at(s: *const Scratch, buf: []u8, rel: []const u8) ![:0]const u8 {
        return std.fmt.bufPrintZ(buf, "{s}/{s}", .{ s.rel, rel });
    }

    /// `rel` under the scratch directory, absolute.
    fn absAt(s: *const Scratch, buf: []u8, rel: []const u8) ![:0]const u8 {
        return std.fmt.bufPrintZ(buf, "{s}/{s}", .{ s.abs, rel });
    }

    /// Removes the tree (the tests make it at most a few levels deep).
    fn remove(s: *const Scratch) void {
        removeTree(sys.AT.FDCWD, s.rel);
    }
};

fn removeTree(dir: i32, name: [*:0]const u8) void {
    const rc = linux.openat(dir, name, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    if (linux.E.init(rc) == .SUCCESS) {
        const d: i32 = @intCast(rc);
        var buf: [4096]u8 align(8) = undefined;
        while (true) {
            const got = linux.getdents64(d, &buf, buf.len);
            if (linux.E.init(got) != .SUCCESS or got == 0) break;
            var it: fd.Entries = .{ .buf = buf[0..got] };
            var removed = false;
            while (it.next()) |e| {
                if (std.mem.eql(u8, e.name, ".") or std.mem.eql(u8, e.name, "..")) continue;
                var nb: [256]u8 = undefined;
                const n = std.fmt.bufPrintZ(&nb, "{s}", .{e.name}) catch continue;
                if (e.type == fd.Entries.dt_dir) removeTree(d, n) else _ = linux.unlinkat(d, n, 0);
                removed = true;
            }
            if (removed) _ = linux.lseek(d, 0, linux.SEEK.SET);
            if (!removed) break;
        }
        _ = linux.close(d);
        _ = linux.unlinkat(dir, name, linux.AT.REMOVEDIR);
    } else {
        _ = linux.unlinkat(dir, name, 0);
    }
}

fn symlink(target: [*:0]const u8, at: [*:0]const u8) !void {
    if (linux.E.init(linux.symlinkat(target, linux.AT.FDCWD, at)) != .SUCCESS) return error.TestUnexpectedResult;
}

fn mkdir(at: [*:0]const u8) !void {
    try ok(sys.mkdirat(sys.AT.FDCWD, at, 0o700));
}

fn touch(at: [*:0]const u8) !void {
    const f = try opened(fd.openFile(fd.cwd, at, .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true }, 0o600));
    f.close();
}

// ---- canonical and protectPaths ----

/// The tree canonical is tried over:
///   real/sub/        a directory
///   link -> real     a relative symlink to it
///   rootlink -> /    a symlink to the root
///   file             a regular file
///   dangling -> nowhere
///   loop -> loop     a symlink that never resolves
fn makeTree(s: *Scratch) !void {
    try s.make("canon");
    var b: [4096]u8 = undefined;
    try mkdir(try s.at(&b, "real"));
    try mkdir(try s.at(&b, "real/sub"));
    try symlink("real", try s.at(&b, "link"));
    try symlink("/", try s.at(&b, "rootlink"));
    try touch(try s.at(&b, "file"));
    try symlink("nowhere", try s.at(&b, "dangling"));
    try symlink("loop", try s.at(&b, "loop"));
}

fn expectCanonical(s: *const Scratch, given: []const u8, want: []const u8) !void {
    var gb: [4096]u8 = undefined;
    var wb: [4096]u8 = undefined;
    const g = try s.absAt(&gb, given);
    const w = if (want.len > 0 and want[0] == '/') want else try s.absAt(&wb, want);
    const got = try prologue.canonical(testing.allocator, g);
    defer testing.allocator.free(got);
    testing.expectEqualStrings(w, got) catch |err| {
        std.debug.print("canonical of {s}\n", .{g});
        return err;
    };
}

test "canonical resolves symlinks, and appends a missing tail to its longest existing prefix" {
    var s: Scratch = .{ .rel = "", .abs = "" };
    try makeTree(&s);
    defer s.remove();

    // What exists is the kernel's name for it.
    try expectCanonical(&s, "real/sub", "real/sub");
    try expectCanonical(&s, "link", "real");
    try expectCanonical(&s, "link/sub", "real/sub");
    try expectCanonical(&s, "link/../real/sub", "real/sub");
    try expectCanonical(&s, "file", "file");
    try expectCanonical(&s, "rootlink", "/");
    // A missing tail, kept as given after the canonical prefix.
    try expectCanonical(&s, "missing", "missing");
    try expectCanonical(&s, "real/sub/missing/deeper", "real/sub/missing/deeper");
    try expectCanonical(&s, "link/missing/deeper", "real/missing/deeper");
    try expectCanonical(&s, "link/sub/missing", "real/sub/missing");
    // A dangling symlink does not resolve: it is its own name under the
    // prefix, not its target's.
    try expectCanonical(&s, "dangling", "dangling");
    try expectCanonical(&s, "dangling/x", "dangling/x");
    // A prefix that is the root: no doubled slash, whether the root is
    // reached by the walk or through a symlink.
    try expectCanonical(&s, "rootlink/flong-prologue-missing/x", "/flong-prologue-missing/x");

    const top = "/flong-prologue-missing-top/a/b";
    const got = try prologue.canonical(testing.allocator, top);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(top, got);
    const root = try prologue.canonical(testing.allocator, "/");
    defer testing.allocator.free(root);
    try testing.expectEqualStrings("/", root);
}

test "protectPaths: the spec's paths, then the state directory, then the holder, each canonical" {
    var s: Scratch = .{ .rel = "", .abs = "" };
    try makeTree(&s);
    defer s.remove();
    var b: [4][4096]u8 = undefined;
    const protect = [_][:0]const u8{ try s.absAt(&b[0], "link/sub"), try s.absAt(&b[1], "link/socket-dir/s") };
    const state = try s.absAt(&b[2], "real");
    const holder = try s.absAt(&b[3], "link/holder.service");

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const got = try prologue.protectPaths(arena.allocator(), &protect, state, holder);
    var w: [4][4096]u8 = undefined;
    const want = [_][]const u8{
        try s.absAt(&w[0], "real/sub"),
        try s.absAt(&w[1], "real/socket-dir/s"),
        try s.absAt(&w[2], "real"),
        try s.absAt(&w[3], "real/holder.service"),
    };
    try testing.expectEqual(want.len, got.len);
    for (want, got) |x, y| try testing.expectEqualStrings(x, y);

    // No protect paths: the launcher's own two.
    const two = try prologue.protectPaths(arena.allocator(), &.{}, state, holder);
    try testing.expectEqual(@as(usize, 2), two.len);
    try testing.expectEqualStrings(want[2], two[0]);
}

const CanonicalOf = struct {
    path: [:0]const u8,

    fn body(self: CanonicalOf) noreturn {
        const got = prologue.canonical(std.heap.page_allocator, self.path) catch proc.exit(125);
        _ = fd.Stdio.out.writeAll(got);
        proc.exit(0);
    }
};

test "canonical refuses what is neither there nor missing, as realpath <path>: <strerror>" {
    var s: Scratch = .{ .rel = "", .abs = "" };
    try makeTree(&s);
    defer s.remove();
    var b: [4096]u8 = undefined;
    var want: [8192]u8 = undefined;
    var c: Captured = .{ .status = 0, .out = "", .err = "" };

    // A file on the way: ENOTDIR, not ENOENT, so no prefix is tried.
    const through_file = try s.absAt(&b, "file/x/y");
    try capture(&c, CanonicalOf{ .path = through_file }, CanonicalOf.body);
    try testing.expectEqual(@as(u8, 125), c.status);
    try testing.expectEqualStrings(try std.fmt.bufPrint(&want, "flong-launch: realpath {s}: Not a directory\n", .{through_file}), c.err);
    try testing.expectEqualStrings("", c.out);

    // A symlink loop: ELOOP, though its prefix resolves.
    const loop = try s.absAt(&b, "loop");
    try capture(&c, CanonicalOf{ .path = loop }, CanonicalOf.body);
    try testing.expectEqual(@as(u8, 125), c.status);
    try testing.expectEqualStrings(try std.fmt.bufPrint(&want, "flong-launch: realpath {s}: Too many levels of symbolic links\n", .{loop}), c.err);

    // A relative path with no '/' left to cut at: ENOENT, printed.
    try capture(&c, CanonicalOf{ .path = "flong-prologue-nothing-here" }, CanonicalOf.body);
    try testing.expectEqual(@as(u8, 125), c.status);
    try testing.expectEqualStrings("flong-launch: realpath flong-prologue-nothing-here: No such file or directory\n", c.err);

    // A relative path whose prefix exists resolves as the C's would.
    const rel = try s.at(&b, "link/missing");
    try capture(&c, CanonicalOf{ .path = rel }, CanonicalOf.body);
    try testing.expectEqual(@as(u8, 0), c.status);
    try testing.expectEqualStrings(try std.fmt.bufPrint(&want, "{s}/real/missing", .{s.abs}), c.out);
    try testing.expectEqualStrings("", c.err);
}

// ---- cacheLock ----

test "cacheLock: a missing cache and one without prepared/ are swept, and leave nothing open" {
    var s: Scratch = .{ .rel = "", .abs = "" };
    try s.make("cache-swept");
    defer s.remove();
    var b: [4096]u8 = undefined;
    const before = fd.liveCount();

    try testing.expectEqual(prologue.CacheLock.swept, try prologue.cacheLock(try s.at(&b, "missing")));
    try testing.expectEqual(before, fd.liveCount());

    const cache = try s.at(&b, "cache");
    try mkdir(cache);
    try testing.expectEqual(prologue.CacheLock.swept, try prologue.cacheLock(cache));
    try testing.expectEqual(before, fd.liveCount());
}

test "cacheLock: a cache with prepared/ is locked shared and held" {
    var s: Scratch = .{ .rel = "", .abs = "" };
    try s.make("cache-locked");
    defer s.remove();
    var b: [4096]u8 = undefined;
    var pb: [4096]u8 = undefined;
    const cache = try s.at(&b, "cache");
    try mkdir(cache);
    try mkdir(try s.at(&pb, "cache/prepared"));
    // Through a symlink, as the C's open follows one.
    var lb: [4096]u8 = undefined;
    const link = try s.at(&lb, "link");
    try symlink("cache", link);

    const before = fd.liveCount();
    const got = try prologue.cacheLock(link);
    try testing.expect(got == .locked);
    try testing.expect(got.locked.isLive());
    try testing.expectEqual(before + 1, fd.liveCount());

    // Another open of it may share the lock, and may not take it alone.
    const other = try opened(fd.openDir(fd.cwd, cache));
    defer other.close();
    try testing.expectEqual(sys.Result(void){ .err = .AGAIN }, other.flock(sys.LOCK.EX | sys.LOCK.NB));
    try testing.expectEqual(sys.Result(void){ .ok = {} }, other.flock(sys.LOCK.SH | sys.LOCK.NB));
    // The held descriptor stays until the process exits (flong-launch.c:55).
}

const CacheLockOf = struct {
    path: [:0]const u8,

    fn body(self: CacheLockOf) noreturn {
        const got = prologue.cacheLock(self.path) catch proc.exit(125);
        proc.exit(if (got == .swept) 75 else 0);
    }
};

test "cacheLock refuses a cache it cannot open, as cache <path>: <strerror>" {
    var s: Scratch = .{ .rel = "", .abs = "" };
    try s.make("cache-file");
    defer s.remove();
    var b: [4096]u8 = undefined;
    const file = try s.at(&b, "cache");
    try touch(file);
    var c: Captured = .{ .status = 0, .out = "", .err = "" };
    try capture(&c, CacheLockOf{ .path = file }, CacheLockOf.body);
    try testing.expectEqual(@as(u8, 125), c.status);
    var want: [8192]u8 = undefined;
    try testing.expectEqualStrings(try std.fmt.bufPrint(&want, "flong-launch: cache {s}: Not a directory\n", .{file}), c.err);
}

/// A sweep of a superseded cache: holds the cache's lock exclusively, says
/// so on `ready`, waits until a lock request on it is blocked (so the
/// launch has opened what the path names now), then does `what` and exits,
/// which lets the lock go.
const Sweep = struct {
    cache: [:0]const u8,
    moved: [:0]const u8,
    ready: fd.Fd(.pipe_w),
    what: enum { release, rename, replace },

    fn body(self: Sweep) noreturn {
        const rc = linux.open(self.cache, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
        if (linux.E.init(rc) != .SUCCESS) proc.exit(10);
        const d: i32 = @intCast(rc);
        if (linux.E.init(linux.flock(d, sys.LOCK.EX)) != .SUCCESS) proc.exit(11);
        var st: linux.Stat = undefined;
        if (linux.E.init(linux.fstat(d, &st)) != .SUCCESS) proc.exit(12);
        if (self.ready.write("l") != .ok) proc.exit(13);
        self.ready.close();
        if (!awaitBlocked(st.ino)) proc.exit(14);
        switch (self.what) {
            .release => {},
            .rename, .replace => if (linux.E.init(linux.rename(self.cache, self.moved)) != .SUCCESS) proc.exit(15),
        }
        if (self.what == .replace) {
            if (linux.E.init(linux.mkdir(self.cache, 0o700)) != .SUCCESS) proc.exit(16);
            var pb: [4096]u8 = undefined;
            const p = std.fmt.bufPrintZ(&pb, "{s}/prepared", .{self.cache}) catch proc.exit(17);
            if (linux.E.init(linux.mkdir(p, 0o700)) != .SUCCESS) proc.exit(18);
        }
        proc.exit(0);
    }

    /// Whether /proc/locks shows a blocked request ("->") on inode `ino`
    /// within 10 s.
    fn awaitBlocked(ino: u64) bool {
        var needle_buf: [32]u8 = undefined;
        const needle = std.fmt.bufPrint(&needle_buf, ":{d} ", .{ino}) catch return false;
        var tries: usize = 0;
        while (tries < 1000) : (tries += 1) {
            var buf: [65536]u8 = undefined;
            const rc = linux.open("/proc/locks", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
            if (linux.E.init(rc) != .SUCCESS) return false;
            const f: i32 = @intCast(rc);
            var n: usize = 0;
            while (n < buf.len) {
                const got = linux.read(f, buf[n..].ptr, buf.len - n);
                if (linux.E.init(got) != .SUCCESS or got == 0) break;
                n += got;
            }
            _ = linux.close(f);
            var lines = std.mem.splitScalar(u8, buf[0..n], '\n');
            while (lines.next()) |l| {
                if (std.mem.indexOf(u8, l, "->") != null and std.mem.indexOf(u8, l, needle) != null) return true;
            }
            const ts: linux.timespec = .{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
            _ = linux.nanosleep(&ts, null);
        }
        return false;
    }
};

fn lockDuringSweep(what: @FieldType(Sweep, "what")) !prologue.CacheLock {
    var s: Scratch = .{ .rel = "", .abs = "" };
    try s.make("cache-sweep");
    defer s.remove();
    var b: [4096]u8 = undefined;
    var mb: [4096]u8 = undefined;
    var pb: [4096]u8 = undefined;
    const cache = try s.at(&b, "cache");
    try mkdir(cache);
    try mkdir(try s.at(&pb, "cache/prepared"));
    const p = try opened(fd.pipe());
    defer p.r.close();
    const sweep = Sweep{ .cache = cache, .moved = try s.at(&mb, "moved"), .ready = p.w, .what = what };
    const child = proc.fork(.{ .keep = &.{p.w.any()} }, sweep, Sweep.body) catch |err| {
        p.w.close();
        return err;
    };
    p.w.close();
    var one: [1]u8 = undefined;
    try testing.expectEqual(sys.Result(usize){ .ok = 1 }, p.r.read(&one));
    const got = prologue.cacheLock(cache) catch |err| {
        child.reapNow(.kill);
        return err;
    };
    try testing.expectEqual(@as(u8, 0), try child.await());
    return got;
}

test "cacheLock waits out a sweep's exclusive lock: locked when the cache stays" {
    const got = try lockDuringSweep(.release);
    try testing.expect(got == .locked);
}

test "cacheLock: swept when the sweep renamed the cache away while it waited" {
    try testing.expectEqual(prologue.CacheLock.swept, try lockDuringSweep(.rename));
}

test "cacheLock: swept when another cache, prepared, took the name while it waited" {
    try testing.expectEqual(prologue.CacheLock.swept, try lockDuringSweep(.replace));
}

// ---- relaunch ----

/// flong-proc, built beside this test: its path made absolute.
var driver_buf: [std.fs.max_path_bytes:0]u8 = undefined;
var driver: [:0]const u8 = "";

fn findDriver() void {
    if (driver.len > 0) return;
    const p = std.fs.cwd().realpath(options.driver, &driver_buf) catch @panic("flong-proc not found");
    driver_buf[p.len] = 0;
    driver = driver_buf[0..p.len :0];
}

const Relaunch = struct {
    argv: []const [:0]const u8,
    /// set to the inherited descriptor's number, printed first on stdout
    inherited: bool = false,

    fn body(self: Relaunch) noreturn {
        // The caller's mask: SIGUSR1 blocked. The prologue's step 1 then
        // blocks its six and ignores SIGPIPE.
        _ = sys.sigprocmask(sys.SIG_SETMASK, sys.sigBit(sys.SIGUSR1));
        const old = sig.block() catch proc.exit(98);
        sig.ignorePipe();
        // A descriptor the wrapper held, not close-on-exec, and one of the
        // launcher's own, close-on-exec, as the state directory is.
        if (self.inherited) {
            const rc = linux.open("/etc/passwd", .{ .ACCMODE = .RDONLY }, 0);
            if (linux.E.init(rc) != .SUCCESS) proc.exit(97);
            var nb: [16]u8 = undefined;
            const line = std.fmt.bufPrint(&nb, "{d}\n", .{rc}) catch proc.exit(96);
            _ = fd.Stdio.out.writeAll(line);
            const own = opened(fd.openDir(fd.cwd, "/")) catch proc.exit(95);
            _ = own.holdUntilExit();
        }
        proc.exit(prologue.relaunch(std.heap.page_allocator, "/c/cache", self.argv, old, @ptrCast(std.os.environ.ptr)));
    }
};

test "relaunch with no argv: 75, said, nothing run" {
    var c: Captured = .{ .status = 0, .out = "", .err = "" };
    try capture(&c, Relaunch{ .argv = &.{} }, Relaunch.body);
    try testing.expectEqual(@as(u8, 75), c.status);
    try testing.expectEqualStrings("flong-launch: the cache /c/cache was swept before this launch locked it\n", c.err);
    try testing.expectEqualStrings("", c.out);
}

test "relaunch execs the wrapper with SIGPIPE default, the old mask and the inherited descriptors (quirk 2)" {
    findDriver();
    var c: Captured = .{ .status = 0, .out = "", .err = "" };
    try capture(&c, Relaunch{ .argv = &.{ driver, "probe", "again" }, .inherited = true }, Relaunch.body);
    try testing.expectEqual(@as(u8, 0), c.status);
    try testing.expectEqualStrings("flong-launch: the cache /c/cache was swept before this launch locked it; relaunching\n", c.err);

    const nl = std.mem.indexOfScalar(u8, c.out, '\n') orelse return error.TestUnexpectedResult;
    const inherited = c.out[0..nl];
    const probe = c.out[nl + 1 ..];
    try testing.expectEqualStrings("again", try field(probe, "argv"));
    // 0-2 and the wrapper's descriptor; the launcher's own went with the
    // exec.
    var want: [64]u8 = undefined;
    try testing.expectEqualStrings(try std.fmt.bufPrint(&want, "0 1 2 {s}", .{inherited}), try field(probe, "fds"));
    // The mask the launcher started with, SIGUSR1 alone (bit 9).
    try testing.expectEqualStrings("0000000000000200", try field(probe, "sigblk"));
    // SIGPIPE (bit 12) not ignored.
    const ign = try std.fmt.parseInt(u64, try field(probe, "sigign"), 16);
    try testing.expectEqual(@as(u64, 0), ign & (1 << 12));
}

test "relaunch whose exec fails: 125, both lines said" {
    var c: Captured = .{ .status = 0, .out = "", .err = "" };
    try capture(&c, Relaunch{ .argv = &.{ "/nonexistent-flong/wrapper", "x" } }, Relaunch.body);
    try testing.expectEqual(@as(u8, 125), c.status);
    try testing.expectEqualStrings(
        "flong-launch: the cache /c/cache was swept before this launch locked it; relaunching\n" ++
            "flong-launch: exec /nonexistent-flong/wrapper: No such file or directory\n",
        c.err,
    );
}

// ---- closeUntracked ----

const Untracked = struct {
    fn body(_: Untracked) noreturn {
        // Interleaved: untracked, tracked, untracked (not close-on-exec),
        // tracked, untracked, so every gap is a close_range of its own and
        // the last reaches ~0U.
        const un1 = rawOpen(true);
        const a = opened(fd.openFile(fd.cwd, "/etc/passwd", .{}, 0)) catch proc.exit(90);
        const un2 = rawOpen(false);
        const d = opened(fd.openDir(fd.cwd, "/")) catch proc.exit(91);
        const un3 = rawOpen(true);
        // One far above the rest.
        const high = linux.dup2(un3, 900);
        if (linux.E.init(high) != .SUCCESS) proc.exit(92);
        const live = fd.liveCount();

        prologue.closeUntracked() catch proc.exit(93);

        // Every handle still live, none added or dropped.
        if (!a.isLive() or !d.isLive() or fd.liveCount() != live) proc.exit(94);
        // The kernel holds 0-2 and the table's, nothing else.
        var tbl: [fd.capacity]sys.fd_t = undefined;
        const kept = fd.snapshot(&tbl);
        const k = kernelFds() orelse proc.exit(95);
        var n: usize = 0;
        for (k.fds[0..k.n]) |v| {
            if (v <= 2) continue;
            if (std.mem.indexOfScalar(sys.fd_t, kept, v) == null) {
                var b: [64]u8 = undefined;
                _ = fd.Stdio.out.writeAll(std.fmt.bufPrint(&b, "left open: {d}\n", .{v}) catch "left open\n");
                proc.exit(1);
            }
            n += 1;
        }
        if (n != kept.len) proc.exit(2);
        for ([_]i32{ un1, un2, un3, 900 }) |u| {
            if (std.mem.indexOfScalar(i32, k.fds[0..k.n], u) != null) proc.exit(3);
        }
        // The file still reads.
        var one: [1]u8 = undefined;
        if (a.read(&one) != .ok) proc.exit(4);
        proc.exit(0);
    }

    fn rawOpen(cloexec: bool) i32 {
        const rc = linux.open("/etc/passwd", .{ .ACCMODE = .RDONLY, .CLOEXEC = cloexec }, 0);
        if (linux.E.init(rc) != .SUCCESS) proc.exit(89);
        return @intCast(rc);
    }

    const Fds = struct { fds: [256]i32 = undefined, n: usize = 0 };

    fn kernelFds() ?Fds {
        const rc = linux.open("/proc/self/fd", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
        if (linux.E.init(rc) != .SUCCESS) return null;
        const dir: i32 = @intCast(rc);
        defer _ = linux.close(dir);
        var k: Fds = .{};
        var buf: [4096]u8 align(8) = undefined;
        while (true) {
            const got = linux.getdents64(dir, &buf, buf.len);
            if (linux.E.init(got) != .SUCCESS) return null;
            if (got == 0) break;
            var it: fd.Entries = .{ .buf = buf[0..got] };
            while (it.next()) |e| {
                const v = std.fmt.parseInt(i32, e.name, 10) catch continue;
                if (v == dir or k.n == k.fds.len) continue;
                k.fds[k.n] = v;
                k.n += 1;
            }
        }
        return k;
    }
};

test "closeUntracked keeps the table's descriptors and 0-2, and closes every other" {
    var c: Captured = .{ .status = 0, .out = "", .err = "" };
    try capture(&c, Untracked{}, Untracked.body);
    testing.expectEqual(@as(u8, 0), c.status) catch |err| {
        std.debug.print("{s}{s}", .{ c.out, c.err });
        return err;
    };
    try testing.expectEqualStrings("", c.err);
}
