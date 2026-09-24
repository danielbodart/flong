//! The launch's halves of record.zig and cgroup.zig in the build sandbox
//! (the Zig port's L2; DESIGN.md, "Tests": the record contract, and
//! ordering checkpoint 10):
//!
//!   - the writer's bytes are tests/golden/records/'s, with and without
//!     postStop, leader= appended at the offset, while the record is
//!     unnamed-then-linked, locked, mode 0600; removed, it is gone
//!   - a name taken: by a live record (refused), a malformed one (quirk 5,
//!     refused, and dropped), an ended one (released, and the name taken),
//!     not a regular file (refused); a newline in a value, a record too long;
//!     taken again during the lock wait (the loop has no count)
//!   - the cache lock: absent, without the prepared root, locked, not a
//!     directory
//!   - the session made, its duplicate refused, a controller the holder
//!     lacks refused, and a failure after the session's mkdir undone
//!
//! A holder here is any directory of the caller's, named in messages by a
//! cgroup path it is not: nothing below needs cgroupfs but the files it
//! reads, which the tests make. What each refusal says is read from
//! stderr, captured around the call.

const std = @import("std");
const linux = std.os.linux;
const sys = @import("sys");
const fd = @import("fd");
const msg = @import("msg");
const proc = @import("proc");
const cgroup = @import("cgroup");
const record = @import("record");
const options = @import("options");
const testing = std.testing;

// ---- the fixture ----

/// A scratch directory, its absolute path, a state directory with
/// sessions/ (record.stateOpen's), and a holder.
const Fixture = struct {
    tmp: testing.TmpDir,
    root: []u8,
    state: record.State,
    holder: cgroup.Holder,

    fn init(holder_path: []const u8) !Fixture {
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();
        const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
        errdefer testing.allocator.free(root);
        try tmp.dir.makeDir("state");
        try tmp.dir.makeDir("holder");
        try std.posix.fchmodat(tmp.dir.fd, "state", 0o700, 0);
        const state_path = try std.fmt.allocPrintSentinel(testing.allocator, "{s}/state", .{root}, 0);
        defer testing.allocator.free(state_path);
        const state = try record.stateOpen(state_path);
        const hdir = try std.fmt.allocPrintSentinel(testing.allocator, "{s}/holder", .{root}, 0);
        defer testing.allocator.free(hdir);
        const h = switch (try fd.openCgroup(fd.cwd, hdir)) {
            .ok => |h| h,
            .err => return error.Unexpected,
        };
        return .{
            .tmp = tmp,
            .root = root,
            .state = state,
            .holder = .{ .path = cgroup.Path.of(&.{holder_path}).?, .fd = h.holdUntilExit() },
        };
    }

    /// The Held descriptors stay open, as they would in the launcher; the
    /// directory goes.
    fn deinit(self: *Fixture) void {
        testing.allocator.free(self.root);
        self.tmp.cleanup();
    }

    fn sessions(self: *Fixture) std.fs.Dir {
        return self.tmp.dir.openDir("state/sessions", .{}) catch unreachable; // proven: stateOpen made it
    }
};

/// What the code under test says on stderr (fd 2) between `start` and
/// `stop`, through a pipe.
const Said = struct {
    saved: i32,
    r: i32,
    buf: [8192]u8 = undefined,
    len: usize = 0,

    fn start() Said {
        var p: [2]i32 = undefined;
        std.debug.assert(linux.pipe2(&p, .{ .CLOEXEC = true }) == 0);
        const saved: i32 = @intCast(linux.fcntl(2, sys.F_DUPFD_CLOEXEC, 10));
        _ = linux.dup2(p[1], 2);
        _ = linux.close(p[1]);
        return .{ .saved = saved, .r = p[0] };
    }

    fn stop(self: *Said) []const u8 {
        _ = linux.dup2(self.saved, 2);
        _ = linux.close(self.saved);
        while (self.len < self.buf.len) {
            const n = linux.read(self.r, self.buf[self.len..].ptr, self.buf.len - self.len);
            if (@as(isize, @bitCast(n)) <= 0) break;
            self.len += n;
        }
        _ = linux.close(self.r);
        return self.buf[0..self.len];
    }
};

fn readFile(dir: std.fs.Dir, name: []const u8) ![]u8 {
    return dir.readFileAlloc(testing.allocator, name, 1 << 16);
}

/// tests/golden/records/<name> with each @VAR@ replaced, as basic.nix's
/// golden_record does.
fn golden(name: []const u8, vars: []const [2][]const u8) ![]u8 {
    var dir = try std.fs.openDirAbsolute(options.records, .{});
    defer dir.close();
    var text = try readFile(dir, name);
    for (vars) |v| {
        const key = try std.fmt.allocPrint(testing.allocator, "@{s}@", .{v[0]});
        defer testing.allocator.free(key);
        const next = try std.mem.replaceOwned(u8, testing.allocator, text, key, v[1]);
        testing.allocator.free(text);
        text = next;
    }
    try testing.expect(std.mem.indexOfScalar(u8, text, '@') == null);
    return text;
}

// ---- the writer ----

test "the record's bytes are tests/golden/records/, locked, linked, removed" {
    msg.prog = "flong-launch";
    var fx = try Fixture.init("/sys/fs/cgroup/h");
    defer fx.deinit();
    const live = fd.liveCount();
    const pid: sys.pid_t = linux.getpid();
    const pid_text = try std.fmt.allocPrint(testing.allocator, "{d}", .{pid});
    defer testing.allocator.free(pid_text);
    const start_text = try std.fmt.allocPrint(testing.allocator, "{d}", .{proc.starttime(pid)});
    defer testing.allocator.free(start_text);
    try testing.expect(proc.starttime(pid) != 0);

    for ([_]struct { name: []const u8, machine: [:0]const u8, poststop: ?[]const u8 }{
        .{ .name = "poststop", .machine = "demo-1", .poststop = "/nix/store/aaaa-flong-poststop/bin/poststop" },
        .{ .name = "no-poststop", .machine = "m", .poststop = null },
    }) |c| {
        const cg = try std.fmt.allocPrint(testing.allocator, "/sys/fs/cgroup/h/c/{s}", .{c.machine});
        defer testing.allocator.free(cg);
        var rec = try record.create(fx.state.sessions, &fx.holder, c.machine, c.poststop, cg);
        var dir = fx.sessions();
        defer dir.close();

        // Before leader=: what rec_create wrote, poststop= and cgroup=.
        const before = try readFile(dir, c.machine);
        defer testing.allocator.free(before);
        const want_before = try std.fmt.allocPrint(testing.allocator, "{s}{s}{s}cgroup={s}\n", .{
            if (c.poststop != null) "poststop=" else "", c.poststop orelse "", if (c.poststop != null) "\n" else "", cg,
        });
        defer testing.allocator.free(want_before);
        try testing.expectEqualStrings(want_before, before);

        // Linked once, mode 0600, and locked: another open's LOCK_NB fails.
        const st = try dir.statFile(c.machine);
        try testing.expectEqual(@as(u32, 0o600), @as(u32, @intCast(st.mode & 0o7777)));
        var other = try dir.openFile(c.machine, .{});
        try testing.expect(!try other.tryLock(.exclusive));
        other.close();

        // leader= at the offset, after the rest.
        try rec.setLeader(pid);
        const got = try readFile(dir, c.machine);
        defer testing.allocator.free(got);
        const want = try golden(c.name, &.{ .{ "POSTSTOP", c.poststop orelse "" }, .{ "CGROUP", cg }, .{ "PID", pid_text }, .{ "START", start_text } });
        defer testing.allocator.free(want);
        try testing.expectEqualStrings(want, got);
        // And the sweep reads it as the C's writer's.
        var f: record.Fields = .{};
        try testing.expectEqual(@as(?[]const u8, null), record.parse(got, &f));
        try testing.expectEqual(pid, f.leader);

        // postStop done: the line blanked, the rest as it was.
        if (c.poststop != null) {
            try rec.poststopDone();
            const blanked = try readFile(dir, c.machine);
            defer testing.allocator.free(blanked);
            const nl = std.mem.indexOfScalar(u8, want, '\n').? + 1;
            for (blanked[0..nl]) |b| try testing.expectEqual(@as(u8, '\n'), b);
            try testing.expectEqualStrings(want[nl..], blanked[nl..]);
        }

        // Removed: unlinked, then closed.
        rec.remove();
        try testing.expectError(error.FileNotFound, dir.statFile(c.machine));
    }
    // Nothing but the held directories is left open.
    try testing.expectEqual(live, fd.liveCount());
}

test "a record closed without its unlink stays, and its lock is free" {
    var fx = try Fixture.init("/sys/fs/cgroup/h");
    defer fx.deinit();
    var rec = try record.create(fx.state.sessions, &fx.holder, "kept", null, "/sys/fs/cgroup/h/c/kept");
    rec.closeKeeping();
    var dir = fx.sessions();
    defer dir.close();
    var f = try dir.openFile("kept", .{});
    defer f.close();
    try testing.expect(try f.tryLock(.exclusive));
}

// ---- a name taken ----

/// record.create's refusal, said and returned.
fn refused(fx: *Fixture, machine: [:0]const u8, post_stop: ?[]const u8, cg: []const u8) ![]u8 {
    var said = Said.start();
    const r = record.create(fx.state.sessions, &fx.holder, machine, post_stop, cg);
    const text = said.stop();
    if (r) |rec| {
        var kept = rec;
        kept.remove();
        return error.NotRefused;
    } else |err| try testing.expectEqual(error.Reported, err);
    return testing.allocator.dupe(u8, text);
}

test "a name taken: running, malformed, ended, not a file; a newline; too long" {
    msg.prog = "flong-launch";
    var fx = try Fixture.init("/sys/fs/cgroup/h");
    defer fx.deinit();
    const live_count = fd.liveCount();
    var dir = fx.sessions();
    defer dir.close();

    // A live launcher's record, no leader= yet: refused, and left.
    var live = try record.create(fx.state.sessions, &fx.holder, "m", null, "/sys/fs/cgroup/h/c/m");
    {
        const said = try refused(&fx, "m", null, "/sys/fs/cgroup/h/c/m");
        defer testing.allocator.free(said);
        try testing.expectEqualStrings("flong-launch: a session named m is already running\n", said);
    }
    live.remove();

    // A malformed record under the name: the sweep drops it, and the
    // launch is refused though the name is then free (quirk 5, kept).
    try dir.writeFile(.{ .sub_path = "m", .data = "x=1\n" });
    {
        const said = try refused(&fx, "m", null, "/sys/fs/cgroup/h/c/m");
        defer testing.allocator.free(said);
        try testing.expectEqualStrings("flong-launch: the record of m is removed: it has an unknown, repeated or misplaced line\n" ++
            "flong-launch: a session named m has ended but cannot be released yet\n", said);
    }
    try testing.expectError(error.FileNotFound, dir.statFile("m"));

    // An ended session's record, unlocked, its cgroup gone and its leader
    // not the recorded process: released, and the name taken.
    try dir.writeFile(.{ .sub_path = "m", .data = "cgroup=/sys/fs/cgroup/h/c/m\nleader=1:1\n" });
    var taken = try record.create(fx.state.sessions, &fx.holder, "m", null, "/sys/fs/cgroup/h/c/m");
    {
        const got = try readFile(dir, "m");
        defer testing.allocator.free(got);
        try testing.expectEqualStrings("cgroup=/sys/fs/cgroup/h/c/m\n", got);
    }
    taken.remove();

    // Not a regular file under the name: left, refused.
    try dir.makeDir("d");
    {
        const said = try refused(&fx, "d", null, "/sys/fs/cgroup/h/c/d");
        defer testing.allocator.free(said);
        try testing.expectEqualStrings("flong-launch: a session named d has ended but cannot be released yet\n", said);
    }

    // A newline in either value, and a record past REC_MAX.
    {
        const said = try refused(&fx, "n", "/nix/store/x\nleader=1:1", "/sys/fs/cgroup/h/c/n");
        defer testing.allocator.free(said);
        try testing.expectEqualStrings("flong-launch: a newline is in the postStop path or the cgroup path of n\n", said);
    }
    {
        const said = try refused(&fx, "n", null, "/sys/fs/cgroup/h/c/n\n");
        defer testing.allocator.free(said);
        try testing.expectEqualStrings("flong-launch: a newline is in the postStop path or the cgroup path of n\n", said);
    }
    {
        // "cgroup=" + value + "\n" is REC_MAX bytes: with its NUL, one too
        // many; one byte shorter fits.
        const long = try testing.allocator.alloc(u8, record.rec_max - "cgroup=\n".len);
        defer testing.allocator.free(long);
        @memset(long, 'a');
        const said = try refused(&fx, "n", null, long);
        defer testing.allocator.free(said);
        try testing.expectEqualStrings("flong-launch: the record of n is too long\n", said);
        var fits = try record.create(fx.state.sessions, &fx.holder, "n", null, long[1..]);
        fits.remove();
    }
    try testing.expectEqual(live_count, fd.liveCount());
}

/// The other side of the test below, on a thread: once a lock helper of
/// this process is blocked in flock(2) on the ended record `held` locks,
/// that record's name is given to another ended record, and `held` let go.
/// Every wait is for a state; the bound only keeps a broken run finite.
const Swap = struct {
    dir: std.fs.Dir,
    held: std.fs.File,
    parent: i32,
    swapped: bool = false,

    fn run(self: *Swap) void {
        // 1. Until the helper proc.lockWait forks waits on the lock.
        var turns: usize = 0;
        while (!lockHelperWaiting(self.parent)) : (turns += 1) {
            if (turns == 60_000) break;
            std.Thread.sleep(std.time.ns_per_ms);
        } else {
            // 2. The name taken by another ended record, unlocked.
            if (self.dir.deleteFile("m")) {
                if (self.dir.writeFile(.{ .sub_path = "m", .data = "cgroup=/sys/fs/cgroup/h/c/m\nleader=1:1\n" })) {
                    self.swapped = true;
                } else |_| {}
            } else |_| {}
        }
        // 3. The first record let go: the helper takes its lock.
        self.held.close();
    }

    /// Whether a child of `parent` is in flock(2), by /proc/<pid>/stat's
    /// ppid and /proc/<pid>/syscall's number.
    fn lockHelperWaiting(parent: i32) bool {
        var procs = std.fs.openDirAbsolute("/proc", .{ .iterate = true }) catch return false;
        defer procs.close();
        var it = procs.iterate();
        while (it.next() catch return false) |e| {
            _ = std.fmt.parseUnsigned(i32, e.name, 10) catch continue;
            var buf: [512]u8 = undefined;
            var path: [64]u8 = undefined;
            const stat = procs.readFile(std.fmt.bufPrint(&path, "{s}/stat", .{e.name}) catch continue, &buf) catch continue;
            const close = std.mem.lastIndexOfScalar(u8, stat, ')') orelse continue;
            var f = std.mem.tokenizeScalar(u8, stat[close + 1 ..], ' ');
            _ = f.next();
            const ppid = std.fmt.parseUnsigned(i32, f.next() orelse continue, 10) catch continue;
            if (ppid != parent) continue;
            const call = procs.readFile(std.fmt.bufPrint(&path, "{s}/syscall", .{e.name}) catch continue, &buf) catch continue;
            var num: [16]u8 = undefined;
            const want = std.fmt.bufPrint(&num, "{d} ", .{@intFromEnum(linux.SYS.flock)}) catch continue;
            if (std.mem.startsWith(u8, call, want)) return true;
        }
        return false;
    }
};

test "a name taken again during the wait: another turn, the loop uncounted" {
    // Ordering checkpoint 10's EEXIST loop has no count: each turn follows
    // the release of the session that held the name. Here the name is
    // taken twice: an ended record whose lock is held (the wait), then,
    // during that wait, another ended record under the name (.gone, and
    // another EEXIST), released in turn; the third link takes the name.
    msg.prog = "flong-launch";
    var fx = try Fixture.init("/sys/fs/cgroup/h");
    defer fx.deinit();
    const live = fd.liveCount();
    var dir = fx.sessions();
    defer dir.close();
    try dir.writeFile(.{ .sub_path = "m", .data = "cgroup=/sys/fs/cgroup/h/c/m\nleader=1:1\n" });
    const held = try dir.openFile("m", .{});
    try held.lock(.exclusive);
    var swap: Swap = .{ .dir = dir, .held = held, .parent = linux.getpid() };
    const t = try std.Thread.spawn(.{}, Swap.run, .{&swap});
    const r = record.create(fx.state.sessions, &fx.holder, "m", null, "/sys/fs/cgroup/h/c/m");
    t.join();
    var rec = try r;
    try testing.expect(swap.swapped);
    const got = try readFile(dir, "m");
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("cgroup=/sys/fs/cgroup/h/c/m\n", got);
    rec.remove();
    try testing.expectEqual(live, fd.liveCount());
}

// ---- the cache lock ----

test "the cache lock: absent, unprepared, locked, not a directory" {
    msg.prog = "flong-launch";
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    const cache = try std.fmt.allocPrintSentinel(testing.allocator, "{s}/cache", .{root}, 0);
    defer testing.allocator.free(cache);

    try testing.expect(try record.cacheLock(cache) == .swept);
    try tmp.dir.makeDir("cache");
    try testing.expect(try record.cacheLock(cache) == .swept);
    try tmp.dir.makeDir("cache/prepared");
    const before = fd.liveCount();
    const got = try record.cacheLock(cache);
    try testing.expect(got == .locked);
    try testing.expectEqual(before + 1, fd.liveCount());
    // Shared: another shared lock is granted, an exclusive one is not.
    var other = try tmp.dir.openDir("cache", .{ .iterate = true });
    defer other.close();
    try testing.expectError(error.WouldBlock, std.posix.flock(other.fd, std.posix.LOCK.EX | std.posix.LOCK.NB));
    try std.posix.flock(other.fd, std.posix.LOCK.SH | std.posix.LOCK.NB);

    try tmp.dir.writeFile(.{ .sub_path = "file", .data = "" });
    const file = try std.fmt.allocPrintSentinel(testing.allocator, "{s}/file", .{root}, 0);
    defer testing.allocator.free(file);
    var said = Said.start();
    const r = record.cacheLock(file);
    const text = said.stop();
    try testing.expectError(error.Reported, r);
    const want = try std.fmt.allocPrint(testing.allocator, "flong-launch: cache {s}: Not a directory\n", .{file});
    defer testing.allocator.free(want);
    try testing.expectEqualStrings(want, text);
}

// ---- the session ----

const Limit = struct { file: [:0]const u8, value: [:0]const u8 };

fn createRefused(fx: *Fixture, machine: [:0]const u8, limits: []const Limit) ![]u8 {
    var said = Said.start();
    const r = cgroup.sessionCreate(&fx.holder, "c", machine, limits);
    const text = said.stop();
    if (r) |s| {
        var kept = s;
        kept.closeAll();
        return error.NotRefused;
    } else |err| try testing.expectEqual(error.Reported, err);
    return testing.allocator.dupe(u8, text);
}

test "the session: made with its leaves, a duplicate refused, a controller missing, a failure undone" {
    msg.prog = "flong-launch";
    var fx = try Fixture.init("/sys/fs/cgroup/h");
    defer fx.deinit();
    const live = fd.liveCount();

    // No limits: no controller file is read; the container, the session
    // and its three leaves, each open.
    var s = try cgroup.sessionCreate(&fx.holder, "c", "m", &[_]Limit{});
    try testing.expectEqualStrings("/sys/fs/cgroup/h/c/m", s.path.slice());
    for (s.leaf) |l| try testing.expect(l != null);
    for ([_][]const u8{ "holder/c/m/sandbox", "holder/c/m/hooks", "holder/c/m/pasta" }) |p| {
        var d = try fx.tmp.dir.openDir(p, .{});
        d.close();
    }
    s.closeAll();
    try testing.expectEqual(live, fd.liveCount());
    {
        const said = try createRefused(&fx, "m", &.{});
        defer testing.allocator.free(said);
        try testing.expectEqualStrings("flong-launch: a session named m is already running (/sys/fs/cgroup/h/c/m exists)\n", said);
    }

    // A limit whose controller the holder does not have: refused by name,
    // before anything is made.
    try fx.tmp.dir.writeFile(.{ .sub_path = "holder/cgroup.controllers", .data = "cpu memory\n" });
    try fx.tmp.dir.writeFile(.{ .sub_path = "holder/cgroup.subtree_control", .data = "" });
    {
        const said = try createRefused(&fx, "m2", &.{.{ .file = "pids.max", .value = "10" }});
        defer testing.allocator.free(said);
        try testing.expectEqualStrings("flong-launch: the limit pids.max needs the pids controller, which /sys/fs/cgroup/h does not have\n", said);
    }
    try testing.expectError(error.FileNotFound, fx.tmp.dir.statFile("holder/c/m2"));

    // The controller on the holder and the container, and the session's
    // own enable failing after its mkdir: undone, the container kept.
    try fx.tmp.dir.writeFile(.{ .sub_path = "holder/cgroup.controllers", .data = "cpu pids memory\n" });
    try fx.tmp.dir.writeFile(.{ .sub_path = "holder/c/cgroup.controllers", .data = "pids\n" });
    try fx.tmp.dir.writeFile(.{ .sub_path = "holder/c/cgroup.subtree_control", .data = "" });
    {
        const said = try createRefused(&fx, "m2", &.{.{ .file = "pids.max", .value = "10" }});
        defer testing.allocator.free(said);
        try testing.expectEqualStrings("flong-launch: open cgroup.controllers: No such file or directory\n", said);
    }
    try testing.expectError(error.FileNotFound, fx.tmp.dir.statFile("holder/c/m2"));
    try testing.expect((try fx.tmp.dir.statFile("holder/c")).kind == .directory);
    const enabled = try readFile(fx.tmp.dir, "holder/cgroup.subtree_control");
    defer testing.allocator.free(enabled);
    try testing.expectEqualStrings("+pids", enabled);
    try testing.expectEqual(live, fd.liveCount());
}
