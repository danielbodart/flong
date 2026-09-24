//! launch/bwrap.zig and sig.awaitFdOrExit from outside (the `test` step;
//! the Zig port's L4): bwrap's spawn against a stand-in
//! (flong-fake-bwrap, tests/zig/fakebwrap.zig, built for it), which says
//! the argv and the descriptors it was started with.
//!
//! - bwrap's argv per branch (plain, relay, nestedSandbox, a project
//!   filter, keep-fds, trace), each descriptor's number read back as its
//!   name, against the golden argv; and the stand-in holds 0-2 and exactly
//!   the descriptors its argv names, the keep-fds included.
//! - checkpoint 2's list: after the root's walk of ChildEnds (written here
//!   as launch.zig's will be) the launcher holds its three ends and bwrap's
//!   pidfd, and nothing of bwrap's; on a refused seccomp program (U2 and
//!   the keep-fds in the list, nothing spawned) and on a failed start (the
//!   launcher's ends closed by spawn) nothing is left.
//! - awaitFdOrExit: the descriptor, the child's exit, a tie (the
//!   descriptor wins, with data and at EOF), a terminating signal first, a
//!   dropped one; the child-exit wait bounded by a forked tester, so a wait
//!   that never ends fails as Hung.
//!
//! U1 and U2 stand in as this process's own user namespace, opened by
//! fd.openUserns; the keep-fd is /dev/null, opened by a raw call, as
//! the wrapper's are.

const std = @import("std");
const linux = std.os.linux;
const sys = @import("sys");
const fd = @import("fd");
const msg = @import("msg");
const sig = @import("sig");
const proc = @import("proc");
const spec = @import("spec");
const bwrap = @import("bwrap");
const options = @import("options");
const testing = std.testing;
const Allocator = std.mem.Allocator;

// ---- helpers ----

/// flong-fake-bwrap's path, made absolute once.
var fake_buf: [std.fs.max_path_bytes:0]u8 = undefined;
var fake: [:0]const u8 = "";

fn fakeBwrap() [*:0]const u8 {
    if (fake.len == 0) {
        const p = std.fs.cwd().realpath(options.fake_bwrap, &fake_buf) catch @panic("flong-fake-bwrap not found");
        fake_buf[p.len] = 0;
        fake = fake_buf[0..p.len :0];
    }
    return fake.ptr;
}

fn opened(r: anytype) !@FieldType(@typeInfo(@TypeOf(r)).error_union.payload, "ok") {
    return switch (try r) {
        .ok => |h| h,
        .err => error.TestUnexpectedResult,
    };
}

fn rawOpen(path: [*:0]const u8) !i32 {
    const rc = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.E.init(rc) != .SUCCESS) return error.Open;
    return @intCast(rc);
}

/// This process's own user namespace, opened as the launcher opens U1's:
/// fd.openUserns of a pid.
fn userns() !fd.Fd(.userns) {
    return opened(fd.openUserns(linux.getpid()));
}

/// What a call wrote on stderr: fd 2 is a memfd for its length.
const Capture = struct {
    saved: i32,
    file: i32,

    fn begin() !Capture {
        const mf = linux.memfd_create("bwrap-test", linux.MFD.CLOEXEC);
        if (linux.E.init(mf) != .SUCCESS) return error.Memfd;
        const saved = linux.fcntl(2, 1030, 10); // F_DUPFD_CLOEXEC
        if (linux.E.init(saved) != .SUCCESS) return error.Dup;
        if (linux.E.init(linux.dup2(@intCast(mf), 2)) != .SUCCESS) return error.Dup;
        return .{ .saved = @intCast(saved), .file = @intCast(mf) };
    }

    fn end(self: Capture, buf: []u8) ![]const u8 {
        _ = linux.dup2(self.saved, 2);
        _ = linux.close(self.saved);
        defer _ = linux.close(self.file);
        const n = linux.pread(self.file, buf.ptr, buf.len, 0);
        if (linux.E.init(n) != .SUCCESS) return error.Read;
        return buf[0..n];
    }
};

/// Reads `r` to its end.
fn drain(gpa: Allocator, r: fd.Fd(.pipe_r)) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var buf: [4096]u8 = undefined;
    while (true) {
        const got = switch (r.read(&buf)) {
            .ok => |g| g,
            .err => return error.TestUnexpectedResult,
        };
        if (got == 0) break;
        try out.appendSlice(gpa, buf[0..got]);
    }
    return out.items;
}

/// Checkpoint 2, as launch.zig's linear function walks it (launch/
/// bwrap.zig's header): every descriptor bwrap alone needs, closed.
fn walk(ends: *const bwrap.ChildEnds) void {
    if (ends.info_w) |h| h.close();
    if (ends.ready_w) |h| h.close();
    if (ends.gate_r) |h| h.close();
    for (ends.seccomp) |h| h.close();
    ends.u2.close();
    for (ends.keep) |h| h.close();
}

/// Each of `ends`' handles is closed.
fn expectWalked(ends: *const bwrap.ChildEnds) !void {
    if (ends.info_w) |h| try testing.expect(!h.isLive());
    if (ends.ready_w) |h| try testing.expect(!h.isLive());
    if (ends.gate_r) |h| try testing.expect(!h.isLive());
    for (ends.seccomp) |h| try testing.expect(!h.isLive());
    try testing.expect(!ends.u2.isLive());
    for (ends.keep) |h| try testing.expect(!h.isLive());
}

// ---- the spec every branch starts from ----

const uidmap = [_]spec.IdMap{ .{ .inside = 0, .outside = 100000, .count = 1000 }, .{ .inside = 1000, .outside = 1000, .count = 1 } };
const gidmap = [_]spec.IdMap{ .{ .inside = 0, .outside = 100000, .count = 100 }, .{ .inside = 100, .outside = 100, .count = 1 } };
const command = [_][*:0]const u8{ "sh", "-c", "exec \"$@\"", "--" };

fn baseSpec() spec.Spec {
    return .{
        .machine = "m",
        .container = "c",
        .state = "/run/user/1000/flong",
        .cache = "/home/u/.cache/flong/c",
        .closure = "/nix/store/test-only-closure",
        .uidmap = &uidmap,
        .gidmap = &gidmap,
        .uid = 1000,
        .gid = 100,
        .home = "/home/u",
        .groups = &.{ 100, 27 },
        .chdir = "/home/u/w",
        .holder = "flong.slice/s",
        .command = &command,
    };
}

const init_path = "/nix/store/test-only-flong-init";

/// The fixed part up to --info-fd's number (flong-launch.c:279-294),
/// nested namespaces off.
const head = [_][]const u8{
    "--userns",          "@U1@",          "--userns2",     "@U2@",          "--assert-userns-disabled",
    "--unshare-net",     "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup",
    "--die-with-parent", "--as-pid-1",    "--info-fd",     "@INFO@",
};
/// From the capabilities to /.hostsys (:299-317).
const middle = [_][]const u8{
    "--cap-add",           "CAP_SETGID",                      "--cap-add",     "CAP_SETPCAP",
    "--uid",               "1000",                            "--gid",         "100",
    "--overlay-src",       "/home/u/.cache/flong/c/prepared", "--tmp-overlay", "/",
    "--ro-bind",           "/nix/store",                      "/nix/store",    "--ro-bind",
    "/nix/var/nix/db",     "/nix/var/nix/db",                 "--proc",        "/proc",
    "--dev",               "/dev",                            "--perms",       "0755",
    "--tmpfs",             "/run",                            "--ro-bind",     "/nix/store/test-only-closure",
    "/run/current-system", "--perms",                         "0755",          "--dir",
    "/run/user",           "--perms",                         "0700",          "--tmpfs",
    "/run/user/1000",      "--perms",                         "1777",          "--tmpfs",
    "/tmp",                "--ro-bind",                       "/sys",          "/.hostsys",
};
const tail_command = [_][]const u8{ "--", "sh", "-c", "exec \"$@\"", "--" };

fn cat(comptime parts: []const []const []const u8) []const []const u8 {
    comptime var out: []const []const u8 = &.{};
    inline for (parts) |p| out = out ++ p;
    return out;
}

// ---- bwrap's spawn against the stand-in ----

const Branch = struct {
    /// the spec's seccomp programs
    seccomp: []const [:0]const u8 = &.{},
    nested: u64 = 0,
    trace: bool = false,
    groups: ?[]const u32 = null,
    /// one keep-fd, named by --ro-bind-data after --clearenv
    keep_fd: bool = false,
    relay: bool = false,
};

/// Spawns the stand-in as bwrap for `b`, walks checkpoint 2's list, and
/// checks its argv against `want` (@X@ each descriptor's name) and that it
/// held 0-2 and exactly the descriptors named.
fn expectSpawn(b: Branch, want: []const []const u8) !void {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    msg.prog = "flong-launch";
    msg.mode = .cut;

    const ns1 = try userns();
    defer ns1.close();
    const out = try opened(fd.pipe());
    defer out.r.close();

    var keep: []const fd.Fd(.inherited) = &.{};
    var s = baseSpec();
    s.seccomp = b.seccomp;
    s.nested_userns = b.nested;
    s.trace = b.trace;
    if (b.groups) |g| s.groups = g;
    var keep_text: []const u8 = "@KEEP@";
    if (b.keep_fd) {
        const k = try fd.adoptInherited(try rawOpen("/dev/null"));
        const ks = try arena.alloc(fd.Fd(.inherited), 1);
        ks[0] = k;
        keep = ks;
        keep_text = try std.fmt.allocPrint(arena, "{d}", .{k.raw()});
        const kf = try arena.alloc(sys.fd_t, 1);
        kf[0] = k.raw();
        s.keep_fds = kf;
        const words = try arena.alloc([:0]const u8, 9);
        for ([_][]const u8{ "--clearenv", "--setenv", "HOME", "/home/u", "--perms", "0644", "--ro-bind-data", keep_text, "/etc/resolv.conf" }, 0..) |w, i|
            words[i] = try arena.dupeZ(u8, w);
        s.bwrap_args = words;
    }

    const before = fd.liveCount();
    var ends: bwrap.ChildEnds = .{ .u2 = try userns(), .keep = keep };
    const got = try bwrap.spawn(arena, &s, .{ .bwrap = fakeBwrap(), .init = init_path }, ns1, b.relay, .{ null, out.w.any(), null }, null, &ends);

    // Every descriptor's name, by its number, before the walk closes them.
    var names: std.ArrayList([2][]const u8) = .empty;
    const named = struct {
        fn add(gpa: Allocator, l: *std.ArrayList([2][]const u8), name: []const u8, h: anytype) !void {
            try l.append(gpa, .{ name, try std.fmt.allocPrint(gpa, "{d}", .{h.raw()}) });
        }
    };
    try named.add(arena, &names, "@U1@", ns1);
    try named.add(arena, &names, "@U2@", ends.u2);
    try named.add(arena, &names, "@INFO@", ends.info_w.?);
    try named.add(arena, &names, "@READY@", ends.ready_w.?);
    try named.add(arena, &names, "@GATE@", ends.gate_r.?);
    try testing.expectEqual(b.seccomp.len, ends.seccomp.len);
    for (ends.seccomp, 0..) |h, i| try named.add(arena, &names, try std.fmt.allocPrint(arena, "@SECCOMP{d}@", .{i}), h);
    for (ends.keep) |h| try named.add(arena, &names, "@KEEP@", h);

    // 2. checkpoint 2: the child's ends, at once.
    walk(&ends);
    out.w.close();
    try expectWalked(&ends);
    // The launcher's three ends and bwrap's pidfd, for U2 and the keep-fd
    // it gave up.
    try testing.expectEqual(before + 4 - 1 - keep.len, fd.liveCount());

    const said = try drain(arena, out.r);
    try testing.expectEqual(@as(u8, 0), try got.child.await());
    got.info_r.close();
    got.ready_r.close();
    got.gate_w.close();
    try testing.expectEqual(before - 1 - keep.len, fd.liveCount());

    // Its argv, each number read back as its descriptor's name.
    var lines = std.mem.splitScalar(u8, said, '\n');
    var args: std.ArrayList([]const u8) = .empty;
    var fds_line: []const u8 = "";
    while (lines.next()) |l| {
        if (std.mem.startsWith(u8, l, "arg ")) {
            try args.append(arena, l[4..]);
        } else if (std.mem.startsWith(u8, l, "fds")) {
            fds_line = l;
        }
    }
    var norm: std.ArrayList([]const u8) = .empty;
    for (args.items, 0..) |w, i| {
        var n = w;
        // A number is a descriptor's where the argv names one: after its
        // option, or flong-init's first two words.
        const prev = if (i > 0) args.items[i - 1] else "";
        const prev2 = if (i > 1) args.items[i - 2] else "";
        const is_fd = eql(prev, "--userns") or eql(prev, "--userns2") or eql(prev, "--info-fd") or
            eql(prev, "--add-seccomp-fd") or eql(prev, "--ro-bind-data") or eql(prev, init_path) or eql(prev2, init_path);
        if (is_fd) {
            for (names.items) |nm| {
                if (eql(nm[1], w)) n = nm[0];
            }
        }
        try norm.append(arena, n);
    }
    for (want, 0..) |w, i| {
        if (i >= norm.items.len) break;
        testing.expectEqualStrings(w, norm.items[i]) catch |err| {
            std.debug.print("bwrap argv word {d} differs\n", .{i});
            return err;
        };
    }
    try testing.expectEqual(want.len, norm.items.len);

    // It held 0-2 and exactly what its argv names, each once.
    var held: std.ArrayList([]const u8) = .empty;
    var words = std.mem.tokenizeScalar(u8, fds_line["fds".len..], ' ');
    while (words.next()) |w| {
        var n: []const u8 = w;
        for (names.items) |nm| {
            if (eql(nm[1], w)) n = nm[0];
        }
        try held.append(arena, n);
    }
    var expect_held: std.ArrayList([]const u8) = .empty;
    try expect_held.appendSlice(arena, &.{ "0", "1", "2" });
    for (names.items) |nm| try expect_held.append(arena, nm[0]);
    std.mem.sort([]const u8, held.items, {}, lessStr);
    std.mem.sort([]const u8, expect_held.items, {}, lessStr);
    try testing.expectEqual(expect_held.items.len, held.items.len);
    for (expect_held.items, held.items) |e, h| try testing.expectEqualStrings(e, h);
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn lessStr(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

const init_plain = [_][]const u8{ "--", init_path, "@GATE@", "@READY@", "100,27", "-", "-", "/home/u/w" };

test "spawn: plain" {
    try expectSpawn(.{}, comptime cat(&.{ &head, &middle, &init_plain, &tail_command }));
}

test "spawn: relay, a session of its own and flong-init's ctty" {
    try expectSpawn(.{ .relay = true }, comptime cat(&.{
        &head,
        &.{"--new-session"},
        &middle,
        &.{ "--", init_path, "@GATE@", "@READY@", "100,27", "ctty", "-", "/home/u/w" },
        &tail_command,
    }));
}

test "spawn: nestedSandbox drops --assert-userns-disabled" {
    try expectSpawn(.{ .nested = 128 }, comptime cat(&.{
        &.{ "--userns", "@U1@", "--userns2", "@U2@" },
        head[5..],
        &middle,
        &init_plain,
        &tail_command,
    }));
}

test "spawn: the tier's filters and a project filter, each opened and passed in order" {
    try expectSpawn(.{ .seccomp = &.{ "/etc/passwd", "/dev/null", "/proc/self/status" } }, comptime cat(&.{
        &head,
        &.{ "--add-seccomp-fd", "@SECCOMP0@", "--add-seccomp-fd", "@SECCOMP1@", "--add-seccomp-fd", "@SECCOMP2@" },
        &middle,
        &init_plain,
        &tail_command,
    }));
}

test "spawn: a keep-fd is kept at its number, which its bwrap-arg names" {
    try expectSpawn(.{ .keep_fd = true }, comptime cat(&.{
        &head,
        &middle,
        &.{ "--clearenv", "--setenv", "HOME", "/home/u", "--perms", "0644", "--ro-bind-data", "@KEEP@", "/etc/resolv.conf" },
        &init_plain,
        &tail_command,
    }));
}

test "spawn: trace, and no groups" {
    try expectSpawn(.{ .trace = true, .groups = &.{} }, comptime cat(&.{
        &head,
        &middle,
        &.{ "--", init_path, "@GATE@", "@READY@", "-", "-", "trace", "/home/u/w" },
        &tail_command,
    }));
}

test "spawn: a seccomp program refused; U2, the keep-fd and the program opened before it are in the list, nothing spawned" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    msg.prog = "flong-launch";
    msg.mode = .cut;
    const ns1 = try userns();
    defer ns1.close();
    const k = try fd.adoptInherited(try rawOpen("/dev/null"));
    var s = baseSpec();
    s.seccomp = &.{ "/etc/passwd", "/nonexistent/b.bpf", "/dev/null" };
    const ks = [_]fd.Fd(.inherited){k};
    const before = fd.liveCount();
    var ends: bwrap.ChildEnds = .{ .u2 = try userns(), .keep = &ks };
    var errbuf: [4096]u8 = undefined;
    const cap = try Capture.begin();
    const r = bwrap.spawn(arena, &s, .{ .bwrap = fakeBwrap(), .init = init_path }, ns1, false, .{ null, null, null }, null, &ends);
    const said = try cap.end(&errbuf);
    try testing.expectError(error.Reported, r);
    try testing.expectEqualStrings("flong-launch: open seccomp program /nonexistent/b.bpf: No such file or directory\n", said);
    try testing.expectEqual(@as(usize, 1), ends.seccomp.len);
    try testing.expect(ends.info_w == null and ends.ready_w == null and ends.gate_r == null);
    walk(&ends);
    try expectWalked(&ends);
    // U2 and the keep-fd gone with the program: nothing else was made.
    try testing.expectEqual(before - 1, fd.liveCount());
}

test "spawn: a start refused after the pipes; the launcher's ends closed, the child's in the list" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    msg.prog = "flong-launch";
    msg.mode = .cut;
    const ns1 = try userns();
    defer ns1.close();
    const s = baseSpec();
    const before = fd.liveCount();
    var ends: bwrap.ChildEnds = .{ .u2 = try userns(), .keep = &.{} };

    // Every free slot reserved but the six the pipes take: the pidfd's
    // reservation, in Spawn.start, finds the table full.
    var held: [fd.capacity]fd.Reservation = undefined;
    var n: usize = 0;
    while (fd.reserve()) |r| : (n += 1) held[n] = r else |_| {}
    try testing.expect(n >= 6);
    for (held[n - 6 .. n]) |r| r.cancel();
    n -= 6;
    defer for (held[0..n]) |r| r.cancel();

    var errbuf: [4096]u8 = undefined;
    const cap = try Capture.begin();
    const r = bwrap.spawn(arena, &s, .{ .bwrap = fakeBwrap(), .init = init_path }, ns1, false, .{ null, null, null }, null, &ends);
    const said = try cap.end(&errbuf);
    try testing.expectError(error.Reported, r);
    const want = try std.fmt.allocPrint(arena, "flong-launch: clone3 {s}: too many open descriptors\n", .{fakeBwrap()});
    try testing.expectEqualStrings(want, said);
    try testing.expect(ends.info_w != null and ends.ready_w != null and ends.gate_r != null);
    walk(&ends);
    try expectWalked(&ends);
    try testing.expectEqual(before, fd.liveCount());
}

test "spawn: a bwrap that cannot be exec'd is a child that exits 127, its ends walked alike" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    msg.prog = "flong-launch";
    msg.mode = .cut;
    const ns1 = try userns();
    defer ns1.close();
    const s = baseSpec();
    const errp = try opened(fd.pipe());
    defer errp.r.close();
    const before = fd.liveCount() - 1;
    var ends: bwrap.ChildEnds = .{ .u2 = try userns(), .keep = &.{} };
    const got = try bwrap.spawn(arena, &s, .{ .bwrap = "/nonexistent/bwrap", .init = init_path }, ns1, false, .{ null, null, errp.w.any() }, null, &ends);
    walk(&ends);
    errp.w.close();
    const said = try drain(arena, errp.r);
    try testing.expectEqual(@as(u8, 127), try got.child.await());
    try testing.expectEqualStrings("flong-launch: exec /nonexistent/bwrap: No such file or directory\n", said);
    got.info_r.close();
    got.ready_r.close();
    got.gate_w.close();
    try testing.expectEqual(before, fd.liveCount());
}

// ---- awaitFdOrExit ----

/// A child that waits for `r` to be readable, then exits 0: alive until
/// its pipe is written or closed.
const Waits = struct {
    r: fd.Fd(.pipe_r),

    fn body(self: Waits) noreturn {
        sig.awaitFd(self.r, sys.POLL.IN) catch proc.exit(1);
        proc.exit(0);
    }
};

const Exits = struct {
    fn body(_: Exits) noreturn {
        proc.exit(3);
    }
};

/// A child that has exited, unreaped.
fn exited() !proc.Child {
    const c = try proc.fork(.{}, Exits{}, Exits.body);
    try sig.awaitFd(c.pidfd, sys.POLL.IN);
    return c;
}

/// awaitFdOrExit(r, c) in a forked tester, within 10 s: its answer, or
/// error.Hung once the tester is killed and reaped (a wait that never ends).
const Tester = struct {
    r: fd.Fd(.pipe_r),
    c: fd.Fd(.pidfd),

    fn body(self: Tester) noreturn {
        const w = sig.awaitFdOrExit(self.r, self.c) catch proc.exit(2);
        proc.exit(@intFromEnum(w));
    }
};

fn awaitInTester(r: fd.Fd(.pipe_r), c: fd.Fd(.pidfd)) !sig.Woke {
    const t = try proc.fork(.{ .keep = &.{ r.any(), c.any() } }, Tester{ .r = r, .c = c }, Tester.body);
    var p = [1]sys.pollfd{.{ .fd = t.pidfd.raw(), .events = sys.POLL.IN, .revents = 0 }};
    const n = switch (sys.poll(&p, 10_000)) {
        .ok => |n| n,
        .err => return error.TestUnexpectedResult,
    };
    if (n == 0) {
        t.reapNow(.kill);
        return error.Hung;
    }
    const st = try t.await();
    return switch (st) {
        0 => .ready,
        1 => .exited,
        else => error.TestUnexpectedResult,
    };
}

test "awaitFdOrExit: the descriptor, with data or at EOF, while the child lives" {
    const hold = try opened(fd.pipe());
    defer hold.w.close();
    const c = try proc.fork(.{ .keep = &.{hold.r.any()} }, Waits{ .r = hold.r }, Waits.body);
    hold.r.close();
    defer c.reapNow(.kill);

    const p = try opened(fd.pipe());
    defer p.r.close();
    _ = p.w.write("x");
    try testing.expectEqual(sig.Woke.ready, try sig.awaitFdOrExit(p.r, c.pidfd));
    p.w.close();
    var buf: [1]u8 = undefined;
    _ = p.r.read(&buf);
    // Its writers gone: EOF, POLLHUP alone. Bounded: a wait that took
    // POLLHUP for nothing would spin for ever.
    try testing.expectEqual(sig.Woke.ready, try awaitInTester(p.r, c.pidfd));
}

test "awaitFdOrExit: the child's exit ends a wait on a descriptor that never becomes ready (bounded)" {
    const c = try exited();
    defer c.reapNow(.wait);
    const p = try opened(fd.pipe());
    defer p.r.close();
    defer p.w.close();
    try testing.expectEqual(sig.Woke.exited, try awaitInTester(p.r, c.pidfd));
    try testing.expectEqual(sig.Woke.exited, try sig.awaitFdOrExit(p.r, c.pidfd));
}

test "awaitFdOrExit: a tie goes to the descriptor, with data and at EOF" {
    const c = try exited();
    defer c.reapNow(.wait);
    {
        const p = try opened(fd.pipe());
        defer p.r.close();
        defer p.w.close();
        _ = p.w.write("x");
        try testing.expectEqual(sig.Woke.ready, try sig.awaitFdOrExit(p.r, c.pidfd));
        try testing.expectEqual(sig.Woke.ready, try awaitInTester(p.r, c.pidfd));
    }
    {
        const p = try opened(fd.pipe());
        defer p.r.close();
        p.w.close();
        try testing.expectEqual(sig.Woke.ready, try sig.awaitFdOrExit(p.r, c.pidfd));
        try testing.expectEqual(sig.Woke.ready, try awaitInTester(p.r, c.pidfd));
    }
}

test "awaitFdOrExit: a terminating signal is looked at first; another is dropped" {
    const old = try sig.block();
    defer sig.setMask(old);
    try sig.openSignalfd();
    defer {
        sig.fd.?.close();
        sig.fd = null;
        sig.abort_signal = 0;
    }
    const c = try exited();
    defer c.reapNow(.wait);
    const p = try opened(fd.pipe());
    defer p.r.close();
    defer p.w.close();
    _ = p.w.write("x");

    _ = linux.kill(linux.getpid(), linux.SIG.TERM);
    try testing.expectError(error.Aborted, sig.awaitFdOrExit(p.r, c.pidfd));
    try testing.expectEqual(@as(u8, sys.SIGTERM), sig.abort_signal);
    sig.abort_signal = 0;

    _ = linux.kill(linux.getpid(), linux.SIG.WINCH);
    try testing.expectEqual(sig.Woke.ready, try sig.awaitFdOrExit(p.r, c.pidfd));
    try testing.expectEqual(false, try sig.take(0));
}
