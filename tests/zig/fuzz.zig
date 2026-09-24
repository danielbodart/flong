//! The sweep's readers fuzzed (minish, the `test` step; ZIG.md, "Tests":
//! fuzzing). flong-sweeper reads records, cgroup paths, cgroup.events,
//! /proc files and inotify events a caller can shape, and its exit stops
//! the holder and every session (module.nix:936-941), so none may panic or
//! reach `unreachable` on any input (ZIG.md, open decision 2). Each target
//! first replays its checked-in corpus (tests/zig/corpus/<target>/, one
//! input per file; a crash found is added there), then runs `runs` token
//! lists (tests/zig/inputs.zig) and `runs` raw byte strings, each under a
//! fixed seed and again under a random one, which minish prints on a
//! failure. In ReleaseSafe (native-test-release) a panic is the build's
//! failure; each target also checks what its answer must hold.
//!
//! The mountinfo reader is L2's (cg_check_nsdelegate, the launch half), so
//! it is not here yet.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const minish = @import("minish");
const sys = @import("sys");
const fd = @import("fd");
const proc = @import("proc");
const cgroup = @import("cgroup");
const record = @import("record");
const inputs = @import("inputs");
const options = @import("options");
const testing = std.testing;

/// 10,000 in ReleaseSafe (native-test-release), where the volume is; 1,000
/// in Debug (native-test-debug), which is there for Debug's own safety
/// checks: its 10,000 took about 2 min against ReleaseSafe's 43 s, and its
/// 1,000 take 14 s (this host, 2026-09-24). The corpus replays in both.
const runs = if (builtin.mode == .Debug) 1_000 else 10_000;
const fixed_seed = 0xf1_0e6;

fn randomSeed() u64 {
    var b: [8]u8 = undefined;
    _ = linux.getrandom(&b, b.len, 0);
    return std.mem.readInt(u64, &b, .little);
}

// ---- the targets, each over bytes ----

/// How many inputs of the current run the target's reader answered with
/// something (a record accepted, a session's form, a pid's starttime...),
/// and how many it turned away. A target that never gets past its first
/// check, or a builder that makes nothing the reader takes, would pass
/// every property having tested nothing, so each token run must reach
/// both answers (Target.run).
var reached: usize = 0;
var turned: usize = 0;

fn count(hit: bool) void {
    if (hit) reached += 1 else turned += 1;
}

var fields: record.Fields = .{};

fn parse(b: []const u8) !void {
    const ok = record.parse(b, &fields) == null;
    count(ok);
    if (ok) {
        try testing.expect(fields.cgroup_len > 0 and fields.cgroup_len < sys.path_max);
        try testing.expect(fields.poststop_len < sys.path_max);
        try testing.expect(fields.leader >= 0);
        try testing.expect(std.mem.indexOf(u8, b, fields.cgroupPath()) != null);
    }
    _ = record.poststopLineLen(b);
}

fn sessionForm(b: []const u8) !void {
    // The corpus's form: the machine, a newline, the path.
    const nl = std.mem.indexOfScalar(u8, b, '\n') orelse b.len;
    const machine = b[0..nl];
    const path = if (nl < b.len) b[nl + 1 ..] else b[0..0];
    const got = cgroup.sessionForm(path, machine);
    count(got != null);
    if (got) |at| {
        try testing.expect(at > cgroup.root.len and at < path.len);
        try testing.expect(std.mem.startsWith(u8, path, cgroup.root ++ "/"));
    }
}

fn populated(b: []const u8) !void {
    const p = cgroup.populated(b);
    count(p != .absent);
    if (p != .absent) try testing.expect(std.mem.indexOf(u8, b, "populated ") != null);
}

fn ownCgroup(b: []const u8) !void {
    const own = cgroup.ownFrom(b);
    count(own == .path);
    switch (own) {
        .path => |p| try testing.expect(p.len > 0 and p[0] == '/'),
        .unexpected, .no_entry => {},
    }
}

fn stat(b: []const u8) !void {
    const v = proc.statStarttime(b);
    count(v != 0);
    if (std.mem.lastIndexOfScalar(u8, b, ')') == null) try testing.expectEqual(@as(u64, 0), v);
}

fn closedInode(b: []const u8) !void {
    const v = record.closedInode(b);
    count(v != 0);
    if (v != 0) try testing.expect(b.len > 1 and b[0] == '#');
}

fn inotify(b: []const u8) !void {
    const got = record.batch(b);
    count(got.nwaits > 0);
    try testing.expect(got.nwaits <= record.max_waits);
    for (got.waits[0..got.nwaits]) |w| try testing.expect(w != 0);
    var it: fd.InotifyEvents = .{ .buf = b };
    var n: usize = 0;
    while (it.next()) |_| n += 1;
    try testing.expect(n <= b.len / @sizeOf(fd.InotifyEvent));
}

// ---- the runs ----

/// The largest input a builder makes: a record past REC_MAX.
var scratch: [2 * record.rec_max]u8 align(4) = undefined;
var machine_scratch: [256]u8 = undefined;

fn Target(comptime name: []const u8, comptime check: fn ([]const u8) anyerror!void, comptime tokensTo: fn ([]const u16) []const u8) type {
    return struct {
        fn fromTokens(tokens: []const u16) !void {
            try check(tokensTo(tokens));
        }

        fn fromBytes(b: []const u8) !void {
            try check(b);
        }

        /// The corpus first, then the four runs.
        fn run() !void {
            try replay(name, check);
            const token_gen = minish.gen.list(u16, minish.gen.int(u16), 0, 48);
            const byte_gen = minish.gen.list(u8, minish.gen.int(u8), 0, 512);
            for ([_]u64{ fixed_seed, randomSeed() }) |seed| {
                reached = 0;
                turned = 0;
                try minish.check(testing.allocator, token_gen, fromTokens, .{ .num_runs = runs, .seed = seed });
                // The token builders aim at the reader: at least one input
                // in a hundred is answered, and at least one turned away.
                if (reached < runs / 100 or turned == 0) {
                    std.debug.print("fuzz {s}: seed {x}: {d} answered, {d} turned away\n", .{ name, seed, reached, turned });
                    return error.Unreached;
                }
                try minish.check(testing.allocator, byte_gen, fromBytes, .{ .num_runs = runs, .seed = seed });
            }
        }
    };
}

/// Every file of tests/zig/corpus/<name>/, fed whole to `check`.
fn replay(comptime name: []const u8, comptime check: fn ([]const u8) anyerror!void) !void {
    var root = try std.fs.openDirAbsolute(options.corpus, .{});
    defer root.close();
    var dir = try root.openDir(name, .{ .iterate = true });
    defer dir.close();
    var it = dir.iterate();
    var n: usize = 0;
    while (try it.next()) |e| {
        if (e.kind != .file) continue;
        const b = try dir.readFileAlloc(testing.allocator, e.name, 1 << 20);
        defer testing.allocator.free(b);
        check(b) catch |err| {
            std.debug.print("corpus {s}/{s} fails\n", .{ name, e.name });
            return err;
        };
        n += 1;
    }
    // A corpus that is not there would pass having replayed nothing.
    try testing.expect(n > 0);
}

fn recordTokens(t: []const u16) []const u8 {
    return inputs.record(t, &scratch);
}

fn sessionTokens(t: []const u16) []const u8 {
    const m, const p = inputs.sessionForm(t, &machine_scratch, scratch[machine_scratch.len..]);
    // Joined as the corpus spells it.
    @memcpy(scratch[0..m.len], m);
    scratch[m.len] = '\n';
    std.mem.copyForwards(u8, scratch[m.len + 1 ..][0..p.len], p);
    return scratch[0 .. m.len + 1 + p.len];
}

fn eventsTokens(t: []const u16) []const u8 {
    return inputs.events(t, &scratch);
}

fn ownTokens(t: []const u16) []const u8 {
    return inputs.ownCgroup(t, &scratch);
}

fn statTokens(t: []const u16) []const u8 {
    return inputs.stat(t, &scratch);
}

fn inodeTokens(t: []const u16) []const u8 {
    return inputs.inodeName(t, &scratch);
}

fn inotifyTokens(t: []const u16) []const u8 {
    return inputs.inotify(t, scratch[0..record.events_len]);
}

test "fuzz record.parse (and blank_poststop's line)" {
    try Target("record-parse", parse, recordTokens).run();
}

test "fuzz cgroup.sessionForm" {
    try Target("cgroup-session-form", sessionForm, sessionTokens).run();
}

test "fuzz cgroup.populated (cgroup.events)" {
    try Target("cgroup-populated", populated, eventsTokens).run();
}

test "fuzz cgroup.ownFrom (/proc/self/cgroup)" {
    try Target("cgroup-own", ownCgroup, ownTokens).run();
}

test "fuzz proc.statStarttime (/proc/<pid>/stat field 22)" {
    try Target("proc-stat", stat, statTokens).run();
}

test "fuzz record.closedInode" {
    try Target("record-closed-inode", closedInode, inodeTokens).run();
}

test "fuzz record.batch (inotify events)" {
    try Target("record-inotify", inotify, inotifyTokens).run();
}
