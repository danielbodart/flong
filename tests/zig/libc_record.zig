//! test-libc: the sweep's readers against the C they port (ZIG.md, "The
//! record contract"): record.parse against parse_record, cgroup.sessionForm
//! against session_form, record.closedInode against closed_inode, the C
//! compiled from launcher/ as the launcher compiles it (tests/zig/
//! record_c.c). A record the C launcher writes is read the same by both
//! sweepers, and so is one a caller forged: the refusal's words, the
//! fields, or the same answer. Each over fixed cases, then 10,000 inputs
//! (tests/zig/inputs.zig) under a fixed seed and 10,000 under a random one,
//! printed on a difference.

const std = @import("std");
const sys = @import("sys");
const cgroup = @import("cgroup");
const record = @import("record");
const inputs = @import("inputs");
const testing = std.testing;

extern fn c_parse(buf: [*]const u8, len: usize, poststop: [*]u8, cgroup: [*]u8, leader: *c_int, start: *c_ulonglong, why: *?[*:0]const u8) c_int;
extern fn c_session_form(path: [*:0]const u8, machine: [*:0]const u8) c_long;
extern fn c_closed_inode(name: [*:0]const u8) c_ulonglong;

var zig_fields: record.Fields = .{};
var c_poststop: [sys.path_max]u8 = undefined;
var c_cgroup: [sys.path_max]u8 = undefined;

fn sameParse(b: []const u8) !void {
    var leader: c_int = 0;
    var start: c_ulonglong = 0;
    var why: ?[*:0]const u8 = null;
    const rc = c_parse(b.ptr, b.len, &c_poststop, &c_cgroup, &leader, &start, &why);
    const z = record.parse(b, &zig_fields);
    if (rc != 0) {
        try testing.expectEqualStrings(std.mem.span(why.?), z orelse "accepted");
        return;
    }
    try testing.expectEqual(@as(?[]const u8, null), z);
    try testing.expectEqualStrings(std.mem.sliceTo(&c_poststop, 0), zig_fields.poststop[0..zig_fields.poststop_len]);
    try testing.expectEqualStrings(std.mem.sliceTo(&c_cgroup, 0), zig_fields.cgroupPath());
    try testing.expectEqual(@as(i32, leader), zig_fields.leader);
    try testing.expectEqual(@as(u64, start), zig_fields.starttime);
}

fn sameSessionForm(machine: []const u8, path: []const u8) !void {
    var m: [512]u8 = undefined;
    var p: [2 * record.rec_max + 1]u8 = undefined;
    @memcpy(m[0..machine.len], machine);
    m[machine.len] = 0;
    @memcpy(p[0..path.len], path);
    p[path.len] = 0;
    const c = c_session_form(@ptrCast(&p), @ptrCast(&m));
    const z = cgroup.sessionForm(path, machine);
    try testing.expectEqual(if (c < 0) null else @as(?usize, @intCast(c)), z);
}

fn sameClosedInode(name: []const u8) !void {
    var n: [512]u8 = undefined;
    @memcpy(n[0..name.len], name);
    n[name.len] = 0;
    try testing.expectEqual(@as(u64, c_closed_inode(@ptrCast(&n))), record.closedInode(name));
}

var scratch: [2 * record.rec_max]u8 = undefined;
var machine_scratch: [256]u8 = undefined;

/// 10,000 random token lists under `seed`, each fed to `f`.
fn differential(seed: u64, comptime f: fn (std.Random, []u16) anyerror!void) !void {
    var prng = std.Random.DefaultPrng.init(seed);
    const r = prng.random();
    var tokens: [48]u16 = undefined;
    for (0..10_000) |_| {
        const len = r.uintAtMost(usize, tokens.len);
        for (tokens[0..len]) |*t| t.* = r.int(u16);
        f(r, tokens[0..len]) catch |err| {
            std.debug.print("differs under seed {d}, tokens {any}\n", .{ seed, tokens[0..len] });
            return err;
        };
    }
}

fn seeds() [2]u64 {
    var s: [2]u64 = .{ 0xc0ffee, 0 };
    std.crypto.random.bytes(std.mem.asBytes(&s[1]));
    return s;
}

test "record.parse reads every record as parse_record does" {
    for ([_][]const u8{
        "poststop=/nix/store/x-stop\ncgroup=/sys/fs/cgroup/h/c/m\nleader=12:345\n",
        "cgroup=/sys/fs/cgroup/h/c/m\nleader=12:345\n",
        "\n\n\ncgroup=/c\nleader=1:0\n",
        "",
        "cgroup=/c",
        "cgroup=/c\x00\n",
        "cgroup=/c\nleader=01:1\n",
        "cgroup=/c\nleader=+1:1\n",
        "cgroup=/c\nleader=1:-1\n",
        "cgroup=/c\nleader=2147483648:1\n",
        "cgroup=/c\nleader=1:18446744073709551616\n",
        "cgroup=/c\ncgroup=/c\n",
        "leader=1:1\ncgroup=/c\n",
    }) |b| try sameParse(b);
    for (seeds()) |seed| try differential(seed, struct {
        fn f(r: std.Random, t: []u16) !void {
            const b = inputs.record(t, &scratch);
            try sameParse(b);
            // And the same bytes cut anywhere, as a short read would.
            try sameParse(b[0..r.uintAtMost(usize, b.len)]);
        }
    }.f);
}

test "cgroup.sessionForm spells a session's cgroup as session_form does" {
    for (seeds()) |seed| try differential(seed, struct {
        fn f(_: std.Random, t: []u16) !void {
            const m, const p = inputs.sessionForm(t, &machine_scratch, &scratch);
            try sameSessionForm(m, p);
        }
    }.f);
}

test "record.closedInode reads an event's name as closed_inode does" {
    for (seeds()) |seed| try differential(seed, struct {
        fn f(_: std.Random, t: []u16) !void {
            try sameClosedInode(inputs.inodeName(t[0..@min(t.len, 24)], scratch[0..300]));
        }
    }.f);
}
