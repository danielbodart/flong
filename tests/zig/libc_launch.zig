//! test-libc, the launch's half (phase 7, L2): cgroup.mountinfo against
//! cg_check_nsdelegate (flong-cgroup.c:44-88) reading the same text, the C
//! compiled from launcher/ as the launcher compiles it
//! (tests/zig/mountinfo_c.c), over fixed cases, the corpus's shapes, then
//! 10,000 inputs (tests/zig/inputs.zig) under a fixed seed and 10,000 under
//! a random one, printed on a difference; and sys.O_TMPFILE against glibc's
//! fcntl.h.

const std = @import("std");
const sys = @import("sys");
const cgroup = @import("cgroup");
const inputs = @import("inputs");
const testing = std.testing;

extern fn c_check_nsdelegate(text: [*]const u8, len: usize, said: *[*:0]const u8) c_int;
extern fn c_o_tmpfile() c_uint;
extern fn c_has_item(list: [*:0]const u8, item: [*:0]const u8, sep: u8) c_int;

/// What the C decided, by what it said.
fn cVerdict(text: []const u8) !cgroup.Mountinfo {
    var said: [*:0]const u8 = undefined;
    const rc = c_check_nsdelegate(text.ptr, text.len, &said);
    if (rc == 0) return .delegated;
    const s = std.mem.span(said);
    if (std.mem.startsWith(u8, s, "cgroup2 is not mounted at /sys/fs/cgroup: ")) return .not_cgroup2;
    if (std.mem.startsWith(u8, s, "cgroup2 at /sys/fs/cgroup is not mounted with nsdelegate: ")) return .not_delegated;
    std.debug.print("the C said: {s}\n", .{s});
    return error.Unexpected;
}

fn same(text: []const u8) !void {
    const c = try cVerdict(text);
    const z = cgroup.mountinfo(text);
    if (c != z) {
        std.debug.print("mountinfo differs: C {s}, Zig {s}, over {d} bytes: \"{f}\"\n", .{ @tagName(c), @tagName(z), text.len, std.zig.fmtString(text[0..@min(text.len, 400)]) });
        return error.Differs;
    }
}

test "mountinfo: the fixed cases, equal to the C" {
    for ([_][]const u8{
        "",
        "\n",
        "29 23 0:26 / /sys/fs/cgroup rw shared:4 - cgroup2 cgroup2 rw,nsdelegate,memory_recursiveprot\n",
        "29 23 0:26 / /sys/fs/cgroup rw shared:4 - cgroup2 cgroup2 rw\n",
        "29 23 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw,nsdelegate\n40 29 0:30 / /sys/fs/cgroup rw - tmpfs tmpfs rw\n",
        "40 29 0:30 / /sys/fs/cgroup rw - tmpfs tmpfs rw\n29 23 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup2 nsdelegate\n",
        // A later line without its separator changes nothing.
        "29 23 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup2 nsdelegate\n41 29 0:31 / /sys/fs/cgroup rw\n",
        "29 23 0:26 / /sys/fs/cgroup rw - cgroup2",
        "29 23 0:26 / /sys/fs/cgroup - cgroup2 cgroup2 nsdelegate",
        "29 23 0:26 / /sys/fs/cgroup",
        "29 23 0:26 / /sys/fs/cgroup ",
        "29 23 0:26 / /sys/fs/cgroup  - cgroup2 x nsdelegate\n",
        "29  23   0:26 / /sys/fs/cgroup rw  -  cgroup2  cgroup2  ,,nsdelegate,\n",
        "29 23 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw,nsdel\x00egate\n",
        "29 23 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw,nsdelegate\x00\n",
        "29 23 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw,nsdelegatex,xnsdelegate\n",
        "29 23 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup2 nsdelegate,\n",
        "29 23 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup2 ,nsdelegate\n",
        "29 23 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw,,\n",
        "29 23 0:26 / /sys/fs/cgroup rw - - cgroup2 cgroup2 nsdelegate\n",
        "29 23 0:26 / /sys/fs/cgroup rw -- cgroup2 cgroup2 nsdelegate\n",
        "29 23 0:26 / /sys/fs/cgroup\\040x rw - cgroup2 cgroup2 nsdelegate\n",
        "\x00 29 23 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup2 nsdelegate\n",
        "29 23 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup2 nsdelegate\r\n",
        "29 23 0:26 / /sys/fs/cgroup rw\t- cgroup2 cgroup2 nsdelegate\n",
        "a b c d /sys/fs/cgroup - cgroup2 s nsdelegate",
        "a b c d /sys/fs/cgroup x - cgroup2",
        "a b c d /sys/fs/cgroup x -  cgroup2   s   nsdelegate",
    }) |t| try same(t);
    // A line longer than any buffer: getline's, and the whole read.
    var long: [20000]u8 = undefined;
    const head = "29 23 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw,";
    @memcpy(long[0..head.len], head);
    @memset(long[head.len..], 'x');
    const tail = ",nsdelegate\n";
    @memcpy(long[long.len - tail.len ..], tail);
    try same(&long);
}

var scratch: [16384]u8 = undefined;

fn randomSeed() u64 {
    var b: [8]u8 = undefined;
    _ = std.os.linux.getrandom(&b, b.len, 0);
    return std.mem.readInt(u64, &b, .little);
}

test "mountinfo: 10,000 token-built texts, fixed and random seeds, equal to the C" {
    for ([_]u64{ 0xf1_0e6, randomSeed() }) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        const r = prng.random();
        var delegated: usize = 0;
        for (0..10_000) |_| {
            var tokens: [48]u16 = undefined;
            const n = r.uintAtMost(usize, tokens.len);
            for (tokens[0..n]) |*t| t.* = r.int(u16);
            const text = inputs.mountinfo(tokens[0..n], &scratch);
            same(text) catch |err| {
                std.debug.print("seed {x}\n", .{seed});
                return err;
            };
            if (cgroup.mountinfo(text) == .delegated) delegated += 1;
        }
        // The builder reaches the answer that lets a launch on.
        try testing.expect(delegated >= 100);
    }
}

test "hasItem: 100,000 lists and items, both separators, equal to the C" {
    // Short texts over a small alphabet, so items, prefixes, runs of
    // separators and the other separator all come up; the list may hold a
    // NUL, which ends it for both.
    const alphabet = "ab, \x00";
    var prng = std.Random.DefaultPrng.init(0x4a5_1e3);
    const r = prng.random();
    var found: usize = 0;
    for (0..100_000) |_| {
        var list: [13:0]u8 = undefined;
        var item: [4:0]u8 = undefined;
        const ln = r.uintAtMost(usize, 12);
        for (list[0..ln]) |*c| c.* = alphabet[r.uintLessThan(usize, alphabet.len)];
        list[ln] = 0;
        const in = r.uintAtMost(usize, 3);
        // An item has no NUL: it is a C string on both sides.
        for (item[0..in]) |*c| c.* = alphabet[r.uintLessThan(usize, alphabet.len - 1)];
        item[in] = 0;
        const sep: u8 = if (r.boolean()) ',' else ' ';
        const c = c_has_item(&list, &item, sep) != 0;
        const z = cgroup.hasItem(list[0..ln], item[0..in], sep);
        if (c != z) {
            std.debug.print("hasItem differs: C {}, Zig {}, list \"{f}\" item \"{f}\" sep '{c}'\n", .{ c, z, std.zig.fmtString(list[0..ln]), std.zig.fmtString(item[0..in]), sep });
            return error.Differs;
        }
        if (z) found += 1;
    }
    // Both answers come up often.
    try testing.expect(found >= 10_000 and found <= 90_000);
}

test "sys.O_TMPFILE is glibc's O_TMPFILE" {
    try testing.expectEqual(@as(u32, c_o_tmpfile()), @as(u32, @bitCast(sys.O_TMPFILE)));
}
