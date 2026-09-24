//! test-libc: num.strtoullBase0 against glibc's strtoull, base 0, behind the
//! leading-digit check of flong-seccomp.c:112-121 (DESIGN.md, "Tests"; quirk
//! 15). The C is built with _GNU_SOURCE, under which glibc 2.38 and later
//! redirect strtoull to __isoc23_strtoull, the C23 one that reads 0b; so
//! that is the one compared (the plain symbol is the older, which does not).

const std = @import("std");
const num = @import("num");

extern "c" fn __isoc23_strtoull(s: [*:0]const u8, end: *[*:0]const u8, base: c_int) c_ulonglong;
extern "c" fn __errno_location() *c_int;

/// flong-seccomp.c's parse_number, verbatim but for the types.
fn parseNumberC(s: [:0]const u8) ?u64 {
    if (s.len == 0 or s[0] < '0' or s[0] > '9') return null;
    __errno_location().* = 0;
    var end: [*:0]const u8 = undefined;
    const v = __isoc23_strtoull(s.ptr, &end, 0);
    if (__errno_location().* != 0 or end[0] != 0) return null;
    return v;
}

fn expectLikeC(s: []const u8) !void {
    var buf: [128]u8 = undefined;
    @memcpy(buf[0..s.len], s);
    buf[s.len] = 0;
    const z = buf[0..s.len :0];
    std.testing.expectEqual(parseNumberC(z), num.strtoullBase0(s)) catch |err| {
        std.debug.print("differs on \"{f}\"\n", .{std.zig.fmtString(s)});
        return err;
    };
}

// Every character a policy's value could hold that means anything to
// strtoull, and some that do not.
const alphabet = "0123456789abcdefABCDEFxXbBgGzZ+- \t_.8";

test "every string of up to 4 characters over the alphabet" {
    var s: [4]u8 = undefined;
    try expectLikeC("");
    for (1..5) |len| {
        var idx = [_]usize{0} ** 4;
        outer: while (true) {
            for (0..len) |i| s[i] = alphabet[idx[i]];
            try expectLikeC(s[0..len]);
            var k: usize = 0;
            while (k < len) : (k += 1) {
                idx[k] += 1;
                if (idx[k] < alphabet.len) continue :outer;
                idx[k] = 0;
            }
            break;
        }
    }
}

test "the edges of the range, in every base" {
    for ([_][]const u8{
        "18446744073709551615",                                               "18446744073709551616",
        "99999999999999999999",                                               "0xffffffffffffffff",
        "0x10000000000000000",                                                "0x0000000000000000000ffffffffffffffff",
        "01777777777777777777777",                                            "02000000000000000000000",
        "0b1111111111111111111111111111111111111111111111111111111111111111", "0b10000000000000000000000000000000000000000000000000000000000000000",
        "0x",                                                                 "0b",
        "0x1",                                                                "0b1",
        "0b102",                                                              "0xfg",
        "010",                                                                "018",
        "1_0",                                                                "0xFFFFFFFF",
        "4294967295",
    }) |s| try expectLikeC(s);
}

test "random strings of digits and prefixes" {
    var prng = std.Random.DefaultPrng.init(0xf10);
    const r = prng.random();
    var s: [40]u8 = undefined;
    for (0..200_000) |_| {
        const len = r.intRangeAtMost(usize, 1, s.len);
        for (s[0..len]) |*ch| ch.* = alphabet[r.uintLessThan(usize, 22)]; // digits, a-f, A-F
        switch (r.uintLessThan(u8, 4)) {
            0 => {},
            1 => if (len > 2) {
                s[0] = '0';
                s[1] = "xXbB"[r.uintLessThan(usize, 4)];
            },
            2 => s[0] = '0',
            else => if (len > 2) {
                s[0] = '0';
                s[1] = 'b';
                for (s[2..len]) |*ch| ch.* = "01"[r.uintLessThan(usize, 2)];
            },
        }
        try expectLikeC(s[0..len]);
    }
}

// ---- num.strtoull10 against glibc's strtoull, base 10 ----
// fl_starttime's field 22 (flong-util.c:384) and closed_inode's "#<inode>"
// (flong-record.c:751) read outside text with it: the value, where it
// stopped and ERANGE must be glibc's for any bytes.

fn expectBase10LikeC(s: []const u8) !void {
    var buf: [128]u8 = undefined;
    @memcpy(buf[0..s.len], s);
    buf[s.len] = 0;
    __errno_location().* = 0;
    var end: [*:0]const u8 = undefined;
    const v = __isoc23_strtoull(@ptrCast(&buf), &end, 10);
    const want: num.Strtoull = .{
        .value = v,
        .len = @intFromPtr(end) - @intFromPtr(&buf),
        .range = __errno_location().* != 0,
    };
    std.testing.expectEqual(want, num.strtoull10(s)) catch |err| {
        std.debug.print("strtoull10 differs on \"{f}\"\n", .{std.zig.fmtString(s)});
        return err;
    };
}

const alphabet10 = "0123456789 \t\n\x0b\x0c\r+-x\x00a";

test "strtoull10: every string of up to 4 characters, and random ones" {
    var s: [4]u8 = undefined;
    try expectBase10LikeC("");
    for (1..5) |len| {
        var idx = [_]usize{0} ** 4;
        outer: while (true) {
            for (0..len) |i| s[i] = alphabet10[idx[i]];
            try expectBase10LikeC(s[0..len]);
            var k: usize = 0;
            while (k < len) : (k += 1) {
                idx[k] += 1;
                if (idx[k] < alphabet10.len) continue :outer;
                idx[k] = 0;
            }
            break;
        }
    }
    var seed: u64 = 0x5eed10;
    for (0..2) |round| {
        if (round == 1) std.crypto.random.bytes(std.mem.asBytes(&seed));
        var prng = std.Random.DefaultPrng.init(seed);
        const r = prng.random();
        var t: [40]u8 = undefined;
        for (0..10_000) |_| {
            const len = r.intRangeAtMost(usize, 0, t.len);
            for (t[0..len]) |*ch| ch.* = if (r.boolean()) '0' + r.uintLessThan(u8, 10) else alphabet10[r.uintLessThan(usize, alphabet10.len)];
            expectBase10LikeC(t[0..len]) catch |err| {
                std.debug.print("seed {d}\n", .{seed});
                return err;
            };
        }
    }
    for ([_][]const u8{ "18446744073709551615", "18446744073709551616", "-18446744073709551615", "-18446744073709551616", "  -1", "+", "-", "00000000000000000000000000001" }) |e|
        try expectBase10LikeC(e);
}
