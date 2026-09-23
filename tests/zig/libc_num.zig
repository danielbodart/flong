//! test-libc: num.strtoullBase0 against glibc's strtoull, base 0, behind the
//! leading-digit check of flong-seccomp.c:112-121 (ZIG.md, "Tests"; quirk
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
