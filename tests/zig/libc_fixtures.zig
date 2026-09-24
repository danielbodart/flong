//! test-libc: the fixtures' number readers against the glibc calls their C
//! made (the Zig port's phase 6): ioctl-probe's strtoul0 against strtoul(s,
//! NULL, 0), which a C built with _GNU_SOURCE calls as glibc's C23
//! __isoc23_strtoul (it reads 0b); bpfdump's atoi against atoi. Every
//! string of up to 3 bytes over an alphabet of the characters either reads
//! differently, and random longer ones.

const std = @import("std");
const ioctl_probe = @import("ioctl_probe");
const bpfdump = @import("bpfdump");

extern fn __isoc23_strtoul(s: [*:0]const u8, end: ?*[*:0]u8, base: c_int) c_ulong;
extern fn atoi(s: [*:0]const u8) c_int;

const alphabet = " \t+-0179abfxXbBgz";

fn check(s: []const u8) !void {
    var buf: [128]u8 = undefined;
    @memcpy(buf[0..s.len], s);
    buf[s.len] = 0;
    const z: [*:0]const u8 = buf[0..s.len :0];
    try std.testing.expectEqual(@as(u64, __isoc23_strtoul(z, null, 0)), ioctl_probe.strtoul0(s));
    try std.testing.expectEqual(@as(i32, atoi(z)), bpfdump.atoi(s));
}

test "every short string" {
    var s: [3]u8 = undefined;
    try check("");
    for (alphabet) |a| {
        s[0] = a;
        try check(s[0..1]);
        for (alphabet) |b_| {
            s[1] = b_;
            try check(s[0..2]);
            for (alphabet) |c| {
                s[2] = c;
                try check(s[0..3]);
            }
        }
    }
}

test "the edges and random strings" {
    for ([_][]const u8{
        "0x5412",                  "0x100005412",          "0x10000541c",           "0x100005401",
        "18446744073709551615",    "18446744073709551616", "-18446744073709551615", "0xffffffffffffffff",
        "0x10000000000000000",     "0b" ++ "1" ** 64,      "0b1" ++ "0" ** 64,      "01777777777777777777777",
        "02000000000000000000000", "2147483647",           "2147483648",            "-2147483649",
        "9223372036854775807",     "9223372036854775808",  "-9223372036854775808",  "-9223372036854775809",
        "4294967296",              "  -0x5412",            "\x0b12",                "\r\n 0b",
    }) |s| try check(s);
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const r = prng.random();
    for (0..20000) |_| {
        var s: [40]u8 = undefined;
        const n = r.uintLessThan(usize, s.len);
        for (s[0..n]) |*ch| ch.* = if (r.boolean()) alphabet[r.uintLessThan(usize, alphabet.len)] else "0123456789abcdef"[r.uintLessThan(usize, 16)];
        try check(s[0..n]);
    }
}
