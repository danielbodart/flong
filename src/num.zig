//! num.zig: numbers from outside the process, read exactly as the C read
//! them (ZIG.md, "Messages, errors and panics").
//!
//! This file imports nothing of flong's. It grows with the programs.

const std = @import("std");

/// A policy's comparison value, as flong-seccomp.c:112-121's parse_number
/// reads it: the first byte a decimal digit, then glibc's strtoull with base
/// 0 over the whole of `s`, refusing a range error or anything left over
/// (quirk 15). Null is a refusal.
///
/// The digit check leaves strtoull no blank, sign or wrap to take, so what
/// remains of it is the base, from the prefix:
///   0x or 0X and a hex digit: hexadecimal, after the prefix
///   0b or 0B and a 0 or 1: binary, after the prefix; the C is built with
///     _GNU_SOURCE, so glibc 2.38 and later give it the C23 strtoull, which
///     reads this prefix (the golden case numbers.bpf pins `0b1` as 1)
///   0: octal, the 0 included
///   otherwise decimal
/// 0x or 0b followed by anything else is glibc's "0" with the rest left
/// over, so a refusal here. A value above 2^64 - 1 is ERANGE, a refusal.
///
/// `s` holds no NUL: a C string ends at its first, and the caller's words
/// come from a line split where one would have ended it.
pub fn strtoullBase0(s: []const u8) ?u64 {
    if (s.len == 0 or !std.ascii.isDigit(s[0])) return null;
    var base: u8 = 10;
    var digits = s;
    if (s[0] == '0' and s.len > 1) {
        switch (s[1]) {
            'x', 'X' => if (s.len > 2 and digitValue(s[2]) < 16) {
                base = 16;
                digits = s[2..];
            } else return null,
            'b', 'B' => if (s.len > 2 and digitValue(s[2]) < 2) {
                base = 2;
                digits = s[2..];
            } else return null,
            else => base = 8,
        }
    }
    var v: u64 = 0;
    for (digits) |ch| {
        const d = digitValue(ch);
        if (d >= base) return null;
        const shifted = @mulWithOverflow(v, base);
        if (shifted[1] != 0) return null;
        const added = @addWithOverflow(shifted[0], d);
        if (added[1] != 0) return null;
        v = added[0];
    }
    return v;
}

/// What glibc's strtoull(s, &end, 10) answers over the C string `s` (up to
/// its first NUL, if any): the value, how many bytes it read (`end - s`;
/// 0 when there were no digits), and whether it said ERANGE. As glibc, in
/// the C locale: blanks (space, \t, \n, \v, \f, \r) skipped, then one
/// optional sign, then decimal digits; a '-' negates the value modulo 2^64;
/// past 2^64 - 1 the value is 2^64 - 1 and ERANGE is set, whatever the
/// sign. For fl_starttime's field 22 (flong-util.c:384) and closed_inode's
/// "#<inode>" (flong-record.c:745-753), which read outside text as the C did.
pub const Strtoull = struct { value: u64, len: usize, range: bool };

pub fn strtoull10(s: []const u8) Strtoull {
    const text = s[0 .. std.mem.indexOfScalar(u8, s, 0) orelse s.len];
    var i: usize = 0;
    while (i < text.len and isCSpace(text[i])) i += 1;
    var negative = false;
    if (i < text.len and (text[i] == '+' or text[i] == '-')) {
        negative = text[i] == '-';
        i += 1;
    }
    const first = i;
    var v: u64 = 0;
    var range = false;
    while (i < text.len and std.ascii.isDigit(text[i])) : (i += 1) {
        if (range) continue;
        const shifted = @mulWithOverflow(v, 10);
        const added = @addWithOverflow(shifted[0], text[i] - '0');
        if (shifted[1] != 0 or added[1] != 0) {
            range = true;
            v = std.math.maxInt(u64);
        } else v = added[0];
    }
    // No digits: 0, and end is s itself, the blanks and sign unread.
    if (i == first) return .{ .value = 0, .len = 0, .range = false };
    if (negative and !range) v = 0 -% v;
    return .{ .value = v, .len = i, .range = range };
}

/// isspace in the C locale.
fn isCSpace(ch: u8) bool {
    return ch == ' ' or (ch >= '\t' and ch <= '\r');
}

/// A digit's value in any base up to 36, as strtoull reads it, or 36 when
/// `ch` is no digit at all.
fn digitValue(ch: u8) u8 {
    return switch (ch) {
        '0'...'9' => ch - '0',
        'a'...'z' => ch - 'a' + 10,
        'A'...'Z' => ch - 'A' + 10,
        else => 36,
    };
}

const testing = std.testing;

test "the bases" {
    try testing.expectEqual(@as(?u64, 0), strtoullBase0("0"));
    try testing.expectEqual(@as(?u64, 10), strtoullBase0("10"));
    try testing.expectEqual(@as(?u64, 8), strtoullBase0("010"));
    try testing.expectEqual(@as(?u64, 0), strtoullBase0("00"));
    try testing.expectEqual(@as(?u64, 0x1f), strtoullBase0("0x1F"));
    try testing.expectEqual(@as(?u64, 0x1f), strtoullBase0("0X1f"));
    try testing.expectEqual(@as(?u64, 1), strtoullBase0("0b1"));
    try testing.expectEqual(@as(?u64, 5), strtoullBase0("0B101"));
    try testing.expectEqual(@as(?u64, 0), strtoullBase0("0x0"));
}

test "the limits" {
    try testing.expectEqual(@as(?u64, std.math.maxInt(u64)), strtoullBase0("18446744073709551615"));
    try testing.expectEqual(@as(?u64, null), strtoullBase0("18446744073709551616"));
    try testing.expectEqual(@as(?u64, std.math.maxInt(u64)), strtoullBase0("0xffffffffffffffff"));
    try testing.expectEqual(@as(?u64, null), strtoullBase0("0x10000000000000000"));
    try testing.expectEqual(@as(?u64, std.math.maxInt(u64)), strtoullBase0("01777777777777777777777"));
    try testing.expectEqual(@as(?u64, null), strtoullBase0("02000000000000000000000"));
    try testing.expectEqual(@as(?u64, 1), strtoullBase0("0x00000000000000000000000001"));
}

test "what the C refused" {
    for ([_][]const u8{
        "",     "+1",   "-1", " 1", "\t1", "1_0", "1 ",  "08",   "09",   "0x", "0xg", "0X", "0b", "0b2", "0B",
        "0x1g", "0b12", "1a", "a1", "0o7", "1e3", "1.0", "0xx1", "0bb1", "٣",
    }) |s| {
        try testing.expectEqual(@as(?u64, null), strtoullBase0(s));
    }
}

test "strtoull10 reads as glibc's base 10" {
    const T = Strtoull;
    try testing.expectEqual(T{ .value = 12, .len = 2, .range = false }, strtoull10("12"));
    try testing.expectEqual(T{ .value = 12, .len = 4, .range = false }, strtoull10(" \t12x"));
    try testing.expectEqual(T{ .value = 3, .len = 2, .range = false }, strtoull10("+3"));
    try testing.expectEqual(T{ .value = std.math.maxInt(u64) - 4, .len = 2, .range = false }, strtoull10("-5"));
    try testing.expectEqual(T{ .value = 0, .len = 0, .range = false }, strtoull10(" -"));
    try testing.expectEqual(T{ .value = 0, .len = 0, .range = false }, strtoull10(""));
    try testing.expectEqual(T{ .value = 0, .len = 0, .range = false }, strtoull10("x1"));
    try testing.expectEqual(T{ .value = 7, .len = 1, .range = false }, strtoull10("7\x008"));
    try testing.expectEqual(T{ .value = std.math.maxInt(u64), .len = 20, .range = false }, strtoull10("18446744073709551615"));
    try testing.expectEqual(T{ .value = std.math.maxInt(u64), .len = 20, .range = true }, strtoull10("18446744073709551616"));
    try testing.expectEqual(T{ .value = std.math.maxInt(u64), .len = 22, .range = true }, strtoull10("-999999999999999999999"));
}

test "every u64 reads back from each base" {
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const r = prng.random();
    var buf: [80]u8 = undefined;
    for (0..20_000) |i| {
        const v: u64 = switch (i % 4) {
            0 => r.int(u64),
            1 => r.int(u64) >> r.int(u6),
            2 => i,
            else => std.math.maxInt(u64) - i,
        };
        try testing.expectEqual(@as(?u64, v), strtoullBase0(try std.fmt.bufPrint(&buf, "{d}", .{v})));
        try testing.expectEqual(@as(?u64, v), strtoullBase0(try std.fmt.bufPrint(&buf, "0x{x}", .{v})));
        try testing.expectEqual(@as(?u64, v), strtoullBase0(try std.fmt.bufPrint(&buf, "0X{X}", .{v})));
        try testing.expectEqual(@as(?u64, v), strtoullBase0(try std.fmt.bufPrint(&buf, "0{o}", .{v})));
        try testing.expectEqual(@as(?u64, v), strtoullBase0(try std.fmt.bufPrint(&buf, "0b{b}", .{v})));
    }
}
