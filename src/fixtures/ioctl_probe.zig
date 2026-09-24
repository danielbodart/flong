//! ioctl-probe REQUEST: prints the errno name of ioctl(0, REQUEST, buf), or
//! ok (ZIG.md, "Phase 6"). The C that tests/probes.nix held until phase 6,
//! line by line. The buffer, 256 zero bytes, holds whatever a request it is
//! asked about writes back: TCGETS on a real terminal writes a whole
//! termios. The request is passed whole, all 64 bits, which the C library's
//! ioctl would truncate to an int; it is read as the C's strtoul(s, NULL,
//! 0) reads it (`strtoul0`).
//!
//! Static, no libc. An errno glibc has no name for is "(null)", where the
//! C's puts(NULL) would crash; no request a caller makes reaches it.

const std = @import("std");
const linux = std.os.linux;
const sys = @import("sys");
const errno = @import("errno");
const msg = @import("msg");

pub const std_options: std.Options = .{
    .enable_segfault_handler = false,
    .keep_sigpipe = true,
};

pub const panic = std.debug.FullPanic(msg.onPanic(125));

pub fn main() noreturn {
    msg.prog = "ioctl-probe";
    msg.mode = .whole;
    const argv = sys.argv();
    if (argv.len != 2) {
        msg.bare("usage: ioctl-probe REQUEST", .{});
        sys.exitGroup(2);
    }
    const request = strtoul0(std.mem.span(argv[1]));
    var buf = [_]u8{0} ** 256;
    const rc = linux.syscall3(.ioctl, 0, request, @intFromPtr(&buf));
    // Only 0 is ok; any other return prints errno's name, and a positive
    // one (NS_GET_NSTYPE's, an fd) leaves errno as it was, 0 (its name "0").
    const e = linux.E.init(rc);
    const name: []const u8 = if (rc == 0) "ok" else errno.name(e) orelse "(null)";
    // puts: the name and a newline, in one write at exit.
    var line: [32]u8 = undefined;
    @memcpy(line[0..name.len], name);
    line[name.len] = '\n';
    var rest: []const u8 = line[0 .. name.len + 1];
    while (rest.len > 0) {
        switch (sys.write(1, rest)) {
            .ok => |n| rest = rest[n..],
            .err => break,
        }
    }
    sys.exitGroup(0);
}

/// glibc's strtoul(s, NULL, 0) on a 64-bit long, in the C locale, as the C
/// compiled with _GNU_SOURCE calls it (glibc 2.38 and later give it C23's,
/// which reads a 0b prefix): blanks skipped, one sign, then the base from
/// the prefix: 0x or 0X before a hex digit, hexadecimal; 0b or 0B before a
/// 0 or 1, binary; a leading 0, octal; else decimal. Digits of the base
/// are read up to the first that is not one; none is 0. Past 2^64 - 1 the
/// value is 2^64 - 1 whatever the sign; a '-' negates it modulo 2^64.
pub fn strtoul0(s: []const u8) u64 {
    var i: usize = 0;
    while (i < s.len and (s[i] == ' ' or (s[i] >= '\t' and s[i] <= '\r'))) i += 1;
    var negative = false;
    if (i < s.len and (s[i] == '+' or s[i] == '-')) {
        negative = s[i] == '-';
        i += 1;
    }
    var base: u8 = 10;
    if (i < s.len and s[i] == '0') {
        base = 8;
        if (i + 2 < s.len) {
            const x = s[i + 1];
            if ((x == 'x' or x == 'X') and digit(s[i + 2]) < 16) {
                base = 16;
                i += 2;
            } else if ((x == 'b' or x == 'B') and digit(s[i + 2]) < 2) {
                base = 2;
                i += 2;
            }
        }
    }
    var v: u64 = 0;
    var range = false;
    while (i < s.len and digit(s[i]) < base) : (i += 1) {
        const shifted = @mulWithOverflow(v, base);
        const added = @addWithOverflow(shifted[0], digit(s[i]));
        if (shifted[1] != 0 or added[1] != 0) range = true;
        v = added[0];
    }
    if (range) return std.math.maxInt(u64);
    return if (negative) 0 -% v else v;
}

/// A digit's value in any base up to 36, or 36 when `ch` is none.
fn digit(ch: u8) u8 {
    return switch (ch) {
        '0'...'9' => ch - '0',
        'a'...'z' => ch - 'a' + 10,
        'A'...'Z' => ch - 'A' + 10,
        else => 36,
    };
}

const testing = std.testing;

test "strtoul0 reads as glibc's strtoul with base 0" {
    try testing.expectEqual(@as(u64, 0x5412), strtoul0("0x5412"));
    try testing.expectEqual(@as(u64, 0x100005412), strtoul0("0x100005412"));
    try testing.expectEqual(@as(u64, 21522), strtoul0("21522"));
    try testing.expectEqual(@as(u64, 0o52022), strtoul0("052022"));
    try testing.expectEqual(@as(u64, 5), strtoul0("0b101"));
    try testing.expectEqual(@as(u64, 0), strtoul0("0x"));
    try testing.expectEqual(@as(u64, 0), strtoul0("0xg"));
    try testing.expectEqual(@as(u64, 0), strtoul0("0b2"));
    try testing.expectEqual(@as(u64, 0), strtoul0(""));
    try testing.expectEqual(@as(u64, 12), strtoul0(" \t+12z"));
    try testing.expectEqual(@as(u64, 0 -% @as(u64, 12)), strtoul0("-12"));
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), strtoul0("0x10000000000000000"));
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), strtoul0("-0x10000000000000000"));
}
