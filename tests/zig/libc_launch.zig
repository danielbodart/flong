//! test-libc, the launch's half (phase 7, L2): sys.O_TMPFILE against
//! glibc's fcntl.h (tests/zig/fcntl.h, through translate-c).

const std = @import("std");
const sys = @import("sys");
const c = @import("fcntl_h");
const testing = std.testing;

test "sys.O_TMPFILE is glibc's O_TMPFILE" {
    try testing.expectEqual(@as(u32, c.O_TMPFILE), @as(u32, @bitCast(sys.O_TMPFILE)));
}
