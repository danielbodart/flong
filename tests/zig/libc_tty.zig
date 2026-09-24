//! sys.cfmakeraw against glibc's (DESIGN.md, "Tests": test-libc): the kernel's
//! struct termios as the launcher saves it (TCGETS), and glibc's own
//! struct with the same flags, line and control characters, each made raw,
//! must agree field for field, over every flag bit alone, all of them, and
//! 20,000 random structs. glibc's struct and cfmakeraw come through
//! translate-c of <termios.h> (tests/zig/termios.h), from the glibc this
//! build links.

const std = @import("std");
const sys = @import("sys");
const c = @import("termios_h");
const testing = std.testing;

/// glibc's struct with the kernel's values: what glibc's tcgetattr fills
/// from TCGETS, but for the speeds, which cfmakeraw leaves alone.
fn glibcOf(k: sys.Termios) c.struct_termios {
    var g = std.mem.zeroes(c.struct_termios);
    g.c_iflag = k.iflag;
    g.c_oflag = k.oflag;
    g.c_cflag = k.cflag;
    g.c_lflag = k.lflag;
    g.c_line = k.line;
    for (k.cc, 0..) |v, i| g.c_cc[i] = v;
    return g;
}

fn agrees(k: sys.Termios) !void {
    var g = glibcOf(k);
    c.cfmakeraw(&g);
    var z = k;
    sys.cfmakeraw(&z);
    try testing.expectEqual(@as(u32, @intCast(g.c_iflag)), z.iflag);
    try testing.expectEqual(@as(u32, @intCast(g.c_oflag)), z.oflag);
    try testing.expectEqual(@as(u32, @intCast(g.c_cflag)), z.cflag);
    try testing.expectEqual(@as(u32, @intCast(g.c_lflag)), z.lflag);
    try testing.expectEqual(g.c_line, z.line);
    for (z.cc, 0..) |v, i| try testing.expectEqual(g.c_cc[i], v);
}

test "the kernel's first 19 control characters are glibc's, VMIN and VTIME at the same places" {
    try testing.expect(sys.nccs <= c.NCCS);
    try testing.expectEqual(c.VMIN, sys.VMIN);
    try testing.expectEqual(c.VTIME, sys.VTIME);
    for ([_][2]u32{
        .{ sys.IGNBRK, c.IGNBRK }, .{ sys.BRKINT, c.BRKINT }, .{ sys.PARMRK, c.PARMRK }, .{ sys.ISTRIP, c.ISTRIP },
        .{ sys.INLCR, c.INLCR },   .{ sys.IGNCR, c.IGNCR },   .{ sys.ICRNL, c.ICRNL },   .{ sys.IXON, c.IXON },
        .{ sys.OPOST, c.OPOST },   .{ sys.ISIG, c.ISIG },     .{ sys.ICANON, c.ICANON }, .{ sys.ECHO, c.ECHO },
        .{ sys.ECHONL, c.ECHONL }, .{ sys.IEXTEN, c.IEXTEN }, .{ sys.CSIZE, c.CSIZE },   .{ sys.CS8, c.CS8 },
        .{ sys.PARENB, c.PARENB },
    }) |p| try testing.expectEqual(p[1], p[0]);
}

test "cfmakeraw agrees with glibc's: each bit alone, none, all" {
    const zero: sys.Termios = .{ .iflag = 0, .oflag = 0, .cflag = 0, .lflag = 0, .line = 0, .cc = @splat(0) };
    try agrees(zero);
    try agrees(.{ .iflag = ~@as(u32, 0), .oflag = ~@as(u32, 0), .cflag = ~@as(u32, 0), .lflag = ~@as(u32, 0), .line = 0xff, .cc = @splat(0xff) });
    var bit: u5 = 0;
    while (true) : (bit += 1) {
        const b = @as(u32, 1) << bit;
        var t = zero;
        t.iflag = b;
        t.oflag = b;
        t.cflag = b;
        t.lflag = b;
        try agrees(t);
        if (bit == 31) break;
    }
}

test "cfmakeraw agrees with glibc's over random structs" {
    var prng = std.Random.DefaultPrng.init(0x7e5);
    const r = prng.random();
    for (0..20_000) |_| {
        var t: sys.Termios = undefined;
        r.bytes(std.mem.asBytes(&t));
        try agrees(t);
    }
}
