//! test-libc: errno.zig against the glibc flong-seccomp links (ZIG.md,
//! "Tests"): strerror(3) and strerrorname_np(3) for every number from 0 to
//! 4096, and a few beyond.

const std = @import("std");
const sys = @import("sys");
const errno = @import("errno");

extern "c" fn strerror(n: c_int) [*:0]const u8;
extern "c" fn strerrorname_np(n: c_int) ?[*:0]const u8;

fn expectLikeGlibc(n: u16) !void {
    var buf: [errno.max_len]u8 = undefined;
    const e: sys.E = @enumFromInt(n);
    const want = std.mem.span(strerror(n));
    std.testing.expectEqualStrings(want, errno.describe(e, &buf)) catch |err| {
        std.debug.print("errno {d}\n", .{n});
        return err;
    };
    const want_name: ?[]const u8 = if (strerrorname_np(n)) |p| std.mem.span(p) else null;
    if (want_name) |w| {
        try std.testing.expectEqualStrings(w, errno.name(e) orelse return error.NoName);
    } else {
        try std.testing.expectEqual(@as(?[]const u8, null), errno.name(e));
    }
    // text() is describe() for every number glibc has a text for.
    if (errno.text(e)) |t| try std.testing.expectEqualStrings(want, t);
}

test "errno.zig says what glibc says, 0 to 4096" {
    for (0..4097) |n| try expectLikeGlibc(@intCast(n));
}

test "and at the top of the range" {
    for ([_]u16{ 9999, 32767, 32768, 65534, 65535 }) |n| try expectLikeGlibc(n);
}
