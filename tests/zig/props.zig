//! Property tests over num.zig (minish, the `test` step; DESIGN.md, "Tests").
//! libc_num.zig holds it to glibc; this holds it to a model of the bases.

const std = @import("std");
const minish = @import("minish");
const num = @import("num");
const testing = std.testing;

/// The model: the prefix picks the base, the rest must be digits of it,
/// all through std.fmt.parseUnsigned, which refuses signs, blanks and
/// underscores only when told the base (it takes `_` between digits, so
/// they are refused here first).
fn model(s: []const u8) ?u64 {
    if (s.len == 0 or !std.ascii.isDigit(s[0])) return null;
    if (std.mem.indexOfScalar(u8, s, '_') != null) return null;
    var base: u8 = 10;
    var digits = s;
    if (s.len > 1 and s[0] == '0') {
        switch (s[1]) {
            'x', 'X' => {
                base = 16;
                digits = s[2..];
            },
            'b', 'B' => {
                base = 2;
                digits = s[2..];
            },
            else => base = 8,
        }
    }
    if (digits.len == 0) return null;
    return std.fmt.parseUnsigned(u64, digits, base) catch null;
}

fn agrees(s: []const u8) !void {
    try testing.expectEqual(model(s), num.strtoullBase0(s));
}

test "property: strtoullBase0 agrees with the model on any string of its characters" {
    try minish.check(testing.allocator, minish.gen.string(.{
        .min_len = 0,
        .max_len = 24,
        .charset = .custom,
        .custom_chars = "0123456789abcdefABCDEFxXbB_+- g",
    }), agrees, .{ .num_runs = 10_000, .seed = 0xf10 });
}

test "property: strtoullBase0 never panics on any bytes" {
    try minish.check(testing.allocator, minish.gen.list(u8, minish.gen.int(u8), 0, 64), struct {
        fn f(s: []const u8) !void {
            _ = num.strtoullBase0(s);
        }
    }.f, .{ .num_runs = 10_000 });
}
