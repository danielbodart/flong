//! fd-probe: prints the descriptors it was started with, space separated,
//! then its argv after argv[0]: "0 1 2 7 | 7". A spawn test compares the
//! two halves: what the child holds against what its argv names.

const std = @import("std");
const procfds = @import("procfds.zig");

pub fn main() !void {
    const set = try procfds.read();
    var buf: [1024]u8 = undefined;
    var w = std.fs.File.stdout().writer(&buf);
    const out = &w.interface;
    for (set.slice(), 0..) |fd, i| try out.print("{s}{d}", .{ if (i == 0) "" else " ", fd });
    try out.writeAll(" |");
    for (std.os.argv[1..]) |a| try out.print(" {s}", .{a});
    try out.writeAll("\n");
    try out.flush();
}
