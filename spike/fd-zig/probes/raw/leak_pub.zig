const std = @import("std");
const posix = std.posix;

fn fixtureExact(allocator: std.mem.Allocator) !void {
    var ptr = try allocator.alloc(u8, 1);
    _ = ptr;
}

pub fn fixturePub(allocator: std.mem.Allocator) !void {
    var ptr = try allocator.alloc(u8, 1);
    _ = ptr;
}

fn fixtureConst(allocator: std.mem.Allocator) !void {
    const ptr = try allocator.alloc(u8, 1);
    _ = ptr;
}

fn fdLeakPrivate() !void {
    const fd = try posix.open("/etc/hostname", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    _ = fd;
}

fn fileLeakPrivate() !void {
    const f = try std.fs.cwd().openFile("/etc/hostname", .{});
    _ = f;
}
