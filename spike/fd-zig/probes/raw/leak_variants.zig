const std = @import("std");
const posix = std.posix;

// leak after a read, void return
pub fn leakAfterRead() void {
    const fd = posix.open("/etc/hostname", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0) catch return;
    var buf: [8]u8 = undefined;
    _ = posix.read(fd, &buf) catch {};
}

// leak, allocator named "allocator" as in the docs
pub fn leakAlloc(allocator: std.mem.Allocator) void {
    const p = allocator.alloc(u8, 4) catch return;
    p[0] = 1;
}

// leak File after read, void return
pub fn leakFile() void {
    const f = std.fs.cwd().openFile("/etc/hostname", .{}) catch return;
    var buf: [8]u8 = undefined;
    _ = f.read(&buf) catch {};
}

// double free as in the docs
pub fn docDoubleFree(allocator: std.mem.Allocator) !void {
    const ptr = try allocator.alloc(u8, 1);
    allocator.free(ptr);
    allocator.free(ptr);
}
