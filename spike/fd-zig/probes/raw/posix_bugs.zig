const std = @import("std");
const posix = std.posix;

// BUG: double close
pub fn doubleClose() !void {
    const fd = try posix.open("/etc/hostname", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    posix.close(fd);
    posix.close(fd);
}

// BUG: leak on the error path (no errdefer)
pub fn leakOnError(fail: bool) !posix.fd_t {
    const fd = try posix.open("/etc/hostname", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (fail) return error.Nope;
    return fd;
}

// BUG: plain leak
pub fn plainLeak() !void {
    const fd = try posix.open("/etc/hostname", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    _ = fd;
}

// BUG: use after close
pub fn useAfterClose() !void {
    const fd = try posix.open("/etc/hostname", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    posix.close(fd);
    var buf: [8]u8 = undefined;
    _ = try posix.read(fd, &buf);
}

// OK: control
pub fn fine() !void {
    const fd = try posix.open("/etc/hostname", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    defer posix.close(fd);
    var buf: [8]u8 = undefined;
    _ = try posix.read(fd, &buf);
}
