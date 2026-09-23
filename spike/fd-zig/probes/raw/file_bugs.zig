const std = @import("std");

// BUG: double close
pub fn doubleClose() !void {
    const f = try std.fs.cwd().openFile("/etc/hostname", .{});
    f.close();
    f.close();
}

// BUG: leak on the error path
pub fn leakOnError(fail: bool) !std.fs.File {
    const f = try std.fs.cwd().openFile("/etc/hostname", .{});
    if (fail) return error.Nope;
    return f;
}

// BUG: plain leak
pub fn plainLeak() !void {
    const f = try std.fs.cwd().openFile("/etc/hostname", .{});
    _ = f;
}

// BUG: use after close
pub fn useAfterClose() !void {
    const f = try std.fs.cwd().openFile("/etc/hostname", .{});
    f.close();
    var buf: [8]u8 = undefined;
    _ = try f.read(&buf);
}

// OK
pub fn fine() !void {
    const f = try std.fs.cwd().openFile("/etc/hostname", .{});
    defer f.close();
    var buf: [8]u8 = undefined;
    _ = try f.read(&buf);
}
