// Must not compile: a file where a directory is taken, as the dirfd of an
// open (openat relative to a file is ENOTDIR at run time, caught here).
const fd = @import("fd");

export fn bug() void {
    const r = fd.openFile(fd.cwd, "/etc/passwd", .{}, 0) catch return;
    const f = switch (r) {
        .ok => |f| f,
        .err => return,
    };
    defer f.close();
    _ = fd.openFile(f, "x", .{}, 0) catch return;
}
