// Must not compile: an operation the kind does not have. A directory is
// read through getdents64, never read(2).
const fd = @import("fd");

export fn bug() void {
    const r = fd.openDir(fd.cwd, "/") catch return;
    const d = switch (r) {
        .ok => |d| d,
        .err => return,
    };
    defer d.close();
    var b: [1]u8 = undefined;
    _ = d.read(&b);
}
