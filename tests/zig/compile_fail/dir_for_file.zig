// Must not compile: a handle of one kind where another is wanted. The kind
// is in the type, so a directory is not a file.
const fd = @import("fd");

fn useFile(f: fd.File) void {
    _ = f.fstat();
}

export fn bug() void {
    const r = fd.openDir(fd.cwd, "/") catch return;
    const d = switch (r) {
        .ok => |d| d,
        .err => return,
    };
    defer d.close();
    useFile(d);
}
