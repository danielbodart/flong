// Must not compile: a read of a pipe's write end, which only writes.
const fd = @import("fd");

export fn bug() void {
    const r = fd.pipe() catch return;
    const p = switch (r) {
        .ok => |p| p,
        .err => return,
    };
    defer p.r.close();
    defer p.w.close();
    var b: [1]u8 = undefined;
    _ = p.w.read(&b);
}
