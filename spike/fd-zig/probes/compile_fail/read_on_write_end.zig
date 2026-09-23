// Must not compile: a read on a pipe's write end.
const fd = @import("fd");

export fn bug() void {
    const p = fd.pipe() catch return;
    var b: [1]u8 = undefined;
    _ = p.w.read(&b) catch {};
}
