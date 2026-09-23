// Must not compile: a pidfd where a directory is wanted.
const fd = @import("fd");

export fn bug() void {
    var plan = fd.Spawn.init("/bin/true");
    var child = plan.start() catch return;
    defer child.deinit();
    _ = fd.openFile(child.pidfd, "x", .{}) catch {};
}
