// Must not compile: a directory as Spawn's cgroup. A child is created only
// in an O_PATH|O_NOFOLLOW cgroup handle (fd.openCgroup), never in whatever
// directory is at hand (ZIG.md, "Descriptor kinds").
const std = @import("std");
const fd = @import("fd");
const proc = @import("proc");

export fn bug() void {
    const r = fd.openDir(fd.cwd, "/sys/fs/cgroup") catch return;
    const d = switch (r) {
        .ok => |d| d,
        .err => return,
    };
    defer d.close();
    var s = proc.Spawn.init(std.heap.page_allocator, "/bin/true") catch return;
    s.cgroup = d;
}
