// Must not compile: stdio passed as a descriptor. 0-2 are the program's
// stdio, set through Spawn.stdio; passFd keeps descriptors from 3 up.
const std = @import("std");
const fd = @import("fd");
const proc = @import("proc");

export fn bug() void {
    var s = proc.Spawn.init(std.heap.page_allocator, "/bin/true") catch return;
    s.passFd(fd.Stdio.err) catch return;
}
