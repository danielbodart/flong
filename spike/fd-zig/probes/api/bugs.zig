//! Planted fd bugs, written against fd.zig, for zwanzig. Each function is
//! one bug; `ok*` are controls that must stay quiet. Analysed, not compiled.

const fd = @import("../../src/fd.zig");

// B1: double close
pub fn b1DoubleClose() !void {
    const f = try fd.openFile(null, "/etc/hostname", .{});
    f.close();
    f.close();
}

// B2: read after close
pub fn b2ReadAfterClose() !void {
    const f = try fd.openFile(null, "/etc/hostname", .{});
    f.close();
    var b: [1]u8 = undefined;
    _ = try f.read(&b);
}

// B3: raw number taken after close
pub fn b3RawAfterClose() !i32 {
    const d = try fd.openDir(null, "/");
    d.close();
    return d.raw();
}

// B4: plain leak
pub fn b4Leak() void {
    const p = fd.openPath(null, "/etc") catch return;
    _ = p.raw();
}

// B5: a copy in a struct used after the original is closed
const Holder = struct { h: fd.File };
pub fn b5StaleInStruct() !void {
    const f = try fd.openFile(null, "/etc/hostname", .{});
    const s = Holder{ .h = f };
    f.close();
    var b: [1]u8 = undefined;
    _ = try s.h.read(&b);
}

// B6: double close of a pipe end
pub fn b6PipeDoubleClose() !void {
    const p = try fd.pipe();
    defer p.r.close();
    p.w.close();
    p.w.close();
}

// B7: a child deinit twice (closes its pidfd twice)
pub fn b7ChildDoubleDeinit() !void {
    var plan = fd.Spawn.init("/run/current-system/sw/bin/true");
    var c = try plan.start();
    c.deinit();
    c.deinit();
}

// B8: close through an alias
pub fn b8AliasDoubleClose() !void {
    const f = try fd.openFile(null, "/etc/hostname", .{});
    const g = f;
    f.close();
    g.close();
}

// OK1: defer close
pub fn ok1Defer() !void {
    const f = try fd.openFile(null, "/etc/hostname", .{});
    defer f.close();
    var b: [1]u8 = undefined;
    _ = try f.read(&b);
}

// OK2: errdefer, ownership returned
pub fn ok2Returned() !fd.Dir {
    const d = try fd.openDir(null, "/");
    errdefer d.close();
    if (d.raw() < 0) return error.Nope;
    return d;
}

// OK3: child waited then deinit
pub fn ok3Child() !u8 {
    var plan = fd.Spawn.init("/run/current-system/sw/bin/true");
    var c = try plan.start();
    defer c.deinit();
    return c.wait();
}
