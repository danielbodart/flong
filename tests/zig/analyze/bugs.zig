//! Planted descriptor bugs for zwanzig, the spike's B1-B8
//! (spike/fd-zig/probes/api/bugs.zig), written against the fd.zig of ZIG.md
//! ("The descriptor layer"), which lands in phase 2: zwanzig reads syntax
//! and matches methods by name, so this is analysed, never compiled. Each
//! function is one bug; `ok*` are controls that must stay quiet. B4 (a leak)
//! and B5 (a stale copy in a struct) are beyond zwanzig: the table and the
//! property test catch those.

const fd = @import("fd");
const proc = @import("proc");

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

// B3: the number taken after close
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

// B7: a child ended twice (its pidfd closed twice)
pub fn b7ChildReleasedTwice(spawn: *proc.Spawn) !void {
    var c = try spawn.start();
    c.release();
    c.release();
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

// OK3: a child awaited, which ends it
pub fn ok3Child(spawn: *proc.Spawn) !u8 {
    var c = try spawn.start();
    return c.await();
}
