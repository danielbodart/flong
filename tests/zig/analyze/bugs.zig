//! Planted descriptor bugs for zwanzig, the spike's B1-B8
//! (spike/fd-zig/probes/api/bugs.zig, archived; B6 is a directory's here, as
//! there are no pipes yet) and phase 2's B9-B11, written against src/fd.zig
//! as flong's code calls it: an open's result through msg.check.
//! zwanzig reads syntax and matches methods by name, so this is analysed,
//! never compiled (proc.zig's Spawn arrives in phase 5). Each function is
//! one bug; `ok*` are controls that must stay quiet. B4 (a leak) and B5 (a
//! stale copy in a struct) are beyond zwanzig: the table and the property
//! test (tests/zig/fd_props.zig) catch those.

const fd = @import("fd");
const msg = @import("msg");
const proc = @import("proc");

// B1: double close
pub fn b1DoubleClose() !void {
    const f = try msg.check(fd.openFile(fd.cwd, "/etc/hostname", .{}, 0), "x", .{});
    f.close();
    f.close();
}

// B2: read after close
pub fn b2ReadAfterClose() !void {
    const f = try msg.check(fd.openFile(fd.cwd, "/etc/hostname", .{}, 0), "x", .{});
    f.close();
    var b: [1]u8 = undefined;
    _ = f.read(&b);
}

// B3: the number taken after close
pub fn b3RawAfterClose() !i32 {
    const d = try msg.check(fd.openDir(fd.cwd, "/"), "x", .{});
    d.close();
    return d.raw();
}

// B4: plain leak
pub fn b4Leak() void {
    const d = msg.check(fd.openDir(fd.cwd, "/etc"), "x", .{}) catch return;
    _ = d.raw();
}

// B5: a copy in a struct used after the original is closed
const Holder = struct { h: fd.File };
pub fn b5StaleInStruct() !void {
    const f = try msg.check(fd.openFile(fd.cwd, "/etc/hostname", .{}, 0), "x", .{});
    const s = Holder{ .h = f };
    f.close();
    var b: [1]u8 = undefined;
    _ = s.h.read(&b);
}

// B6: double close of a directory, one deferred
pub fn b6DeferAndClose() !void {
    const d = try msg.check(fd.openDir(fd.cwd, "/"), "x", .{});
    defer d.close();
    d.close();
}

// B7: a child ended twice (its pidfd closed twice)
pub fn b7ChildReleasedTwice(spawn: *proc.Spawn) !void {
    var c = try spawn.start();
    c.release();
    c.release();
}

// B8: close through an alias
pub fn b8AliasDoubleClose() !void {
    const f = try msg.check(fd.openFile(fd.cwd, "/etc/hostname", .{}, 0), "x", .{});
    const g = f;
    f.close();
    g.close();
}

// B9: a rename through a closed directory
pub fn b9RenameAfterClose(dir: [*:0]const u8) !void {
    const d = try msg.check(fd.openDir(fd.cwd, dir), "x", .{});
    d.close();
    _ = d.renameat(".tmp", d, "final");
}

// B10: project's temp file closed on its failure path and by the defer
pub fn b10TempClosedTwice(d: fd.Dir) !void {
    const tmp = try msg.check(fd.openFile(d, ".tmp", .{}, 0o600), "x", .{});
    defer tmp.close();
    if (write(tmp)) |_| {} else |_| tmp.close();
}

// B11: closed before the result is judged, and again after it
pub fn b11ClosedAgainOnError(d: fd.Dir) !void {
    const tmp = try msg.check(fd.openFile(d, ".tmp", .{}, 0o600), "x", .{});
    const written = write(tmp);
    tmp.close();
    written catch |err| {
        tmp.close();
        return err;
    };
}

fn write(f: fd.File) !void {
    _ = f;
}

// OK1: defer close
pub fn ok1Defer() !void {
    const f = try msg.check(fd.openFile(fd.cwd, "/etc/hostname", .{}, 0), "x", .{});
    defer f.close();
    var b: [1]u8 = undefined;
    _ = f.read(&b);
}

// OK2: errdefer, ownership returned
pub fn ok2Returned() !fd.Dir {
    const d = try msg.check(fd.openDir(fd.cwd, "/"), "x", .{});
    errdefer d.close();
    if (d.raw() < 0) return error.Nope;
    return d;
}

// OK3: a child awaited, which ends it
pub fn ok3Child(spawn: *proc.Spawn) !u8 {
    var c = try spawn.start();
    return c.await();
}

// OK4: project's own order: closed once, then unlinked by name on failure
pub fn ok4TempUnlinked(d: fd.Dir) !void {
    const tmp = try msg.check(fd.openFile(d, ".tmp", .{}, 0o600), "x", .{});
    const written = write(tmp);
    tmp.close();
    written catch |err| {
        _ = d.unlinkat(".tmp", 0);
        return err;
    };
}

// OK5: a held copy outlives nothing it should not
pub fn ok5Held() !fd.Held(.dir) {
    const d = try msg.check(fd.openDir(fd.cwd, "/"), "x", .{});
    return d.holdUntilExit();
}
