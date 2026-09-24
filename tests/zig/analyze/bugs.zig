//! Planted descriptor bugs for zwanzig, the spike's B1-B8
//! (spike/fd-zig/probes/api/bugs.zig, archived; B6 is a directory's here, as
//! there are no pipes yet) and phase 2's B9-B11, written against src/fd.zig
//! as flong's code calls it: an open's result through msg.check.
//! zwanzig reads syntax and matches methods by name, so this is analysed,
//! never compiled. Each function is one bug (B12-B26 one per minting
//! function); `ok*` are controls that must stay quiet. B4 (a leak) and B5 (a
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

// ---- phase 4's B12-B15: the mount helper's kinds (src/mount.zig) ----

// B12: a walk's component closed twice
pub fn b12WalkClosedTwice(root: fd.Fd(.path)) !void {
    const next = try msg.check(fd.walkOpen(root, "srv", true), "x", .{});
    next.close();
    next.close();
}

// B13: a detached tree attached after it was closed
pub fn b13TreeMovedAfterClose(src: fd.Fd(.path), dest: fd.Fd(.path)) !void {
    const t = try msg.check(fd.openTree(src, "", 0), "x", .{});
    t.close();
    _ = t.moveTo(dest);
}

// B14: a filesystem context created after it was closed
pub fn b14FsctxAfterClose() !void {
    const ctx = try msg.check(fd.fsopen("tmpfs"), "x", .{});
    ctx.close();
    _ = ctx.create();
}

// B15: an exact source closed twice. (A close through closeChecked is
// not one zwanzig sees, even modelled as a close: the table's generation
// catches that one at run time.)
pub fn b15ExactClosedTwice() !void {
    const s = try msg.check(fd.openExact(.path, "/srv"), "x", .{});
    s.close();
    s.close();
}

// OK6: the walk's own step: the previous component closed once, the next
// returned
pub fn ok6WalkStep(root: fd.Fd(.path)) !fd.Fd(.path) {
    const a = try msg.check(fd.walkOpen(root, "srv", true), "x", .{});
    const b = try msg.check(fd.walkOpen(a, "work", true), "x", .{});
    a.close();
    return b;
}

// ---- phase 5's B16-B19: the sweeper's and the process layer's kinds ----

// B16: a cgroup closed twice
pub fn b16CgroupClosedTwice() !void {
    const cg = try msg.check(fd.openCgroup(fd.cwd, "/sys/fs/cgroup/x"), "x", .{});
    cg.close();
    cg.close();
}

// B17: an inotify descriptor watched after it was closed
pub fn b17InotifyAfterClose() !void {
    const i = try msg.check(fd.inotifyInit(), "x", .{});
    i.close();
    _ = i.addWatch("/proc/self/fd/3", 8);
}

// B18: a pidfd signalled after it was closed
pub fn b18PidfdAfterClose() !void {
    const p = (try msg.check(fd.pidfdOpen(1), "x", .{}));
    p.close();
    _ = p.sendSignal(9);
}

// B19: a state directory, opened without following, closed twice
pub fn b19NoFollowClosedTwice() !void {
    const d = try msg.check(fd.openDirNoFollow(fd.cwd, "/run/user/1000/flong"), "x", .{});
    d.close();
    d.close();
}

// OK7: a leader's pidfd awaited then closed once, as record.zig's
// wait_leader does
pub fn ok7PidfdOnce() !void {
    const p = try msg.check(fd.pidfdOpen(1), "x", .{});
    defer p.close();
    _ = p.waitid(4);
}

// ---- B20-B23: the other minting functions phase 5 added ----
// zwanzig honours `release` as a Child's ending, but not `reapNow(.kill)`
// (a close model's call with an argument) nor `try c.await()` (measured
// phase 5): a Child ended twice through those is the table's to catch at
// run time, as closeChecked's double close is.

// B20: a forked helper's Child released twice
pub fn b20ForkReleasedTwice(ctx: u8, comptime body: fn (u8) noreturn) !void {
    const c = try proc.fork(.{}, ctx, body);
    c.release();
    c.release();
}

// B21: a spawned program's Child awaited after it was released
pub fn b21SpawnAwaitedAfterRelease(s: *proc.Spawn) !void {
    const c = try s.start();
    c.release();
    _ = c.await() catch 0;
}

// B22: a signalfd read after it was closed
pub fn b22SignalfdAfterClose(si: anytype) !void {
    const s = try msg.check(fd.openSignalfd(0), "x", .{});
    s.close();
    _ = s.readSiginfo(si);
}

// B23: a pipe's write end closed twice
pub fn b23PipeClosedTwice() !void {
    const p = try msg.check(fd.pipe(), "x", .{});
    p.r.close();
    p.w.close();
    p.w.close();
}

// ---- B24-B26: the terminal's minting functions (phase 7 L3) ----

// B24: a pty master closed twice
pub fn b24PtmxClosedTwice() !void {
    const m = try msg.check(fd.openPtmx(), "x", .{});
    m.close();
    m.close();
}

// B25: a pty slave's size set after it was closed
pub fn b25SlaveAfterClose(ws: anytype) !void {
    const s = try msg.check(fd.openSlave("/dev/pts/0"), "x", .{});
    s.close();
    _ = s.setWinsize(ws);
}

// B26: the reopened terminal written after it was closed
pub fn b26OutAfterClose() !void {
    const o = try msg.check(fd.reopenOut(), "x", .{});
    o.close();
    _ = o.write("x");
}

// The terminal's controls: each opened, used, closed once.
pub fn ok8PtyOnce() !void {
    const m = try msg.check(fd.openPtmx(), "x", .{});
    defer m.close();
    _ = m.unlock();
}

pub fn ok9OutOnce() !void {
    const o = try msg.check(fd.reopenOut(), "x", .{});
    _ = o.write("x");
    o.close();
}
