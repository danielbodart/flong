//! ns.zig: the two user namespaces, U1 and U2 (launcher/flong-ns.c and
//! flong-ns.h of 5f1f08e; the Zig port's L2; DESIGN.md's ordering checkpoint 4).
//!
//! U1 is keep-id and owned by the caller. It owns every other namespace of
//! the session: network, mount, ipc, uts, pid, cgroup. U2 is a child of U1
//! and holds the payload, with no capabilities and, by default, no user
//! namespaces of its own. So the payload holds no capability over its
//! network namespace, even in principle (flong-ns.h:1-7).
//!
//! Each namespace is made by a process that unshares it and then waits, so
//! the namespace lives while it is opened and mapped. That process is ours
//! and unreaped until we have the namespace open, so its pid cannot name
//! anyone else when we open /proc/<pid>/ns/user (flong-ns.c:3-6).
//!
//! Every helper blocks only on pipes whose other end the launcher or
//! another helper holds, and ends when it reads EOF. So the launcher
//! releases helpers by closing its pipe ends, on success and on failure
//! alike, and a launcher that dies releases them the same way. Every wait
//! in the launcher is a sig.awaitFd, so a terminating signal aborts the
//! launch at any step (:8-12). That is why each maker below ends in one
//! cleanup, in the C's `out:` order: every pipe end closed first, then the
//! map programs killed and reaped, then the helpers reaped. An errdefer
//! chain would reap a helper while its pipe is still open, and the helper,
//! blocked on that pipe, would never end.
//!
//! The helpers are fork bodies (proc.fork): they keep only their pipe ends
//! and U1, and their sig.fd is stale, so their waits poll their own
//! descriptors alone (flong-util.c:476-479). A helper that fails says why
//! and exits 125; one that ends by a failed handshake exits 125 silently,
//! as the C's `_exit(125)` does. A status of 125 from a helper, and 127
//! from a map program (a failed exec, which the spawned child has already
//! reported), is therefore not said again (:28-40, 132-139).

const std = @import("std");
const sys = @import("sys");
const fdt = @import("fd");
const msg = @import("msg");
const sig = @import("sig");
const proc = @import("proc");
const spec = @import("spec");

const Allocator = std.mem.Allocator;
const Userns = fdt.Fd(.userns);
const Child = proc.Child;

/// struct fl_userns (flong-ns.h:11-14): a descriptor on each namespace,
/// /proc/<pid>/ns/user, O_RDONLY|O_CLOEXEC.
pub const Namespaces = struct {
    u1: Userns,
    u2: Userns,
};

/// What ns_create reads of the spec (flong-ns.h:16-35): U1's extents and
/// U2's user.max_user_namespaces.
pub const Maps = struct {
    uidmap: []const spec.IdMap,
    gidmap: []const spec.IdMap,
    nested_userns: u64 = 0,
};

/// The setuid map programs, compiled in (FLONG_NEWUIDMAP, FLONG_NEWGIDMAP):
/// /run/wrappers/bin/newuidmap and newgidmap on NixOS.
pub const Programs = struct {
    newuidmap: [*:0]const u8,
    newgidmap: [*:0]const u8,
};

/// ns_create (flong-ns.c:372-383): makes U1, then U2 inside it. Called once,
/// after the record exists and before the session cgroup is made. On
/// failure nothing is left: helpers reaped, descriptors closed. A newuidmap
/// failure names /etc/subuid and subUidRanges in its message.
/// error.Aborted when a terminating signal ended it (sig.abort_signal set).
/// Every allocation is in `gpa`, the launcher's arena.
pub fn create(gpa: Allocator, maps: Maps, progs: Programs) sig.Error!Namespaces {
    const one = try makeU1(gpa, maps, progs);
    const two = makeU2(gpa, maps, one) catch |err| {
        one.close();
        return err;
    };
    return .{ .u1 = one, .u2 = two };
}

// ---- the pieces both makers share (flong-ns.c:25-150) ----

/// helper_failed (flong-ns.c:28-40): reaps a helper that closed its pipe
/// before it was done. A helper that failed has said why and exited 125;
/// any other status (a signal, say) is said here, so a failure is never
/// silent. When the reap itself fails (a terminating signal, say), the
/// helper is left in `child` for the maker's cleanup, and that failure is
/// the answer: error.Aborted stays Aborted, as the C's fl_abort_signal
/// stays set (:35-36); error.Reported otherwise.
fn helperFailed(child: *?Child, what: []const u8) sig.Error {
    const st = child.*.?.await() catch |e| return e;
    child.* = null;
    if (st != 125) msg.say("{s} ended with status {d} before it was done", .{ what, st });
    return error.Reported;
}

/// await_msg (flong-ns.c:42-55): waits for the `buf.len` bytes a helper
/// sends in one write (at most PIPE_BUF, so they arrive together). True
/// when they came, false on EOF (the helper ended first) or a short read.
/// The handshake bytes' values are never looked at (quirk 11).
fn awaitMsg(r: fdt.Fd(.pipe_r), buf: []u8) sig.Error!bool {
    try sig.awaitFd(r, sys.POLL.IN);
    const n = try msg.check(r.read(buf), "read from a namespace helper", .{});
    return n == buf.len;
}

/// fl_write_at (flong-util.c:167-186) from the working directory, as the
/// helpers write /proc files: opened O_WRONLY|O_NOFOLLOW, all of `s`.
fn writeAt(path: [*:0]const u8, s: []const u8) msg.Error!void {
    const f = try msg.check(fdt.openFile(fdt.cwd, path, .{ .ACCMODE = .WRONLY, .NOFOLLOW = true }, 0), "open {s}", .{path});
    defer f.close();
    _ = try msg.check(f.writeAll(s), "write {s} to {s}", .{ s, path });
}

/// The C's `fl_err("malloc")` when the arena cannot grow.
fn noMemory() msg.Error {
    return msg.fail(.NOMEM, "malloc", .{});
}

/// map_argv (flong-ns.c:57-83): newuidmap's or newgidmap's argv, the
/// program, U1's pid, then each extent's inside, outside and count, in
/// `gpa`. spawn_map (:118-130) then starts it, with the launcher's own
/// environment, stdio and working directory.
fn spawnMap(gpa: Allocator, prog: [*:0]const u8, pid: sys.pid_t, m: []const spec.IdMap) msg.Error!Child {
    var s = proc.Spawn.init(gpa, prog) catch return noMemory();
    const pid_text = std.fmt.allocPrintSentinel(gpa, "{d}", .{pid}, 0) catch return noMemory();
    s.arg(pid_text.ptr) catch return noMemory();
    for (m) |e| {
        for ([_]u64{ e.inside, e.outside, e.count }) |v| {
            const t = std.fmt.allocPrintSentinel(gpa, "{d}", .{v}, 0) catch return noMemory();
            s.arg(t.ptr) catch return noMemory();
        }
    }
    return s.start();
}

/// map_failed (flong-ns.c:132-139): says why a map program failed, unless
/// it is 127, an exec failure the spawned child has already said.
fn mapFailed(prog: []const u8, st: u8, file: []const u8, option: []const u8) void {
    if (st != 127)
        msg.say("{s} failed (status {d}): the caller needs a range of at least 65536 ids in {s} (users.users.<name>.{s})", .{ prog, st, file, option });
}

/// identity_map (flong-ns.c:85-101): U2's map text, U1's extents with each
/// outside id replaced by the inside one, so U2's ids are U1's unchanged.
/// It must follow U1's extents: the kernel wants each U2 extent inside a
/// single U1 extent, so one "0 0 65536" is EPERM.
pub fn identityMap(gpa: Allocator, m: []const spec.IdMap) Allocator.Error![:0]const u8 {
    var t: std.ArrayList(u8) = .empty;
    for (m) |e| try t.print(gpa, "{d} {d} {d}\n", .{ e.inside, e.inside, e.count });
    return t.toOwnedSliceSentinel(gpa, 0);
}

// ---- U1 (flong-ns.c:103-220) ----

const U1Child = struct { up: fdt.Fd(.pipe_w), hold: fdt.Fd(.pipe_r) };

/// u1_child (flong-ns.c:103-116): unshares, says so, and holds U1 until
/// the launcher closes the hold pipe.
fn u1Child(c: U1Child) noreturn {
    switch (sys.unshare(sys.CLONE.NEWUSER)) {
        .ok => {},
        .err => |e| msg.die(e, "unshare a user namespace (U1)", .{}),
    }
    switch (c.up.write("u")) {
        .ok => |n| if (n != 1) proc.exit(125),
        .err => proc.exit(125),
    }
    var b: [1]u8 = undefined;
    proc.exit(switch (c.hold.read(&b)) {
        .ok => 0,
        .err => 125,
    });
}

/// make_u1 (flong-ns.c:152-220): U1's child unshares; newuidmap and
/// newgidmap map it, in parallel, both reaped before either is judged; U1
/// is opened while the child still holds it, and only then is the child
/// released and reaped. Ordering checkpoint 4, one function: the steps are
/// numbered, and the cleanup after them runs on every path.
pub fn makeU1(gpa: Allocator, maps: Maps, progs: Programs) sig.Error!Userns {
    var up: ?fdt.Pipe = null;
    var hold: ?fdt.Pipe = null;
    var child: ?Child = null;
    var umap: ?Child = null;
    var gmap: ?Child = null;
    var ns: ?Userns = null;

    const made: sig.Error!void = steps: {
        // 1. The two pipes: `up` carries the child's "u", `hold` keeps it
        // until the launcher closes its write end (:159-162).
        up = msg.check(fdt.pipe(), "pipe", .{}) catch |e| break :steps e;
        hold = msg.check(fdt.pipe(), "pipe", .{}) catch |e| break :steps e;

        // 2. The child, keeping its two ends; ours of them close at once
        // (:163-171).
        child = proc.fork(.{ .keep = &.{ up.?.w.any(), hold.?.r.any() } }, U1Child{ .up = up.?.w, .hold = hold.?.r }, u1Child) catch |e| break :steps e;
        up.?.w.close();
        hold.?.r.close();

        // 3. Its "u": U1 exists. EOF is a child that ended first
        // (:173-179).
        var c: [1]u8 = undefined;
        if (!(awaitMsg(up.?.r, &c) catch |e| break :steps e)) {
            break :steps helperFailed(&child, "U1's child");
        }

        // 4. newuidmap and newgidmap run together: each is a setuid program
        // that reads /etc/subuid or /etc/subgid, and neither needs the
        // other (:181-185).
        const pid = child.?.pid;
        umap = spawnMap(gpa, progs.newuidmap, pid, maps.uidmap) catch |e| break :steps e;
        gmap = spawnMap(gpa, progs.newgidmap, pid, maps.gidmap) catch |e| break :steps e;

        // 5. Both reaped before either is judged (:186-197).
        const su = umap.?.await() catch |e| break :steps e;
        umap = null;
        const sg = gmap.?.await() catch |e| break :steps e;
        gmap = null;
        if (su != 0) mapFailed("newuidmap", su, "/etc/subuid", "subUidRanges");
        if (sg != 0) mapFailed("newgidmap", sg, "/etc/subgid", "subGidRanges");
        if (su != 0 or sg != 0) break :steps error.Reported;

        // 6. U1 opened while its child holds it, then the child released
        // and reaped; its status is not looked at (:199-205).
        ns = msg.check(fdt.openUserns(pid), "open /proc/{d}/ns/user", .{pid}) catch |e| break :steps e;
        hold.?.w.close();
        _ = child.?.await() catch |e| break :steps e;
        child = null;
        msg.trace("U1-mapped");
    };

    // The cleanup (:210-219), on every path: every pipe end first, then the
    // map programs killed and reaped, then the child reaped, which the
    // closed hold pipe has released.
    if (std.meta.isError(made)) {
        if (ns) |h| h.close();
    }
    if (up) |p| {
        if (p.r.isLive()) p.r.close();
        if (p.w.isLive()) p.w.close();
    }
    if (hold) |p| {
        if (p.r.isLive()) p.r.close();
        if (p.w.isLive()) p.w.close();
    }
    if (umap) |c| c.reapNow(.kill);
    if (gmap) |c| c.reapNow(.kill);
    if (child) |c| c.reapNow(.wait);
    try made;
    return ns.?;
}

// ---- U2 (flong-ns.c:222-370) ----

/// u2_end (flong-ns.c:222-235): how U2's helper ends when U2's child is
/// not done: the child reaped, so no orphan is left, and 125. With
/// `report`, the child ended by itself and its status is said unless it
/// said why itself (125). Without, the helper has said its own failure and
/// closed the child's pipe, which ends the child. The helper has no
/// signalfd, so the reap waits only for the child's pidfd.
fn u2End(gchild: Child, report: bool) u8 {
    if (report) {
        // helper_failed: a failed reap leaves nothing to do but exit.
        const st = gchild.await() catch {
            gchild.release();
            return 125;
        };
        if (st != 125) msg.say("U2's child ended with status {d} before it was done", .{st});
    } else {
        gchild.reapNow(.wait);
    }
    return 125;
}

const U2Child = struct {
    up: fdt.Fd(.pipe_w),
    maps: fdt.Fd(.pipe_r),
    rel: fdt.Fd(.pipe_r),
    maxns: u64,
};

/// u2_child (flong-ns.c:237-258): unshares U2 from inside U1, waits for
/// its maps, then limits nested user namespaces. The limit is U2's own
/// user.max_user_namespaces, which only a process in U2 with its
/// capabilities can write, and this process has them as U2's creator. It
/// then holds U2 until the launcher closes the release pipe.
fn u2Child(c: U2Child) noreturn {
    // 1. U2, and its "u" (:247-249).
    switch (sys.unshare(sys.CLONE.NEWUSER)) {
        .ok => {},
        .err => |e| msg.die(e, "unshare a user namespace (U2)", .{}),
    }
    var b: [1]u8 = undefined;
    switch (c.up.write("u")) {
        .ok => |n| if (n != 1) proc.exit(125),
        .err => proc.exit(125),
    }
    // 2. The helper's "m": the maps are written (:249-250).
    switch (c.maps.read(&b)) {
        .ok => |n| if (n != 1) proc.exit(125),
        .err => proc.exit(125),
    }
    // 3. Only then the limit, and "n" (:251-255).
    var n: [24]u8 = undefined;
    const text = std.fmt.bufPrint(&n, "{d}", .{c.maxns}) catch unreachable; // proven: a u64 is at most 20 digits
    writeAt("/proc/sys/user/max_user_namespaces", text) catch proc.exit(125);
    switch (c.up.write("n")) {
        .ok => |w| if (w != 1) proc.exit(125),
        .err => proc.exit(125),
    }
    // 4. Held until the launcher lets go (:256-257).
    proc.exit(switch (c.rel.read(&b)) {
        .ok => 0,
        .err => 125,
    });
}

const U2Helper = struct {
    u1: Userns,
    rep: fdt.Fd(.pipe_w),
    rel: fdt.Fd(.pipe_r),
    maxns: u64,
    uidmap: []const u8,
    gidmap: []const u8,
};

/// u2_helper (flong-ns.c:260-311), in U1. Writing a namespace's maps needs
/// a process in its parent namespace with CAP_SETUID and CAP_SETGID there:
/// U1's owner has every capability in U1 once it joins it, and the
/// launcher stays outside. The helper sends U2's child's pid and then
/// waits for that child, so the pid stays the child's, even a dead one's,
/// until the launcher has opened U2 and released it. Its steps are
/// checkpoint 4's: strictly sequential with the child's, all in
/// `u2Steps`, one linear function; this only exits with its answer.
fn u2Helper(h: U2Helper) noreturn {
    proc.exit(u2Steps(h));
}

/// u2_helper's steps, in order, answering the helper's exit status. A
/// status, not an exit, ends each path, so every path visibly ends U2's
/// child (awaited, reaped or released) before the helper exits.
fn u2Steps(h: U2Helper) u8 {
    // 1. Into U1, and the two pipes to the child (:273-276).
    switch (h.u1.setns(.user)) {
        .ok => {},
        .err => |e| msg.die(e, "join U1", .{}),
    }
    const a = msg.check(fdt.pipe(), "pipe", .{}) catch return 125;
    const b = msg.check(fdt.pipe(), "pipe", .{}) catch return 125;

    // 2. The child, keeping its ends of both and the release pipe, which
    // this helper then closes with its own ends of the child's (:277-287).
    const gchild = proc.fork(.{ .keep = &.{ a.w.any(), b.r.any(), h.rel.any() } }, U2Child{
        .up = a.w,
        .maps = b.r,
        .rel = h.rel,
        .maxns = h.maxns,
    }, u2Child) catch return 125;
    a.w.close();
    b.r.close();
    h.rel.close();
    const g = gchild.pid;

    // 3. The child's "u": U2 exists (:289-290).
    var c: [1]u8 = undefined;
    switch (a.r.read(&c)) {
        .ok => |n| if (n != 1) return u2End(gchild, true),
        .err => return u2End(gchild, true),
    }

    // 4. U2's maps, uid_map then gid_map, then "m" (:291-300). A failure
    // closes the child's pipe, which ends it.
    var path_buf: [64]u8 = undefined;
    const written = blk: {
        const uid_path = std.fmt.bufPrintZ(&path_buf, "/proc/{d}/uid_map", .{g}) catch unreachable; // proven: 19 + 11 < 64
        writeAt(uid_path, h.uidmap) catch break :blk false;
        const gid_path = std.fmt.bufPrintZ(&path_buf, "/proc/{d}/gid_map", .{g}) catch unreachable; // proven: as uid_path
        writeAt(gid_path, h.gidmap) catch break :blk false;
        switch (b.w.write("m")) {
            .ok => |n| if (n == 1) break :blk true,
            .err => |e| {
                msg.sayErrno(e, "release U2's child", .{});
                break :blk false;
            },
        }
        // A write of 0 bytes: the C's fl_err with whatever errno it had.
        msg.sayErrno(.IO, "release U2's child", .{});
        break :blk false;
    };
    if (!written) {
        b.w.close();
        return u2End(gchild, false);
    }

    // 5. The child's "n": the limit is written (:301-302).
    switch (a.r.read(&c)) {
        .ok => |n| if (n != 1) return u2End(gchild, true),
        .err => return u2End(gchild, true),
    }

    // 6. Only after "n", the pid to the launcher, which ends the child by
    // closing the release pipe, also when this write fails because it has
    // given up; then the child reaped (:303-307).
    switch (h.rep.write(std.mem.asBytes(&g))) {
        .ok => |n| if (n != @sizeOf(sys.pid_t)) msg.sayErrno(.IO, "send U2's pid", .{}),
        .err => |e| msg.sayErrno(e, "send U2's pid", .{}),
    }
    const st = gchild.await() catch {
        gchild.release();
        return 125;
    };
    return if (st == 0) 0 else 125;
}

/// make_u2 (flong-ns.c:313-370): U2's helper joins U1 and makes U2 with
/// its child; the launcher opens U2 by the pid the helper sends, while the
/// child still holds it, then releases the child and reaps the helper.
/// Ordering checkpoint 4, one function: the steps are numbered, and the
/// cleanup after them runs on every path. `outer`, U1, stays the caller's.
pub fn makeU2(gpa: Allocator, maps: Maps, outer: Userns) sig.Error!Userns {
    var rep: ?fdt.Pipe = null;
    var rel: ?fdt.Pipe = null;
    var helper: ?Child = null;
    var ns: ?Userns = null;

    const made: sig.Error!void = steps: {
        // 1. U2's map texts, split along U1's extents, and the two pipes:
        // `rep` carries U2's pid, `rel` keeps U2's child until the
        // launcher closes its write end (:317-326).
        const uidmap = identityMap(gpa, maps.uidmap) catch break :steps noMemory();
        const gidmap = identityMap(gpa, maps.gidmap) catch break :steps noMemory();
        rep = msg.check(fdt.pipe(), "pipe", .{}) catch |e| break :steps e;
        rel = msg.check(fdt.pipe(), "pipe", .{}) catch |e| break :steps e;

        // 2. The helper, keeping U1 and its two ends; ours of them close
        // at once (:327-336).
        helper = proc.fork(.{ .keep = &.{ outer.any(), rep.?.w.any(), rel.?.r.any() } }, U2Helper{
            .u1 = outer,
            .rep = rep.?.w,
            .rel = rel.?.r,
            .maxns = maps.nested_userns,
            .uidmap = uidmap,
            .gidmap = gidmap,
        }, u2Helper) catch |e| break :steps e;
        rep.?.w.close();
        rel.?.r.close();

        // 3. U2's pid, sent only once U2 is mapped and limited; EOF is a
        // helper that ended first (:338-344).
        var g_bytes: [@sizeOf(sys.pid_t)]u8 = undefined;
        if (!(awaitMsg(rep.?.r, &g_bytes) catch |e| break :steps e)) {
            break :steps helperFailed(&helper, "U2's helper");
        }
        const g = std.mem.bytesToValue(sys.pid_t, &g_bytes);

        // 4. U2 opened while its child holds it, before the release pipe
        // closes; then the helper, which waits for the child, reaped
        // (:345-355).
        ns = msg.check(fdt.openUserns(g), "open /proc/{d}/ns/user", .{g}) catch |e| break :steps e;
        rel.?.w.close();
        const st = helper.?.await() catch |e| break :steps e;
        helper = null;
        if (st != 0) break :steps msg.refuse("U2's helper ended with status {d} after U2 was made", .{st});
        msg.trace("U2-made");
    };

    // The cleanup (:360-369), on every path: every pipe end first, which
    // releases the helper and its child, then the helper reaped.
    if (std.meta.isError(made)) {
        if (ns) |h| h.close();
    }
    if (rep) |p| {
        if (p.r.isLive()) p.r.close();
        if (p.w.isLive()) p.w.close();
    }
    if (rel) |p| {
        if (p.r.isLive()) p.r.close();
        if (p.w.isLive()) p.w.close();
    }
    if (helper) |c| c.reapNow(.wait);
    try made;
    return ns.?;
}

// ---- tests ----

const testing = std.testing;

test "identityMap splits along U1's extents" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const m = [_]spec.IdMap{
        .{ .inside = 0, .outside = 1000, .count = 1 },
        .{ .inside = 1, .outside = 100000, .count = 65536 },
    };
    try testing.expectEqualStrings("0 0 1\n1 1 65536\n", try identityMap(arena.allocator(), &m));
    try testing.expectEqualStrings("", try identityMap(arena.allocator(), &.{}));
    const big = [_]spec.IdMap{.{ .inside = std.math.maxInt(u64), .outside = 0, .count = 4294967294 }};
    try testing.expectEqualStrings("18446744073709551615 18446744073709551615 4294967294\n", try identityMap(arena.allocator(), &big));
}
