//! mount.zig: the mount helper, launcher/flong-mount.c ported function by
//! function (ZIG.md, "Phase 4"); its specification is flong-mount.h:1-60,
//! and its order ordering checkpoint 7, held by `run` alone. The C was
//! deleted in phase 4 (b), and its line numbers here are those of a7919be.
//!
//! bwrap resolves nested destinations by path and follows symlinks a payload
//! planted, so it mounts only fixed destinations in fresh filesystems, and
//! everything else is mounted here, after bwrap has built the root and
//! before the gate opens, by a walker that opens each destination one
//! component at a time and attaches onto the descriptor it ends with.
//!
//! Everything here runs in one forked, single-threaded child that exits when
//! `run` returns, so a descriptor left open on a failure path goes with the
//! process: the launcher owns every cleanup that outlives it
//! (flong-mount.c:3-5). The child is a fork body of the Zig launcher's
//! (src/launch.zig, since phase 7's L4), and the check-only C launcher's
//! through src/hybrid/mount_c.zig until L5; this file reads no argv or
//! environ and knows nothing of C. Every failure is said once, where it happens, in the
//! launcher's words and cut mode (msg.zig), and passed up as
//! `error.Reported`.

const std = @import("std");
const sys = @import("sys");
const fd = @import("fd");
const msg = @import("msg");

const Error = msg.Error;

/// enum fl_mount_kind (flong-spec.h:26-35).
pub const Kind = enum {
    /// declared bindMounts: the source follows symlinks, as its author
    /// intended
    bind_ro,
    bind_rw,
    /// caller binds and the workspace: the source is canonical and is
    /// opened with RESOLVE_NO_SYMLINKS, so a symlink met now is a race
    bind_ro_exact,
    bind_rw_exact,
    /// allowedDevices: a read-write bind that is not nodev
    dev,
    tmpfs,
    /// a lower directory under a writable layer that is thrown away
    overlay,
    /// a mode-0 read-only node of the destination's own kind
    mask,
};

/// struct fl_mount (flong-spec.h:37-44).
pub const Mount = struct {
    kind: Kind,
    /// absolute, inside the session, plain components (spec_parse)
    dest: [:0]const u8,
    /// binds and dev: the host source; overlay: the lower
    src: ?[:0]const u8 = null,
    /// tmpfs: octal digits ("0700")
    mode: ?[:0]const u8 = null,
    /// tmpfs: tmpfs's size= value
    size: ?[:0]const u8 = null,
    /// tmpfs: its root is the payload's, not container root's
    owner_user: bool = false,
};

/// struct fl_mount_job (flong-mount.h:67-81).
pub const Job = struct {
    /// U1, from ns_create
    u1: fd.Fd(.userns),
    /// pidfd of bwrap's child, the session's pid 1
    leader: fd.Fd(.pidfd),
    /// read end of the ready pipe
    ready: fd.Fd(.pipe_r),
    mounts: []const Mount,
    /// the payload, as ids inside the container
    uid: u32,
    gid: u32,
    home: [:0]const u8,
    /// the spec's protect paths plus the state directory and the holder's
    /// cgroup, each made canonical by the launcher before the fork
    protect: []const [:0]const u8,
};

/// One mount, from its spec to the detached tree attached in the session
/// (flong-mount.c:31-38).
const Src = struct {
    m: *const Mount,
    /// a detached mount; null for a mask until attach makes it
    tree: ?fd.Fd(.tree) = null,
    /// the tree's unique mount id, once made
    id: u64 = 0,
    /// a bind of something on the host (binds, devices)
    host: bool = false,
};

/// What the walker needs to know about the session (flong-mount.c:40-47).
const Walker = struct {
    job: *const Job,
    /// O_PATH of the session's /
    root: fd.Fd(.path),
    root_id: u64,
    /// to tell a host bind from the session's own mounts; empty until the
    /// declared mounts are attached (flong-mount.c:607-608)
    srcs: []const Src = &.{},
};

/// The unique mount id of the mount `h` is on (flong-mount.c:55-64): never
/// reused, unlike the old one, and a detached tree keeps it when attached.
fn mountId(h: anytype) Error!u64 {
    return msg.check(h.mountId(), "statx", .{});
}

/// File access as the payload, which U1 maps onto the caller, or as U1
/// root (flong-mount.c:66-78). setfsuid clears the file capabilities (DAC
/// override among them) while the fsuid is not 0, so a source is reached
/// with the caller's own reach, not with container root's over every
/// subordinate id. setfsuid answers the old value, not a failure, so the
/// new one is read back: the uid, then (only if it took) the gid.
fn fsIds(uid: u32, gid: u32) Error!void {
    _ = sys.setfsgid(gid);
    _ = sys.setfsuid(uid);
    const none = std.math.maxInt(u32);
    if (sys.setfsuid(none) != uid or sys.setfsgid(none) != gid)
        return msg.refuse("cannot take file ids {d}:{d}", .{ uid, gid });
}

/// What `asPayload`'s `f` answered, boxed: `f` may answer an error union
/// of its own, which `Error!R` would otherwise merge into its errors.
fn Answer(comptime R: type) type {
    return struct { r: R };
}

/// `f(ctx)` with the payload's file ids, then 0:0 again. A failed restore
/// is said and returned ahead of whatever `f` answered, as
/// flong-mount.c:122-128 and 286-289 do; a descriptor `f` opened then goes
/// with the process.
fn asPayload(job: *const Job, comptime R: type, ctx: anytype, comptime f: fn (@TypeOf(ctx)) R) Error!Answer(R) {
    try fsIds(job.uid, job.gid);
    const r = f(ctx);
    try fsIds(0, 0);
    return .{ .r = r };
}

// ---- sources, in a mount namespace of the helper's own ----

/// Whether `a` and `b` are the same path or one lies inside the other.
/// Both are canonical (flong-mount.c:82-92).
pub fn overlaps(a: []const u8, b: []const u8) bool {
    if (std.mem.eql(u8, a, "/") or std.mem.eql(u8, b, "/")) return true;
    const n = @min(a.len, b.len);
    if (!std.mem.eql(u8, a[0..n], b[0..n])) return false;
    return a.len == b.len or (if (a.len < b.len) b[a.len] else a[b.len]) == '/';
}

/// Condition 4 (flong-mount.c:94-110): no source reaches flong's state, the
/// holder's cgroup or frisket's socket. The path is the one the kernel
/// resolved the descriptor to, so a symlink or a bind cannot hide where a
/// source really is. A source deleted since reads back with " (deleted)"
/// and misses the compare (quirk 29, kept).
fn checkProtected(job: *const Job, h: anytype, src: [:0]const u8) Error!void {
    var path: [sys.path_max]u8 = undefined;
    const link = fd.selfPath(h);
    const n = try msg.check(sys.readlinkat(sys.AT.FDCWD, link.path(), path[0 .. path.len - 1]), "readlink {s}", .{src});
    for (job.protect) |p| {
        if (overlaps(path[0..n], p))
            return msg.refuse("the mount source {s} is, holds or lies inside {s}, which no session may reach", .{ src, p });
    }
}

/// Opens a bind's (`.path`) or an overlay's (`.dir`) source as the payload
/// (flong-mount.c:112-138). An exact source is canonical, so a symlink on
/// it now is a race and ends the launch; any other follows symlinks, as its
/// author intended.
fn openSource(job: *const Job, m: *const Mount, comptime k: fd.Kind) Error!fd.Fd(k) {
    const exact = m.kind == .bind_ro_exact or m.kind == .bind_rw_exact;
    const src = m.src.?; // spec_parse gives every bind, dev and overlay a source
    const Open = struct {
        src: [:0]const u8,
        exact: bool,
        fn open(o: @This()) fd.Error!sys.Result(fd.Fd(k)) {
            return if (o.exact) fd.openExact(k, o.src) else fd.openFollowing(k, o.src);
        }
    };
    const r = (try asPayload(job, fd.Error!sys.Result(fd.Fd(k)), Open{ .src = src, .exact = exact }, Open.open)).r;
    const res = r catch return msg.refuse("mount source {s}: too many open descriptors", .{src});
    const h = switch (res) {
        .ok => |h| h,
        .err => |e| {
            if (exact and e == .LOOP) return msg.refuse("a symlink is on the way to {s}", .{src});
            return msg.fail(e, "mount source {s}", .{src});
        },
    };
    checkProtected(job, h, src) catch |e| {
        h.close();
        return e;
    };
    return h;
}

/// A bind or a device (flong-mount.c:140-161): a recursive clone of the
/// source, nosuid, nodev unless it is a device, read-only when asked.
fn prepareBind(job: *const Job, s: *Src) Error!void {
    const m = s.m;
    const src = try openSource(job, m, .path);
    const cloned = fd.openTree(src, "", sys.OPEN_TREE_CLONE | sys.AT.EMPTY_PATH | sys.AT_RECURSIVE);
    src.close();
    const tree = try msg.check(cloned, "cannot clone {s}", .{m.src.?});
    s.tree = tree;
    var attr: sys.MountAttr = .{ .attr_set = sys.MOUNT_ATTR.NOSUID };
    if (m.kind != .dev) attr.attr_set |= sys.MOUNT_ATTR.NODEV;
    if (m.kind == .bind_ro or m.kind == .bind_ro_exact) attr.attr_set |= sys.MOUNT_ATTR.RDONLY;
    _ = try msg.check(tree.mountSetattr(true, &attr), "cannot restrict {s}", .{m.src.?});
    s.host = true;
}

/// One fsconfig string: key, value.
const Opt = struct { [:0]const u8, [:0]const u8 };

/// A fresh filesystem of `fstype`, configured by `opts`, detached with
/// `attrs` (flong-mount.c:163-183).
fn makeFs(fstype: [:0]const u8, opts: []const Opt, attrs: u32) Error!fd.Fd(.tree) {
    const fs = try msg.check(fd.fsopen(fstype), "fsopen {s}", .{fstype});
    for (opts) |o| {
        switch (fs.setString(o[0], o[1])) {
            .ok => {},
            .err => |e| {
                const r = msg.fail(e, "{s} {s}={s}", .{ fstype, o[0], o[1] });
                fs.close();
                return r;
            },
        }
    }
    const mnt: Error!fd.Fd(.tree) = switch (fs.create()) {
        .err => |e| msg.fail(e, "{s}", .{fstype}),
        .ok => msg.check(fd.fsmount(fs, attrs), "fsmount {s}", .{fstype}),
    };
    fs.close();
    return mnt;
}

/// flong-mount.c:185-200: mode, size when given, and the payload's ids
/// when its root is the payload's.
fn prepareTmpfs(job: *const Job, s: *Src) Error!void {
    const m = s.m;
    var uid_buf: [16]u8 = undefined;
    var gid_buf: [16]u8 = undefined;
    const uid = std.fmt.bufPrintZ(&uid_buf, "{d}", .{job.uid}) catch unreachable; // proven: a u32 is at most 10 digits
    const gid = std.fmt.bufPrintZ(&gid_buf, "{d}", .{job.gid}) catch unreachable; // proven: a u32 is at most 10 digits
    var opts: [4]Opt = undefined;
    var n: usize = 0;
    opts[n] = .{ "mode", m.mode.? }; // spec_parse gives every tmpfs a mode
    n += 1;
    if (m.size) |size| {
        opts[n] = .{ "size", size };
        n += 1;
    }
    if (m.owner_user) {
        opts[n] = .{ "uid", uid };
        opts[n + 1] = .{ "gid", gid };
        n += 2;
    }
    s.tree = try makeFs("tmpfs", opts[0..n], sys.MOUNT_ATTR.NOSUID | sys.MOUNT_ATTR.NODEV);
}

/// Why a step of the overlay's chain failed: the errno, or a full table.
const Failed = union(enum) { errno: sys.E, table_full };

/// An overlay whose writes go with the session (flong-mount.c:202-238): the
/// lower is read with the payload's reach, the upper and work directories
/// sit on one detached tmpfs that nothing names, and the upper is the
/// payload's. Every layer is passed as a descriptor, so nothing is resolved
/// by name. The overlay itself is made as U1 root, whose credentials it
/// keeps for its own writes. `i` is the mount's place in the sorted list.
fn prepareOverlay(job: *const Job, s: *Src, scratch: *?fd.Fd(.tree), i: usize) Error!void {
    const m = s.m;
    if (scratch.* == null) scratch.* = try makeFs("tmpfs", &.{.{ "mode", "0700" }}, sys.MOUNT_ATTR.NOSUID | sys.MOUNT_ATTR.NODEV);
    const sc = scratch.*.?;
    var upper_buf: [32]u8 = undefined;
    var work_buf: [32]u8 = undefined;
    const upper = std.fmt.bufPrintZ(&upper_buf, "upper{d}", .{i}) catch unreachable; // proven: "upper" and a usize fit 32
    const work = std.fmt.bufPrintZ(&work_buf, "work{d}", .{i}) catch unreachable; // proven: "work" and a usize fit 32

    const made: sys.Result(void) = made: {
        switch (sc.mkdirat(upper, 0o755)) {
            .ok => {},
            .err => |e| break :made .{ .err = e },
        }
        switch (sc.mkdirat(work, 0o700)) {
            .ok => {},
            .err => |e| break :made .{ .err = e },
        }
        break :made sc.fchownat(upper, job.uid, job.gid, sys.AT.SYMLINK_NOFOLLOW);
    };
    _ = try msg.check(made, "overlay {s}: its upper directory", .{m.dest});

    const lower = try openSource(job, m, .dir);
    var up: ?fd.Fd(.dir) = null;
    var wk: ?fd.Fd(.dir) = null;
    var fs: ?fd.Fd(.fsctx) = null;
    const chain: ?Failed = chain: {
        if (openInto(fd.Dir, &up, fd.openDir(sc, upper))) |f| break :chain f;
        if (openInto(fd.Dir, &wk, fd.openDir(sc, work))) |f| break :chain f;
        if (openInto(fd.Fd(.fsctx), &fs, fd.fsopen("overlay"))) |f| break :chain f;
        const ctx = fs.?;
        if (failed(ctx.setFd("lowerdir+", lower))) |f| break :chain f;
        if (failed(ctx.setFd("upperdir", up.?))) |f| break :chain f;
        if (failed(ctx.setFd("workdir", wk.?))) |f| break :chain f;
        if (failed(ctx.setFlag("userxattr"))) |f| break :chain f;
        if (failed(ctx.create())) |f| break :chain f;
        break :chain openInto(fd.Fd(.tree), &s.tree, fd.fsmount(ctx, sys.MOUNT_ATTR.NOSUID | sys.MOUNT_ATTR.NODEV));
    };
    const said: Error!void = if (chain) |f| switch (f) {
        .errno => |e| msg.fail(e, "overlay {s}", .{m.dest}),
        .table_full => msg.refuse("overlay {s}: too many open descriptors", .{m.dest}),
    };
    lower.close();
    if (up) |h| h.close();
    if (wk) |h| h.close();
    if (fs) |h| h.close();
    return said;
}

/// An open's handle into `slot`, or why not, for prepareOverlay's chain.
fn openInto(comptime H: type, slot: *?H, r: fd.Error!sys.Result(H)) ?Failed {
    const res = r catch return .table_full;
    switch (res) {
        .ok => |h| {
            slot.* = h;
            return null;
        },
        .err => |e| return .{ .errno = e },
    }
}

/// A call's failure, for prepareOverlay's chain, or null.
fn failed(r: sys.Result(void)) ?Failed {
    return switch (r) {
        .ok => null,
        .err => |e| .{ .errno = e },
    };
}

// ---- the walk, in the session's mount namespace ----

/// Whether the mount `h` is on belongs to a host bind: its own tree, or a
/// submount the bind brought along (flong-mount.c:242-265). Climbs parents
/// until it meets a mount made here or the session's root: bwrap's fixed
/// mounts (/run, /tmp) and the root are the session's own.
fn onHostBind(w: *const Walker, h: fd.Fd(.path)) Error!bool {
    var id = try mountId(h);
    while (true) {
        if (id == w.root_id) return false;
        for (w.srcs) |s| {
            if (s.tree != null and s.id == id) return s.host;
        }
        const req: sys.MntIdReq = .{ .mnt_id = id, .param = sys.STATMOUNT_MNT_BASIC };
        var sm: sys.StatMount = undefined;
        _ = try msg.check(sys.statmount(&req, &sm), "statmount", .{});
        if (sm.mnt_parent_id == id) return false;
        id = sm.mnt_parent_id;
    }
}

const Want = enum { file, dir, any };

/// Who made a missing name (flong-mount.c:273-274's 1, 2 and 0).
const Made = enum { session, host, existed };

/// Where makeNode makes: the name in the directory, and which kind.
const MakeAt = struct { dir: fd.Fd(.path), name: [*:0]const u8, is_dir: bool };

/// The make itself: a directory 0755, or an empty file 0644, never through
/// a symlink. A full table is EMFILE, what the C's open would answer.
fn makeNode(at: MakeAt) sys.Result(void) {
    if (at.is_dir) return at.dir.mkdirat(at.name, 0o755);
    const r = fd.openFile(at.dir, at.name, .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .NOFOLLOW = true }, 0o644) catch
        return .{ .err = .MFILE };
    return switch (r) {
        .ok => |f| f.closeChecked(),
        .err => |e| .{ .err = e },
    };
}

/// Makes the missing `name` in `dir`, the component of `dest` that ends at
/// `end` (flong-mount.c:269-295). On a host bind as the payload, so the
/// kernel checks the write as the caller's and the result is the caller's
/// on the host; on the session's own mounts as container root. EEXIST is a
/// concurrent session having made it first.
fn makeMissing(w: *const Walker, dir: fd.Fd(.path), name: [*:0]const u8, is_dir: bool, dest: [:0]const u8, end: usize) Error!Made {
    const host = try onHostBind(w, dir);
    const at: MakeAt = .{ .dir = dir, .name = name, .is_dir = is_dir };
    const r = if (host) (try asPayload(w.job, sys.Result(void), at, makeNode)).r else makeNode(at);
    return switch (r) {
        .ok => if (host) .host else .session,
        .err => |e| if (e == .EXIST) .existed else msg.fail(e, "cannot make {s}", .{dest[0..end]}),
    };
}

/// Whether dest[0..end] is the payload's home or lies inside it
/// (flong-mount.c:297-302).
pub fn inHome(home: []const u8, dest: []const u8, end: usize) bool {
    return end >= home.len and std.mem.eql(u8, dest[0..home.len], home) and (end == home.len or dest[home.len] == '/');
}

/// Walks `dest` from the session's root one component at a time and
/// returns an O_PATH handle on it (flong-mount.c:304-366). With `create`, a
/// missing component is made: a directory on the way, and the last one of
/// the kind wanted. The C dups the root to start from; here the first step
/// starts from the root's own handle, which is never closed.
fn walk(w: *const Walker, dest: [:0]const u8, want: Want, create: bool) Error!fd.Fd(.path) {
    var buf: [sys.path_max]u8 = undefined;
    if (dest.len >= buf.len) return msg.refuse("{s}: the path is too long", .{dest});
    @memcpy(buf[0 .. dest.len + 1], dest[0 .. dest.len + 1]);

    var cur: ?fd.Fd(.path) = null;
    var start: usize = 1;
    while (true) {
        const slash = std.mem.indexOfScalarPos(u8, buf[0..dest.len], start, '/');
        const end = slash orelse dest.len;
        const next: ?usize = if (slash) |i| i + 1 else null;
        buf[end] = 0;
        const name: [:0]const u8 = buf[start..end :0];
        const is_dir = next != null or want == .dir;
        const at = cur orelse w.root;

        var r = fd.walkOpen(at, name, is_dir) catch return msg.refuse("{s}: too many open descriptors", .{dest});
        if (r == .err and r.err == .NOENT and create) {
            const made = makeMissing(w, at, name, is_dir, dest, end) catch |e| {
                if (cur) |c| c.close();
                return e;
            };
            r = fd.walkOpen(at, name, is_dir) catch return msg.refuse("{s}: too many open descriptors", .{dest});
            // Made as container root on the session's own mounts: inside
            // home it is the payload's. Nothing but this helper can reach
            // those mounts before the gate.
            if (r == .ok and made == .session and inHome(w.job.home, dest, end)) {
                switch (r.ok.fchownat("", w.job.uid, w.job.gid, sys.AT.EMPTY_PATH)) {
                    .ok => {},
                    .err => |e| {
                        const x = msg.fail(e, "cannot give {s} to the payload", .{dest[0..end]});
                        r.ok.close();
                        if (cur) |c| c.close();
                        return x;
                    },
                }
            }
        }
        if (cur) |c| c.close();
        cur = switch (r) {
            .ok => |h| h,
            .err => |e| {
                if (e == .LOOP) return msg.refuse("a symlink is on the way to {s}", .{dest});
                if (e == .NOTDIR and next != null) return msg.refuse("{s}, on the way to {s}, is not a directory", .{ dest[0..end], dest });
                if (e == .NOTDIR) return msg.refuse("{s} is not a directory", .{dest});
                return msg.fail(e, "{s}", .{dest});
            },
        };
        start = next orelse break;
    }

    const h = cur.?; // the loop runs at least once
    const st = switch (h.fstat()) {
        .ok => |st| st,
        .err => |e| {
            const x = msg.fail(e, "{s}", .{dest});
            h.close();
            return x;
        },
    };
    if (want == .file and sys.S.ISDIR(st.mode)) {
        h.close();
        return msg.refuse("{s} is a directory and its source is not", .{dest});
    }
    return h;
}

/// A mask (flong-mount.c:368-401): a mode-0 read-only node of the
/// destination's own kind, so the payload can neither read what it covers
/// nor write to it. A directory gets an empty tmpfs; anything else a mode-0
/// file on a tmpfs, bound alone.
fn makeMask(is_dir: bool) Error!fd.Fd(.tree) {
    const attrs = sys.MOUNT_ATTR.RDONLY | sys.MOUNT_ATTR.NOEXEC | sys.MOUNT_ATTR.NOSUID | sys.MOUNT_ATTR.NODEV;
    if (is_dir) return makeFs("tmpfs", &.{.{ "mode", "0000" }}, attrs);

    // The tmpfs stays writable until the file is on it; the clone that is
    // bound gets the mask's flags.
    const fs = try makeFs("tmpfs", &.{.{ "mode", "0755" }}, sys.MOUNT_ATTR.NOSUID | sys.MOUNT_ATTR.NODEV);
    const f = msg.check(fd.openFile(fs, "mask", .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true }, 0), "mask file", .{}) catch |e| {
        fs.close();
        return e;
    };
    f.close();
    const attr: sys.MountAttr = .{ .attr_set = attrs };
    const tree: Error!fd.Fd(.tree) = tree: {
        const t = msg.check(fd.openTree(fs, "mask", sys.OPEN_TREE_CLONE), "open_tree mask file", .{}) catch |e| break :tree e;
        switch (t.mountSetattr(false, &attr)) {
            .ok => break :tree t,
            .err => |e| {
                const x = msg.fail(e, "mask file", .{});
                t.close();
                break :tree x;
            },
        }
    };
    fs.close();
    return tree;
}

/// Attaches one prepared mount at its destination (flong-mount.c:403-436).
fn attach(w: *const Walker, s: *Src) Error!void {
    const m = s.m;
    var want: Want = .dir;
    var create = true;
    if (m.kind == .mask) {
        // The target must exist: a mask over nothing hides nothing and
        // would make a node where the declaration expected one.
        want = .any;
        create = false;
    } else if (s.host) {
        const st = try msg.check(s.tree.?.fstat(), "{s}", .{m.src.?});
        want = if (sys.S.ISDIR(st.mode)) .dir else .file;
    }
    const dest = try walk(w, m.dest, want, create);
    if (m.kind == .mask) {
        // A failed fstat says nothing, as flong-mount.c:425 says nothing.
        const st = switch (dest.fstat()) {
            .ok => |st| st,
            .err => {
                dest.close();
                return error.Reported;
            },
        };
        const tree = makeMask(sys.S.ISDIR(st.mode)) catch |e| {
            dest.close();
            return e;
        };
        s.tree = tree;
        s.id = mountId(tree) catch |e| {
            dest.close();
            return e;
        };
    }
    switch (s.tree.?.moveTo(dest)) {
        .ok => dest.close(),
        .err => |e| {
            const x = msg.fail(e, "cannot mount on {s}", .{m.dest});
            dest.close();
            return x;
        },
    }
}

// ---- /sys and /run ----

/// A fresh read-only filesystem of `fstype` at `dest` (flong-mount.c:440-454).
fn mountFresh(w: *const Walker, fstype: [:0]const u8, dest: [:0]const u8, create: bool) Error!void {
    const attrs = sys.MOUNT_ATTR.RDONLY | sys.MOUNT_ATTR.NOSUID | sys.MOUNT_ATTR.NODEV | sys.MOUNT_ATTR.NOEXEC;
    const mnt = try makeFs(fstype, &.{}, attrs);
    const moved: Error!void = if (walk(w, dest, .dir, create)) |at| moved: {
        const r: Error!void = switch (mnt.moveTo(at)) {
            .ok => {},
            .err => |e| msg.fail(e, "cannot mount {s} on {s}", .{ fstype, dest }),
        };
        at.close();
        break :moved r;
    } else |e| e;
    mnt.close();
    return moved;
}

// ---- the helper ----

fn byDest(_: void, a: Src, b: Src) bool {
    return std.mem.orderZ(u8, a.m.dest, b.m.dest) == .lt;
}

/// Sorts `srcs` by destination, parents first, and refuses the same
/// destination twice (flong-mount.c:533-541). spec_parse has already made
/// each destination an absolute path of plain components.
pub fn sortRefusingTwice(srcs: []Src) Error!void {
    std.mem.sort(Src, srcs, {}, byDest);
    for (1..srcs.len) |i| {
        if (std.mem.eql(u8, srcs[i - 1].m.dest, srcs[i].m.dest))
            return msg.refuse("{s} is mounted twice", .{srcs[i].m.dest});
    }
}

/// The mount helper's whole life (flong-mount.c:521-615; ZIG.md ordering
/// checkpoint 7, whose order is this function's and no helper's): returns
/// when every mount, /sys and /run are done, or `error.Reported` after
/// saying why not. Runs in the forked child: setns into a user namespace is
/// one-way, so it cannot run in the launcher.
pub fn run(job: *const Job) Error!void {
    // The mounts in the child's memory: page_allocator, never freed
    // (flong-mount.c:524's calloc, which the C also never frees).
    const srcs = std.heap.page_allocator.alloc(Src, job.mounts.len) catch return msg.fail(.NOMEM, "calloc", .{});

    // Directories made on the way are 0755 whatever the caller's umask: a
    // 0700 root-owned /srv would hide a bind below it from the payload.
    _ = sys.umask(0o022);

    // Parents first, and the same destination twice is refused, before any
    // work, so a bad spec costs nothing.
    for (job.mounts, srcs) |*m, *s| s.* = .{ .m = m };
    try sortRefusingTwice(srcs);

    // 1. The leader's namespaces, through the pidfd the launcher opened at
    //    child-pid: the process is never looked up by its number again, and
    //    only the caller may ask.
    const mnt = try msg.check(fd.openNs(job.leader, .mntns), "the session's mount namespace", .{});
    const net = try msg.check(fd.openNs(job.leader, .netns), "the session's network namespace", .{});
    const cgns = try msg.check(fd.openNs(job.leader, .cgroupns), "the session's cgroup namespace", .{});

    // 2. U1 root: every capability over the session's namespaces, none over
    //    anything the caller could not already touch.
    _ = try msg.check(job.u1.setns(.user), "setns U1", .{});
    const root_ids: sys.Result(void) = switch (sys.setresgid(0, 0, 0)) {
        .ok => sys.setresuid(0, 0, 0),
        .err => |e| .{ .err = e },
    };
    _ = try msg.check(root_ids, "cannot become U1's root", .{});

    // 3. A copy of the host's mount namespace, owned by U1, where the
    //    sources are opened and cloned while bwrap builds the root.
    _ = try msg.check(sys.unshare(sys.CLONE.NEWNS), "unshare a mount namespace", .{});
    var scratch: ?fd.Fd(.tree) = null;
    for (srcs, 0..) |*s, i| {
        switch (s.m.kind) {
            .bind_ro, .bind_rw, .bind_ro_exact, .bind_rw_exact, .dev => try prepareBind(job, s),
            .tmpfs => try prepareTmpfs(job, s),
            .overlay => try prepareOverlay(job, s, &scratch, i),
            .mask => {},
        }
        if (s.tree) |t| s.id = try mountId(t);
    }

    // 4. Nothing touches the session's mount namespace before bwrap has
    //    finished it: flong-init writes the ready byte once bwrap has built
    //    the whole root, and EOF means bwrap failed before its child was
    //    ready (flong-mount.c:506-519).
    var byte: [1]u8 = undefined;
    const n = try msg.check(job.ready.read(&byte), "the ready pipe", .{});
    if (n == 0) return msg.refuse("the sandbox never became ready", .{});
    msg.trace("sandbox-ready");

    // 5. The session's mount namespace, and /sys first: a declaration under
    //    /sys then lands on the session's own sysfs, or fails, where a fresh
    //    sysfs mounted after it would cover it without a word.
    _ = try msg.check(mnt.setns(.mnt), "setns the session's mount namespace", .{});
    const root = try msg.check(fd.openPath(fd.cwd, "/", .{ .DIRECTORY = true }), "the session's root", .{});
    var w: Walker = .{ .job = job, .root = root, .root_id = try mountId(root) };
    // The kernel refuses a fresh sysfs unless one is fully visible in the
    // mount namespace, so bwrap bound the host's at /.hostsys. A sysfs made
    // in the session's network namespace shows only the session's
    // interfaces. cgroup2 is mounted from the payload's own cgroup
    // namespace, which bwrap rooted at the sandbox leaf, so the mount's
    // root is the cgroup /proc/self/cgroup names, "/": Go uses a cgroup2
    // mount only when its root is a prefix of that path, and it, nproc,
    // Node and Java read the declared limits there. The leaf is the
    // namespace's root, whose files nsdelegate keeps the payload from
    // writing (flong-mount.c:456-482).
    _ = try msg.check(net.setns(.net), "setns the session's network namespace", .{});
    _ = try msg.check(cgns.setns(.cgroup), "setns the session's cgroup namespace", .{});
    // /sys may be missing from the root; /sys/fs/cgroup is sysfs's own and
    // cannot be made.
    try mountFresh(&w, "sysfs", "/sys", true);
    try mountFresh(&w, "cgroup2", "/sys/fs/cgroup", false);
    // /.hostsys is on the root, which only this helper can change before the
    // gate, so it is named by path.
    _ = try msg.check(sys.umount2("/.hostsys", sys.MNT_DETACH | sys.UMOUNT_NOFOLLOW), "cannot detach /.hostsys", .{});
    _ = try msg.check(w.root.unlinkat(".hostsys", sys.AT.REMOVEDIR), "cannot remove /.hostsys", .{});

    // 6. The mounts, parents first.
    w.srcs = srcs;
    for (srcs) |*s| try attach(&w, s);

    // 7. /run read-only, last, because declarations bind under /run: the
    //    tmpfs itself only, so the mounts under it keep their own flags and
    //    /run/user/<uid> stays writable (flong-mount.c:484-497).
    const run_dir = try walk(&w, "/run", .dir, false);
    const ro: sys.MountAttr = .{ .attr_set = sys.MOUNT_ATTR.RDONLY };
    switch (run_dir.mountSetattr(false, &ro)) {
        .ok => run_dir.close(),
        .err => |e| {
            const x = msg.fail(e, "cannot make /run read-only", .{});
            run_dir.close();
            return x;
        },
    }
}

// ---- for the walker's driver (tests/zig/walker.zig) ----

/// The walk and what it needs, for tests/zig/walker.zig, which drives it
/// in a user and mount namespace of its own (ZIG.md, "checks.native").
pub const testing_only = struct {
    pub const WalkWant = Want;

    /// A walker over `root`, whose mount is the session's own.
    pub fn walker(job: *const Job, root: fd.Fd(.path)) Error!Walker {
        return .{ .job = job, .root = root, .root_id = try mountId(root) };
    }

    pub fn walkFrom(w: *const Walker, dest: [:0]const u8, want: Want, create: bool) Error!fd.Fd(.path) {
        return walk(w, dest, want, create);
    }

    pub fn makeMissingIn(w: *const Walker, dir: fd.Fd(.path), name: [*:0]const u8, is_dir: bool, dest: [:0]const u8) Error!Made {
        return makeMissing(w, dir, name, is_dir, dest, dest.len);
    }

    pub fn mask(is_dir: bool) Error!fd.Fd(.tree) {
        return makeMask(is_dir);
    }

    pub fn openSourceAs(job: *const Job, m: *const Mount) Error!fd.Fd(.path) {
        return openSource(job, m, .path);
    }

    pub const MadeBy = Made;
    pub const Walk = Walker;
};

// ---- tests ----

const testing = std.testing;

test "overlaps: the same path, one inside the other, or /" {
    try testing.expect(overlaps("/a", "/a"));
    try testing.expect(overlaps("/a", "/a/b"));
    try testing.expect(overlaps("/a/b", "/a"));
    try testing.expect(overlaps("/", "/anything"));
    try testing.expect(overlaps("/anything", "/"));
    try testing.expect(!overlaps("/a", "/ab"));
    try testing.expect(!overlaps("/ab", "/a"));
    try testing.expect(!overlaps("/a/b", "/a/c"));
    try testing.expect(!overlaps("/run/user/1000", "/run/user/10000"));
    try testing.expect(overlaps("/run/user/1000", "/run/user/1000/flong"));
    // A deleted source's " (deleted)" misses the compare (quirk 29).
    try testing.expect(!overlaps("/srv/protected (deleted)", "/srv/protected"));
}

test "inHome: home itself or below, by whole components" {
    try testing.expect(inHome("/home/alice", "/home/alice", 11));
    try testing.expect(inHome("/home/alice", "/home/alice/tmp", 15));
    try testing.expect(inHome("/home/alice", "/home/alice/tmp", 11));
    try testing.expect(!inHome("/home/alice", "/home/alice/tmp", 5));
    try testing.expect(!inHome("/home/alice", "/home/alicex", 12));
}

test "the sort is strcmp's, parents first, and a destination twice is refused" {
    const ms = [_]Mount{
        .{ .kind = .tmpfs, .dest = "/srv/work/b" },
        .{ .kind = .tmpfs, .dest = "/srv/work" },
        .{ .kind = .tmpfs, .dest = "/srv/work-x" },
        .{ .kind = .tmpfs, .dest = "/srv/\xc3\xa9" },
        .{ .kind = .tmpfs, .dest = "/a" },
    };
    var srcs: [ms.len]Src = undefined;
    for (&ms, &srcs) |*m, *s| s.* = .{ .m = m };
    try sortRefusingTwice(&srcs);
    const want = [_][]const u8{ "/a", "/srv/work", "/srv/work-x", "/srv/work/b", "/srv/\xc3\xa9" };
    for (want, srcs) |d, s| try testing.expectEqualStrings(d, s.m.dest);

    const twice = [_]Mount{
        .{ .kind = .tmpfs, .dest = "/x" },
        .{ .kind = .mask, .dest = "/y" },
        .{ .kind = .tmpfs, .dest = "/x" },
    };
    var srcs2: [twice.len]Src = undefined;
    for (&twice, &srcs2) |*m, *s| s.* = .{ .m = m };
    msg.prog = "mount-test";
    defer msg.prog = "flong";
    try testing.expectError(error.Reported, sortRefusingTwice(&srcs2));
}
