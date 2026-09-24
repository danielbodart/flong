//! cgroup.zig: the session cgroup (flong-cgroup.h). Phase 5 ports the
//! sweep's half of launcher/flong-cgroup.c: the sweeper's holder
//! (:92-144, 146-157, 279-298), a record's session opened (:415-486),
//! killed, waited for (:490-529) and removed (:531-602). The launch's half
//! (the nsdelegate check, finding the holder, making the session) is L2's.
//!
//! Everything is reached from descriptors once the holder is open: the
//! container level, the session and its leaves are each opened with one
//! path component under their parent, with O_NOFOLLOW, and removed the same
//! way. cgroupfs has no symlinks of its own and cgroup2 cannot rename a
//! cgroup, so a descriptor keeps naming the directory it was opened on
//! (:1-8).

const std = @import("std");
const sys = @import("sys");
const fdt = @import("fd");
const msg = @import("msg");
const sig = @import("sig");
const names = @import("names");

const Error = msg.Error;

/// CGROOT (flong-cgroup.c:24).
pub const root = "/sys/fs/cgroup";

/// The leaves of a session, in order (flong-cgroup.c:26).
pub const leaf_names = [_][:0]const u8{ "sandbox", "hooks", "pasta" };

/// PATH_MAX, the C's path buffers.
const path_max = sys.path_max;

/// A path in a PATH_MAX buffer, NUL-terminated, as the C keeps them.
pub const Path = struct {
    buf: [path_max]u8 = undefined,
    len: usize = 0,

    /// `s` if it fits with its NUL (the C's snprintf into PATH_MAX), else
    /// null.
    fn of(parts: []const []const u8) ?Path {
        var p: Path = .{};
        for (parts) |s| {
            if (p.len + s.len >= path_max) return null;
            @memcpy(p.buf[p.len..][0..s.len], s);
            p.len += s.len;
        }
        p.buf[p.len] = 0;
        return p;
    }

    pub fn slice(self: *const Path) [:0]const u8 {
        return self.buf[0..self.len :0];
    }
};

// ---- reading and writing a cgroup's files (flong-util.c:167-218) ----

/// fl_write_at: all of `s` to `path` under `dir`, opened
/// O_WRONLY|O_CLOEXEC|O_NOFOLLOW.
pub fn writeAt(dir: anytype, path: [:0]const u8, s: []const u8) Error!void {
    const f = try msg.check(fdt.openFile(dir, path, .{ .ACCMODE = .WRONLY, .NOFOLLOW = true }, 0), "open {s}", .{path});
    defer f.close();
    _ = try msg.check(f.writeAll(s), "write {s} to {s}", .{ s, path });
}

/// fl_read_at: at most buf.len - 1 bytes of `path` under `dir` (the C
/// keeps the last for its NUL), opened O_RDONLY|O_CLOEXEC|O_NOFOLLOW.
pub fn readAt(dir: anytype, path: [:0]const u8, buf: []u8) Error!usize {
    const f = try msg.check(fdt.openFile(dir, path, .{ .NOFOLLOW = true }, 0), "open {s}", .{path});
    defer f.close();
    var len: usize = 0;
    while (len < buf.len - 1) {
        const n = try msg.check(f.read(buf[len .. buf.len - 1]), "read {s}", .{path});
        if (n == 0) break;
        len += n;
    }
    return len;
}

// ---- the holder ----

/// The delegated cgroup sessions are made under (struct fl_holder,
/// flong-cgroup.h:25-28), kept until the process exits.
pub const Holder = struct {
    path: Path,
    fd: fdt.Held(.cgroup),
};

/// What /proc/self/cgroup's "0::" line says (flong-cgroup.c:102-112), read
/// as the C reads its NUL-terminated buffer.
pub const Own = union(enum) {
    /// the path after "0::", up to its newline
    path: []const u8,
    no_entry,
    /// the path after "0::" does not start with '/'
    unexpected: []const u8,
};

pub fn ownFrom(text: []const u8) Own {
    const c = text[0 .. std.mem.indexOfScalar(u8, text, 0) orelse text.len];
    var p: usize = 0;
    while (!std.mem.startsWith(u8, c[p..], "0::")) {
        p = (std.mem.indexOfScalarPos(u8, c, p, '\n') orelse return .no_entry) + 1;
    }
    const rest = c[p + 3 ..];
    const line = rest[0 .. std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len];
    if (line.len == 0 or line[0] != '/') return .{ .unexpected = line };
    return .{ .path = line };
}

/// own_cgroup (flong-cgroup.c:92-117): this process's cgroup, the "0::"
/// line of /proc/self/cgroup, as an absolute path under /sys/fs/cgroup.
fn ownCgroup() Error!Path {
    var buf: [path_max + 64]u8 = undefined;
    const len = try readAt(fdt.cwd, "/proc/self/cgroup", &buf);
    if (len == buf.len - 1) return msg.refuse("/proc/self/cgroup is too long", .{});
    const p = switch (ownFrom(buf[0..len])) {
        .path => |p| p,
        .no_entry => return msg.refuse("no cgroup2 entry in /proc/self/cgroup", .{}),
        .unexpected => |p| return msg.refuse("an unexpected cgroup in /proc/self/cgroup: {s}", .{p}),
    };
    // The root cgroup is "/", which would give ".../cgroup/".
    return Path.of(&.{ root, if (std.mem.eql(u8, p, "/")) "" else p }) orelse
        msg.refuse("the launcher's cgroup path is too long", .{});
}

/// The uid that owns the cgroup behind `h`, or (uid_t)-1 when fstat fails
/// (flong-cgroup.c:128-133).
fn owner(h: anytype) sys.uid_t {
    return switch (h.fstat()) {
        .ok => |st| st.uid,
        .err => std.math.maxInt(sys.uid_t),
    };
}

/// cut_parent (flong-cgroup.c:135-144): `path` cut at its last '/', never
/// above the cgroup2 root.
fn cutParent(path: *Path) Error!void {
    const slash = std.mem.lastIndexOfScalar(u8, path.slice(), '/');
    if (slash == null or slash.? < root.len)
        return msg.refuse("{s} has no parent cgroup of its own", .{path.slice()});
    path.len = slash.?;
    path.buf[path.len] = 0;
}

/// holder_take (flong-cgroup.c:146-157): the cgroup at `path`, open as
/// `h`, is the holder when the caller owns it. Takes `h` either way.
fn holderTake(path: Path, h: fdt.Fd(.cgroup)) Error!Holder {
    if (owner(h) != sys.getuid()) {
        h.close();
        return msg.refuse("the holder's cgroup {s} is not delegated to you", .{path.slice()});
    }
    return .{ .path = path, .fd = h.holdUntilExit() };
}

/// The holder at `path`, an absolute cgroup path, when the caller owns it
/// (holder_take after open_cgroup); the sweeper's is `holderSelf`'s, a
/// driver's may be named.
pub fn holderAt(path: Path) Error!Holder {
    const h = try msg.check(fdt.openCgroup(fdt.cwd, path.slice()), "open the holder's cgroup {s}", .{path.slice()});
    return holderTake(path, h);
}

/// cg_holder_self (flong-cgroup.c:279-298): the sweeper's holder, the
/// parent of its own cgroup, since the holder unit runs it in its
/// DelegateSubgroup=supervisor leaf. A sweeper started anywhere else must
/// not guess one: it releases only the sessions under its holder.
pub fn holderSelf() Error!Holder {
    var own = try ownCgroup();
    const s = own.slice();
    const leaf = s[std.mem.lastIndexOfScalar(u8, s, '/').?..];
    if (!std.mem.eql(u8, leaf, "/supervisor"))
        return msg.refuse("not in a holder unit's supervisor cgroup (in {s}): run the sweeper in a unit with DelegateSubgroup=supervisor", .{s});
    try cutParent(&own);
    return holderAt(own);
}

// ---- a session named by a record ----

/// session_form (flong-cgroup.c:415-440): where a record's path names its
/// container level, when the path spells a session cgroup,
/// /sys/fs/cgroup/<holder...>/<container>/<machine>: every component
/// non-empty and neither "." nor "..", the container a name, and the last
/// component the record's own machine. The offset of the container in
/// `path`, or null. Both are read as C strings, up to a first NUL.
pub fn sessionForm(path_in: []const u8, machine_in: []const u8) ?usize {
    const path = path_in[0 .. std.mem.indexOfScalar(u8, path_in, 0) orelse path_in.len];
    const machine = machine_in[0 .. std.mem.indexOfScalar(u8, machine_in, 0) orelse machine_in.len];
    if (!std.mem.startsWith(u8, path, root ++ "/")) return null;
    var p: usize = root.len;
    var last: ?usize = null;
    var before: ?usize = null;
    var n: usize = 0;
    while (p < path.len and path[p] == '/') {
        const c = p + 1;
        const len = (std.mem.indexOfScalarPos(u8, path, c, '/') orelse path.len) - c;
        const comp = path[c..][0..len];
        if (len == 0 or std.mem.eql(u8, comp, ".") or std.mem.eql(u8, comp, "..")) return null;
        before = last;
        last = c;
        n += 1;
        p = c + len;
    }
    // A holder, a container and a machine at least.
    if (n < 3 or !std.mem.eql(u8, path[last.?..], machine) or !names.isName(machine) or
        !names.isName(path[before.? .. last.? - 1]))
        return null;
    return before.?;
}

/// struct fl_cgroup (flong-cgroup.h:66-70): a session opened for the sweep.
pub const Session = struct {
    path: Path,
    fd: fdt.Fd(.cgroup),
    /// each leaf; null when absent
    leaf: [leaf_names.len]?fdt.Fd(.cgroup) = .{ null, null, null },

    /// cg_close (flong-cgroup.c:597-602): closes the session and every
    /// leaf, removes nothing. Not named `close`, which zwanzig's models
    /// take for one descriptor's (.zwanzig.json): the handles inside are
    /// closed by name here.
    pub fn closeAll(self: *Session) void {
        for (&self.leaf) |*l| {
            if (l.*) |h| h.close();
            l.* = null;
        }
        self.fd.close();
    }
};

/// cg_session_open's answers (flong-cgroup.h:92-112).
pub const Opened = union(enum) {
    session: Session,
    /// the session cgroup does not exist (a launcher that died before
    /// making it)
    absent,
    /// the session is under another holder, whose sweep releases it;
    /// nothing is printed
    other_holder,
    /// the path is refused, and why is printed: only this lets the sweep
    /// drop the record
    refused,
};

/// cg_session_open (flong-cgroup.c:442-486): opens the existing session
/// cgroup a record names. The path is checked to be a session's before
/// anything is opened, and exactly <holder>/<container>/<machine> before
/// anything is killed: a record naming any other cgroup would get that
/// cgroup killed. It is opened only under `h`, one component at a time and
/// never through a symlink. A failure to open what it names is
/// error.Reported, which may pass (EMFILE, ENOMEM), so the record stays.
pub fn sessionOpen(h: *const Holder, path: []const u8, machine: []const u8) Error!Opened {
    const rest = sessionForm(path, machine) orelse {
        msg.say("the record {s} does not name a session's cgroup: {s}", .{ machine, path });
        return .refused;
    };
    const hpath = h.path.slice();
    if (rest != hpath.len + 1 or !std.mem.startsWith(u8, path, hpath)) return .other_holder;
    const cg_path = Path.of(&.{path}) orelse {
        msg.say("the record {s} names a cgroup path that is too long", .{machine});
        return .refused;
    };

    const cname = path[rest..][0 .. std.mem.indexOfScalarPos(u8, path, rest, '/').? - rest];
    var container_buf: [names.name_max + 1]u8 = undefined;
    @memcpy(container_buf[0..cname.len], cname);
    container_buf[cname.len] = 0;
    const container = container_buf[0..cname.len :0];
    const cfd = switch (fdt.openCgroup(h.fd, container) catch return msg.refuse("open {s}/{s}: too many open descriptors", .{ hpath, container })) {
        .ok => |c| c,
        .err => |e| return if (e == .NOENT) .absent else msg.fail(e, "open {s}/{s}", .{ hpath, container }),
    };
    var machine_buf: [names.name_max + 1]u8 = undefined;
    @memcpy(machine_buf[0..machine.len], machine);
    machine_buf[machine.len] = 0;
    const opened = fdt.openCgroup(cfd, machine_buf[0..machine.len :0]);
    cfd.close();
    const fd = switch (opened catch return msg.refuse("open {s}: too many open descriptors", .{cg_path.slice()})) {
        .ok => |c| c,
        .err => |e| return if (e == .NOENT) .absent else msg.fail(e, "open {s}", .{cg_path.slice()}),
    };
    var s: Session = .{ .path = cg_path, .fd = fd };
    for (leaf_names, 0..) |leaf, i| {
        const r = fdt.openCgroup(s.fd, leaf) catch {
            s.closeAll();
            return msg.refuse("open {s}/{s}: too many open descriptors", .{ cg_path.slice(), leaf });
        };
        switch (r) {
            .ok => |l| s.leaf[i] = l,
            .err => |e| if (e != .NOENT) {
                s.closeAll();
                return msg.fail(e, "open {s}/{s}", .{ cg_path.slice(), leaf });
            },
        }
    }
    return .{ .session = s };
}

// ---- ending a session ----

/// cg_kill (flong-cgroup.c:490-493): "1" to the session's cgroup.kill,
/// every process in every leaf.
pub fn kill(s: *const Session) Error!void {
    return writeAt(s.fd, "cgroup.kill", "1");
}

/// What a read of cgroup.events says of "populated " (flong-cgroup.c:514-523),
/// as the C reads its NUL-terminated buffer: the first "populated " and the
/// byte after it.
pub const Populated = enum { absent, empty, busy };

pub fn populated(text: []const u8) Populated {
    const c = text[0 .. std.mem.indexOfScalar(u8, text, 0) orelse text.len];
    const at = std.mem.indexOf(u8, c, "populated ") orelse return .absent;
    const v = at + "populated ".len;
    return if (v < c.len and c[v] == '0') .empty else .busy;
}

/// cg_wait_empty (flong-cgroup.c:495-529): waits, with no timeout, until
/// the cgroup behind `cg` (a session or a leaf) reports "populated 0" in
/// cgroup.events. The kernel flags cgroup.events with POLLPRI when it
/// changes after the last read, so each read arms the next wait and a
/// change between the read and the poll is never missed.
pub fn waitEmpty(cg: fdt.Fd(.cgroup)) sig.Error!void {
    const ev = try msg.check(fdt.openFile(cg, "cgroup.events", .{ .NOFOLLOW = true }, 0), "open cgroup.events", .{});
    defer ev.close();
    while (true) {
        var buf: [256]u8 = undefined;
        const len = try msg.check(ev.pread(buf[0..255], 0), "read cgroup.events", .{});
        switch (populated(buf[0..len])) {
            .absent => return msg.refuse("cgroup.events has no populated line", .{}),
            .empty => return,
            .busy => try sig.awaitFd(ev, sys.POLL.PRI),
        }
    }
}

/// remove_tree's answers besides an error (flong-cgroup.c:537-538).
pub const Removed = enum { gone, busy };

/// remove_tree (flong-cgroup.c:531-575): removes the cgroup `name` under
/// `parent` and every cgroup below it. A leaf normally has none and goes
/// with one rmdir; a payload allowed nested namespaces can make cgroups of
/// its own inside its leaf, and cgroup.kill has already ended whatever ran
/// in them. rmdir says EBUSY both for a cgroup with processes and for one
/// with children, so on EBUSY the children are removed and the rmdir is
/// tried once more: a cgroup with no children left that is still busy has
/// processes in it. The recursion is unbounded, as the C's (quirk 27).
/// `tree[0..len]` names it in messages, cut to PATH_MAX as the C's
/// snprintf cuts. Every level shares `tree`, each writing its children's
/// names past its own, so a level's frame holds no path buffer: a depth
/// the descriptor table allows (fd.capacity, about 1,020 levels) takes
/// about 2.5 MiB of stack, not the 6.7 MiB a path per frame took.
fn removeTree(parent: anytype, name: [*:0]const u8, tree: *TreePath, len: usize) Error!Removed {
    const path = tree[0..len];
    switch (parent.unlinkat(name, sys.AT.REMOVEDIR)) {
        .ok => return .gone,
        .err => |e| switch (e) {
            .NOENT => return .gone,
            .BUSY => {},
            else => return msg.fail(e, "rmdir {s}", .{path}),
        },
    }
    const d = try msg.check(fdt.openDirNoFollow(parent, name), "open {s}", .{path});
    var rc: Removed = .gone;
    var children = false;
    var buf: [2048]u8 align(8) = undefined;
    // A failed read ends the listing, as readdir's NULL does (:557).
    walk: while (rc == .gone) {
        const n = switch (d.getdents64(&buf)) {
            .ok => |n| n,
            .err => break,
        };
        if (n == 0) break;
        var it: fdt.Entries = .{ .buf = buf[0..n] };
        while (it.next()) |e| {
            if (e.type != fdt.Entries.dt_dir or std.mem.eql(u8, e.name, ".") or std.mem.eql(u8, e.name, "..")) continue;
            var sub_name: [256]u8 = undefined;
            @memcpy(sub_name[0..e.name.len], e.name);
            sub_name[e.name.len] = 0;
            rc = removeTree(d, sub_name[0..e.name.len :0], tree, cutJoin(tree, len, e.name)) catch |err| {
                d.close();
                return err;
            };
            children = true;
            if (rc != .gone) break :walk;
        }
    }
    d.close();
    if (rc != .gone) return rc;
    if (!children) return .busy;
    return switch (parent.unlinkat(name, sys.AT.REMOVEDIR)) {
        .ok => .gone,
        .err => |e| switch (e) {
            .NOENT => .gone,
            .BUSY => .busy,
            else => msg.fail(e, "rmdir {s}", .{path}),
        },
    };
}

/// remove_tree's paths: cg_remove's leaf path, "%s/%s" into PATH_MAX + 16,
/// and each level's below it.
const TreePath = [path_max + 16]u8;

/// snprintf(sub, PATH_MAX, "%s/%s", tree[0..len], b), written in place:
/// the length of the child's path, cut at PATH_MAX - 1 as snprintf cuts.
/// It writes only past tree[0..len], which stays the parent's: a parent
/// longer than the cut gives its first PATH_MAX - 1 bytes and writes
/// nothing.
fn cutJoin(tree: *TreePath, len: usize, b: []const u8) usize {
    var n = @min(len, path_max - 1);
    for ([_][]const u8{ "/", b }) |part| {
        const take = @min(part.len, path_max - 1 - n);
        @memcpy(tree[n..][0..take], part[0..take]);
        n += take;
    }
    return n;
}

/// cg_remove (flong-cgroup.c:577-595): the leaves, then the session
/// cgroup, removed from its parent, the container level, which the
/// session's descriptor reaches as "..". A leaf still populated (pasta
/// exits 20-40 ms after the kill) makes it stop there: `.busy`, and the
/// record is kept for the next sweep.
pub fn remove(s: *const Session) Error!Removed {
    var tree: TreePath = undefined;
    const p = s.path.slice();
    for (leaf_names) |leaf| {
        // s.path is shorter than PATH_MAX, so "%s/%s" fits PATH_MAX + 16.
        const joined = std.fmt.bufPrint(&tree, "{s}/{s}", .{ p, leaf }) catch unreachable; // proven: path_max - 1 + 1 + 7 < path_max + 16
        const rc = try removeTree(s.fd, leaf, &tree, joined.len);
        if (rc != .gone) return rc;
    }
    const cfd = try msg.check(fdt.openCgroup(s.fd, ".."), "open the parent of {s}", .{p});
    defer cfd.close();
    const base = p[std.mem.lastIndexOfScalar(u8, p, '/').? + 1 ..];
    @memcpy(tree[0..p.len], p);
    return removeTree(cfd, @as([*:0]const u8, @ptrCast(base.ptr)), &tree, p.len);
}

// ---- tests ----

const testing = std.testing;

test "sessionForm: a session's cgroup, and what is not one" {
    const m = "demo-1";
    try testing.expectEqual(@as(?usize, 47), sessionForm("/sys/fs/cgroup/user.slice/app.slice/holder.svc/demo/demo-1", m));
    try testing.expectEqual(@as(?usize, 17), sessionForm("/sys/fs/cgroup/h/c/demo-1", m));
    for ([_][]const u8{
        "/sys/fs/cgroup/c/demo-1", // no holder
        "/sys/fs/cgroup/h/c/demo-2", // another machine
        "/sys/fs/cgroup/h/./demo-1",
        "/sys/fs/cgroup/h/../demo-1",
        "/sys/fs/cgroup//h/c/demo-1",
        "/sys/fs/cgroup/h/c/demo-1/",
        "/sys/fs/cgroup/h/.c/demo-1", // a container that is not a name
        "/sys/fs/cgroupx/h/c/demo-1",
        "/sys/fs/cgroup",
        "/sys/fs/cgroup/",
        "",
        "/sys/fs/cgroup/h/c/demo-1\x00x",
    }) |p| {
        if (std.mem.indexOfScalar(u8, p, 0) != null) {
            // Up to the NUL, as the C reads it: a session.
            try testing.expectEqual(@as(?usize, 17), sessionForm(p, m));
        } else try testing.expectEqual(@as(?usize, null), sessionForm(p, m));
    }
    try testing.expectEqual(@as(?usize, null), sessionForm("/sys/fs/cgroup/h/c/.x", ".x"));
}

test "populated reads the first populated line" {
    try testing.expectEqual(Populated.empty, populated("populated 0\nfrozen 0\n"));
    try testing.expectEqual(Populated.busy, populated("populated 1\nfrozen 0\n"));
    try testing.expectEqual(Populated.busy, populated("populated "));
    try testing.expectEqual(Populated.absent, populated("frozen 0\n"));
    try testing.expectEqual(Populated.absent, populated("x\x00populated 0\n"));
    try testing.expectEqual(Populated.empty, populated("xpopulated 0"));
}

test "ownFrom reads the 0:: line" {
    try testing.expectEqualStrings("/user.slice", ownFrom("1:name=systemd:/x\n0::/user.slice\n").path);
    try testing.expectEqualStrings("/", ownFrom("0::/\n").path);
    try testing.expect(ownFrom("1::/x\n") == .no_entry);
    try testing.expect(ownFrom("") == .no_entry);
    try testing.expectEqualStrings("", ownFrom("0::\n").unexpected);
    try testing.expectEqualStrings("x", ownFrom("0::x").unexpected);
}

test "cutJoin writes past its parent only, cut as snprintf into PATH_MAX" {
    var tree: TreePath = undefined;
    @memcpy(tree[0..3], "/a/");
    try testing.expectEqualStrings("/a/b", tree[0..cutJoin(&tree, 2, "b")]);
    // A parent longer than PATH_MAX - 1 (a leaf's path): its first
    // PATH_MAX - 1 bytes, and the parent's tail left as it was.
    @memset(tree[0 .. path_max + 7], 'x');
    tree[path_max + 6] = 'y';
    try testing.expectEqual(@as(usize, path_max - 1), cutJoin(&tree, path_max + 7, "child"));
    try testing.expectEqual(@as(u8, 'y'), tree[path_max + 6]);
    // Near the cut, the name is cut and nothing before the parent's end
    // moves.
    @memset(tree[0 .. path_max - 3], 'p');
    const n = cutJoin(&tree, path_max - 3, "child");
    try testing.expectEqual(@as(usize, path_max - 1), n);
    try testing.expectEqualStrings("p/c", tree[path_max - 4 .. n]);
}
