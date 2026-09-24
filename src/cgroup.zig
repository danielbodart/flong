//! cgroup.zig: the session cgroup (flong-cgroup.h). Phase 5 ports the
//! sweep's half of launcher/flong-cgroup.c: the sweeper's holder
//! (:92-144, 146-157, 279-298), a record's session opened (:415-486),
//! killed, waited for (:490-529) and removed (:531-602). Phase 7's L2 ports
//! the launch's half: the nsdelegate check (:28-88), finding the holder
//! (:159-277) and making the session (:300-413).
//!
//! Every session gets its own cgroup, <holder>/<container>/<machine>, with
//! three leaves: sandbox (bwrap, everything in the session, and the mount
//! helper for the moment it runs), hooks (postStart and whatever it leaves
//! running) and pasta. Each process is created in its leaf with
//! clone3(CLONE_INTO_CGROUP) and never migrated; the session cgroup itself
//! holds no process, so controllers can be enabled below it. No limit is
//! written unless the spec declares one, and a controller is enabled only
//! when a declared limit needs it (flong-cgroup.h:1-17).
//!
//! The launch's half imports proc (the holder's start) and passwd (the
//! refusal's name); the sweeper's build, which reaches only the sweep's
//! half, gives cgroup neither, and Zig resolves an import only where it is
//! used (build.zig's `launcher (phase 7)` block gives the launch's both).
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
const proc = @import("proc");
const passwd = @import("passwd");

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
    pub fn of(parts: []const []const u8) ?Path {
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

// ---- the nsdelegate check (flong-cgroup.c:28-88) ----

/// has_item (flong-cgroup.c:30-42): whether `item` is one of the items in
/// `list`, separated by `sep`: the options of a mount, the controllers of a
/// cgroup. `list` is read as the C reads its string, up to a first NUL.
pub fn hasItem(list_in: []const u8, item: []const u8, sep: u8) bool {
    const list = list_in[0 .. std.mem.indexOfScalar(u8, list_in, 0) orelse list_in.len];
    var p: usize = 0;
    while (true) {
        if (p < list.len and list[p] == sep) p += 1;
        const rest = list[p..];
        if (std.mem.startsWith(u8, rest, item) and (rest.len == item.len or rest[item.len] == sep)) return true;
        p = std.mem.indexOfScalarPos(u8, list, p, sep) orelse return false;
    }
}

/// strtok_r(3) with the one delimiter ' ', over `line` from `pos.*`:
/// leading spaces skipped, the token up to the next space, which it
/// consumes; null at the end.
fn token(line: []const u8, pos: *usize) ?[]const u8 {
    var i = pos.*;
    while (i < line.len and line[i] == ' ') i += 1;
    if (i == line.len) {
        pos.* = i;
        return null;
    }
    const start = i;
    while (i < line.len and line[i] != ' ') i += 1;
    pos.* = if (i < line.len) i + 1 else i;
    return line[start..i];
}

/// What /proc/self/mountinfo says of /sys/fs/cgroup.
pub const Mountinfo = enum { not_cgroup2, not_delegated, delegated };

/// cg_check_nsdelegate's reading (flong-cgroup.c:50-75), of a whole
/// mountinfo text. A line is "id parent dev root mountpoint options
/// [optional...] - fstype source superoptions", its fields separated by
/// single spaces (a space inside a field is written \040). nsdelegate is a
/// superblock option. The last line on /sys/fs/cgroup with its " - " is
/// the mount on top, the one a path reaches, so it alone decides. Each
/// line is read as getline and strtok_r read it: up to a first NUL, runs
/// of spaces as one. Any bytes are read without a panic.
pub fn mountinfo(text: []const u8) Mountinfo {
    var is_cgroup2 = false;
    var delegated = false;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |whole| {
        const line = whole[0 .. std.mem.indexOfScalar(u8, whole, 0) orelse whole.len];
        var pos: usize = 0;
        var n: usize = 0;
        var point: []const u8 = "";
        while (n < 5) : (n += 1) point = token(line, &pos) orelse break;
        if (n < 5 or !std.mem.eql(u8, point, root)) continue;
        // strtok_r(NULL, "", ...): the rest of the line, or null at its end.
        if (pos == line.len) continue;
        const rest = line[pos..];
        const sep = std.mem.indexOf(u8, rest, " - ") orelse continue;
        var at = pos + sep + 3;
        const fstype = token(line, &at);
        _ = token(line, &at);
        const super = token(line, &at);
        is_cgroup2 = fstype != null and std.mem.eql(u8, fstype.?, "cgroup2");
        delegated = is_cgroup2 and super != null and hasItem(super.?, "nsdelegate", ',');
    }
    if (!is_cgroup2) return .not_cgroup2;
    if (!delegated) return .not_delegated;
    return .delegated;
}

/// cg_check_nsdelegate (flong-cgroup.c:44-88): refuses to go on unless
/// cgroup2 is mounted at /sys/fs/cgroup with nsdelegate. Without it a
/// payload could move out of the cgroup that reaps it. The text is read
/// whole into `gpa`, the launcher's arena.
pub fn checkNsdelegate(gpa: std.mem.Allocator) Error!void {
    const f = try msg.check(fdt.openFile(fdt.cwd, "/proc/self/mountinfo", .{}, 0), "open /proc/self/mountinfo", .{});
    const read = fdt.readAll(f, gpa);
    f.close();
    const text = try msg.check(read catch sys.Result([]u8){ .err = .NOMEM }, "read /proc/self/mountinfo", .{});
    switch (mountinfo(text)) {
        .not_cgroup2 => return msg.refuse("cgroup2 is not mounted at " ++ root ++ ": sessions need the unified hierarchy", .{}),
        .not_delegated => return msg.refuse("cgroup2 at " ++ root ++ " is not mounted with nsdelegate: a session could move out of the cgroup that reaps it", .{}),
        .delegated => {},
    }
}

// ---- finding the holder (flong-cgroup.c:159-277) ----

/// refuse_no_manager (flong-cgroup.c:159-168): the refusal when there is
/// nowhere to put a session's cgroup, naming the caller as /etc/passwd
/// does, or by uid (quirk 19).
fn refuseNoManager(gpa: std.mem.Allocator) Error {
    return noManager(gpa, sys.getuid());
}

/// refuse_no_manager for `uid`, which the driver's checks name.
pub fn noManager(gpa: std.mem.Allocator, uid: sys.uid_t) Error {
    if (passwd.lookup(gpa, uid)) |name|
        return msg.refuse("no user manager for {s}: set users.users.{s}.linger = true", .{ name, name });
    return msg.refuse("no user manager for uid {d}: set users.users.<name>.linger = true", .{uid});
}

/// An open of a cgroup by its absolute path: the handle, or the errno,
/// which a full table answers as EMFILE, as the C would get it.
fn openAbsolute(path: *const Path) sys.Result(fdt.Fd(.cgroup)) {
    return fdt.openCgroup(fdt.cwd, path.slice()) catch .{ .err = .MFILE };
}

/// holder_under_manager (flong-cgroup.c:170-208): the user manager is
/// there. Opens <manager>/<rel>, first starting the holder unit, with
/// `start_argv`, when its cgroup is absent. The warm path is one open.
fn holderUnderManager(gpa: std.mem.Allocator, manager: []const u8, rel: []const u8, start_argv: []const [:0]const u8) sig.Error!Holder {
    const path = Path.of(&.{ manager, "/", rel }) orelse return msg.refuse("the holder's cgroup path is too long", .{});
    switch (openAbsolute(&path)) {
        .ok => |h| return holderTake(path, h),
        .err => |e| if (e != .NOENT) return msg.fail(e, "open the holder's cgroup {s}", .{path.slice()}),
    }
    if (start_argv.len == 0)
        return msg.refuse("the holder's cgroup {s} does not exist, and there is no way to start it", .{path.slice()});

    var s = proc.Spawn.init(gpa, start_argv[0]) catch return msg.fail(.NOMEM, "malloc", .{});
    for (start_argv[1..]) |a| s.arg(a) catch return msg.fail(.NOMEM, "malloc", .{});
    const child = try s.start();
    // An aborted or failed reap closes the pidfd and leaves the start to
    // end on its own (quirk 8, kept: :195-198).
    const status = child.await() catch |err| {
        child.release();
        return err;
    };
    if (status != 0) return msg.refuse("starting the holder failed ({s} exited {d})", .{ start_argv[0], status });

    return switch (openAbsolute(&path)) {
        .ok => |h| holderTake(path, h),
        .err => |e| if (e == .NOENT)
            msg.refuse("the holder's cgroup {s} does not exist after starting it", .{path.slice()})
        else
            msg.fail(e, "open the holder's cgroup {s}", .{path.slice()}),
    };
}

/// holder_delegated (flong-cgroup.c:210-238): no user manager. The
/// launcher's own cgroup, when a system unit with User= and Delegate=yes
/// gave it to the caller; its parent when limits need controllers, since a
/// cgroup with processes in it cannot enable any for its children.
fn holderDelegated(gpa: std.mem.Allocator, own: Path, have_limits: bool) Error!Holder {
    const fd = switch (openAbsolute(&own)) {
        .ok => |h| h,
        .err => |e| return msg.fail(e, "open the launcher's cgroup {s}", .{own.slice()}),
    };
    if (owner(fd) != sys.getuid()) {
        fd.close();
        return refuseNoManager(gpa);
    }
    if (!have_limits) return holderTake(own, fd);
    fd.close();

    var parent = own;
    try cutParent(&parent);
    const pfd = switch (openAbsolute(&parent)) {
        .ok => |h| h,
        .err => null,
    };
    if (pfd == null or owner(pfd.?) != sys.getuid()) {
        if (pfd) |h| h.close();
        return msg.refuse("limits need a delegated cgroup with no process in it, and {s} is not yours: run the launcher's unit with DelegateSubgroup=", .{parent.slice()});
    }
    return holderTake(parent, pfd.?);
}

/// cg_holder_find (flong-cgroup.c:240-277; flong-cgroup.h:35-56): the
/// holder for a launch. `rel` is the spec's holder, a relative path of
/// plain components the spec has checked.
///  1. The user manager's cgroup is the launcher's own cgroup up to and
///     including its user@UID.service component, or, when the launcher
///     runs outside it (a login session's scope),
///     /user.slice/user-UID.slice/user@UID.service. If that exists, the
///     holder is <it>/<rel>, started with `start_argv` when absent.
///  2. With no user manager: the launcher's own cgroup, when it is the
///     caller's; with limits, its parent, which must be the caller's too.
///  3. Otherwise refused, naming users.users.<name>.linger.
/// Paths and the start's argv are in `gpa`, the launcher's arena.
pub fn holderFind(gpa: std.mem.Allocator, rel: []const u8, start_argv: []const [:0]const u8, have_limits: bool) sig.Error!Holder {
    const own = try ownCgroup();
    const o = own.slice();
    var unit_buf: [64]u8 = undefined;
    const unit = std.fmt.bufPrint(&unit_buf, "user@{d}.service", .{sys.getuid()}) catch unreachable; // proven: 13 + 10 < 64

    var hit: ?usize = null;
    var p = root.len;
    while (std.mem.indexOfScalarPos(u8, o, p, '/')) |slash| {
        const c = o[slash + 1 ..];
        if (std.mem.startsWith(u8, c, unit) and (c.len == unit.len or c[unit.len] == '/')) {
            hit = slash + 1 + unit.len;
            break;
        }
        p = slash + 1;
    }
    var slice_buf: [64]u8 = undefined;
    const manager = if (hit) |h|
        Path.of(&.{o[0..h]}).?
    else
        Path.of(&.{ root, "/user.slice/", std.fmt.bufPrint(&slice_buf, "user-{d}.slice/", .{sys.getuid()}) catch unreachable, unit }).?; // proven: 16 + 10 < 64

    switch (openAbsolute(&manager)) {
        .ok => |h| {
            const u = owner(h);
            h.close();
            if (u != sys.getuid()) return msg.refuse("the user manager's cgroup {s} is not yours", .{manager.slice()});
            return holderUnderManager(gpa, manager.slice(), rel, start_argv);
        },
        .err => |e| if (e != .NOENT) return msg.fail(e, "open the user manager's cgroup {s}", .{manager.slice()}),
    }
    return holderDelegated(gpa, own, have_limits);
}

// ---- making the session (flong-cgroup.c:300-413) ----

/// cg_session_path (flong-cgroup.c:302-308): the path the session's cgroup
/// will have, for the record, which is written before the cgroup exists.
pub fn sessionPath(h: *const Holder, container: []const u8, machine: []const u8) Error!Path {
    return Path.of(&.{ h.path.slice(), "/", container, "/", machine }) orelse
        msg.refuse("the session's cgroup path is too long", .{});
}

/// enable_controllers (flong-cgroup.c:310-337): enables in the cgroup
/// behind `dir`, named `path` in messages, the controllers `limits` need.
/// A controller is the limit file's name up to its dot. One the level does
/// not have, because systemd did not delegate it, is refused by name rather
/// than by the ENOENT the write would give. The write itself is EBUSY while
/// the level has a process of its own, which is why the holder's process
/// lives in its supervisor leaf.
fn enableControllers(dir: anytype, path: []const u8, limits: anytype) Error!void {
    if (limits.len == 0) return;
    var have_buf: [256]u8 = undefined;
    const n = try readAt(dir, "cgroup.controllers", &have_buf);
    const have = have_buf[0 .. std.mem.indexOfScalar(u8, have_buf[0..n], '\n') orelse n];
    for (limits) |l| {
        const file: []const u8 = l.file;
        // snprintf(name, 32, "%.*s", ...): up to the dot, at most 31 bytes.
        const name = file[0..@min(std.mem.indexOfScalar(u8, file, '.') orelse file.len, 31)];
        if (!hasItem(have, name, ' '))
            return msg.refuse("the limit {s} needs the {s} controller, which {s} does not have", .{ file, name, path });
        var plus_buf: [34]u8 = undefined;
        const plus = std.fmt.bufPrint(&plus_buf, "+{s}", .{name}) catch unreachable; // proven: 1 + 31 < 34
        try writeAt(dir, "cgroup.subtree_control", plus);
    }
}

/// cg_session_create (flong-cgroup.c:339-413; flong-cgroup.h:82-92): makes
/// the session cgroup: mkdir <container> (EEXIST is fine: it is shared and
/// never removed, since another launch may be making its session in it
/// right now), the controllers the limits need enabled down to the session,
/// mkdir <machine> (EEXIST is a refusal: a duplicate session), mkdir and
/// open the three leaves, and each limit written into the sandbox leaf,
/// where the payload's programs read them (its cgroup namespace is rooted
/// there, and Go reads cpu.max in its own cgroup and nowhere above). On a
/// failure after <machine> is made, what was made is removed, in reverse:
/// nothing has run in the session yet, so every directory is empty and
/// goes at once. `limits` is a slice of spec.Limit: each has `file` and
/// `value`, NUL-terminated.
pub fn sessionCreate(h: *const Holder, container: [:0]const u8, machine: [:0]const u8, limits: anytype) Error!Session {
    const path = try sessionPath(h, container, machine);
    const p = path.slice();
    const hpath = h.path.slice();

    switch (h.fd.mkdirat(container, 0o755)) {
        .ok => {},
        .err => |e| if (e != .EXIST) return msg.fail(e, "mkdir {s}/{s}", .{ hpath, container }),
    }
    const cfd = try msg.check(fdt.openCgroup(h.fd, container), "open {s}/{s}", .{ hpath, container });
    defer cfd.close();

    // A controller must be enabled on every level above the cgroup whose
    // file sets the limit: the holder, the container level and the
    // session, above the sandbox leaf.
    try enableControllers(h.fd, hpath, limits);
    try enableControllers(cfd, p[0..std.mem.lastIndexOfScalar(u8, p, '/').?], limits);

    switch (cfd.mkdirat(machine, 0o755)) {
        .ok => {},
        .err => |e| return if (e == .EXIST)
            msg.refuse("a session named {s} is already running ({s} exists)", .{ machine, p })
        else
            msg.fail(e, "mkdir {s}", .{p}),
    }

    var made: Made = .{};
    const done: Error!void = steps: {
        made.fd = msg.check(fdt.openCgroup(cfd, machine), "open {s}", .{p}) catch |e| break :steps e;
        enableControllers(made.fd.?, p, limits) catch |e| break :steps e;
        for (leaf_names, 0..) |name, i| {
            switch (made.fd.?.mkdirat(name, 0o755)) {
                .ok => {},
                .err => |e| break :steps msg.fail(e, "mkdir {s}/{s}", .{ p, name }),
            }
            made.leaf[i] = msg.check(fdt.openCgroup(made.fd.?, name), "open {s}/{s}", .{ p, name }) catch |e| break :steps e;
        }
        for (limits) |l| writeAt(made.leaf[0].?, l.file, l.value) catch |e| break :steps e;
    };
    done catch |err| {
        made.undo(cfd, machine);
        return err;
    };
    return .{ .path = path, .fd = made.fd.?, .leaf = made.leaf };
}

/// What sessionCreate has made below the container level, open.
const Made = struct {
    fd: ?fdt.Fd(.cgroup) = null,
    leaf: [leaf_names.len]?fdt.Fd(.cgroup) = .{ null, null, null },

    /// The undo (flong-cgroup.c:401-412), in reverse: each leaf closed and
    /// removed, then the session closed and removed from the container
    /// level `cfd`. Nothing has run in the session yet, so every directory
    /// made is empty and goes at once; rmdir's errors are not looked at.
    fn undo(self: *Made, cfd: fdt.Fd(.cgroup), machine: [:0]const u8) void {
        var i = leaf_names.len;
        while (i > 0) {
            i -= 1;
            if (self.leaf[i]) |h| h.close();
            self.leaf[i] = null;
            if (self.fd) |f| _ = f.unlinkat(leaf_names[i], sys.AT.REMOVEDIR);
        }
        if (self.fd) |f| f.close();
        self.fd = null;
        _ = cfd.unlinkat(machine, sys.AT.REMOVEDIR);
    }
};

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
