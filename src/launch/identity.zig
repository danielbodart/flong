//! launch/identity.zig: the payload's identity, from the prepared root
//! (rootless-wrapper.bash:330-360), for `flong launch DECL.zon`'s
//! prologue (DESIGN.md, "Launch sequence": the
//! payload's identity).
//!
//!   open  $P/etc/passwd and $P/etc/group, read whole; or swept (:331-339)
//!   of    the user's passwd entry by name, its ids against the
//!         declaration's, and its groups (groups.zig) (:340-360)
//!
//! On the warm path nothing is locked yet, so a launch of another
//! generation may sweep this cache between prepare.zig's test of prepared/
//! and these opens: `open` then answers `.swept`, and the prologue starts
//! over (prologue.relaunchSelf), preparing the root afresh, as flong
//! launch's own relaunch does. Once open, the files are read whole
//! whatever happens to their names. Each path is followed as the wrapper's
//! redirections followed it.
//!
//! passwd is read as the wrapper's `while IFS=: read -r n _ u g _ h s`
//! reads it, as groups.zig reads /etc/group: a line is what ends in a
//! newline, a NUL dropped, nothing trimmed, no line skipped, and the last
//! name, the shell, is the rest of the line after the sixth ':' (the one
//! ':' ending a single word dropped). The first line whose name is the
//! user's wins. The ids stay text: they are compared as text with the
//! declaration's (:350), and the spec reads them.
//!
//! Each refusal is the wrapper's text, said through msg under the
//! declaration's name (prologue.exit_refused).

const std = @import("std");
const sys = @import("sys");
const fdt = @import("fd");
const msg = @import("msg");
const groups = @import("groups");

const Allocator = std.mem.Allocator;

/// The prepared root's passwd and group, read whole.
pub const Files = struct {
    passwd: []const u8,
    group: []const u8,
};

/// What `open` found.
pub const Opened = union(enum) {
    files: Files,
    /// $P is gone: the cache was swept, and the launch starts over
    swept,
};

/// `exec {pw}<"$P/etc/passwd" {gr}<"$P/etc/group"` (:336-339), `prepared`
/// being $P: both opened, passwd first, then read whole into `gpa`. When
/// either will not open, `.swept` if $P is not a directory (following
/// symlinks, as `-d`), else the refusal "cannot read $P/etc/passwd and
/// $P/etc/group", which a read error also gets.
pub fn open(gpa: Allocator, prepared: []const u8) msg.Error!Opened {
    const pw_path = std.fmt.allocPrintSentinel(gpa, "{s}/etc/passwd", .{prepared}, 0) catch return oom();
    const gr_path = std.fmt.allocPrintSentinel(gpa, "{s}/etc/group", .{prepared}, 0) catch return oom();
    const pw = switch (try opened(pw_path)) {
        .ok => |f| f,
        .err => return gone(gpa, prepared),
    };
    defer pw.close();
    const gr = switch (try opened(gr_path)) {
        .ok => |f| f,
        .err => return gone(gpa, prepared),
    };
    defer gr.close();
    const passwd = try readWhole(gpa, pw, prepared);
    const group = try readWhole(gpa, gr, prepared);
    return .{ .files = .{ .passwd = passwd, .group = group } };
}

fn opened(path: [:0]const u8) msg.Error!sys.Result(fdt.File) {
    return fdt.openFile(fdt.cwd, path, .{}, 0) catch msg.refuse("{s}: too many open descriptors", .{path});
}

/// `[[ ! -d $P ]]` then relaunch, else the refusal (:337-338).
fn gone(gpa: Allocator, prepared: []const u8) msg.Error!Opened {
    const at = gpa.dupeZ(u8, prepared) catch return oom();
    const dir = switch (sys.fstatat(sys.AT.FDCWD, at, 0)) {
        .ok => |st| sys.S.ISDIR(st.mode),
        .err => false,
    };
    if (!dir) return .swept;
    return cannotRead(prepared);
}

fn readWhole(gpa: Allocator, f: fdt.File, prepared: []const u8) msg.Error![]const u8 {
    const r = fdt.readAll(f, gpa) catch return oom();
    return switch (r) {
        .ok => |t| t,
        .err => cannotRead(prepared),
    };
}

fn cannotRead(prepared: []const u8) msg.Error {
    return msg.refuse("cannot read {s}/etc/passwd and {s}/etc/group", .{ prepared, prepared });
}

/// The payload's identity: $uid, $gid, $home, $shell and $groups.
pub const Identity = struct {
    uid: []const u8,
    gid: []const u8,
    home: []const u8,
    shell: []const u8,
    /// the primary gid first, then every group naming the user
    groups: []const []const u8,
};

/// :340-358 over `files`, for the declaration's `user`, `cuid` and `cgid`;
/// `prepared` ($P) names the file in a refusal. Refusals: "<user> is not a
/// user in $P/etc/passwd" (no line of that name, or one with an empty uid:
/// `-z $uid`, :347) and "<user> is <uid>:<gid> in the prepared root, and
/// the declaration says <cuid>:<cgid>" (:348-352): the maps were made from
/// the declared ids, so ids the root disagrees with would put the user's
/// files on the wrong host ids. Everything is `gpa`'s, an arena's.
pub fn of(gpa: Allocator, files: Files, prepared: []const u8, user: []const u8, cuid: u32, cgid: u32) msg.Error!Identity {
    const e = (find(gpa, files.passwd, user) catch return oom()) orelse
        return msg.refuse("{s} is not a user in {s}/etc/passwd", .{ user, prepared });
    if (e.uid.len == 0) return msg.refuse("{s} is not a user in {s}/etc/passwd", .{ user, prepared });
    var ub: [10]u8 = undefined;
    var gb: [10]u8 = undefined;
    const cuid_text = ub[0..std.fmt.printInt(&ub, cuid, 10, .lower, .{})];
    const cgid_text = gb[0..std.fmt.printInt(&gb, cgid, 10, .lower, .{})];
    if (!std.mem.eql(u8, e.uid, cuid_text) or !std.mem.eql(u8, e.gid, cgid_text))
        return msg.refuse("{s} is {s}:{s} in the prepared root, and the declaration says {d}:{d}", .{ user, e.uid, e.gid, cuid, cgid });
    const list = groups.of(gpa, files.group, user, e.gid) catch return oom();
    return .{ .uid = e.uid, .gid = e.gid, .home = e.home, .shell = e.shell, .groups = list };
}

/// A passwd entry's four fields the wrapper keeps.
pub const Entry = struct { uid: []const u8, gid: []const u8, home: []const u8, shell: []const u8 };

/// The first line of `text`, an /etc/passwd, whose name is `user`, read
/// as `IFS=: read -r n _ u g _ h s` reads it (:341-346); null when none
/// is. A field is a slice of `text`, or of a copy of its line in `gpa`
/// when the line has a NUL.
pub fn find(gpa: Allocator, text: []const u8, user: []const u8) Allocator.Error!?Entry {
    var rest = text;
    while (std.mem.indexOfScalar(u8, rest, '\n')) |end| {
        const line = try groups.dropNul(gpa, rest[0..end]);
        rest = rest[end + 1 ..];
        const n, _, const u, const g, _, const h, const s = groups.fields(7, line);
        if (std.mem.eql(u8, n, user)) return .{ .uid = u, .gid = g, .home = h, .shell = s };
    }
    return null;
}

fn oom() msg.Error {
    return msg.fail(.NOMEM, "malloc", .{});
}

// ---- tests ----

const testing = std.testing;

fn expectEntry(want: ?[4][]const u8, text: []const u8, user: []const u8) !void {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const got = try find(arena.allocator(), text, user);
    if (want) |w| {
        const e = got orelse return error.TestUnexpectedResult;
        try testing.expectEqualStrings(w[0], e.uid);
        try testing.expectEqualStrings(w[1], e.gid);
        try testing.expectEqualStrings(w[2], e.home);
        try testing.expectEqualStrings(w[3], e.shell);
    } else try testing.expectEqual(@as(?Entry, null), got);
}

test "find: the user's line by name, the first one, as bash's read splits it" {
    const text =
        \\root:x:0:0:System administrator:/root:/run/current-system/sw/bin/bash
        \\agent:x:1000:100::/home/agent:/run/current-system/sw/bin/bash
        \\agent:x:1001:101::/home/other:/bin/sh
        \\
    ;
    try expectEntry(.{ "1000", "100", "/home/agent", "/run/current-system/sw/bin/bash" }, text, "agent");
    try expectEntry(.{ "0", "0", "/root", "/run/current-system/sw/bin/bash" }, text, "root");
    try expectEntry(null, text, "nobody");
    try expectEntry(null, text, "agen");
    // The last line without a newline is not read.
    try expectEntry(null, "agent:x:1000:100::/home/agent:/bin/sh", "agent");
    // The shell is the rest of the line: one ':' ending a word dropped,
    // more kept.
    try expectEntry(.{ "1", "2", "/h", "/bin/sh" }, "agent:x:1:2::/h:/bin/sh:\n", "agent");
    try expectEntry(.{ "1", "2", "/h", "/bin/sh:x" }, "agent:x:1:2::/h:/bin/sh:x\n", "agent");
    try expectEntry(.{ "1", "2", "/h", "/bin/sh::" }, "agent:x:1:2::/h:/bin/sh::\n", "agent");
    // Too few fields: the missing ones empty.
    try expectEntry(.{ "1", "", "", "" }, "agent:x:1\n", "agent");
    try expectEntry(.{ "", "", "", "" }, "agent\n", "agent");
    // Nothing trimmed, no line skipped, a NUL dropped, a '\r' kept.
    try expectEntry(null, " agent:x:1:2::/h:/s\n", "agent");
    try expectEntry(.{ "1", "2", "/h", "/s" }, "#x\nag\x00ent:x:1:2::/h:/s\n", "agent");
    try expectEntry(.{ " 1", "2", "/h", "/s\r" }, "agent:x: 1:2::/h:/s\r\n", "agent");
    try expectEntry(.{ "1", "2", "/h", "/s" }, "#agent:x:9:9::/:/\nagent:x:1:2::/h:/s\n", "agent");
}
