//! launch/lookup.zig: where a declaration's name leads (DESIGN.md,
//! "The declaration's command"). A declaration's command is a link
//! `NAME -> flong`, and `flong launch NAME` does what the link does: flong
//! loads NAME.zon from the first of these directories that has it.
//!
//!   /etc/flong                  what the NixOS module writes, through
//!                               environment.etc, one file per flong.<name>
//!   $XDG_CONFIG_HOME/flong      the caller's own, outside Nix; with
//!                               XDG_CONFIG_HOME unset or not absolute,
//!                               $HOME/.config/flong, as the XDG base
//!                               directory specification says
//!
//! The system's directory comes first, so a declaration the system
//! installs is the one its name runs whatever the caller's configuration
//! holds; a caller's file of the same name is shadowed, and `flong list`
//! does not show it. Nothing here moves a trust boundary: a caller can
//! run `flong launch` with any file anyway (DESIGN.md, "The declaration":
//! the trust boundary does not move).
//!
//! A name is a file name: a basename, with no '/', neither "." nor "..".
//! One that is none of the directories' says every path it looked for.

const std = @import("std");
const sys = @import("sys");
const fdt = @import("fd");
const cmd = @import("cmd");

const Allocator = std.mem.Allocator;

pub const system_dir = "/etc/flong";

/// The directories a name is looked up in, in order: `system_dir`, then
/// the caller's, when the environment names one.
pub fn dirs(gpa: Allocator, environ: []const [*:0]const u8) Allocator.Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    try out.append(gpa, system_dir);
    if (try userDir(gpa, environ)) |d| try out.append(gpa, d);
    return out.items;
}

fn userDir(gpa: Allocator, environ: []const [*:0]const u8) Allocator.Error!?[]const u8 {
    if (cmd.getenv(environ, "XDG_CONFIG_HOME")) |x| {
        if (x.len > 0 and x[0] == '/') return try std.fmt.allocPrint(gpa, "{s}/flong", .{x});
    }
    if (cmd.getenv(environ, "HOME")) |h| {
        if (h.len > 0 and h[0] == '/') return try std.fmt.allocPrint(gpa, "{s}/.config/flong", .{h});
    }
    return null;
}

/// Whether `name` can be a declaration's file name.
pub fn isName(name: []const u8) bool {
    return name.len > 0 and name.len <= 250 and std.mem.indexOfScalar(u8, name, '/') == null and
        std.mem.indexOfScalar(u8, name, 0) == null and
        !std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, "..");
}

/// What `find` found.
pub const Found = union(enum) {
    /// the declaration's file
    path: [:0]const u8,
    /// none: every path looked for, in order
    missing: []const []const u8,
};

/// NAME.zon in the first of `dirs` that has one: a file there that cannot
/// be stat'd for any reason but its absence counts as found, and its load
/// says why it cannot be read.
pub fn find(gpa: Allocator, name: []const u8, environ: []const [*:0]const u8) Allocator.Error!Found {
    var looked: std.ArrayList([]const u8) = .empty;
    for (try dirs(gpa, environ)) |d| {
        const path = try std.fmt.allocPrintSentinel(gpa, "{s}/{s}.zon", .{ d, name }, 0);
        try looked.append(gpa, path);
        switch (sys.fstatat(sys.AT.FDCWD, path, 0)) {
            .ok => return .{ .path = path },
            .err => |e| if (e != .NOENT and e != .NOTDIR) return .{ .path = path },
        }
    }
    return .{ .missing = looked.items };
}

/// `(looked for A)`, `(looked for A and B)`: the refusal's tail.
pub fn lookedFor(gpa: Allocator, paths: []const []const u8) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(gpa, "looked for ");
    for (paths, 0..) |p, i| {
        if (i > 0) try out.appendSlice(gpa, if (i + 1 == paths.len) " and " else ", ");
        try out.appendSlice(gpa, p);
    }
    return out.items;
}

/// One declaration `flong list` shows.
pub const Entry = struct { name: []const u8, path: []const u8 };

/// Every declaration a name would run, by directory in lookup order and
/// by name within one; a name an earlier directory has is shadowed and
/// left out. A directory that cannot be listed has none.
pub fn list(gpa: Allocator, environ: []const [*:0]const u8) Allocator.Error![]const Entry {
    var out: std.ArrayList(Entry) = .empty;
    for (try dirs(gpa, environ)) |d| {
        const first = out.items.len;
        try names(gpa, d, &out);
        std.mem.sort(Entry, out.items[first..], {}, byName);
        // Shadowed by an earlier directory's.
        var kept = first;
        for (out.items[first..]) |e| {
            const shadowed = for (out.items[0..first]) |x| {
                if (std.mem.eql(u8, x.name, e.name)) break true;
            } else false;
            if (shadowed) continue;
            out.items[kept] = e;
            kept += 1;
        }
        out.items.len = kept;
    }
    return out.items;
}

fn byName(_: void, a: Entry, b: Entry) bool {
    return std.mem.lessThan(u8, a.name, b.name);
}

/// Each `NAME.zon` in `dir`, appended to `out`.
fn names(gpa: Allocator, dir: []const u8, out: *std.ArrayList(Entry)) Allocator.Error!void {
    const at = try gpa.dupeZ(u8, dir);
    const r = fdt.openDir(fdt.cwd, at) catch return;
    const h = switch (r) {
        .ok => |h| h,
        .err => return,
    };
    defer h.close();
    var buf: [4096]u8 align(8) = undefined;
    while (true) {
        const n = switch (h.getdents64(&buf)) {
            .ok => |n| n,
            .err => return,
        };
        if (n == 0) return;
        var it: fdt.Entries = .{ .buf = buf[0..n] };
        while (it.next()) |e| {
            if (!std.mem.endsWith(u8, e.name, ".zon")) continue;
            const name = e.name[0 .. e.name.len - ".zon".len];
            if (!isName(name)) continue;
            try out.append(gpa, .{
                .name = try gpa.dupe(u8, name),
                .path = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ dir, e.name }),
            });
        }
    }
}

// ---- tests ----

const testing = std.testing;

test "dirs: /etc/flong, then XDG_CONFIG_HOME's or HOME's" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const both = try dirs(a, &.{ "HOME=/home/u", "XDG_CONFIG_HOME=/cfg" });
    try testing.expectEqual(2, both.len);
    try testing.expectEqualStrings("/etc/flong", both[0]);
    try testing.expectEqualStrings("/cfg/flong", both[1]);
    const home = try dirs(a, &.{ "XDG_CONFIG_HOME=relative", "HOME=/home/u" });
    try testing.expectEqualStrings("/home/u/.config/flong", home[1]);
    try testing.expectEqual(1, (try dirs(a, &.{"HOME="})).len);
}

test "lookedFor lists every path" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings("looked for /etc/flong/agent.zon", try lookedFor(a, &.{"/etc/flong/agent.zon"}));
    try testing.expectEqualStrings("looked for /a and /b", try lookedFor(a, &.{ "/a", "/b" }));
    try testing.expectEqualStrings("looked for /a, /b and /c", try lookedFor(a, &.{ "/a", "/b", "/c" }));
}

test "isName: a file's name, no path" {
    try testing.expect(isName("agent-trusted"));
    try testing.expect(!isName(""));
    try testing.expect(!isName("a/b"));
    try testing.expect(!isName(".."));
    try testing.expect(!isName("a" ** 251));
}
