//! launch/refuse.zig: refuse_path (rootless-wrapper.bash:100-116), what a
//! workspace or a caller's bind cannot be, for `flong launch` (STANDALONE.md,
//! "`flong launch DECL.zon -- ARGS`": the workspace and the caller's binds).
//!
//! Three refusals, tested in the wrapper's order: a ':' or a newline, which
//! would make $binds and FLONG_BINDS ambiguous to anything that splits them,
//! a guard included; / itself, the whole host; and a destination the
//! declaration mounts already, where the launcher would refuse the second
//! mount as a spec error. The path is the resolved one, as the wrapper
//! refuses it after `canon` (:133-135, 154-156), so what is refused is what
//! would be mounted.
//!
//! Pure: the answer is a value, and the caller prints it. Its text is the
//! wrapper's, byte for byte, without the "$name: " that die (:41-44) puts
//! in front and the exit status 1 it leaves with (STANDALONE.md: asserted
//! strings and exit codes stay).

const std = @import("std");

/// refuse_path's first argument: the only two words the wrapper passes it
/// (:135, 156).
pub const What = enum { workspace, bind };

/// Which of refuse_path's three dies (:108, 109, 113).
pub const Reason = enum {
    /// `*:* | *"$nl"*` (:108).
    separator,
    /// `/` (:109).
    root,
    /// `[[ $2 == "$d" ]]` for a d of declared_dests (:111-115).
    declared,
};

/// A refusal: what was refused, its path and why.
pub const Refusal = struct {
    what: What,
    path: []const u8,
    reason: Reason,

    /// The wrapper's message (:108, 109, 113), for `{f}`.
    pub fn format(r: Refusal, w: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (r.reason) {
            .separator => try w.print("{s} contains ':' or a newline: {s}", .{ @tagName(r.what), r.path }),
            .root => try w.print("{s} resolves to /", .{@tagName(r.what)}),
            .declared => try w.print("{s} {s} is where the declaration already mounts something", .{ @tagName(r.what), r.path }),
        }
    }
};

/// refuse_path WHAT PATH (:105-116): the refusal of `path`, a resolved
/// workspace or bind, or null when the session can be given it.
/// `declared_dests` is the declaration's destinations, in order; each is
/// compared whole, as `==` with a quoted right side compares (:112).
pub fn refusePath(what: What, path: []const u8, declared_dests: []const []const u8) ?Refusal {
    // The case comes first and its first pattern wins: a path with a ':' is
    // refused for it whatever else it is, and "/" as the root even where the
    // declaration names it (:107-110).
    const reason: ?Reason = if (std.mem.indexOfAny(u8, path, ":\n") != null)
        .separator
    else if (std.mem.eql(u8, path, "/"))
        .root
    else for (declared_dests) |d| {
        if (std.mem.eql(u8, path, d)) break .declared;
    } else null;
    return .{ .what = what, .path = path, .reason = reason orelse return null };
}

// ---- tests ----

const testing = std.testing;

fn expectMessage(expected: []const u8, r: ?Refusal) !void {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.print("{f}", .{r.?});
    try testing.expectEqualStrings(expected, w.buffered());
}

test "refusePath: the wrapper's three refusals and their text" {
    const dests = [_][]const u8{ "/nix/store", "/home/me/.ssh", "/run/x" };
    try expectMessage("workspace contains ':' or a newline: /srv/a:b", refusePath(.workspace, "/srv/a:b", &dests));
    try expectMessage("bind contains ':' or a newline: /srv/a\nb", refusePath(.bind, "/srv/a\nb", &dests));
    try expectMessage("workspace resolves to /", refusePath(.workspace, "/", &dests));
    try expectMessage("bind resolves to /", refusePath(.bind, "/", &dests));
    try expectMessage("bind /home/me/.ssh is where the declaration already mounts something", refusePath(.bind, "/home/me/.ssh", &dests));
    try expectMessage("workspace /run/x is where the declaration already mounts something", refusePath(.workspace, "/run/x", &dests));
}

test "refusePath: what passes" {
    const dests = [_][]const u8{ "/nix/store", "/home/me/.ssh" };
    const ok = [_][]const u8{
        "/home/me",
        "/home/me/project",
        // Only a destination itself is refused, not what is above or below
        // it: the wrapper compares whole strings (:112).
        "/home/me/.ssh/keys",
        "/nix",
        "/nix/store/",
        // Only "/" is the root: the wrapper's case pattern is the one word.
        "//",
        "/.",
        // Blanks, a '\r', and a NUL are none of the separators.
        "/srv/a b",
        "/srv/a\tb",
        "/srv/a\rb",
        "/srv/a\x00b",
        "",
    };
    for (ok) |p| try testing.expectEqual(@as(?Refusal, null), refusePath(.bind, p, &dests));
    try testing.expectEqual(@as(?Refusal, null), refusePath(.workspace, "/nix/store", &.{}));
}

test "refusePath: the case's order, then the destinations" {
    // A ':' is refused as one even where the path is also a destination,
    // and "/" as the root even where the declaration names it.
    const dests = [_][]const u8{ "/a:b", "/" };
    try testing.expectEqual(Reason.separator, refusePath(.bind, "/a:b", &dests).?.reason);
    try testing.expectEqual(Reason.root, refusePath(.bind, "/", &dests).?.reason);
    // The ':' or newline anywhere, at either end too.
    for ([_][]const u8{ ":", "\n", ":/x", "/x:", "\n/x", "/x\n", "/x:ro" }) |p|
        try testing.expectEqual(Reason.separator, refusePath(.workspace, p, &.{}).?.reason);
    // A path the refusal carries is the one given.
    const r = refusePath(.bind, "/srv/x:y", &.{}).?;
    try testing.expectEqual(What.bind, r.what);
    try testing.expectEqualStrings("/srv/x:y", r.path);
}

test "refusePath: a long path is quoted whole" {
    var long: [200]u8 = undefined;
    @memset(&long, 'a');
    long[0] = '/';
    long[100] = ':';
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.print("{f}", .{refusePath(.bind, &long, &.{}).?});
    try testing.expectEqualStrings("bind contains ':' or a newline: ", w.buffered()[0 .. w.buffered().len - long.len]);
    try testing.expectEqualStrings(&long, w.buffered()[w.buffered().len - long.len ..]);
}
