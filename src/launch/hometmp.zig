//! hometmp.zig: whether $home/tmp gets a private tmpfs
//! (rootless-wrapper.bash:362-374), for `flong launch`'s prologue
//! (STANDALONE.md, "flong launch DECL.zon -- ARGS"). Pure: the paths are
//! values.
//!
//! A private tmpfs, unless it would land on the host through a bind, where
//! the host's directory would be covered, or on a declared mount's
//! destination, where the launcher refuses a second mount. When it gets
//! one, TMPDIR is $home/tmp; otherwise /tmp (:373-374).
//!
//! $home/tmp is the payload's home and "/tmp" joined as bash joins them,
//! with no cleaning: a home of / makes //tmp, which no clean destination
//! equals. Each binds test is `[[ $home/tmp == "$p" || $home/tmp == "$p"/*
//! ]]` (:368): $p quoted, so matched as it is, and `*` any string, so
//! $home/tmp is $p or starts with $p and a '/'. Each declared destination
//! is tested for equality alone (:371).

const std = @import("std");

/// Whether $home/tmp is mounted as a private tmpfs: it is not `workspace`,
/// in it, or the same for any of the caller's `binds` (ro or rw) or the
/// declaration's `declared_binds` (their destinations), and it is none of
/// `declared_dests` (:366-372).
pub fn private(
    home: []const u8,
    workspace: []const u8,
    binds: []const []const u8,
    declared_binds: []const []const u8,
    declared_dests: []const []const u8,
) bool {
    if (under(home, workspace)) return false;
    for (binds) |p| if (under(home, p)) return false;
    for (declared_binds) |p| if (under(home, p)) return false;
    for (declared_dests) |p| if (isHomeTmp(p, home)) return false;
    return true;
}

/// `[[ $home/tmp == "$p" || $home/tmp == "$p"/* ]]` (:368).
fn under(home: []const u8, p: []const u8) bool {
    if (isHomeTmp(p, home)) return true;
    // $home/tmp starts with $p/: it is at least one byte longer than $p.
    const len = home.len + "/tmp".len;
    if (len <= p.len or byteAt(home, p.len) != '/') return false;
    for (p, 0..) |c, i| if (byteAt(home, i) != c) return false;
    return true;
}

/// `s` is $home/tmp.
fn isHomeTmp(s: []const u8, home: []const u8) bool {
    return s.len == home.len + "/tmp".len and std.mem.startsWith(u8, s, home) and std.mem.endsWith(u8, s, "/tmp");
}

/// Byte `i` of $home/tmp, below its length.
fn byteAt(home: []const u8, i: usize) u8 {
    return if (i < home.len) home[i] else "/tmp"[i - home.len];
}

// ---- tests ----

const testing = std.testing;

test "under is the wrapper's test, as bash 5.3 answered it" {
    // With home /h: $home/tmp is /h/tmp.
    const rows = [_]struct { p: []const u8, yes: bool }{
        .{ .p = "/h/tmp", .yes = true },
        .{ .p = "/h", .yes = true },
        .{ .p = "", .yes = true }, // "/h/tmp" == ""/*
        .{ .p = "/h/", .yes = false },
        .{ .p = "/h/tmp/", .yes = false },
        .{ .p = "/h/tmpx", .yes = false },
        .{ .p = "/h/t", .yes = false },
        .{ .p = "/h*", .yes = false },
        .{ .p = "/", .yes = false }, // "//*"
        .{ .p = "/hx", .yes = false },
        .{ .p = "/h/tmp/x", .yes = false },
    };
    for (rows) |r| try testing.expectEqual(r.yes, under("/h", r.p));
    // A home of /: //tmp, below "" and "/" only as bash joins it.
    try testing.expect(under("/", "/"));
    try testing.expect(under("/", "//tmp"));
    try testing.expect(!under("/", "/tmp"));
}

test "under agrees with the joined string on any paths" {
    const pieces = [_][]const u8{ "/", "h", "tmp", "t", "mp", "*", "" };
    var prng = std.Random.DefaultPrng.init(0x7e_0b);
    const r = prng.random();
    var hb: [64]u8 = undefined;
    var pb: [64]u8 = undefined;
    var jb: [80]u8 = undefined;
    var yes: usize = 0;
    for (0..50_000) |_| {
        var hn: usize = 0;
        for (0..r.uintAtMost(usize, 4)) |_| {
            const p = pieces[r.uintLessThan(usize, pieces.len)];
            @memcpy(hb[hn..][0..p.len], p);
            hn += p.len;
        }
        var pn: usize = 0;
        for (0..r.uintAtMost(usize, 6)) |_| {
            const p = pieces[r.uintLessThan(usize, pieces.len)];
            @memcpy(pb[pn..][0..p.len], p);
            pn += p.len;
        }
        const joined = try std.fmt.bufPrint(&jb, "{s}/tmp", .{hb[0..hn]});
        const p = pb[0..pn];
        const want = std.mem.eql(u8, joined, p) or
            (joined.len > p.len and std.mem.startsWith(u8, joined, p) and joined[p.len] == '/');
        try testing.expectEqual(want, under(hb[0..hn], p));
        try testing.expectEqual(std.mem.eql(u8, joined, p), isHomeTmp(p, hb[0..hn]));
        if (want) yes += 1;
    }
    try testing.expect(yes >= 1000);
}

test "private: a tmpfs unless a bind or a declared destination has $home/tmp" {
    const none: []const []const u8 = &.{};
    try testing.expect(private("/home/u", "/home/u/src", none, none, none));
    // The workspace, the caller's binds, and the declared binds: $home/tmp
    // itself, or a directory it is in.
    try testing.expect(!private("/home/u", "/home/u", none, none, none));
    try testing.expect(!private("/home/u", "/home/u/tmp", none, none, none));
    try testing.expect(!private("/home/u", "/w", &.{ "/x", "/home" }, none, none));
    try testing.expect(!private("/home/u", "/w", none, &.{"/home/u/tmp"}, none));
    try testing.expect(private("/home/u", "/w", &.{"/home/u/tmp/x"}, &.{"/home/u2"}, none));
    // A declared destination only when it is $home/tmp, not one it is in:
    // the tmpfs goes on top of a declared mount at $home.
    try testing.expect(!private("/home/u", "/w", none, none, &.{ "/nix", "/home/u/tmp" }));
    try testing.expect(private("/home/u", "/w", none, none, &.{"/home/u"}));
    // As bash joins: a home of / is //tmp.
    try testing.expect(private("/", "/w", none, none, &.{"/tmp"}));
    try testing.expect(!private("/", "/w", none, none, &.{"//tmp"}));
}
