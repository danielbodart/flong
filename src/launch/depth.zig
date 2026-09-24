//! depth.zig: the depth rule for the workspace and the caller's writable
//! binds (rootless-wrapper.bash:210-232), for `flong launch`'s prologue
//! (DESIGN.md, "Launch sequence"). Pure: the roots and
//! the masks are values, and the answer is the first mask refused, for
//! the caller to print as `refusal` says.
//!
//! A mask two or more levels below the root of a writable bind can be
//! moved from under it: a session renames the masked name's parent and
//! leaves a decoy in its place, so the mask covers the decoy and the real
//! file is readable at the new name. The declaration's own binds were
//! checked at evaluation; the workspace and the caller's binds exist only
//! at launch. A mask is checked by its own path, where the workspace and
//! caller binds land, and by its host path through the declared bind it
//! lies in (the header's mask_hosts, module.nix's maskHost).
//!
//! The wrapper's test is `[[ -n $h && $h == "$root"/*/* ]]` (:227): the
//! root quoted, so matched as it is, and each `*` any string, '/' and the
//! empty string included, since `[[ == ]]` matches a pattern and expands
//! no path. So a path is below a root when it starts with the root and a
//! '/', and a '/' follows somewhere after that: /w/a/ and /w// are two
//! levels below /w, /w/a and /w/ are not.

const std = @import("std");

/// A place a session can write that a mask may lie below: the workspace or
/// one of the caller's binds, canonical, as they will be mounted.
pub const Root = struct {
    path: []const u8,
    /// its mode: rw, or ro, which no rule applies to (:224)
    rw: bool,
};

/// A declared mask: the path it hides in the session, and the host path
/// it hides through the declared bind it lies in, null when it lies in
/// none (the header's "" in mask_hosts).
pub const Mask = struct {
    path: []const u8,
    host: ?[]const u8,
};

/// A mask the rule refuses: the mask, the path of it found below the root
/// (its own or its host's), and the root.
pub const Hidden = struct {
    mask: []const u8,
    hidden: []const u8,
    root: []const u8,
};

/// The wrapper's refusal (:228), for `Hidden`'s mask, hidden and root in
/// that order. The prologue prints it after the declaration's name.
pub const refusal = "the mask {s} hides {s}, two or more levels below the writable bind {s}, where a session could rename its parent from under it";

/// The first mask two or more levels below a writable root, in the
/// wrapper's order (:218-226): the caller's binds in their order and then
/// the workspace, each writable one against every mask in order, each
/// mask by its own path and then its host path. Null when there is none.
pub fn check(workspace: Root, binds: []const Root, masks: []const Mask) ?Hidden {
    for (binds) |b| if (against(b, masks)) |h| return h;
    return against(workspace, masks);
}

/// `root` against every mask, when it is writable.
fn against(root: Root, masks: []const Mask) ?Hidden {
    if (!root.rw) return null;
    for (masks) |m| {
        for ([_]?[]const u8{ m.path, m.host }) |path| {
            const h = path orelse continue;
            if (below(h, root.path)) return .{ .mask = m.path, .hidden = h, .root = root.path };
        }
    }
    return null;
}

/// `[[ -n $h && $h == "$root"/*/* ]]` (:227): `h` is `root`, a '/', then
/// anything holding a '/'. An empty `h` is no path.
fn below(h: []const u8, root: []const u8) bool {
    if (h.len == 0) return false;
    if (!std.mem.startsWith(u8, h, root)) return false;
    const rest = h[root.len..];
    if (rest.len == 0 or rest[0] != '/') return false;
    return std.mem.indexOfScalar(u8, rest[1..], '/') != null;
}

// ---- tests ----

const testing = std.testing;

test "below is the wrapper's $root/*/*, as bash 5.3 matched it" {
    // Each row as `[[ $h == "$root"/*/* ]]` answered it.
    const rows = [_]struct { h: []const u8, root: []const u8, yes: bool }{
        .{ .h = "/w/a/b", .root = "/w", .yes = true },
        .{ .h = "/w/a/", .root = "/w", .yes = true },
        .{ .h = "/w//", .root = "/w", .yes = true },
        .{ .h = "/w/*/x", .root = "/w", .yes = true },
        .{ .h = "/w/.a/b", .root = "/w", .yes = true },
        .{ .h = "/w/a/b/c/d", .root = "/w", .yes = true },
        .{ .h = "/w/a", .root = "/w", .yes = false },
        .{ .h = "/w/", .root = "/w", .yes = false },
        .{ .h = "/w", .root = "/w", .yes = false },
        .{ .h = "/wa/b/c", .root = "/w", .yes = false },
        .{ .h = "", .root = "/w", .yes = false },
        // The root is quoted: its own '*' is a '*'.
        .{ .h = "/w*/a/b", .root = "/w*", .yes = true },
        .{ .h = "/wx/a/b", .root = "/w*", .yes = false },
        .{ .h = "/w/a/b", .root = "/w*", .yes = false },
    };
    for (rows) |r| try testing.expectEqual(r.yes, below(r.h, r.root));
}

/// `[[ $h == "$root"/*/* ]]` by backtracking over the pattern, the way a
/// glob matches: literals, and `*` for any string.
fn globbed(h: []const u8, root: []const u8) bool {
    const Piece = union(enum) { lit: []const u8, star };
    const pattern = [_]Piece{ .{ .lit = root }, .{ .lit = "/" }, .star, .{ .lit = "/" }, .star };
    const S = struct {
        fn match(s: []const u8, p: []const Piece) bool {
            if (p.len == 0) return s.len == 0;
            switch (p[0]) {
                .lit => |l| return std.mem.startsWith(u8, s, l) and match(s[l.len..], p[1..]),
                .star => {
                    for (0..s.len + 1) |i| if (match(s[i..], p[1..])) return true;
                    return false;
                },
            }
        }
    };
    return h.len > 0 and S.match(h, &pattern);
}

test "below agrees with a glob matcher on any path" {
    const pieces = [_][]const u8{ "/", "//", "w", "a", "*", ".", "..", "wa", "" };
    var prng = std.Random.DefaultPrng.init(0xde_97);
    const r = prng.random();
    var hb: [64]u8 = undefined;
    var rb: [64]u8 = undefined;
    var yes: usize = 0;
    for (0..50_000) |_| {
        var hn: usize = 0;
        for (0..r.uintAtMost(usize, 7)) |_| {
            const p = pieces[r.uintLessThan(usize, pieces.len)];
            @memcpy(hb[hn..][0..p.len], p);
            hn += p.len;
        }
        var rn: usize = 0;
        for (0..r.uintAtMost(usize, 3)) |_| {
            const p = pieces[r.uintLessThan(usize, pieces.len)];
            @memcpy(rb[rn..][0..p.len], p);
            rn += p.len;
        }
        const want = globbed(hb[0..hn], rb[0..rn]);
        try testing.expectEqual(want, below(hb[0..hn], rb[0..rn]));
        if (want) yes += 1;
    }
    try testing.expect(yes >= 1000);
}

test "check refuses a mask, or its host path, two levels below a writable root" {
    const masks = [_]Mask{
        .{ .path = "/home/u/.ssh", .host = "/srv/home/u/.ssh" },
        .{ .path = "/etc/secret", .host = null },
    };
    const ws: Root = .{ .path = "/home", .rw = true };
    try testing.expectEqualDeep(@as(?Hidden, .{ .mask = "/home/u/.ssh", .hidden = "/home/u/.ssh", .root = "/home" }), check(ws, &.{}, &masks));
    // One level below is not refused.
    try testing.expectEqual(@as(?Hidden, null), check(.{ .path = "/home/u", .rw = true }, &.{}, &masks));
    // Read-only, nothing is renamed.
    try testing.expectEqual(@as(?Hidden, null), check(.{ .path = "/home", .rw = false }, &.{}, &masks));
    // By the host path, through the declared bind.
    try testing.expectEqualDeep(
        @as(?Hidden, .{ .mask = "/home/u/.ssh", .hidden = "/srv/home/u/.ssh", .root = "/srv" }),
        check(.{ .path = "/tmp/w", .rw = true }, &.{.{ .path = "/srv", .rw = true }}, &masks),
    );
    try testing.expectEqual(@as(?Hidden, null), check(.{ .path = "/tmp/w", .rw = true }, &.{.{ .path = "/srv", .rw = false }}, &masks));
    // The mask's own path before its host path.
    const both = [_]Mask{.{ .path = "/x/a/b", .host = "/x/c/d" }};
    try testing.expectEqualStrings("/x/a/b", check(.{ .path = "/x", .rw = true }, &.{}, &both).?.hidden);
    // An empty path is none, a host or not.
    const empty = [_]Mask{ .{ .path = "", .host = "" }, .{ .path = "/y/z", .host = "" } };
    try testing.expectEqual(@as(?Hidden, null), check(.{ .path = "/y", .rw = true }, &.{}, &empty));
    try testing.expectEqual(@as(?Hidden, null), check(ws, &.{}, &.{}));
}

test "check goes through the caller's binds in order, then the workspace" {
    const masks = [_]Mask{
        .{ .path = "/a/b/c", .host = null },
        .{ .path = "/w/x/y", .host = "/b/p/q" },
    };
    const ws: Root = .{ .path = "/w", .rw = true };
    const binds = [_]Root{ .{ .path = "/b", .rw = true }, .{ .path = "/a", .rw = true } };
    // The first bind, by the second mask's host, before the second bind's
    // first mask and the workspace.
    try testing.expectEqualDeep(@as(?Hidden, .{ .mask = "/w/x/y", .hidden = "/b/p/q", .root = "/b" }), check(ws, &binds, &masks));
    try testing.expectEqualDeep(@as(?Hidden, .{ .mask = "/a/b/c", .hidden = "/a/b/c", .root = "/a" }), check(ws, binds[1..], &masks));
    try testing.expectEqualDeep(@as(?Hidden, .{ .mask = "/w/x/y", .hidden = "/w/x/y", .root = "/w" }), check(ws, &.{}, &masks));
    // Within a root, the masks in order.
    const two = [_]Mask{ .{ .path = "/r/2/2", .host = null }, .{ .path = "/r/1/1", .host = null } };
    try testing.expectEqualStrings("/r/2/2", check(.{ .path = "/r", .rw = true }, &.{}, &two).?.mask);
}

test "refusal is the wrapper's text" {
    var buf: [256]u8 = undefined;
    const h: Hidden = .{ .mask = "/home/u/.ssh", .hidden = "/srv/u/.ssh", .root = "/srv" };
    try testing.expectEqualStrings(
        "the mask /home/u/.ssh hides /srv/u/.ssh, two or more levels below the writable bind /srv, where a session could rename its parent from under it",
        try std.fmt.bufPrint(&buf, refusal, .{ h.mask, h.hidden, h.root }),
    );
}
