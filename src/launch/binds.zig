//! launch/binds.zig: the caller's binds (rootless-wrapper.bash:138-180),
//! for `flong launch DECL.zon`'s prologue (DESIGN.md, "Launch
//! sequence": the caller's binds), from the binds commands'
//! output (cmd.outputOf).
//!
//! One PATH (read-only), PATH:ro or PATH:rw per line, each resolved and
//! refused as the workspace is (workspace.resolveDir, refuse.zig). A path
//! named twice is bound once, writable if either line says so, where it
//! was first named. A bind of the workspace itself is the workspace,
//! which it makes writable when it says rw, since the launcher refuses a
//! destination twice (:139-172). $binds, what the guard and the payload
//! read, is each bind as PATH:MODE, one per line, the mode on every line
//! so a reader sees what is granted without knowing the default
//! (:173-178).
//!
//! The output is read as the wrapper read `raw=$(...)` through `while IFS=
//! read -r line ... <<<"$raw"`: NULs dropped and the trailing newlines
//! removed (cmd.substitute), then one line per newline, nothing trimmed,
//! a backslash itself, an empty line skipped. A line of ":rw" alone is
//! the empty path, which canon takes as the working directory (:94).
//!
//! Each refusal is said through msg under the declaration's name
//! (prologue.exit_refused): "bind is not a directory: <path without its
//! suffix>", and refuse.zig's three for `bind`.
//!
//! A line PATH:overlay:LAYERS is an overlay the caller keeps: PATH, resolved
//! and refused as a bind's, is its lower and where it is mounted, and
//! LAYERS a directory of the caller's holding its `upper` and `work`,
//! where its writes land and stay (mount.zig, `prepareOverlayKept`). A path
//! has no ':', so the line splits at its first ":overlay:" without
//! ambiguity. LAYERS is taken as it is written, absolute and clean, never
//! resolved: the launcher opens it exactly, and a symlink on the way to it
//! is refused there (prologue.openLayers). $binds shows the line as
//! PATH:overlay, never where its layers are. An overlay is refused when
//! its PATH is the workspace or another line's, when LAYERS is, holds or
//! lies inside its own PATH (overlayfs refuses overlapping layers, as
//! ELOOP), when LAYERS lies at or inside the workspace or another line's
//! PATH, where the payload would write the upper behind overlayfs's back
//! (a declared bind's source is the declaration's, which `protect`
//! keeps such a directory from), and
//! when two overlays' layers meet, which the second's lock would refuse as
//! another container's.

const std = @import("std");
const msg = @import("msg");
const mount = @import("mount");
const refuse = @import("refuse");
const workspace = @import("workspace");
const cmd = @import("cmd");

const Allocator = std.mem.Allocator;
const Mode = workspace.Mode;

/// One of the caller's binds, as it will be mounted: bind_paths[i] and
/// bind_modes[i].
pub const Bind = struct {
    /// canonical
    path: [:0]const u8,
    mode: Mode,
    /// an overlay's LAYERS, absolute and clean; null for a bind, whose
    /// `mode` alone says what it is
    layers: ?[:0]const u8 = null,
};

/// What the lines come to.
pub const Binds = struct {
    /// in the order each path was first named
    list: []const Bind,
    /// the workspace's mode, made rw by a bind of it that says rw
    workspace_mode: Mode,
    /// $binds: "PATH:MODE" per bind, "PATH:overlay" per overlay,
    /// newline-separated, no newline last; "" when there is none
    text: []const u8,
};

/// No binds command (:143-144, 180): no bind, $binds empty, the
/// workspace's mode as it was.
pub fn none(ws: workspace.Workspace) Binds {
    return .{ .list = &.{}, .workspace_mode = ws.mode, .text = "" };
}

/// :145-179 over `raw`, the binds commands' stdout, which it rewrites in
/// place (cmd.substitute), for the workspace `ws` and the declaration's
/// destinations `declared_dests`. Everything is `gpa`'s, an arena's.
pub fn parse(gpa: Allocator, raw: []u8, ws: workspace.Workspace, declared_dests: []const []const u8) msg.Error!Binds {
    var list: std.ArrayList(Bind) = .empty;
    var ws_mode = ws.mode;
    var lines = std.mem.splitScalar(u8, cmd.substitute(raw), '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (splitOverlay(line)) |o| {
            try overlay(gpa, &list, o, ws, declared_dests);
            continue;
        }
        const s = workspace.splitMode(line);
        const mode = s.mode orelse .ro;
        const p = try workspace.resolveDir(gpa, s.path) orelse
            return msg.refuse("bind is not a directory: {s}", .{s.path});
        if (refuse.refusePath(.bind, p, declared_dests)) |r| return workspace.sayRefusal(gpa, r);
        if (std.mem.eql(u8, p, ws.path)) {
            if (mode == .rw) ws_mode = .rw;
            continue;
        }
        for (list.items) |*b| {
            if (std.mem.eql(u8, b.path, p)) {
                if (b.layers != null) return msg.refuse("{s} is named both as a bind and as an overlay", .{p});
                if (mode == .rw) b.mode = .rw;
                break;
            }
        } else list.append(gpa, .{ .path = p, .mode = mode }) catch return oom();
    }
    // Every line is in: whether any overlay's layers lie where the
    // container can reach them, or meet another's.
    for (list.items, 0..) |o, i| {
        const l = o.layers orelse continue;
        if (atOrInside(l, ws.path)) return msg.refuse("overlay {s}: its layers {s} lie in the workspace {s}, which the container can write", .{ o.path, l, ws.path });
        for (list.items, 0..) |b, j| {
            if (i == j) continue;
            if (atOrInside(l, b.path)) return msg.refuse("overlay {s}: its layers {s} lie in {s}, which the container is given", .{ o.path, l, b.path });
            if (b.layers) |bl| if (mount.overlaps(l, bl))
                return msg.refuse("overlay {s}: its layers {s} meet {s}'s, {s}", .{ o.path, l, b.path, bl });
        }
    }
    return .{ .list = list.items, .workspace_mode = ws_mode, .text = try text(gpa, list.items) };
}

/// A line PATH:overlay:LAYERS, split at its first ":overlay:".
pub const Overlay = struct {
    path: []const u8,
    layers: []const u8,
};

const overlay_word = ":overlay:";

/// The line as an overlay's, or null when it has no ":overlay:".
pub fn splitOverlay(line: []const u8) ?Overlay {
    const at = std.mem.indexOf(u8, line, overlay_word) orelse return null;
    return .{ .path = line[0..at], .layers = line[at + overlay_word.len ..] };
}

/// Why LAYERS, as written, cannot be an overlay's: null when it is an
/// absolute path, clean, with no ':' or newline.
pub fn layersBad(layers: []const u8) ?[]const u8 {
    if (std.mem.indexOfAny(u8, layers, ":\n") != null) return "contain ':' or a newline";
    if (layers.len == 0 or layers[0] != '/') return "are not an absolute path";
    if (std.mem.eql(u8, layers, "/")) return "are /";
    var it = std.mem.splitScalar(u8, layers[1..], '/');
    while (it.next()) |c| {
        if (c.len == 0 or std.mem.eql(u8, c, ".") or std.mem.eql(u8, c, ".."))
            return "have an empty, '.' or '..' component";
    }
    return null;
}

/// `a` is `b` or lies inside it, by whole components; both canonical.
fn atOrInside(a: []const u8, b: []const u8) bool {
    if (std.mem.eql(u8, b, "/")) return true;
    return std.mem.startsWith(u8, a, b) and (a.len == b.len or a[b.len] == '/');
}

/// One overlay's line, into `list`: its PATH resolved and refused as a
/// bind's, its LAYERS judged as written. The same line twice is one
/// overlay; the same PATH with other layers, or as a bind too, is refused.
fn overlay(gpa: Allocator, list: *std.ArrayList(Bind), o: Overlay, ws: workspace.Workspace, declared_dests: []const []const u8) msg.Error!void {
    const p = try workspace.resolveDir(gpa, o.path) orelse
        return msg.refuse("overlay is not a directory: {s}", .{o.path});
    if (refuse.refusePath(.bind, p, declared_dests)) |r| return workspace.sayRefusal(gpa, r);
    if (layersBad(o.layers)) |why| return msg.refuse("overlay {s}: its layers {s}: {s}", .{ p, why, o.layers });
    if (std.mem.eql(u8, p, ws.path)) return msg.refuse("overlay {s} is the workspace, which is bound", .{p});
    if (mount.overlaps(o.layers, p)) return msg.refuse("overlay {s}: LAYERS lies inside PATH: its layers {s} are, hold or lie inside it", .{ p, o.layers });
    for (list.items) |b| {
        if (!std.mem.eql(u8, b.path, p)) continue;
        const l = b.layers orelse return msg.refuse("{s} is named both as a bind and as an overlay", .{p});
        if (std.mem.eql(u8, l, o.layers)) return;
        return msg.refuse("overlay {s} is named twice, with layers {s} and {s}", .{ p, l, o.layers });
    }
    list.append(gpa, .{ .path = p, .mode = .rw, .layers = gpa.dupeZ(u8, o.layers) catch return oom() }) catch return oom();
}

/// $binds (:175-178): an overlay as PATH:overlay, its layers left out.
pub fn text(gpa: Allocator, list: []const Bind) msg.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (list, 0..) |b, i| {
        if (i > 0) out.append(gpa, '\n') catch return oom();
        const mode = if (b.layers != null) "overlay" else @tagName(b.mode);
        out.print(gpa, "{s}:{s}", .{ b.path, mode }) catch return oom();
    }
    return out.items;
}

fn oom() msg.Error {
    return msg.fail(.NOMEM, "malloc", .{});
}

// ---- tests ----

const testing = std.testing;

test "splitOverlay: at the first :overlay:, nothing else" {
    try testing.expectEqual(@as(?Overlay, null), splitOverlay("/a:rw"));
    try testing.expectEqual(@as(?Overlay, null), splitOverlay("/a:overlay"));
    const o = splitOverlay("/nix/store:overlay:/home/u/l").?;
    try testing.expectEqualStrings("/nix/store", o.path);
    try testing.expectEqualStrings("/home/u/l", o.layers);
    const twice = splitOverlay("/a:overlay:/b:overlay:/c").?;
    try testing.expectEqualStrings("/a", twice.path);
    try testing.expectEqualStrings("/b:overlay:/c", twice.layers);
    const empty = splitOverlay(":overlay:").?;
    try testing.expectEqualStrings("", empty.path);
    try testing.expectEqualStrings("", empty.layers);
}

test "layersBad: absolute, clean, no separator" {
    try testing.expectEqual(@as(?[]const u8, null), layersBad("/home/u/.cache/l"));
    try testing.expectEqual(@as(?[]const u8, null), layersBad("/l"));
    for ([_][]const u8{ "", "l", "./l", "/", "/a//b", "/a/./b", "/a/../b", "/a/", "/a:b", "/a\nb", "/b:overlay:/c" }) |l|
        try testing.expect(layersBad(l) != null);
}

test "atOrInside: by whole components" {
    try testing.expect(atOrInside("/a", "/a"));
    try testing.expect(atOrInside("/a/b", "/a"));
    try testing.expect(atOrInside("/a", "/"));
    try testing.expect(!atOrInside("/ab", "/a"));
    try testing.expect(!atOrInside("/a", "/a/b"));
}

test "text: PATH:MODE per bind, the mode on every line" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings("", try text(a, &.{}));
    try testing.expectEqualStrings("/a:ro", try text(a, &.{.{ .path = "/a", .mode = .ro }}));
    try testing.expectEqualStrings("/a:ro\n/b c:rw", try text(a, &.{ .{ .path = "/a", .mode = .ro }, .{ .path = "/b c", .mode = .rw } }));
    // An overlay is PATH:overlay, its layers nowhere.
    try testing.expectEqualStrings("/a:ro\n/nix/store:overlay", try text(a, &.{ .{ .path = "/a", .mode = .ro }, .{ .path = "/nix/store", .mode = .rw, .layers = "/l" } }));
}
