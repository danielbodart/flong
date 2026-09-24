//! launch/binds.zig: the caller's binds (rootless-wrapper.bash:138-180),
//! for `flong launch DECL.zon`'s prologue (STANDALONE.md, "`flong launch
//! DECL.zon -- ARGS`": the caller's binds), from the binds commands'
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

const std = @import("std");
const msg = @import("msg");
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
};

/// What the lines come to.
pub const Binds = struct {
    /// in the order each path was first named
    list: []const Bind,
    /// the workspace's mode, made rw by a bind of it that says rw
    workspace_mode: Mode,
    /// $binds: "PATH:MODE" per bind, newline-separated, no newline last;
    /// "" when there is none
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
                if (mode == .rw) b.mode = .rw;
                break;
            }
        } else list.append(gpa, .{ .path = p, .mode = mode }) catch return oom();
    }
    return .{ .list = list.items, .workspace_mode = ws_mode, .text = try text(gpa, list.items) };
}

/// $binds (:175-178).
pub fn text(gpa: Allocator, list: []const Bind) msg.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (list, 0..) |b, i| {
        if (i > 0) out.append(gpa, '\n') catch return oom();
        out.print(gpa, "{s}:{s}", .{ b.path, @tagName(b.mode) }) catch return oom();
    }
    return out.items;
}

fn oom() msg.Error {
    return msg.fail(.NOMEM, "malloc", .{});
}

// ---- tests ----

const testing = std.testing;

test "text: PATH:MODE per bind, the mode on every line" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings("", try text(a, &.{}));
    try testing.expectEqualStrings("/a:ro", try text(a, &.{.{ .path = "/a", .mode = .ro }}));
    try testing.expectEqualStrings("/a:ro\n/b c:rw", try text(a, &.{ .{ .path = "/a", .mode = .ro }, .{ .path = "/b c", .mode = .rw } }));
}
