//! launch/workspace.zig: the workspace (rootless-wrapper.bash:84-136), for
//! `flong launch DECL.zon`'s prologue (DESIGN.md, "Launch
//! sequence": the workspace), and `resolveDir`, the wrapper's
//! canon, which the caller's binds share (launch/binds.zig).
//!
//! The workspace is the caller's directory, or what the declaration's
//! workspace command prints (cmd.zig, then cmd.substitute, as $(...)
//! left it), with an optional :ro or :rw; rw when it says neither
//! (:121-130). It is resolved before it is checked, so what is checked is
//! what is mounted, and the guard judges the path the launcher is given
//! (:131-135); then refuse.zig's refusals.
//!
//! canon (:86-98) resolved a path by `cd -P` and $PWD, without a fork, and
//! went back to the caller's directory. This resolves it without a chdir
//! and without a fork, by quirk 21's mechanism (prologue.kernelName): an
//! O_PATH|O_DIRECTORY open, following symlinks, and the kernel's name for
//! it, which is what getcwd, and so $PWD after `cd -P`, gives. A relative
//! path is taken from the process's working directory, as cd's chdir takes
//! it, and "" is "./", that directory itself (:94). cd also needs search
//! permission on the directory itself, which an O_PATH open does not:
//! access(X_OK) on the open directory asks it (the real ids, which are the
//! effective ones: flong is not setuid). A path that is none of this is
//! not a directory, whatever the errno, as cd's failure went to /dev/null.
//! CDPATH and `-` need no counterpart: nothing here searches or means
//! $OLDPWD.
//!
//! Each refusal is said through msg under the declaration's name
//! (prologue.exit_refused).

const std = @import("std");
const sys = @import("sys");
const fdt = @import("fd");
const msg = @import("msg");
const prologue = @import("prologue");
const refuse = @import("refuse");

const Allocator = std.mem.Allocator;

/// A workspace's or a bind's mode.
pub const Mode = enum { ro, rw };

/// The workspace, as it will be mounted: $workspace and $workspace_mode
/// (:134-136).
pub const Workspace = struct {
    /// canonical
    path: [:0]const u8,
    mode: Mode,
};

/// A path and the mode its suffix names, if any.
pub const Suffixed = struct {
    path: []const u8,
    mode: ?Mode,
};

/// `*:ro` and `*:rw` (:126-130, 149-153): the text without the suffix,
/// and its mode; the text itself and null when it has neither.
pub fn splitMode(raw: []const u8) Suffixed {
    if (std.mem.endsWith(u8, raw, ":ro")) return .{ .path = raw[0 .. raw.len - 3], .mode = .ro };
    if (std.mem.endsWith(u8, raw, ":rw")) return .{ .path = raw[0 .. raw.len - 3], .mode = .rw };
    return .{ .path = raw, .mode = null };
}

/// canon PATH (:92-98): `path`'s physical path, in `gpa`, or null when it
/// does not name a directory `cd -P` could enter. A full descriptor table
/// is refused.
pub fn resolveDir(gpa: Allocator, path: []const u8) msg.Error!?[:0]const u8 {
    // A NUL cannot be in what bash passed cd; one here names nothing.
    if (std.mem.indexOfScalar(u8, path, 0) != null) return null;
    const at = gpa.dupeZ(u8, if (path.len == 0) "." else path) catch return oom();
    const r = fdt.openPath(fdt.cwd, at, .{ .DIRECTORY = true }) catch
        return msg.refuse("{s}: too many open descriptors", .{path});
    const h = switch (r) {
        .ok => |h| h,
        .err => return null,
    };
    defer h.close();
    const link = fdt.selfPath(h);
    switch (sys.access(link.path(), sys.X_OK)) {
        .ok => {},
        .err => return null,
    }
    var buf: [sys.path_max]u8 = undefined;
    return switch (prologue.kernelName(h, &buf)) {
        .ok => |name| gpa.dupeZ(u8, name) catch return oom(),
        .err => null,
    };
}

/// The caller's directory, as the wrapper took it without a fork
/// (`cwd=$PWD`, :91, 121-122): the kernel's name for it, /proc/self/cwd's
/// link, in `gpa`. $PWD was bash's, the logical path when the caller's
/// PWD named this directory; the physical one is what `canon` made of it,
/// so only a refusal's text can differ.
pub fn current(gpa: Allocator) msg.Error![]const u8 {
    var buf: [sys.path_max]u8 = undefined;
    const n = try msg.check(sys.readlinkat(sys.AT.FDCWD, "/proc/self/cwd", &buf), "readlink /proc/self/cwd", .{});
    if (n >= buf.len) return msg.fail(.NAMETOOLONG, "readlink /proc/self/cwd", .{});
    return gpa.dupe(u8, buf[0..n]) catch return oom();
}

/// The workspace from `raw` (:126-136): the caller's directory
/// (`current`) or a workspace command's output after cmd.substitute. Its
/// suffix split off (rw when none), the rest resolved, then refused as
/// refuse_path refuses it against `declared_dests`. Refusals: "workspace
/// is not a directory: <raw without its suffix>" and refuse.zig's three.
pub fn resolve(gpa: Allocator, raw: []const u8, declared_dests: []const []const u8) msg.Error!Workspace {
    const s = splitMode(raw);
    const path = try resolveDir(gpa, s.path) orelse
        return msg.refuse("workspace is not a directory: {s}", .{s.path});
    if (refuse.refusePath(.workspace, path, declared_dests)) |r| return sayRefusal(gpa, r);
    return .{ .path = path, .mode = s.mode orelse .rw };
}

/// Says refuse_path's refusal `r` (refuse.zig's text) under the prologue's
/// prefix, and returns the failure.
pub fn sayRefusal(gpa: Allocator, r: refuse.Refusal) msg.Error {
    const text = std.fmt.allocPrint(gpa, "{f}", .{r}) catch return oom();
    return msg.refuse("{s}", .{text});
}

fn oom() msg.Error {
    return msg.fail(.NOMEM, "malloc", .{});
}

// ---- tests ----

const testing = std.testing;

test "splitMode: :ro and :rw at the end, nothing else" {
    const cases = [_]struct { given: []const u8, path: []const u8, mode: ?Mode }{
        .{ .given = "/w", .path = "/w", .mode = null },
        .{ .given = "/w:ro", .path = "/w", .mode = .ro },
        .{ .given = "/w:rw", .path = "/w", .mode = .rw },
        .{ .given = "/w:ro:rw", .path = "/w:ro", .mode = .rw },
        .{ .given = "/w:rx", .path = "/w:rx", .mode = null },
        .{ .given = "/w:RO", .path = "/w:RO", .mode = null },
        .{ .given = ":ro", .path = "", .mode = .ro },
        .{ .given = "ro", .path = "ro", .mode = null },
        .{ .given = "/w:ro\n", .path = "/w:ro\n", .mode = null },
        .{ .given = "", .path = "", .mode = null },
    };
    for (cases) |c| {
        const got = splitMode(c.given);
        try testing.expectEqualStrings(c.path, got.path);
        try testing.expectEqual(c.mode, got.mode);
    }
}
