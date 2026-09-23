//! flong-walker: the mount helper's walk (src/mount.zig), driven from a
//! shell in checks.native (ZIG.md, "Tests", checks.native; tests/native.nix
//! runs it as root of a user and mount namespace of alice's). Built only by
//! tests/integration.nix. Every refusal is src/mount.zig's own message,
//! under this program's name; the status is 0, or 1 after a refusal.
//!
//!   flong-walker walk ROOT DEST dir|file|any create|exist
//!       walks DEST from ROOT, as the helper walks a destination from the
//!       session's root, and prints where it ended: "ok PATH"
//!   flong-walker made ROOT NAME
//!       makes the directory ROOT/NAME as the walker would after an ENOENT,
//!       and prints who made it: "session", or "existed" when it was there
//!       already (a concurrent session's make, the EEXIST branch)
//!   flong-walker mask ROOT DEST
//!       walks DEST (which must exist) and attaches a mask of its kind
//!   flong-walker source SRC exact|following PROTECT...
//!       opens SRC as a bind's source is opened and checks it against the
//!       protected paths: "ok PATH", or the refusal
//!   flong-walker race ROOT DEST N VIEW exists|missing
//!       N walks of DEST with create (each of DEST<i> for missing) while a
//!       swapper exchanges a directory on the way with a symlink to VIEW;
//!       prints "refused=R contained=C escaped=E odd=O"
//!   flong-walker naive ROOT DEST N VIEW
//!       the control: N opens of ROOT/DEST by path, following symlinks, as
//!       bwrap resolved a destination; prints the same counts
const std = @import("std");
const linux = std.os.linux;
const sys = @import("sys");
const fd = @import("fd");
const msg = @import("msg");
const mount = @import("mount");

const T = mount.testing_only;

pub const panic = std.debug.FullPanic(msg.onPanic(125));
pub const std_options: std.Options = .{ .enable_segfault_handler = false };

fn usage() noreturn {
    msg.bare("usage: flong-walker walk|made|mask|source|race|naive ...", .{});
    sys.exitGroup(2);
}

fn out(comptime fmt: []const u8, args: anytype) void {
    var buf: [8192]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, fmt ++ "\n", args) catch "flong-walker: line too long\n";
    _ = fd.Stdio.out.writeAll(line);
}

fn where(h: anytype, buf: *[sys.path_max]u8) []const u8 {
    const link = fd.selfPath(h);
    return switch (sys.readlinkat(sys.AT.FDCWD, link.path(), buf)) {
        .ok => |n| buf[0..n],
        .err => "?",
    };
}

fn job() mount.Job {
    return .{
        .u1 = undefined,
        .leader = undefined,
        .ready = undefined,
        .mounts = &.{},
        .uid = 0,
        .gid = 0,
        .home = "/nonexistent",
        .protect = &.{},
    };
}

fn openRoot(path: [*:0]const u8) fd.Fd(.path) {
    return msg.check(fd.openPath(fd.cwd, path, .{ .DIRECTORY = true }), "{s}", .{path}) catch sys.exitGroup(1);
}

const Counts = struct { refused: usize = 0, contained: usize = 0, escaped: usize = 0, odd: usize = 0 };

fn classify(c: *Counts, path: []const u8, root: []const u8, view: []const u8) void {
    if (std.mem.startsWith(u8, path, view)) {
        c.escaped += 1;
    } else if (std.mem.startsWith(u8, path, root) and path.len > root.len and path[root.len] == '/') {
        c.contained += 1;
    } else {
        out("odd: {s}", .{path});
        c.odd += 1;
    }
}

pub fn main() noreturn {
    msg.prog = "flong-walker";
    msg.mode = .cut;
    const argv = sys.argv();
    if (argv.len < 2) usage();
    const cmd = std.mem.span(argv[1]);
    var buf: [sys.path_max]u8 = undefined;
    const j = job();

    if (std.mem.eql(u8, cmd, "walk") and argv.len == 6) {
        const root = openRoot(argv[2]);
        const w = T.walker(&j, root) catch sys.exitGroup(1);
        const want = std.meta.stringToEnum(T.WalkWant, std.mem.span(argv[4])) orelse usage();
        const create = std.mem.eql(u8, std.mem.span(argv[5]), "create");
        const h = T.walkFrom(&w, std.mem.span(argv[3]), want, create) catch sys.exitGroup(1);
        out("ok {s}", .{where(h, &buf)});
        sys.exitGroup(0);
    }
    if (std.mem.eql(u8, cmd, "made") and argv.len == 4) {
        const root = openRoot(argv[2]);
        const w = T.walker(&j, root) catch sys.exitGroup(1);
        const name = std.mem.span(argv[3]);
        const made = T.makeMissingIn(&w, root, name, true, name) catch sys.exitGroup(1);
        out("{s}", .{@tagName(made)});
        sys.exitGroup(0);
    }
    if (std.mem.eql(u8, cmd, "mask") and argv.len == 4) {
        const root = openRoot(argv[2]);
        const w = T.walker(&j, root) catch sys.exitGroup(1);
        const dest = T.walkFrom(&w, std.mem.span(argv[3]), .any, false) catch sys.exitGroup(1);
        const st = msg.check(dest.fstat(), "fstat", .{}) catch sys.exitGroup(1);
        const tree = T.mask(sys.S.ISDIR(st.mode)) catch sys.exitGroup(1);
        _ = msg.check(tree.moveTo(dest), "cannot mount on {s}", .{argv[3]}) catch sys.exitGroup(1);
        out("masked {s}", .{where(dest, &buf)});
        sys.exitGroup(0);
    }
    if (std.mem.eql(u8, cmd, "source") and argv.len >= 4) {
        var protect: [16][:0]const u8 = undefined;
        const n = argv.len - 4;
        if (n > protect.len) usage();
        for (argv[4..], 0..) |p, i| protect[i] = std.mem.span(p);
        var pj = j;
        pj.protect = protect[0..n];
        const exact = std.mem.eql(u8, std.mem.span(argv[3]), "exact");
        const m: mount.Mount = .{ .kind = if (exact) .bind_ro_exact else .bind_ro, .dest = "/unused", .src = std.mem.span(argv[2]) };
        const h = T.openSourceAs(&pj, &m) catch sys.exitGroup(1);
        out("ok {s}", .{where(h, &buf)});
        sys.exitGroup(0);
    }
    if (std.mem.eql(u8, cmd, "race") and argv.len == 7) {
        const root_path = std.mem.span(argv[2]);
        const root = openRoot(argv[2]);
        const w = T.walker(&j, root) catch sys.exitGroup(1);
        const n = std.fmt.parseInt(usize, std.mem.span(argv[4]), 10) catch usage();
        const view = std.mem.span(argv[5]);
        const missing = std.mem.eql(u8, std.mem.span(argv[6]), "missing");
        // Each refusal is said on stderr, which the caller checks holds
        // only "a symlink is on the way" lines.
        var c: Counts = .{};
        for (0..n) |i| {
            var dest_buf: [sys.path_max]u8 = undefined;
            const dest = if (missing)
                std.fmt.bufPrintZ(&dest_buf, "{s}{d}", .{ argv[3], i }) catch usage()
            else
                std.mem.span(argv[3]);
            const h = T.walkFrom(&w, dest, .dir, true) catch {
                c.refused += 1;
                continue;
            };
            classify(&c, where(h, &buf), root_path, view);
            h.close();
        }
        out("refused={d} contained={d} escaped={d} odd={d}", .{ c.refused, c.contained, c.escaped, c.odd });
        sys.exitGroup(0);
    }
    if (std.mem.eql(u8, cmd, "naive") and argv.len == 6) {
        const root_path = std.mem.span(argv[2]);
        const n = std.fmt.parseInt(usize, std.mem.span(argv[4]), 10) catch usage();
        const view = std.mem.span(argv[5]);
        var path_buf: [sys.path_max]u8 = undefined;
        const path = std.fmt.bufPrintZ(&path_buf, "{s}{s}", .{ root_path, argv[3] }) catch usage();
        var c: Counts = .{};
        for (0..n) |_| {
            const r = fd.openPath(fd.cwd, path, .{ .DIRECTORY = true }) catch sys.exitGroup(1);
            switch (r) {
                .ok => |h| {
                    classify(&c, where(h, &buf), root_path, view);
                    h.close();
                },
                .err => c.refused += 1,
            }
        }
        out("refused={d} contained={d} escaped={d} odd={d}", .{ c.refused, c.contained, c.escaped, c.odd });
        sys.exitGroup(0);
    }
    usage();
}
