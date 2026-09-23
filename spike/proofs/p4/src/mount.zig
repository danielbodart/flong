//! p4-mount DIR: P4's round trip of the mount calls (ZIG.md, "Phase 0:
//! proofs"), through the structs of src/abi.zig. Run as root of a user and
//! mount namespace of its own (`unshare -Urm`, tests: default.nix), in DIR,
//! an absolute path it may write. It makes DIR/a (a new tmpfs) and DIR/b (a
//! clone of it), and checks each call's result on the kernel, with a control
//! beside each refusal. Prints `p4: ok: ...` per check and `p4: all ok`;
//! exits 1 naming the first check that failed.
const std = @import("std");
const linux = std.os.linux;
const abi = @import("abi");

const E = linux.E;
const AT_FDCWD = linux.AT.FDCWD;
const AT_EMPTY_PATH = linux.AT.EMPTY_PATH;

fn write(fd: i32, comptime fmt: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, fmt, args) catch buf[0..];
    _ = linux.write(fd, s.ptr, s.len);
}

fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    write(2, "p4: FAIL: " ++ fmt ++ "\n", args);
    linux.exit_group(1);
}

fn ok(comptime fmt: []const u8, args: anytype) void {
    write(1, "p4: ok: " ++ fmt ++ "\n", args);
}

/// The result of a call that must succeed.
fn must(rc: usize, what: []const u8) usize {
    const e = E.init(rc);
    if (e != .SUCCESS) fail("{s}: {s}", .{ what, @tagName(e) });
    return rc;
}

fn mustFd(rc: usize, what: []const u8) i32 {
    return @intCast(must(rc, what));
}

/// A call that must fail with one of `want`; a descriptor it returns anyway
/// is closed.
fn refused(rc: usize, want: []const E, what: []const u8) E {
    const e = E.init(rc);
    if (e == .SUCCESS) fail("{s}: succeeded, want {s}", .{ what, @tagName(want[0]) });
    for (want) |w| if (e == w) {
        ok("{s}: refused, {s}", .{ what, @tagName(e) });
        return e;
    };
    fail("{s}: {s}, want {s}", .{ what, @tagName(e), @tagName(want[0]) });
}

fn oflags(o: linux.O) u64 {
    return @as(u32, @bitCast(o));
}

const o_path_dir: linux.O = .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true };

/// The unique mount id (statx's stx_mnt_id at 0x90, under
/// STATX_MNT_ID_UNIQUE) of what `path` names under `dfd`.
fn mntIdUnique(dfd: i32, path: [*:0]const u8, flags: u32, what: []const u8) u64 {
    var stx: linux.Statx = undefined;
    _ = must(linux.statx(dfd, path, flags, abi.STATX_MNT_ID_UNIQUE, &stx), what);
    return abi.statxMntIdUnique(&stx) orelse fail("{s}: STATX_MNT_ID_UNIQUE not in the mask 0x{x}", .{ what, stx.mask });
}

/// The reused id, STATX_MNT_ID's, at the same 0x90.
fn mntIdOld(dfd: i32, path: [*:0]const u8, what: []const u8) u64 {
    var stx: linux.Statx = undefined;
    _ = must(linux.statx(dfd, path, 0, abi.STATX_MNT_ID, &stx), what);
    if (stx.mask & abi.STATX_MNT_ID == 0) fail("{s}: STATX_MNT_ID not in the mask", .{what});
    return stx.__pad2[0];
}

var sm_buf: [4096]u8 align(8) = undefined;

/// statmount of the mount whose unique id is `id`, VER0 request.
fn statmount(id: u64, mask: u64, what: []const u8) *const abi.statmount {
    const req: abi.mnt_id_req = .{ .size = abi.MNT_ID_REQ_SIZE_VER0, .spare = 0, .mnt_id = id, .param = mask };
    _ = must(abi.statmountCall(&req, &sm_buf, 0), what);
    const sm: *const abi.statmount = @ptrCast(&sm_buf);
    if (sm.mask & mask != mask) fail("{s}: mask 0x{x}, asked 0x{x}", .{ what, sm.mask, mask });
    if (sm.mnt_id != id) fail("{s}: mnt_id {d}, asked {d}", .{ what, sm.mnt_id, id });
    return sm;
}

fn smString(sm: *const abi.statmount, off: u32, what: []const u8) []const u8 {
    _ = sm;
    return abi.statmount.string(&sm_buf, off) orelse fail("{s}: string at {d} outside the buffer", .{ what, off });
}

fn expectEq(comptime T: type, got: T, want: T, what: []const u8) void {
    if (got != want) fail("{s}: {any}, want {any}", .{ what, got, want });
}

fn expectStr(got: []const u8, want: []const u8, what: []const u8) void {
    if (!std.mem.eql(u8, got, want)) fail("{s}: \"{s}\", want \"{s}\"", .{ what, got, want });
}

pub fn main() void {
    if (std.os.argv.len != 2) fail("usage: p4-mount DIR", .{});
    const dir: [*:0]const u8 = std.os.argv[1];
    const dir_s = std.mem.span(dir);
    if (dir_s.len == 0 or dir_s[0] != '/') fail("DIR must be absolute", .{});
    const dfd = mustFd(linux.openat(AT_FDCWD, dir, o_path_dir, 0), "open DIR");
    const parent_id = mntIdUnique(dfd, "", AT_EMPTY_PATH, "statx DIR");
    var path_buf: [4096]u8 = undefined;

    // ---- fsopen, fsconfig, fsmount: a detached tmpfs ----
    const fs = mustFd(abi.fsopen("tmpfs", abi.FSOPEN_CLOEXEC), "fsopen tmpfs");
    _ = must(abi.fsconfig(fs, abi.FSCONFIG_SET_STRING, "mode", "0755", 0), "fsconfig mode");
    _ = must(abi.fsconfig(fs, abi.FSCONFIG_SET_STRING, "size", "1m", 0), "fsconfig size");
    _ = refused(abi.fsconfig(fs, abi.FSCONFIG_SET_STRING, "p4-no-such-option", "x", 0), &.{.INVAL}, "fsconfig of an unknown key");
    _ = must(abi.fsconfig(fs, abi.FSCONFIG_CMD_CREATE, null, null, 0), "fsconfig create");
    const mfd = mustFd(abi.fsmount(fs, abi.FSMOUNT_CLOEXEC, 0), "fsmount");
    ok("fsopen tmpfs, fsconfig mode size create, fsmount: fd {d}", .{mfd});

    // Its tree, made through the detached mount's descriptor: a file, a
    // relative symlink within it, and three that lead out of it.
    _ = must(linux.mkdirat(mfd, "sub", 0o755), "mkdir sub");
    _ = linux.close(mustFd(linux.openat(mfd, "sub/f", .{ .ACCMODE = .WRONLY, .CREAT = true, .CLOEXEC = true }, 0o644), "create sub/f"));
    _ = must(linux.symlinkat("sub", mfd, "link"), "symlink link -> sub");
    _ = must(linux.symlinkat("/", mfd, "abs"), "symlink abs -> /");
    _ = must(linux.symlinkat("..", mfd, "up"), "symlink up -> ..");
    const detached_id = mntIdUnique(mfd, "", AT_EMPTY_PATH, "statx the detached mount");
    if (detached_id == parent_id) fail("the detached mount has DIR's id {d}", .{parent_id});

    // ---- move_mount: attach it at DIR/a ----
    _ = must(linux.mkdirat(dfd, "a", 0o755), "mkdir a");
    _ = must(abi.move_mount(mfd, "", dfd, "a", abi.MOVE_MOUNT_F_EMPTY_PATH), "move_mount to a");
    const a_id = mntIdUnique(dfd, "a", 0, "statx a");
    expectEq(u64, a_id, detached_id, "a's unique mount id is the fsmount's");
    ok("move_mount: DIR/a is mount {d} (DIR's is {d})", .{ a_id, parent_id });

    // ---- statmount by the unique id, the VER0 request ----
    const want = abi.STATMOUNT_SB_BASIC | abi.STATMOUNT_MNT_BASIC | abi.STATMOUNT_FS_TYPE | abi.STATMOUNT_MNT_POINT;
    {
        const sm = statmount(a_id, want, "statmount a");
        expectEq(u64, sm.sb_magic, abi.TMPFS_MAGIC, "statmount a: sb_magic");
        expectStr(smString(sm, sm.fs_type, "fs_type"), "tmpfs", "statmount a: fs_type");
        const a_path = std.fmt.bufPrint(&path_buf, "{s}/a", .{dir_s}) catch unreachable;
        expectStr(smString(sm, sm.mnt_point, "mnt_point"), a_path, "statmount a: mnt_point");
        expectEq(u64, sm.mnt_parent_id, parent_id, "statmount a: mnt_parent_id, DIR's statx id");
        expectEq(u64, sm.mnt_id_old, mntIdOld(dfd, "a", "statx a, STATX_MNT_ID"), "statmount a: mnt_id_old, statx's STATX_MNT_ID");
        expectEq(u64, sm.mnt_attr & abi.MOUNT_ATTR_RDONLY, 0, "statmount a: not read-only yet");
        ok("statmount {d}: tmpfs, sb_magic 0x{x}, at {s}, parent {d}, old id {d}", .{ a_id, sm.sb_magic, a_path, sm.mnt_parent_id, sm.mnt_id_old });
    }
    _ = refused(abi.statmountCall(&.{ .size = abi.MNT_ID_REQ_SIZE_VER0, .spare = 0, .mnt_id = a_id + (1 << 40), .param = want }, &sm_buf, 0), &.{.NOENT}, "statmount of an id no mount has");

    // ---- mount_setattr: a read-only ----
    _ = must(abi.mount_setattr(dfd, "a", 0, &.{ .attr_set = abi.MOUNT_ATTR_RDONLY, .attr_clr = 0, .propagation = 0, .userns_fd = 0 }), "mount_setattr a rdonly");
    if (statmount(a_id, want, "statmount a, read-only").mnt_attr & abi.MOUNT_ATTR_RDONLY == 0) fail("statmount a: MOUNT_ATTR_RDONLY not set", .{});
    _ = refused(linux.mkdirat(dfd, "a/x", 0o755), &.{.ROFS}, "mkdir in a, read-only");
    ok("mount_setattr MOUNT_ATTR_RDONLY: statmount reports it", .{});

    // ---- open_tree(OPEN_TREE_CLONE) of a, attached at DIR/b ----
    const tfd = mustFd(abi.open_tree(dfd, "a", abi.OPEN_TREE_CLONE | abi.OPEN_TREE_CLOEXEC), "open_tree a clone");
    const clone_id = mntIdUnique(tfd, "", AT_EMPTY_PATH, "statx the clone");
    if (clone_id == a_id) fail("the clone has a's id {d}", .{a_id});
    _ = must(linux.mkdirat(dfd, "b", 0o755), "mkdir b");
    _ = must(abi.move_mount(tfd, "", dfd, "b", abi.MOVE_MOUNT_F_EMPTY_PATH), "move_mount the clone to b");
    const b_id = mntIdUnique(dfd, "b", 0, "statx b");
    expectEq(u64, b_id, clone_id, "b's unique mount id is the clone's");
    {
        const sm = statmount(b_id, want, "statmount b");
        expectEq(u64, sm.sb_magic, abi.TMPFS_MAGIC, "statmount b: sb_magic");
        if (sm.mnt_attr & abi.MOUNT_ATTR_RDONLY == 0) fail("statmount b: the clone lost MOUNT_ATTR_RDONLY", .{});
        const b_path = std.fmt.bufPrint(&path_buf, "{s}/b", .{dir_s}) catch unreachable;
        expectStr(smString(sm, sm.mnt_point, "mnt_point"), b_path, "statmount b: mnt_point");
    }
    var sa: linux.Statx = undefined;
    var sb: linux.Statx = undefined;
    _ = must(linux.statx(dfd, "a/sub/f", 0, linux.STATX_INO, &sa), "statx a/sub/f");
    _ = must(linux.statx(dfd, "b/sub/f", 0, linux.STATX_INO, &sb), "statx b/sub/f");
    expectEq(u64, sb.ino, sa.ino, "b/sub/f is a/sub/f");
    // Writable again on b alone: the superblock is shared, the flag is not.
    _ = must(abi.mount_setattr(dfd, "b", 0, &.{ .attr_set = 0, .attr_clr = abi.MOUNT_ATTR_RDONLY, .propagation = 0, .userns_fd = 0 }), "mount_setattr b clear rdonly");
    _ = must(linux.mkdirat(dfd, "b/x", 0o755), "mkdir b/x");
    _ = must(linux.statx(dfd, "a/x", 0, linux.STATX_INO, &sa), "statx a/x, made through b");
    _ = refused(linux.mkdirat(dfd, "a/y", 0o755), &.{.ROFS}, "mkdir in a, still read-only");
    ok("open_tree OPEN_TREE_CLONE, move_mount: DIR/b is mount {d}, the same tmpfs, read-only until cleared on b alone", .{b_id});

    // ---- openat2 under a ----
    const root = mustFd(linux.openat(dfd, "a", o_path_dir, 0), "open a");
    const rd: linux.O = .{ .CLOEXEC = true };
    const Case = struct { path: [*:0]const u8, resolve: u64, want: ?[]const E };
    const beneath = abi.RESOLVE_BENEATH;
    const nolinks = abi.RESOLVE_NO_SYMLINKS | abi.RESOLVE_NO_MAGICLINKS;
    const cases = [_]Case{
        .{ .path = "sub/f", .resolve = beneath, .want = null },
        .{ .path = "link/f", .resolve = beneath, .want = null },
        .{ .path = "../a/sub/f", .resolve = beneath, .want = &.{.XDEV} },
        .{ .path = "abs/tmp", .resolve = beneath, .want = &.{.XDEV} },
        .{ .path = "up/a/sub/f", .resolve = beneath, .want = &.{.XDEV} },
        .{ .path = "link/f", .resolve = 0, .want = null },
        .{ .path = "link/f", .resolve = nolinks, .want = &.{.LOOP} },
        .{ .path = "sub/f", .resolve = nolinks, .want = null },
        .{ .path = "abs/sub/f", .resolve = abi.RESOLVE_IN_ROOT, .want = null },
    };
    for (cases) |cs| {
        const how: abi.open_how = .{ .flags = oflags(rd), .mode = 0, .resolve = cs.resolve };
        const what = std.fmt.bufPrint(&path_buf, "openat2 a, \"{s}\", resolve 0x{x}", .{ cs.path, cs.resolve }) catch unreachable;
        const rc = abi.openat2(root, cs.path, &how);
        if (cs.want) |w| {
            _ = refused(rc, w, what);
        } else {
            _ = linux.close(mustFd(rc, what));
            ok("{s}: opened", .{what});
        }
    }
    // A magic link: /proc/self/fd/N names a's root. The path from "/" has
    // no symlink but "self" (a plain one, which NO_MAGICLINKS allows).
    const magic = std.fmt.bufPrintZ(&path_buf, "/proc/self/fd/{d}/sub", .{root}) catch unreachable;
    {
        const how: abi.open_how = .{ .flags = oflags(o_path_dir), .mode = 0, .resolve = 0 };
        _ = linux.close(mustFd(abi.openat2(AT_FDCWD, magic, &how), "openat2 through /proc/self/fd, no resolve flags"));
        ok("openat2 through /proc/self/fd, no resolve flags: opened", .{});
        const how2: abi.open_how = .{ .flags = oflags(o_path_dir), .mode = 0, .resolve = abi.RESOLVE_NO_MAGICLINKS };
        _ = refused(abi.openat2(AT_FDCWD, magic, &how2), &.{.LOOP}, "openat2 through /proc/self/fd, RESOLVE_NO_MAGICLINKS");
    }
    // A how of the wrong size: the kernel reads the size it is given.
    {
        const how: abi.open_how = .{ .flags = oflags(rd), .mode = 0, .resolve = 0 };
        _ = refused(linux.syscall4(.openat2, @bitCast(@as(isize, root)), @intFromPtr("sub/f"), @intFromPtr(&how), abi.OPEN_HOW_SIZE_VER0 - 8), &.{.INVAL}, "openat2 with a 16-byte how");
    }

    write(1, "p4: all ok\n", .{});
}
