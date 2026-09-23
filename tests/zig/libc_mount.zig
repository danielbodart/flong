//! test-libc: the mount-helper shim (src/hybrid/mount_c.zig) against
//! launcher/flong-mount.h as the C launcher compiles it, through
//! translate-c with glibc's headers (ZIG.md, "The mount-helper shim" and
//! "test-libc"): every field of struct fl_mount_job and struct fl_mount at
//! the same offset with the same size, enum fl_mount_kind's values in the
//! shim's order, flong_mount_main's prototype; then the shim itself, in a
//! fork child as the launcher calls it, on the path that needs no
//! namespace: a destination twice (1, one line). The shim's panic (125,
//! one line) is its root's, which a test binary's is not; the launcher's
//! derivation runs it (native.nix).

const std = @import("std");
const sys = @import("sys");
const mount_c = @import("mount_c");
const h = @import("mount_h");
const linux = std.os.linux;

const testing = std.testing;

fn sameLayout(comptime Mine: type, comptime C: type) !void {
    inline for (std.meta.fields(Mine)) |f| {
        if (!@hasField(C, f.name)) {
            std.debug.print("{s}: no {s} in the header\n", .{ @typeName(C), f.name });
            return error.TestUnexpectedResult;
        }
        try testing.expectEqual(@offsetOf(C, f.name), @offsetOf(Mine, f.name));
        try testing.expectEqual(@sizeOf(@FieldType(C, f.name)), @sizeOf(f.type));
    }
    inline for (std.meta.fields(C)) |f| {
        if (!@hasField(Mine, f.name)) {
            std.debug.print("{s}: {s} is not mirrored\n", .{ @typeName(Mine), f.name });
            return error.TestUnexpectedResult;
        }
    }
    try testing.expectEqual(@sizeOf(C), @sizeOf(Mine));
    try testing.expectEqual(@alignOf(C), @alignOf(Mine));
}

test "struct fl_mount_job and struct fl_mount, field by field" {
    try sameLayout(mount_c.FlMountJob, h.struct_fl_mount_job);
    try sameLayout(mount_c.FlMount, h.struct_fl_mount);
    // uid_t and gid_t are unsigned 32-bit, as the shim reads them.
    try testing.expectEqual(@as(h.uid_t, 0) -% 1, @as(h.uid_t, std.math.maxInt(u32)));
    try testing.expectEqual(@sizeOf(h.enum_fl_mount_kind), @sizeOf(c_uint));
}

test "umount2's flags are glibc's (flong-mount.c:477)" {
    try testing.expectEqual(@as(u32, h.MNT_DETACH), sys.MNT_DETACH);
    try testing.expectEqual(@as(u32, h.UMOUNT_NOFOLLOW), sys.UMOUNT_NOFOLLOW);
}

test "enum fl_mount_kind in the shim's order" {
    const pairs = .{
        .{ h.FL_BIND_RO, .bind_ro },             .{ h.FL_BIND_RW, .bind_rw },
        .{ h.FL_BIND_RO_EXACT, .bind_ro_exact }, .{ h.FL_BIND_RW_EXACT, .bind_rw_exact },
        .{ h.FL_DEV, .dev },                     .{ h.FL_TMPFS, .tmpfs },
        .{ h.FL_OVERLAY, .overlay },             .{ h.FL_MASK, .mask },
    };
    inline for (pairs) |p| try testing.expectEqual(@as(@TypeOf(mount_c.kinds[0]), p[1]), mount_c.kinds[p[0]]);
    try testing.expectEqual(@as(usize, pairs.len), mount_c.kinds.len);
}

test "flong_mount_main's prototype" {
    const F = @typeInfo(@TypeOf(h.flong_mount_main)).@"fn";
    try testing.expectEqual(@as(usize, 2), F.params.len);
    try testing.expect(F.params[1].type.? == c_int);
    // translate-c drops _Noreturn: the C's void is the Zig's noreturn.
    try testing.expect(F.return_type.? == void);
    const P = @typeInfo(F.params[0].type.?).pointer;
    try testing.expect(P.child == h.struct_fl_mount_job and P.is_const);
    const Z = @typeInfo(@TypeOf(mount_c.flong_mount_main)).@"fn";
    try testing.expectEqual(F.params.len, Z.params.len);
    try testing.expect(Z.params[1].type.? == c_int);
    try testing.expect(Z.return_type.? == noreturn);
    try testing.expect(Z.calling_convention.eql(F.calling_convention));
}

/// Runs the shim in a fork child with stderr on a pipe: its status and
/// what it said.
fn runShim(job: *const mount_c.FlMountJob, buf: []u8) !struct { status: u32, said: []const u8 } {
    var p: [2]i32 = undefined;
    try testing.expectEqual(@as(usize, 0), linux.pipe2(&p, .{ .CLOEXEC = true }));
    const pid: i32 = @intCast(@as(isize, @bitCast(linux.fork())));
    if (pid == 0) {
        _ = linux.dup2(p[1], 2);
        mount_c.flong_mount_main(job, 0);
    }
    _ = linux.close(p[1]);
    var n: usize = 0;
    while (true) {
        const r = linux.read(p[0], buf[n..].ptr, buf.len - n);
        if (linux.E.init(r) != .SUCCESS or r == 0) break;
        n += r;
    }
    _ = linux.close(p[0]);
    var status: u32 = 0;
    _ = linux.waitpid(pid, &status, 0);
    return .{ .status = status, .said = buf[0..n] };
}

test "the shim in a fork child: a destination twice is said once, and exits 1" {
    const ms = [_]mount_c.FlMount{
        .{ .kind = h.FL_TMPFS, .dest = "/srv/work", .src = null, .mode = "0755", .size = null, .owner_user = 0 },
        .{ .kind = h.FL_BIND_RO, .dest = "/srv/work", .src = "/srv/lower", .mode = null, .size = null, .owner_user = 0 },
    };
    const protect = [_][*:0]const u8{"/run/user/1000/flong"};
    const job: mount_c.FlMountJob = .{
        .u1 = -1,
        .leader_pidfd = -1,
        .ready = -1,
        .mounts = &ms,
        .nmounts = ms.len,
        .uid = 1000,
        .gid = 100,
        .home = "/home/alice",
        .protect = &protect,
        .nprotect = protect.len,
    };
    var buf: [4096]u8 = undefined;
    const r = try runShim(&job, &buf);
    try testing.expectEqualStrings("flong-launch: /srv/work is mounted twice\n", r.said);
    try testing.expect(linux.W.IFEXITED(r.status));
    try testing.expectEqual(@as(u32, 1), linux.W.EXITSTATUS(r.status));
}
