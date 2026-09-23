//! The kernel ABI of flong's Zig against Zig's bundled uapi headers
//! (tests/zig/abi.h, translated per target by build.zig's `abi` step):
//! every struct field's offset and size, every constant and syscall number,
//! compiled for x86_64-linux-musl and aarch64-linux-musl, so only Zig's
//! headers are read, never the host's (ZIG.md, "test-libc"). P4 of phase 0
//! (spike/proofs/p4, archived in ~/Projects/flong-spikes-archive/zig) moved
//! here: the mount structs are its own copies (`mine`) until phase 4 puts
//! them in sys.zig, which then drops them from here; sys.zig's structs are
//! checked as they are.
//!
//! Every check is comptime, so compiling for an arch is checking it; the
//! host's arch also runs, printing what was compared. Each arch must have
//! taken its own asm/ headers (__NR_openat 257 or 56). The controls,
//! -Dabi-plant=arch (the other arch's numbers expected) and
//! -Dabi-plant=offset (every header offset moved by one), must each fail
//! the build naming what differs (native.nix, cross-aarch64).
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const sys = @import("sys");
const c = @import("c");
const options = @import("options");

/// The structs and constants phases 4-5 will put in sys.zig
/// (spike/proofs/p4/src/abi.zig), each a u32 and u64 in the kernel's order.
const mine = struct {
    /// openat2's `how` (linux/openat2.h:19-23).
    pub const open_how = extern struct {
        flags: u64,
        mode: u64,
        resolve: u64,
    };

    /// mount_setattr's attributes (linux/mount.h, `struct mount_attr`); VER0.
    pub const mount_attr = extern struct {
        attr_set: u64,
        attr_clr: u64,
        propagation: u64,
        userns_fd: u64,
    };

    /// statmount's and listmount's request (linux/mount.h, `struct mnt_id_req`),
    /// VER0 only: the header's fifth field, mnt_ns_id, is VER1 (kernel 6.11).
    /// The kernel takes the size from `size`, so a VER0 request is 24 bytes.
    pub const mnt_id_req = extern struct {
        size: u32,
        spare: u32,
        mnt_id: u64,
        param: u64,
    };

    /// statmount's fixed part (linux/mount.h, `struct statmount`), up to the
    /// variable `str[]`, whose offsets the `[str]` fields hold.
    pub const statmount = extern struct {
        size: u32,
        mnt_opts: u32,
        mask: u64,
        sb_dev_major: u32,
        sb_dev_minor: u32,
        sb_magic: u64,
        sb_flags: u32,
        fs_type: u32,
        mnt_id: u64,
        mnt_parent_id: u64,
        mnt_id_old: u32,
        mnt_parent_id_old: u32,
        mnt_attr: u64,
        mnt_propagation: u64,
        mnt_peer_group: u64,
        mnt_master: u64,
        propagate_from: u64,
        mnt_root: u32,
        mnt_point: u32,
        mnt_ns_id: u64,
        fs_subtype: u32,
        sb_source: u32,
        opt_num: u32,
        opt_array: u32,
        opt_sec_num: u32,
        opt_sec_array: u32,
        __spare2: [46]u64,
    };

    /// clone3's arguments (linux/sched.h, `struct clone_args`), VER2 with
    /// `cgroup` (kernel 5.7), what CLONE_INTO_CGROUP needs.
    pub const clone_args = extern struct {
        flags: u64,
        pidfd: u64,
        child_tid: u64,
        parent_tid: u64,
        exit_signal: u64,
        stack: u64,
        stack_size: u64,
        tls: u64,
        set_tid: u64,
        set_tid_size: u64,
        cgroup: u64,
    };

    comptime {
        std.debug.assert(@sizeOf(open_how) == 24); // OPEN_HOW_SIZE_VER0
        std.debug.assert(@sizeOf(mount_attr) == 32); // MOUNT_ATTR_SIZE_VER0
        std.debug.assert(@sizeOf(mnt_id_req) == 24); // MNT_ID_REQ_SIZE_VER0
        std.debug.assert(@sizeOf(statmount) == 512);
        std.debug.assert(@sizeOf(clone_args) == 88); // CLONE_ARGS_SIZE_VER2
        // std's Statx has no stx_mnt_id: the 8 bytes at 0x90 are __pad2[0],
        // which STATX_MNT_ID and STATX_MNT_ID_UNIQUE fill.
        std.debug.assert(@sizeOf(linux.Statx) == 256);
        std.debug.assert(@offsetOf(linux.Statx, "__pad2") == 0x90);
    }

    pub const OPEN_HOW_SIZE_VER0 = 24;
    pub const MOUNT_ATTR_SIZE_VER0 = 32;
    pub const MNT_ID_REQ_SIZE_VER0 = 24;
    pub const CLONE_ARGS_SIZE_VER2 = 88;

    pub const RESOLVE_NO_XDEV = 0x01;
    pub const RESOLVE_NO_MAGICLINKS = 0x02;
    pub const RESOLVE_NO_SYMLINKS = 0x04;
    pub const RESOLVE_BENEATH = 0x08;
    pub const RESOLVE_IN_ROOT = 0x10;

    pub const OPEN_TREE_CLONE = 1;
    pub const OPEN_TREE_CLOEXEC = 0o2000000; // O_CLOEXEC on both arches
    pub const MOVE_MOUNT_F_EMPTY_PATH = 0x04;
    pub const FSOPEN_CLOEXEC = 0x01;
    pub const FSMOUNT_CLOEXEC = 0x01;
    pub const FSCONFIG_SET_STRING = 1;
    pub const FSCONFIG_CMD_CREATE = 6;
    pub const MOUNT_ATTR_RDONLY = 0x01;
    pub const AT_RECURSIVE = 0x8000;

    pub const STATX_MNT_ID = 0x1000;
    pub const STATX_MNT_ID_UNIQUE = 0x4000;

    pub const STATMOUNT_SB_BASIC = 0x01;
    pub const STATMOUNT_MNT_BASIC = 0x02;
    pub const STATMOUNT_MNT_POINT = 0x10;
    pub const STATMOUNT_FS_TYPE = 0x20;

    pub const TMPFS_MAGIC = 0x01021994;

    pub const CLONE_PIDFD = 0x1000;
    pub const CLONE_INTO_CGROUP = 0x200000000;
    pub const PIDFD_GET_MNT_NAMESPACE = 0xff03; // _IO(PIDFS_IOCTL_MAGIC, 3)
};

const arch = @tagName(builtin.cpu.arch);

fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    @compileError(std.fmt.comptimePrint("abi: " ++ arch ++ ": " ++ fmt, args));
}

// Each arch took its own asm/ headers: the syscall numbers differ, and
// asm/unistd.h is the per-arch directory's (x86-linux-any or
// aarch64-linux-any). The controls, which show a mismatch fails the build:
// -Dabi-plant=arch expects the other arch's numbers, -Dabi-plant=offset
// moves every header offset by one.
const openat_expected = switch (builtin.cpu.arch) {
    .x86_64 => if (options.plant == .arch) 56 else 257,
    .aarch64 => if (options.plant == .arch) 257 else 56,
    else => @compileError("abi: checks x86_64 and aarch64 only"),
};

// Zig's bundled headers, not another set: linux/version.h is 6.13.4
// (ZIG.md, "Measured"), and a header newer than that would define
// STATMOUNT_MNT_UIDMAP (6.15).
const version_expected = (6 << 16) | (13 << 8) | 4;

/// Every field of Mine is in C at the same offset with the same size, and
/// every field of C is in Mine, or lies past Mine's end (a later version's
/// tail, like mnt_id_req's VER1 mnt_ns_id) or is zero-sized at its end (a
/// flexible array).
fn sameLayout(comptime Mine: type, comptime C: type, comptime what: []const u8) usize {
    @setEvalBranchQuota(100_000);
    var n: usize = 0;
    for (std.meta.fields(Mine)) |f| {
        if (!@hasField(C, f.name)) fail("{s}.{s}: not in the header", .{ what, f.name });
        const mo = @offsetOf(Mine, f.name);
        const co = @offsetOf(C, f.name) + (if (options.plant == .offset) 1 else 0);
        if (mo != co) fail("{s}.{s}: offset {d}, header {d}", .{ what, f.name, mo, co });
        const ms = @sizeOf(f.type);
        const cs = @sizeOf(@FieldType(C, f.name));
        if (ms != cs) fail("{s}.{s}: size {d}, header {d}", .{ what, f.name, ms, cs });
        n += 1;
    }
    for (std.meta.fields(C)) |f| {
        if (@hasField(Mine, f.name)) continue;
        if (@offsetOf(C, f.name) < @sizeOf(Mine))
            fail("{s}.{s}: in the header at {d}, missing", .{ what, f.name, @offsetOf(C, f.name) });
    }
    if (@alignOf(Mine) != @alignOf(C)) fail("{s}: align {d}, header {d}", .{ what, @alignOf(Mine), @alignOf(C) });
    return n;
}

fn sameSize(comptime Mine: type, comptime C: type, comptime what: []const u8, comptime size: usize) void {
    if (@sizeOf(Mine) != size) fail("{s}: size {d}, expected {d}", .{ what, @sizeOf(Mine), size });
    if (@sizeOf(C) != size) fail("{s}: header size {d}, expected {d}", .{ what, @sizeOf(C), size });
}

/// sys.Iovec against struct iovec (linux/uio.h), whose fields are
/// iov_base and iov_len.
fn iovecLayout() usize {
    const pairs = .{ .{ "base", "iov_base" }, .{ "len", "iov_len" } };
    inline for (pairs) |p| {
        const mo = @offsetOf(sys.Iovec, p[0]);
        const co = @offsetOf(c.struct_iovec, p[1]) + (if (options.plant == .offset) 1 else 0);
        if (mo != co) fail("iovec.{s}: offset {d}, header {d}", .{ p[0], mo, co });
        if (@sizeOf(@FieldType(sys.Iovec, p[0])) != @sizeOf(@FieldType(c.struct_iovec, p[1])))
            fail("iovec.{s}: size differs from {s}", .{ p[0], p[1] });
    }
    return pairs.len;
}

/// std's Statx against the header's struct statx: its fields are the
/// header's with stx_ dropped, but for the spares, and __pad2 starts at
/// stx_mnt_id (0x90), where phase 4 reads the unique mount id.
fn statxLayout() usize {
    @setEvalBranchQuota(100_000);
    const S = linux.Statx;
    const C = c.struct_statx;
    var n: usize = 0;
    for (std.meta.fields(S)) |f| {
        const cname = if (std.mem.eql(u8, f.name, "__pad1"))
            "__spare0"
        else if (std.mem.eql(u8, f.name, "__pad2"))
            "stx_mnt_id"
        else
            "stx_" ++ f.name;
        if (!@hasField(C, cname)) fail("Statx.{s}: no {s} in the header", .{ f.name, cname });
        if (@offsetOf(S, f.name) != @offsetOf(C, cname))
            fail("Statx.{s}: offset {d}, header {s} {d}", .{ f.name, @offsetOf(S, f.name), cname, @offsetOf(C, cname) });
        if (!std.mem.eql(u8, f.name, "__pad2") and @sizeOf(f.type) != @sizeOf(@FieldType(C, cname)))
            fail("Statx.{s}: size differs from {s}", .{ f.name, cname });
        n += 1;
    }
    if (@offsetOf(C, "stx_mnt_id") != 0x90) fail("stx_mnt_id at {d}, not 0x90", .{@offsetOf(C, "stx_mnt_id")});
    if (@sizeOf(@FieldType(C, "stx_mnt_id")) != @sizeOf(@typeInfo(@FieldType(S, "__pad2")).array.child))
        fail("stx_mnt_id is not __pad2[0]'s size", .{});
    if (@sizeOf(S) != @sizeOf(C)) fail("Statx: size {d}, header {d}", .{ @sizeOf(S), @sizeOf(C) });
    return n;
}

/// Every integer constant of `mine` equals the header's macro of that name,
/// but for OPEN_HOW_SIZE_VER0, which the uapi header does not define.
fn sameConstants() usize {
    @setEvalBranchQuota(100_000);
    var n: usize = 0;
    for (@typeInfo(mine).@"struct".decls) |d| {
        const v = @field(mine, d.name);
        if (@TypeOf(v) != comptime_int) continue;
        if (std.mem.eql(u8, d.name, "OPEN_HOW_SIZE_VER0")) {
            if (v != @sizeOf(c.struct_open_how)) fail("OPEN_HOW_SIZE_VER0 {d}, sizeof {d}", .{ v, @sizeOf(c.struct_open_how) });
        } else {
            if (!@hasDecl(c, d.name)) fail("{s}: not in the header", .{d.name});
            const h = @field(c, d.name);
            if (v != h) fail("{s}: {d}, header {d}", .{ d.name, v, h });
        }
        n += 1;
    }
    return n;
}

/// The calls `mine` is for, by std's SYS for this arch, against asm/unistd.h.
fn sameSyscalls() usize {
    const names = .{ "open_tree", "move_mount", "fsopen", "fsconfig", "fsmount", "mount_setattr", "openat2", "statmount", "statx", "clone3", "pidfd_open", "openat" };
    inline for (names) |name| {
        const h = @field(c, "__NR_" ++ name);
        const s = @intFromEnum(@field(linux.SYS, name));
        if (h != s) fail("__NR_{s} {d}, std.os.linux.SYS {d}", .{ name, h, s });
    }
    return names.len;
}

pub const report = blk: {
    if (c.__NR_openat != openat_expected)
        fail("__NR_openat is {d}, expected {d}: not this arch's asm/unistd.h", .{ c.__NR_openat, openat_expected });
    if (c.LINUX_VERSION_CODE != version_expected)
        fail("LINUX_VERSION_CODE {d}, expected 6.13.4 ({d}): not Zig's bundled headers", .{ c.LINUX_VERSION_CODE, version_expected });
    if (@hasDecl(c, "STATMOUNT_MNT_UIDMAP")) fail("STATMOUNT_MNT_UIDMAP defined: headers newer than 6.13", .{});

    sameSize(mine.open_how, c.struct_open_how, "open_how", 24);
    sameSize(mine.mount_attr, c.struct_mount_attr, "mount_attr", c.MOUNT_ATTR_SIZE_VER0);
    // The header's mnt_id_req is VER1; ours is VER0, its first 24 bytes.
    if (@sizeOf(mine.mnt_id_req) != c.MNT_ID_REQ_SIZE_VER0) fail("mnt_id_req: size {d}, not VER0", .{@sizeOf(mine.mnt_id_req)});
    if (@sizeOf(c.struct_mnt_id_req) != c.MNT_ID_REQ_SIZE_VER1) fail("header mnt_id_req is not VER1", .{});
    sameSize(mine.statmount, c.struct_statmount, "statmount", 512);
    if (!@hasDecl(c.struct_statmount, "str")) fail("statmount: no flexible str[]", .{});
    sameSize(mine.clone_args, c.struct_clone_args, "clone_args", c.CLONE_ARGS_SIZE_VER2);
    sameSize(sys.Iovec, c.struct_iovec, "iovec", 2 * @sizeOf(usize));

    break :blk .{
        .arch = arch,
        .openat = c.__NR_openat,
        .version = c.LINUX_VERSION_CODE,
        .open_how = sameLayout(mine.open_how, c.struct_open_how, "open_how"),
        .mount_attr = sameLayout(mine.mount_attr, c.struct_mount_attr, "mount_attr"),
        .mnt_id_req = sameLayout(mine.mnt_id_req, c.struct_mnt_id_req, "mnt_id_req"),
        .statmount = sameLayout(mine.statmount, c.struct_statmount, "statmount"),
        .clone_args = sameLayout(mine.clone_args, c.struct_clone_args, "clone_args"),
        .iovec = iovecLayout(),
        .statx = statxLayout(),
        .constants = sameConstants(),
        .syscalls = sameSyscalls(),
        .stx_mnt_id = @offsetOf(c.struct_statx, "stx_mnt_id"),
    };
};

comptime {
    _ = report;
}

test "the kernel ABI matches Zig's bundled headers" {
    std.debug.print("abi: {s}: __NR_openat {d}, LINUX_VERSION_CODE {d}, stx_mnt_id at 0x{x}; fields compared: open_how {d}, mount_attr {d}, mnt_id_req {d}, statmount {d}, clone_args {d}, iovec {d}, Statx {d}; constants {d}, syscalls {d}\n", .{
        report.arch,       report.openat,     report.version,    report.stx_mnt_id,
        report.open_how,   report.mount_attr, report.mnt_id_req, report.statmount,
        report.clone_args, report.iovec,      report.statx,      report.constants,
        report.syscalls,
    });
}
