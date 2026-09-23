//! The mount ABI flong's Zig will use, written by hand: the structs std.os.linux
//! lacks, the constants, and the syscall wrappers. P4 (ZIG.md, "Phase 0:
//! proofs") checks every struct here against Zig's bundled uapi headers, for
//! x86_64 and aarch64 (src/abi_test.zig), and round-trips the calls on a
//! kernel (src/mount.zig).
//!
//! Every struct is made of u32 and u64 in the kernel's own order, so its
//! layout is the same on every 64-bit Linux; the size asserts below pin it,
//! and the published size constants (MOUNT_ATTR_SIZE_VER0 and the like) are
//! the sizes the kernel reads.
const std = @import("std");
const linux = std.os.linux;

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

    /// The NUL-terminated string at `off` in the variable part of `buf`,
    /// which holds a statmount the kernel filled; null when it lies outside
    /// the `size` the kernel reported.
    pub fn string(buf: []const u8, off: u32) ?[]const u8 {
        const sm: *const statmount = @ptrCast(@alignCast(buf.ptr));
        const start = @sizeOf(statmount) + @as(usize, off);
        if (start >= sm.size or sm.size > buf.len) return null;
        const rest = buf[start..sm.size];
        const len = std.mem.indexOfScalar(u8, rest, 0) orelse return null;
        return rest[0..len];
    }
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

/// The unique mount id statx filled at 0x90 (`stx_mnt_id`), which
/// statmount's `mnt_id` names, or null when the kernel did not fill it.
pub fn statxMntIdUnique(stx: *const linux.Statx) ?u64 {
    if (stx.mask & STATX_MNT_ID_UNIQUE == 0) return null;
    return stx.__pad2[0];
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

/// The calls, each returning the raw result for linux.E.init.
pub fn open_tree(dfd: i32, path: [*:0]const u8, flags: u32) usize {
    return linux.syscall3(.open_tree, @bitCast(@as(isize, dfd)), @intFromPtr(path), flags);
}

pub fn move_mount(from_dfd: i32, from: [*:0]const u8, to_dfd: i32, to: [*:0]const u8, flags: u32) usize {
    return linux.syscall5(.move_mount, @bitCast(@as(isize, from_dfd)), @intFromPtr(from), @bitCast(@as(isize, to_dfd)), @intFromPtr(to), flags);
}

pub fn fsopen(name: [*:0]const u8, flags: u32) usize {
    return linux.syscall2(.fsopen, @intFromPtr(name), flags);
}

pub fn fsconfig(fd: i32, cmd: u32, key: ?[*:0]const u8, value: ?[*:0]const u8, aux: i32) usize {
    return linux.syscall5(.fsconfig, @bitCast(@as(isize, fd)), cmd, @intFromPtr(key), @intFromPtr(value), @bitCast(@as(isize, aux)));
}

pub fn fsmount(fd: i32, flags: u32, attr_flags: u32) usize {
    return linux.syscall3(.fsmount, @bitCast(@as(isize, fd)), flags, attr_flags);
}

pub fn mount_setattr(dfd: i32, path: [*:0]const u8, flags: u32, attr: *const mount_attr) usize {
    return linux.syscall5(.mount_setattr, @bitCast(@as(isize, dfd)), @intFromPtr(path), flags, @intFromPtr(attr), @sizeOf(mount_attr));
}

pub fn openat2(dfd: i32, path: [*:0]const u8, how: *const open_how) usize {
    return linux.syscall4(.openat2, @bitCast(@as(isize, dfd)), @intFromPtr(path), @intFromPtr(how), @sizeOf(open_how));
}

pub fn statmountCall(req: *const mnt_id_req, buf: []align(8) u8, flags: u32) usize {
    return linux.syscall4(.statmount, @intFromPtr(req), @intFromPtr(buf.ptr), buf.len, flags);
}
