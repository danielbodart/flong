//! The kernel ABI of flong's Zig against Zig's bundled uapi headers
//! (tests/zig/abi.h, translated per target by build.zig's `abi` step):
//! every struct field's offset and size, every constant and syscall number,
//! compiled for x86_64-linux-musl and aarch64-linux-musl, so only Zig's
//! headers are read, never the host's (ZIG.md, "test-libc"). P4 of phase 0
//! (spike/proofs/p4, archived in ~/Projects/flong-spikes-archive/zig) moved
//! here; since phase 4 the mount structs and constants checked are
//! sys.zig's own (the mount helper's), and `mine` keeps only clone3's,
//! until phase 5 puts them in sys.zig too.
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

/// clone3's struct and constants, which phase 5 will put in sys.zig
/// (spike/proofs/p4/src/abi.zig).
const mine = struct {
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
        std.debug.assert(@sizeOf(clone_args) == 88); // CLONE_ARGS_SIZE_VER2
        // std's Statx has no stx_mnt_id: the 8 bytes at 0x90 are __pad2[0],
        // which STATX_MNT_ID and STATX_MNT_ID_UNIQUE fill.
        std.debug.assert(@sizeOf(linux.Statx) == 256);
        std.debug.assert(@offsetOf(linux.Statx, "__pad2") == 0x90);
    }

    pub const CLONE_ARGS_SIZE_VER2 = 88;
    pub const CLONE_PIDFD = 0x1000;
    pub const CLONE_INTO_CGROUP = 0x200000000;
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

/// sys.CapHeader and sys.CapData against linux/capability.h's
/// __user_cap_header_struct and __user_cap_data_struct: flong-init's
/// capset (phase 3).
fn capLayout() usize {
    const Pair = struct { []const u8, []const u8 };
    const header = [_]Pair{ .{ "version", "version" }, .{ "pid", "pid" } };
    const data = [_]Pair{ .{ "effective", "effective" }, .{ "permitted", "permitted" }, .{ "inheritable", "inheritable" } };
    inline for (.{ .{ sys.CapHeader, c.struct___user_cap_header_struct, header, "cap header" }, .{ sys.CapData, c.struct___user_cap_data_struct, data, "cap data" } }) |t| {
        inline for (t[2]) |p| {
            const mo = @offsetOf(t[0], p[0]);
            const co = @offsetOf(t[1], p[1]) + (if (options.plant == .offset) 1 else 0);
            if (mo != co) fail("{s}.{s}: offset {d}, header {d}", .{ t[3], p[0], mo, co });
            if (@sizeOf(@FieldType(t[0], p[0])) != @sizeOf(@FieldType(t[1], p[1])))
                fail("{s}.{s}: size differs", .{ t[3], p[0] });
        }
        if (@sizeOf(t[0]) != @sizeOf(t[1])) fail("{s}: size {d}, header {d}", .{ t[3], @sizeOf(t[0]), @sizeOf(t[1]) });
    }
    return header.len + data.len;
}

/// sys.KSigaction against asm/signal.h's struct sigaction, the kernel's
/// (x86_64's own, aarch64's asm-generic/signal.h with SA_RESTORER defined):
/// flong-init's rt_sigaction (phase 3), whose layout strace checks on
/// x86_64 only.
fn sigactionLayout() usize {
    const pairs = .{ .{ "handler", "sa_handler" }, .{ "flags", "sa_flags" }, .{ "restorer", "sa_restorer" }, .{ "mask", "sa_mask" } };
    inline for (pairs) |p| {
        const mo = @offsetOf(sys.KSigaction, p[0]);
        const co = @offsetOf(c.struct_sigaction, p[1]) + (if (options.plant == .offset) 1 else 0);
        if (mo != co) fail("sigaction.{s}: offset {d}, header {d}", .{ p[0], mo, co });
        if (@sizeOf(@FieldType(sys.KSigaction, p[0])) != @sizeOf(@FieldType(c.struct_sigaction, p[1])))
            fail("sigaction.{s}: size differs from {s}", .{ p[0], p[1] });
    }
    if (@sizeOf(sys.KSigaction) != @sizeOf(c.struct_sigaction))
        fail("sigaction: size {d}, header {d}", .{ @sizeOf(sys.KSigaction), @sizeOf(c.struct_sigaction) });
    return pairs.len;
}

/// flong-init's constants in sys.zig against their macros (phase 3).
fn initConstants() usize {
    const pairs = .{
        .{ "ngroups_max", sys.ngroups_max, c.NGROUPS_MAX },
        .{ "PR.CAPBSET_READ", sys.PR.CAPBSET_READ, c.PR_CAPBSET_READ },
        .{ "PR.CAPBSET_DROP", sys.PR.CAPBSET_DROP, c.PR_CAPBSET_DROP },
        .{ "PR.CAP_AMBIENT", sys.PR.CAP_AMBIENT, c.PR_CAP_AMBIENT },
        .{ "PR.CAP_AMBIENT_CLEAR_ALL", sys.PR.CAP_AMBIENT_CLEAR_ALL, c.PR_CAP_AMBIENT_CLEAR_ALL },
        .{ "cap_version_3", sys.cap_version_3, c._LINUX_CAPABILITY_VERSION_3 },
        .{ "cap_u32s_3", sys.cap_u32s_3, c._LINUX_CAPABILITY_U32S_3 },
        .{ "TIOCSCTTY", sys.TIOCSCTTY, c.TIOCSCTTY },
        .{ "SIG.INT", sys.SIG.INT, c.SIGINT },
        .{ "SIG.QUIT", sys.SIG.QUIT, c.SIGQUIT },
        .{ "SIG.SETMASK", sys.SIG.SETMASK, c.SIG_SETMASK },
        .{ "sa_restorer", sys.sa_restorer, c.SA_RESTORER },
    };
    inline for (pairs) |p| {
        if (p[1] != p[2]) fail("sys.{s}: {d}, header {d}", .{ p[0], p[1], p[2] });
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

/// Every integer constant of `mine` equals the header's macro of that name.
fn sameConstants() usize {
    @setEvalBranchQuota(100_000);
    var n: usize = 0;
    for (@typeInfo(mine).@"struct".decls) |d| {
        const v = @field(mine, d.name);
        if (@TypeOf(v) != comptime_int) continue;
        if (!@hasDecl(c, d.name)) fail("{s}: not in the header", .{d.name});
        const h = @field(c, d.name);
        if (v != h) fail("{s}: {d}, header {d}", .{ d.name, v, h });
        n += 1;
    }
    return n;
}

/// The mount helper's constants in sys.zig against their macros (phase 4:
/// linux/openat2.h, mount.h, fcntl.h, stat.h, sched.h, pidfd.h).
fn mountConstants() usize {
    const pairs = .{
        .{ "RESOLVE.NO_XDEV", sys.RESOLVE.NO_XDEV, c.RESOLVE_NO_XDEV },
        .{ "RESOLVE.NO_MAGICLINKS", sys.RESOLVE.NO_MAGICLINKS, c.RESOLVE_NO_MAGICLINKS },
        .{ "RESOLVE.NO_SYMLINKS", sys.RESOLVE.NO_SYMLINKS, c.RESOLVE_NO_SYMLINKS },
        .{ "RESOLVE.BENEATH", sys.RESOLVE.BENEATH, c.RESOLVE_BENEATH },
        .{ "RESOLVE.IN_ROOT", sys.RESOLVE.IN_ROOT, c.RESOLVE_IN_ROOT },
        .{ "MOUNT_ATTR.RDONLY", sys.MOUNT_ATTR.RDONLY, c.MOUNT_ATTR_RDONLY },
        .{ "MOUNT_ATTR.NOSUID", sys.MOUNT_ATTR.NOSUID, c.MOUNT_ATTR_NOSUID },
        .{ "MOUNT_ATTR.NODEV", sys.MOUNT_ATTR.NODEV, c.MOUNT_ATTR_NODEV },
        .{ "MOUNT_ATTR.NOEXEC", sys.MOUNT_ATTR.NOEXEC, c.MOUNT_ATTR_NOEXEC },
        .{ "OPEN_TREE_CLONE", sys.OPEN_TREE_CLONE, c.OPEN_TREE_CLONE },
        .{ "OPEN_TREE_CLOEXEC", sys.OPEN_TREE_CLOEXEC, c.OPEN_TREE_CLOEXEC },
        .{ "AT_RECURSIVE", sys.AT_RECURSIVE, c.AT_RECURSIVE },
        .{ "AT.EMPTY_PATH", sys.AT.EMPTY_PATH, c.AT_EMPTY_PATH },
        .{ "AT.SYMLINK_NOFOLLOW", sys.AT.SYMLINK_NOFOLLOW, c.AT_SYMLINK_NOFOLLOW },
        .{ "AT.REMOVEDIR", sys.AT.REMOVEDIR, c.AT_REMOVEDIR },
        .{ "MOVE_MOUNT_F_EMPTY_PATH", sys.MOVE_MOUNT_F_EMPTY_PATH, c.MOVE_MOUNT_F_EMPTY_PATH },
        .{ "MOVE_MOUNT_T_EMPTY_PATH", sys.MOVE_MOUNT_T_EMPTY_PATH, c.MOVE_MOUNT_T_EMPTY_PATH },
        .{ "FSOPEN_CLOEXEC", sys.FSOPEN_CLOEXEC, c.FSOPEN_CLOEXEC },
        .{ "FSMOUNT_CLOEXEC", sys.FSMOUNT_CLOEXEC, c.FSMOUNT_CLOEXEC },
        .{ "FSCONFIG.SET_FLAG", sys.FSCONFIG.SET_FLAG, c.FSCONFIG_SET_FLAG },
        .{ "FSCONFIG.SET_STRING", sys.FSCONFIG.SET_STRING, c.FSCONFIG_SET_STRING },
        .{ "FSCONFIG.SET_FD", sys.FSCONFIG.SET_FD, c.FSCONFIG_SET_FD },
        .{ "FSCONFIG.CMD_CREATE", sys.FSCONFIG.CMD_CREATE, c.FSCONFIG_CMD_CREATE },
        .{ "STATX_MNT_ID_UNIQUE", sys.STATX_MNT_ID_UNIQUE, c.STATX_MNT_ID_UNIQUE },
        .{ "STATMOUNT_MNT_BASIC", sys.STATMOUNT_MNT_BASIC, c.STATMOUNT_MNT_BASIC },
        .{ "mnt_id_req_size_ver0", sys.mnt_id_req_size_ver0, c.MNT_ID_REQ_SIZE_VER0 },
        .{ "MountAttr size", @sizeOf(sys.MountAttr), c.MOUNT_ATTR_SIZE_VER0 },
        .{ "CLONE.NEWNS", sys.CLONE.NEWNS, c.CLONE_NEWNS },
        .{ "CLONE.NEWCGROUP", sys.CLONE.NEWCGROUP, c.CLONE_NEWCGROUP },
        .{ "CLONE.NEWUSER", sys.CLONE.NEWUSER, c.CLONE_NEWUSER },
        .{ "CLONE.NEWNET", sys.CLONE.NEWNET, c.CLONE_NEWNET },
        .{ "PIDFD_GET_CGROUP_NAMESPACE", sys.PIDFD_GET_CGROUP_NAMESPACE, c.PIDFD_GET_CGROUP_NAMESPACE },
        .{ "PIDFD_GET_MNT_NAMESPACE", sys.PIDFD_GET_MNT_NAMESPACE, c.PIDFD_GET_MNT_NAMESPACE },
        .{ "PIDFD_GET_NET_NAMESPACE", sys.PIDFD_GET_NET_NAMESPACE, c.PIDFD_GET_NET_NAMESPACE },
        .{ "path_max", sys.path_max, c.PATH_MAX },
    };
    inline for (pairs) |p| {
        if (p[1] != p[2]) fail("sys.{s}: {d}, header {d}", .{ p[0], p[1], p[2] });
    }
    return pairs.len;
}

/// The calls `mine` is for, by std's SYS for this arch, against asm/unistd.h.
fn sameSyscalls() usize {
    const names = .{
        "open_tree", "move_mount", "fsopen",       "fsconfig",       "fsmount",    "mount_setattr", "openat2", "statmount", "statx",         "clone3",  "pidfd_open", "openat",
        // flong-init's (phase 3)
        "setgroups", "prctl",      "rt_sigaction", "rt_sigprocmask", "chdir",      "close_range",   "execve",  "capset",
        // the mount helper's (phase 4)
           "setns",         "unshare", "setresuid",  "setresgid",
        "setfsuid",  "setfsgid",   "fchownat",     "umask",          "readlinkat", "umount2",       "ioctl",   "pipe2",     "clock_gettime",
    };
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

    sameSize(sys.OpenHow, c.struct_open_how, "open_how", 24);
    sameSize(sys.MountAttr, c.struct_mount_attr, "mount_attr", c.MOUNT_ATTR_SIZE_VER0);
    // The header's mnt_id_req is VER1; ours is VER0, its first 24 bytes.
    if (@sizeOf(sys.MntIdReq) != c.MNT_ID_REQ_SIZE_VER0) fail("mnt_id_req: size {d}, not VER0", .{@sizeOf(sys.MntIdReq)});
    if (@sizeOf(c.struct_mnt_id_req) != c.MNT_ID_REQ_SIZE_VER1) fail("header mnt_id_req is not VER1", .{});
    sameSize(sys.StatMount, c.struct_statmount, "statmount", 512);
    if (!@hasDecl(c.struct_statmount, "str")) fail("statmount: no flexible str[]", .{});
    sameSize(mine.clone_args, c.struct_clone_args, "clone_args", c.CLONE_ARGS_SIZE_VER2);
    sameSize(sys.Iovec, c.struct_iovec, "iovec", 2 * @sizeOf(usize));

    break :blk .{
        .arch = arch,
        .openat = c.__NR_openat,
        .version = c.LINUX_VERSION_CODE,
        .open_how = sameLayout(sys.OpenHow, c.struct_open_how, "open_how"),
        .mount_attr = sameLayout(sys.MountAttr, c.struct_mount_attr, "mount_attr"),
        .mnt_id_req = sameLayout(sys.MntIdReq, c.struct_mnt_id_req, "mnt_id_req"),
        .statmount = sameLayout(sys.StatMount, c.struct_statmount, "statmount"),
        .clone_args = sameLayout(mine.clone_args, c.struct_clone_args, "clone_args"),
        .iovec = iovecLayout(),
        .statx = statxLayout(),
        .cap = capLayout(),
        .sigaction = sigactionLayout(),
        .init = initConstants(),
        .mount = mountConstants(),
        .constants = sameConstants(),
        .syscalls = sameSyscalls(),
        .stx_mnt_id = @offsetOf(c.struct_statx, "stx_mnt_id"),
    };
};

comptime {
    _ = report;
}

test "the kernel ABI matches Zig's bundled headers" {
    std.debug.print("abi: {s}: __NR_openat {d}, LINUX_VERSION_CODE {d}, stx_mnt_id at 0x{x}; fields compared: open_how {d}, mount_attr {d}, mnt_id_req {d}, statmount {d}, clone_args {d}, iovec {d}, Statx {d}, capability {d}, sigaction {d}; constants: clone3's {d}, flong-init's {d}, the mount helper's {d}; syscalls {d}\n", .{
        report.arch,       report.openat,     report.version,    report.stx_mnt_id,
        report.open_how,   report.mount_attr, report.mnt_id_req, report.statmount,
        report.clone_args, report.iovec,      report.statx,      report.cap,
        report.sigaction,  report.constants,  report.init,       report.mount,
        report.syscalls,
    });
}
