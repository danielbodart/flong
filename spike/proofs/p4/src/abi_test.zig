//! P4's header check (ZIG.md, "Phase 0: proofs"): every struct and constant
//! of src/abi.zig against Zig's bundled uapi headers (src/abi.h), translated
//! for this module's target by build.zig's addTranslateC. build.zig compiles
//! it for x86_64-linux-musl and aarch64-linux-musl; every check is comptime,
//! so a mismatch on either arch is a compile error naming the field, and the
//! host's arch also runs the test, which prints what was compared.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const abi = @import("abi");
const c = @import("c");
const options = @import("options");

const arch = @tagName(builtin.cpu.arch);

fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    @compileError(std.fmt.comptimePrint("p4: " ++ arch ++ ": " ++ fmt, args));
}

// Each arch took its own asm/ headers: the syscall numbers differ, and
// asm/unistd.h is the per-arch directory's (x86-linux-any or
// aarch64-linux-any). The controls, which show a mismatch fails the build:
// -Dplant=arch expects the other arch's numbers, -Dplant=offset moves every
// header offset by one.
const openat_expected = switch (builtin.cpu.arch) {
    .x86_64 => if (options.plant == .arch) 56 else 257,
    .aarch64 => if (options.plant == .arch) 257 else 56,
    else => @compileError("p4: checks x86_64 and aarch64 only"),
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

/// std's Statx against the header's struct statx: its fields are the
/// header's with stx_ dropped, but for the spares, and __pad2 starts at
/// stx_mnt_id (0x90), where abi.statxMntIdUnique reads.
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

/// Every integer constant of abi.zig equals the header's macro of that name,
/// but for OPEN_HOW_SIZE_VER0, which the uapi header does not define.
fn sameConstants() usize {
    @setEvalBranchQuota(100_000);
    var n: usize = 0;
    for (@typeInfo(abi).@"struct".decls) |d| {
        const v = @field(abi, d.name);
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

/// The calls abi.zig makes, by std's SYS for this arch, against asm/unistd.h.
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

    sameSize(abi.open_how, c.struct_open_how, "open_how", 24);
    sameSize(abi.mount_attr, c.struct_mount_attr, "mount_attr", c.MOUNT_ATTR_SIZE_VER0);
    // The header's mnt_id_req is VER1; ours is VER0, its first 24 bytes.
    if (@sizeOf(abi.mnt_id_req) != c.MNT_ID_REQ_SIZE_VER0) fail("mnt_id_req: size {d}, not VER0", .{@sizeOf(abi.mnt_id_req)});
    if (@sizeOf(c.struct_mnt_id_req) != c.MNT_ID_REQ_SIZE_VER1) fail("header mnt_id_req is not VER1", .{});
    sameSize(abi.statmount, c.struct_statmount, "statmount", 512);
    if (!@hasDecl(c.struct_statmount, "str")) fail("statmount: no flexible str[]", .{});
    sameSize(abi.clone_args, c.struct_clone_args, "clone_args", c.CLONE_ARGS_SIZE_VER2);

    break :blk .{
        .arch = arch,
        .openat = c.__NR_openat,
        .version = c.LINUX_VERSION_CODE,
        .open_how = sameLayout(abi.open_how, c.struct_open_how, "open_how"),
        .mount_attr = sameLayout(abi.mount_attr, c.struct_mount_attr, "mount_attr"),
        .mnt_id_req = sameLayout(abi.mnt_id_req, c.struct_mnt_id_req, "mnt_id_req"),
        .statmount = sameLayout(abi.statmount, c.struct_statmount, "statmount"),
        .clone_args = sameLayout(abi.clone_args, c.struct_clone_args, "clone_args"),
        .statx = statxLayout(),
        .constants = sameConstants(),
        .syscalls = sameSyscalls(),
        .stx_mnt_id = @offsetOf(c.struct_statx, "stx_mnt_id"),
    };
};

comptime {
    _ = report;
}

test "the mount ABI matches Zig's bundled headers" {
    std.debug.print("p4: {s}: __NR_openat {d}, LINUX_VERSION_CODE {d}, stx_mnt_id at 0x{x}; fields compared: open_how {d}, mount_attr {d}, mnt_id_req {d}, statmount {d}, clone_args {d}, Statx {d}; constants {d}, syscalls {d}\n", .{
        report.arch,       report.openat,     report.version,    report.stx_mnt_id,
        report.open_how,   report.mount_attr, report.mnt_id_req, report.statmount,
        report.clone_args, report.statx,      report.constants,  report.syscalls,
    });
}
