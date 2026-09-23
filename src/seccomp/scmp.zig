//! scmp.zig: the part of libseccomp 2.6.1 flong-seccomp calls, its eight
//! functions and the constants and struct they take (seccomp.h). The only
//! file of flong-seccomp that names a C symbol; test-libc
//! (tests/zig/libc_scmp.zig) holds every value and layout here equal to
//! seccomp.h's, through translate-c.
//!
//! libseccomp reports a failure as a negated errno (flong-seccomp.c:81);
//! each wrapper that can fail returns that errno, or null for success.

const std = @import("std");
const sys = @import("sys");
const fd = @import("fd");

/// scmp_filter_ctx, a filter being built.
pub const Filter = opaque {};

/// SCMP_ACT_ALLOW, SCMP_ACT_LOG (seccomp.h:385-389).
pub const act_allow: u32 = 0x7fff0000;
pub const act_log: u32 = 0x7ffc0000;

/// SCMP_ACT_ERRNO(x) (seccomp.h:377).
pub fn actErrno(x: u32) u32 {
    return 0x00050000 | (x & 0x0000ffff);
}

/// SCMP_ARCH_X86_64, SCMP_ARCH_X86 and SCMP_ARCH_X32 (seccomp.h:127-140):
/// the audit arch tokens.
pub const arch_x86_64: u32 = 0xc000003e;
pub const arch_x86: u32 = 0x40000003;
pub const arch_x32: u32 = 0x4000003e;

/// enum scmp_filter_attr, the one flong-seccomp sets (seccomp.h:73).
pub const Attr = enum(c_uint) { ctl_optimize = 8 };

/// enum scmp_compare (seccomp.h:88-98).
pub const Op = enum(c_uint) {
    ne = 1,
    lt = 2,
    le = 3,
    eq = 4,
    ge = 5,
    gt = 6,
    masked_eq = 7,
};

/// struct scmp_arg_cmp (seccomp.h:108-113). masked_eq takes the mask in
/// datum_a and the value in datum_b.
pub const ArgCmp = extern struct {
    arg: c_uint,
    op: Op,
    datum_a: u64,
    datum_b: u64,
};

comptime {
    std.debug.assert(@sizeOf(ArgCmp) == 24);
    std.debug.assert(@offsetOf(ArgCmp, "datum_a") == 8);
}

/// __NR_SCMP_ERROR (seccomp.h:897): a name libseccomp does not know.
pub const nr_error: c_int = -1;

extern fn seccomp_init(def_action: u32) ?*Filter;
extern fn seccomp_release(ctx: *Filter) void;
extern fn seccomp_arch_native() u32;
extern fn seccomp_arch_add(ctx: *Filter, arch_token: u32) c_int;
extern fn seccomp_attr_set(ctx: *Filter, attr: Attr, value: u32) c_int;
extern fn seccomp_syscall_resolve_name(name: [*:0]const u8) c_int;
extern fn seccomp_rule_add_array(ctx: *Filter, action: u32, syscall: c_int, arg_cnt: c_uint, arg_array: [*]const ArgCmp) c_int;
extern fn seccomp_export_bpf(ctx: *const Filter, fd: c_int) c_int;

/// A libseccomp return code: null for 0, else the errno it negates. Every
/// failure libseccomp 2.6.1 returns is a negated errno; anything else is a
/// bug there, and a panic here, a refusal to the caller.
fn status(rc: c_int) ?sys.E {
    if (rc == 0) return null;
    if (rc < 0 and rc >= -0xffff) return @enumFromInt(@as(u16, @intCast(-rc)));
    std.debug.panic("libseccomp returned {d}", .{rc});
}

/// seccomp_init: a filter whose default action is `action`, or null.
pub fn init(action: u32) ?*Filter {
    return seccomp_init(action);
}

pub fn release(ctx: *Filter) void {
    seccomp_release(ctx);
}

pub fn archNative() u32 {
    return seccomp_arch_native();
}

pub fn archAdd(ctx: *Filter, arch: u32) ?sys.E {
    return status(seccomp_arch_add(ctx, arch));
}

pub fn attrSet(ctx: *Filter, attr: Attr, value: u32) ?sys.E {
    return status(seccomp_attr_set(ctx, attr, value));
}

/// The native number of `name`, a negative pseudo number, or nr_error.
pub fn resolveName(name: [*:0]const u8) c_int {
    return seccomp_syscall_resolve_name(name);
}

pub fn ruleAddArray(ctx: *Filter, action: u32, nr: c_int, cmps: []const ArgCmp) ?sys.E {
    return status(seccomp_rule_add_array(ctx, action, nr, @intCast(cmps.len), cmps.ptr));
}

/// Where a filter goes: stdout, or the project's temp file (ZIG.md, "Lint
/// and analysis": exportBpf is one of the ways a descriptor's number leaves
/// the table).
pub const Out = union(enum) {
    stdout,
    file: fd.File,
};

/// seccomp_export_bpf: the filter's bytes in one write (api.c:760, quirk
/// 17).
pub fn exportBpf(ctx: *const Filter, out: Out) ?sys.E {
    const n: c_int = switch (out) {
        .stdout => 1,
        .file => |f| f.raw(),
    };
    return status(seccomp_export_bpf(ctx, n));
}
