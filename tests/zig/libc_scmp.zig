//! test-libc: src/seccomp/scmp.zig against seccomp.h, through translate-c
//! of the libseccomp flong-seccomp links (ZIG.md, "Tests"): every constant,
//! the struct's layout, the enum values, each extern's arity, and the calls
//! themselves, once, as flong-seccomp and bpfdump make them.

const std = @import("std");
const scmp = @import("scmp");
const h = @import("seccomp_h");

const testing = std.testing;

test "the actions" {
    try testing.expectEqual(@as(u32, h.SCMP_ACT_ALLOW), scmp.act_allow);
    try testing.expectEqual(@as(u32, h.SCMP_ACT_LOG), scmp.act_log);
    // SCMP_ACT_ERRNO is a macro translate-c renders as a function; every
    // value flong-seccomp can pass, and the bits it drops beyond.
    var x: u32 = 0;
    while (x <= 0x1ffff) : (x += 1) {
        try testing.expectEqual(@as(u32, h.SCMP_ACT_ERRNO(x)), scmp.actErrno(x));
    }
    try testing.expectEqual(@as(u32, h.SCMP_ACT_ERRNO(0xffffffff)), scmp.actErrno(0xffffffff));
}

test "the arches, the attribute, the error number" {
    try testing.expectEqual(@as(u32, h.flong_arch_x86_64), scmp.arch_x86_64);
    try testing.expectEqual(@as(u32, h.flong_arch_x86), scmp.arch_x86);
    try testing.expectEqual(@as(u32, h.flong_arch_x32), scmp.arch_x32);
    try testing.expectEqual(@as(c_uint, h.SCMP_FLTATR_CTL_OPTIMIZE), @intFromEnum(scmp.Attr.ctl_optimize));
    try testing.expectEqual(@as(c_int, h.__NR_SCMP_ERROR), scmp.nr_error);
}

test "the comparisons" {
    try testing.expectEqual(@as(c_uint, h.SCMP_CMP_NE), @intFromEnum(scmp.Op.ne));
    try testing.expectEqual(@as(c_uint, h.SCMP_CMP_LT), @intFromEnum(scmp.Op.lt));
    try testing.expectEqual(@as(c_uint, h.SCMP_CMP_LE), @intFromEnum(scmp.Op.le));
    try testing.expectEqual(@as(c_uint, h.SCMP_CMP_EQ), @intFromEnum(scmp.Op.eq));
    try testing.expectEqual(@as(c_uint, h.SCMP_CMP_GE), @intFromEnum(scmp.Op.ge));
    try testing.expectEqual(@as(c_uint, h.SCMP_CMP_GT), @intFromEnum(scmp.Op.gt));
    try testing.expectEqual(@as(c_uint, h.SCMP_CMP_MASKED_EQ), @intFromEnum(scmp.Op.masked_eq));
    try testing.expectEqual(@sizeOf(h.enum_scmp_compare), @sizeOf(scmp.Op));
    try testing.expectEqual(@sizeOf(h.enum_scmp_filter_attr), @sizeOf(scmp.Attr));
}

test "struct scmp_arg_cmp" {
    const C = h.struct_scmp_arg_cmp;
    try testing.expectEqual(@sizeOf(C), @sizeOf(scmp.ArgCmp));
    try testing.expectEqual(@alignOf(C), @alignOf(scmp.ArgCmp));
    inline for (.{ "arg", "op", "datum_a", "datum_b" }) |f| {
        try testing.expectEqual(@offsetOf(C, f), @offsetOf(scmp.ArgCmp, f));
        try testing.expectEqual(@sizeOf(@FieldType(C, f)), @sizeOf(@FieldType(scmp.ArgCmp, f)));
    }
}

test "each extern takes what seccomp.h says" {
    inline for (.{
        .{ "seccomp_init", 1 },
        .{ "seccomp_release", 1 },
        .{ "seccomp_arch_native", 0 },
        .{ "seccomp_arch_add", 2 },
        .{ "seccomp_attr_set", 3 },
        .{ "seccomp_syscall_resolve_name", 1 },
        .{ "seccomp_rule_add_array", 5 },
        .{ "seccomp_export_bpf", 2 },
        .{ "seccomp_syscall_resolve_num_arch", 2 },
        .{ "free", 1 },
    }) |f| {
        const info = @typeInfo(@TypeOf(@field(h, f[0]))).@"fn";
        try testing.expectEqual(@as(usize, f[1]), info.params.len);
    }
}

test "each extern's parameters and return" {
    // bpfdump's two, whose pointer types are what could go wrong: a
    // uint32_t and an int in, a char * out; a void * in.
    const r = @typeInfo(@TypeOf(h.seccomp_syscall_resolve_num_arch)).@"fn";
    try testing.expectEqual(u32, r.params[0].type.?);
    try testing.expectEqual(c_int, r.params[1].type.?);
    try testing.expectEqual(@sizeOf(usize), @sizeOf(r.return_type.?));
    const f = @typeInfo(@TypeOf(h.free)).@"fn";
    try testing.expectEqual(@sizeOf(usize), @sizeOf(f.params[0].type.?));
}

test "the names, as bpfdump asks for them" {
    // bpfdump.c:293: a number on each of its three arches, x32's biased.
    for ([_]struct { arch: u32, nr: c_int, want: ?[]const u8 }{
        .{ .arch = scmp.arch_x86_64, .nr = 0, .want = "read" },
        .{ .arch = scmp.arch_x86_64, .nr = 59, .want = "execve" },
        .{ .arch = scmp.arch_x32, .nr = 0x40000000 + 1, .want = "write" },
        .{ .arch = scmp.arch_x86, .nr = 11, .want = "execve" },
        .{ .arch = scmp.arch_x86_64, .nr = 1023, .want = null },
    }) |c| {
        const got = scmp.resolveNumArch(c.arch, c.nr);
        defer scmp.freeName(got);
        const want_c = h.seccomp_syscall_resolve_num_arch(c.arch, c.nr);
        defer h.free(want_c);
        if (c.want) |w| {
            try testing.expectEqualStrings(w, std.mem.span(got.?));
            try testing.expectEqualStrings(w, std.mem.span(want_c.?));
        } else {
            try testing.expect(got == null);
            try testing.expect(want_c == null);
        }
    }
    scmp.freeName(null);
}

test "the calls, as flong-seccomp makes them" {
    const ctx = scmp.init(scmp.actErrno(38)) orelse return error.NoFilter;
    defer scmp.release(ctx);
    if (scmp.archNative() == scmp.arch_x86_64) {
        try testing.expectEqual(@as(?std.os.linux.E, null), scmp.archAdd(ctx, scmp.arch_x86));
        try testing.expectEqual(@as(?std.os.linux.E, null), scmp.archAdd(ctx, scmp.arch_x32));
    }
    try testing.expectEqual(@as(?std.os.linux.E, null), scmp.attrSet(ctx, .ctl_optimize, 2));
    try testing.expectEqual(h.seccomp_syscall_resolve_name("read"), scmp.resolveName("read"));
    try testing.expectEqual(scmp.nr_error, scmp.resolveName("no_such_call"));
    const nr = scmp.resolveName("ioctl");
    try testing.expectEqual(@as(?std.os.linux.E, null), scmp.ruleAddArray(ctx, scmp.act_allow, nr, &.{
        .{ .arg = 1, .op = .masked_eq, .datum_a = 0xffffffff, .datum_b = 0x5401 },
    }));
    // A rule repeating the default: libseccomp's EACCES, which
    // compile.zig names.
    try testing.expectEqual(@as(?std.os.linux.E, .ACCES), scmp.ruleAddArray(ctx, scmp.actErrno(38), scmp.resolveName("read"), &.{}));
}
