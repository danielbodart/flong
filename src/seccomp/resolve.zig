//! resolve.zig: `flong-seccomp resolve ARCH NR`, the name of syscall NR on
//! ARCH, one line on stdout, as libseccomp's own table has it: what a
//! `log` rule's audit record (type=1326) names by number, turned back into
//! the names a policy is written in. ARCH and NR are the record's `arch=`
//! and `syscall=` as the kernel prints them: ARCH the audit arch in hex,
//! with or without `0x`, in either case (c000003e for x86_64, 40000003 for
//! i386), NR in decimal. An x32 call is reported under x86_64's arch, its
//! number carrying __X32_SYSCALL_BIT (0x40000000), and is resolved as x32;
//! x32's own token, 4000003e, is taken too.
//!
//! A number libseccomp does not know on ARCH, or an ARCH it does not know,
//! is said and exits 1; a malformed argument is a usage error, exit 2.

const std = @import("std");
const msg = @import("msg");
const fd = @import("fd");
const scmp = @import("scmp.zig");

pub const prog = "flong-seccomp-resolve";

const usage = "usage: flong-seccomp resolve ARCH NR";

/// __X32_SYSCALL_BIT (asm/unistd.h).
const x32_bit: u32 = 0x40000000;

/// ARCH as audit prints it: hex, at most 32 bits, `0x` allowed.
fn parseArch(s: []const u8) ?u32 {
    const digits = if (std.mem.startsWith(u8, s, "0x") or std.mem.startsWith(u8, s, "0X")) s[2..] else s;
    if (digits.len == 0 or digits.len > 8) return null;
    for (digits) |c| if (!std.ascii.isHex(c)) return null;
    return std.fmt.parseInt(u32, digits, 16) catch null;
}

/// NR as audit prints it: decimal, no sign, at most 32 bits.
fn parseNr(s: []const u8) ?u32 {
    if (s.len == 0 or s.len > 10) return null;
    for (s) |c| if (!std.ascii.isDigit(c)) return null;
    return std.fmt.parseInt(u32, s, 10) catch null;
}

/// The arch and number libseccomp is asked about: an x86_64 record's x32
/// call becomes x32's token, its number kept, as libseccomp's x32 table
/// holds it with the bit.
fn target(arch: u32, nr: u32) struct { u32, u32 } {
    if (arch == scmp.arch_x86_64 and nr & x32_bit != 0) return .{ scmp.arch_x32, nr };
    return .{ arch, nr };
}

/// The name, in `buf`, or null when libseccomp knows none.
pub fn resolve(buf: []u8, arch: u32, nr: u32) ?[]const u8 {
    const t = target(arch, nr);
    if (t[1] > std.math.maxInt(c_int)) return null;
    const name = scmp.resolveNumArch(t[0], @intCast(t[1])) orelse return null;
    defer scmp.freeName(name);
    const n = std.mem.span(name);
    if (n.len > buf.len) return null;
    @memcpy(buf[0..n.len], n);
    return buf[0..n.len];
}

/// `flong-seccomp resolve ARCH NR`: its exit status.
pub fn main(args: []const [*:0]const u8) u8 {
    if (args.len != 2) {
        msg.bare(usage, .{});
        return 2;
    }
    msg.prog = prog;
    const arch_word = std.mem.span(args[0]);
    const nr_word = std.mem.span(args[1]);
    const arch = parseArch(arch_word) orelse {
        msg.say("not an audit arch in hex: {s}", .{arch_word});
        return 2;
    };
    const nr = parseNr(nr_word) orelse {
        msg.say("not a syscall number: {s}", .{nr_word});
        return 2;
    };
    var buf: [128]u8 = undefined;
    const name = resolve(&buf, arch, nr) orelse {
        msg.say("no syscall {d} on arch {x:0>8}", .{ nr, arch });
        return 1;
    };
    buf[name.len] = '\n';
    msg.check(fd.Stdio.out.writeAll(buf[0 .. name.len + 1]), "writing the name", .{}) catch return 1;
    return 0;
}

// ---- tests ----

const testing = std.testing;

test "ARCH and NR read as audit prints them" {
    try testing.expectEqual(@as(?u32, 0xc000003e), parseArch("c000003e"));
    try testing.expectEqual(@as(?u32, 0xc000003e), parseArch("0xC000003E"));
    try testing.expectEqual(@as(?u32, 0x40000003), parseArch("40000003"));
    for ([_][]const u8{ "", "0x", "c000003e0", "x86_64", "-1", " c000003e", "c000003e\n" }) |s|
        try testing.expectEqual(@as(?u32, null), parseArch(s));
    try testing.expectEqual(@as(?u32, 101), parseNr("101"));
    try testing.expectEqual(@as(?u32, 0x40000209), parseNr("1073742345"));
    for ([_][]const u8{ "", "-1", "+1", "0x65", "4294967296", "1 " }) |s|
        try testing.expectEqual(@as(?u32, null), parseNr(s));
}

test "a number named on each arch" {
    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings("read", resolve(&buf, scmp.arch_x86_64, 0).?);
    try testing.expectEqualStrings("ptrace", resolve(&buf, scmp.arch_x86_64, 101).?);
    // i386's own table: 26 is ptrace there, 0 restart_syscall.
    try testing.expectEqualStrings("ptrace", resolve(&buf, scmp.arch_x86, 26).?);
    try testing.expectEqualStrings("restart_syscall", resolve(&buf, scmp.arch_x86, 0).?);
    // x32 as audit reports it, under x86_64 with the bit: 521 is x32's
    // ptrace, and 0 its read.
    try testing.expectEqualStrings("ptrace", resolve(&buf, scmp.arch_x86_64, x32_bit | 521).?);
    try testing.expectEqualStrings("read", resolve(&buf, scmp.arch_x86_64, x32_bit | 0).?);
    try testing.expectEqualStrings("ptrace", resolve(&buf, scmp.arch_x32, x32_bit | 521).?);
    // Numbers and arches libseccomp does not know.
    try testing.expectEqual(@as(?[]const u8, null), resolve(&buf, scmp.arch_x86_64, 4000));
    try testing.expectEqual(@as(?[]const u8, null), resolve(&buf, 0x12345678, 0));
    try testing.expectEqual(@as(?[]const u8, null), resolve(&buf, scmp.arch_x86_64, 0xffffffff));
}
