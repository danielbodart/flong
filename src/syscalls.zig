//! syscalls.zig: the system calls of the architecture flong is built for,
//! by the names the kernel and libseccomp give them, which is what
//! `seccomp.syscalls` takes (decl.zig) and `flong check` judges a name by.
//!
//! The table is Zig's own, sys.SYS, corrected where it is not the
//! kernel's: it spells two calls its own way, and lags the kernel by the
//! calls added since it was written. tests/zig/libc_scmp.zig holds the
//! result to the libseccomp flong-seccomp links, both ways, so a Zig or a
//! libseccomp that moves either list fails test-libc rather than a
//! declaration's build.

const std = @import("std");
const builtin = @import("builtin");
const sys = @import("sys");

/// Zig's spelling of a call, and the kernel's, which systemd and
/// libseccomp use: on a 64-bit architecture `newfstatat` has no 64.
const respelt = [_]struct { zig: []const u8, kernel: []const u8 }{
    .{ .zig = "fstatat64", .kernel = "newfstatat" },
    .{ .zig = "sysctl", .kernel = "_sysctl" },
};

/// The calls this architecture has that Zig 0.15's table does not.
const newer: []const []const u8 = switch (builtin.cpu.arch) {
    .x86_64 => &.{ "file_getattr", "file_setattr", "listns", "rseq_slice_yield", "uprobe" },
    .aarch64 => &.{ "file_getattr", "file_setattr", "listns", "rseq_slice_yield" },
    else => &.{},
};

fn inTable(name: []const u8) bool {
    return std.meta.stringToEnum(sys.SYS, name) != null;
}

/// Whether `name` is a system call of this architecture, by the kernel's
/// name for it.
pub fn known(name: []const u8) bool {
    for (respelt) |r| {
        if (std.mem.eql(u8, name, r.zig)) return false;
        if (std.mem.eql(u8, name, r.kernel)) return inTable(r.zig);
    }
    for (newer) |n| if (std.mem.eql(u8, name, n)) return true;
    return inTable(name);
}

/// Every name `known` takes, for the test that holds them to libseccomp.
pub fn all(gpa: std.mem.Allocator) error{OutOfMemory}![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    inline for (@typeInfo(sys.SYS).@"enum".fields) |f| {
        const kernel = for (respelt) |r| {
            if (std.mem.eql(u8, f.name, r.zig)) break r.kernel;
        } else f.name;
        try out.append(gpa, kernel);
    }
    try out.appendSlice(gpa, newer);
    return out.toOwnedSlice(gpa);
}

test "the kernel's spelling, never Zig's own" {
    try std.testing.expect(known("read"));
    try std.testing.expect(known("ptrace"));
    try std.testing.expect(known("io_uring_setup"));
    try std.testing.expect(known("newfstatat"));
    try std.testing.expect(!known("fstatat64"));
    try std.testing.expect(!known("sysctl"));
    try std.testing.expect(!known("Ptrace"));
    try std.testing.expect(!known(""));
    try std.testing.expect(!known("@keyring"));
    try std.testing.expect(known("file_setattr"));
    const names = try all(std.testing.allocator);
    defer std.testing.allocator.free(names);
    for (names) |n| try std.testing.expect(known(n));
}
