//! Planted for fdlint: every marked line must be reported, and nothing in
//! comments or strings ("std.posix.close") may be.
const std = @import("std");
const fd = @import("fd");

pub fn rawClose(n: i32) void {
    std.posix.close(n); // L1 raw-namespace
}

const P = std.posix; // L2 raw-namespace: the alias is caught where it is made

pub fn viaAlias(n: i32) void {
    P.close(n); // not reported: P was caught above
}

pub fn stdFile() !void {
    const f = try std.fs.cwd().openFile("/etc/hostname", .{}); // L3 raw-namespace
    f.close();
}

pub fn linuxDup(n: i32) usize {
    return std.os.linux.dup(n); // L4 raw-namespace (os)
}

pub fn guts(h: fd.File) u8 {
    return h.slot; // L5 handle-guts
}

pub fn forge() fd.File {
    return .{ .slot = 0, .gen = 0 }; // L6, L7 handle-guts: a forged handle
}

const c = @cImport(@cInclude("unistd.h")); // L8 cimport
