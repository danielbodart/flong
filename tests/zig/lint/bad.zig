//! Planted for fdlint, linted as src/lint/bad.zig, where every rule applies:
//! each line marked below must be reported at its column, and nothing in
//! comments or strings ("std.posix.close", "catch unreachable") may be.
//! Never compiled.
const std = @import("std");
const sys = @import("sys");
const fd = @import("fd");

const P = std.posix; // raw-namespace and posix: the alias is caught where it is made

pub fn viaAlias(n: i32) void {
    P.close(n); // not reported: P was caught above
}

pub fn raw(n: i32) usize {
    _ = std.os.linux.dup(n); // raw-namespace (os)
    _ = std.fs.cwd(); // raw-namespace (fs)
    _ = std.c.getpid(); // raw-namespace (c)
    std.process.exit(0); // raw-namespace (process)
}

pub fn posixElsewhere() void {
    _ = sys.linux.posix; // posix, though not after std.
}

extern fn getpid() c_int; // extern
extern "c" fn getuid() c_uint; // extern
extern var environ: [*:null]?[*:0]u8; // extern
export fn exported() void {} // extern
const sym = @extern(*const fn () void, .{ .name = "x" }); // extern
const c = @cImport(@cInclude("unistd.h")); // extern

pub fn number(h: fd.File) i32 {
    return h.raw(); // raw-number
}

pub fn args() usize {
    return sys.argv().len + sys.environ().len; // argv, argv
}

pub fn guts(h: fd.File) u32 {
    return h.slot + h.gen; // handle-guts, handle-guts
}

pub fn foreign() void {
    _ = fd.adoptForeign(3, .userns); // adopt-foreign
}

pub fn chatter() void {
    std.debug.print("x", .{}); // debug-output
    std.log.info("x", .{}); // debug-output
}

pub fn unproven(s: []const u8) u64 {
    return std.fmt.parseInt(u64, s, 10) catch unreachable; // catch-unreachable: no reason given
}

var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{}; // alloc
var dbg: std.heap.DebugAllocator(.{}) = .{}; // alloc
