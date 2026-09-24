//! Planted for fdlint, linted as src/seccomp/scmp.zig, where `export` is
//! allowed: nothing here may be reported. Never compiled.
const std = @import("std");
const builtin = @import("builtin");
const sys = @import("sys");

const Job = extern struct { a: u32, b: u32 };
const Tag = extern union { n: u32, f: f32 };
const Kind = enum(u8) { a, b };

export fn planted_export(job: *const Job, tracing: c_int) callconv(.c) noreturn {
    _ = job;
    _ = tracing;
    if (builtin.os.tag != .linux) @compileError("Linux only");
    const n = std.fmt.parseInt(u8, "7", 10) catch unreachable; // proven: a literal in range
    sys.exitGroup(n);
}

// std.posix.close(3), "std.os.linux", sys.argv(): in a comment and a string.
const text = "std.posix.close(3); catch unreachable; h.raw(); std.debug.print";
