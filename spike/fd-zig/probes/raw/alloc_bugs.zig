const std = @import("std");

// BUG: plain leak (allocator) — does the engine report leaks at all?
pub fn plainLeak(a: std.mem.Allocator) !void {
    const p = try a.create(u32);
    p.* = 1;
}

// BUG: leak on the error path
pub fn leakOnError(a: std.mem.Allocator, fail: bool) !*u32 {
    const p = try a.create(u32);
    if (fail) return error.Nope;
    return p;
}

// BUG: double free
pub fn doubleFree(a: std.mem.Allocator) !void {
    const p = try a.create(u32);
    a.destroy(p);
    a.destroy(p);
}
