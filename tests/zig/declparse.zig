//! flong-decl-parse: src/decl.zig's `load` over each file named, the parse
//! `flong check` and `flong launch` make of a declaration, for the
//! decl-render check (tests/decl-render.nix), which runs it over every test
//! declaration module.nix renders. Built for the host by `zig build
//! decl-parse` and never shipped: `flong check` takes its place in each
//! declaration's derivation (STANDALONE.md, S2).
//!
//!   flong-decl-parse FILE...
//!       prints "ok FILE" for each file that parses; says each one that
//!       does not as `FILE:line:col: why`, and the status is then 1
const std = @import("std");
const sys = @import("sys");
const msg = @import("msg");
const decl = @import("decl");

pub const panic = std.debug.FullPanic(msg.onPanic(125));
pub const std_options: std.Options = .{ .enable_segfault_handler = false };

pub fn main() void {
    msg.prog = "flong-decl-parse";
    const argv = sys.argv();
    if (argv.len < 2) {
        msg.bare("usage: flong-decl-parse FILE...", .{});
        sys.exitGroup(2);
    }
    var status: u8 = 0;
    for (argv[1..]) |arg| {
        var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena_state.deinit();
        const path = std.mem.span(arg);
        if (decl.load(arena_state.allocator(), path)) |_| {
            msg.bare("ok {s}", .{path});
        } else |err| {
            // load has said why, but for an allocation that failed.
            if (err == error.OutOfMemory) msg.say("{s}: out of memory", .{path});
            status = 1;
        }
    }
    sys.exitGroup(status);
}
