//! schema.zig: decl-options.json on stdout, from decl_docs.writeSchema, or
//! with `reference`, docs/declaration.md, from decl_docs.writeReference,
//! for `zig build schema`, which writes both to the repository. Built for
//! the host and never shipped; `flong schema` and `flong help decl
//! --markdown` print the same bytes.

const std = @import("std");
const decl_docs = @import("decl_docs");

pub fn main() !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const args = try std.process.argsAlloc(arena_state.allocator());
    var buf: [4096]u8 = undefined;
    var out = std.fs.File.stdout().writer(&buf);
    if (args.len == 2 and std.mem.eql(u8, args[1], "reference")) {
        try decl_docs.writeReference(&out.interface, .markdown);
    } else if (args.len == 1) {
        try decl_docs.writeSchema(&out.interface);
    } else {
        std.debug.print("usage: flong-schema [reference]\n", .{});
        std.process.exit(2);
    }
    try out.interface.flush();
}
