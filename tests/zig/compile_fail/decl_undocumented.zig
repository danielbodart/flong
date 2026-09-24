// Must not compile: a declaration field with no doc comment, which is the
// option's only description (DESIGN.md, "The declaration"). The build
// harvests decl_undocumented/decl.zig in src/decl.zig's place.
const std = @import("std");
const decl_docs = @import("decl_docs");

export fn bug() void {
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    decl_docs.writeSchema(&w) catch {};
}
