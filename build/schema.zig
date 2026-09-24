//! schema.zig: decl-options.json on stdout, from decl_docs.writeSchema, for
//! `zig build schema`, which writes it to the repository's root. Built for
//! the host and never shipped, until `flong schema` prints the same bytes.

const std = @import("std");
const decl_docs = @import("decl_docs");

pub fn main() !void {
    var buf: [4096]u8 = undefined;
    var out = std.fs.File.stdout().writer(&buf);
    try decl_docs.writeSchema(&out.interface);
    try out.interface.flush();
}
