// src/decl.zig's place in decl_undocumented.zig: `shell` has no doc comment.

pub const Command = []const [:0]const u8;

pub const Declaration = struct {
    /// Documented.
    user: []const u8,
    shell: []const u8 = "",

    pub const computed = [_][]const u8{};
};
