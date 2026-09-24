//! names.zig: machine and container names (flong-util.c:220-233,
//! flong-util.h:71-78).
//!
//! A name becomes a record's file name and a cgroup's, so it holds no '/',
//! and it never starts with '.', which rules out "." and ".." and keeps it
//! clear of dot files.

const std = @import("std");

/// FL_NAME_MAX: the longest machine or container name.
pub const name_max = 128;

/// fl_is_name: [A-Za-z0-9_-][A-Za-z0-9_.-]{0,name_max-1}.
pub fn isName(s: []const u8) bool {
    if (s.len == 0 or s.len > name_max or s[0] == '.') return false;
    for (s) |c| {
        switch (c) {
            'A'...'Z', 'a'...'z', '0'...'9', '_', '-', '.' => {},
            else => return false,
        }
    }
    return true;
}

const testing = std.testing;

test "names" {
    for ([_][]const u8{ "a", "demo-1", "A_b.c-9", "-x", "x.", "a" ** 128 }) |s| try testing.expect(isName(s));
    for ([_][]const u8{ "", ".", "..", ".x", "a/b", "a b", "a\x00", "é", "a" ** 129, "#123" }) |s| try testing.expect(!isName(s));
}
