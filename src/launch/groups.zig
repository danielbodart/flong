//! launch/groups.zig: the payload's groups, from the prepared root's
//! /etc/group (rootless-wrapper.bash:353-358), for `flong launch`
//! (STANDALONE.md, "`flong launch DECL.zon -- ARGS`": the payload's
//! identity). flong-init sets exactly these, so the caller's host groups
//! never reach the payload.
//!
//! The primary gid first, then the gid of every line whose member list
//! names the user, in file order. The wrapper reads the file with
//! `while IFS=: read -r _ _ g m` and tests `,$m, == *,"$user",*`; this
//! reads it as bash does, not as glibc's files module would (passwd.zig
//! does that, for getpwuid): the two differ, and it is the wrapper's
//! reading the payload got.
//!
//!   - a line is what ends in a newline; a last line without one is read,
//!     but read fails, so the loop ends before its body sees it (:356, 358);
//!   - a NUL is dropped, not a line's end: bash's read skips it, where
//!     glibc's parser stops at it;
//!   - IFS is ':' alone, so nothing is trimmed: a blank next to a name is
//!     part of it, and names no one;
//!   - no line is skipped: a '#' comment, a "+"/"-" compat entry and an
//!     empty line are read like any other, and give a group when their
//!     fields say so, where glibc skips all three;
//!   - `m` is the rest of the line after the third ':', the one ':' ending
//!     it dropped only when it ends a single word (see `fields`);
//!   - `-r` keeps a backslash as itself.
//!
//! The match is a substring test on ",$m,": a member is named when
//! ",$user," appears in it, which for a name without a ',' is a member of
//! the ','-separated list equal to it. A gid is kept as its field's text,
//! unchecked, and one equal to the primary gid's text is left out; any
//! other, the same number spelt differently included, is added, repeats
//! too (:357). What is not a gid the spec refused, as it refuses an
//! unmapped one.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// The groups the wrapper gives the payload (:355-358): `gid`, the
/// primary gid's text from the prepared root's passwd, first, then the gid
/// field of each line of `text`, an /etc/group, whose member list names
/// `user` and whose gid is not `gid`, in file order. The list is `gpa`'s,
/// an arena's; a gid is a slice of `text`, or of a copy of its line in
/// `gpa` when the line has a NUL.
pub fn of(gpa: Allocator, text: []const u8, user: []const u8, gid: []const u8) Allocator.Error![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    try list.append(gpa, gid);
    var rest = text;
    while (std.mem.indexOfScalar(u8, rest, '\n')) |end| {
        const line = try dropNul(gpa, rest[0..end]);
        rest = rest[end + 1 ..];
        _, _, const g, const m = fields(4, line);
        if (names(m, user) and !std.mem.eql(u8, g, gid)) try list.append(gpa, g);
    }
    return list.toOwnedSlice(gpa);
}

/// `[[ ,$m, == *,"$user",* ]]` (:357): the quoted user is literal, so this
/// is whether ",user," is a substring of ",m,", searched without making
/// either.
fn names(m: []const u8, user: []const u8) bool {
    const v = m.len + 2; // ",m,"
    const u = user.len + 2; // ",user,"
    if (u > v) return false;
    for (0..v - u + 1) |p| {
        for (0..u) |i| {
            const want = if (i == 0 or i == u - 1) ',' else user[i - 1];
            const got = if (p + i == 0 or p + i == v - 1) ',' else m[p + i - 1];
            if (want != got) break;
        } else return true;
    }
    return false;
}

/// `IFS=: read -r` into `n` names over one line (bash's read.def): each
/// name but the last takes the text up to the next ':', or all that is
/// left, and the names after the text runs out are empty. The last takes
/// the rest, dropping the ':' after it only when the rest is one word and
/// that ':' (so "g:x:1:alice:" gives m "alice", but "g:x:1:alice::" gives
/// "alice::" and "g:x:1:alice:bob:" gives "alice:bob:"). subid.zig reads
/// its files the same way.
fn fields(comptime n: usize, line: []const u8) [n][]const u8 {
    var out: [n][]const u8 = @splat("");
    var rest = line;
    for (out[0 .. n - 1]) |*f| {
        const at = std.mem.indexOfScalar(u8, rest, ':') orelse {
            f.* = rest;
            return out;
        };
        f.* = rest[0..at];
        rest = rest[at + 1 ..];
    }
    const at = std.mem.indexOfScalar(u8, rest, ':');
    out[n - 1] = if (at != null and at.? + 1 == rest.len) rest[0..at.?] else rest;
    return out;
}

/// `line` without its NULs, which bash's read drops: `line` itself when it
/// has none, else a copy in `gpa`.
fn dropNul(gpa: Allocator, line: []const u8) Allocator.Error![]const u8 {
    if (std.mem.indexOfScalar(u8, line, 0) == null) return line;
    const copy = try gpa.alloc(u8, line.len - std.mem.count(u8, line, "\x00"));
    var i: usize = 0;
    for (line) |b| {
        if (b == 0) continue;
        copy[i] = b;
        i += 1;
    }
    return copy;
}

// ---- tests ----

const testing = std.testing;

/// The groups `of` gives, space-separated, as the wrapper's
/// `printf ' %s' "${groups[@]}"` would print them.
fn expectGroups(expected: []const u8, text: []const u8, user: []const u8, gid: []const u8) !void {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const list = try of(arena.allocator(), text, user, gid);
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    for (list) |g| try w.print(" {s}", .{g});
    try testing.expectEqualStrings(expected, w.buffered());
}

test "of: the primary gid first, then each group naming the user, in file order" {
    const text =
        \\root:x:0:
        \\wheel:x:1:alice,bob
        \\users:x:100:
        \\audio:x:17:bob
        \\video:x:26:bob,alice
        \\kvm:x:302:carol,alice,dave
        \\alice:x:1000:
        \\
    ;
    try expectGroups(" 100 1 26 302", text, "alice", "100");
    try expectGroups(" 100 1 17 26", text, "bob", "100");
    try expectGroups(" 100 302", text, "carol", "100");
    try expectGroups(" 1000", text, "eve", "1000");
    try expectGroups(" 100", "", "alice", "100");
    // The primary group named in its own member list is not repeated.
    try expectGroups(" 100 1", "users:x:100:alice\nwheel:x:1:alice\n", "alice", "100");
}

test "of: a member is a whole name in the list" {
    const cases = [_]struct { m: []const u8, named: bool }{
        .{ .m = "alice", .named = true },
        .{ .m = "alice,bob", .named = true },
        .{ .m = "bob,alice", .named = true },
        .{ .m = "bob,alice,carol", .named = true },
        .{ .m = ",alice,", .named = true },
        .{ .m = "alice,alice", .named = true },
        .{ .m = "alic", .named = false },
        .{ .m = "alicex", .named = false },
        .{ .m = "xalice", .named = false },
        .{ .m = "bob,alicex,carol", .named = false },
        .{ .m = "bob,xalice", .named = false },
        .{ .m = " alice", .named = false },
        .{ .m = "alice ", .named = false },
        .{ .m = "bob, alice", .named = false },
        .{ .m = "", .named = false },
        .{ .m = ",", .named = false },
    };
    for (cases) |c| try testing.expectEqual(c.named, names(c.m, "alice"));
    // An empty user is named by an empty list or an empty member, as
    // ",," holds ",,".
    try testing.expect(names("", ""));
    try testing.expect(names("a,,b", ""));
    try testing.expect(names("a,", ""));
    try testing.expect(!names("a", ""));
    // A user with a ',' is a substring test across members, as the glob is.
    try testing.expect(names("x,a,b,y", "a,b"));
    try testing.expect(!names("a,bb", "a,b"));
}

test "of: the member list is the rest of the line" {
    // One ':' after a single word is dropped; anything more stays, and the
    // ':' then joins the last name to what follows it.
    try expectGroups(" 100 1", "wheel:x:1:alice:\n", "alice", "100");
    try expectGroups(" 100", "wheel:x:1:alice::\n", "alice", "100");
    try expectGroups(" 100", "wheel:x:1:alice:bob\n", "alice", "100");
    try expectGroups(" 100 1", "wheel:x:1:bob,alice,carol:x\n", "alice", "100");
    try expectGroups(" 100", "wheel:x:1:bob,alice:x\n", "alice", "100");
    // Too few fields: no member list.
    try expectGroups(" 100", "wheel:x:1\nwheel:x\nwheel\n\n", "alice", "100");
}

test "of: bash's read, not glibc's files module" {
    // The last line has no newline: read fails on it, and the loop ends
    // before its body sees it.
    try expectGroups(" 100", "wheel:x:1:alice", "alice", "100");
    try expectGroups(" 100 17", "audio:x:17:alice\nwheel:x:1:alice", "alice", "100");
    // No line is skipped: a comment, a compat entry and a line that starts
    // with a blank are read like the rest.
    try expectGroups(" 100 1 2 3", "#wheel:x:1:alice\n+nis:x:2:alice\n  sp:x:3:alice\n", "alice", "100");
    // A '\r' is part of the list's last member.
    try expectGroups(" 100", "wheel:x:1:alice\r\n", "alice", "100");
    try expectGroups(" 100 1", "wheel:x:1:alice,\r\n", "alice", "100");
    // A NUL is dropped, where glibc would end the line at it.
    try expectGroups(" 100 1", "wheel:x:1:al\x00ice\n", "alice", "100");
    try expectGroups(" 100 17", "audio:x:1\x007:bob,alice\x00\n", "alice", "100");
    // -r: a backslash is itself.
    try expectGroups(" 100 1", "wheel:x:1:al\\ice\n", "al\\ice", "100");
}

test "of: a gid is its field's text" {
    // Compared as text with the primary gid's, and added whatever it
    // holds: the spec refused what is not a number.
    try expectGroups(" 100 0100", "users:x:0100:alice\n", "alice", "100");
    try expectGroups(" 100 ", "empty:x::alice\n", "alice", "100");
    try expectGroups(" 100 x", "word:x:x:alice\n", "alice", "100");
    try expectGroups(" 100  17", "blank:x: 17:alice\n", "alice", "100");
    // Twice in the file, twice in the list.
    try expectGroups(" 100 1 1", "wheel:x:1:alice\nwheel:x:1:alice\n", "alice", "100");
}

test "of on hostile bytes: no panic, and every group is a field naming the user" {
    // Lines of fields, each field a few pieces: names, lists, gids, blanks,
    // NULs, colons and newlines of their own, and random bytes.
    const pieces = [_][]const u8{ "", "alice", "bob", ",", "alice,bob", "1", "100", "x", "#", "+", " ", "\x00", "\\", ":", "\n" };
    var prng = std.Random.DefaultPrng.init(0x6_0f0);
    const r = prng.random();
    var buf: [1024]u8 = undefined; // at most 4 lines of 5 fields of 2 pieces of 9 bytes, with separators
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var found: usize = 0;
    for (0..20_000) |_| {
        _ = arena.reset(.retain_capacity);
        var n: usize = 0;
        for (0..r.uintAtMost(usize, 4)) |_| {
            for (0..r.uintAtMost(usize, 5)) |field| {
                if (field > 0) {
                    buf[n] = ':';
                    n += 1;
                }
                for (0..r.intRangeAtMost(usize, 1, 2)) |_| {
                    const i = r.uintAtMost(usize, pieces.len);
                    if (i == pieces.len) {
                        buf[n] = r.int(u8);
                        n += 1;
                    } else {
                        @memcpy(buf[n..][0..pieces[i].len], pieces[i]);
                        n += pieces[i].len;
                    }
                }
            }
            buf[n] = '\n';
            n += 1;
        }
        const list = try of(arena.allocator(), buf[0..n], "alice", "100");
        try testing.expectEqualStrings("100", list[0]);
        for (list[1..]) |g| {
            found += 1;
            try testing.expect(!std.mem.eql(u8, g, "100"));
            try testing.expect(std.mem.indexOfAny(u8, g, ":\n\x00") == null);
        }
    }
    try testing.expect(found >= 10);
}
