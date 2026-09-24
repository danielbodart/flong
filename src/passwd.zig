//! passwd.zig: getpwuid's one use in the launcher, a user's name for the
//! refusal when there is no user manager (flong-cgroup.c:159-168), without
//! libc (ZIG.md, "Decided": no libc for flong-launch; quirk 19).
//!
//! glibc's getpwuid asks NSS, which on NixOS reads /etc/passwd ("files")
//! and then systemd's and any other module's users. This reads /etc/passwd
//! alone, so a user NSS alone knows gets the refusal's `uid N` form, which
//! the C gave only for a uid no module knew; the name form, the one the
//! tests assert, is unchanged (quirk 19, Change).
//!
//! A line is read as glibc's files module reads it (nss_files, files-pwd.c
//! through files-parse.c): leading blanks skipped, an empty line or one
//! starting with '#' skipped, then name, password, uid and gid separated by
//! ':', the rest not looked at. A line ends at a first NUL, as the C
//! string glibc parses does. The first line with the uid wins. Where
//! this is stricter than glibc's strtoul, a uid field that is not plain
//! decimal digits (a sign, a blank, one past 2^32 - 1) matches nothing. A
//! "+" or "-" entry, compat's, never matches, as in glibc.

const std = @import("std");
const fdt = @import("fd");

/// The name /etc/passwd gives `uid`, in `gpa`; null when it gives none or
/// cannot be read (getpwuid's NULL either way).
pub fn lookup(gpa: std.mem.Allocator, uid: u32) ?[]const u8 {
    const r = fdt.openFile(fdt.cwd, "/etc/passwd", .{}, 0) catch return null;
    const f = switch (r) {
        .ok => |f| f,
        .err => return null,
    };
    defer f.close();
    const text = switch (fdt.readAll(f, gpa) catch return null) {
        .ok => |t| t,
        .err => return null,
    };
    return nameOf(text, uid);
}

/// The name of the first entry of `text`, an /etc/passwd, whose uid is
/// `uid`. Any bytes are read without a panic.
pub fn nameOf(text: []const u8, uid: u32) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |whole| {
        // The line glibc parses is a C string: it ends at a first NUL.
        const raw = whole[0 .. std.mem.indexOfScalar(u8, whole, 0) orelse whole.len];
        const line = std.mem.trimLeft(u8, raw, " \t\r\x0b\x0c");
        if (line.len == 0 or line[0] == '#') continue;
        var fields = std.mem.splitScalar(u8, line, ':');
        const name = fields.next().?;
        _ = fields.next() orelse continue; // the password
        const u = number(fields.next() orelse continue) orelse continue;
        _ = number(fields.next() orelse continue) orelse continue; // the gid
        if (name.len > 0 and (name[0] == '+' or name[0] == '-')) continue;
        if (u == uid) return name;
    }
    return null;
}

/// A uid or gid field: decimal digits, at least one, within u32.
fn number(s: []const u8) ?u32 {
    if (s.len == 0) return null;
    for (s) |c| if (c < '0' or c > '9') return null;
    return std.fmt.parseUnsigned(u32, s, 10) catch null;
}

// ---- tests ----

const testing = std.testing;

test "nameOf reads /etc/passwd as glibc's files module does" {
    const text =
        \\# a comment
        \\root:x:0:0:System administrator:/root:/bin/sh
        \\
        \\   alice:x:1000:100::/home/alice:/bin/sh
        \\+nis:x:1001:100::/:/bin/sh
        \\short:x:1002
        \\badgid:x:1003:x::/:/bin/sh
        \\sign:x:+1004:100::/:/bin/sh
        \\big:x:4294967296:100::/:/bin/sh
        \\first:x:1005:100::/:/bin/sh
        \\second:x:1005:100::/:/bin/sh
        \\nofields:x:1006:100
        \\
    ;
    try testing.expectEqualStrings("root", nameOf(text, 0).?);
    try testing.expectEqualStrings("alice", nameOf(text, 1000).?);
    try testing.expectEqual(@as(?[]const u8, null), nameOf(text, 1001));
    try testing.expectEqual(@as(?[]const u8, null), nameOf(text, 1002));
    try testing.expectEqual(@as(?[]const u8, null), nameOf(text, 1003));
    try testing.expectEqual(@as(?[]const u8, null), nameOf(text, 1004));
    try testing.expectEqual(@as(?[]const u8, null), nameOf(text, 0xffffffff));
    try testing.expectEqualStrings("first", nameOf(text, 1005).?);
    try testing.expectEqualStrings("nofields", nameOf(text, 1006).?);
    try testing.expectEqual(@as(?[]const u8, null), nameOf(text, 4242));
    try testing.expectEqual(@as(?[]const u8, null), nameOf("", 0));
    try testing.expectEqualStrings("nonl", nameOf("nonl:x:7:7", 7).?);
    try testing.expectEqualStrings("crlf", nameOf("crlf:x:8:8:\r\n", 8).?);
    // A NUL ends the line: the name before it has no fields, and the
    // fields after it are not read.
    try testing.expectEqual(@as(?[]const u8, null), nameOf("nul\x00:x:9:9:\n", 9));
    try testing.expectEqual(@as(?[]const u8, null), nameOf("nul:x:9\x00:9:\n", 9));
    try testing.expectEqualStrings("nulgid", nameOf("nulgid:x:10:10\x00junk\n", 10).?);
    try testing.expectEqual(@as(?[]const u8, null), nameOf("\x00a:x:11:11\n", 11));
}

test "nameOf on hostile bytes: no panic, and a name is a field of the text" {
    // Lines of fields, each field a few pieces: digits, signs, blanks,
    // NULs, colons and newlines of their own, and random bytes.
    const pieces = [_][]const u8{ "", "0", "1", "7", "12", "007", "4294967296", "+", "-", "#", " ", "\t", "\x00", "x", "nm", ":", "\n" };
    var prng = std.Random.DefaultPrng.init(0xf1_0e6);
    const r = prng.random();
    var buf: [1024]u8 = undefined; // at most 6 lines of 6 fields of 2 pieces of 10 bytes, with separators
    var found: usize = 0;
    for (0..20_000) |_| {
        var n: usize = 0;
        for (0..r.uintAtMost(usize, 6)) |line| {
            if (line > 0) {
                buf[n] = '\n';
                n += 1;
            }
            for (0..r.uintAtMost(usize, 6)) |field| {
                if (field > 0) {
                    buf[n] = ':';
                    n += 1;
                }
                for (0..r.uintAtMost(usize, 2)) |_| {
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
        }
        const uid = r.uintAtMost(u32, 12);
        const name = nameOf(buf[0..n], uid) orelse continue;
        found += 1;
        // A slice of the text, holding none of the bytes that end it.
        const at = @intFromPtr(name.ptr) - @intFromPtr(&buf);
        try testing.expect(at + name.len <= n);
        try testing.expect(std.mem.indexOfAny(u8, name, ":\n\x00") == null);
        try testing.expect(name.len == 0 or (name[0] != '+' and name[0] != '-' and name[0] != '#'));
    }
    // The pieces reach a match (about 36 of the 20,000).
    try testing.expect(found >= 10);
}
