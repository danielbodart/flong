//! launch/subid.zig: the maps (rootless-wrapper.bash:234-275), for
//! `flong launch` (STANDALONE.md, "`flong launch DECL.zon -- ARGS`": the
//! maps). Two parts, both pure:
//!
//!   find      the caller's entry in /etc/subuid or /etc/subgid, as the
//!             wrapper's loops find it (:238-250)
//!   buildMap  fl_map (:255-268): a container id onto the caller's, the ids
//!             around it filled from the entry, as IN OUT COUNT extents
//!
//! The wrapper reads each file with `while IFS=: read -r n s c`, and this
//! reads it as bash does, not as shadow's or glibc's parsers would:
//!
//!   - a line is what ends in a newline; a last line without one is read,
//!     but read fails, so the loop ends before its body sees it;
//!   - a NUL is dropped, not a line's end: bash's read skips it;
//!   - IFS is ':' alone, so no blank is trimmed from any field, and a '#'
//!     or a "+"/"-" entry is an ordinary line whose name matches no one;
//!   - `c` is the rest of the line after the second ':', the one ':' ending
//!     it dropped only when it ends a single word (see `fields`);
//!   - `-r` keeps a backslash as itself.
//!
//! An entry is the caller's when its name is the caller's passwd name or
//! uid, compared whole, its start and count match `^[0-9]+$`, and
//! `((c >= 65536))`. That last is bash's arithmetic, not a decimal read: a
//! leading 0 makes the count octal, an octal count with an 8 or 9 is an
//! arithmetic error that fails the test (bash says so on stderr and the loop
//! goes on), and a count past 2^63 - 1 wraps at 64 bits (`arith`). The
//! first such entry wins (:240-243).
//!
//! What fl_map is given keeps each field's text, as the wrapper's $sub and
//! $subn do: the start's text is in the cache key (:280), and fl_map passes
//! a field on untouched where it does no arithmetic on it (`Word`). Where a
//! field is not plain decimal (a leading 0, or past 2^63 - 1), that text and
//! the arithmetic's value differ, and the extents are the wrapper's all the
//! same: newuidmap then refused them, or the spec did.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// The caller's entry: its start and count fields, as the wrapper keeps
/// them in $sub/$gsub and $subn/$gsubn (:241, 247). Digits only.
pub const Range = struct {
    start: []const u8,
    count: []const u8,
};

/// The widest fl_map ever uses, and the least `find` accepts (:240, 260).
pub const width = 65536;

/// The first entry of `text`, an /etc/subuid or /etc/subgid, for the
/// caller, whose passwd name is `name` (the wrapper's $me, which is the uid
/// itself when passwd has no name for it, :59-65) and whose uid is `uid`;
/// null when there is none. A field is a slice of `text`, or of a copy of
/// its line in `gpa`, an arena, when the line has a NUL.
pub fn find(gpa: Allocator, text: []const u8, name: []const u8, uid: u32) Allocator.Error!?Range {
    var uid_buf: [10]u8 = undefined;
    const uid_text = uid_buf[0..std.fmt.printInt(&uid_buf, uid, 10, .lower, .{})];
    var rest = text;
    while (std.mem.indexOfScalar(u8, rest, '\n')) |end| {
        const line = try dropNul(gpa, rest[0..end]);
        rest = rest[end + 1 ..];
        const n, const s, const c = fields(3, line);
        if (!std.mem.eql(u8, n, name) and !std.mem.eql(u8, n, uid_text)) continue;
        if (!digits(s) or !digits(c)) continue;
        if ((arith(c) orelse continue) < width) continue;
        return .{ .start = s, .count = c };
    }
    return null;
}

/// One word of an extent, as fl_map puts it in MAP.
pub const Word = union(enum) {
    /// A field's text, passed on as it is where fl_map does no arithmetic
    /// on it: the start in the first extent, and the start and the count in
    /// the last when the container id is 0 (:263, 267).
    text: []const u8,
    /// An arithmetic result or an id, printed in decimal as bash prints it,
    /// a '-' first if negative.
    value: i64,

    /// As bash expands it into an argument (the cache tool's --map-users
    /// and --map-groups, :274-275, and the spec's uidmap and gidmap,
    /// :387-388), for `{f}`.
    pub fn format(word: Word, w: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (word) {
            .text => |t| try w.writeAll(t),
            .value => |v| try w.print("{d}", .{v}),
        }
    }

    /// The number the spec read in it: decimal digits, a leading 0 read as
    /// one (as the argv spec's parse read it, and assemble.zig's idmaps
    /// now), so a start of 0100000 is 100000 here where
    /// fl_map's arithmetic read 32768. Null for a negative value, which the
    /// spec refused as not a decimal number; maxInt(u64) for one past it,
    /// past every id the spec accepts.
    pub fn number(word: Word) ?u64 {
        switch (word) {
            .value => |v| return if (v < 0) null else @intCast(v),
            .text => |t| {
                if (!digits(t)) return null;
                var n: u64 = 0;
                for (t) |d| {
                    n = std.math.mul(u64, n, 10) catch return std.math.maxInt(u64);
                    n = std.math.add(u64, n, d - '0') catch return std.math.maxInt(u64);
                }
                return n;
            },
        }
    }
};

/// IN OUT COUNT, one extent of MAP (:255-257).
pub const Extent = [3]Word;

/// MAP: two or three extents, in fl_map's order.
pub const Map = struct {
    extents: [3]Extent,
    len: usize,

    pub fn slice(m: *const Map) []const Extent {
        return m.extents[0..m.len];
    }

    fn add(m: *Map, e: Extent) void {
        m.extents[m.len] = e;
        m.len += 1;
    }
};

/// What fl_map comes to.
pub const Built = union(enum) {
    map: Map,
    /// `h=$((h + c))` (:264) on a start bash's arithmetic cannot read, a
    /// leading 0 then an 8 or a 9 (or `left=$((left - c))` on such a count,
    /// which `find` never gives): bash's "value too great for base", which
    /// ended the wrapper under errexit with status 1. The word's text.
    not_a_number: []const u8,
};

/// fl_map CONTAINER-ID HOST-ID SUB WIDTH (:258-268), `range` being `find`'s.
/// The container id `container` maps onto the caller's `host`; the ids
/// below it are the range's first ones, those above it the rest, at most
/// `width` of the range used in all. Every step is the wrapper's, bash's
/// 64-bit wrapping arithmetic included; `((...))` on a word bash cannot
/// read is false, as it is in the wrapper, where bash also says so on
/// stderr.
pub fn buildMap(container: u32, host: u32, range: Range) Built {
    const c: i64 = container;
    var h: Word = .{ .text = range.start };
    var left: Word = .{ .text = range.count };
    // `if ((left > 65536)); then left=65536; fi` (:260): the count's text
    // stays when it is 65536 or less, which for `find`'s is only a count
    // that comes to 65536 exactly, such as 0200000.
    if ((eval(left) orelse 0) > width) left = .{ .value = width };
    var m: Map = .{ .extents = undefined, .len = 0 };
    if (c > 0) {
        m.add(.{ .{ .value = 0 }, h, .{ .value = c } });
        // Each value is taken before its word is written: a union built in
        // place would be read half made.
        const hv = eval(h) orelse return .{ .not_a_number = range.start };
        h = .{ .value = hv +% c };
        // `left=$((left - c))`: the count was read by find's test, and a
        // count bash could not read would have failed it; but a Range from
        // elsewhere is still refused as the wrapper would have died.
        const lv = eval(left) orelse return .{ .not_a_number = range.count };
        left = .{ .value = lv -% c };
    }
    m.add(.{ .{ .value = c }, .{ .value = host }, .{ .value = 1 } });
    if ((eval(left) orelse 0) > 0) m.add(.{ .{ .value = c + 1 }, h, left });
    return .{ .map = m };
}

/// A word's value in bash's arithmetic, or null where bash says "value too
/// great for base".
fn eval(word: Word) ?i64 {
    return switch (word) {
        .value => |v| v,
        .text => |t| if (digits(t)) arith(t) else null,
    };
}

/// A word of digits as bash's arithmetic reads it: octal after a leading
/// 0, decimal otherwise, wrapping at 64 bits as bash's intmax_t does
/// (`$((99999999999999999999))` is 7766279631452241919); null for an 8 or
/// a 9 in an octal word.
fn arith(word: []const u8) ?i64 {
    const base: u64 = if (word.len > 1 and word[0] == '0') 8 else 10;
    var n: u64 = 0;
    for (word) |d| {
        if (d - '0' >= base) return null;
        n = n *% base +% (d - '0');
    }
    return @bitCast(n);
}

/// `[[ $x =~ ^[0-9]+$ ]]` (:240): at least one digit, and nothing else.
fn digits(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |d| if (d < '0' or d > '9') return false;
    return true;
}

/// `IFS=: read -r` into `n` names over one line (bash's read.def): each
/// name but the last takes the text up to the next ':', or all that is
/// left, and the names after the text runs out are empty. The last takes
/// the rest, dropping the ':' after it only when the rest is one word and
/// that ':' (so "a:1:2:" gives c "2", but "a:1:2::" gives "2::" and
/// "a:1:2:3:" gives "2:3:").
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

fn expectFind(text: []const u8, name: []const u8, uid: u32, start: ?[]const u8, count: []const u8) !void {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const r = try find(arena.allocator(), text, name, uid);
    if (start) |s| {
        try testing.expectEqualStrings(s, r.?.start);
        try testing.expectEqualStrings(count, r.?.count);
    } else try testing.expectEqual(@as(?Range, null), r);
}

test "find: NixOS's own lines, by name or by uid" {
    const text =
        \\root:1000000:65536
        \\alice:100000:65536
        \\bob:165536:65536
        \\1002:231072:65536
        \\
    ;
    try expectFind(text, "alice", 1000, "100000", "65536");
    try expectFind(text, "bob", 1001, "165536", "65536");
    // By uid, where passwd named no one (the wrapper's $me is then the uid).
    try expectFind(text, "1002", 1002, "231072", "65536");
    // By uid, where passwd's name has no entry of its own.
    try expectFind(text, "carol", 1002, "231072", "65536");
    try expectFind(text, "dave", 1003, null, "");
    try expectFind("", "alice", 1000, null, "");
}

test "find: the first entry wide enough wins, by name or uid alike" {
    const text =
        \\alice:100000:1000
        \\alice:x:65536
        \\alice:200000:65535
        \\1000:300000:65536
        \\alice:400000:65536
        \\
    ;
    try expectFind(text, "alice", 1000, "300000", "65536");
    try expectFind(text, "alice", 1001, "400000", "65536");
    // Wider is fine, and kept as it is; fl_map uses 65536 of it.
    try expectFind("alice:100000:1000000\n", "alice", 1000, "100000", "1000000");
}

test "find: bash's read, not a passwd parser" {
    // The last line has no newline: read fails on it, so the loop ends
    // before its body sees it (:239, 244).
    try expectFind("alice:100000:65536", "alice", 1000, null, "");
    try expectFind("bob:1:65536\nalice:100000:65536", "alice", 1000, null, "");
    // IFS is ':' alone: nothing is trimmed, so a blank or a '\r' is part of
    // a field, and the field then fails its test or its comparison.
    try expectFind(" alice:100000:65536\n", "alice", 1000, null, "");
    try expectFind("alice :100000:65536\n", "alice", 1000, null, "");
    try expectFind("alice: 100000:65536\n", "alice", 1000, null, "");
    try expectFind("alice:100000:65536 \n", "alice", 1000, null, "");
    try expectFind("alice:100000:65536\r\n", "alice", 1000, null, "");
    // A comment or a compat entry is a line like any other.
    try expectFind("#alice:1:65536\n+alice:2:65536\nalice:3:65536\n", "alice", 1000, "3", "65536");
    try expectFind("#alice:1:65536\n", "#alice", 1000, "1", "65536");
    // A NUL is dropped, anywhere, and the line read without it.
    try expectFind("al\x00ice:10\x000000:65\x00536\n", "alice", 1000, "100000", "65536");
    try expectFind("alice:100000:65536\x00\n", "alice", 1000, "100000", "65536");
    try expectFind("alice:100000:\x00\n", "alice", 1000, null, "");
    // -r: a backslash is itself, and escapes no ':'.
    try expectFind("al\\:ice:100000:65536\n", "al\\", 1000, null, "");
    try expectFind("al\\:100000:65536\n", "al\\", 1000, "100000", "65536");
    // Empty lines and short ones.
    try expectFind("\n\nalice\nalice:100000\nalice:100000:65536\n", "alice", 1000, "100000", "65536");
    // An empty name matches only an empty $me.
    try expectFind(":100000:65536\n", "", 1000, "100000", "65536");
    try expectFind(":100000:65536\n", "alice", 1000, null, "");
}

test "find: the count is the rest of the line" {
    // One ':' after a single word is dropped; anything more stays, and a
    // count with a ':' in it is no number.
    try expectFind("alice:100000:65536:\n", "alice", 1000, "100000", "65536");
    try expectFind("alice:100000:65536::\n", "alice", 1000, null, "");
    try expectFind("alice:100000:65536:x\n", "alice", 1000, null, "");
    try expectFind("alice:100000:65536:x:\n", "alice", 1000, null, "");
    try expectFind("alice:100000:\n", "alice", 1000, null, "");
    try expectFind("alice:100000::\n", "alice", 1000, null, "");
}

test "find: ^[0-9]+$, then bash's arithmetic on the count" {
    for ([_][]const u8{ "", "-1", "+1", "1e5", "0x186a0", "１", "100000 " }) |s| {
        var buf: [64]u8 = undefined;
        const line = try std.fmt.bufPrint(&buf, "alice:{s}:65536\n", .{s});
        try expectFind(line, "alice", 1000, null, "");
    }
    for ([_][]const u8{ "", "-65536", "+65536", "65536.0", "0x10000", "65535" }) |c| {
        var buf: [64]u8 = undefined;
        const line = try std.fmt.bufPrint(&buf, "alice:100000:{s}\n", .{c});
        try expectFind(line, "alice", 1000, null, "");
    }
    // A leading 0 is octal: 065536 is 27,486, 0200000 is 65536.
    try expectFind("alice:100000:065536\n", "alice", 1000, null, "");
    try expectFind("alice:100000:0200000\n", "alice", 1000, "100000", "0200000");
    // An 8 or 9 in an octal count is bash's "value too great for base": the
    // test fails and the loop goes on to the next line.
    try expectFind("alice:1:099999\nalice:2:65536\n", "alice", 1000, "2", "65536");
    // 64-bit wrapping: 2^63 is negative, 2^64 + 65536 is 65536, and
    // 10^20 - 1 is 7,766,279,631,452,241,919.
    try expectFind("alice:1:9223372036854775808\n", "alice", 1000, null, "");
    try expectFind("alice:1:18446744073709617152\n", "alice", 1000, "1", "18446744073709617152");
    try expectFind("alice:1:99999999999999999999\n", "alice", 1000, "1", "99999999999999999999");
    // The start is only matched, never evaluated here: any digits.
    try expectFind("alice:099999:65536\n", "alice", 1000, "099999", "65536");
    try expectFind("alice:0:65536\n", "alice", 1000, "0", "65536");
}

test "arith: bash's reading of a word of digits" {
    try testing.expectEqual(@as(?i64, 0), arith("0"));
    try testing.expectEqual(@as(?i64, 0), arith("000"));
    try testing.expectEqual(@as(?i64, 65536), arith("65536"));
    try testing.expectEqual(@as(?i64, 65536), arith("0200000"));
    try testing.expectEqual(@as(?i64, 27486), arith("065536"));
    try testing.expectEqual(@as(?i64, null), arith("08"));
    try testing.expectEqual(@as(?i64, null), arith("099999"));
    try testing.expectEqual(@as(?i64, std.math.maxInt(i64)), arith("9223372036854775807"));
    try testing.expectEqual(@as(?i64, std.math.minInt(i64)), arith("9223372036854775808"));
    try testing.expectEqual(@as(?i64, 7766279631452241919), arith("99999999999999999999"));
}

/// fl_map's MAP, as the wrapper prints it with `printf ' %s' "${MAP[@]}"`.
fn expectMap(expected: []const u8, container: u32, host: u32, start: []const u8, count: []const u8) !void {
    const b = buildMap(container, host, .{ .start = start, .count = count });
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    switch (b) {
        .map => |m| for (m.slice()) |e| try w.print(" {f} {f} {f}", .{ e[0], e[1], e[2] }),
        .not_a_number => |s| try w.print("died {s}", .{s}),
    }
    try testing.expectEqualStrings(expected, w.buffered());
}

// Each expectation is what bash 5.3 printed for rootless-wrapper.bash:258-268
// copied into a script under `set -euo pipefail`, given the same four
// arguments (the wrapper's died under errexit where this says "died").
test "buildMap: fl_map's extents" {
    // Container root: root onto the caller, 1 up from the range.
    try expectMap(" 0 1000 1 1 100000 65536", 0, 1000, "100000", "65536");
    try expectMap(" 0 1000 1 1 231072 65536", 0, 1000, "231072", "65536");
    // A user above root: the ids below it first, then the caller, then the
    // rest.
    try expectMap(" 0 100000 1 1 1000 1 2 100001 65535", 1, 1000, "100000", "65536");
    try expectMap(" 0 100000 1000 1000 1000 1 1001 101000 64536", 1000, 1000, "100000", "65536");
    try expectMap(" 0 100000 65535 65535 1000 1 65536 165535 1", 65535, 1000, "100000", "65536");
    // At or past the range's end, nothing is left for above.
    try expectMap(" 0 100000 65536 65536 1000 1", 65536, 1000, "100000", "65536");
    try expectMap(" 0 100000 70000 70000 1000 1", 70000, 1000, "100000", "65536");
    // A wider range: 65536 of it at most.
    try expectMap(" 0 100000 1000 1000 1000 1 1001 101000 64536", 1000, 1000, "100000", "1000000");
    try expectMap(" 0 1000 1 1 100000 65536", 0, 1000, "100000", "1000000");
    // The highest ids.
    try expectMap(" 0 4294967294 1 1 4294901760 65536", 0, 4294967294, "4294901760", "65536");
}

test "buildMap: a field that is not plain decimal, as the wrapper had it" {
    // The start's text where there is no arithmetic on it; octal where
    // there is (0100000 is 32768).
    try expectMap(" 0 0100000 1000 1000 1000 1 1001 33768 64536", 1000, 1000, "0100000", "65536");
    try expectMap(" 0 0100000 1000 1000 1000 1 1001 33768 64536", 1000, 1000, "0100000", "0200000");
    // Container root: both texts, untouched.
    try expectMap(" 0 1000 1 1 0100000 0200000", 0, 1000, "0100000", "0200000");
    try expectMap(" 0 1000 1 1 099999 65536", 0, 1000, "099999", "65536");
    try expectMap(" 0 1000 1 1 100000 18446744073709617152", 0, 1000, "100000", "18446744073709617152");
    // A start bash cannot read, once there is arithmetic on it.
    try expectMap("died 099999", 1000, 1000, "099999", "65536");
    // Wrapping: past 2^63 - 1 the start goes negative.
    try expectMap(" 0 9223372036854775807 1000 1000 1000 1 1001 -9223372036854774809 64536", 1000, 1000, "9223372036854775807", "65536");
    try expectMap(" 0 100000 1000 1000 1000 1 1001 101000 64536", 1000, 1000, "100000", "18446744073709617152");
    try expectMap(" 0 100000 1000 1000 1000 1 1001 101000 64536", 1000, 1000, "100000", "99999999999999999999");
}

test "buildMap: the words as the spec read them" {
    const m = buildMap(1000, 1000, .{ .start = "0100000", .count = "65536" }).map;
    try testing.expectEqual(@as(usize, 3), m.len);
    const want = [3][3]?u64{ .{ 0, 100000, 1000 }, .{ 1000, 1000, 1 }, .{ 1001, 33768, 64536 } };
    for (m.slice(), want) |e, w| for (e, w) |word, n| try testing.expectEqual(n, word.number());
    const neg = buildMap(1000, 1000, .{ .start = "9223372036854775807", .count = "65536" }).map;
    try testing.expectEqual(@as(?u64, null), neg.extents[2][1].number());
    const big = buildMap(0, 1000, .{ .start = "100000", .count = "18446744073709617152" }).map;
    try testing.expectEqual(@as(?u64, std.math.maxInt(u64)), big.extents[1][2].number());
    try testing.expectEqual(@as(?u64, 100000), big.extents[1][1].number());
}

test "find then buildMap: the caller's maps from the files" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const sub = (try find(arena.allocator(), "root:1000000:65536\nalice:100000:65536\n", "alice", 1000)).?;
    const gsub = (try find(arena.allocator(), "alice:200000:131072\n", "alice", 1000)).?;
    const u = buildMap(1000, 1000, sub).map;
    const g = buildMap(100, 100, gsub).map;
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    for (u.slice()) |e| try w.print("--map-users={f}:{f}:{f}\n", .{ e[0], e[1], e[2] });
    for (g.slice()) |e| try w.print("--map-groups={f}:{f}:{f}\n", .{ e[0], e[1], e[2] });
    try testing.expectEqualStrings(
        \\--map-users=0:100000:1000
        \\--map-users=1000:1000:1
        \\--map-users=1001:101000:64536
        \\--map-groups=0:200000:100
        \\--map-groups=100:100:1
        \\--map-groups=101:200100:65436
        \\
    , w.buffered());
}

test "find on hostile bytes: no panic, and a match is the wrapper's" {
    // Lines of fields, each field a few pieces: names, numbers bash reads
    // three ways, blanks, NULs, colons and newlines of their own, and
    // random bytes.
    const pieces = [_][]const u8{ "", "0", "1", "65536", "0200000", "099999", "99999999999999999999", "alice", "1000", "+", "#", " ", "\x00", "\\", ":", "\n" };
    var prng = std.Random.DefaultPrng.init(0x5ab1d);
    const r = prng.random();
    var buf: [1024]u8 = undefined; // at most 4 lines of 4 fields of 2 pieces of 20 bytes, with separators
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var found: usize = 0;
    for (0..20_000) |_| {
        _ = arena.reset(.retain_capacity);
        var n: usize = 0;
        for (0..r.uintAtMost(usize, 4)) |_| {
            for (0..r.uintAtMost(usize, 4)) |field| {
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
        const got = try find(arena.allocator(), buf[0..n], "alice", 1000) orelse continue;
        found += 1;
        try testing.expect(digits(got.start) and digits(got.count));
        try testing.expect(arith(got.count).? >= width);
        switch (buildMap(1000, 1000, got)) {
            .map => |m| try testing.expect(m.len >= 2 and m.len <= 3),
            .not_a_number => |s| try testing.expect(arith(s) == null),
        }
    }
    // The pieces reach a match, often enough to mean something.
    try testing.expect(found >= 10);
}
