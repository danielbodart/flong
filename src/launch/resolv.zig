//! resolv.zig: a networked session's /etc/resolv.conf and pasta's
//! --dns-forward words, from the host's (rootless-wrapper.bash:404-442),
//! for `flong launch`'s prologue (STANDALONE.md, "flong launch DECL.zon --
//! ARGS"). Pure: the host's file is text the caller read, once, as pasta
//! reads it once, so a host that moves networks keeps a live session on
//! the old resolver (:410-411). A file the caller cannot read is the empty
//! text (:414).
//!
//! A networked session's resolver is pasta. One synthetic nameserver per
//! family the host's resolv.conf names a nameserver in, in the host's
//! order, each with its --dns-forward: for a family with none, pasta would
//! send the queries to the host's own loopback. search, domain and options
//! come across as they are, so a short name means in here what it means
//! out there (:405-410).
//!
//! The wrapper reads the file with `while read -r rkey value rest || [[ -n
//! $rkey ]]` (:415), IFS unset, so its default, and this reads it as that
//! loop does, checked against bash 5.3:
//! - a line ends at '\n', and the last one needs none;
//! - a NUL is dropped, as bash's read drops it, so the bytes either side
//!   join ("sea\0rch" is search);
//! - blanks (space and tab) before the first word and after the last are
//!   dropped, and the first two words are split at runs of them;
//! - rest is what follows the second word and its blanks, blanks inside it
//!   kept; -r keeps a backslash as it is, and a '\r' is not a blank.
//! Only a first word of exactly nameserver, search, domain or options
//! counts (:416-435), so a comment, '#' or ';', is nothing.

const std = @import("std");

const Allocator = std.mem.Allocator;

/// WHERE A NETWORKED SESSION SENDS ITS DNS, for pasta to take from there.
/// --dns-forward catches UDP and TCP to ports 53 and 853 at this address
/// and re-sends each query FROM THE HOST to the host's own first
/// nameserver. Re-originated there, so a stub resolver on the host's
/// loopback (resolved's 127.0.0.53, a dnsmasq on 127.0.0.1) answers a
/// session that has no way to the host's loopback otherwise. That is why
/// this and not a copy of the host's resolv.conf: copied in, 127.0.0.53
/// names the SESSION's loopback, where nothing is listening.
///
/// 169.254.1.1 is Podman's address for the same job (`dnsForwardIpv4` in
/// go.podman.io/common's libnetwork/pasta), followed deliberately. It is
/// IPv4 link-local, which no router forwards, so nothing beyond the host's
/// own link could answer it even without pasta in the way. A LAN has it
/// only through link-local autoconfiguration, and then all the session
/// loses is that one address's DNS ports. And it is well clear of the
/// addresses a cloud answers on (metadata at 169.254.169.254, AWS's
/// resolver at 169.254.169.253, ECS at 169.254.170.2), so no rule about
/// those catches it, and nobody reading a resolv.conf takes it for one of
/// them. A steering hook's own service address in the same namespace
/// (frisket's, on `lo`) must be another address again: on `lo`, it would
/// take these queries before pasta ever saw them.
///
/// 100::1 for IPv6, which Podman does not forward at all. It is in RFC
/// 6666's discard-only block, which exists to be dropped: globally
/// unreachable, used by no LAN, and blackholed by the first router that
/// sees it. Link-local, the IPv4 answer, is no use in IPv6: an fe80::
/// nameserver needs a zone, and the interface inside is named after
/// whichever host interface pasta copied.
pub const dns_forward4 = "169.254.1.1";
pub const dns_forward6 = "100::1";

/// The session's file begins with this line (:413).
pub const header = "# flong: pasta forwards queries sent here to the host's resolver.\n";

/// The session's resolver, from the host's.
pub const Resolv = struct {
    /// the host names an IPv4 nameserver, so dns_forward4 is forwarded
    forward4: bool,
    /// the host names an IPv6 nameserver, so dns_forward6 is forwarded
    forward6: bool,
    /// the session's /etc/resolv.conf, `header` first, every line ending
    /// in '\n', in the allocator `read` was given
    text: []const u8,
    /// pasta's arguments: --dns-forward and the address, per family
    /// forwarded, in the host's order (:429)
    words: [4][]const u8,
    len: u8,

    /// The --dns-forward words, the spec's pasta-arg words in order.
    pub fn pastaArgs(self: *const Resolv) []const []const u8 {
        return self.words[0..self.len];
    }
};

/// The session's resolver from `host`, the host's /etc/resolv.conf as
/// read. `text` is in `gpa`, which nothing else is left in.
pub fn read(gpa: Allocator, host: []const u8) Allocator.Error!Resolv {
    // bash's read drops every NUL before it splits.
    const kept = try gpa.alloc(u8, host.len - std.mem.count(u8, host, "\x00"));
    defer gpa.free(kept);
    var n: usize = 0;
    for (host) |c| {
        if (c == 0) continue;
        kept[n] = c;
        n += 1;
    }

    var r: Resolv = .{ .forward4 = false, .forward6 = false, .text = &.{}, .words = undefined, .len = 0 };
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, header);
    var lines = std.mem.splitScalar(u8, kept, '\n');
    while (lines.next()) |line| {
        const l = split(line);
        if (std.mem.eql(u8, l.key, "nameserver")) {
            // `case $value in *:*) ... *.*) ... *) continue` (:418-428): a
            // ':' is IPv6 before a '.' is IPv4, so ::ffff:1.2.3.4 is IPv6;
            // each family once, the first nameserver in it deciding its
            // place.
            const ns = if (std.mem.indexOfScalar(u8, l.value, ':') != null) v6: {
                if (r.forward6) continue;
                r.forward6 = true;
                break :v6 dns_forward6;
            } else if (std.mem.indexOfScalar(u8, l.value, '.') != null) v4: {
                if (r.forward4) continue;
                r.forward4 = true;
                break :v4 dns_forward4;
            } else continue;
            r.words[r.len] = "--dns-forward";
            r.words[r.len + 1] = ns;
            r.len += 2;
            try out.print(gpa, "nameserver {s}\n", .{ns});
        } else if (std.mem.eql(u8, l.key, "search") or std.mem.eql(u8, l.key, "domain") or std.mem.eql(u8, l.key, "options")) {
            // `$rkey $value${rest:+ $rest}` (:433): the blank after the
            // key even when value is empty.
            try out.print(gpa, "{s} {s}", .{ l.key, l.value });
            if (l.rest.len > 0) try out.print(gpa, " {s}", .{l.rest});
            try out.append(gpa, '\n');
        }
    }
    r.text = try out.toOwnedSlice(gpa);
    return r;
}

/// A line as `read -r rkey value rest` splits it at the default IFS.
const Line = struct { key: []const u8, value: []const u8, rest: []const u8 };

/// IFS's whitespace within a line: '\n' ends the line first.
const blanks = " \t";

fn split(line: []const u8) Line {
    var s = std.mem.trim(u8, line, blanks);
    const key = word(&s);
    const value = word(&s);
    return .{ .key = key, .value = value, .rest = s };
}

/// The first word of `s`, which has no blank at either end, leaving `s`
/// what follows it and its blanks.
fn word(s: *[]const u8) []const u8 {
    const end = std.mem.indexOfAny(u8, s.*, blanks) orelse s.len;
    const w = s.*[0..end];
    s.* = std.mem.trimLeft(u8, s.*[end..], blanks);
    return w;
}

// ---- tests ----

const testing = std.testing;

test "split is bash's read -r rkey value rest" {
    // Each row as bash 5.3's loop split it.
    const rows = [_]struct { line: []const u8, key: []const u8, value: []const u8, rest: []const u8 }{
        .{ .line = "options  a \t  b  \t ", .key = "options", .value = "a", .rest = "b" },
        .{ .line = "options a b \t  c\t\td \t ", .key = "options", .value = "a", .rest = "b \t  c\t\td" },
        .{ .line = "\t\toptions\t\tv\t\t", .key = "options", .value = "v", .rest = "" },
        .{ .line = "search\tx  ", .key = "search", .value = "x", .rest = "" },
        .{ .line = "  nameserver 1.1.1.1\r", .key = "nameserver", .value = "1.1.1.1\r", .rest = "" },
        .{ .line = "search q\\ r\\\\ s", .key = "search", .value = "q\\", .rest = "r\\\\ s" },
        .{ .line = " \t ", .key = "", .value = "", .rest = "" },
        .{ .line = "", .key = "", .value = "", .rest = "" },
        .{ .line = "nameserver", .key = "nameserver", .value = "", .rest = "" },
        .{ .line = "x\x0b\x0cy z", .key = "x\x0b\x0cy", .value = "z", .rest = "" },
    };
    for (rows) |r| {
        const l = split(r.line);
        try testing.expectEqualStrings(r.key, l.key);
        try testing.expectEqualStrings(r.value, l.value);
        try testing.expectEqualStrings(r.rest, l.rest);
    }
}

fn expectResolv(host: []const u8, text: []const u8, args: []const []const u8) !void {
    const r = try read(testing.allocator, host);
    defer testing.allocator.free(r.text);
    try testing.expectEqualStrings(text, r.text);
    try testing.expectEqual(args.len, r.pastaArgs().len);
    for (args, r.pastaArgs()) |want, got| try testing.expectEqualStrings(want, got);
    var four = false;
    var six = false;
    for (args) |a| {
        if (std.mem.eql(u8, a, dns_forward4)) four = true;
        if (std.mem.eql(u8, a, dns_forward6)) six = true;
    }
    try testing.expectEqual(four, r.forward4);
    try testing.expectEqual(six, r.forward6);
}

test "read: the host's nameservers become one synthetic one per family, in order" {
    // No file, or nothing in it: the header alone, and no forward.
    try expectResolv("", header, &.{});
    try expectResolv("# nothing\n", header, &.{});
    // systemd-resolved's stub, and search and options across.
    try expectResolv(
        "# This is /run/systemd/resolve/stub-resolv.conf\nnameserver 127.0.0.53\noptions edns0 trust-ad\nsearch lan\n",
        header ++ "nameserver 169.254.1.1\noptions edns0 trust-ad\nsearch lan\n",
        &.{ "--dns-forward", "169.254.1.1" },
    );
    // IPv6 first, then IPv4; a second of either family skipped, wherever
    // it comes.
    try expectResolv(
        "nameserver fe80::1%eth0\nnameserver 192.168.1.1\nnameserver 2001:db8::53\nnameserver 10.0.0.1\n",
        header ++ "nameserver 100::1\nnameserver 169.254.1.1\n",
        &.{ "--dns-forward", "100::1", "--dns-forward", "169.254.1.1" },
    );
    // ':' before '.': a v4-mapped address is IPv6.
    try expectResolv("nameserver ::ffff:1.2.3.4\n", header ++ "nameserver 100::1\n", &.{ "--dns-forward", "100::1" });
    // A nameserver with neither, or no value, is no family and takes no
    // place; what follows the address is not looked at.
    try expectResolv(
        "nameserver\nnameserver localhost\nnameserver 1.1.1.1 junk here\n",
        header ++ "nameserver 169.254.1.1\n",
        &.{ "--dns-forward", "169.254.1.1" },
    );
    // Only the four keys, exactly: comments, other keys, a key in another
    // case, sortlist.
    try expectResolv(
        "#nameserver 1.1.1.1\n; nameserver 1.1.1.1\nNameserver 1.1.1.1\nsortlist 10.0.0.0\nlookup file bind\n",
        header,
        &.{},
    );
}

test "read: search, domain and options come across as bash wrote them" {
    try expectResolv(
        "domain example.com\n\tsearch  a.example   b.example \t\noptions ndots:2\t timeout:1  \t attempts:2 \n",
        header ++ "domain example.com\nsearch a.example b.example\noptions ndots:2 timeout:1  \t attempts:2\n",
        &.{},
    );
    // No value: the key and a blank.
    try expectResolv("search\n", header ++ "search \n", &.{});
    try expectResolv("options  \t\n", header ++ "options \n", &.{});
    // A '\r' is not a blank: it stays, and the value still has a '.'.
    try expectResolv(
        "search lan\r\nnameserver 1.1.1.1\r\n",
        header ++ "search lan\r\nnameserver 169.254.1.1\n",
        &.{ "--dns-forward", "169.254.1.1" },
    );
    // A backslash is kept (-r).
    try expectResolv("search a\\ b\n", header ++ "search a\\ b\n", &.{});
}

test "read: NULs are dropped and the last line needs no newline" {
    try expectResolv(
        "sea\x00rch q\nname\x00server\x00 1.1.1.1\n\x00\nsearch last",
        header ++ "search q\nnameserver 169.254.1.1\nsearch last\n",
        &.{ "--dns-forward", "169.254.1.1" },
    );
    try expectResolv("\x00", header, &.{});
    try expectResolv("options x \x00 y", header ++ "options x y\n", &.{});
    try expectResolv("nameserver 1\x00.1", header ++ "nameserver 169.254.1.1\n", &.{ "--dns-forward", "169.254.1.1" });
}

test "read on hostile bytes: every line of the text is one of the four keys" {
    const pieces = [_][]const u8{ "nameserver", "nameserver ", "search ", "domain", "options ", "#", " ", "\t", "\n", "\n", "\x00", "\r", ":", ".", "1.1", "::1", "a", "" };
    var prng = std.Random.DefaultPrng.init(0x4e_5c);
    const r = prng.random();
    var buf: [256]u8 = undefined;
    var forwards: usize = 0;
    for (0..20_000) |_| {
        var n: usize = 0;
        for (0..r.uintAtMost(usize, 24)) |_| {
            const i = r.uintAtMost(usize, pieces.len);
            if (i == pieces.len) {
                buf[n] = r.int(u8);
                n += 1;
            } else {
                @memcpy(buf[n..][0..pieces[i].len], pieces[i]);
                n += pieces[i].len;
            }
        }
        const got = try read(testing.allocator, buf[0..n]);
        defer testing.allocator.free(got.text);
        try testing.expect(std.mem.startsWith(u8, got.text, header));
        try testing.expect(std.mem.endsWith(u8, got.text, "\n"));
        try testing.expect(std.mem.indexOfScalar(u8, got.text, 0) == null);
        var ns: usize = 0;
        var lines = std.mem.splitScalar(u8, got.text[header.len..], '\n');
        while (lines.next()) |line| {
            if (line.len == 0) {
                // Only the empty string after the last '\n'.
                try testing.expectEqual(@as(?[]const u8, null), lines.next());
                break;
            }
            const l = split(line);
            if (std.mem.eql(u8, l.key, "nameserver")) {
                ns += 1;
                try testing.expect(std.mem.eql(u8, line, "nameserver " ++ dns_forward4) or std.mem.eql(u8, line, "nameserver " ++ dns_forward6));
            } else {
                try testing.expect(std.mem.eql(u8, l.key, "search") or std.mem.eql(u8, l.key, "domain") or std.mem.eql(u8, l.key, "options"));
            }
        }
        // One nameserver line per forward, in the same order.
        try testing.expectEqual(ns * 2, got.len);
        try testing.expectEqual(@as(usize, @intFromBool(got.forward4)) + @intFromBool(got.forward6), ns);
        forwards += ns;
    }
    try testing.expect(forwards >= 1000);
}
