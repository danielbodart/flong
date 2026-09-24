//! launch/childpid.zig: step 13, bwrap's child-pid, read from --info-fd
//! (launcher/flong-launch.c:450-523 of 5f1f08e; the Zig port's L4; DESIGN.md,
//! "Tests": the child-pid reader over split reads and the 4096-byte bound).
//!
//! bwrap writes a JSON object on --info-fd once it has cloned the sandbox's
//! pid 1: `{\n    "child-pid": N`, then `,\n    "<ns>-namespace": M` per
//! namespace and `\n}\n`, in several writes. The launcher needs only N, and
//! reads until N is whole: the digits followed by something else, or the
//! pipe at EOF. Two parts:
//!
//!   parse  child_pid (:452-474), pure: what the bytes read so far say.
//!   wait   wait_child_pid's loop (:485-511): waits for the pipe or bwrap's
//!          exit, reads, and parses again, into one 4096-byte buffer.
//!
//! What wait_child_pid does with N (:512-522: the leader's pidfd, its
//! network namespace, `leader=` in the record) is the launch's, which holds
//! those handles; so is the info pipe's read end, held and never closed
//! (quirk 31: bwrap would die of SIGPIPE at its next write, :480-484).
//!
//! A deviation from the port's plan, whose module list named only
//! `launch.zig`: the launch's helpers are split by concern into modules
//! under src/launch/, this one taking no Launch struct, only what it reads.

const std = @import("std");
const sys = @import("sys");
const msg = @import("msg");
const sig = @import("sig");

/// wait_child_pid's buffer (:487, 497): 4096 bytes, one kept for the C's
/// NUL, so at most `max_read` bytes of bwrap's JSON are ever read.
pub const buf_len = 4096;
pub const max_read = buf_len - 1;

/// What the bytes read so far say (child_pid's return, :454).
pub const Answer = union(enum) {
    /// Not yet whole: read more (child_pid's 0).
    more,
    /// Refused (child_pid's -1).
    malformed,
    /// The pid, whole: 1 to 999,999,999.
    pid: sys.pid_t,
};

const key = "\"child-pid\"";

/// child_pid (:455-474) over `info`, the bytes read so far, `eof` when the
/// last read returned 0. The C reads its buffer as a string, so only the
/// bytes before the first NUL count: a NUL ends what strstr and strspn see
/// (:457, 461-468), and the digits before it are whole only at EOF. Kept:
///
///   - only the first "child-pid" key counts, as strstr finds it (:457);
///   - the space skipped around the colon is " \t\n", no '\r' (:461, 467);
///   - the digits are only 0-9, no sign; leading zeros are read (strtol,
///     base 10, :473); more than 9 is refused, but only once they are known
///     to be whole (:469-472);
///   - a pid of 0 is child_pid's "more is needed" (its 0), so the loop reads
///     on, and refuses at EOF or at the bound.
pub fn parse(info: []const u8, eof: bool) Answer {
    const s = info[0 .. std.mem.indexOfScalar(u8, info, 0) orelse info.len];
    var p = (std.mem.indexOf(u8, s, key) orelse return .more) + key.len;
    p = span(s, p, " \t\n");
    if (p == s.len) return .more;
    if (s[p] != ':') return .malformed;
    p = span(s, p + 1, " \t\n");
    const digits = span(s, p, "0123456789") - p;
    if (p + digits == s.len and !eof) return .more;
    if (digits == 0 or digits > 9) return .malformed;
    var pid: sys.pid_t = 0;
    for (s[p .. p + digits]) |c| pid = pid * 10 + (c - '0');
    if (pid == 0) return .more;
    return .{ .pid = pid };
}

/// strspn from `at`: the index of the first byte of `s` not in `set`.
fn span(s: []const u8, at: usize, comptime set: []const u8) usize {
    var i = at;
    while (i < s.len and std.mem.indexOfScalar(u8, set, s[i]) != null) i += 1;
    return i;
}

/// wait_child_pid's loop (:485-511): reads bwrap's info from `source` until
/// it names bwrap's child, and returns that pid. `source` (a pointer or a
/// value) has
///
///   ready() sig.Error!bool       await_or_bwrap (:414-448): true when the
///                                info pipe is readable (it wins a tie),
///                                false when bwrap exited first
///                                (sig.awaitFdOrExit over the info pipe and
///                                bwrap's pidfd; sig.zig)
///   read([]u8) sys.Result(usize) one read of the info pipe's read end
///
/// Refusals, each said once and returned as error.Reported:
///
///   - "bwrap failed before it made the sandbox": bwrap exited first, or
///     EOF with nothing read; bwrap has said why on stderr (:476-477,
///     495-496, 507-508);
///   - "read bwrap's info: <strerror>": a read failed, but for EINTR, which
///     reads again (:498-502);
///   - "bwrap reported no child pid: <what was read, up to a NUL>":
///     malformed, EOF before the pid was whole, or `max_read` bytes read
///     and it not whole yet (:506-509).
///
/// A failed or aborted ready() is passed up as it came, nothing more said.
/// Nothing is read after the read that completes the pid (:483-484).
pub fn wait(source: anytype) sig.Error!sys.pid_t {
    var buf: [buf_len]u8 = undefined;
    var got: usize = 0;
    while (true) {
        if (!try source.ready()) return msg.refuse("bwrap failed before it made the sandbox", .{});
        const r = switch (source.read(buf[got..max_read])) {
            .ok => |n| n,
            .err => |e| if (e == .INTR) continue else return msg.fail(e, "read bwrap's info", .{}),
        };
        got += r;
        const eof = r == 0;
        switch (parse(buf[0..got], eof)) {
            .pid => |pid| return pid,
            .more => if (!eof and got < max_read) continue,
            .malformed => {},
        }
        if (eof and got == 0) return msg.refuse("bwrap failed before it made the sandbox", .{});
        return msg.refuse("bwrap reported no child pid: {s}", .{asString(buf[0..got])});
    }
}

/// What printf's %s prints of the buffer: up to its first NUL (:504, 509).
fn asString(b: []const u8) []const u8 {
    return b[0 .. std.mem.indexOfScalar(u8, b, 0) orelse b.len];
}

// ---- tests: parse, the cases child_pid tells apart ----

const testing = std.testing;

fn expectAnswer(want: Answer, info: []const u8, eof: bool) !void {
    try testing.expectEqual(want, parse(info, eof));
}

fn pidIs(n: sys.pid_t) Answer {
    return .{ .pid = n };
}

test "bwrap's own JSON, whole or cut anywhere" {
    const json = "{\n    \"child-pid\": 4242,\n    \"cgroup-namespace\": 4026531835,\n    \"ipc-namespace\": 4026531839\n}\n";
    try expectAnswer(pidIs(4242), json, false);
    try expectAnswer(pidIs(4242), json, true);
    const at = std.mem.indexOf(u8, json, "4242").?;
    for (0..json.len + 1) |cut| {
        // Whole once the comma after the digits is in.
        const want: Answer = if (cut > at + 4) pidIs(4242) else .more;
        try expectAnswer(want, json[0..cut], false);
    }
    // The pid is whole at EOF with nothing after it.
    try expectAnswer(pidIs(4242), json[0 .. at + 4], true);
    try expectAnswer(pidIs(424), json[0 .. at + 3], true);
}

test "the key, the colon and the space around it" {
    try expectAnswer(.more, "", false);
    try expectAnswer(.more, "", true);
    try expectAnswer(.more, "{\"child\": 5,", true);
    try expectAnswer(.more, "child-pid: 5,", true);
    try expectAnswer(.more, "\"child-pid\"", false);
    try expectAnswer(.more, "\"child-pid\" \t\n", true);
    try expectAnswer(pidIs(5), "\"child-pid\"\n\t :\n\t 5}", false);
    try expectAnswer(pidIs(5), "\"child-pid\":5 ", false);
    try expectAnswer(.malformed, "\"child-pid\"x: 5,", false);
    try expectAnswer(.malformed, "\"child-pid\" = 5,", false);
    // '\r' is not space to strspn(" \t\n").
    try expectAnswer(.malformed, "\"child-pid\"\r: 5,", false);
    try expectAnswer(.malformed, "\"child-pid\": \r5,", false);
    // The first key counts, however malformed.
    try expectAnswer(.malformed, "\"child-pid\"; \"child-pid\": 5,", false);
    try expectAnswer(pidIs(5), "\"child-pid\": 5, \"child-pid\": x", false);
    // Overlapping keys: the first ends where the second begins.
    try expectAnswer(.malformed, "\"child-pid\"child-pid\": 5,", false);
}

test "the digits: none, a sign, too many, leading zeros, zero" {
    try expectAnswer(.malformed, "\"child-pid\": ,", false);
    try expectAnswer(.malformed, "\"child-pid\": -5,", false);
    try expectAnswer(.malformed, "\"child-pid\": +5,", false);
    try expectAnswer(.malformed, "\"child-pid\": x", false);
    // Nothing after the colon: more, until EOF refuses it.
    try expectAnswer(.more, "\"child-pid\": ", false);
    try expectAnswer(.malformed, "\"child-pid\": ", true);
    try expectAnswer(pidIs(999_999_999), "\"child-pid\": 999999999,", false);
    try expectAnswer(pidIs(1), "\"child-pid\": 000000001,", false);
    try expectAnswer(pidIs(7), "\"child-pid\": 007\n", false);
    // Ten digits are refused, but only once they are whole.
    try expectAnswer(.more, "\"child-pid\": 1234567890", false);
    try expectAnswer(.malformed, "\"child-pid\": 1234567890", true);
    try expectAnswer(.malformed, "\"child-pid\": 1234567890,", false);
    try expectAnswer(.malformed, "\"child-pid\": 0000000001,", false);
    // 0 is child_pid's "more": never a pid.
    try expectAnswer(.more, "\"child-pid\": 0,", false);
    try expectAnswer(.more, "\"child-pid\": 000000000,", true);
    try expectAnswer(.more, "\"child-pid\": 0", true);
}

test "a NUL ends what the C sees" {
    try expectAnswer(.more, "\x00\"child-pid\": 5,", true);
    try expectAnswer(.more, "\"child-\x00pid\": 5,", true);
    try expectAnswer(.more, "\"child-pid\" \x00: 5,", true);
    // The digits before a NUL are whole only at EOF.
    try expectAnswer(.more, "\"child-pid\": 5\x00,", false);
    try expectAnswer(pidIs(5), "\"child-pid\": 5\x00,", true);
    try expectAnswer(pidIs(5), "\"child-pid\": 5,\x00", false);
    try expectAnswer(.malformed, "\"child-pid\": \x005,", true);
}
