//! src/tty.zig from outside (phase 7 L3): the pty path as prepare makes it
//! and the relay reads it, the ^] detector as a pure state machine against
//! a model over any chunking, and `finish` on what `prepare` leaves off a
//! terminal. The relay itself, the watchdog and the drain need a terminal
//! of the caller's, which checks.native's pty driver gives
//! (tests/zig/ttydriver.zig, tests/ptydrive.py).

const std = @import("std");
const minish = @import("minish");
const sys = @import("sys");
const fdt = @import("fd");
const proc = @import("proc");
const tty = @import("tty");
const testing = std.testing;

test "the pty: /dev/ptmx, TIOCSPTLCK, TIOCGPTN, the slave by path, and EIO once the last slave closes" {
    const start = fdt.liveCount();
    const master = switch (try fdt.openPtmx()) {
        .ok => |m| m,
        .err => return error.TestUnexpectedResult,
    };
    defer master.close();
    // Locked, the slave cannot be opened (the control for the unlock).
    const n = master.ptyNumber().ok;
    var buf: [32]u8 = undefined;
    const name = try std.fmt.bufPrintZ(&buf, "/dev/pts/{d}", .{n});
    try testing.expectEqual(sys.E.IO, (try fdt.openSlave(name)).err);
    try testing.expect(master.unlock() == .ok);
    const slave = switch (try fdt.openSlave(name)) {
        .ok => |s| s,
        .err => return error.TestUnexpectedResult,
    };
    // A terminal, not the caller's controlling one (O_NOCTTY), whose size
    // either end sets.
    try testing.expect(sys.isatty(slave.raw()));
    const ws: sys.Winsize = .{ .row = 30, .col = 100, .xpixel = 0, .ypixel = 0 };
    try testing.expect(master.setWinsize(&ws) == .ok);
    try testing.expectEqual(ws, sys.getWinsize(slave.raw()).ok);
    try testing.expect(slave.setWinsize(&.{ .row = 40, .col = 120, .xpixel = 0, .ypixel = 0 }) == .ok);
    try testing.expectEqual(@as(u16, 120), sys.getWinsize(slave.raw()).ok.col);
    // The O_NONBLOCK master: EAGAIN with nothing to read.
    var got: [64]u8 = undefined;
    try testing.expectEqual(sys.E.AGAIN, master.read(&got).err);
    // Raw modes pass bytes as they are; both ways.
    var modes = sys.tcgetattr(slave.raw()).ok;
    sys.cfmakeraw(&modes);
    try testing.expect(slave.tcsetattr(.now, &modes) == .ok);
    try testing.expectEqual(sys.Result(usize){ .ok = 4 }, sys.write(slave.raw(), "out\n"));
    var p = [1]sys.pollfd{fdt.pollEntry(master, sys.POLL.IN)};
    try testing.expect(sys.poll(&p, 10_000) == .ok);
    try testing.expectEqualStrings("out\n", got[0..master.read(&got).ok]);
    try testing.expectEqual(sys.Result(usize){ .ok = 3 }, master.write("in\n"));
    try testing.expectEqualStrings("in\n", got[0..sys.read(slave.raw(), &got).ok]);
    // Output the slave wrote before its last close is still read, then
    // EIO: every slave is closed (flong-tty.c:441, 501).
    try testing.expectEqual(sys.Result(usize){ .ok = 4 }, sys.write(slave.raw(), "bye\n"));
    slave.close();
    try testing.expectEqualStrings("bye\n", got[0..master.read(&got).ok]);
    try testing.expectEqual(sys.E.IO, master.read(&got).err);
    try testing.expectEqual(start + 1, fdt.liveCount());
}

test "off a terminal: passthrough, nothing marked, and finish does nothing, twice" {
    // The test runner's stdin is not a terminal; a Tty from prepare then
    // holds nothing, and a finish of it or of Tty{} touches nothing.
    if (fdt.Stdio.in.isatty()) return error.SkipZigTest;
    const start = fdt.liveCount();
    var t: tty.Tty = .{};
    tty.finish(&t);
    try tty.prepare(&t, "box", 1000);
    try testing.expect(!t.relay and t.master == null and t.slave == null and t.out == null);
    try testing.expectEqual([3]?fdt.AnyFd{ null, null, null }, tty.stdio(&t));
    try tty.start(&t, fdt.Fd(.pidfd){ .slot = 0, .gen = 0 });
    try testing.expect(t.guard_child == null and t.modes == null);
    tty.resize(&t);
    tty.spawned(&t);
    tty.finish(&t);
    tty.finish(&t);
    try testing.expectEqual(start, fdt.liveCount());
}

/// A child whose 0-2 are a pty slave: prepare makes a relay, start forks
/// the watchdog and makes the terminal raw, and finish twice. It exits 0,
/// or with the number of the first check that failed.
const Relay = struct {
    slave: fdt.Fd(.pty_slave),

    fn body(self: Relay) noreturn {
        for (0..3) |i| if (sys.dup2(self.slave.raw(), @intCast(i)) == .err) proc.exit(10);
        var t: tty.Tty = .{};
        tty.prepare(&t, "box", 1000) catch proc.exit(11);
        if (!t.relay or t.master == null or t.out == null or !t.marked) proc.exit(12);
        tty.spawned(&t);
        const leader = switch (fdt.pidfdOpen(std.os.linux.getpid()) catch proc.exit(13)) {
            .ok => |h| h,
            .err => proc.exit(13),
        };
        tty.start(&t, leader) catch proc.exit(14);
        if (t.guard_child == null or !t.raw_mode) proc.exit(15);
        if (fdt.Stdio.in.tcgetattr().ok.lflag & sys.ICANON != 0) proc.exit(16);
        const live = fdt.liveCount();
        tty.finish(&t);
        // Everything finish put back or closed is gone from the Tty, so a
        // second finish finds nothing to do: no descriptor closed twice (a
        // stale handle panics), no watchdog reaped twice, no second clear.
        // Four closed: the master, the reopened terminal, the watchdog's
        // pipe and its pidfd.
        if (fdt.liveCount() != live - 4) proc.exit(17);
        if (t.modes != null or t.raw_mode or t.guard != null or t.guard_child != null or
            t.master != null or t.slave != null or t.out != null or t.marked) proc.exit(18);
        tty.finish(&t);
        if (fdt.liveCount() != live - 4) proc.exit(19);
        leader.close();
        proc.exit(0);
    }
};

test "a relay on a terminal: start, then finish twice restores once, closes once and clears once" {
    const master = switch (try fdt.openPtmx()) {
        .ok => |m| m,
        .err => return error.TestUnexpectedResult,
    };
    defer master.close();
    try testing.expect(master.unlock() == .ok);
    var buf: [32]u8 = undefined;
    const name = try std.fmt.bufPrintZ(&buf, "/dev/pts/{d}", .{master.ptyNumber().ok});
    const slave = switch (try fdt.openSlave(name)) {
        .ok => |s| s,
        .err => return error.TestUnexpectedResult,
    };
    defer slave.close();
    const before = sys.tcgetattr(slave.raw()).ok;
    // The control: raw modes, which the child sets, differ from these.
    try testing.expect(before.lflag & sys.ICANON != 0);
    const child = try proc.fork(.{ .keep = &.{slave.any()} }, Relay{ .slave = slave }, Relay.body);
    try testing.expectEqual(@as(u8, 0), try child.await());
    try testing.expectEqual(before, sys.tcgetattr(slave.raw()).ok);
    // What the terminal was sent: the mark, then the clear, once each.
    var got: [4096]u8 = undefined;
    var len: usize = 0;
    while (len < got.len) switch (master.read(got[len..])) {
        .ok => |n| if (n == 0) break else {
            len += n;
        },
        .err => break,
    };
    var mark_buf: [256]u8 = undefined;
    const mark = tty.mark(&mark_buf, "box", 1000).?;
    var want: [512]u8 = undefined;
    try testing.expectEqualStrings(try std.fmt.bufPrint(&want, "{s}{s}", .{ mark, tty.unmark }), got[0..len]);
}

// ---- the escape: a model over any chunking ----

/// One keystroke: a ^] or another byte, and when its read happened.
const Key = struct { escape: bool, at: i64 };

/// The C's rule as a model over the whole input, not a machine fed bytes:
/// within each run of ^] with nothing between, the presses group from a
/// run's first: a press more than a second after its group's first starts
/// the next group there. The escape completes at the third press of a
/// group (flong-tty.c:360-372, 479-486).
fn model(keys: []const Key) usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i < keys.len) {
        if (!keys[i].escape) {
            i += 1;
            continue;
        }
        var group_first = keys[i].at;
        var in_group: usize = 0;
        while (i < keys.len and keys[i].escape) : (i += 1) {
            if (in_group > 0 and keys[i].at - group_first > std.time.ns_per_s) {
                group_first = keys[i].at;
                in_group = 0;
            }
            in_group += 1;
            if (in_group == 3) n += 1;
        }
    }
    return n;
}

/// The times of the ^] fed so far, one per call, as the relay's clock is
/// read once per ^] it sees.
const Clock = struct {
    keys: []const Key,
    i: usize = 0,

    pub fn now(self: *Clock) i64 {
        while (!self.keys[self.i].escape) self.i += 1;
        const at = self.keys[self.i].at;
        self.i += 1;
        return at;
    }
};

/// A case: keystrokes as (kind, gap in ms) pairs, and read sizes; minish's
/// tuples.
fn escapeAgrees(case: anytype) !void {
    var keys: [64]Key = undefined;
    var bytes: [64]u8 = undefined;
    var at: i64 = 0;
    const n = @min(case[0].len, keys.len);
    for (case[0][0..n], 0..) |k, i| {
        // Mostly ^], so runs of three happen; a quarter of the gaps none
        // at all, so three at one instant happen; the others up to 1.1 s,
        // with the second's edge itself in play.
        at += if (k[1] >= 1500) std.time.ns_per_s else if (k[1] < 400) 0 else @as(i64, k[1] - 400) * std.time.ns_per_ms;
        keys[i] = .{ .escape = k[0] < 3, .at = at };
        bytes[i] = if (k[0] < 3) tty.Escape.key else "x\r\x00\x1c"[k[0] - 3];
    }
    // The same bytes fed in the case's chunks.
    var e: tty.Escape = .{};
    var clock: Clock = .{ .keys = keys[0..n] };
    var got: usize = 0;
    var off: usize = 0;
    var c: usize = 0;
    while (off < n) : (c += 1) {
        const size: usize = if (c < case[1].len) @max(1, case[1][c]) else n - off;
        const end = @min(n, off + size);
        got += e.feed(bytes[off..end], &clock);
        off = end;
    }
    try testing.expectEqual(model(keys[0..n]), got);
    // And the plain reading, as far as it goes: a completion needs three
    // ^] with nothing between within a second, and three at one instant
    // after another key (or none) always complete.
    var within = false;
    var instant = false;
    for (2..@max(n, 2)) |i| {
        const three = keys[i].escape and keys[i - 1].escape and keys[i - 2].escape;
        if (three and keys[i].at - keys[i - 2].at <= std.time.ns_per_s) within = true;
        if (three and keys[i].at == keys[i - 2].at and (i == 2 or !keys[i - 3].escape)) instant = true;
    }
    if (got > 0) try testing.expect(within);
    if (instant) try testing.expect(got > 0);
    if (instant) instants += 1;
    if (got > 0) completions += 1;
}

/// How many cases had three ^] at one instant, and how many completed the
/// escape: the controls that the property's plain reading is not vacuous.
var instants: usize = 0;
var completions: usize = 0;

/// The type of the values generator type G makes.
fn Value(comptime G: type) type {
    const f = @typeInfo(@typeInfo(@FieldType(G, "generateFn")).pointer.child).@"fn";
    return @typeInfo(f.return_type.?).error_union.payload;
}

test "property: the escape is the model's, over any chunking of the reads" {
    const gen = minish.gen;
    const key = comptime gen.tuple2(u8, u16, gen.intRange(u8, 0, 6), gen.intRange(u16, 0, 1600));
    const Key2 = Value(@TypeOf(key));
    const keys = comptime gen.list(Key2, key, 0, 40);
    const chunks = comptime gen.list(u8, gen.intRange(u8, 0, 8), 0, 20);
    const case = comptime gen.tuple2([]const Key2, []const u8, keys, chunks);
    try minish.check(testing.allocator, case, escapeAgrees, .{ .num_runs = 10_000, .seed = 0x1d1d1d });
    try minish.check(testing.allocator, case, escapeAgrees, .{ .num_runs = 10_000 });
    try testing.expect(instants > 1000 and completions > 1000);
}

test "the model's own controls: 137's three, and what falls short" {
    const s = std.time.ns_per_s;
    try testing.expectEqual(@as(usize, 1), model(&.{ .{ .escape = true, .at = 0 }, .{ .escape = true, .at = 0 }, .{ .escape = true, .at = 0 } }));
    try testing.expectEqual(@as(usize, 0), model(&.{ .{ .escape = true, .at = 0 }, .{ .escape = false, .at = 0 }, .{ .escape = true, .at = 0 }, .{ .escape = true, .at = 0 } }));
    try testing.expectEqual(@as(usize, 1), model(&.{ .{ .escape = true, .at = 0 }, .{ .escape = true, .at = s / 2 }, .{ .escape = true, .at = s } }));
    try testing.expectEqual(@as(usize, 0), model(&.{ .{ .escape = true, .at = 0 }, .{ .escape = true, .at = s / 2 }, .{ .escape = true, .at = s + 1 } }));
    // The group restarts at the late press, not at a sliding window.
    try testing.expectEqual(@as(usize, 0), model(&.{ .{ .escape = true, .at = 0 }, .{ .escape = true, .at = 9 * s / 10 }, .{ .escape = true, .at = s + 1 }, .{ .escape = true, .at = s + 2 } }));
    try testing.expectEqual(@as(usize, 2), model(&.{ .{ .escape = true, .at = 0 }, .{ .escape = true, .at = 0 }, .{ .escape = true, .at = 0 }, .{ .escape = true, .at = 2 * s }, .{ .escape = true, .at = 2 * s }, .{ .escape = true, .at = 2 * s } }));
}
