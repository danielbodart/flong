//! launch/childpid.zig from outside (minish, the `test` step; DESIGN.md,
//! "Tests": the child-pid parser over split reads and the 4096-byte bound,
//! and fuzzing). `childpid.wait` is driven by a scripted source standing
//! for the info pipe and bwrap's pidfd: its bytes served in chunks the test
//! picks, a read failing with EINTR on the way, then EOF, bwrap's exit, or a
//! read error. What the loop says is read back from stderr, a memfd for the
//! length of each call.
//!
//! - fixed cases: each refusal of flong-launch.c:485-511 with its message,
//!   the bound at each side of 4095 bytes, EINTR, an aborted wait;
//! - a property: bwrap's JSON (any pid, any namespaces, any space around
//!   the colon) under any chunking gives its pid, says nothing, and reads
//!   nothing past the read that completed the pid;
//! - a property: a malformed or oversize info under any chunking is refused
//!   with the C's message, quoting what was read;
//! - fuzzing: the corpus (tests/zig/corpus/launch-childpid/, one input per
//!   file, a crash found added there) replayed first under several
//!   chunkings and ends, then `runs` token-built and `runs` raw inputs under
//!   a fixed seed and again under a random one, each checked against what
//!   the whole input says (`expected`): the answer is the same under every
//!   chunking, and a refusal quotes exactly the bytes read.
//!
//! This is its own test root, not a target of tests/zig/fuzz.zig: that file
//! is the sweep's, and trunk's; the branch adds only to build.zig's
//! launcher block (the Zig port's phase 7).

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const minish = @import("minish");
const sys = @import("sys");
const msg = @import("msg");
const sig = @import("sig");
const childpid = @import("childpid");
const options = @import("options");
const testing = std.testing;

const max_read = childpid.max_read;

/// As tests/zig/fuzz.zig: 10,000 in ReleaseSafe, 1,000 in Debug.
const runs = if (builtin.mode == .Debug) 1_000 else 10_000;
const fixed_seed = 0xc41d;

fn randomSeed() u64 {
    var b: [8]u8 = undefined;
    _ = linux.getrandom(&b, b.len, 0);
    return std.mem.readInt(u64, &b, .little);
}

// ---- stderr, by raw calls ----

/// What a call wrote on stderr: fd 2 is a memfd for its length.
const Capture = struct {
    saved: i32,
    file: i32,

    fn begin() !Capture {
        const mf = linux.memfd_create("childpid-test", linux.MFD.CLOEXEC);
        if (linux.E.init(mf) != .SUCCESS) return error.Memfd;
        const saved = linux.fcntl(2, 1030, 10); // F_DUPFD_CLOEXEC
        if (linux.E.init(saved) != .SUCCESS) return error.Dup;
        if (linux.E.init(linux.dup2(@intCast(mf), 2)) != .SUCCESS) return error.Dup;
        return .{ .saved = @intCast(saved), .file = @intCast(mf) };
    }

    fn end(self: Capture, buf: []u8) ![]const u8 {
        _ = linux.dup2(self.saved, 2);
        _ = linux.close(self.saved);
        defer _ = linux.close(self.file);
        const n = linux.pread(self.file, buf.ptr, buf.len, 0);
        if (linux.E.init(n) != .SUCCESS) return error.Read;
        return buf[0..n];
    }
};

// ---- the scripted source ----

/// What follows the last byte served.
const End = enum {
    /// every writer gone: a read returns 0
    eof,
    /// bwrap exits while its child still holds the pipe: ready() says so
    exit,
    /// the next read fails with EIO
    fail,
};

/// The info pipe and bwrap's pidfd, played from `data`: each read serves
/// the next of `cuts` (cycled; 0 is a read failing with EINTR, and every
/// cut is also bounded by what is left and by the room offered), then
/// `end`. It checks the loop's side of the bound as it goes: every read
/// offers exactly the room left below `max_read`, never none, and no read
/// comes after EOF or an error; the first that does ends the loop.
const Script = struct {
    data: []const u8,
    cuts: []const u16,
    end: End,
    /// ready() fails with this, in place of reporting readiness, before
    /// the read that would serve byte `abort_at` (null: never).
    abort_at: ?usize = null,

    served: usize = 0,
    k: usize = 0,
    reads: usize = 0,
    /// served after each read that served bytes, in order
    marks: [max_read + 1]usize = undefined,
    nmarks: usize = 0,
    ended: bool = false,
    wrong: ?[]const u8 = null,

    pub fn ready(self: *Script) sig.Error!bool {
        // A loop gone wrong is ended here, as a signal would end it, so a
        // loop that never stops fails the test and does not hang it.
        if (self.wrong != null) return error.Aborted;
        if (self.abort_at) |at| if (self.served >= at) return error.Aborted;
        return !(self.served == self.data.len and self.end == .exit);
    }

    pub fn read(self: *Script, buf: []u8) sys.Result(usize) {
        self.reads += 1;
        if (self.ended) self.wrong = "read again after EOF or an error";
        if (buf.len == 0) self.wrong = "a read with no room";
        if (buf.len != max_read - self.served) self.wrong = "the room is not what is left below the bound";
        if (self.served == self.data.len) {
            self.ended = true;
            return switch (self.end) {
                .eof => .{ .ok = 0 },
                .fail => .{ .err = .IO },
                .exit => blk: {
                    self.wrong = "read after bwrap's exit";
                    break :blk .{ .ok = 0 };
                },
            };
        }
        var cut: usize = 0;
        if (self.cuts.len > 0) {
            cut = self.cuts[self.k % self.cuts.len];
            self.k += 1;
            // An EINTR, unless every cut is one.
            if (cut == 0 and self.k <= 4 * self.cuts.len) return .{ .err = .INTR };
        }
        if (cut == 0) cut = self.data.len;
        const n = @min(cut, self.data.len - self.served, buf.len);
        @memcpy(buf[0..n], self.data[self.served..][0..n]);
        self.served += n;
        self.marks[self.nmarks] = self.served;
        self.nmarks += 1;
        return .{ .ok = n };
    }
};

// ---- what the loop answers, and what it should ----

const Outcome = union(enum) {
    pid: sys.pid_t,
    /// refused: what it said, one message on stderr
    said: []const u8,
    aborted,
};

var errbuf: [4096]u8 = undefined;

fn run(s: *Script) !Outcome {
    msg.prog = "flong-launch";
    msg.mode = .cut;
    const cap = try Capture.begin();
    const r = childpid.wait(s);
    const err = try cap.end(&errbuf);
    if (s.wrong) |w| {
        std.debug.print("childpid.wait: {s}\n", .{w});
        return error.Bound;
    }
    const pid = r catch |e| switch (e) {
        error.Reported => return .{ .said = err },
        error.Aborted => {
            try testing.expectEqualStrings("", err);
            return .aborted;
        },
    };
    try testing.expectEqualStrings("", err);
    return .{ .pid = pid };
}

/// The launcher's line for a body in `parts`: "flong-launch: ", the body,
/// all cut at 1022 bytes, then the newline (msg.zig's cut mode,
/// flong-util.c:67-79).
fn line(buf: []u8, parts: []const []const u8) []const u8 {
    const prefix = "flong-launch: ";
    @memcpy(buf[0..prefix.len], prefix);
    var n: usize = prefix.len;
    for (parts) |p| {
        const k = @min(p.len, msg.cut_len - n);
        @memcpy(buf[n..][0..k], p[0..k]);
        n += k;
    }
    buf[n] = '\n';
    return buf[0 .. n + 1];
}

var want_buf: [2048]u8 = undefined;

/// What a refused loop said; a pid or an abort fails the test.
fn saidOf(o: Outcome) ![]const u8 {
    return switch (o) {
        .said => |t| t,
        else => {
            std.debug.print("want a refusal, got {any}\n", .{o});
            return error.NotRefused;
        },
    };
}

fn cString(b: []const u8) []const u8 {
    return b[0 .. std.mem.indexOfScalar(u8, b, 0) orelse b.len];
}

const failed = "flong-launch: bwrap failed before it made the sandbox\n";
const read_failed = "flong-launch: read bwrap's info: Input/output error\n";

/// What the loop must answer for `data` then `end`, from the whole input,
/// whatever the chunking: the pid if one is whole within the bound; else
/// which refusal. A "no child pid" refusal quotes what was read when it
/// stopped, which the chunking decides; `check` holds that part.
const Want = union(enum) { pid: sys.pid_t, failed, read_failed, no_pid };

fn expected(data: []const u8, end: End) Want {
    if (data.len >= max_read) {
        return switch (childpid.parse(data[0..max_read], false)) {
            .pid => |p| .{ .pid = p },
            else => .no_pid,
        };
    }
    const at_end = childpid.parse(data, end == .eof);
    if (at_end == .pid) return .{ .pid = at_end.pid };
    // Refused before the end if a prefix read is already malformed; the
    // prefix at the end is the whole, so that is a malformed whole.
    if (childpid.parse(data, false) == .malformed) return .no_pid;
    return switch (end) {
        .eof => if (data.len == 0) .failed else .no_pid,
        .exit => .failed,
        .fail => .read_failed,
    };
}

/// Runs `s` and checks its outcome against `expected`, and that the loop
/// stopped where the C stops: at the first read after which the bytes read
/// say something other than "more", and a refusal quotes exactly them.
fn check(s: *Script) !Outcome {
    const got = try run(s);
    const want = expected(s.data, s.end);
    errdefer std.debug.print("childpid over \"{f}\" ({d} bytes), end {s}, cuts {any}: want {any}, got {any}\n", .{
        std.zig.fmtString(s.data[0..@min(s.data.len, 300)]), s.data.len, @tagName(s.end), s.cuts[0..@min(s.cuts.len, 20)], want, got,
    });
    // Every read before the last left the bytes read "more".
    if (s.nmarks > 0) for (s.marks[0 .. s.nmarks - 1]) |m| {
        try testing.expectEqual(childpid.Answer.more, childpid.parse(s.data[0..m], false));
    };
    switch (want) {
        .pid => |p| {
            try testing.expectEqual(Outcome{ .pid = p }, got);
            // Nothing read after the read that completed it: EOF is read
            // only when the digits needed it to be whole.
            if (s.ended) {
                try testing.expect(s.end == .eof and s.served == s.data.len);
                try testing.expectEqual(childpid.Answer.more, childpid.parse(s.data, false));
            } else {
                try testing.expectEqual(Outcome{ .pid = p }, switch (childpid.parse(s.data[0..s.served], false)) {
                    .pid => |q| Outcome{ .pid = q },
                    else => Outcome.aborted,
                });
            }
        },
        .failed => try testing.expectEqualStrings(failed, try saidOf(got)),
        .read_failed => try testing.expectEqualStrings(read_failed, try saidOf(got)),
        .no_pid => {
            const quoted = cString(s.data[0..s.served]);
            try testing.expectEqualStrings(line(&want_buf, &.{ "bwrap reported no child pid: ", quoted }), try saidOf(got));
            // It stopped because the bytes read are malformed, or at EOF,
            // or at the bound.
            const at_eof = s.ended and s.end == .eof;
            try testing.expect(s.served == max_read or at_eof or
                childpid.parse(s.data[0..s.served], false) == .malformed);
        },
    }
    return got;
}

fn script(data: []const u8, cuts: []const u16, end: End) Script {
    return .{ .data = data, .cuts = cuts, .end = end };
}

// ---- fixed cases ----

const bwrap_json = "{\n    \"child-pid\": 31337,\n    \"cgroup-namespace\": 4026531835,\n    \"ipc-namespace\": 4026532461,\n    \"mnt-namespace\": 4026532459,\n    \"net-namespace\": 4026532464,\n    \"pid-namespace\": 4026532462,\n    \"uts-namespace\": 4026532460\n}\n";

test "bwrap's JSON, whole, byte by byte, and in bwrap's own writes" {
    for ([_][]const u16{ &.{}, &.{1}, &.{ 3, 0, 7 }, &.{ 26, 38, 200 } }) |cuts| {
        for ([_]End{ .eof, .exit, .fail }) |end| {
            var s = script(bwrap_json, cuts, end);
            try testing.expectEqual(Outcome{ .pid = 31337 }, try check(&s));
        }
    }
    // bwrap's first write is `{\n    "child-pid": N` alone: the pid is
    // whole only with the next write's comma, and the loop waits for it.
    var s = script(bwrap_json, &.{ 24, 1 }, .eof);
    try testing.expectEqual(Outcome{ .pid = 31337 }, try check(&s));
    try testing.expectEqual(@as(usize, 2), s.reads);
    try testing.expectEqual(@as(usize, 25), s.served);
}

test "the refusals, each with the C's message" {
    const cases = [_]struct { data: []const u8, end: End, said: []const u8 }{
        .{ .data = "", .end = .eof, .said = failed },
        .{ .data = "", .end = .exit, .said = failed },
        .{ .data = "{\n    \"child-pid\": 5", .end = .exit, .said = failed },
        .{ .data = "", .end = .fail, .said = read_failed },
        .{ .data = "{\n    \"child-pid\": 5", .end = .fail, .said = read_failed },
        .{ .data = "{}\n", .end = .eof, .said = "flong-launch: bwrap reported no child pid: {}\n\n" },
        .{ .data = "{\"child-pid\": -1,", .end = .eof, .said = "flong-launch: bwrap reported no child pid: {\"child-pid\": -1,\n" },
        .{ .data = "{\"child-pid\" = 1,", .end = .exit, .said = "flong-launch: bwrap reported no child pid: {\"child-pid\" = 1,\n" },
        .{ .data = "{\"child-pid\": 1234567890}", .end = .eof, .said = "flong-launch: bwrap reported no child pid: {\"child-pid\": 1234567890}\n" },
        .{ .data = "{\"child-pid\": 0,", .end = .eof, .said = "flong-launch: bwrap reported no child pid: {\"child-pid\": 0,\n" },
        .{ .data = "{\"child-pid\": 12", .end = .eof, .said = "" },
        .{ .data = "{\"child-\x00pid\": 12,", .end = .eof, .said = "flong-launch: bwrap reported no child pid: {\"child-\n" },
    };
    for (cases) |c| {
        var s = script(c.data, &.{}, c.end);
        const got = try check(&s);
        if (c.said.len == 0) {
            // The digits at EOF are whole.
            try testing.expectEqual(Outcome{ .pid = 12 }, got);
        } else {
            try testing.expectEqualStrings(c.said, try saidOf(got));
        }
    }
}

test "a malformed info is refused at once, quoting only what was read" {
    // The key's colon is missing in the first write: nothing more is read.
    var s = script("{\"child-pid\"; and more to come", &.{ 13, 5 }, .eof);
    try testing.expectEqualStrings("flong-launch: bwrap reported no child pid: {\"child-pid\";\n", try saidOf(try check(&s)));
    try testing.expectEqual(@as(usize, 1), s.reads);
}

test "EINTR reads again; an aborted wait says nothing" {
    var s = script(bwrap_json, &.{ 0, 0, 5, 0 }, .eof);
    try testing.expectEqual(Outcome{ .pid = 31337 }, try check(&s));
    for ([_]usize{ 0, 1, 20, 24 }) |at| {
        var a = script(bwrap_json, &.{1}, .eof);
        a.abort_at = at;
        try testing.expectEqual(Outcome.aborted, try run(&a));
        try testing.expectEqual(at, a.served);
    }
}

/// `pad` bytes of space, then `tail`, in `buf`.
fn padded(buf: []u8, pad: usize, tail: []const u8) []const u8 {
    @memset(buf[0..pad], ' ');
    @memcpy(buf[pad..][0..tail.len], tail);
    return buf[0 .. pad + tail.len];
}

test "the 4095-byte bound, at each side" {
    var buf: [2 * childpid.buf_len]u8 = undefined;
    var said_buf: [2048]u8 = undefined;
    const long_said = line(&said_buf, &.{ "bwrap reported no child pid: ", " " ** max_read });
    try testing.expectEqual(@as(usize, 1023), long_said.len);
    try testing.expect(std.mem.endsWith(u8, long_said, "pid:" ++ " " ** 980 ++ "\n"));
    for ([_][]const u16{ &.{}, &.{1000}, &.{ 4094, 1 }, &.{4095} }) |cuts| {
        // No key in 4095 bytes: refused at the bound, never read past it,
        // the message cut at 1022 bytes.
        {
            var s = script(padded(&buf, 5000, bwrap_json), cuts, .eof);
            try testing.expectEqualStrings(long_said, try saidOf(try check(&s)));
            try testing.expectEqual(@as(usize, max_read), s.served);
        }
        // The pid's comma is byte 4095: whole.
        {
            const tail = "\"child-pid\": 77,";
            var s = script(padded(&buf, max_read - tail.len, tail), cuts, .eof);
            try testing.expectEqual(Outcome{ .pid = 77 }, try check(&s));
        }
        // The digits end at byte 4095 with more to come: not known to be
        // whole, refused, though the pipe has the comma.
        {
            const tail = "\"child-pid\": 77";
            var s = script(padded(&buf, max_read - tail.len, tail ++ ",\n}\n"), cuts, .eof);
            try testing.expectEqualStrings(long_said, try saidOf(try check(&s)));
        }
        // The same digits end at byte 4094, then EOF: whole.
        {
            const tail = "\"child-pid\": 77";
            var s = script(padded(&buf, max_read - 1 - tail.len, tail), cuts, .eof);
            try testing.expectEqual(Outcome{ .pid = 77 }, try check(&s));
        }
        // Exactly 4095 bytes, then EOF: the bound comes first.
        {
            const tail = "\"child-pid\": 77";
            var s = script(padded(&buf, max_read - tail.len, tail), cuts, .eof);
            try testing.expectEqualStrings(long_said, try saidOf(try check(&s)));
            try testing.expect(!s.ended);
        }
    }
}

// ---- properties ----

/// bwrap's JSON, drawn: a pid of 1 to 9 digits (leading zeros too), each
/// space around the colon from " \t\n", 0 to 8 namespaces, the closing
/// brace or not.
fn drawJson(r: std.Random, buf: []u8) struct { []const u8, sys.pid_t } {
    var w: std.Io.Writer = .fixed(buf);
    const pid = r.intRangeAtMost(sys.pid_t, 1, 999_999_999);
    w.writeAll("{\n    \"child-pid\"") catch unreachable; // proven: buf holds the longest draw
    const spaces = " \t\n";
    for (0..r.uintAtMost(usize, 3)) |_| w.writeByte(spaces[r.uintLessThan(usize, 3)]) catch unreachable; // proven: as above
    w.writeByte(':') catch unreachable; // proven: as above
    for (0..r.uintAtMost(usize, 3)) |_| w.writeByte(spaces[r.uintLessThan(usize, 3)]) catch unreachable; // proven: as above
    const zeros = r.uintAtMost(usize, 9 - std.fmt.count("{d}", .{pid}));
    for (0..zeros) |_| w.writeByte('0') catch unreachable; // proven: as above
    w.print("{d}", .{pid}) catch unreachable; // proven: as above
    for (0..r.uintAtMost(usize, 8)) |_| w.print(",\n    \"ns{d}-namespace\": {d}", .{ r.int(u8), r.int(u32) }) catch unreachable; // proven: as above
    if (r.boolean()) w.writeAll("\n}\n") catch unreachable; // proven: as above
    return .{ w.buffered(), pid };
}

fn drawCuts(r: std.Random, buf: []u16) []const u16 {
    const n = r.uintAtMost(usize, buf.len);
    for (buf[0..n]) |*c| c.* = switch (r.uintLessThan(u8, 4)) {
        0 => 0,
        1 => r.uintAtMost(u16, 4),
        2 => r.uintAtMost(u16, 40),
        else => r.uintAtMost(u16, 5000),
    };
    return buf[0..n];
}

var draw_buf: [2 * childpid.buf_len]u8 = undefined;
var cut_buf: [16]u16 = undefined;

fn anyChunking(seed: u64) !void {
    var prng = std.Random.DefaultPrng.init(seed);
    const r = prng.random();
    const json, const pid = drawJson(r, &draw_buf);
    const cuts = drawCuts(r, &cut_buf);
    // bwrap may end either way once its JSON is written, or a later read
    // fail: none is reached once the pid is whole, which a closed brace or
    // a namespace makes it; else only EOF makes it whole.
    const whole = std.mem.indexOfScalar(u8, json, ',') != null or std.mem.endsWith(u8, json, "}\n");
    const end: End = if (whole) r.enumValue(End) else .eof;
    var s = script(json, cuts, end);
    const got = try check(&s);
    try testing.expectEqual(Outcome{ .pid = pid }, got);
}

test "property: bwrap's JSON under any chunking gives its pid, says nothing, reads no further" {
    try minish.check(testing.allocator, minish.gen.int(u64), anyChunking, .{ .num_runs = runs, .seed = fixed_seed });
    try minish.check(testing.allocator, minish.gen.int(u64), anyChunking, .{ .num_runs = runs, .seed = randomSeed() });
}

/// One fault in bwrap's JSON, drawn: each is refused with the C's message.
fn drawFault(r: std.Random, json: []const u8, buf: []u8) []const u8 {
    const colon = std.mem.indexOfScalar(u8, json, ':').?;
    const key_at = std.mem.indexOf(u8, json, "\"child-pid\"").?;
    const digits_at = colon + 1 + (std.mem.indexOfNone(u8, json[colon + 1 ..], " \t\n") orelse 0);
    var w: std.Io.Writer = .fixed(buf);
    switch (r.uintLessThan(u8, 8)) {
        // the colon replaced
        0 => w.print("{s}={s}", .{ json[0..colon], json[colon + 1 ..] }) catch unreachable, // proven: buf is twice json
        // a sign before the digits
        1 => w.print("{s}{c}{s}", .{ json[0..digits_at], "-+"[r.uintLessThan(usize, 2)], json[digits_at..] }) catch unreachable, // proven: as above
        // ten digits or more
        2 => w.print("{s}{d}{s}", .{ json[0..digits_at], r.intRangeAtMost(u64, 1_000_000_000, 99_999_999_999), json[digits_at..] }) catch unreachable, // proven: as above
        // no digits
        3 => w.print("{s}x{s}", .{ json[0..digits_at], json[digits_at..] }) catch unreachable, // proven: as above
        // a '\r' before the colon
        4 => w.print("{s}\r{s}", .{ json[0..colon], json[colon..] }) catch unreachable, // proven: as above
        // a NUL before the key
        5 => w.print("{s}\x00{s}", .{ json[0..key_at], json[key_at..] }) catch unreachable, // proven: as above
        // no key
        6 => w.print("{s}{s}", .{ json[0 .. key_at + 1], json[key_at + 2 ..] }) catch unreachable, // proven: as above
        // the key past the bound
        else => {
            const pad = max_read - r.uintAtMost(usize, key_at + 8);
            for (0..pad) |_| w.writeByte(" \t\n"[r.uintLessThan(usize, 3)]) catch unreachable; // proven: buf holds max_read + json
            w.writeAll(json) catch unreachable; // proven: as above
        },
    }
    return w.buffered();
}

var fault_buf: [3 * childpid.buf_len]u8 = undefined;

fn anyFault(seed: u64) !void {
    var prng = std.Random.DefaultPrng.init(seed);
    const r = prng.random();
    const json, _ = drawJson(r, &draw_buf);
    const bad = drawFault(r, json, &fault_buf);
    var s = script(bad, drawCuts(r, &cut_buf), .eof);
    const got = try check(&s);
    try testing.expect(got == .said);
    try testing.expect(std.mem.startsWith(u8, try saidOf(got), "flong-launch: bwrap reported no child pid: "));
}

test "property: a malformed or oversize info is refused with the C's message, under any chunking" {
    try minish.check(testing.allocator, minish.gen.int(u64), anyFault, .{ .num_runs = runs, .seed = fixed_seed });
    try minish.check(testing.allocator, minish.gen.int(u64), anyFault, .{ .num_runs = runs, .seed = randomSeed() });
}

// ---- fuzzing ----

/// How many inputs of the current run gave a pid, and how many were
/// refused: a builder that never reaches the pid, or never misses it,
/// would pass having tested half the loop.
var reached: usize = 0;
var turned: usize = 0;

/// Each input under a chunking and an end drawn from `seed`.
fn fuzzOne(data: []const u8, seed: u64) !void {
    var prng = std.Random.DefaultPrng.init(seed);
    const r = prng.random();
    var s = script(data, drawCuts(r, &cut_buf), r.enumValue(End));
    switch (try check(&s)) {
        .pid => |p| {
            reached += 1;
            try testing.expect(p >= 1 and p <= 999_999_999);
            try testing.expect(std.mem.indexOf(u8, data, "\"child-pid\"") != null);
        },
        .said => turned += 1,
        .aborted => return error.Unexpected,
    }
}

var token_buf: [48 * 700]u8 = undefined;

/// A token list as an info: key, colon, space, digits, NUL, padding
/// towards the bound, bwrap's namespace lines, any byte.
fn tokensTo(t: []const u16, buf: []u8) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    for (t) |tok| {
        const arg = tok >> 4;
        (switch (tok & 15) {
            0, 1 => w.writeAll("\"child-pid\""),
            2, 3 => w.writeByte(':'),
            4 => w.writeByte(' '),
            5 => w.writeByte("\t\n\r\x0b"[arg % 4]),
            6, 7 => w.print("{d}", .{@as(u64, arg) * (arg % 97 + 1)}),
            8 => w.writeByte('0'),
            9 => w.writeByte(0),
            10 => w.writeAll(",\n    \"net-namespace\": 4026532464"),
            11 => w.writeAll("\n}\n"),
            12 => w.writeByte("-+{},\""[arg % 6]),
            13 => w.splatByteAll(' ', arg % 700),
            14 => w.writeByte(@truncate(arg)),
            else => w.writeAll("{\n    \"child-pid\": "),
        }) catch break;
    }
    return w.buffered();
}

fn fromTokens(v: anytype) !void {
    try fuzzOne(tokensTo(v[0], &token_buf), v[1]);
}

fn fromBytes(v: anytype) !void {
    try fuzzOne(v[0], v[1]);
}

/// Every file of tests/zig/corpus/launch-childpid/, under each end and
/// several chunkings: whole, byte by byte, 3 with EINTRs, and 4095.
fn replay() !void {
    var root = try std.fs.openDirAbsolute(options.corpus, .{});
    defer root.close();
    var dir = try root.openDir("launch-childpid", .{ .iterate = true });
    defer dir.close();
    var it = dir.iterate();
    var n: usize = 0;
    while (try it.next()) |e| {
        if (e.kind != .file) continue;
        const b = try dir.readFileAlloc(testing.allocator, e.name, 1 << 20);
        defer testing.allocator.free(b);
        for ([_][]const u16{ &.{}, &.{1}, &.{ 3, 0 }, &.{4095} }) |cuts| {
            for ([_]End{ .eof, .exit, .fail }) |end| {
                var s = script(b, cuts, end);
                _ = check(&s) catch |err| {
                    std.debug.print("corpus launch-childpid/{s} fails\n", .{e.name});
                    return err;
                };
            }
        }
        n += 1;
    }
    // A corpus that is not there would pass having replayed nothing.
    try testing.expect(n > 0);
}

test "fuzz childpid.wait, the corpus first" {
    try replay();
    const token_gen = minish.gen.tuple2([]const u16, u64, minish.gen.list(u16, minish.gen.int(u16), 0, 48), minish.gen.int(u64));
    const byte_gen = minish.gen.tuple2([]const u8, u64, minish.gen.list(u8, minish.gen.int(u8), 0, 512), minish.gen.int(u64));
    for ([_]u64{ fixed_seed, randomSeed() }) |seed| {
        reached = 0;
        turned = 0;
        try minish.check(testing.allocator, token_gen, fromTokens, .{ .num_runs = runs, .seed = seed });
        if (reached < runs / 100 or turned < runs / 100) {
            std.debug.print("fuzz launch-childpid: seed {x}: {d} gave a pid, {d} refused\n", .{ seed, reached, turned });
            return error.Unreached;
        }
        try minish.check(testing.allocator, byte_gen, fromBytes, .{ .num_runs = runs, .seed = seed });
    }
}
