//! msg.zig: what flong's programs print on stderr, and how they die (ZIG.md,
//! "Messages, errors and panics").
//!
//! Every message is "<prog>: <body>\n", written unbuffered in one call, EINTR
//! retried and a failure dropped: there is nowhere left to report it
//! (flong-util.c:37-49). No std.debug.print, std.log or buffered stderr. Two
//! modes, as the C has:
//!
//!   cut    the body cut at 1022 bytes, then the newline, one write: the
//!          launcher, its children, the mount helper and flong-sweeper
//!          (flong-util.c:51-79, a 1024-byte buffer, one byte kept free)
//!   whole  the body however long, one writev of its pieces: flong-init and
//!          flong-seccomp, whose messages quote a word of up to 4095 bytes
//!          (flong-seccomp.c:75) or a directory of any length
//!          (flong-init.c:59-67)
//!
//! A format is Zig's, reduced: `{s}` takes a string (a slice, a literal or a
//! [*:0]const u8) and becomes a piece of its own, uncopied, so a whole
//! message needs no buffer and no allocator; any other `{...}` formats one
//! value (a number, in practice) into a 64-byte scratch with that spec;
//! `{{` and `}}` are braces. A count of arguments that does not match the
//! format is a compile error.
//!
//! Failures travel as `error.Reported`: printed once, where they happened,
//! then passed up with nothing more to say.

const std = @import("std");
const sys = @import("sys");
const errno = @import("errno");

pub const Mode = enum { cut, whole };

/// The program's name, the prefix of every message. Each root sets it
/// first, with `mode`.
pub var prog: []const u8 = "flong";
pub var mode: Mode = .cut;

/// fl_tracing (flong-util.h:43): stage stamps are printed only when set.
pub var tracing: bool = false;

/// The longest body cut mode prints (flong-util.c:67-70).
pub const cut_len = 1022;

/// A failure already printed.
pub const Error = error{Reported};

/// Says "<prog>: <body>\n" and goes on (fl_errx without the error).
pub fn say(comptime fmt: []const u8, args: anytype) void {
    emit(fmt, args, null);
}

/// fl_err's message where the caller goes on: "<prog>: <body>: <strerror(e)>".
pub fn sayErrno(e: sys.E, comptime fmt: []const u8, args: anytype) void {
    emit(fmt, args, e);
}

/// Says "<body>\n" with no prefix, as a usage line is
/// (flong-seccomp.c:334).
pub fn bare(comptime fmt: []const u8, args: anytype) void {
    emitAs(false, fmt, args, null);
}

/// fl_errx: says it, and returns the failure to pass up.
pub fn refuse(comptime fmt: []const u8, args: anytype) Error {
    emit(fmt, args, null);
    return error.Reported;
}

/// fl_err: says it with ": <strerror(e)>", and returns the failure.
pub fn fail(e: sys.E, comptime fmt: []const u8, args: anytype) Error {
    emit(fmt, args, e);
    return error.Reported;
}

/// A result's value, or its errno said as `fail` says it. An open of
/// fd.zig's is `error{TableFull}!Result(Fd(k))`, and its TableFull is said
/// as "<body>: too many open descriptors" (ZIG.md, "The descriptor layer").
pub fn check(r: anytype, comptime fmt: []const u8, args: anytype) Error!Checked(@TypeOf(r)) {
    const res = switch (@typeInfo(@TypeOf(r))) {
        .error_union => |u| blk: {
            if (u.error_set != error{TableFull})
                @compileError("msg.check: an error union other than error{TableFull}!Result");
            break :blk r catch return refuse(fmt ++ ": too many open descriptors", args);
        },
        else => r,
    };
    return switch (res) {
        .ok => |v| v,
        .err => |e| fail(e, fmt, args),
    };
}

fn Checked(comptime T: type) type {
    return switch (@typeInfo(T)) {
        .error_union => |u| @FieldType(u.payload, "ok"),
        else => @FieldType(T, "ok"),
    };
}

/// fl_die: says it (with the errno's text when there is one) and exits 125,
/// for a fork body, whose failure its parent reads as "said why"
/// (flong-util.c:98-105).
pub fn die(e: ?sys.E, comptime fmt: []const u8, args: anytype) noreturn {
    emit(fmt, args, e);
    sys.exitGroup(125);
}

/// fl_trace: "T <microseconds> <stage>\n" when tracing, stamped now.
pub fn trace(stage: []const u8) void {
    if (!tracing) return;
    traceAt(sys.clockRealtime(), stage);
}

/// fl_trace_at (flong-util.c:112-121): stamped at `t`, printed now, in a
/// 256-byte buffer. A longer line is cut at 255 bytes, newline and all, as
/// the C's snprintf leaves it.
pub fn traceAt(t: sys.timespec, stage: []const u8) void {
    if (!tracing) return;
    var buf: [256]u8 = undefined;
    const line = traceLine(&buf, t, stage);
    writeAll(&.{.{ .base = line.ptr, .len = line.len }});
}

fn traceLine(buf: *[256]u8, t: sys.timespec, stage: []const u8) []const u8 {
    const us = @as(i64, t.sec) * 1_000_000 + @divTrunc(@as(i64, t.nsec), 1000);
    var w: std.Io.Writer = .fixed(buf[0..255]);
    w.print("T {d} ", .{us}) catch return buf[0..w.end]; // a stamp is at most 22 bytes; never taken
    const room = 255 - w.end;
    const stage_len = @min(stage.len, room);
    @memcpy(buf[w.end..][0..stage_len], stage[0..stage_len]);
    var n = w.end + stage_len;
    if (n < 255) {
        buf[n] = '\n';
        n += 1;
    }
    return buf[0..n];
}

/// The panic handler every root installs, as
/// `pub const panic = std.debug.FullPanic(msg.onPanic(status));`: one line,
/// "<prog>: internal error: <msg>", then exit_group(status). The default
/// ends in abort, which pid 1 drops (posix.zig:680-727).
pub fn onPanic(comptime status: u8) fn ([]const u8, ?usize) noreturn {
    return struct {
        fn panic(text: []const u8, _: ?usize) noreturn {
            emit("internal error: {s}", .{text}, null);
            sys.exitGroup(status);
        }
    }.panic;
}

// ---- building and writing ----

const Segment = union(enum) {
    lit: []const u8,
    arg: []const u8, // the spec between the braces
};

fn segments(comptime fmt: []const u8) []const Segment {
    comptime {
        var out: []const Segment = &.{};
        var lit: []const u8 = "";
        var i = 0;
        while (i < fmt.len) {
            if (fmt[i] == '{' and i + 1 < fmt.len and fmt[i + 1] == '{') {
                lit = lit ++ "{";
                i += 2;
            } else if (fmt[i] == '}' and i + 1 < fmt.len and fmt[i + 1] == '}') {
                lit = lit ++ "}";
                i += 2;
            } else if (fmt[i] == '{') {
                const close = std.mem.indexOfScalarPos(u8, fmt, i, '}') orelse
                    @compileError("msg: an unclosed { in \"" ++ fmt ++ "\"");
                if (lit.len > 0) out = out ++ [_]Segment{.{ .lit = lit }};
                lit = "";
                out = out ++ [_]Segment{.{ .arg = fmt[i + 1 .. close] }};
                i = close + 1;
            } else if (fmt[i] == '}') {
                @compileError("msg: an unopened } in \"" ++ fmt ++ "\"");
            } else {
                lit = lit ++ fmt[i .. i + 1];
                i += 1;
            }
        }
        if (lit.len > 0) out = out ++ [_]Segment{.{ .lit = lit }};
        const final = out;
        return final;
    }
}

fn argCount(comptime segs: []const Segment) usize {
    var n: usize = 0;
    for (segs) |s| {
        if (s == .arg) n += 1;
    }
    return n;
}

/// The pieces of one message: prog, ": ", the body's segments, then ": "
/// and the errno's text if any, then "\n".
fn pieceCount(comptime fmt: []const u8) usize {
    return segments(fmt).len + 5;
}

/// What a message's formatted values are written into, on the caller's
/// stack.
fn Scratch(comptime fmt: []const u8) type {
    return struct {
        values: [argCount(segments(fmt))][64]u8 = undefined,
        err: [errno.max_len]u8 = undefined,
    };
}

fn build(
    comptime fmt: []const u8,
    args: anytype,
    e: ?sys.E,
    scratch: *Scratch(fmt),
    iov: *[pieceCount(fmt)]sys.Iovec,
) []const sys.Iovec {
    const segs = comptime segments(fmt);
    const fields = @typeInfo(@TypeOf(args)).@"struct".fields;
    if (fields.len != comptime argCount(segs))
        @compileError(std.fmt.comptimePrint("msg: \"{s}\" takes {d} arguments, given {d}", .{ fmt, argCount(segs), fields.len }));

    var n: usize = 0;
    iov[n] = piece(prog);
    n += 1;
    iov[n] = piece(": ");
    n += 1;
    comptime var a = 0;
    inline for (segs) |seg| {
        switch (seg) {
            .lit => |text| iov[n] = piece(text),
            .arg => |spec| {
                const v = @field(args, fields[a].name);
                iov[n] = piece(if (comptime std.mem.eql(u8, spec, "s"))
                    string(v)
                else
                    std.fmt.bufPrint(&scratch.values[a], "{" ++ spec ++ "}", .{v}) catch "?");
                a += 1;
            },
        }
        n += 1;
    }
    if (e) |err| {
        iov[n] = piece(": ");
        n += 1;
        iov[n] = piece(errno.describe(err, &scratch.err));
        n += 1;
    }
    iov[n] = piece("\n");
    n += 1;
    return iov[0..n];
}

fn piece(s: []const u8) sys.Iovec {
    return .{ .base = s.ptr, .len = s.len };
}

fn string(v: anytype) []const u8 {
    const T = @TypeOf(v);
    return switch (@typeInfo(T)) {
        .pointer => |p| switch (p.size) {
            .slice => v,
            .one => v, // a literal: *const [N:0]u8
            .many => if (p.sentinel() != null) std.mem.span(v) else @compileError("msg: {s} of a many-pointer with no sentinel"),
            .c => std.mem.span(v),
        },
        else => @compileError("msg: {s} of a " ++ @typeName(T)),
    };
}

/// The cut form of `iov`: every piece but the newline, cut at `cut_len`
/// bytes, then the newline.
fn cutInto(buf: *[cut_len + 1]u8, iov: []const sys.Iovec) []const u8 {
    var n: usize = 0;
    for (iov[0 .. iov.len - 1]) |p| {
        const take = @min(p.len, cut_len - n);
        @memcpy(buf[n..][0..take], p.base[0..take]);
        n += take;
    }
    buf[n] = '\n';
    return buf[0 .. n + 1];
}

fn emit(comptime fmt: []const u8, args: anytype, e: ?sys.E) void {
    emitAs(true, fmt, args, e);
}

fn emitAs(prefixed: bool, comptime fmt: []const u8, args: anytype, e: ?sys.E) void {
    var scratch: Scratch(fmt) = .{};
    var iov: [pieceCount(fmt)]sys.Iovec = undefined;
    const all = build(fmt, args, e, &scratch, &iov);
    const pieces = if (prefixed) all else all[2..];
    switch (mode) {
        .whole => writeAll(pieces),
        .cut => {
            var buf: [cut_len + 1]u8 = undefined;
            const line = cutInto(&buf, pieces);
            writeAll(&.{piece(line)});
        },
    }
}

/// Writes every piece to stderr, going on after a short write (a pipe that
/// took part of a long message) and giving up on an error.
fn writeAll(pieces: []const sys.Iovec) void {
    var iov_buf: [64]sys.Iovec = undefined;
    var rest = pieces;
    while (rest.len > 0) {
        // IOV_MAX is 1024; no message has more than a few dozen pieces.
        const batch = rest[0..@min(rest.len, iov_buf.len)];
        @memcpy(iov_buf[0..batch.len], batch);
        var iov = iov_buf[0..batch.len];
        while (iov.len > 0) {
            var done = switch (sys.writev(2, iov)) {
                .ok => |w| w,
                .err => return,
            };
            if (done == 0) return;
            while (iov.len > 0 and done >= iov[0].len) {
                done -= iov[0].len;
                iov = iov[1..];
            }
            if (iov.len > 0) {
                iov[0].base += done;
                iov[0].len -= done;
            }
        }
        rest = rest[batch.len..];
    }
}

// ---- tests ----

const testing = std.testing;

fn joined(buf: []u8, iov: []const sys.Iovec) []const u8 {
    var n: usize = 0;
    for (iov) |p| {
        @memcpy(buf[n..][0..p.len], p.base[0..p.len]);
        n += p.len;
    }
    return buf[0..n];
}

fn render(buf: []u8, comptime fmt: []const u8, args: anytype, e: ?sys.E) []const u8 {
    var scratch: Scratch(fmt) = .{};
    var iov: [pieceCount(fmt)]sys.Iovec = undefined;
    return joined(buf, build(fmt, args, e, &scratch, &iov));
}

test "a message is prog, the body, the errno's text, a newline" {
    prog = "flong-seccomp";
    defer prog = "flong";
    var buf: [256]u8 = undefined;
    try testing.expectEqualStrings(
        "flong-seccomp: line 3: unknown directive: frob\n",
        render(&buf, "line {d}: {s}: {s}", .{ @as(u32, 3), "unknown directive", @as([]const u8, "frob") }, null),
    );
    try testing.expectEqualStrings(
        "flong-seccomp: reading the policy: Is a directory\n",
        render(&buf, "reading the policy", .{}, .ISDIR),
    );
    try testing.expectEqualStrings(
        "flong-seccomp: x: Unknown error 4095\n",
        render(&buf, "x", .{}, @enumFromInt(4095)),
    );
    const z: [*:0]const u8 = "zero-terminated";
    try testing.expectEqualStrings("flong-seccomp: {zero-terminated} 0x1f\n", render(&buf, "{{{s}}} 0x{x}", .{ z, @as(u8, 31) }, null));
}

test "a whole message is never cut; a cut one is 1022 bytes and a newline" {
    const long = "w" ** 4095;
    var buf: [5000]u8 = undefined;
    var scratch: Scratch("line {d}: {s}: {s}") = .{};
    var iov: [pieceCount("line {d}: {s}: {s}")]sys.Iovec = undefined;
    const pieces = build("line {d}: {s}: {s}", .{ @as(u32, 1), "bad argument comparison", @as([]const u8, long) }, null, &scratch, &iov);
    const whole = joined(&buf, pieces);
    try testing.expectEqual(("flong: line 1: bad argument comparison: ".len + 4095 + 1), whole.len);
    try testing.expect(std.mem.endsWith(u8, whole, "w\n"));

    var cbuf: [cut_len + 1]u8 = undefined;
    const cut = cutInto(&cbuf, pieces);
    try testing.expectEqual(@as(usize, 1023), cut.len);
    try testing.expectEqualStrings(whole[0..1022], cut[0..1022]);
    try testing.expectEqual(@as(u8, '\n'), cut[1022]);

    // A short one is not touched.
    var s2: Scratch("ok") = .{};
    var iov2: [pieceCount("ok")]sys.Iovec = undefined;
    const short = build("ok", .{}, null, &s2, &iov2);
    try testing.expectEqualStrings(joined(&buf, short), cutInto(&cbuf, short));
}

test "a trace line, and one cut at 255 bytes" {
    var buf: [256]u8 = undefined;
    try testing.expectEqualStrings("T 1700000000123456 launcher-start\n", traceLine(&buf, .{ .sec = 1_700_000_000, .nsec = 123_456_789 }, "launcher-start"));
    const line = traceLine(&buf, .{ .sec = 1, .nsec = 0 }, "s" ** 300);
    try testing.expectEqual(@as(usize, 255), line.len);
    try testing.expect(std.mem.startsWith(u8, line, "T 1000000 sss"));
    try testing.expect(line[254] == 's');
}

test "check unwraps a result, and says an errno once" {
    const ok: sys.Result(usize) = .{ .ok = 7 };
    try testing.expectEqual(@as(usize, 7), try check(ok, "never said", .{}));
    // The failing path writes to stderr, under a prog that names this test.
    prog = "msg-test";
    defer prog = "flong";
    const bad: sys.Result(usize) = .{ .err = .BADF };
    try testing.expectError(error.Reported, check(bad, "planted by msg.zig's test, ignore", .{}));
    // An open's two failures, and its value.
    const opened: error{TableFull}!sys.Result(u16) = .{ .ok = 3 };
    try testing.expectEqual(@as(u16, 3), try check(opened, "never said", .{}));
    const full: error{TableFull}!sys.Result(u16) = error.TableFull;
    try testing.expectError(error.Reported, check(full, "planted by msg.zig's test, ignore", .{}));
}
