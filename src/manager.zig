//! manager.zig: the launcher's one way of asking systemd for anything,
//! over the user bus (DESIGN.md, "Talking to systemd"). Two requests, each
//! a job of the user manager's waited for until it is removed:
//!
//!   startUnit       StartUnit(NAME, "replace"): the holder unit, when its
//!                   cgroup is absent (DESIGN.md, "The holder")
//!   startScope      StartTransientUnit(NAME.scope, "fail", PIDs=[PID],
//!                   Slice, CollectMode, Description): the launcher moved
//!                   into a scope of the manager's (cgroup.adopt)
//!
//! Both are org.freedesktop.systemd1's public API, org.freedesktop.systemd1
//! (5), reached through the user's bus at /run/user/UID/bus, the broker
//! systemd's own clients use; never the manager's undocumented private
//! socket. The connection is the user's (SASL EXTERNAL, the kernel's
//! SO_PEERCRED saying who), and lives for one request: Hello, an AddMatch
//! for the manager's JobRemoved, Subscribe, then the request, sent at once
//! (the broker and the manager each take a connection's messages in order,
//! so the match and the subscription are in place before the job can end).
//! The reply names the job; a JobRemoved that names it, whenever it comes,
//! ends the wait with its result, "done" or a refusal naming the other
//! (`Wait`). An error reply to any of the four is said by its name and
//! message.
//!
//! No wait has a timeout: each read is sig.awaitFd's, which a terminating
//! signal ends as error.Aborted once the launch has its signalfd, and which
//! before then is a plain wait that the signal's default ends.

const std = @import("std");
const sys = @import("sys");
const fdt = @import("fd");
const msg = @import("msg");
const sig = @import("sig");
const dbus = @import("dbus");

const Allocator = std.mem.Allocator;

/// A call to the manager's interface.
fn systemdCall(member: []const u8, signature: []const u8) dbus.Call {
    return .{
        .destination = "org.freedesktop.systemd1",
        .path = "/org/freedesktop/systemd1",
        .interface = "org.freedesktop.systemd1.Manager",
        .member = member,
        .signature = signature,
    };
}

/// A call to the broker's own interface.
fn busCall(member: []const u8, signature: []const u8) dbus.Call {
    return .{
        .destination = "org.freedesktop.DBus",
        .path = "/org/freedesktop/DBus",
        .interface = "org.freedesktop.DBus",
        .member = member,
        .signature = signature,
    };
}

/// StartUnit(`unit`, "replace"), waited for: the holder unit, whose
/// Type=exec means its job ends once the sweeper runs.
pub fn startUnit(gpa: Allocator, uid: sys.uid_t, unit: []const u8) sig.Error!void {
    var w: dbus.Writer = .init(gpa);
    w.string(unit) catch return oom();
    w.string("replace") catch return oom();
    try runJob(gpa, uid, unit, systemdCall("StartUnit", "ss"), w.bytes());
}

/// StartTransientUnit(`unit`, "fail", [PIDs=[pid], Slice=`slice`,
/// CollectMode=inactive-or-failed, Description=`description`], []),
/// waited for. The manager makes the scope and moves `pid` into it,
/// asking the system manager to when the process is in a cgroup of root's,
/// which it allows for its own user's processes; the job ends once it has.
pub fn startScope(gpa: Allocator, uid: sys.uid_t, unit: []const u8, pid: sys.pid_t, slice: []const u8, description: []const u8) sig.Error!void {
    var w: dbus.Writer = .init(gpa);
    scopeBody(&w, unit, pid, slice, description) catch return oom();
    try runJob(gpa, uid, unit, systemdCall("StartTransientUnit", "ssa(sv)a(sa(sv))"), w.bytes());
}

fn scopeBody(w: *dbus.Writer, unit: []const u8, pid: sys.pid_t, slice: []const u8, description: []const u8) !void {
    try w.string(unit);
    try w.string("fail");
    const props = try w.arrayStart(8);
    try w.structStart();
    try w.string("PIDs");
    try w.variantUint32s(&.{@intCast(pid)});
    try w.structStart();
    try w.string("Slice");
    try w.variantString(slice);
    try w.structStart();
    try w.string("CollectMode");
    try w.variantString("inactive-or-failed");
    try w.structStart();
    try w.string("Description");
    try w.variantString(description);
    w.arrayEnd(props);
    // No auxiliary units.
    try w.emptyArray(8);
}

fn oom() msg.Error {
    return msg.fail(.NOMEM, "malloc", .{});
}

/// The bus's path for `uid`, which the launch's runtime directory check
/// has already found to be the user's (DESIGN.md, "Launch sequence").
fn busPath(buf: []u8, uid: sys.uid_t) []const u8 {
    return std.fmt.bufPrint(buf, "/run/user/{d}/bus", .{uid}) catch unreachable; // proven: 14 + 10 < 64
}

const match_job_removed = "type='signal',sender='org.freedesktop.systemd1',path='/org/freedesktop/systemd1',interface='org.freedesktop.systemd1.Manager',member='JobRemoved'";

/// The four calls of one connection, in the order sent, serials 1 to 4:
/// Hello first, as the broker requires, then the match, the subscription
/// and the request.
fn calls(request: dbus.Call) [4]dbus.Call {
    return .{ busCall("Hello", ""), busCall("AddMatch", "s"), systemdCall("Subscribe", ""), request };
}

/// One connection's request: `call`, about `unit`, its job waited for.
fn runJob(gpa: Allocator, uid: sys.uid_t, unit: []const u8, call: dbus.Call, body: []const u8) sig.Error!void {
    var path_buf: [64]u8 = undefined;
    const path = busPath(&path_buf, uid);
    var c: Conn = .{ .path = path, .frames = .{ .gpa = gpa }, .bus = try msg.check(fdt.connectUnix(path), "connect to the user bus {s}", .{path}) };
    defer c.bus.close();
    try c.auth(uid);

    var match: dbus.Writer = .init(gpa);
    match.string(match_job_removed) catch return oom();
    const sent = calls(call);
    const bodies = [sent.len][]const u8{ "", match.bytes(), "", body };
    var out: std.ArrayList(u8) = .empty;
    for (sent, bodies, 1..) |s, b, serial| {
        const m = dbus.methodCall(gpa, @intCast(serial), s, b) catch return oom();
        out.appendSlice(gpa, m) catch return oom();
    }
    try msg.check(c.bus.writeAll(out.items), "write to the user bus {s}", .{path});

    var w: Wait = .{ .gpa = gpa, .calls = &sent, .unit = unit };
    while (true) {
        const m = try c.next();
        if (try w.take(&m)) |result| return judge(call.member, unit, result);
    }
}

/// The wait for one request's job, message by message: what `take` makes
/// of each, until the job's result is known.
const Wait = struct {
    gpa: Allocator,
    /// the connection's calls, serial N at N - 1; the last is the request
    calls: []const dbus.Call,
    unit: []const u8,
    /// the job the reply named, once it has
    job: ?[]const u8 = null,
    /// JobRemoved signals that came before the reply named their job
    early: std.ArrayList(Removed) = .empty,

    /// The job's result once `m` settles it; null to read on. An error
    /// reply to one of the calls is a refusal naming it; a reply to the
    /// request that names no job is the bus sending what is not D-Bus.
    fn take(w: *Wait, m: *const dbus.Message) msg.Error!?[]const u8 {
        switch (m.type) {
            .@"error" => {
                const rs = m.reply_serial orelse return null;
                if (rs < 1 or rs > w.calls.len) return null;
                var r = m.reader();
                const text = if (std.mem.startsWith(u8, m.signature, "s")) r.string() catch "" else "";
                return msg.refuse("the user manager refused {s} {s}: {s}: {s}", .{ w.calls[rs - 1].member, w.unit, m.error_name orelse "?", text });
            },
            .reply => {
                if ((m.reply_serial orelse 0) != w.calls.len) return null;
                if (!std.mem.eql(u8, m.signature, "o")) return msg.refuse("the user bus's reply to {s} names no job", .{w.calls[w.calls.len - 1].member});
                var r = m.reader();
                const j = r.string() catch return msg.refuse("the user bus's reply to {s} names no job", .{w.calls[w.calls.len - 1].member});
                w.job = w.gpa.dupe(u8, j) catch return oom();
                for (w.early.items) |e| if (std.mem.eql(u8, e.job, j)) return e.result;
            },
            .signal => {
                const rm = jobRemoved(m) orelse return null;
                if (w.job) |j| return if (std.mem.eql(u8, rm.job, j)) rm.result else null;
                w.early.append(w.gpa, .{
                    .job = w.gpa.dupe(u8, rm.job) catch return oom(),
                    .result = w.gpa.dupe(u8, rm.result) catch return oom(),
                }) catch return oom();
            },
            else => {},
        }
        return null;
    }
};

const Removed = struct { job: []const u8, result: []const u8 };

/// The job and result of the manager's JobRemoved(u id, o job, s unit, s
/// result); null for any other message, or one that does not read so.
fn jobRemoved(m: *const dbus.Message) ?Removed {
    if (!optEql(m.interface, "org.freedesktop.systemd1.Manager") or !optEql(m.member, "JobRemoved") or !std.mem.eql(u8, m.signature, "uoss")) return null;
    var r = m.reader();
    _ = r.uint32() catch return null;
    const job = r.string() catch return null;
    _ = r.string() catch return null;
    const result = r.string() catch return null;
    return .{ .job = job, .result = result };
}

fn optEql(a: ?[]const u8, b: []const u8) bool {
    return if (a) |x| std.mem.eql(u8, x, b) else false;
}

/// "done" is the job's success; any other result is a refusal naming it.
fn judge(member: []const u8, unit: []const u8, result: []const u8) msg.Error!void {
    if (std.mem.eql(u8, result, "done")) return;
    return msg.refuse("the user manager's {s} {s} ended \"{s}\" (journalctl --user -u {s})", .{ member, unit, result, unit });
}

/// What has been read of a connection, cut into messages: bytes go in by
/// `room` and `filled`, whole messages come out of `pop`, each valid until
/// the next.
const Frames = struct {
    gpa: Allocator,
    buf: std.ArrayList(u8) = .empty,
    /// how much of `buf` the last message popped took
    used: usize = 0,

    /// Space for at least `n` more bytes.
    fn room(f: *Frames, n: usize) msg.Error![]u8 {
        f.buf.ensureUnusedCapacity(f.gpa, n) catch return oom();
        return f.buf.unusedCapacitySlice();
    }

    fn filled(f: *Frames, n: usize) void {
        f.buf.items.len += n;
    }

    /// The next whole message, or null until more has been read;
    /// error.Malformed for bytes that are not D-Bus.
    fn pop(f: *Frames) dbus.Malformed!?dbus.Message {
        if (f.used > 0) {
            const rest = f.buf.items.len - f.used;
            std.mem.copyForwards(u8, f.buf.items[0..rest], f.buf.items[f.used..]);
            f.buf.items.len = rest;
            f.used = 0;
        }
        const n = (try dbus.frameLen(f.buf.items)) orelse return null;
        if (f.buf.items.len < n) return null;
        f.used = n;
        return try dbus.parse(f.buf.items[0..n]);
    }
};

/// A connection: the socket and what has been read of it.
const Conn = struct {
    path: []const u8,
    bus: fdt.Fd(.bus),
    frames: Frames,

    fn malformed(c: *Conn) msg.Error {
        return msg.refuse("the user bus {s} sent what is not D-Bus", .{c.path});
    }

    /// Reads at least once more; EOF is the bus gone.
    fn fill(c: *Conn) sig.Error!void {
        try sig.awaitFd(c.bus, sys.POLL.IN);
        const n = try msg.check(c.bus.read(try c.frames.room(4096)), "read the user bus {s}", .{c.path});
        if (n == 0) return msg.refuse("the user bus {s} closed the connection", .{c.path});
        c.frames.filled(n);
    }

    /// SASL EXTERNAL as the uid's decimal, in hex, then BEGIN; anything but
    /// OK is a refusal quoting it.
    fn auth(c: *Conn, uid: sys.uid_t) sig.Error!void {
        var dec_buf: [10]u8 = undefined;
        const dec = std.fmt.bufPrint(&dec_buf, "{d}", .{uid}) catch unreachable; // proven: a u32 is 10 digits
        var line_buf: [64]u8 = undefined;
        const line = std.fmt.bufPrint(&line_buf, "\x00AUTH EXTERNAL {x}\r\n", .{dec}) catch unreachable; // proven: 15 + 20 + 2 < 64
        try msg.check(c.bus.writeAll(line), "write to the user bus {s}", .{c.path});
        const b = &c.frames.buf;
        while (std.mem.indexOf(u8, b.items, "\r\n") == null) {
            if (b.items.len > 512) return c.malformed();
            try c.fill();
        }
        const end = std.mem.indexOf(u8, b.items, "\r\n").?;
        const answer = b.items[0..end];
        if (!std.mem.startsWith(u8, answer, "OK ")) return msg.refuse("the user bus {s} refused to authenticate uid {d}: {s}", .{ c.path, uid, answer });
        c.frames.used = end + 2;
        try msg.check(c.bus.writeAll("BEGIN\r\n"), "write to the user bus {s}", .{c.path});
    }

    fn next(c: *Conn) sig.Error!dbus.Message {
        while (true) {
            if (c.frames.pop() catch return c.malformed()) |m| return m;
            try c.fill();
        }
    }
};

// ---- tests ----

const testing = std.testing;

test "a scope's body reads back as StartTransientUnit's signature says" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var w: dbus.Writer = .init(arena.allocator());
    try scopeBody(&w, "flong-launch-42.scope", 42, "app.slice", "flong launch work");
    const m = try dbus.parse(try dbus.methodCall(arena.allocator(), 4, systemdCall("StartTransientUnit", "ssa(sv)a(sa(sv))"), w.bytes()));
    var r = m.reader();
    try testing.expectEqualStrings("flong-launch-42.scope", try r.string());
    try testing.expectEqualStrings("fail", try r.string());
    // The properties' array: PIDs first, an au of one pid.
    _ = try r.uint32();
    try r.structStart();
    try testing.expectEqualStrings("PIDs", try r.string());
    try testing.expectEqualStrings("au", try r.signature());
    try testing.expectEqual(@as(u32, 4), try r.uint32());
    try testing.expectEqual(@as(u32, 42), try r.uint32());
}

test "judge: done is success, anything else names the unit's journal" {
    try judge("StartUnit", "x.service", "done");
    try testing.expectError(error.Reported, judge("StartUnit", "x.service", "failed"));
}

/// Messages as the bus would send them, for the tests: little-endian, each
/// field written as the specification lays it out.
const Fake = struct {
    a: Allocator,

    fn message(f: Fake, t: dbus.Type, serial: u32, reply_serial: ?u32, member: ?[]const u8, error_name: ?[]const u8, signature: []const u8, body: []const u8) ![]const u8 {
        var h: dbus.Writer = .init(f.a);
        try h.byte('l');
        try h.byte(@intFromEnum(t));
        try h.byte(0);
        try h.byte(1);
        try h.uint32(@intCast(body.len));
        try h.uint32(serial);
        const m = try h.arrayStart(8);
        if (member) |v| {
            try h.structStart();
            try h.byte(2);
            try h.signature("s");
            try h.string("org.freedesktop.systemd1.Manager");
            try h.structStart();
            try h.byte(3);
            try h.signature("s");
            try h.string(v);
        }
        if (error_name) |v| {
            try h.structStart();
            try h.byte(4);
            try h.signature("s");
            try h.string(v);
        }
        if (reply_serial) |v| {
            try h.structStart();
            try h.byte(5);
            try h.signature("u");
            try h.uint32(v);
        }
        if (signature.len > 0) {
            try h.structStart();
            try h.byte(8);
            try h.signature("g");
            try h.signature(signature);
        }
        h.arrayEnd(m);
        try h.structStart();
        try h.put(body);
        return h.bytes();
    }

    fn reply(f: Fake, to: u32, job: []const u8) ![]const u8 {
        var w: dbus.Writer = .init(f.a);
        try w.string(job);
        return f.message(.reply, 100 + to, to, null, null, "o", w.bytes());
    }

    fn removed(f: Fake, job: []const u8, result: []const u8) ![]const u8 {
        var w: dbus.Writer = .init(f.a);
        try w.uint32(7);
        try w.string(job);
        try w.string("x.scope");
        try w.string(result);
        return f.message(.signal, 50, null, "JobRemoved", null, "uoss", w.bytes());
    }

    fn failure(f: Fake, to: u32, name: []const u8, text: []const u8) ![]const u8 {
        var w: dbus.Writer = .init(f.a);
        try w.string(text);
        return f.message(.@"error", 60, to, null, name, "s", w.bytes());
    }
};

fn waitFor(a: Allocator) !Wait {
    const sent = calls(systemdCall("StartTransientUnit", "ssa(sv)a(sa(sv))"));
    return .{ .gpa = a, .calls = try a.dupe(dbus.Call, &sent), .unit = "x.scope" };
}

test "Wait: the JobRemoved for the reply's job ends it, before or after the reply" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f: Fake = .{ .a = a };
    // After: other jobs' signals and other replies are read past.
    var w = try waitFor(a);
    try testing.expectEqual(@as(?[]const u8, null), try w.take(&try dbus.parse(try f.reply(1, "/x"))));
    try testing.expectEqual(@as(?[]const u8, null), try w.take(&try dbus.parse(try f.reply(4, "/j/9"))));
    try testing.expectEqual(@as(?[]const u8, null), try w.take(&try dbus.parse(try f.removed("/j/8", "failed"))));
    try testing.expectEqualStrings("done", (try w.take(&try dbus.parse(try f.removed("/j/9", "done")))).?);
    // Before: held until the reply names its job.
    var e = try waitFor(a);
    try testing.expectEqual(@as(?[]const u8, null), try e.take(&try dbus.parse(try f.removed("/j/3", "failed"))));
    try testing.expectEqual(@as(?[]const u8, null), try e.take(&try dbus.parse(try f.removed("/j/2", "done"))));
    try testing.expectEqualStrings("done", (try e.take(&try dbus.parse(try f.reply(4, "/j/2")))).?);
}

test "Wait: an error reply to any of the calls refuses, naming it" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f: Fake = .{ .a = a };
    var w = try waitFor(a);
    // One to a serial not ours is read past.
    try testing.expectEqual(@as(?[]const u8, null), try w.take(&try dbus.parse(try f.failure(9, "x.Y", "z"))));
    try testing.expectError(error.Reported, w.take(&try dbus.parse(try f.failure(3, "org.freedesktop.DBus.Error.AccessDenied", "no"))));
    // A reply to the request that names no job.
    var n = try waitFor(a);
    const bad = try f.message(.reply, 5, 4, null, null, "s", "\x01\x00\x00\x00x\x00");
    try testing.expectError(error.Reported, n.take(&try dbus.parse(bad)));
}

test "jobRemoved: only the manager's JobRemoved, read whole" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const f: Fake = .{ .a = arena.allocator() };
    const rm = jobRemoved(&try dbus.parse(try f.removed("/j/4", "canceled"))).?;
    try testing.expectEqualStrings("/j/4", rm.job);
    try testing.expectEqualStrings("canceled", rm.result);
    // Another member, and the right member with the wrong signature.
    try testing.expectEqual(@as(?Removed, null), jobRemoved(&try dbus.parse(try f.message(.signal, 3, null, "UnitNew", null, "", ""))));
    try testing.expectEqual(@as(?Removed, null), jobRemoved(&try dbus.parse(try f.message(.signal, 3, null, "JobRemoved", null, "u", "\x07\x00\x00\x00"))));
}

test "Frames: messages come out whole, however the bytes arrive" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f: Fake = .{ .a = a };
    const one = try f.reply(4, "/j/1");
    const two = try f.removed("/j/1", "done");
    const stream = try std.mem.concat(a, u8, &.{ one, two });
    // A byte at a time, and all at once.
    for ([_]usize{ 1, stream.len }) |step| {
        var fr: Frames = .{ .gpa = a };
        var got: usize = 0;
        var at: usize = 0;
        while (at < stream.len) {
            const n = @min(step, stream.len - at);
            @memcpy((try fr.room(n))[0..n], stream[at..][0..n]);
            fr.filled(n);
            at += n;
            while (try fr.pop()) |m| {
                got += 1;
                try testing.expectEqual(if (got == 1) dbus.Type.reply else dbus.Type.signal, m.type);
            }
        }
        try testing.expectEqual(@as(usize, 2), got);
    }
    var bad: Frames = .{ .gpa = a };
    @memcpy((try bad.room(16))[0..16], "x" ** 16);
    bad.filled(16);
    try testing.expectError(error.Malformed, bad.pop());
}
