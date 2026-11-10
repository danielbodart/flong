//! manager.zig: the launcher's one way of asking systemd for anything,
//! over the user bus (DESIGN.md, "The holder"). Two requests, each a job
//! of the user manager's waited for until it is removed:
//!
//!   startUnit       StartUnit(NAME, "replace"): the holder unit, when its
//!                   cgroup is absent (in place of `systemctl --user start`)
//!   startScope      StartTransientUnit(NAME.scope, "fail", PIDs=[PID],
//!                   Slice, CollectMode, Description): the launcher moved
//!                   into a scope of the manager's (in place of
//!                   `systemd-run --user --scope`'s exec)
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
//! ends the wait with its result, "done" or a refusal naming the other.
//! An error reply to any of the four is said by its name and message.
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

const systemd: dbus.Call = .{
    .destination = "org.freedesktop.systemd1",
    .path = "/org/freedesktop/systemd1",
    .interface = "org.freedesktop.systemd1.Manager",
    .member = "",
};

/// StartUnit(`unit`, "replace"), waited for: the holder unit, whose
/// ExecStart's Type=exec means its job ends once the sweeper runs.
pub fn startUnit(gpa: Allocator, uid: sys.uid_t, unit: []const u8) sig.Error!void {
    var b: dbus.Body = .init(gpa);
    b.string(unit) catch return oom();
    b.string("replace") catch return oom();
    var call = systemd;
    call.member = "StartUnit";
    call.signature = "ss";
    try runJob(gpa, uid, unit, call, b.buf.items);
}

/// StartTransientUnit(`unit`, "fail", [PIDs=[pid], Slice=`slice`,
/// CollectMode=inactive-or-failed, Description=`description`], []),
/// waited for. The manager makes the scope and moves `pid` into it,
/// asking the system manager to when the process is in a cgroup of root's,
/// which it allows for its own user's processes; the job ends once it has.
pub fn startScope(gpa: Allocator, uid: sys.uid_t, unit: []const u8, pid: sys.pid_t, slice: []const u8, description: []const u8) sig.Error!void {
    var b: dbus.Body = .init(gpa);
    scopeBody(&b, unit, pid, slice, description) catch return oom();
    var call = systemd;
    call.member = "StartTransientUnit";
    call.signature = "ssa(sv)a(sa(sv))";
    try runJob(gpa, uid, unit, call, b.buf.items);
}

fn scopeBody(b: *dbus.Body, unit: []const u8, pid: sys.pid_t, slice: []const u8, description: []const u8) !void {
    try b.string(unit);
    try b.string("fail");
    const props = try b.arrayStart(8);
    try b.structStart();
    try b.string("PIDs");
    try b.variantUint32s(&.{@intCast(pid)});
    try b.structStart();
    try b.string("Slice");
    try b.variantString(slice);
    try b.structStart();
    try b.string("CollectMode");
    try b.variantString("inactive-or-failed");
    try b.structStart();
    try b.string("Description");
    try b.variantString(description);
    b.arrayEnd(props);
    // No auxiliary units.
    b.arrayEnd(try b.arrayStart(8));
}

fn oom() msg.Error {
    return msg.fail(.NOMEM, "malloc", .{});
}

/// The bus's path for `uid`, which the launch's runtime directory check
/// has already found to be the user's (DESIGN.md, "Launch sequence").
fn busPath(buf: []u8, uid: sys.uid_t) []const u8 {
    return std.fmt.bufPrint(buf, "/run/user/{d}/bus", .{uid}) catch unreachable; // proven: 15 + 10 < 64
}

/// One connection's request: `call`, about `unit`, its job waited for.
fn runJob(gpa: Allocator, uid: sys.uid_t, unit: []const u8, call: dbus.Call, body: []const u8) sig.Error!void {
    var path_buf: [64]u8 = undefined;
    const path = busPath(&path_buf, uid);
    var c: Conn = .{ .gpa = gpa, .path = path, .bus = try msg.check(fdt.connectUnix(path), "connect to the user bus {s}", .{path}) };
    defer c.bus.close();
    try c.auth(uid);

    // Hello first, as the broker requires; then the match, the
    // subscription and the request, all before reading any reply.
    var match: dbus.Body = .init(gpa);
    match.string("type='signal',sender='org.freedesktop.systemd1',path='/org/freedesktop/systemd1',interface='org.freedesktop.systemd1.Manager',member='JobRemoved'") catch return oom();
    var subscribe = systemd;
    subscribe.member = "Subscribe";
    const sent = [_]struct { call: dbus.Call, body: []const u8 }{
        .{ .call = .{ .destination = "org.freedesktop.DBus", .path = "/org/freedesktop/DBus", .interface = "org.freedesktop.DBus", .member = "Hello" }, .body = "" },
        .{ .call = .{ .destination = "org.freedesktop.DBus", .path = "/org/freedesktop/DBus", .interface = "org.freedesktop.DBus", .member = "AddMatch", .signature = "s" }, .body = match.buf.items },
        .{ .call = subscribe, .body = "" },
        .{ .call = call, .body = body },
    };
    var out: std.ArrayList(u8) = .empty;
    for (sent, 1..) |s, serial| {
        const m = dbus.methodCall(gpa, @intCast(serial), s.call, s.body) catch return oom();
        out.appendSlice(gpa, m) catch return oom();
    }
    try msg.check(c.bus.writeAll(out.items), "write to the user bus {s}", .{path});
    const request: u32 = sent.len;

    var job: ?[]const u8 = null;
    // JobRemoved signals that came before the reply named their job.
    var early: std.ArrayList(Removed) = .empty;
    while (true) {
        const m = try c.next();
        switch (m.type) {
            .@"error" => if (m.reply_serial) |rs| if (rs >= 1 and rs <= sent.len) {
                var r = m.reader();
                const text = if (std.mem.startsWith(u8, m.signature, "s")) r.string() catch "" else "";
                return msg.refuse("the user manager refused {s} {s}: {s}: {s}", .{ sent[rs - 1].call.member, unit, m.error_name orelse "?", text });
            },
            .reply => if ((m.reply_serial orelse 0) == request) {
                if (!std.mem.eql(u8, m.signature, "o")) return c.malformed();
                var r = m.reader();
                const j = r.string() catch return c.malformed();
                job = gpa.dupe(u8, j) catch return oom();
                for (early.items) |e| if (std.mem.eql(u8, e.job, job.?)) return judge(call.member, unit, e.result);
            },
            .signal => if (jobRemoved(&m)) |rm| {
                if (job) |j| {
                    if (std.mem.eql(u8, rm.job, j)) return judge(call.member, unit, rm.result);
                } else {
                    early.append(gpa, .{
                        .job = gpa.dupe(u8, rm.job) catch return oom(),
                        .result = gpa.dupe(u8, rm.result) catch return oom(),
                    }) catch return oom();
                }
            },
            else => {},
        }
    }
}

const Removed = struct { job: []const u8, result: []const u8 };

/// The job and result of the manager's JobRemoved(u id, o job, s unit, s
/// result); null for any other message, or one that does not read so.
fn jobRemoved(m: *const dbus.Message) ?Removed {
    if (!eq(m.interface, "org.freedesktop.systemd1.Manager") or !eq(m.member, "JobRemoved") or !std.mem.eql(u8, m.signature, "uoss")) return null;
    var r = m.reader();
    _ = r.uint32() catch return null;
    const job = r.string() catch return null;
    _ = r.string() catch return null;
    const result = r.string() catch return null;
    return .{ .job = job, .result = result };
}

fn eq(a: ?[]const u8, b: []const u8) bool {
    return if (a) |x| std.mem.eql(u8, x, b) else false;
}

/// "done" is the job's success; any other result is a refusal naming it.
fn judge(member: []const u8, unit: []const u8, result: []const u8) msg.Error!void {
    if (std.mem.eql(u8, result, "done")) return;
    return msg.refuse("the user manager's {s} {s} ended \"{s}\" (journalctl --user -u {s})", .{ member, unit, result, unit });
}

/// A connection: the socket and what has been read of it.
const Conn = struct {
    gpa: Allocator,
    path: []const u8,
    bus: fdt.Fd(.bus),
    buf: std.ArrayList(u8) = .empty,
    /// how much of `buf` the last message took
    used: usize = 0,

    fn malformed(c: *Conn) msg.Error {
        return msg.refuse("the user bus {s} sent what is not D-Bus", .{c.path});
    }

    /// Reads at least once more into `buf`; EOF is the bus gone.
    fn fill(c: *Conn) sig.Error!void {
        try sig.awaitFd(c.bus, sys.POLL.IN);
        c.buf.ensureUnusedCapacity(c.gpa, 4096) catch return oom();
        const n = try msg.check(c.bus.read(c.buf.unusedCapacitySlice()), "read the user bus {s}", .{c.path});
        if (n == 0) return msg.refuse("the user bus {s} closed the connection", .{c.path});
        c.buf.items.len += n;
    }

    /// SASL EXTERNAL as the uid's decimal, in hex, then BEGIN; anything but
    /// OK is a refusal quoting it.
    fn auth(c: *Conn, uid: sys.uid_t) sig.Error!void {
        var dec_buf: [10]u8 = undefined;
        const dec = std.fmt.bufPrint(&dec_buf, "{d}", .{uid}) catch unreachable; // proven: a u32 is 10 digits
        var line_buf: [64]u8 = undefined;
        const line = std.fmt.bufPrint(&line_buf, "\x00AUTH EXTERNAL {x}\r\n", .{dec}) catch unreachable; // proven: 16 + 20 + 2 < 64
        try msg.check(c.bus.writeAll(line), "write to the user bus {s}", .{c.path});
        while (std.mem.indexOf(u8, c.buf.items, "\r\n") == null) {
            if (c.buf.items.len > 512) return c.malformed();
            try c.fill();
        }
        const end = std.mem.indexOf(u8, c.buf.items, "\r\n").?;
        const answer = c.buf.items[0..end];
        if (!std.mem.startsWith(u8, answer, "OK ")) return msg.refuse("the user bus {s} refused to authenticate uid {d}: {s}", .{ c.path, uid, answer });
        c.used = end + 2;
        try msg.check(c.bus.writeAll("BEGIN\r\n"), "write to the user bus {s}", .{c.path});
    }

    /// The next whole message, its bytes valid until the next call.
    fn next(c: *Conn) sig.Error!dbus.Message {
        // Drop the last message's bytes.
        if (c.used > 0) {
            const rest = c.buf.items.len - c.used;
            std.mem.copyForwards(u8, c.buf.items[0..rest], c.buf.items[c.used..]);
            c.buf.items.len = rest;
            c.used = 0;
        }
        while (true) {
            if (dbus.frameLen(c.buf.items) catch return c.malformed()) |n| {
                if (c.buf.items.len >= n) {
                    c.used = n;
                    return dbus.parse(c.buf.items[0..n]) catch return c.malformed();
                }
                c.buf.ensureTotalCapacity(c.gpa, n) catch return oom();
            }
            try c.fill();
        }
    }
};

// ---- tests ----

const testing = std.testing;

test "a scope's body reads back as StartTransientUnit's signature says" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var b: dbus.Body = .init(arena.allocator());
    try scopeBody(&b, "flong-launch-42.scope", 42, "app.slice", "flong launch work");
    var call = systemd;
    call.member = "StartTransientUnit";
    call.signature = "ssa(sv)a(sa(sv))";
    const m = try dbus.parse(try dbus.methodCall(arena.allocator(), 4, call, b.buf.items));
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
