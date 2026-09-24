//! flong-launch-driver: the launch's halves of phase 7's L2 driven from a
//! shell in checks.native (DESIGN.md, "Tests": checkpoint 4's U1 and U2
//! through /run/wrappers/bin/newuidmap, the U2 abort; cgroup's launch
//! half; a record the Zig sweeper sweeps; passwd). It prepares signals as
//! the launcher does (blocked, read from a signalfd, SIGPIPE ignored,
//! SIGCHLD default) and says what it says as flong launch. Static, no libc,
//! as a flong program is.
//!
//!   ns NEWUIDMAP NEWGIDMAP UIDMAP GIDMAP NESTED
//!       ns.create with those map programs; UIDMAP and GIDMAP are
//!       "inside:outside:count,..."; then, from a child in each namespace,
//!       its uid_map, gid_map (as its own process reads them) and, in U2,
//!       user.max_user_namespaces; then what is left: descriptors, pipes,
//!       children; after a refusal, only what is left
//!   u2-abort UIDMAP GIDMAP
//!       U1, then SIGTERM queued to itself, then U2: the wait for U2's pid
//!       ends Aborted; then what is left, as for ns
//!   u2-maps UIDMAP GIDMAP U2UIDMAP
//!       U1, then U2 with U2UIDMAP's extents in place of U1's uid extents:
//!       outside U1's, U2's helper cannot write U2's uid_map; then what is
//!       left, as for ns
//!   nsdelegate
//!       cgroup.checkNsdelegate on this process's /proc/self/mountinfo
//!   holder REL LIMITS [START...]
//!       cgroup.holderFind(REL, START, LIMITS == "limits"): its path
//!   session HOLDER CONTAINER MACHINE [FILE=VALUE...]
//!       cgroup.sessionCreate under the holder HOLDER with those limits:
//!       its path, each leaf's limit files as written, then closed and
//!       left
//!   record STATE HOLDER CONTAINER MACHINE [POSTSTOP-WORD...]
//!       as a launch lays it down: record.create in STATE's sessions/, the
//!       session's cgroup, leader= this process; the record's bytes; then
//!       closed without its unlink, as a killed launcher leaves it
//!   passwd UID
//!       passwd.lookup's name, or "none"; then the no-manager refusal
//!
//! Exit: 0 when it did what was asked, 1 when not (said on stderr), 2 on a
//! usage error, 125 on a panic.

const std = @import("std");
const linux = std.os.linux;
const sys = @import("sys");
const fd = @import("fd");
const msg = @import("msg");
const sig = @import("sig");
const proc = @import("proc");
const spec = @import("spec");
const ns = @import("ns");
const cgroup = @import("cgroup");
const record = @import("record");
const passwd = @import("passwd");

pub const std_options: std.Options = .{ .enable_segfault_handler = false, .keep_sigpipe = true };
pub const panic = std.debug.FullPanic(msg.onPanic(125));

/// One line on stdout, one write.
fn out(comptime fmt: []const u8, args: anytype) void {
    var buf: [65536]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, fmt ++ "\n", args) catch return;
    _ = fd.Stdio.out.writeAll(line);
}

fn usage() noreturn {
    msg.say("usage: flong-launch-driver ns|u2-abort|u2-maps|nsdelegate|holder|session|record|passwd ...", .{});
    proc.exit(2);
}

/// A small file, read whole into `buf`, or null.
fn readFile(path: [*:0]const u8, buf: []u8) ?[]u8 {
    const rc = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.E.init(rc) != .SUCCESS) return null;
    const f: i32 = @intCast(rc);
    defer _ = linux.close(f);
    var n: usize = 0;
    while (n < buf.len) {
        const r = linux.read(f, buf[n..].ptr, buf.len - n);
        if (linux.E.init(r) != .SUCCESS) return null;
        if (r == 0) break;
        n += r;
    }
    return buf[0..n];
}

/// "inside:outside:count,..." as extents.
fn parseMaps(gpa: std.mem.Allocator, text: []const u8) ![]spec.IdMap {
    var list: std.ArrayList(spec.IdMap) = .empty;
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |e| {
        var f = std.mem.splitScalar(u8, e, ':');
        const inside = try std.fmt.parseUnsigned(u64, f.next() orelse return error.Usage, 10);
        const outside = try std.fmt.parseUnsigned(u64, f.next() orelse return error.Usage, 10);
        const count = try std.fmt.parseUnsigned(u64, f.next() orelse return error.Usage, 10);
        try list.append(gpa, .{ .inside = inside, .outside = outside, .count = count });
    }
    return list.items;
}

/// A file's lines joined by " / ", its whitespace runs as one space.
fn oneLine(buf: []u8, text: []const u8) []const u8 {
    var n: usize = 0;
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |l| {
        if (n > 0) {
            @memcpy(buf[n..][0..3], " / ");
            n += 3;
        }
        var words = std.mem.tokenizeAny(u8, l, " \t");
        var first = true;
        while (words.next()) |w| {
            if (!first) {
                buf[n] = ' ';
                n += 1;
            }
            first = false;
            @memcpy(buf[n..][0..w.len], w);
            n += w.len;
        }
    }
    return buf[0..n];
}

const Look = struct { u: fd.Fd(.userns), name: []const u8, limit: bool };

/// A child in the namespace, saying what its own process reads there.
fn look(l: Look) noreturn {
    switch (l.u.setns(.user)) {
        .ok => {},
        .err => |e| msg.die(e, "setns {s}", .{l.name}),
    }
    var buf: [4096]u8 = undefined;
    var line: [4096]u8 = undefined;
    out("{s} uid_map: {s}", .{ l.name, oneLine(&line, readFile("/proc/self/uid_map", &buf) orelse "?") });
    out("{s} gid_map: {s}", .{ l.name, oneLine(&line, readFile("/proc/self/gid_map", &buf) orelse "?") });
    if (l.limit) out("{s} max_user_namespaces: {s}", .{ l.name, oneLine(&line, readFile("/proc/sys/user/max_user_namespaces", &buf) orelse "?") });
    proc.exit(0);
}

fn lookIn(u: fd.Fd(.userns), name: []const u8, limit: bool) !void {
    const c = try proc.fork(.{ .keep = &.{u.any()} }, Look{ .u = u, .name = name, .limit = limit }, look);
    const st = try c.await();
    if (st != 0) return error.Reported;
}

/// What a launch step leaves: the table's live descriptors, the pipes and
/// every descriptor number in /proc/self/fd (0-2 and the listing's own
/// excluded), the children not yet reaped, and the processes in this
/// process's cgroup but it and its ancestors.
fn left() void {
    var names: [2048]u8 = undefined;
    var n: usize = 0;
    var pipes: usize = 0;
    const dir_rc = linux.open("/proc/self/fd", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    const dir: i32 = @intCast(dir_rc);
    var buf: [4096]u8 align(8) = undefined;
    while (true) {
        const got = linux.getdents64(dir, &buf, buf.len);
        if (got == 0 or linux.E.init(got) != .SUCCESS) break;
        var it: fd.Entries = .{ .buf = buf[0..got] };
        while (it.next()) |e| {
            const num = std.fmt.parseUnsigned(i32, e.name, 10) catch continue;
            if (num <= 2 or num == dir) continue;
            var path_buf: [64]u8 = undefined;
            const path = std.fmt.bufPrintZ(&path_buf, "/proc/self/fd/{d}", .{num}) catch continue;
            var target: [256]u8 = undefined;
            const tl = linux.readlink(path, &target, target.len);
            if (linux.E.init(tl) != .SUCCESS) continue;
            if (std.mem.startsWith(u8, target[0..tl], "pipe:")) pipes += 1;
            const w = std.fmt.bufPrint(names[n..], "{s} ", .{target[0..tl]}) catch continue;
            n += w.len;
        }
    }
    _ = linux.close(dir);
    out("live: {d}", .{fd.liveCount()});
    out("open: {s}", .{std.mem.trimRight(u8, names[0..n], " ")});
    out("pipes: {d}", .{pipes});
    var info: linux.siginfo_t = undefined;
    const w = linux.waitid(.ALL, 0, &info, linux.W.EXITED | linux.W.NOHANG | linux.W.NOWAIT);
    out("children: {s}", .{if (linux.E.init(w) == .CHILD) "none" else "some"});
    // The processes in this cgroup but this one and its ancestors.
    var cg: [4096]u8 = undefined;
    const own = readFile("/proc/self/cgroup", &cg) orelse "";
    const at = std.mem.indexOf(u8, own, "0::") orelse return;
    const rel = std.mem.trimRight(u8, own[at + 3 ..], "\n");
    var procs_path: [4200]u8 = undefined;
    const pp = std.fmt.bufPrintZ(&procs_path, "/sys/fs/cgroup{s}/cgroup.procs", .{rel}) catch return;
    var procs: [65536]u8 = undefined;
    const text = readFile(pp, &procs) orelse "";
    // This process and its ancestors: the shell, and the timeout(1) that
    // bounds a run which would otherwise hang (checks.native).
    var mine: [8]i32 = undefined;
    var nmine: usize = 1;
    mine[0] = linux.getpid();
    while (nmine < mine.len) : (nmine += 1) mine[nmine] = parentOf(mine[nmine - 1]) orelse break;
    var others: usize = 0;
    var it = std.mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |p| {
        const pid = std.fmt.parseUnsigned(i32, p, 10) catch continue;
        if (std.mem.indexOfScalar(i32, mine[0..nmine], pid) == null) others += 1;
    }
    out("others in the cgroup: {d}", .{others});
}

/// The parent of `pid`, from /proc/<pid>/stat's fourth field (after the
/// command's closing parenthesis, the state, then the ppid), or null.
fn parentOf(pid: i32) ?i32 {
    var path_buf: [32]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buf, "/proc/{d}/stat", .{pid}) catch return null;
    var buf: [1024]u8 = undefined;
    const stat = readFile(path, &buf) orelse return null;
    const close = std.mem.lastIndexOfScalar(u8, stat, ')') orelse return null;
    var f = std.mem.tokenizeScalar(u8, stat[close + 1 ..], ' ');
    _ = f.next() orelse return null;
    const ppid = std.fmt.parseUnsigned(i32, f.next() orelse return null, 10) catch return null;
    return if (ppid > 0) ppid else null;
}

const progs_default: ns.Programs = .{ .newuidmap = "/run/wrappers/bin/newuidmap", .newgidmap = "/run/wrappers/bin/newgidmap" };

fn run(gpa: std.mem.Allocator, args: []const [*:0]const u8) !void {
    if (args.len < 2) return error.Usage;
    const cmd = std.mem.span(args[1]);
    const a = args[2..];
    if (std.mem.eql(u8, cmd, "ns")) {
        if (a.len != 5) return error.Usage;
        const maps: ns.Maps = .{
            .uidmap = try parseMaps(gpa, std.mem.span(a[2])),
            .gidmap = try parseMaps(gpa, std.mem.span(a[3])),
            .nested_userns = try std.fmt.parseUnsigned(u64, std.mem.span(a[4]), 10),
        };
        // A refusal leaves nothing either: what is left is said on both
        // paths, so a failure's cleanup is checked as the success's is.
        const n = ns.create(gpa, maps, .{ .newuidmap = a[0], .newgidmap = a[1] }) catch |err| {
            left();
            return err;
        };
        out("made", .{});
        left();
        try lookIn(n.u1, "u1", false);
        try lookIn(n.u2, "u2", true);
        n.u2.close();
        n.u1.close();
    } else if (std.mem.eql(u8, cmd, "u2-abort")) {
        if (a.len != 2) return error.Usage;
        const maps: ns.Maps = .{ .uidmap = try parseMaps(gpa, std.mem.span(a[0])), .gidmap = try parseMaps(gpa, std.mem.span(a[1])) };
        const one = try ns.makeU1(gpa, maps, progs_default);
        out("u1 made", .{});
        // SIGTERM is blocked, so it waits on the signalfd, where U2's first
        // wait finds it.
        _ = linux.kill(linux.getpid(), linux.SIG.TERM);
        if (ns.makeU2(gpa, maps, one)) |two| {
            out("u2 made", .{});
            two.close();
        } else |err| out("u2: {s}, signal {d}", .{ @errorName(err), sig.abort_signal });
        left();
        one.close();
    } else if (std.mem.eql(u8, cmd, "u2-maps")) {
        if (a.len != 3) return error.Usage;
        const maps: ns.Maps = .{ .uidmap = try parseMaps(gpa, std.mem.span(a[0])), .gidmap = try parseMaps(gpa, std.mem.span(a[1])) };
        const one = try ns.makeU1(gpa, maps, progs_default);
        out("u1 made", .{});
        if (ns.makeU2(gpa, .{ .uidmap = try parseMaps(gpa, std.mem.span(a[2])), .gidmap = maps.gidmap }, one)) |two| {
            out("u2 made", .{});
            two.close();
        } else |err| out("u2: {s}", .{@errorName(err)});
        left();
        one.close();
    } else if (std.mem.eql(u8, cmd, "nsdelegate")) {
        try cgroup.checkNsdelegate(gpa);
        out("nsdelegate: yes", .{});
    } else if (std.mem.eql(u8, cmd, "holder")) {
        if (a.len < 2) return error.Usage;
        var start: std.ArrayList([:0]const u8) = .empty;
        for (a[2..]) |w| try start.append(gpa, std.mem.span(w));
        const h = try cgroup.holderFind(gpa, std.mem.span(a[0]), start.items, std.mem.eql(u8, std.mem.span(a[1]), "limits"));
        out("holder: {s}", .{h.path.slice()});
    } else if (std.mem.eql(u8, cmd, "session")) {
        if (a.len < 3) return error.Usage;
        const h = try cgroup.holderAt(cgroup.Path.of(&.{std.mem.span(a[0])}) orelse return error.Usage);
        var limits: std.ArrayList(spec.Limit) = .empty;
        for (a[3..]) |w| {
            const kv = std.mem.span(w);
            const eq = std.mem.indexOfScalar(u8, kv, '=') orelse return error.Usage;
            try limits.append(gpa, .{ .file = try gpa.dupeZ(u8, kv[0..eq]), .value = try gpa.dupeZ(u8, kv[eq + 1 ..]) });
        }
        var s = try cgroup.sessionCreate(&h, std.mem.span(a[1]), std.mem.span(a[2]), limits.items);
        out("session: {s}", .{s.path.slice()});
        for (limits.items) |l| {
            var buf: [256]u8 = undefined;
            const n = try cgroup.readAt(s.leaf[0].?, l.file, &buf);
            out("sandbox {s}: {s}", .{ l.file, std.mem.trimRight(u8, buf[0..n], "\n") });
        }
        s.closeAll();
    } else if (std.mem.eql(u8, cmd, "record")) {
        if (a.len < 4) return error.Usage;
        const h = try cgroup.holderAt(cgroup.Path.of(&.{std.mem.span(a[1])}) orelse return error.Usage);
        const state = try record.stateOpen(std.mem.span(a[0]));
        const machine = std.mem.span(a[3]);
        const path = try cgroup.sessionPath(&h, std.mem.span(a[2]), machine);
        // The words after MACHINE, if any, are postStop's one command.
        const words = try gpa.alloc([:0]const u8, a.len - 4);
        for (words, a[4..]) |*w, x| w.* = std.mem.span(x);
        const one = [_]spec.Command{words};
        var rec = try record.create(state.sessions, &h, machine, if (words.len > 0) one[0..] else one[0..0], path.slice());
        var s = try cgroup.sessionCreate(&h, std.mem.span(a[2]), machine, &[_]spec.Limit{});
        s.closeAll();
        try rec.setLeader(linux.getpid());
        var buf: [record.rec_max + 1]u8 = undefined;
        const n = try msg.check(record.readRecord(rec.rec, &buf), "read the record", .{});
        _ = fd.Stdio.out.writeAll(buf[0..n]);
        rec.closeKeeping();
    } else if (std.mem.eql(u8, cmd, "passwd")) {
        if (a.len != 1) return error.Usage;
        const uid = try std.fmt.parseUnsigned(u32, std.mem.span(a[0]), 10);
        out("name: {s}", .{passwd.lookup(gpa, uid) orelse "none"});
        cgroup.noManager(gpa, uid) catch {};
    } else return error.Usage;
}

pub fn main() noreturn {
    msg.prog = "flong launch";
    msg.mode = .cut;
    _ = sig.block() catch proc.exit(1);
    sig.ignorePipe();
    sig.defaultChld();
    sig.openSignalfd() catch proc.exit(1);
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    run(arena.allocator(), sys.argv()) catch |err| switch (err) {
        error.Usage, error.InvalidCharacter, error.Overflow => usage(),
        error.Reported, error.Aborted => proc.exit(1),
        else => {
            msg.say("{s}", .{@errorName(err)});
            proc.exit(1);
        },
    };
    proc.exit(0);
}
