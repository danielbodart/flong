//! flong-proc: proc.zig, sig.zig and cgroup.zig's sweep half driven from a
//! shell (DESIGN.md, "Tests": the spawn probe; checks.native's clone3 into a
//! cgroup, a fork after setns(CLONE_NEWUSER), and a session killed, waited
//! for and removed). P3's driver (tests/proofs/p3, retired in phase 5)
//! moved onto the real modules. Static, no libc, as a flong program is.
//!
//!   flong-proc probe [--out N] [ARG...]
//!       the spawn probe: what it was started with, one line each, on N (a
//!       descriptor passed to it) or stdout: fds (from 0 up, the probe's
//!       own listing excluded), argv (ARG...), sigblk, sigign, sigcgt (hex,
//!       /proc/self/status), cwd, env ('|'-joined), stdio (dev:ino of 0, 1
//!       and 2, '-' when closed), cgroup (/proc/self/cgroup's 0:: path)
//!   flong-proc fork
//!       a working noreturn body, exit 7; the parent's defer runs once, in
//!       the parent
//!   flong-proc fork-panic
//!       a body that panics: the child says one line and exits 125
//!   flong-proc cgroup LEAF
//!       proc.fork into LEAF (fd.openCgroup) and Spawn of `probe` into it:
//!       each child's cgroup, and the parent's
//!   flong-proc userns NS LEAF
//!       setns(NS, CLONE_NEWUSER), NS a /proc/PID/ns/user, then a fork into
//!       LEAF whose child is uid 0 there, reads its uid_map and, holding
//!       the namespace's capabilities, unshares a UTS namespace and sets
//!       its hostname
//!   flong-proc session HOLDER CONTAINER MACHINE
//!       cgroup.zig's sweep half on a session the shell made:
//!       sessionOpen of HOLDER/CONTAINER/MACHINE under the holder HOLDER,
//!       kill, waitEmpty, remove; prints each answer
//!
//! Exit: 0 when it did what was asked, 1 when not, 2 on a usage error, 125
//! on a panic.

const std = @import("std");
const linux = std.os.linux;
const sys = @import("sys");
const fd = @import("fd");
const msg = @import("msg");
const sig = @import("sig");
const proc = @import("proc");
const cgroup = @import("cgroup");

pub const std_options: std.Options = .{ .enable_segfault_handler = false, .keep_sigpipe = true };
pub const panic = std.debug.FullPanic(msg.onPanic(125));

/// One line on `to`, one write.
fn out(to: i32, comptime fmt: []const u8, args: anytype) void {
    var buf: [65536]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, fmt ++ "\n", args) catch return;
    _ = linux.write(to, line.ptr, line.len);
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

/// The value of a "Key:\tvalue" line of /proc/self/status.
fn statusField(status: []const u8, key: []const u8) []const u8 {
    var lines = std.mem.splitScalar(u8, status, '\n');
    while (lines.next()) |l| {
        if (std.mem.startsWith(u8, l, key) and l.len > key.len and l[key.len] == ':')
            return std.mem.trim(u8, l[key.len + 1 ..], " \t");
    }
    return "?";
}

/// /proc/self/cgroup's 0:: path.
fn ownCgroup(buf: []u8) []const u8 {
    const text = readFile("/proc/self/cgroup", buf) orelse return "?";
    return switch (cgroup.ownFrom(text)) {
        .path => |p| p,
        else => "?",
    };
}

/// `sep` and `e` into `buf`, each newline in `e` written "\\n", so a
/// value that holds one stays on the env line: the bytes written, or null
/// when they do not fit.
pub fn escapeEnv(buf: []u8, sep: []const u8, e: []const u8) ?usize {
    var n: usize = 0;
    for ([_][]const u8{ sep, e }, 0..) |part, k| {
        for (part) |ch| {
            const one = [1]u8{ch};
            const piece: []const u8 = if (k == 1 and ch == '\n') "\\n" else &one;
            if (n + piece.len > buf.len) return null;
            @memcpy(buf[n..][0..piece.len], piece);
            n += piece.len;
        }
    }
    return n;
}

fn probe(args: []const [*:0]const u8) u8 {
    var to: i32 = 1;
    var rest = args;
    if (rest.len >= 2 and std.mem.eql(u8, std.mem.span(rest[0]), "--out")) {
        to = std.fmt.parseInt(i32, std.mem.span(rest[1]), 10) catch return 2;
        rest = rest[2..];
    }
    var line: [65536]u8 = undefined;
    var n: usize = 0;

    // fds, from a listing of /proc/self/fd, its own descriptor left out.
    const rc = linux.open("/proc/self/fd", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    if (linux.E.init(rc) != .SUCCESS) return 1;
    const dir: i32 = @intCast(rc);
    var fds: [256]i32 = undefined;
    var nfds: usize = 0;
    var dbuf: [4096]u8 align(8) = undefined;
    while (true) {
        const got = linux.getdents64(dir, &dbuf, dbuf.len);
        if (linux.E.init(got) != .SUCCESS) return 1;
        if (got == 0) break;
        var it: fd.Entries = .{ .buf = dbuf[0..got] };
        while (it.next()) |e| {
            const v = std.fmt.parseInt(i32, e.name, 10) catch continue;
            if (v == dir or nfds == fds.len) continue;
            fds[nfds] = v;
            nfds += 1;
        }
    }
    _ = linux.close(dir);
    std.mem.sort(i32, fds[0..nfds], {}, std.sort.asc(i32));
    n = (std.fmt.bufPrint(&line, "fds:", .{}) catch return 1).len;
    for (fds[0..nfds]) |v| n += (std.fmt.bufPrint(line[n..], " {d}", .{v}) catch return 1).len;
    out(to, "{s}", .{line[0..n]});

    n = (std.fmt.bufPrint(&line, "argv:", .{}) catch return 1).len;
    for (rest) |a| n += (std.fmt.bufPrint(line[n..], " {s}", .{a}) catch return 1).len;
    out(to, "{s}", .{line[0..n]});

    var status_buf: [8192]u8 = undefined;
    const status = readFile("/proc/self/status", &status_buf) orelse return 1;
    out(to, "sigblk: {s}", .{statusField(status, "SigBlk")});
    out(to, "sigign: {s}", .{statusField(status, "SigIgn")});
    out(to, "sigcgt: {s}", .{statusField(status, "SigCgt")});

    var cwd: [4096]u8 = undefined;
    const cl = linux.readlink("/proc/self/cwd", &cwd, cwd.len);
    out(to, "cwd: {s}", .{if (linux.E.init(cl) == .SUCCESS) cwd[0..cl] else "?"});

    n = (std.fmt.bufPrint(&line, "env:", .{}) catch return 1).len;
    for (std.os.environ, 0..) |e, i| n += escapeEnv(line[n..], if (i == 0) " " else "|", std.mem.span(e)) orelse return 1;
    out(to, "{s}", .{line[0..n]});

    n = (std.fmt.bufPrint(&line, "stdio:", .{}) catch return 1).len;
    for (0..3) |i| {
        var st: linux.Stat = undefined;
        if (linux.E.init(linux.fstat(@intCast(i), &st)) == .SUCCESS) {
            n += (std.fmt.bufPrint(line[n..], " {d}:{d}", .{ st.dev, st.ino }) catch return 1).len;
        } else n += (std.fmt.bufPrint(line[n..], " -", .{}) catch return 1).len;
    }
    out(to, "{s}", .{line[0..n]});

    var cg: [4096]u8 = undefined;
    out(to, "cgroup: {s}", .{ownCgroup(&cg)});
    return 0;
}

const Parent = struct {
    parent: linux.pid_t,

    fn body(self: Parent) noreturn {
        out(1, "child ran: pid {d}, parent {d}", .{ linux.getpid(), self.parent });
        proc.exit(7);
    }

    fn panics(_: Parent) noreturn {
        @panic("planted");
    }
};

fn fork(panicking: bool) u8 {
    const me = linux.getpid();
    defer out(1, "parent defer ran: pid {d}", .{linux.getpid()});
    const child = (if (panicking)
        proc.fork(.{}, Parent{ .parent = me }, Parent.panics)
    else
        proc.fork(.{}, Parent{ .parent = me }, Parent.body)) catch return 1;
    const st = child.await() catch return 1;
    out(1, "child exited {d}", .{st});
    return if (st == @as(u8, if (panicking) 125 else 7)) 0 else 1;
}

const InCgroup = struct {
    fn body(_: InCgroup) noreturn {
        var cg: [4096]u8 = undefined;
        out(1, "child cgroup: {s}", .{ownCgroup(&cg)});
        proc.exit(0);
    }
};

fn inCgroup(leaf: [:0]const u8) u8 {
    var cg: [4096]u8 = undefined;
    out(1, "parent cgroup: {s}", .{ownCgroup(&cg)});
    const h = msg.check(fd.openCgroup(fd.cwd, leaf), "open {s}", .{leaf}) catch return 1;
    defer h.close();
    const child = proc.fork(.{ .cgroup = h }, InCgroup{}, InCgroup.body) catch return 1;
    if ((child.await() catch return 1) != 0) return 1;
    // A program spawned into it: the probe, whose cgroup line says where.
    var mem: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&mem);
    var s = proc.Spawn.init(fba.allocator(), "/proc/self/exe") catch return 1;
    s.arg("probe") catch return 1;
    s.cgroup = h;
    const spawned = s.start() catch return 1;
    return if ((spawned.await() catch return 1) == 0) 0 else 1;
}

const InUserns = struct {
    fn body(_: InUserns) noreturn {
        out(1, "child uid: {d}", .{linux.getuid()});
        var buf: [4096]u8 = undefined;
        const map = readFile("/proc/self/uid_map", &buf) orelse proc.exit(1);
        var joined: [4096]u8 = undefined;
        var n: usize = 0;
        var lines = std.mem.tokenizeScalar(u8, map, '\n');
        var first = true;
        while (lines.next()) |l| {
            if (!first) n += (std.fmt.bufPrint(joined[n..], " / ", .{}) catch proc.exit(1)).len;
            first = false;
            var words = std.mem.tokenizeAny(u8, l, " \t");
            var w1 = true;
            while (words.next()) |w| {
                n += (std.fmt.bufPrint(joined[n..], "{s}{s}", .{ if (w1) "" else " ", w }) catch proc.exit(1)).len;
                w1 = false;
            }
        }
        out(1, "child uid_map: {s}", .{joined[0..n]});
        // The namespace's capabilities: a UTS namespace of its own, named.
        if (linux.E.init(linux.unshare(linux.CLONE.NEWUTS)) != .SUCCESS) proc.exit(1);
        const name = "p3-userns";
        if (linux.E.init(linux.syscall2(.sethostname, @intFromPtr(name.ptr), name.len)) != .SUCCESS) proc.exit(1);
        var uts: linux.utsname = undefined;
        _ = linux.uname(&uts);
        out(1, "child hostname: {s}", .{std.mem.sliceTo(&uts.nodename, 0)});
        var cg: [4096]u8 = undefined;
        out(1, "child cgroup: {s}", .{ownCgroup(&cg)});
        proc.exit(0);
    }
};

fn inUserns(ns: [:0]const u8, leaf: [:0]const u8) u8 {
    const rc = linux.open(ns, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.E.init(rc) != .SUCCESS) return 1;
    if (sys.setns(@intCast(rc), sys.CLONE.NEWUSER) != .ok) return 1;
    _ = linux.close(@intCast(rc));
    out(1, "parent uid after setns: {d}", .{linux.getuid()});
    const h = msg.check(fd.openCgroup(fd.cwd, leaf), "open {s}", .{leaf}) catch return 1;
    defer h.close();
    const child = proc.fork(.{ .cgroup = h }, InUserns{}, InUserns.body) catch return 1;
    const st = child.await() catch return 1;
    out(1, "child exited {d}", .{st});
    return if (st == 0) 0 else 1;
}

fn session(holder: [:0]const u8, container: []const u8, machine: []const u8) u8 {
    var hp: cgroup.Path = .{};
    @memcpy(hp.buf[0..holder.len], holder);
    hp.len = holder.len;
    hp.buf[hp.len] = 0;
    const h = cgroup.holderAt(hp) catch return 1;
    var path: [4096]u8 = undefined;
    const p = std.fmt.bufPrint(&path, "{s}/{s}/{s}", .{ holder, container, machine }) catch return 1;
    var opened = cgroup.sessionOpen(&h, p, machine) catch return 1;
    out(1, "opened: {s}", .{@tagName(opened)});
    const s = switch (opened) {
        .session => |*s| s,
        else => return 0,
    };
    defer s.closeAll();
    for (s.leaf, cgroup.leaf_names) |l, name| out(1, "leaf {s}: {s}", .{ name, if (l != null) "open" else "absent" });
    cgroup.kill(s) catch return 1;
    out(1, "killed", .{});
    cgroup.waitEmpty(s.fd) catch return 1;
    out(1, "empty", .{});
    const r = cgroup.remove(s) catch return 1;
    out(1, "removed: {s}", .{@tagName(r)});
    return 0;
}

pub fn main() noreturn {
    msg.prog = "flong-proc";
    msg.mode = .cut;
    sig.defaultChld();
    const argv = sys.argv();
    if (argv.len < 2) proc.exit(2);
    const cmd = std.mem.span(argv[1]);
    const a = argv[2..];
    const rc: u8 = if (std.mem.eql(u8, cmd, "probe"))
        probe(a)
    else if (std.mem.eql(u8, cmd, "fork") and a.len == 0)
        fork(false)
    else if (std.mem.eql(u8, cmd, "fork-panic") and a.len == 0)
        fork(true)
    else if (std.mem.eql(u8, cmd, "cgroup") and a.len == 1)
        inCgroup(std.mem.span(a[0]))
    else if (std.mem.eql(u8, cmd, "userns") and a.len == 2)
        inUserns(std.mem.span(a[0]), std.mem.span(a[1]))
    else if (std.mem.eql(u8, cmd, "session") and a.len == 3)
        session(std.mem.span(a[0]), std.mem.span(a[1]), std.mem.span(a[2]))
    else
        2;
    proc.exit(rc);
}
