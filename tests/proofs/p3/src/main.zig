//! p3-proc: P3's driver (ZIG.md, "Phase 0: proofs"). Each subcommand forks
//! through proc.fork, prints what parent and child saw, one line each, and
//! exits 0 only when the child's view is the one asked for.
//!
//!   p3-proc fork             a working noreturn body; the parent's defer
//!                            runs once, in the parent
//!   p3-proc fork-panic       a body that panics: the child exits 125, and
//!                            the parent's defer still runs once
//!   p3-proc cgroup LEAF      clone3(CLONE_INTO_CGROUP|CLONE_PIDFD) into LEAF,
//!                            a directory under /sys/fs/cgroup opened
//!                            O_PATH|O_DIRECTORY|O_NOFOLLOW; the child's
//!                            /proc/self/cgroup must name LEAF
//!   p3-proc userns NS [LEAF] setns(NS, CLONE_NEWUSER), NS a /proc/PID/ns/user,
//!                            then a fork (into LEAF when given) whose child
//!                            must be uid 0 there and hold the namespace's
//!                            capabilities: it unshares a UTS namespace and
//!                            sets its hostname
//!
//! Exit: 0 when the check holds, 1 when it does not, 2 on a usage error, 125
//! on a panic.

const std = @import("std");
const linux = std.os.linux;
const proc = @import("proc.zig");

// As every flong root will (ZIG.md, "Per binary"): no segfault handler, and
// a panic is one line and exit_group, so a panicking fork child ends at once
// and never unwinds into the parent's code.
pub const std_options: std.Options = .{ .enable_segfault_handler = false, .keep_sigpipe = true };
pub const panic = std.debug.FullPanic(onPanic);

fn onPanic(m: []const u8, _: ?usize) noreturn {
    say(2, "p3-proc: internal error: {s}", .{m});
    linux.exit_group(125);
}

/// One line on fd, one write; a failed write is dropped (ZIG.md, "Messages").
fn say(fd: i32, comptime fmt: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, fmt ++ "\n", args) catch return;
    _ = linux.write(fd, line.ptr, line.len);
}

/// Reads a small file into buf. The caller names what failed.
fn readFile(path: [*:0]const u8, buf: []u8) ?[]u8 {
    const rc = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.E.init(rc) != .SUCCESS) {
        proc.report(std.mem.span(path), linux.E.init(rc));
        return null;
    }
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    var n: usize = 0;
    while (n < buf.len) {
        const r = linux.read(fd, buf[n..].ptr, buf.len - n);
        switch (linux.E.init(r)) {
            .SUCCESS => if (r == 0) break else {
                n += r;
            },
            .INTR => {},
            else => |e| {
                proc.report(std.mem.span(path), e);
                return null;
            },
        }
    }
    return buf[0..n];
}

/// A file's whitespace collapsed to single spaces and its lines joined by
/// " / ", so a multi-line map prints as one line.
fn oneLine(in: []const u8, out: []u8) []const u8 {
    var n: usize = 0;
    var lines = std.mem.tokenizeScalar(u8, in, '\n');
    var first_line = true;
    while (lines.next()) |l| {
        if (!first_line) n += (std.fmt.bufPrint(out[n..], " / ", .{}) catch return out[0..n]).len;
        first_line = false;
        var words = std.mem.tokenizeAny(u8, l, " \t");
        var first_word = true;
        while (words.next()) |w| {
            const sep = if (first_word) "" else " ";
            first_word = false;
            n += (std.fmt.bufPrint(out[n..], "{s}{s}", .{ sep, w }) catch return out[0..n]).len;
        }
    }
    return out[0..n];
}

pub fn main() noreturn {
    linux.exit_group(run());
}

fn run() u8 {
    const argv = std.os.argv;
    if (argv.len < 2) return usage();
    const cmd = std.mem.span(argv[1]);
    if (std.mem.eql(u8, cmd, "fork") and argv.len == 2) return forkCheck(false);
    if (std.mem.eql(u8, cmd, "fork-panic") and argv.len == 2) return forkCheck(true);
    if (std.mem.eql(u8, cmd, "cgroup") and argv.len == 3) return cgroupCheck(argv[2]);
    if (std.mem.eql(u8, cmd, "userns") and (argv.len == 3 or argv.len == 4))
        return usernsCheck(argv[2], if (argv.len == 4) argv[3] else null);
    return usage();
}

fn usage() u8 {
    say(2, "usage: p3-proc fork | fork-panic | cgroup LEAF | userns NS [LEAF]", .{});
    return 2;
}

// ---- fork: the body cannot return, and no parent defer runs in the child ----

const ForkCtx = struct { parent: linux.pid_t, planted_panic: bool };

fn forkBody(ctx: ForkCtx) noreturn {
    say(1, "child ran: pid {d}, parent {d}", .{ linux.getpid(), ctx.parent });
    if (ctx.planted_panic) @panic("planted");
    linux.exit_group(7);
}

fn forkCheck(planted_panic: bool) u8 {
    // Runs when forkCheck returns, which only the parent does: the child's
    // body ends in exit_group or the panic handler, never back in here. The
    // line is printed once, last, with the parent's pid (default.nix checks).
    defer say(1, "parent defer ran: pid {d}", .{linux.getpid()});
    const child = proc.fork(.{}, ForkCtx{ .parent = linux.getpid(), .planted_panic = planted_panic }, forkBody) catch return 1;
    const status = child.await() catch return 1;
    say(1, "child exited {d}", .{status});
    return if (status == @as(u8, if (planted_panic) 125 else 7)) 0 else 1;
}

// ---- cgroup: clone3(CLONE_INTO_CGROUP) into an O_PATH leaf ----

const cgroup_root = "/sys/fs/cgroup";

/// What /proc/self/cgroup reads in LEAF on the unified hierarchy: "0::"
/// then LEAF below the mount, in the reader's cgroup namespace.
fn expectedCgroup(leaf: []const u8, buf: []u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, leaf, cgroup_root ++ "/")) {
        say(2, "p3-proc: {s}: not under " ++ cgroup_root, .{leaf});
        return null;
    }
    return std.fmt.bufPrint(buf, "0::{s}\n", .{leaf[cgroup_root.len..]}) catch null;
}

fn openLeaf(leaf: [*:0]const u8) ?i32 {
    const rc = linux.open(leaf, .{ .PATH = true, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    if (linux.E.init(rc) != .SUCCESS) {
        proc.report(std.mem.span(leaf), linux.E.init(rc));
        return null;
    }
    return @intCast(rc);
}

/// The child's check of its own cgroup; true when it names `expect`.
fn childCgroupIs(expect: []const u8) bool {
    var buf: [4096]u8 = undefined;
    const got = readFile("/proc/self/cgroup", &buf) orelse return false;
    say(1, "child cgroup: {s}", .{std.mem.trimRight(u8, got, "\n")});
    return std.mem.eql(u8, got, expect);
}

const CgroupCtx = struct { expect: []const u8 };

fn cgroupBody(ctx: CgroupCtx) noreturn {
    linux.exit_group(if (childCgroupIs(ctx.expect)) 0 else 1);
}

fn cgroupCheck(leaf_z: [*:0]const u8) u8 {
    const leaf = std.mem.span(leaf_z);
    var ebuf: [4096]u8 = undefined;
    const expect = expectedCgroup(leaf, &ebuf) orelse return 1;
    const cg = openLeaf(leaf_z) orelse return 1;
    defer _ = linux.close(cg);

    const child = proc.fork(.{ .cgroup = cg }, CgroupCtx{ .expect = expect }, cgroupBody) catch return 1;
    const status = child.await() catch return 1;
    say(1, "child exited {d}", .{status});

    // The parent was not moved: CLONE_INTO_CGROUP places the child only.
    var pbuf: [4096]u8 = undefined;
    const mine = readFile("/proc/self/cgroup", &pbuf) orelse return 1;
    say(1, "parent cgroup: {s}", .{std.mem.trimRight(u8, mine, "\n")});
    return if (status == 0 and !std.mem.eql(u8, mine, expect)) 0 else 1;
}

// ---- userns: a fork after setns(CLONE_NEWUSER) ----

const UsernsCtx = struct { expect_cgroup: ?[]const u8 };
const hostname = "p3-userns";

fn usernsBody(ctx: UsernsCtx) noreturn {
    var ok = true;
    const uid = linux.getuid();
    say(1, "child uid: {d}", .{uid});
    ok = ok and uid == 0;

    var buf: [4096]u8 = undefined;
    var line: [4096]u8 = undefined;
    if (readFile("/proc/self/uid_map", &buf)) |map| {
        say(1, "child uid_map: {s}", .{oneLine(map, &line)});
    } else ok = false;

    ok = utsCheck() and ok;

    if (ctx.expect_cgroup) |expect| ok = childCgroupIs(expect) and ok;
    linux.exit_group(if (ok) 0 else 1);
}

/// CAP_SYS_ADMIN over a UTS namespace the user namespace owns, which only a
/// process whose credentials are in that namespace has: unshare one, set
/// its hostname, read it back.
fn utsCheck() bool {
    const u = linux.unshare(linux.CLONE.NEWUTS);
    if (linux.E.init(u) != .SUCCESS) {
        proc.report("unshare CLONE_NEWUTS", linux.E.init(u));
        return false;
    }
    const h = linux.syscall2(.sethostname, @intFromPtr(hostname.ptr), hostname.len);
    if (linux.E.init(h) != .SUCCESS) {
        proc.report("sethostname", linux.E.init(h));
        return false;
    }
    var uts: linux.utsname = undefined;
    _ = linux.uname(&uts);
    const got = std.mem.sliceTo(&uts.nodename, 0);
    say(1, "child hostname: {s}", .{got});
    return std.mem.eql(u8, got, hostname);
}

fn usernsCheck(ns_path: [*:0]const u8, leaf_z: ?[*:0]const u8) u8 {
    var ebuf: [4096]u8 = undefined;
    const expect: ?[]const u8 = if (leaf_z) |l| (expectedCgroup(std.mem.span(l), &ebuf) orelse return 1) else null;
    const cg: ?i32 = if (leaf_z) |l| (openLeaf(l) orelse return 1) else null;
    defer if (cg) |c| {
        _ = linux.close(c);
    };

    const rc = linux.open(ns_path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.E.init(rc) != .SUCCESS) {
        proc.report(std.mem.span(ns_path), linux.E.init(rc));
        return 1;
    }
    const ns: i32 = @intCast(rc);
    defer _ = linux.close(ns);
    switch (proc.setns(ns, linux.CLONE.NEWUSER)) {
        .ok => {},
        .err => |e| {
            proc.report("setns CLONE_NEWUSER", e);
            return 1;
        },
    }
    say(1, "parent uid after setns: {d}", .{linux.getuid()});

    const child = proc.fork(.{ .cgroup = cg }, UsernsCtx{ .expect_cgroup = expect }, usernsBody) catch return 1;
    const status = child.await() catch return 1;
    say(1, "child exited {d}", .{status});
    return if (status == 0) 0 else 1;
}
