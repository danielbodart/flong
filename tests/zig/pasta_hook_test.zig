//! src/launch/hook.zig and src/launch/pasta.zig from outside (the `test`
//! step; the Zig port's L4): the Spawn each builds, argv, envp, stdio,
//! the kept descriptors, the directory and the cgroup, against golden
//! tables read from what flong-launch.c:586-675 (a7919be) builds: run_hook's
//! setenv calls and fl_spawn, start_pasta's pushes and fl_spawn. @X@ in a
//! table stands for what only the run knows: this process's pid, U1's,
//! the network namespace's and the pid file's numbers.
//!
//! The namespaces are this process's own, opened by /proc/<pid>/ns as the
//! launcher opens its own; a cgroup handle is "/" opened as one
//! (O_PATH|O_DIRECTORY), which nothing here starts a child in but the
//! failing start below.

const std = @import("std");
const linux = std.os.linux;
const sys = @import("sys");
const fd = @import("fd");
const msg = @import("msg");
const proc = @import("proc");
const spec = @import("spec");
const hook = @import("hook");
const pasta = @import("pasta");
const testing = std.testing;
const Allocator = std.mem.Allocator;

// ---- handles, and stderr by raw calls ----

/// This process's own user and network namespaces, opened as the launcher
/// opens U1's and pid 1's: fd.openUserns and fd.openNetns of a pid.
fn ownUserns() !fd.Fd(.userns) {
    return switch (try fd.openUserns(linux.getpid())) {
        .ok => |h| h,
        .err => error.Open,
    };
}

fn ownNetns() !fd.Fd(.netns) {
    return switch (try fd.openNetns(linux.getpid())) {
        .ok => |h| h,
        .err => error.Open,
    };
}

const Handles = struct {
    userns: fd.Fd(.userns),
    netns: fd.Held(.netns),
    leaf: fd.Fd(.cgroup),

    fn open() !Handles {
        const userns = try ownUserns();
        const netns = try ownNetns();
        const leaf = switch (try fd.openCgroup(fd.cwd, "/")) {
            .ok => |h| h,
            .err => return error.Open,
        };
        return .{ .userns = userns, .netns = netns.holdUntilExit(), .leaf = leaf };
    }

    /// The held netns stays in the table, as the launcher's does; only
    /// the owned ones close.
    fn close(self: Handles) void {
        self.userns.close();
        self.leaf.close();
    }
};

/// What a call wrote on stderr: fd 2 is a memfd for its length.
const Capture = struct {
    saved: i32,
    file: i32,

    fn begin() !Capture {
        const mf = linux.memfd_create("pasta-hook-test", linux.MFD.CLOEXEC);
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

// ---- the spec ----

/// A spec with only what the two pieces read set to anything but its
/// default; the rest as a caller's usual one.
fn specWith(post_start: []const [:0]const u8, network: bool, pasta_args: []const [:0]const u8, pasta_wait: bool) spec.Spec {
    return .{
        .machine = "m-1",
        .container = "c",
        .state = "/run/user/1000/flong",
        .cache = "/home/u/.cache/flong/c",
        .closure = "/nix/store/closure",
        .uidmap = &.{.{ .inside = 0, .outside = 100000, .count = 65536 }},
        .gidmap = &.{.{ .inside = 0, .outside = 100000, .count = 65536 }},
        .uid = 1000,
        .gid = 100,
        .home = "/home/u",
        .holder = "flong.slice/s",
        .post_start = post_start,
        .network = network,
        .pasta_args = pasta_args,
        .pasta_wait = pasta_wait,
        // A keep-fd, as the wrapper's resolv.conf is: pasta keeps none.
        .keep_fds = &.{9},
        .command = &.{"sh"},
    };
}

fn words(sp: *const proc.Spawn) []const ?[*:0]const u8 {
    return sp.argv.items[0 .. sp.argv.items.len - 1];
}

fn envWords(envp: hook.Envp) []const ?[*:0]const u8 {
    var n: usize = 0;
    while (envp[n] != null) n += 1;
    return envp[0..n];
}

fn substitute(arena: Allocator, w: []const u8, vars: []const [2][]const u8) ![]const u8 {
    var out = w;
    for (vars) |v| out = try std.mem.replaceOwned(u8, arena, out, v[0], v[1]);
    return out;
}

fn expectWords(arena: Allocator, want: []const []const u8, got: []const ?[*:0]const u8, vars: []const [2][]const u8) !void {
    for (want, 0..) |w, i| {
        if (i >= got.len) break;
        testing.expectEqualStrings(try substitute(arena, w, vars), std.mem.span(got[i].?)) catch |err| {
            std.debug.print("word {d} differs\n", .{i});
            return err;
        };
    }
    try testing.expectEqual(want.len, got.len);
}

fn fmt(arena: Allocator, comptime f: []const u8, args: anytype) ![]const u8 {
    return std.fmt.allocPrint(arena, f, args);
}

// ---- the hook ----

const leader: sys.pid_t = 4242;
const hook_program: [:0]const u8 = "/nix/store/x-flong-poststart-m/bin/flong-poststart-m";

/// One row of the hook's table: the launcher's environment, and the
/// environment run_hook's setenv calls leave it with.
const EnvCase = struct { name: []const u8, environ: []const [*:0]const u8, want: []const []const u8 };

const env_cases = [_]EnvCase{
    .{
        .name = "none of the four: each appended, in setenv's order",
        .environ = &.{ "PATH=/run/current-system/sw/bin", "HOME=/home/u" },
        .want = &.{ "PATH=/run/current-system/sw/bin", "HOME=/home/u", "leader=4242", "userns=/proc/@SELF@/fd/@U1@", "netns=/proc/@SELF@/fd/@NETNS@", "machine=m-1" },
    },
    .{
        .name = "an empty environment",
        .environ = &.{},
        .want = &.{ "leader=4242", "userns=/proc/@SELF@/fd/@U1@", "netns=/proc/@SELF@/fd/@NETNS@", "machine=m-1" },
    },
    .{
        .name = "the caller's own: each replaced in place, the first of a name only",
        .environ = &.{ "netns=/run/netns/x", "A=1", "leader=1", "leader=2", "machine=other", "userns=" },
        .want = &.{ "netns=/proc/@SELF@/fd/@NETNS@", "A=1", "leader=4242", "leader=2", "machine=m-1", "userns=/proc/@SELF@/fd/@U1@" },
    },
    .{
        .name = "near names and a name without '=' name nothing",
        .environ = &.{ "machine", "leaderx=1", "lead=1", "usernsX=", "netns2=a", "Machine=b", "=netns" },
        .want = &.{ "machine", "leaderx=1", "lead=1", "usernsX=", "netns2=a", "Machine=b", "=netns", "leader=4242", "userns=/proc/@SELF@/fd/@U1@", "netns=/proc/@SELF@/fd/@NETNS@", "machine=m-1" },
    },
};

fn vars3(arena: Allocator, h: Handles) ![3][2][]const u8 {
    return .{
        .{ "@SELF@", try fmt(arena, "{d}", .{sys.getpid()}) },
        .{ "@U1@", try fmt(arena, "{d}", .{h.userns.raw()}) },
        .{ "@NETNS@", try fmt(arena, "{d}", .{h.netns.raw()}) },
    };
}

test "hook.env: run_hook's setenv calls, as glibc makes them, on a copy" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const h = try Handles.open();
    defer h.close();
    const vars = try vars3(arena, h);
    for (env_cases) |c| {
        var before: std.ArrayList([]const u8) = .empty;
        for (c.environ) |e| try before.append(arena, try arena.dupe(u8, std.mem.span(e)));
        const envp = try hook.env(arena, c.environ, .{ .leader = leader, .self_pid = sys.getpid(), .machine = "m-1" }, h.userns, h.netns);
        expectWords(arena, c.want, envWords(envp), &vars) catch |err| {
            std.debug.print("case: {s}\n", .{c.name});
            return err;
        };
        // The launcher's environment is left as it was.
        for (c.environ, before.items) |e, b| try testing.expectEqualStrings(b, std.mem.span(e));
    }
}

test "hook.env: $userns and $netns name the launcher's descriptors of U1 and the network namespace" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const h = try Handles.open();
    defer h.close();
    const envp = try hook.env(arena, &.{}, .{ .leader = leader, .self_pid = sys.getpid(), .machine = "m-1" }, h.userns, h.netns);
    const got = envWords(envp);
    for ([_]struct { entry: usize, prefix: []const u8, own: []const u8 }{
        .{ .entry = 1, .prefix = "userns=", .own = "/proc/self/ns/user" },
        .{ .entry = 2, .prefix = "netns=", .own = "/proc/self/ns/net" },
    }) |c| {
        const e = std.mem.span(got[c.entry].?);
        try testing.expect(std.mem.startsWith(u8, e, c.prefix));
        const path = try arena.dupeZ(u8, e[c.prefix.len..]);
        var a: linux.Stat = undefined;
        var b: linux.Stat = undefined;
        try testing.expectEqual(@as(usize, 0), linux.stat(path, &a));
        try testing.expectEqual(@as(usize, 0), linux.stat(@ptrCast(c.own.ptr), &b));
        try testing.expectEqual(b.ino, a.ino);
    }
}

test "hook.build: no hook, nothing built and no environment (quirk 3)" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const h = try Handles.open();
    defer h.close();
    const s = specWith(&.{}, true, &.{}, false);
    const live = fd.liveCount();
    try testing.expectEqual(@as(?hook.Hook, null), try hook.build(arena_state.allocator(), &s, &.{"A=1"}, .{ .leader = leader, .self_pid = sys.getpid(), .machine = s.machine }, h.userns, h.netns, h.leaf));
    try testing.expectEqual(live, fd.liveCount());
}

test "hook.build: the spec's words, the four variables, the launcher's stdio and directory, the hooks leaf, nothing kept" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const h = try Handles.open();
    defer h.close();
    const vars = try vars3(arena, h);
    const s = specWith(&.{ hook_program, "a b", "", "--" }, false, &.{}, false);
    const live = fd.liveCount();
    const hk = (try hook.build(arena, &s, &.{"PATH=/bin"}, .{ .leader = leader, .self_pid = sys.getpid(), .machine = s.machine }, h.userns, h.netns, h.leaf)).?;
    try expectWords(arena, &.{ hook_program, "a b", "", "--" }, words(&hk.spawn), &vars);
    try expectWords(arena, &.{ "PATH=/bin", "leader=4242", "userns=/proc/@SELF@/fd/@U1@", "netns=/proc/@SELF@/fd/@NETNS@", "machine=m-1" }, envWords(hk.envp), &vars);
    try testing.expectEqual(hk.envp, hk.spawn.envp.?);
    try testing.expectEqual([3]?fd.AnyFd{ null, null, null }, hk.spawn.stdio);
    try testing.expectEqual(@as(usize, 0), hk.spawn.keep.items.len);
    try testing.expectEqual(@as(?[*:0]const u8, null), hk.spawn.dir);
    try testing.expectEqual(h.leaf, hk.spawn.cgroup.?);
    // Building opened nothing.
    try testing.expectEqual(live, fd.liveCount());
}

// ---- pasta ----

const pasta_program = "/nix/store/x-passt/bin/pasta";

/// The fixed part, as start_pasta pushes it (flong-launch.c:639-644).
const pasta_head = [_][]const u8{
    pasta_program,               "--quiet", "--config-net",      "--userns",
    "/proc/@SELF@/fd/@U1@",      "--netns", "/proc/4242/ns/net", "--pid",
    "/proc/@SELF@/fd/@PIDFILE@",
};

/// One row of pasta's table: the spec's pasta-arg words (module.nix's
/// pastaPortArgs and --no-map-gw, the wrapper's --dns-forward), pasta-wait,
/// and the argv after the fixed part.
const PastaCase = struct { name: []const u8, args: []const [:0]const u8, wait: bool };

const pasta_cases = [_]PastaCase{
    .{
        .name = "fixed forwardPorts, tcp and udp, two hostPorts, the host's loopback, both resolvers, pasta-wait",
        .args = &.{ "-t", "18080:80", "-u", "5353:5353", "-T", "5432,6379", "-U", "5432,6379", "--host-lo-to-ns-lo", "--no-map-gw", "--dns-forward", "169.254.1.1", "--dns-forward", "100::1" },
        .wait = true,
    },
    .{
        .name = "the same, no pasta-wait: the same argv",
        .args = &.{ "-t", "18080:80", "-u", "5353:5353", "-T", "5432,6379", "-U", "5432,6379", "--host-lo-to-ns-lo", "--no-map-gw", "--dns-forward", "169.254.1.1", "--dns-forward", "100::1" },
        .wait = false,
    },
    .{
        .name = "forwardPorts auto, no hostPorts, one resolver",
        .args = &.{ "-t", "auto", "-u", "none", "-T", "none", "-U", "none", "--no-map-gw", "--dns-forward", "100::1" },
        .wait = false,
    },
    .{
        .name = "network and no pasta-arg",
        .args = &.{},
        .wait = false,
    },
    .{
        .name = "words pasta reads, passed as they are",
        .args = &.{ "", "--", "-t", "1,2:3", "a b" },
        .wait = false,
    },
};

test "pasta.build: argv, the pid file, /dev/null, the pasta leaf, nothing kept, per row" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const h = try Handles.open();
    defer h.close();
    for (pasta_cases) |c| {
        const s = specWith(&.{}, true, c.args, c.wait);
        const live = fd.liveCount();
        var p = (try pasta.build(arena, &s, pasta_program, sys.getpid(), h.userns, leader, null, h.leaf)).?;
        // The pid file, held, and /dev/null: nothing else.
        try testing.expectEqual(live + 2, fd.liveCount());
        const vars = [_][2][]const u8{
            .{ "@SELF@", try fmt(arena, "{d}", .{sys.getpid()}) },
            .{ "@U1@", try fmt(arena, "{d}", .{h.userns.raw()}) },
            .{ "@PIDFILE@", try fmt(arena, "{d}", .{p.pid_file.raw()}) },
        };
        var want: std.ArrayList([]const u8) = .empty;
        try want.appendSlice(arena, &pasta_head);
        for (c.args) |a| try want.append(arena, a);
        expectWords(arena, want.items, words(&p.spawn), &vars) catch |err| {
            std.debug.print("case: {s}\n", .{c.name});
            return err;
        };
        try testing.expectEqual(@as(?[*:null]const ?[*:0]const u8, null), p.spawn.envp);
        try testing.expectEqual(p.dev_null.any(), p.spawn.stdio[0].?);
        try testing.expectEqual(@as(?fd.AnyFd, null), p.spawn.stdio[1]);
        try testing.expectEqual(@as(?fd.AnyFd, null), p.spawn.stdio[2]);
        try testing.expectEqual(@as(usize, 0), p.spawn.keep.items.len);
        try testing.expectEqual(@as(?[*:0]const u8, null), p.spawn.dir);
        try testing.expectEqual(h.leaf, p.spawn.cgroup.?);

        // /dev/null, read-only, close-on-exec.
        var link: [64]u8 = undefined;
        const dn = fd.selfPath(p.dev_null);
        const n = linux.readlink(dn.path(), &link, link.len);
        try testing.expectEqualStrings("/dev/null", link[0..n]);
        const fl = linux.fcntl(p.dev_null.raw(), 3, 0); // F_GETFL
        try testing.expectEqual(@as(usize, 0), fl & 3); // O_RDONLY
        try testing.expectEqual(@as(usize, 1), linux.fcntl(p.dev_null.raw(), 1, 0) & 1); // F_GETFD: FD_CLOEXEC

        // The pid file: a memfd named pasta.pid, close-on-exec, and
        // --pid's path, through this process's pid, is that file.
        const pf = fd.selfPath(p.pid_file);
        const m = linux.readlink(pf.path(), &link, link.len);
        try testing.expectEqualStrings("/memfd:pasta.pid (deleted)", link[0..m]);
        try testing.expectEqual(@as(usize, 1), linux.fcntl(p.pid_file.raw(), 1, 0) & 1);
        const pid_arg = try arena.dupeZ(u8, std.mem.span(words(&p.spawn)[8].?));
        var a: linux.Stat = undefined;
        var b: linux.Stat = undefined;
        try testing.expectEqual(@as(usize, 0), linux.stat(pid_arg, &a));
        try testing.expectEqual(@as(usize, 0), linux.fstat(p.pid_file.raw(), &b));
        try testing.expectEqual(b.ino, a.ino);
        // --userns's path is U1.
        const userns_arg = try arena.dupeZ(u8, std.mem.span(words(&p.spawn)[4].?));
        try testing.expectEqual(@as(usize, 0), linux.stat(userns_arg, &a));
        try testing.expectEqual(@as(usize, 0), linux.stat("/proc/self/ns/user", &b));
        try testing.expectEqual(b.ino, a.ino);

        p.dev_null.close();
    }
}

test "pasta.build: no network, nothing built, no pid file" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const h = try Handles.open();
    defer h.close();
    const s = specWith(&.{hook_program}, false, &.{}, false);
    const live = fd.liveCount();
    try testing.expect(try pasta.build(arena_state.allocator(), &s, pasta_program, sys.getpid(), h.userns, leader, null, h.leaf) == null);
    try testing.expectEqual(live, fd.liveCount());
}

test "pasta gets the hook's environment when a hook ran, the launcher's otherwise (quirk 3)" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const h = try Handles.open();
    defer h.close();
    const environ = [_][*:0]const u8{"PATH=/bin"};
    for ([_]bool{ true, false }) |with_hook| {
        const s = specWith(if (with_hook) &.{hook_program} else &.{}, true, &.{"--no-map-gw"}, false);
        // The root's composition: the hook's envp, or null.
        const hk = try hook.build(arena, &s, &environ, .{ .leader = leader, .self_pid = sys.getpid(), .machine = s.machine }, h.userns, h.netns, h.leaf);
        var p = (try pasta.build(arena, &s, pasta_program, sys.getpid(), h.userns, leader, if (hk) |x| x.envp else null, h.leaf)).?;
        defer p.dev_null.close();
        if (with_hook) {
            try testing.expectEqual(hk.?.envp, p.spawn.envp.?);
            const vars = try vars3(arena, h);
            try expectWords(arena, &.{ "PATH=/bin", "leader=4242", "userns=/proc/@SELF@/fd/@U1@", "netns=/proc/@SELF@/fd/@NETNS@", "machine=m-1" }, envWords(p.spawn.envp.?), &vars);
        } else {
            try testing.expectEqual(@as(?hook.Hook, null), hk);
            try testing.expectEqual(@as(?[*:null]const ?[*:0]const u8, null), p.spawn.envp);
        }
    }
}

test "quirk 4: pasta's --netns is the leader's by pid, the hook's $netns the launcher's descriptor" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const h = try Handles.open();
    defer h.close();
    const s = specWith(&.{hook_program}, true, &.{}, false);
    const hk = (try hook.build(arena, &s, &.{}, .{ .leader = leader, .self_pid = sys.getpid(), .machine = s.machine }, h.userns, h.netns, h.leaf)).?;
    var p = (try pasta.build(arena, &s, pasta_program, sys.getpid(), h.userns, leader, hk.envp, h.leaf)).?;
    defer p.dev_null.close();
    try testing.expectEqualStrings("/proc/4242/ns/net", std.mem.span(words(&p.spawn)[6].?));
    try testing.expectEqualStrings(try fmt(arena, "netns=/proc/{d}/fd/{d}", .{ sys.getpid(), h.netns.raw() }), std.mem.span(envWords(hk.envp)[2].?));
}

test "Pasta.start closes /dev/null whether or not pasta started" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const h = try Handles.open();
    defer h.close();
    const s = specWith(&.{}, true, &.{}, false);
    msg.prog = "flong launch";
    msg.mode = .cut;
    var p = (try pasta.build(arena_state.allocator(), &s, pasta_program, sys.getpid(), h.userns, leader, null, h.leaf)).?;
    const dev_null = p.dev_null;
    // "/" is no cgroup: clone3 refuses CLONE_INTO_CGROUP, so nothing
    // starts.
    const cap = try Capture.begin();
    const r = p.start();
    var buf: [1024]u8 = undefined;
    const err = try cap.end(&buf);
    try testing.expectError(error.Reported, r);
    try testing.expect(std.mem.startsWith(u8, err, "flong launch: clone3 " ++ pasta_program ++ ": "));
    try testing.expect(!dev_null.isLive());
    try testing.expect(p.pid_file.isLive());
}

// ---- after the reap ----

test "done: the refusals rootless.nix asserts, and nothing on success" {
    msg.prog = "flong launch";
    msg.mode = .cut;
    const Case = struct { f: *const fn (u8) msg.Error!void, status: u8, want: []const u8 };
    for ([_]Case{
        .{ .f = hook.done, .status = 1, .want = "flong launch: postStart failed (status 1); the payload does not run\n" },
        .{ .f = hook.done, .status = 127, .want = "flong launch: postStart failed (status 127); the payload does not run\n" },
        .{ .f = hook.done, .status = 143, .want = "flong launch: postStart failed (status 143); the payload does not run\n" },
        .{ .f = hook.done, .status = 0, .want = "" },
        .{ .f = pasta.done, .status = 1, .want = "flong launch: pasta failed (status 1); the payload does not run\n" },
        .{ .f = pasta.done, .status = 137, .want = "flong launch: pasta failed (status 137); the payload does not run\n" },
        .{ .f = pasta.done, .status = 0, .want = "" },
    }) |c| {
        const cap = try Capture.begin();
        const r = c.f(c.status);
        var buf: [1024]u8 = undefined;
        const err = try cap.end(&buf);
        try testing.expectEqualStrings(c.want, err);
        if (c.status == 0) try r else try testing.expectError(error.Reported, r);
    }
}

test "done: the trace stages, when tracing" {
    msg.prog = "flong launch";
    msg.mode = .cut;
    msg.tracing = true;
    defer msg.tracing = false;
    for ([_]struct { f: *const fn (u8) msg.Error!void, stage: []const u8 }{
        .{ .f = hook.done, .stage = " hook-done\n" },
        .{ .f = pasta.done, .stage = " pasta-up\n" },
    }) |c| {
        const cap = try Capture.begin();
        try c.f(0);
        var buf: [256]u8 = undefined;
        const out = try cap.end(&buf);
        try testing.expect(std.mem.startsWith(u8, out, "T "));
        try testing.expect(std.mem.endsWith(u8, out, c.stage));
    }
}
