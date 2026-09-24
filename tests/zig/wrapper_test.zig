//! S3's prologue pieces from outside (the `test` step): the parts of
//! rootless-wrapper.bash that `flong launch DECL.zon` does itself, each
//! refusal's text and status as the wrapper's (prologue.exit_refused under
//! the declaration's name, here "agent"):
//!
//!   caller     uid and gid 0, the name, the runtime directory (:52-82)
//!   workspace  canon without a chdir, the suffix, the refusals (:84-136)
//!   cmd        a command's argv, environment, status and output, against
//!              flong-fake-cmd (tests/zig/fakecmd.zig)
//!   binds      the lines, the merge, the fold into the workspace
//!              (:138-180)
//!   identity   the prepared root's passwd and group, swept (:330-360)
//!   prepare    the cold path, the lock, the tool, gc, swept (:277-328)
//!   relaunch   prologue.relaunchSelf, through flong-fake-cmd
//!
//! What prints or exits runs in a forked child, its stdout and stderr on
//! pipes, as prologue_test's pieces do.

const std = @import("std");
const linux = std.os.linux;
const sys = @import("sys");
const fd = @import("fd");
const msg = @import("msg");
const sig = @import("sig");
const proc = @import("proc");
const prologue = @import("prologue");
const subid = @import("subid");
const caller = @import("caller");
const workspace = @import("workspace");
const cmd = @import("cmd");
const binds = @import("binds");
const identity = @import("identity");
const prepare = @import("prepare");
const options = @import("options");
const testing = std.testing;

// ---- helpers ----

fn opened(r: anytype) !@FieldType(@typeInfo(@TypeOf(r)).error_union.payload, "ok") {
    return switch (try r) {
        .ok => |h| h,
        .err => error.TestUnexpectedResult,
    };
}

fn ok(r: anytype) !void {
    switch (r) {
        .ok => {},
        .err => |e| {
            std.debug.print("unexpected errno {s}\n", .{@tagName(e)});
            return error.TestUnexpectedResult;
        },
    }
}

fn drain(r: fd.Fd(.pipe_r), buf: []u8) ![]u8 {
    var n: usize = 0;
    while (n < buf.len) {
        const got = switch (r.read(buf[n..])) {
            .ok => |g| g,
            .err => return error.TestUnexpectedResult,
        };
        if (got == 0) break;
        n += got;
    }
    return buf[0..n];
}

const Captured = struct {
    status: u8 = 0,
    out: []const u8 = "",
    err: []const u8 = "",
    out_buf: [16384]u8 = undefined,
    err_buf: [8192]u8 = undefined,
};

fn InChild(comptime C: type, comptime body: fn (C) anyerror!void) type {
    return struct {
        ctx: C,
        out: fd.Fd(.pipe_w),
        err: fd.Fd(.pipe_w),

        fn run(self: @This()) noreturn {
            if (linux.E.init(linux.dup2(self.out.raw(), 1)) != .SUCCESS) proc.exit(99);
            if (linux.E.init(linux.dup2(self.err.raw(), 2)) != .SUCCESS) proc.exit(99);
            self.out.close();
            self.err.close();
            // The prologue's prefix: the declaration's name.
            msg.prog = "agent";
            msg.mode = .whole;
            body(self.ctx) catch |err| proc.exit(switch (err) {
                error.Reported => prologue.exit_refused,
                error.Aborted => 128 + sig.abort_signal,
                else => 98,
            });
            proc.exit(0);
        }
    };
}

/// Runs `body(ctx)` in a forked child whose stdout and stderr are pipes,
/// under the prologue's prefix: a returned error.Reported exits 1.
fn capture(c: *Captured, ctx: anytype, comptime body: fn (@TypeOf(ctx)) anyerror!void) !void {
    const o = try opened(fd.pipe());
    defer o.r.close();
    const e = try opened(fd.pipe());
    defer e.r.close();
    const W = InChild(@TypeOf(ctx), body);
    const child = proc.fork(.{ .keep = &.{ o.w.any(), e.w.any() } }, W{ .ctx = ctx, .out = o.w, .err = e.w }, W.run) catch |err| {
        o.w.close();
        e.w.close();
        return err;
    };
    o.w.close();
    e.w.close();
    c.out = try drain(o.r, &c.out_buf);
    c.err = try drain(e.r, &c.err_buf);
    c.status = child.await() catch |err| {
        child.reapNow(.kill);
        return err;
    };
}

fn say(comptime fmt: []const u8, args: anytype) void {
    var b: [8192]u8 = undefined;
    _ = fd.Stdio.out.writeAll(std.fmt.bufPrint(&b, fmt, args) catch "(too long)\n");
}

/// A refusal: status 1 and "agent: <want>\n" on stderr.
fn expectRefused(c: *const Captured, want: []const u8) !void {
    var b: [8192]u8 = undefined;
    testing.expectEqualStrings(try std.fmt.bufPrint(&b, "agent: {s}\n", .{want}), c.err) catch |err| {
        std.debug.print("out: {s}\n", .{c.out});
        return err;
    };
    try testing.expectEqual(@as(u8, 1), c.status);
}

fn expectOk(c: *const Captured) !void {
    testing.expectEqual(@as(u8, 0), c.status) catch |err| {
        std.debug.print("stderr: {s}\nstdout: {s}\n", .{ c.err, c.out });
        return err;
    };
}

/// A scratch directory under the test's working directory, its relative
/// and its canonical names.
const Scratch = struct {
    rel: [:0]const u8 = "",
    abs: [:0]const u8 = "",
    rel_buf: [64]u8 = undefined,
    abs_buf: [4096]u8 = undefined,

    fn make(s: *Scratch, what: []const u8) !void {
        s.rel = try std.fmt.bufPrintZ(&s.rel_buf, "wrapper-{s}-{d}", .{ what, linux.getpid() });
        try ok(sys.mkdirat(sys.AT.FDCWD, s.rel, 0o700));
        var cwd: [4096]u8 = undefined;
        const n = linux.readlink("/proc/self/cwd", &cwd, cwd.len);
        if (linux.E.init(n) != .SUCCESS) return error.TestUnexpectedResult;
        s.abs = try std.fmt.bufPrintZ(&s.abs_buf, "{s}/{s}", .{ cwd[0..n], s.rel });
    }

    fn at(s: *const Scratch, buf: []u8, rel: []const u8) ![:0]const u8 {
        return std.fmt.bufPrintZ(buf, "{s}/{s}", .{ s.rel, rel });
    }

    fn absAt(s: *const Scratch, buf: []u8, rel: []const u8) ![:0]const u8 {
        return std.fmt.bufPrintZ(buf, "{s}/{s}", .{ s.abs, rel });
    }

    fn remove(s: *const Scratch) void {
        removeTree(sys.AT.FDCWD, s.rel);
    }
};

fn removeTree(dir: i32, name: [*:0]const u8) void {
    _ = linux.fchmodat(dir, name, 0o700, 0);
    const rc = linux.openat(dir, name, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    if (linux.E.init(rc) == .SUCCESS) {
        const d: i32 = @intCast(rc);
        var buf: [4096]u8 align(8) = undefined;
        while (true) {
            const got = linux.getdents64(d, &buf, buf.len);
            if (linux.E.init(got) != .SUCCESS or got == 0) break;
            var it: fd.Entries = .{ .buf = buf[0..got] };
            var removed = false;
            while (it.next()) |e| {
                if (std.mem.eql(u8, e.name, ".") or std.mem.eql(u8, e.name, "..")) continue;
                var nb: [256]u8 = undefined;
                const n = std.fmt.bufPrintZ(&nb, "{s}", .{e.name}) catch continue;
                if (e.type == fd.Entries.dt_dir) removeTree(d, n) else _ = linux.unlinkat(d, n, 0);
                removed = true;
            }
            if (removed) _ = linux.lseek(d, 0, linux.SEEK.SET);
            if (!removed) break;
        }
        _ = linux.close(d);
        _ = linux.unlinkat(dir, name, linux.AT.REMOVEDIR);
    } else {
        _ = linux.unlinkat(dir, name, 0);
    }
}

fn symlink(target: [*:0]const u8, at: [*:0]const u8) !void {
    if (linux.E.init(linux.symlinkat(target, linux.AT.FDCWD, at)) != .SUCCESS) return error.TestUnexpectedResult;
}

fn mkdir(at: [*:0]const u8) !void {
    try ok(sys.mkdirat(sys.AT.FDCWD, at, 0o700));
}

fn writeFile(at: [*:0]const u8, text: []const u8) !void {
    const f = try opened(fd.openFile(fd.cwd, at, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o600));
    defer f.close();
    try ok(f.writeAll(text));
}

fn readFile(at: [*:0]const u8, buf: []u8) ![]const u8 {
    const f = try opened(fd.openFile(fd.cwd, at, .{}, 0));
    defer f.close();
    var n: usize = 0;
    while (true) {
        const got = switch (f.read(buf[n..])) {
            .ok => |g| g,
            .err => return error.TestUnexpectedResult,
        };
        if (got == 0) return buf[0..n];
        n += got;
    }
}

/// flong-fake-cmd, its path made absolute.
var fake_buf: [std.fs.max_path_bytes:0]u8 = undefined;
var fake: [:0]const u8 = "";

fn fakeCmd() [:0]const u8 {
    if (fake.len == 0) {
        const p = std.fs.cwd().realpath(options.fake_cmd, &fake_buf) catch @panic("flong-fake-cmd not found");
        fake_buf[p.len] = 0;
        fake = fake_buf[0..p.len :0];
    }
    return fake;
}

fn environ() []const [*:0]const u8 {
    return @ptrCast(std.os.environ);
}

fn envp() cmd.Envp {
    return @ptrCast(std.os.environ.ptr);
}

// ---- caller ----

const Identify = struct {
    uid: u32,
    gid: u32,
    name: ?[]const u8,

    fn body(self: Identify) !void {
        const who = try caller.identify(std.heap.page_allocator, self.uid, self.gid, self.name);
        say("{d} {d} {s}", .{ who.uid, who.gid, who.name });
    }
};

test "caller: uid 0 and then gid 0 refused with the wrapper's texts, exit 1; the name or the uid" {
    var c: Captured = .{};
    try capture(&c, Identify{ .uid = 0, .gid = 0, .name = "root" }, Identify.body);
    try expectRefused(&c, "refusing to run as root: flong runs as the calling user, and root has no subordinate range");
    try capture(&c, Identify{ .uid = 1000, .gid = 0, .name = "alice" }, Identify.body);
    try expectRefused(&c, "refusing to run with primary group 0: flong never maps host gid 0 into a session");
    try capture(&c, Identify{ .uid = 1000, .gid = 100, .name = "alice" }, Identify.body);
    try expectOk(&c);
    try testing.expectEqualStrings("1000 100 alice", c.out);
    // A uid passwd does not name is matched by uid (:57-58).
    try capture(&c, Identify{ .uid = 4242, .gid = 100, .name = null }, Identify.body);
    try expectOk(&c);
    try testing.expectEqualStrings("4242 100 4242", c.out);
}

const Runtime = struct {
    path: [:0]const u8,
    euid: u32,

    fn body(self: Runtime) !void {
        try caller.checkRuntime(self.path, self.euid, "alice");
    }
};

fn expectNoRuntime(c: *const Captured, path: []const u8) !void {
    var b: [4096]u8 = undefined;
    try expectRefused(c, try std.fmt.bufPrint(&b, "no runtime directory {s} owned by alice: run it from a login session, or give alice a user manager with users.users.alice.linger = true", .{path}));
}

test "caller: the runtime directory is a directory the caller owns, through a symlink too" {
    var s: Scratch = .{};
    try s.make("rt");
    defer s.remove();
    var b: [4][4096]u8 = undefined;
    const dir = try s.absAt(&b[0], "rt");
    try mkdir(dir);
    const link = try s.absAt(&b[1], "link");
    try symlink("rt", link);
    const file = try s.absAt(&b[2], "file");
    try writeFile(file, "");
    const missing = try s.absAt(&b[3], "missing");
    const me = sys.geteuid();

    var c: Captured = .{};
    try capture(&c, Runtime{ .path = dir, .euid = me }, Runtime.body);
    try expectOk(&c);
    try capture(&c, Runtime{ .path = link, .euid = me }, Runtime.body);
    try expectOk(&c);
    try capture(&c, Runtime{ .path = dir, .euid = me +% 1 }, Runtime.body);
    try expectNoRuntime(&c, dir);
    try capture(&c, Runtime{ .path = file, .euid = me }, Runtime.body);
    try expectNoRuntime(&c, file);
    try capture(&c, Runtime{ .path = missing, .euid = me }, Runtime.body);
    try expectNoRuntime(&c, missing);
}

const Get = struct {
    fn body(_: Get) !void {
        const who = try caller.get(std.heap.page_allocator);
        say("{d} {d} {s} {s} {s}", .{ who.uid, who.gid, who.name, who.runtime, who.state });
    }
};

test "caller.get: this process's ids, and /run/user/$UID or its refusal" {
    var c: Captured = .{};
    try capture(&c, Get{}, Get.body);
    const uid = sys.getuid();
    if (uid == 0 or sys.getgid() == 0) return error.SkipZigTest;
    var b: [256]u8 = undefined;
    if (c.status == 0) {
        const want = try std.fmt.bufPrint(&b, "{d} {d} ", .{ uid, sys.getgid() });
        try testing.expect(std.mem.startsWith(u8, c.out, want));
        var rb: [64]u8 = undefined;
        try testing.expect(std.mem.endsWith(u8, c.out, try std.fmt.bufPrint(&rb, " /run/user/{d} /run/user/{d}/flong", .{ uid, uid })));
    } else {
        try testing.expectEqual(@as(u8, 1), c.status);
        try testing.expect(std.mem.startsWith(u8, c.err, try std.fmt.bufPrint(&b, "agent: no runtime directory /run/user/{d} owned by ", .{uid})));
    }
}

// ---- workspace ----

/// The tree canon is tried over:
///   dir/sub/      directories
///   link -> dir   a relative symlink to one
///   file          a regular file
///   dangling -> nowhere
///   a:b/          a directory whose name has a ':'
///   noexec/       a directory with no search permission
fn makeTree(s: *Scratch, what: []const u8) !void {
    try s.make(what);
    var b: [4096]u8 = undefined;
    try mkdir(try s.at(&b, "dir"));
    try mkdir(try s.at(&b, "dir/sub"));
    try symlink("dir", try s.at(&b, "link"));
    try writeFile(try s.at(&b, "file"), "");
    try symlink("nowhere", try s.at(&b, "dangling"));
    try mkdir(try s.at(&b, "a:b"));
    const noexec = try s.at(&b, "noexec");
    try mkdir(noexec);
    try ok(sys.fchmodat(sys.AT.FDCWD, noexec, 0o600));
}

fn expectResolved(s: *const Scratch, given: []const u8, want: ?[]const u8) !void {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const got = try workspace.resolveDir(arena.allocator(), given);
    if (want) |w| {
        var wb: [4096]u8 = undefined;
        const full = if (w.len > 0 and w[0] == '/') w else try s.absAt(&wb, w);
        testing.expectEqualStrings(full, got orelse {
            std.debug.print("{s} did not resolve\n", .{given});
            return error.TestUnexpectedResult;
        }) catch |err| {
            std.debug.print("resolving {s}\n", .{given});
            return err;
        };
    } else if (got) |g| {
        std.debug.print("{s} resolved to {s}\n", .{ given, g });
        return error.TestUnexpectedResult;
    }
}

test "workspace.resolveDir: cd -P's physical path, relative to the working directory, with no chdir" {
    var s: Scratch = .{};
    try makeTree(&s, "canon");
    defer s.remove();
    var b: [4096]u8 = undefined;
    var cb: [4096]u8 = undefined;
    const before = std.mem.span(@as([*:0]u8, @ptrCast(std.posix.getcwd(&cb) catch return error.TestUnexpectedResult)));
    const live = fd.liveCount();

    try expectResolved(&s, try s.absAt(&b, "dir"), "dir");
    try expectResolved(&s, try s.absAt(&b, "dir/sub/"), "dir/sub");
    try expectResolved(&s, try s.absAt(&b, "link"), "dir");
    try expectResolved(&s, try s.absAt(&b, "link/sub/.."), "dir");
    try expectResolved(&s, try s.absAt(&b, "a:b"), "a:b");
    // Relative: from the working directory, as cd's chdir takes it.
    try expectResolved(&s, try s.at(&b, "link/sub"), "dir/sub");
    // "" is ./, the working directory itself (:94).
    var wb: [4096]u8 = undefined;
    const n = linux.readlink("/proc/self/cwd", &wb, wb.len);
    try expectResolved(&s, "", wb[0..n]);
    try expectResolved(&s, ".", wb[0..n]);
    try expectResolved(&s, "/", "/");
    // Not a directory cd could enter.
    try expectResolved(&s, try s.absAt(&b, "file"), null);
    try expectResolved(&s, try s.absAt(&b, "file/"), null);
    try expectResolved(&s, try s.absAt(&b, "missing"), null);
    try expectResolved(&s, try s.absAt(&b, "dangling"), null);
    try expectResolved(&s, "a\x00b", null);
    // No search permission on the directory itself: cd fails where an
    // O_PATH open would not. Root searches any directory.
    if (sys.geteuid() != 0) try expectResolved(&s, try s.absAt(&b, "noexec"), null);

    // Nothing left open, and the working directory where it was.
    try testing.expectEqual(live, fd.liveCount());
    var ab: [4096]u8 = undefined;
    try testing.expectEqualStrings(before, std.mem.span(@as([*:0]u8, @ptrCast(std.posix.getcwd(&ab) catch return error.TestUnexpectedResult))));
}

const Resolve = struct {
    raw: []const u8,
    dests: []const []const u8 = &.{},

    fn body(self: Resolve) !void {
        const ws = try workspace.resolve(std.heap.page_allocator, self.raw, self.dests);
        say("{s} {s}", .{ ws.path, @tagName(ws.mode) });
    }
};

test "workspace.resolve: the suffix, the physical path, and the wrapper's refusals" {
    var s: Scratch = .{};
    try makeTree(&s, "resolve");
    defer s.remove();
    var b: [4096]u8 = undefined;
    var r: [4096]u8 = undefined;
    var w: [4096]u8 = undefined;
    var c: Captured = .{};

    try capture(&c, Resolve{ .raw = try s.absAt(&b, "link") }, Resolve.body);
    try expectOk(&c);
    try testing.expectEqualStrings(try std.fmt.bufPrint(&w, "{s} rw", .{try s.absAt(&r, "dir")}), c.out);

    try capture(&c, Resolve{ .raw = try std.fmt.bufPrint(&b, "{s}/link:ro", .{s.abs}) }, Resolve.body);
    try expectOk(&c);
    try testing.expectEqualStrings(try std.fmt.bufPrint(&w, "{s} ro", .{try s.absAt(&r, "dir")}), c.out);

    try capture(&c, Resolve{ .raw = try std.fmt.bufPrint(&b, "{s}/dir/sub:rw", .{s.abs}) }, Resolve.body);
    try expectOk(&c);
    try testing.expectEqualStrings(try std.fmt.bufPrint(&w, "{s} rw", .{try s.absAt(&r, "dir/sub")}), c.out);

    // Not a directory: named without its suffix.
    try capture(&c, Resolve{ .raw = try std.fmt.bufPrint(&b, "{s}/file:ro", .{s.abs}) }, Resolve.body);
    try expectRefused(&c, try std.fmt.bufPrint(&w, "workspace is not a directory: {s}/file", .{s.abs}));
    try capture(&c, Resolve{ .raw = "/nonexistent-flong-workspace" }, Resolve.body);
    try expectRefused(&c, "workspace is not a directory: /nonexistent-flong-workspace");

    // refuse_path's three, on the resolved path.
    try capture(&c, Resolve{ .raw = try s.absAt(&b, "a:b") }, Resolve.body);
    try expectRefused(&c, try std.fmt.bufPrint(&w, "workspace contains ':' or a newline: {s}", .{try s.absAt(&r, "a:b")}));
    try capture(&c, Resolve{ .raw = "/" }, Resolve.body);
    try expectRefused(&c, "workspace resolves to /");
    const dest = try s.absAt(&r, "dir");
    try capture(&c, Resolve{ .raw = try s.absAt(&b, "link"), .dests = &.{ "/nix/store", dest } }, Resolve.body);
    try expectRefused(&c, try std.fmt.bufPrint(&w, "workspace {s} is where the declaration already mounts something", .{dest}));
}

test "workspace.current is the working directory's kernel name" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const here = try workspace.current(a);
    try testing.expectEqualStrings((try workspace.resolveDir(a, ".")).?, here);
}

// ---- cmd ----

const Run = struct {
    command: []const [:0]const u8,
    args: []const [*:0]const u8 = &.{},
    vars: []const cmd.Var = &.{},

    fn body(self: Run) !void {
        const a = std.heap.page_allocator;
        const status = try cmd.run(a, self.command, self.args, try cmd.environ(a, environ(), self.vars));
        say("status {d}\n", .{status});
    }
};

test "cmd.run: argv then the launcher's arguments, the environment given, the status" {
    const f = fakeCmd();
    var c: Captured = .{};
    try capture(&c, Run{
        .command = &.{ f, "show", "one word" },
        .args = &.{ "--", "a b", "" },
        .vars = &.{ .{ .name = "workspace", .value = "/w" }, .{ .name = "binds", .value = "/a:ro\n/b:rw" } },
    }, Run.body);
    try expectOk(&c);
    try testing.expect(std.mem.startsWith(u8, c.out, "arg one word\narg --\narg a b\narg \n"));
    try testing.expect(std.mem.indexOf(u8, c.out, "\nenv workspace=/w\n") != null);
    try testing.expect(std.mem.indexOf(u8, c.out, "\nenv binds=/a:ro\n/b:rw\n") != null);
    try testing.expect(std.mem.endsWith(u8, c.out, "status 0\n"));

    try capture(&c, Run{ .command = &.{ f, "fail", "3" }, .args = &.{"ignored"} }, Run.body);
    try expectOk(&c);
    try testing.expectEqualStrings("status 3\n", c.out);
}

test "cmd.run: a program that cannot start says so under the prefix and is 127; a relative one is the working directory's" {
    var c: Captured = .{};
    try capture(&c, Run{ .command = &.{"/nonexistent-flong/cmd"} }, Run.body);
    try expectOk(&c);
    try testing.expectEqualStrings("status 127\n", c.out);
    try testing.expectEqualStrings("agent: exec /nonexistent-flong/cmd: No such file or directory\n", c.err);
    // A bare name is never looked up on PATH.
    try capture(&c, Run{ .command = &.{"true"} }, Run.body);
    try testing.expectEqualStrings("status 127\n", c.out);
    try testing.expectEqualStrings("agent: exec true: No such file or directory\n", c.err);
    try capture(&c, Run{ .command = &.{} }, Run.body);
    try expectRefused(&c, "a command with no program");
}

const Pass = struct {
    commands: []const cmd.Command,

    fn body(self: Pass) !void {
        try cmd.pass(std.heap.page_allocator, self.commands, &.{"x"}, envp());
    }
};

test "cmd.pass: each in order, the first failure ends it silently, exit 1" {
    const f = fakeCmd();
    var c: Captured = .{};
    try capture(&c, Pass{ .commands = &.{ &.{ f, "print", "a" }, &.{ f, "print", "b" } } }, Pass.body);
    try expectOk(&c);
    try testing.expectEqualStrings("ab", c.out);
    try capture(&c, Pass{ .commands = &.{ &.{ f, "print", "a" }, &.{ f, "fail", "4" }, &.{ f, "print", "c" } } }, Pass.body);
    try testing.expectEqual(@as(u8, 1), c.status);
    try testing.expectEqualStrings("a", c.out);
    try testing.expectEqualStrings("", c.err);
    try capture(&c, Pass{ .commands = &.{} }, Pass.body);
    try expectOk(&c);
}

const Capture = struct {
    command: []const [:0]const u8,
    limit: usize = cmd.output_max,

    fn body(self: Capture) !void {
        const got = try cmd.capture(std.heap.page_allocator, self.command, &.{"launcher-arg"}, envp(), self.limit);
        say("status {d}\n", .{got.status});
        _ = fd.Stdio.out.writeAll(got.out);
    }
};

test "cmd.capture: stdout whole and its status; past the limit refused" {
    const f = fakeCmd();
    var c: Captured = .{};
    try capture(&c, Capture{ .command = &.{ f, "print", "/w\\0x\\n\\n" } }, Capture.body);
    try expectOk(&c);
    try testing.expectEqualStrings("status 0\n/w\x00x\n\n", c.out);
    try capture(&c, Capture{ .command = &.{ f, "show" } }, Capture.body);
    try testing.expect(std.mem.startsWith(u8, c.out, "status 0\narg launcher-arg\n"));
    try capture(&c, Capture{ .command = &.{ f, "fail", "5" } }, Capture.body);
    try testing.expectEqualStrings("status 5\n", c.out);
    // Exactly the limit passes; one more does not.
    try capture(&c, Capture{ .command = &.{ f, "flood", "10" }, .limit = 10 }, Capture.body);
    try expectOk(&c);
    try capture(&c, Capture{ .command = &.{ f, "flood", "100000" }, .limit = 10 }, Capture.body);
    var b: [4200]u8 = undefined;
    try expectRefused(&c, try std.fmt.bufPrint(&b, "the output of {s} is longer than 10 bytes", .{f}));
}

const OutputOf = struct {
    commands: []const cmd.Command,

    fn body(self: OutputOf) !void {
        const got = try cmd.outputOf(std.heap.page_allocator, self.commands, &.{}, envp());
        _ = fd.Stdio.out.writeAll(got);
    }
};

test "cmd.outputOf: the stdouts concatenated in order; a failure ends it, exit 1" {
    const f = fakeCmd();
    var c: Captured = .{};
    try capture(&c, OutputOf{ .commands = &.{ &.{ f, "print", "/a\\n" }, &.{ f, "print", "/b:rw" }, &.{ f, "print", "\\n/c" } } }, OutputOf.body);
    try expectOk(&c);
    try testing.expectEqualStrings("/a\n/b:rw\n/c", c.out);
    try capture(&c, OutputOf{ .commands = &.{ &.{ f, "print", "/a" }, &.{ f, "fail", "2" } } }, OutputOf.body);
    try testing.expectEqual(@as(u8, 1), c.status);
    try testing.expectEqualStrings("", c.out);
    try testing.expectEqualStrings("", c.err);
    // The bound is over all of them.
    try capture(&c, OutputOf{ .commands = &.{ &.{ f, "flood", "1048000" }, &.{ f, "flood", "1000" } } }, OutputOf.body);
    var b: [4200]u8 = undefined;
    try expectRefused(&c, try std.fmt.bufPrint(&b, "the output of {s} is longer than 576 bytes", .{f}));
}

// ---- binds ----

const Parse = struct {
    raw: []const u8,
    ws: workspace.Workspace,
    dests: []const []const u8 = &.{},

    fn body(self: Parse) !void {
        const a = std.heap.page_allocator;
        const got = try binds.parse(a, try a.dupe(u8, self.raw), self.ws, self.dests);
        say("{s}\n{s}\n", .{ @tagName(got.workspace_mode), got.text });
        for (got.list) |b| say("{s} {s}\n", .{ b.path, @tagName(b.mode) });
    }
};

test "binds.parse: PATH, PATH:ro, PATH:rw; resolved, merged rw-wins, the workspace's folded into it" {
    var s: Scratch = .{};
    try makeTree(&s, "binds");
    defer s.remove();
    var b: [6][4096]u8 = undefined;
    try mkdir(try s.absAt(&b[5], "other"));
    const dir = try s.absAt(&b[0], "dir");
    const sub = try s.absAt(&b[1], "dir/sub");
    const other = try s.absAt(&b[2], "other");
    const raw = try std.fmt.bufPrint(&b[3],
        \\{s}/dir/sub
        \\
        \\{s}/link:ro
        \\{s}/other:rw
        \\{s}/dir:rw
        \\{s}/other
        \\{s}/link/sub/../sub:rw
        \\
        \\
    , .{ s.abs, s.abs, s.abs, s.abs, s.abs, s.abs });
    var c: Captured = .{};
    // The workspace is `other`, read-only: `other:rw` makes it writable,
    // and it is not a bind of its own.
    try capture(&c, Parse{ .raw = raw, .ws = .{ .path = other, .mode = .ro } }, Parse.body);
    try expectOk(&c);
    var w: [4096]u8 = undefined;
    try testing.expectEqualStrings(try std.fmt.bufPrint(&w, "rw\n{s}:rw\n{s}:rw\n{s} rw\n{s} rw\n", .{ sub, dir, sub, dir }), c.out);

    // A workspace bind that says ro leaves it as it was.
    const ro = try std.fmt.bufPrint(&b[4], "{s}/other:ro\n{s}/dir\n", .{ s.abs, s.abs });
    try capture(&c, Parse{ .raw = ro, .ws = .{ .path = other, .mode = .ro } }, Parse.body);
    try expectOk(&c);
    try testing.expectEqualStrings(try std.fmt.bufPrint(&w, "ro\n{s}:ro\n{s} ro\n", .{ dir, dir }), c.out);

    // Nothing, or blank lines only: no bind, $binds empty.
    try capture(&c, Parse{ .raw = "\n\n", .ws = .{ .path = other, .mode = .rw } }, Parse.body);
    try expectOk(&c);
    try testing.expectEqualStrings("rw\n\n", c.out);
}

test "binds.parse: the wrapper's refusals, the path named without its suffix" {
    var s: Scratch = .{};
    try makeTree(&s, "bindsno");
    defer s.remove();
    var b: [4096]u8 = undefined;
    var w: [4096]u8 = undefined;
    var r: [4096]u8 = undefined;
    const ws: workspace.Workspace = .{ .path = "/nonexistent-flong-ws", .mode = .rw };
    var c: Captured = .{};

    try capture(&c, Parse{ .raw = try std.fmt.bufPrint(&b, "{s}/dir\n{s}/file:rw\n", .{ s.abs, s.abs }), .ws = ws }, Parse.body);
    try expectRefused(&c, try std.fmt.bufPrint(&w, "bind is not a directory: {s}/file", .{s.abs}));
    try capture(&c, Parse{ .raw = try std.fmt.bufPrint(&b, "{s}/a:b:ro", .{s.abs}), .ws = ws }, Parse.body);
    try expectRefused(&c, try std.fmt.bufPrint(&w, "bind contains ':' or a newline: {s}", .{try s.absAt(&r, "a:b")}));
    try capture(&c, Parse{ .raw = "/", .ws = ws }, Parse.body);
    try expectRefused(&c, "bind resolves to /");
    const dest = try s.absAt(&r, "dir");
    try capture(&c, Parse{ .raw = try std.fmt.bufPrint(&b, "{s}/link:ro", .{s.abs}), .ws = ws, .dests = &.{dest} }, Parse.body);
    try expectRefused(&c, try std.fmt.bufPrint(&w, "bind {s} is where the declaration already mounts something", .{dest}));
}

// ---- identity ----

const Identity = struct {
    prepared: []const u8,
    user: []const u8 = "agent",
    cuid: u32 = 1000,
    cgid: u32 = 100,

    fn body(self: Identity) !void {
        const a = std.heap.page_allocator;
        switch (try identity.open(a, self.prepared)) {
            .swept => say("swept\n", .{}),
            .files => |files| {
                const id = try identity.of(a, files, self.prepared, self.user, self.cuid, self.cgid);
                say("{s} {s} {s} {s}", .{ id.uid, id.gid, id.home, id.shell });
                for (id.groups) |g| say(" {s}", .{g});
            },
        }
    }
};

test "identity: the user's entry and groups; swept when $P went; the wrapper's refusals" {
    var s: Scratch = .{};
    try s.make("identity");
    defer s.remove();
    var b: [4][4096]u8 = undefined;
    const p = try s.absAt(&b[0], "prepared");
    try mkdir(p);
    try mkdir(try s.absAt(&b[1], "prepared/etc"));
    try writeFile(try s.absAt(&b[1], "prepared/etc/passwd"), "root:x:0:0::/root:/bin/sh\nagent:x:1000:100::/home/agent:/run/current-system/sw/bin/bash\nodd:x:1000:101::/home/odd:/bin/sh\n");
    try writeFile(try s.absAt(&b[1], "prepared/etc/group"), "users:x:100:agent\nwheel:x:1:agent,odd\nkvm:x:302:agent\n");

    var c: Captured = .{};
    try capture(&c, Identity{ .prepared = p }, Identity.body);
    try expectOk(&c);
    try testing.expectEqualStrings("1000 100 /home/agent /run/current-system/sw/bin/bash 100 1 302", c.out);

    try capture(&c, Identity{ .prepared = p, .user = "nobody" }, Identity.body);
    var w: [4096]u8 = undefined;
    try expectRefused(&c, try std.fmt.bufPrint(&w, "nobody is not a user in {s}/etc/passwd", .{p}));
    try capture(&c, Identity{ .prepared = p, .user = "odd" }, Identity.body);
    try expectRefused(&c, "odd is 1000:101 in the prepared root, and the declaration says 1000:100");
    try capture(&c, Identity{ .prepared = p, .cuid = 1001 }, Identity.body);
    try expectRefused(&c, "agent is 1000:100 in the prepared root, and the declaration says 1001:100");

    // $P gone: swept. $P there without its group: refused.
    try capture(&c, Identity{ .prepared = try s.absAt(&b[2], "gone") }, Identity.body);
    try expectOk(&c);
    try testing.expectEqualStrings("swept\n", c.out);
    try ok(sys.unlinkat(sys.AT.FDCWD, try s.absAt(&b[1], "prepared/etc/group"), 0));
    try capture(&c, Identity{ .prepared = p }, Identity.body);
    try expectRefused(&c, try std.fmt.bufPrint(&w, "cannot read {s}/etc/passwd and {s}/etc/group", .{ p, p }));
}

// ---- prepare ----

const Ensure = struct {
    state: [:0]const u8,
    paths: prepare.Paths,
    /// the fake tool's $FLONG_FAKE_LOG
    log: []const u8,
    closure: [:0]const u8 = "/nix/store/closure",
    /// report whether the cache is held shared, from another open
    probe_lock: bool = false,

    const maps = [_][:0]const u8{ "--map-users=0:100000:1000", "--map-groups=0:100:1" };

    fn body(self: Ensure) !void {
        const a = std.heap.page_allocator;
        const env = try cmd.environ(a, environ(), &.{.{ .name = "FLONG_FAKE_LOG", .value = self.log }});
        const tool: prepare.Tool = .{ .path = fakeCmd(), .map_args = &maps, .envp = env };
        const got = try prepare.ensure(a, self.state, "agent", self.paths, tool, self.closure, "agent");
        switch (got) {
            .warm => say("warm\n", .{}),
            .swept => say("swept\n", .{}),
            .cold => |h| {
                say("cold\n", .{});
                if (self.probe_lock) {
                    const other = try opened(fd.openDir(fd.cwd, self.paths.cache));
                    defer other.close();
                    const ex = other.flock(sys.LOCK.EX | sys.LOCK.NB);
                    const sh = other.flock(sys.LOCK.SH | sys.LOCK.NB);
                    say("ex {s} sh {s}\n", .{ if (ex == .ok) "taken" else "refused", if (sh == .ok) "taken" else "refused" });
                }
                h.close();
            },
        }
    }
};

test "prepare.ensure: cold makes the state 0700 and the cache, runs the tool once, hands the lock on, collects superseded caches" {
    var s: Scratch = .{};
    try s.make("prepare");
    defer s.remove();
    var b: [8][4096]u8 = undefined;
    const state = try s.absAt(&b[0], "state");
    const log = try s.absAt(&b[1], "log");
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const p = try prepare.paths(arena.allocator(), state, "agent", "0123abcd", "89abcdef", 1000, 100, "100000", "100000", 100);

    // A superseded generation, one another launch holds (the fake's
    // "stuck"), the trash a killed collection left, and neighbours that
    // are not this container's or these maps'.
    try mkdir(state);
    for ([_][]const u8{
        "agent-00000000-89abcdef-1000.100.100000.100000.100",
        "agent-stuck000-89abcdef-1000.100.100000.100000.100",
        ".trash.agent-x.1",
        "agent-x-0123abcd-89abcdef-1000.100.100000.100000.100",
        "agent-00000000-89abcdef-1000.100.100000.100000.101",
        "other-00000000-89abcdef-1000.100.100000.100000.100",
    }) |name| try mkdir(try std.fmt.bufPrintZ(&b[2], "{s}/{s}", .{ state, name }));
    // A file of the pattern's shape is not a directory: not collected.
    try writeFile(try std.fmt.bufPrintZ(&b[2], "{s}/agent-11111111-89abcdef-1000.100.100000.100000.100", .{state}), "");
    try ok(sys.fchmodat(sys.AT.FDCWD, state, 0o755));

    var c: Captured = .{};
    try capture(&c, Ensure{ .state = state, .paths = p, .log = log, .probe_lock = true }, Ensure.body);
    try expectOk(&c);
    try testing.expectEqualStrings("cold\nex refused sh taken\n", c.out);
    var w: [4096]u8 = undefined;
    try testing.expectEqualStrings(try std.fmt.bufPrint(&w, "agent: could not remove {s}/agent-stuck000-89abcdef-1000.100.100000.100000.100, kept\n", .{state}), c.err);
    var lb: [8192]u8 = undefined;
    try testing.expectEqualStrings(try std.fmt.bufPrint(&w,
        \\prepare --map-users=0:100000:1000 --map-groups=0:100:1 -- {s} /nix/store/closure agent
        \\gc --map-users=0:100000:1000 --map-groups=0:100:1 -- {s}/agent-00000000-89abcdef-1000.100.100000.100000.100
        \\gc --map-users=0:100000:1000 --map-groups=0:100:1 -- {s}/agent-stuck000-89abcdef-1000.100.100000.100000.100
        \\gc --map-users=0:100000:1000 --map-groups=0:100:1 -- {s}/.trash.agent-x.1
        \\
    , .{ p.cache, state, state, state }), try readFile(log, &lb));
    // The state directory's mode is the caller's to keep: made already, it
    // is left as it was. The cache is there with its prepared root and
    // .prepare.lock.
    const st = switch (sys.fstatat(sys.AT.FDCWD, state, 0)) {
        .ok => |x| x,
        .err => return error.TestUnexpectedResult,
    };
    try testing.expectEqual(@as(u32, 0o755), st.mode & 0o777);
    try ok(sys.fstatat(sys.AT.FDCWD, p.prepared, 0));
    try ok(sys.fstatat(sys.AT.FDCWD, try std.fmt.bufPrintZ(&b[3], "{s}/.prepare.lock", .{p.cache}), 0));

    // Warm: nothing run, nothing opened.
    try writeFile(log, "");
    try capture(&c, Ensure{ .state = state, .paths = p, .log = log }, Ensure.body);
    try expectOk(&c);
    try testing.expectEqualStrings("warm\n", c.out);
    try testing.expectEqualStrings("", try readFile(log, &lb));
}

test "prepare.ensure: a new state directory is 0700; a failed prepare is the wrapper's refusal" {
    var s: Scratch = .{};
    try s.make("prepfail");
    defer s.remove();
    var b: [4][4096]u8 = undefined;
    const state = try s.absAt(&b[0], "state");
    const log = try s.absAt(&b[1], "log");
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const p = try prepare.paths(arena.allocator(), state, "agent", "0123abcd", "89abcdef", 0, 0, "100000", "100000", 100);

    const old = sys.umask(0o022);
    defer _ = sys.umask(old);
    var c: Captured = .{};
    try capture(&c, Ensure{ .state = state, .paths = p, .log = log, .closure = "fail" }, Ensure.body);
    var w: [4096]u8 = undefined;
    try expectRefused(&c, try std.fmt.bufPrint(&w, "preparing the root for agent failed, see {s}/.prepare.*.log", .{p.cache}));
    const st = switch (sys.fstatat(sys.AT.FDCWD, state, 0)) {
        .ok => |x| x,
        .err => return error.TestUnexpectedResult,
    };
    try testing.expectEqual(@as(u32, 0o700), st.mode & 0o777);

    // A state directory that cannot be made: its parent is a file.
    try writeFile(try s.absAt(&b[3], "afile"), "");
    const bad = try s.absAt(&b[2], "afile/state");
    const pb = try prepare.paths(arena.allocator(), bad, "agent", "0123abcd", "89abcdef", 0, 0, "100000", "100000", 100);
    try capture(&c, Ensure{ .state = bad, .paths = pb, .log = log }, Ensure.body);
    try expectRefused(&c, try std.fmt.bufPrint(&w, "cannot make {s}", .{bad}));
}

/// A sweep of a superseded cache (as prologue_test's): holds the cache's
/// lock exclusively, says so on `ready`, waits until a lock request on it
/// is blocked, renames the cache away and exits, which lets the lock go.
const Sweep = struct {
    cache: [:0]const u8,
    moved: [:0]const u8,
    ready: fd.Fd(.pipe_w),

    fn body(self: Sweep) noreturn {
        const rc = linux.open(self.cache, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
        if (linux.E.init(rc) != .SUCCESS) proc.exit(10);
        const d: i32 = @intCast(rc);
        if (linux.E.init(linux.flock(d, sys.LOCK.EX)) != .SUCCESS) proc.exit(11);
        var st: linux.Stat = undefined;
        if (linux.E.init(linux.fstat(d, &st)) != .SUCCESS) proc.exit(12);
        if (self.ready.write("l") != .ok) proc.exit(13);
        self.ready.close();
        if (!awaitBlocked(st.ino)) proc.exit(14);
        if (linux.E.init(linux.rename(self.cache, self.moved)) != .SUCCESS) proc.exit(15);
        proc.exit(0);
    }

    fn awaitBlocked(ino: u64) bool {
        var needle_buf: [32]u8 = undefined;
        const needle = std.fmt.bufPrint(&needle_buf, ":{d} ", .{ino}) catch return false;
        var tries: usize = 0;
        while (tries < 1000) : (tries += 1) {
            var buf: [65536]u8 = undefined;
            const rc = linux.open("/proc/locks", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
            if (linux.E.init(rc) != .SUCCESS) return false;
            const f: i32 = @intCast(rc);
            var n: usize = 0;
            while (n < buf.len) {
                const got = linux.read(f, buf[n..].ptr, buf.len - n);
                if (linux.E.init(got) != .SUCCESS or got == 0) break;
                n += got;
            }
            _ = linux.close(f);
            var lines = std.mem.splitScalar(u8, buf[0..n], '\n');
            while (lines.next()) |l| {
                if (std.mem.indexOf(u8, l, "->") != null and std.mem.indexOf(u8, l, needle) != null) return true;
            }
            const ts: linux.timespec = .{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
            _ = linux.nanosleep(&ts, null);
        }
        return false;
    }
};

test "prepare.ensure: swept when a sweep renamed the cache away while it waited for the lock" {
    var s: Scratch = .{};
    try s.make("prepswept");
    defer s.remove();
    var b: [4][4096]u8 = undefined;
    const state = try s.absAt(&b[0], "state");
    try mkdir(state);
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const p = try prepare.paths(arena.allocator(), state, "agent", "0123abcd", "89abcdef", 1000, 100, "100000", "100000", 100);
    try mkdir(p.cache);

    const pipe = try opened(fd.pipe());
    defer pipe.r.close();
    const sweep = Sweep{ .cache = p.cache, .moved = try s.absAt(&b[1], "moved"), .ready = pipe.w };
    const child = proc.fork(.{ .keep = &.{pipe.w.any()} }, sweep, Sweep.body) catch |err| {
        pipe.w.close();
        return err;
    };
    pipe.w.close();
    var one: [1]u8 = undefined;
    try testing.expectEqual(sys.Result(usize){ .ok = 1 }, pipe.r.read(&one));

    // The pipe's read end and the sweep's pidfd, which its await closes.
    const before = fd.liveCount() - 1;
    const tool: prepare.Tool = .{ .path = fakeCmd(), .map_args = &Ensure.maps, .envp = envp() };
    const got = prepare.ensure(arena.allocator(), state, "agent", p, tool, "/nix/store/closure", "agent") catch |err| {
        child.reapNow(.kill);
        return err;
    };
    try testing.expectEqual(@as(u8, 0), try child.await());
    try testing.expect(got == .swept);
    // The swept cache's descriptor went with it.
    try testing.expectEqual(before, fd.liveCount());
}

// ---- relaunch ----

const Relaunch = struct {
    path: [:0]const u8,

    fn body(self: Relaunch) !void {
        const got = try cmd.capture(std.heap.page_allocator, &.{ self.path, "relaunch", "2" }, &.{}, envp(), 4096);
        say("status {d}\n", .{got.status});
        _ = fd.Stdio.out.writeAll(got.out);
    }
};

test "prologue.relaunchSelf execs this binary again, argv[0] untouched, silently" {
    // flong-fake-cmd run by another name, as a declaration's symlink runs
    // flong, relaunches itself twice: argv[0] stays the link's name, and
    // what runs is /proc/self/exe, the binary.
    var s: Scratch = .{};
    try s.make("relaunch");
    defer s.remove();
    var b: [4096]u8 = undefined;
    const link = try s.absAt(&b, "agent");
    try symlink(fakeCmd(), link);
    var c: Captured = .{};
    try capture(&c, Relaunch{ .path = link }, Relaunch.body);
    try expectOk(&c);
    var w: [8192]u8 = undefined;
    try testing.expectEqualStrings(try std.fmt.bufPrint(&w, "status 0\nargv0 {s}\nexe {s}\n", .{ link, fakeCmd() }), c.out);
    try testing.expectEqualStrings("", c.err);
}
