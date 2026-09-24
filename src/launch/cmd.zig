//! launch/cmd.zig: a declaration's command, run as the caller, for
//! `flong launch DECL.zon`'s prologue (DESIGN.md, "Data is data; shell
//! is for what only launch knows"): the workspace, binds, guard and
//! seccompPolicy commands.
//!
//! The wrapper ran each snippet as `"$BASH" -euo pipefail -c "$1" flong
//! "${launcher_args[@]}"` (rootless-wrapper.bash:46-50). A command is an
//! argv list instead, and flong runs no shell: the program is argv[0], its
//! arguments the rest of the command's argv and then the launcher's own
//! arguments (DESIGN.md, "The declaration": commands, not snippets). It
//! runs as the caller, who is already who this runs as, in the caller's
//! working directory, with the caller's stdin and stderr, and an
//! environment built by `environ`: the caller's, with the names the wrapper
//! exported set (XDG_RUNTIME_DIR, workspace, workspace_mode, binds,
//! machine, as each call site has them). proc.Spawn starts it: every
//! signal's default and an empty mask, and no descriptor of flong's but its
//! stdio.
//!
//! argv[0] is given to execve as it is: no PATH search. Nix writes it
//! absolute. A relative one is found from the caller's working directory,
//! the one the command runs in, as execve resolves it; a bare name is
//! therefore a file in that directory, never a program on PATH. A command
//! that cannot start says why on its stderr, "<name>: exec <argv0>:
//! <strerror>", and has status 127, as a shell's would.
//!
//! A command's failure is its own to explain, as `|| exit 1` left it
//! (:124, 146, 187, 203): `pass` and `outputOf` give error.Reported for a
//! status other than 0 without a word more, and the prologue exits 1.

const std = @import("std");
const sys = @import("sys");
const fdt = @import("fd");
const msg = @import("msg");
const sig = @import("sig");
const proc = @import("proc");

const Allocator = std.mem.Allocator;

/// A command: a program and its arguments (decl.zig's Command).
pub const Command = []const [:0]const u8;

/// An environment for execve: its strings, then a null.
pub const Envp = [*:null]const ?[*:0]const u8;

/// A name the wrapper exported, and its value.
pub const Var = struct { name: []const u8, value: []const u8 };

/// The most a command may print on stdout, all its output together: the
/// wrapper's $(...) had no bound, and a launch must not grow without one.
/// 1 MiB, the declaration's own cap.
pub const output_max = 1 << 20;

/// The caller's environment `base` (main's environ) with each of `vars`
/// set, in order: the first entry named `<name>=` is replaced in place and
/// any later one of that name dropped, so a child bash sees the value too
/// (bash takes the last of a name, glibc's getenv the first); a name with
/// no entry is appended. An entry with no '=' names nothing. The strings
/// and the array are `gpa`'s (the prologue's arena).
pub fn environ(gpa: Allocator, base: []const [*:0]const u8, vars: []const Var) msg.Error!Envp {
    return environAlloc(gpa, base, vars) catch return oom();
}

fn environAlloc(gpa: Allocator, base: []const [*:0]const u8, vars: []const Var) Allocator.Error!Envp {
    var list: std.ArrayList(?[*:0]const u8) = try .initCapacity(gpa, base.len + vars.len + 1);
    for (base) |e| list.appendAssumeCapacity(e);
    for (vars) |v| {
        const entry = (try std.fmt.allocPrintSentinel(gpa, "{s}={s}", .{ v.name, v.value }, 0)).ptr;
        var set = false;
        var i: usize = 0;
        while (i < list.items.len) {
            if (!named(list.items[i].?, v.name)) {
                i += 1;
            } else if (!set) {
                list.items[i] = entry;
                set = true;
                i += 1;
            } else {
                _ = list.orderedRemove(i);
            }
        }
        if (!set) list.appendAssumeCapacity(entry);
    }
    list.appendAssumeCapacity(null);
    return @ptrCast(list.items.ptr);
}

/// The value of the first `<name>=` entry of `environ`, as getenv(3)
/// finds it; null when there is none.
pub fn getenv(env: []const [*:0]const u8, name: []const u8) ?[]const u8 {
    for (env) |e| {
        if (named(e, name)) return std.mem.span(e)[name.len + 1 ..];
    }
    return null;
}

/// Whether `entry` is `<name>=...`.
fn named(entry: [*:0]const u8, name: []const u8) bool {
    const s = std.mem.span(entry);
    return s.len > name.len and std.mem.startsWith(u8, s, name) and s[name.len] == '=';
}

/// The Spawn of `command` with `args` after its own argv, in `envp`; an
/// empty command, which a declaration's check refuses, is refused here
/// too.
fn prepare(gpa: Allocator, command: Command, args: []const [*:0]const u8, envp: Envp) msg.Error!proc.Spawn {
    if (command.len == 0) return msg.refuse("a command with no program", .{});
    var sp = proc.Spawn.init(gpa, command[0].ptr) catch return oom();
    for (command[1..]) |w| sp.arg(w.ptr) catch return oom();
    for (args) |a| sp.arg(a) catch return oom();
    sp.envp = envp;
    return sp;
}

/// Runs `command` ++ `args` in `envp` with the caller's stdio and waits
/// for it: its status, 128+n for a signal. A terminating signal on the
/// launch's signalfd, when there is one, ends the wait (error.Aborted),
/// and the command is killed.
pub fn run(gpa: Allocator, command: Command, args: []const [*:0]const u8, envp: Envp) sig.Error!u8 {
    var sp = try prepare(gpa, command, args, envp);
    const child = try sp.start();
    return child.await() catch |err| {
        child.reapNow(.kill);
        return err;
    };
}

/// Each of `commands` in order, as `run`, until one fails: the guard
/// (:186-188), each of which must pass. A status other than 0 is
/// error.Reported, the command having said why.
pub fn pass(gpa: Allocator, commands: []const Command, args: []const [*:0]const u8, envp: Envp) sig.Error!void {
    for (commands) |c| {
        if (try run(gpa, c, args, envp) != 0) return error.Reported;
    }
}

/// What a command printed, and its status.
pub const Output = struct {
    status: u8,
    /// its stdout, whole, in `gpa`
    out: []u8,
};

/// Runs `command` ++ `args` in `envp` with its stdout on a pipe, reads the
/// pipe to its end and waits for the command, as $(...) does. Output past
/// `limit` bytes is refused ("the output of <argv0> is longer than
/// <limit> bytes") and the command killed. A terminating signal ends the
/// wait (error.Aborted) and kills the command.
pub fn capture(gpa: Allocator, command: Command, args: []const [*:0]const u8, envp: Envp, limit: usize) sig.Error!Output {
    return captureFrom(gpa, command, args, envp, limit, null);
}

/// `capture` with `input` on the command's stdin, as `<<<"$text"` gives
/// it (a here-string: the text and a newline, which the caller includes):
/// in a memfd, read from its start, so no write waits on the command
/// reading.
pub fn captureInput(gpa: Allocator, command: Command, envp: Envp, input: []const u8, limit: usize) sig.Error!Output {
    const f = try msg.check(fdt.memfd("stdin"), "memfd_create", .{});
    defer f.close();
    const n = try msg.check(f.pwrite(input, 0), "writing the input of {s}", .{command[0]});
    if (n != input.len) return msg.fail(.IO, "writing the input of {s}", .{command[0]});
    return captureFrom(gpa, command, &.{}, envp, limit, f);
}

fn captureFrom(gpa: Allocator, command: Command, args: []const [*:0]const u8, envp: Envp, limit: usize, stdin: ?fdt.File) sig.Error!Output {
    var sp = try prepare(gpa, command, args, envp);
    const p = try msg.check(fdt.pipe(), "pipe", .{});
    sp.stdio[1] = p.w.any();
    if (stdin) |f| sp.stdio[0] = f.any();
    const child = sp.start() catch |err| {
        p.r.close();
        p.w.close();
        return err;
    };
    p.w.close();
    const out = drain(gpa, p.r, command[0], limit) catch |err| {
        p.r.close();
        child.reapNow(.kill);
        return err;
    };
    p.r.close();
    const status = child.await() catch |err| {
        child.reapNow(.kill);
        return err;
    };
    return .{ .status = status, .out = out };
}

/// `r` read to its end, each read after a wait a terminating signal can
/// end, into `gpa`; more than `limit` bytes is refused.
fn drain(gpa: Allocator, r: fdt.Fd(.pipe_r), argv0: []const u8, limit: usize) sig.Error![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    while (true) {
        try sig.awaitFd(r, sys.POLL.IN);
        buf.ensureUnusedCapacity(gpa, 4096) catch return oom();
        // At most one byte past the limit, to know it was passed.
        const room = buf.unusedCapacitySlice();
        const want = @min(room.len, limit + 1 - buf.items.len);
        const n = try msg.check(r.read(room[0..want]), "reading the output of {s}", .{argv0});
        if (n == 0) return buf.items;
        buf.items.len += n;
        if (buf.items.len > limit)
            return msg.refuse("the output of {s} is longer than {d} bytes", .{ argv0, limit });
    }
}

/// Each of `commands` in order, as `capture` with `output_max` over all of
/// them, their stdouts concatenated: the binds and seccompPolicy commands
/// (:146, 203). The first that fails ends it: error.Reported, the command
/// having said why.
pub fn outputOf(gpa: Allocator, commands: []const Command, args: []const [*:0]const u8, envp: Envp) sig.Error![]u8 {
    var all: std.ArrayList(u8) = .empty;
    for (commands) |c| {
        const o = try capture(gpa, c, args, envp, output_max - all.items.len);
        if (o.status != 0) return error.Reported;
        all.appendSlice(gpa, o.out) catch return oom();
    }
    return all.items;
}

/// What $(...) makes of a command's output: its NULs dropped (bash drops
/// them, saying so on stderr, which this does not) and its trailing
/// newlines removed. A slice of `out`, which it rewrites in place.
pub fn substitute(out: []u8) []const u8 {
    var n: usize = 0;
    for (out) |b| {
        if (b == 0) continue;
        out[n] = b;
        n += 1;
    }
    while (n > 0 and out[n - 1] == '\n') n -= 1;
    return out[0..n];
}

fn oom() msg.Error {
    return msg.fail(.NOMEM, "malloc", .{});
}

// ---- tests ----

const testing = std.testing;

fn expectEnv(expected: []const []const u8, got: Envp) !void {
    var i: usize = 0;
    while (got[i]) |e| : (i += 1) {
        if (i >= expected.len) return error.TestUnexpectedResult;
        try testing.expectEqualStrings(expected[i], std.mem.span(e));
    }
    try testing.expectEqual(expected.len, i);
}

test "environ sets each name in order: the first entry replaced, later ones dropped, a new one appended" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const base = [_][*:0]const u8{ "PATH=/bin", "binds=old", "HOME=/h", "noequals", "binds=older", "bindsX=y", "binds" };
    const got = try environ(a, &base, &.{
        .{ .name = "binds", .value = "/a:ro\n/b:rw" },
        .{ .name = "workspace", .value = "/w" },
        .{ .name = "XDG_RUNTIME_DIR", .value = "/run/user/1000" },
    });
    try expectEnv(&.{ "PATH=/bin", "binds=/a:ro\n/b:rw", "HOME=/h", "noequals", "bindsX=y", "binds", "workspace=/w", "XDG_RUNTIME_DIR=/run/user/1000" }, got);
    // An empty value is set, and a name set twice takes the second.
    const twice = try environ(a, &.{}, &.{ .{ .name = "x", .value = "1" }, .{ .name = "x", .value = "" } });
    try expectEnv(&.{"x="}, twice);
    try expectEnv(&.{}, try environ(a, &.{}, &.{}));
}

test "getenv takes the first entry of a name" {
    const env = [_][*:0]const u8{ "TERMX=1", "TERM=xterm", "TERM=vt100", "noequals", "EMPTY=" };
    try testing.expectEqualStrings("xterm", getenv(&env, "TERM").?);
    try testing.expectEqualStrings("", getenv(&env, "EMPTY").?);
    try testing.expectEqual(null, getenv(&env, "COLORTERM"));
    try testing.expectEqual(null, getenv(&env, "noequals"));
}

test "substitute drops NULs and the trailing newlines, as $(...) does" {
    const cases = [_][2][]const u8{
        .{ "/w\n", "/w" },
        .{ "/w\n\n\n", "/w" },
        .{ "/w", "/w" },
        .{ "\n", "" },
        .{ "", "" },
        .{ "a\n\nb\n", "a\n\nb" },
        .{ "a\x00b\n\x00\n", "ab" },
        .{ "\x00", "" },
        .{ "a\r\n", "a\r" },
        .{ "\na", "\na" },
    };
    for (cases) |c| {
        var buf: [16]u8 = undefined;
        @memcpy(buf[0..c[0].len], c[0]);
        try testing.expectEqualStrings(c[1], substitute(buf[0..c[0].len]));
    }
}
