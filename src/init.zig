//! flong init (DESIGN.md, "Files"): launcher/flong-init.c, line by line;
//! the C was deleted in phase 3 (b), and its line numbers here are those of
//! db5fdeb. `main` is the subcommand's, which src/main.zig calls.
//!
//! The first program inside the session: bwrap execs it as pid 1
//! (--as-pid-1), so it runs before anything of the payload's and is the
//! gate; bwrap's own --block-fd is fail-open, this one is fail-closed.
//!
//!   flong init GATE READY GROUPS TTY TRACE DIR -- COMMAND...
//!
//! GATE and READY are descriptor numbers, GROUPS is comma-separated gids or
//! "-", TTY is "ctty" or "-", TRACE is "trace" or "-", DIR is absolute. The
//! protocol is argv, not the environment, so the wrapper's --clearenv cannot
//! drop it and nothing has to be unset before the payload sees its
//! environment. In order (ordering checkpoint 9, DESIGN.md) it:
//!
//! 1. calls setgroups. bwrap never does, so without this the caller's host
//!    groups (wheel, docker, kvm) would stay effective. bwrap gives it
//!    CAP_SETGID for this and CAP_SETPCAP for the next step, and nothing else.
//! 2. drops the bounding set, clears the ambient set and zeroes the others, so
//!    the payload holds no capability and can gain none.
//! 3. with "ctty", takes fd 0, the relay's pty, as its controlling terminal:
//!    bwrap's --new-session made it a session leader, and tini -g needs the
//!    terminal to hand the payload the foreground.
//! 4. resets SIGINT and SIGQUIT to their default and empties the signal mask:
//!    a bash "&" hands bwrap both ignored, and tini passes that on.
//! 5. writes one byte on READY: bwrap has finished the root, so the launcher
//!    may run the mount helper and hooks that enter the mount namespace.
//! 6. reads one byte from GATE. EOF means the launcher failed or died before
//!    the helper, the hooks and pasta had all succeeded: exit 125, the payload
//!    never runs.
//! 7. changes to DIR. The workspace is a helper mount made after bwrap built
//!    the root, so this has to follow the gate; bwrap's --chdir would name the
//!    directory underneath it.
//! 8. closes every descriptor above stderr (bwrap leaks its namespace fds),
//!    and execs tini -g -- COMMAND.
//!
//! Every failure before the exec exits 125, the code the launcher reports as
//! "the session did not start", its message printed whole in one writev
//! (quirk 22). No libc, no allocator, no descriptor table: the groups go in
//! a static array and tini's argv is the kernel's own (DESIGN.md,
//! "Conventions"). Static, single-threaded and with no stack size, the start
//! code makes no syscall before main, nor does src/main.zig's dispatch, and
//! RLIMIT_STACK is left as it came (quirk 20; DESIGN.md, "What the port
//! measured": start code).

const std = @import("std");
const sys = @import("sys");
const msg = @import("msg");
const config = @import("config");

/// FLONG_TINI (flong-init.c:52-54), -Dtini, as the C string execve takes.
const tini = std.fmt.comptimePrint("{s}", .{config.tini});

/// The groups, parsed (flong-init.c:113-138's calloc): at most NGROUPS_MAX,
/// counted before any is parsed.
var gids: [sys.ngroups_max]u32 = undefined;

/// s whole as a decimal number: no sign, no blanks, no more than max
/// (flong-init.c:86-99). The C's strtoul, after its check that the first
/// byte is a digit, takes no blank or sign, so what remains is: every byte
/// a digit, and the value within max (ERANGE past 2^64 - 1 is beyond every
/// max here). Leading zeros are digits.
fn decimal(s: []const u8, max: u64) ?u64 {
    if (s.len == 0) return null;
    var v: u64 = 0;
    for (s) |ch| {
        if (ch < '0' or ch > '9') return null;
        // Past max, more digits only make it larger.
        v = v * 10 + (ch - '0');
        if (v > max) return null;
    }
    return v;
}

/// A descriptor argument (flong-init.c:101-109). 0 to 2 are the payload's
/// stdio, never a pipe of the protocol, so naming one is a launcher bug.
/// An i32, not a sys.fd_t: a number bwrap passed on, opened by the
/// launcher, which zwanzig would take for an open this program leaks.
fn fdArg(s: [*:0]const u8, which: []const u8) i32 {
    const v = decimal(std.mem.span(s), std.math.maxInt(i32)) orelse 0;
    if (v < 3) refuse("{s} descriptor is not a number above 2: {s}", .{ which, s });
    return @intCast(v);
}

const Groups = union(enum) {
    /// "-": setgroups(0, NULL).
    none,
    /// The first n of `gids`.
    some: usize,
    too_many,
    /// The first token that is not a gid.
    not_gid: []const u8,
    empty_field,
};

/// "-" or comma-separated gids, each a whole decimal number
/// (flong-init.c:111-138). A gid of (gid_t)-1 is not a group, so it refuses
/// like any other malformed field. The fields are strtok_r's: runs of bytes
/// other than a comma, empty ones skipped, each checked in order; the C
/// writes a NUL over each comma it passes, which nothing reads again, so
/// here the argument is left as it is.
fn groupsArg(s: []const u8, out: []u32) Groups {
    if (std.mem.eql(u8, s, "-")) return .none;
    const count = 1 + std.mem.count(u8, s, ",");
    if (count > sys.ngroups_max) return .too_many;
    var n: usize = 0;
    var it = std.mem.tokenizeScalar(u8, s, ',');
    while (it.next()) |tok| {
        const v = decimal(tok, std.math.maxInt(u32) - 1) orelse return .{ .not_gid = tok };
        out[n] = @intCast(v);
        n += 1;
    }
    // Empty fields were skipped, so ",,1" or "1," would pass silently:
    // every comma must separate two gids.
    if (n != count) return .empty_field;
    return .{ .some = n };
}

/// One of two words, the second meaning "no" (flong-init.c:140-148).
fn flagArg(s: [*:0]const u8, comptime yes: []const u8) bool {
    const w = std.mem.span(s);
    if (std.mem.eql(u8, w, yes)) return true;
    if (std.mem.eql(u8, w, "-")) return false;
    refuse("expected " ++ yes ++ " or -, got {s}", .{s});
}

/// failx: the message alone, then 125 (flong-init.c:78-84).
fn refuse(comptime fmt: []const u8, args: anytype) noreturn {
    msg.die(null, fmt, args);
}

/// fail: the message and the errno's text, then 125 (flong-init.c:69-76).
fn fail(e: sys.E, comptime fmt: []const u8, args: anytype) noreturn {
    msg.die(e, fmt, args);
}

/// The call's value, or its errno said with `what`, then 125.
fn must(r: anytype, comptime what: []const u8) @FieldType(@TypeOf(r), "ok") {
    return switch (r) {
        .ok => |v| v,
        .err => |e| fail(e, what, .{}),
    };
}

/// flong-init.c:150-165.
fn dropCapabilities() void {
    // PR_CAPBSET_READ answers EINVAL past the running kernel's last
    // capability, which may be newer than this program.
    var cap: usize = 0;
    const end = while (true) : (cap += 1) {
        switch (sys.prctl(sys.PR.CAPBSET_READ, cap)) {
            .ok => _ = must(sys.prctl(sys.PR.CAPBSET_DROP, cap), "dropping the bounding set"),
            .err => |e| break e,
        }
    };
    if (end != .INVAL) fail(end, "reading the bounding set", .{});
    _ = must(sys.prctl(sys.PR.CAP_AMBIENT, sys.PR.CAP_AMBIENT_CLEAR_ALL), "clearing the ambient set");
    const none: [sys.cap_u32s_3]sys.CapData = @splat(.{ .effective = 0, .permitted = 0, .inheritable = 0 });
    must(sys.capset(&none), "capset");
}

/// flong-init.c:167-177. SIGQUIT is reset only once SIGINT was.
fn resetSignals() void {
    const reset = switch (sys.sigDefault(sys.SIG.INT)) {
        .ok => sys.sigDefault(sys.SIG.QUIT),
        .err => |e| sys.Result(void){ .err = e },
    };
    must(reset, "resetting SIGINT and SIGQUIT");
    must(sys.emptyMask(), "emptying the signal mask");
}

/// The words of flong init's argv, from the subcommand's word on
/// (flong-init.c:185-193): each slot's pointer, read before `tiniArgv`
/// writes over TRACE, DIR and "--". Nothing but the shape is checked.
pub const Words = struct {
    gate: [*:0]const u8,
    ready: [*:0]const u8,
    groups: [*:0]const u8,
    tty: [*:0]const u8,
    trace: [*:0]const u8,
    dir: [*:0]const u8,
};

/// argv as src/main.zig hands it over: the word "init" in slot 0, so the
/// kernel's slots from `flong init` are these plus one. Null when the
/// shape is wrong: no "--" in slot 7, or no command after it.
pub fn words(argv: []const [*:0]const u8) ?Words {
    if (argv.len < 9 or !std.mem.eql(u8, std.mem.span(argv[7]), "--")) return null;
    return .{ .gate = argv[1], .ready = argv[2], .groups = argv[3], .tty = argv[4], .trace = argv[5], .dir = argv[6] };
}

/// tini's argv, in the kernel's own slots (flong-init.c:222-237): COMMAND
/// is slot 8 onward, and tini's three words go in slots 5-7, whose TRACE,
/// DIR and "--" `words` has read, so &argv[5] is tini's argv as it stands,
/// the kernel's NULL after COMMAND ending it. Under `flong init` those are
/// the kernel's slots 6-8.
pub fn tiniArgv(argv: [][*:0]const u8) [*:null]const ?[*:0]const u8 {
    argv[5] = "tini";
    argv[6] = "-g";
    argv[7] = "--";
    return @ptrCast(argv[5..].ptr);
}

/// flong-init.c:179-238. Ordering checkpoint 9 (DESIGN.md): one linear
/// function, each step numbered as the header's list. `argv` is the
/// kernel's, from the subcommand's word on; `envp` the kernel's environ.
pub fn main(argv: [][*:0]const u8, envp: []const [*:0]const u8) noreturn {
    msg.prog = "flong init";
    msg.mode = .whole;

    // The argv, in the C's order; nothing is called until all of it holds.
    const w = words(argv) orelse
        refuse("usage: flong init GATE READY GROUPS TTY TRACE DIR -- COMMAND...", .{});
    const gate = fdArg(w.gate, "gate");
    const ready = fdArg(w.ready, "ready");
    if (gate == ready) refuse("the gate and ready descriptors are the same", .{});
    const groups: ?[]const u32 = switch (groupsArg(std.mem.span(w.groups), &gids)) {
        .none => null,
        .some => |n| gids[0..n],
        .too_many => refuse("more supplementary groups than the kernel allows", .{}),
        .not_gid => |tok| refuse("not a group id: {s}", .{tok}),
        .empty_field => refuse("an empty field in the group list", .{}),
    };
    const ctty = flagArg(w.tty, "ctty");
    msg.tracing = flagArg(w.trace, "trace");
    const dir = w.dir;
    if (dir[0] != '/') refuse("the working directory is not absolute", .{});

    // 1. setgroups.
    must(sys.setgroups(groups), "setgroups");
    // 2. The bounding set, the ambient set, capset.
    dropCapabilities();
    // 3. The controlling terminal.
    if (ctty) must(sys.ioctl(0, sys.TIOCSCTTY, 0), "taking the terminal (TIOCSCTTY)");
    // 4. SIGINT and SIGQUIT default, an empty mask.
    resetSignals();

    // 5. READY, then its close. No handler is installed, so EINTR cannot
    // arrive; a write or read that ends any other way than with its one
    // byte is the launcher gone.
    // A write of one byte that returns 0 has no errno: the C printed the
    // stale EINVAL its bounding-set loop left, this prints "Success". A
    // pipe, all the launcher passes, never returns 0.
    switch (sys.write(ready, "r")) {
        .ok => |n| if (n != 1) fail(.SUCCESS, "telling the launcher the root is built", .{}),
        .err => |e| fail(e, "telling the launcher the root is built", .{}),
    }
    must(sys.closeChecked(ready), "closing the ready pipe");
    // 6. The gate byte.
    var byte: [1]u8 = undefined;
    const got = must(sys.read(gate, &byte), "waiting at the gate");
    if (got == 0) refuse("the gate closed without opening: not starting the payload", .{});

    // 7. DIR.
    switch (sys.chdir(dir)) {
        .ok => {},
        .err => |e| fail(e, "changing to {s}", .{dir}),
    }
    // 8. Every descriptor above stderr, then the trace and the exec.
    must(sys.closeRange(3, ~@as(u32, 0), 0), "closing inherited descriptors");

    const exec_argv = tiniArgv(argv);
    const exec_envp: [*:null]const ?[*:0]const u8 = @ptrCast(envp.ptr);

    msg.trace("payload-exec");
    fail(sys.execve(tini, exec_argv, exec_envp), "executing {s}", .{tini});
}

// ---- tests ----

const testing = std.testing;

test "decimal: digits only, within max" {
    try testing.expectEqual(@as(?u64, 3), decimal("3", 10));
    try testing.expectEqual(@as(?u64, 7), decimal("007", 10));
    try testing.expectEqual(@as(?u64, 2147483647), decimal("2147483647", std.math.maxInt(i32)));
    try testing.expectEqual(@as(?u64, null), decimal("2147483648", std.math.maxInt(i32)));
    try testing.expectEqual(@as(?u64, null), decimal("18446744073709551616", std.math.maxInt(u32) - 1));
    try testing.expectEqual(@as(?u64, null), decimal("99999999999999999999999", std.math.maxInt(u32) - 1));
    for ([_][]const u8{ "", "+3", "-3", " 3", "3 ", "0x3", "3a" }) |s|
        try testing.expectEqual(@as(?u64, null), decimal(s, 10));
}

test "groups: counted first, then each field in order, then the empty ones" {
    var out: [sys.ngroups_max]u32 = undefined;
    try testing.expectEqual(Groups.none, groupsArg("-", &out));
    try testing.expectEqual(Groups{ .some = 2 }, groupsArg("100,4294967294", &out));
    try testing.expectEqualSlices(u32, &.{ 100, 4294967294 }, out[0..2]);
    try testing.expectEqualStrings("4294967295", groupsArg("1,4294967295", &out).not_gid);
    try testing.expectEqualStrings("x", groupsArg(",,x", &out).not_gid);
    try testing.expectEqual(Groups.empty_field, groupsArg("1,", &out));
    try testing.expectEqual(Groups.empty_field, groupsArg("", &out));
    const many = "," ** sys.ngroups_max;
    try testing.expectEqual(Groups.too_many, groupsArg("x" ++ many, &out));
    const full = "0" ++ ",0" ** (sys.ngroups_max - 1);
    try testing.expectEqual(Groups{ .some = sys.ngroups_max }, groupsArg(full, &out));
}
