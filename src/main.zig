//! flong's root (DESIGN.md, "The native launcher"): one static binary
//! without libc, whose subcommands are the programs that were flong-launch,
//! flong-init and flong-sweeper (STANDALONE.md, S1).
//!
//!   flong launch DECL.zon|NAME [-- ARGS...]
//!   flong init GATE READY GROUPS TTY TRACE DIR -- COMMAND...
//!   flong sweeper STATE-DIR
//!   flong check DECL.zon
//!   flong list
//!   flong schema
//!   flong version
//!   flong help
//!   NAME [ARGS...]            a declaration's link, NAME -> flong
//!
//! The subcommand is argv[0]'s basename, as busybox reads it, then argv[1]:
//! a link named `sweeper` runs the sweeper. A subcommand's main is handed
//! argv from its word on, so its argv[0] is the word wherever it came from,
//! and the kernel's own slots are what flong init rewrites for tini. A
//! basename that is neither a subcommand nor "flong" is a declaration's
//! name (STANDALONE.md, "The declaration's command"): the link runs what
//! `flong launch NAME -- ARGS` does, NAME.zon from the directories
//! launch/lookup.zig names, /etc/flong first. `flong launch` also takes the
//! argv spec, keywords then "--" and a command, until the wrapper that
//! builds one is deleted (STANDALONE.md, S3).
//!
//! Dispatch reads the kernel's argv and environ and nothing else. It makes
//! no syscall, so the first the process makes after execve is its
//! subcommand's (DESIGN.md, "What the port measured": start code), as pid 1
//! needs; tests/native.nix's strace subtest holds it.

const std = @import("std");
const sys = @import("sys");
const msg = @import("msg");
const launch = @import("launch");
const init = @import("init");
const sweeper = @import("sweeper");
const check = @import("check");
const decl_docs = @import("decl_docs");
const lookup = @import("lookup");
const config = @import("config");

/// Every subcommand's failure status, and the panic's: 125 is "the
/// session did not start" to flong launch's callers (DESIGN.md, "Exit
/// codes"), and what flong init and flong sweeper exit with when they
/// cannot go on.
const failed = 125;

/// A usage error, as flong-seccomp's (quirk 16).
const usage_status = 2;

// No SIGSEGV handler, and SIGPIPE left as it came, for each subcommand's
// main to set: the start code would otherwise install the one and ignore
// the other (start.zig:687-719). flong init dies of SIGPIPE writing READY
// after the helper died (quirk 1), and a payload would inherit an ignored
// SIGPIPE through its exec.
pub const std_options: std.Options = .{
    .enable_segfault_handler = false,
    .keep_sigpipe = true,
};

// "<prog>: internal error: <msg>", 125, whichever subcommand panicked; the
// prefix is the one it prints with, "flong" before one has begun. The
// default panic ends in abort, which pid 1 drops (posix.zig:680-727). When
// flong launch panics it skips the teardown: the sweeper releases the
// session, the watchdog restores the terminal and --die-with-parent ends
// the payload (DESIGN.md, "Conventions": panics). In the mount helper, a
// fork of flong launch, 125 reads as a failed mount.
pub const panic = std.debug.FullPanic(msg.onPanic(failed));

/// The subcommands. `check` and `schema` came with the declaration (S2):
/// the one judges a declaration file, the other prints decl-options.json,
/// the declaration's fields as module.nix builds its options from them.
/// `list` (S3) prints each declaration a name runs, and its file. No
/// declaration may be named as one (check.reserved).
pub const Sub = enum { launch, init, sweeper, check, list, schema, version, help };

pub const Dispatch = union(enum) {
    /// A subcommand, and the index of its word in argv: its main is handed
    /// argv[at..].
    sub: struct { sub: Sub, at: usize },
    /// argv[0]'s basename, which names no subcommand.
    declaration: []const u8,
    /// argv[1], which names no subcommand.
    unknown: []const u8,
    /// No subcommand at all.
    usage,
};

/// What argv asks for. Pure: it reads the slots and makes no call.
pub fn dispatch(argv: []const [*:0]const u8) Dispatch {
    if (argv.len == 0) return .usage;
    const base = basename(std.mem.span(argv[0]));
    if (std.meta.stringToEnum(Sub, base)) |s| return .{ .sub = .{ .sub = s, .at = 0 } };
    // An empty argv[0] names nothing, as "flong" does not.
    if (base.len != 0 and !std.mem.eql(u8, base, "flong")) return .{ .declaration = base };
    if (argv.len < 2) return .usage;
    const word = std.mem.span(argv[1]);
    if (std.meta.stringToEnum(Sub, word)) |s| return .{ .sub = .{ .sub = s, .at = 1 } };
    return .{ .unknown = word };
}

/// What follows the last slash; a path that ends in one names nothing.
fn basename(path: []const u8) []const u8 {
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return path;
    return path[slash + 1 ..];
}

const usage =
    \\usage: flong launch DECL.zon|NAME [-- ARGS...]
    \\       flong init GATE READY GROUPS TTY TRACE DIR -- COMMAND...
    \\       flong sweeper STATE-DIR
    \\       flong check DECL.zon
    \\       flong list
    \\       flong schema
    \\       flong version
    \\       flong help
    \\       NAME [ARGS...]    (a declaration's link to flong)
;

/// `flong version`: the version, then each program compiled into flong as
/// `NAME=PATH`, one a line, in build.zig's LaunchPaths' order, which is
/// where a test finds the cache tool its launches run (tests/bench.nix).
const version_text = blk: {
    var t: []const u8 = "flong " ++ config.version ++ "\n";
    for (.{ "bwrap", "self", "pasta", "newuidmap", "newgidmap", "tini", "cache", "seccomp" }) |name| {
        t = t ++ name ++ "=" ++ @field(config, name) ++ "\n";
    }
    break :blk t;
};

pub fn main() noreturn {
    const argv = sys.argvSlots();
    const envp = sys.environ();
    switch (dispatch(argv)) {
        .sub => |d| switch (d.sub) {
            .launch => launch.main(argv, d.at, envp),
            .init => init.main(argv[d.at..], envp),
            .sweeper => sweeper.main(argv[d.at..]),
            .check => check.main(argv[d.at..]),
            .list => list(argv[d.at..], envp),
            .schema => schema(argv[d.at..]),
            .version => put(version_text),
            .help => put(usage ++ "\n"),
        },
        .declaration => |name| launch.named(argv, name, envp),
        .unknown => |word| {
            msg.say("no subcommand \"{s}\"", .{word});
            msg.bare(usage, .{});
            sys.exitGroup(usage_status);
        },
        .usage => {
            msg.bare(usage, .{});
            sys.exitGroup(usage_status);
        },
    }
}

/// flong list: each declaration a name runs, `NAME PATH` a line, the
/// directories in lookup order and the names in each sorted; a name an
/// earlier directory has is not repeated (launch/lookup.zig). Exit 0.
fn list(argv: []const [*:0]const u8, envp: []const [*:0]const u8) noreturn {
    msg.prog = "flong list";
    msg.mode = .whole;
    if (argv.len != 1) {
        msg.bare("usage: flong list", .{});
        sys.exitGroup(usage_status);
    }
    var arena_state: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    const arena = arena_state.allocator();
    var out: std.ArrayList(u8) = .empty;
    const entries = lookup.list(arena, envp) catch outOfMemory();
    for (entries) |e| out.print(arena, "{s} {s}\n", .{ e.name, e.path }) catch outOfMemory();
    put(out.items);
}

fn outOfMemory() noreturn {
    msg.say("out of memory", .{});
    sys.exitGroup(1);
}

/// flong schema: decl-options.json on stdout, the bytes `zig build
/// schema` checks in (build/schema.zig), whole, then exit 0.
fn schema(argv: []const [*:0]const u8) noreturn {
    msg.prog = "flong schema";
    msg.mode = .whole;
    if (argv.len != 1) {
        msg.bare("usage: flong schema", .{});
        sys.exitGroup(usage_status);
    }
    var arena_state: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    var out: std.Io.Writer.Allocating = .init(arena_state.allocator());
    decl_docs.writeSchema(&out.writer) catch {
        msg.say("out of memory", .{});
        sys.exitGroup(1);
    };
    put(out.written());
}

/// Writes `text` on stdout and exits 0, or says why it could not and
/// exits 1.
fn put(text: []const u8) noreturn {
    var rest = text;
    while (rest.len > 0) {
        switch (sys.write(1, rest)) {
            .ok => |n| rest = rest[n..],
            .err => |e| {
                msg.sayErrno(e, "writing to stdout", .{});
                sys.exitGroup(1);
            },
        }
    }
    sys.exitGroup(0);
}

// ---- tests ----

const testing = std.testing;

fn expectSub(want: Sub, at: usize, argv: []const [*:0]const u8) !void {
    const d = dispatch(argv);
    try testing.expectEqual(want, d.sub.sub);
    try testing.expectEqual(at, d.sub.at);
}

test "dispatch: argv[0]'s basename first, then argv[1]" {
    try expectSub(.launch, 1, &.{ "/nix/store/x-flong/bin/flong", "launch", "machine" });
    try expectSub(.init, 1, &.{ "flong", "init", "4", "5" });
    try expectSub(.sweeper, 0, &.{ "/some/where/sweeper", "/run/user/1000/flong" });
    // A subcommand's basename wins over argv[1].
    try expectSub(.version, 0, &.{ "version", "launch" });
    try expectSub(.help, 1, &.{ "flong", "help" });
}

test "dispatch: check and schema are subcommands, and no declaration's name" {
    try expectSub(.check, 1, &.{ "flong", "check", "/etc/flong/agent.zon" });
    try expectSub(.schema, 1, &.{ "flong", "schema" });
    // A declaration named as a subcommand would dispatch to it, so flong
    // check refuses every name dispatch reads as one.
    inline for (@typeInfo(Sub).@"enum".fields) |f| {
        for (check.reserved) |r| {
            if (std.mem.eql(u8, r, f.name)) break;
        } else return error.SubcommandNotReserved;
    }
}

test "dispatch: a basename that is no subcommand is a declaration" {
    try testing.expectEqualStrings("agent", dispatch(&.{ "/run/current-system/sw/bin/agent", "--", "true" }).declaration);
    // The old names are declarations too, and fail loudly.
    try testing.expectEqualStrings("flong-launch", dispatch(&.{"flong-launch"}).declaration);
}

test "dispatch: flong alone, or with a word that is no subcommand" {
    try testing.expectEqual(Dispatch.usage, dispatch(&.{}));
    try testing.expectEqual(Dispatch.usage, dispatch(&.{"flong"}));
    try testing.expectEqual(Dispatch.usage, dispatch(&.{"/bin/flong"}));
    try expectSub(.list, 1, &.{ "flong", "list" });
    try testing.expectEqualStrings("lsit", dispatch(&.{ "flong", "lsit" }).unknown);
    try testing.expectEqualStrings("", dispatch(&.{ "", "" }).unknown);
    // A path ending in a slash has an empty basename, as "" does.
    try expectSub(.launch, 1, &.{ "dir/", "launch" });
}
