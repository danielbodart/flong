//! flong init (DESIGN.md, "Files"): launcher/flong-init.c, line by line;
//! the C was deleted in phase 3 (b), and its line numbers here are those of
//! db5fdeb. `main` is the subcommand's, which src/main.zig calls.
//!
//! The first program inside the session: bwrap execs it as pid 1
//! (--as-pid-1), so it runs before anything of the payload's and is the
//! gate; bwrap's own --block-fd is fail-open, this one is fail-closed.
//!
//!   flong init GATE READY FILES GROUPS TTY TRACE DIR -- COMMAND...
//!
//! GATE and READY are descriptor numbers, FILES one or "-", GROUPS is
//! comma-separated gids or "-", TTY is "ctty" or "-", TRACE is "trace" or
//! "-", DIR is absolute. The protocol is argv, not the environment, so the
//! wrapper's --clearenv cannot drop it and nothing has to be unset before
//! the payload sees its environment. In order (ordering checkpoint 9,
//! DESIGN.md) it:
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
//! 7. with FILES, seeds the files `exec` printed into the payload's home
//!    (`seed`): as the payload's user, since the capabilities went at step
//!    2, and after the gate, since the mount helper's binds into the home
//!    are there only then. Nothing of the session runs yet, so nothing can
//!    race a path it walks.
//! 8. changes to DIR. The workspace is a helper mount made after bwrap built
//!    the root, so this has to follow the gate; bwrap's --chdir would name the
//!    directory underneath it. PWD is then DIR: bwrap set it to where it
//!    left its own working directory, and the payload is exec'd with no
//!    shell to set it again, so a program that trusts $PWD, as a shell's
//!    `pwd` does, would be told the wrong directory.
//! 9. closes every descriptor above stderr (bwrap leaks its namespace fds),
//!    FILES among them, and execs tini -g -- COMMAND.
//!
//! Every failure before the exec exits 125, the code the launcher reports as
//! "the session did not start", its message printed whole in one writev
//! (quirk 22). No libc, no allocator, no descriptor table: the groups go in
//! a static array, the files are read from FILES mapped, and tini's argv is
//! the kernel's own (DESIGN.md,
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

/// `PWD=DIR`, the payload's PWD (step 7): DIR is shorter than PATH_MAX, or
/// the chdir before it would have failed.
var pwd_buf: ["PWD=".len + sys.path_max:0]u8 = undefined;

/// Points the environment's `PWD=` slot at `PWD=dir`, written into `buf`,
/// or leaves the environment as it is when it has no such slot, or `dir` is
/// PATH_MAX or longer. bwrap always sets PWD, so the slot is there.
pub fn setPwd(envp: [][*:0]const u8, dir: []const u8, buf: *["PWD=".len + sys.path_max:0]u8) void {
    if (dir.len >= sys.path_max) return;
    for (envp) |*e| {
        if (!std.mem.startsWith(u8, std.mem.span(e.*), "PWD=")) continue;
        @memcpy(buf[0.."PWD=".len], "PWD=");
        @memcpy(buf["PWD=".len..][0..dir.len], dir);
        buf["PWD=".len + dir.len] = 0;
        e.* = buf[0 .. "PWD=".len + dir.len :0].ptr;
        return;
    }
}

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

/// FILES: "-", none, or a descriptor argument as `fdArg` reads one.
fn filesArg(s: [*:0]const u8) ?i32 {
    if (std.mem.eql(u8, std.mem.span(s), "-")) return null;
    return fdArg(s, "files");
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
/// (flong-init.c:185-193, with FILES after READY): each slot's pointer,
/// read before `tiniArgv` writes over TRACE, DIR and "--". Nothing but the
/// shape is checked.
pub const Words = struct {
    gate: [*:0]const u8,
    ready: [*:0]const u8,
    files: [*:0]const u8,
    groups: [*:0]const u8,
    tty: [*:0]const u8,
    trace: [*:0]const u8,
    dir: [*:0]const u8,
};

/// argv as src/main.zig hands it over: the word "init" in slot 0, so the
/// kernel's slots from `flong init` are these plus one. Null when the
/// shape is wrong: no "--" in slot 8, or no command after it.
pub fn words(argv: []const [*:0]const u8) ?Words {
    if (argv.len < 10 or !std.mem.eql(u8, std.mem.span(argv[8]), "--")) return null;
    return .{ .gate = argv[1], .ready = argv[2], .files = argv[3], .groups = argv[4], .tty = argv[5], .trace = argv[6], .dir = argv[7] };
}

/// tini's argv, in the kernel's own slots (flong-init.c:222-237): COMMAND
/// is slot 9 onward, and tini's three words go in slots 6-8, whose TRACE,
/// DIR and "--" `words` has read, so &argv[6] is tini's argv as it stands,
/// the kernel's NULL after COMMAND ending it. Under `flong init` those are
/// the kernel's slots 7-9.
pub fn tiniArgv(argv: [][*:0]const u8) [*:null]const ?[*:0]const u8 {
    argv[6] = "tini";
    argv[7] = "-g";
    argv[8] = "--";
    return @ptrCast(argv[6..].ptr);
}

// ---- the files (step 7) ----
//
// FILES is a memfd the launcher wrote (spec.filesData): the payload's home,
// then for each file its mode in octal, its path relative to the home and
// its content, every field ended by a NUL. The launcher has judged all of
// it (launch/assemble.zig's execOf and homeFiles, spec.validate); what is
// checked again here is what a walk would go wrong on, and a refusal is a
// launcher bug, said and exited 125 as any other.
//
// Nothing is followed and nothing crosses a mount. The home is opened from
// "/" and each file's directories from the home, one component at a time,
// with openat2's RESOLVE_BENEATH, RESOLVE_NO_SYMLINKS, RESOLVE_NO_MAGICLINKS
// and RESOLVE_NO_XDEV, and the file itself with those and O_NOFOLLOW, so a
// symbolic link anywhere on the way, the last component's included, ends the
// launch, and so does a mount point. RESOLVE_NO_XDEV, because the one
// filesystem a seeded file belongs on is the session's root overlay, whose
// upper layer is the session's own and goes with it: a mount on the way is
// a bind of the caller's or the declaration's -- the workspace, a writable
// host directory -- where a write would land on the host, outside anything
// the declaration says flong writes, or a tmpfs ($home/tmp) that a
// rule with an exception for it would have to tell apart from a bind. A
// home that is itself on another mount than "/" is refused for the same
// reason. A file already there is replaced in place: truncated, its mode
// set, its content written; a directory, a FIFO or a device there is
// refused. Missing directories are made 0700, the payload's.

/// NAME_MAX: the longest component a path may have.
const name_max = 255;

/// One component of a file's path, ended by a NUL for openat2 and mkdirat.
var component: [name_max:0]u8 = undefined;

/// What every open of the walk resolves with.
const beneath = sys.RESOLVE.BENEATH | sys.RESOLVE.NO_SYMLINKS | sys.RESOLVE.NO_MAGICLINKS | sys.RESOLVE.NO_XDEV;

/// openat2 of `path` under `dir` with `beneath`.
fn openBeneath(dir: sys.fd_t, path: [*:0]const u8, flags: sys.O, mode: sys.mode_t) sys.Result(sys.fd_t) {
    const how: sys.OpenHow = .{ .flags = @as(u32, @bitCast(flags)), .mode = mode, .resolve = beneath };
    return sys.openat2(dir, path, &how);
}

/// A directory to walk from: O_PATH, followed by nothing.
const dir_flags: sys.O = .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true };

/// The NUL-ended fields of FILES, in order.
pub const Fields = struct {
    data: []const u8,
    pos: usize = 0,

    /// The next field, or null at the end or where no NUL ends it.
    pub fn next(f: *Fields) ?[:0]const u8 {
        const end = std.mem.indexOfScalarPos(u8, f.data, f.pos, 0) orelse return null;
        const field = f.data[f.pos..end :0];
        f.pos = end + 1;
        return field;
    }

    /// Whether every byte has been read as a field.
    pub fn done(f: *const Fields) bool {
        return f.pos == f.data.len;
    }
};

/// A file's mode as the launcher writes it: octal digits, at most 0777.
pub fn octalMode(s: []const u8) ?u32 {
    if (s.len == 0 or s.len > 3) return null;
    var n: u32 = 0;
    for (s) |c| {
        if (c < '0' or c > '7') return null;
        n = n * 8 + (c - '0');
    }
    return n;
}

/// Whether `path` is relative, not empty, and has no empty, '.' or '..'
/// component, nor one longer than NAME_MAX: what the walk can take one
/// component at a time.
pub fn walkable(path: []const u8) bool {
    if (path.len == 0) return false;
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |c| {
        if (c.len == 0 or c.len > name_max or std.mem.eql(u8, c, ".") or std.mem.eql(u8, c, "..")) return false;
    }
    return true;
}

/// A seeding call's failure: a link and a mount said as the rule they
/// break, anything else with its errno.
fn seedFailed(e: sys.E, home: []const u8, path: []const u8) noreturn {
    switch (e) {
        .LOOP => refuse("seeding {s}/{s}: a symbolic link is on its path, and nothing is followed", .{ home, path }),
        .XDEV => refuse("seeding {s}/{s}: its path crosses a mount, and a seeded file is written to the session's own root alone", .{ home, path }),
        else => fail(e, "seeding {s}/{s}", .{ home, path }),
    }
}

/// Step 7: every file of FILES, in order, under the home it names.
fn seed(files: i32) void {
    const st = must(sys.fstat(files), "reading the files to seed");
    const size: usize = @intCast(st.size);
    if (size == 0) refuse("the files to seed are empty", .{});
    var fields: Fields = .{ .data = must(sys.mmapRead(files, size), "mapping the files to seed") };
    const home = fields.next() orelse refuse("the files to seed do not end with a NUL", .{});
    if (home.len < 2 or home[0] != '/' or !walkable(home[1..])) refuse("the home to seed files in is not a clean absolute path: {s}", .{home});
    const root = must(sys.openat(sys.AT.FDCWD, "/", dir_flags, 0), "opening / to seed files");
    const home_fd = switch (openBeneath(root, home[1..].ptr, dir_flags, 0)) {
        .ok => |h| h,
        .err => |e| switch (e) {
            .LOOP => refuse("seeding files in {s}: a symbolic link is on its path, and nothing is followed", .{home}),
            .XDEV => refuse("seeding files in {s}: it is on another mount than the session's root, and a seeded file is written to the session's own root alone", .{home}),
            else => fail(e, "opening {s} to seed files in", .{home}),
        },
    };
    sys.close(root);
    while (!fields.done()) {
        const mode_text = fields.next() orelse refuse("the files to seed do not end with a NUL", .{});
        const path = fields.next() orelse refuse("the files to seed end with a file that has no path", .{});
        const content = fields.next() orelse refuse("the file to seed {s}/{s} has no content", .{ home, path });
        const mode = octalMode(mode_text) orelse refuse("the file to seed {s}/{s} has a mode that is not permission bits: {s}", .{ home, path, mode_text });
        if (!walkable(path)) refuse("the file to seed {s}/{s} is not a clean path below the home", .{ home, path });
        seedOne(home_fd, home, path, mode, content);
    }
    sys.close(home_fd);
}

/// One file: its directories made 0700 where missing and walked into, the
/// file opened for writing, made or truncated, then its mode and its
/// content. `path` is `walkable`.
fn seedOne(home_fd: sys.fd_t, home: []const u8, path: [:0]const u8, mode: u32, content: []const u8) void {
    var dir = home_fd;
    var rest: [:0]const u8 = path;
    while (std.mem.indexOfScalar(u8, rest, '/')) |slash| {
        const name = rest[0..slash];
        @memcpy(component[0..name.len], name);
        component[name.len] = 0;
        const c: [*:0]const u8 = component[0..name.len :0].ptr;
        // A name already there, a link included, is EEXIST, and the open
        // then judges it.
        switch (sys.mkdirat(dir, c, 0o700)) {
            .ok => {},
            .err => |e| if (e != .EXIST) seedFailed(e, home, path),
        }
        const next = switch (openBeneath(dir, c, dir_flags, 0)) {
            .ok => |n| n,
            .err => |e| seedFailed(e, home, path),
        };
        if (dir != home_fd) sys.close(dir);
        dir = next;
        rest = rest[slash + 1 ..];
    }
    // O_NONBLOCK, so a FIFO with no reader is ENXIO rather than a wait no
    // one ends; the fstat then refuses what is not a regular file before a
    // byte is written.
    const flags: sys.O = .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .NOFOLLOW = true, .NONBLOCK = true, .CLOEXEC = true };
    const opened = openBeneath(dir, rest.ptr, flags, mode);
    if (dir != home_fd) sys.close(dir);
    const f = switch (opened) {
        .ok => |f| f,
        .err => |e| seedFailed(e, home, path),
    };
    const st = switch (sys.fstat(f)) {
        .ok => |st| st,
        .err => |e| seedFailed(e, home, path),
    };
    if (!sys.S.ISREG(st.mode)) refuse("seeding {s}/{s}: something other than a regular file is there", .{ home, path });
    // The mode as it is asked for: O_CREAT's was under the umask, and a
    // file that was there kept its own.
    switch (sys.fchmod(f, mode)) {
        .ok => {},
        .err => |e| seedFailed(e, home, path),
    }
    var done: usize = 0;
    while (done < content.len) {
        switch (sys.write(f, content[done..])) {
            .ok => |n| {
                if (n == 0) seedFailed(.IO, home, path);
                done += n;
            },
            .err => |e| seedFailed(e, home, path),
        }
    }
    switch (sys.closeChecked(f)) {
        .ok => {},
        .err => |e| seedFailed(e, home, path),
    }
}

/// flong-init.c:179-238. Ordering checkpoint 9 (DESIGN.md): one linear
/// function, each step numbered as the header's list. `argv` is the
/// kernel's, from the subcommand's word on; `envp` the kernel's environ.
pub fn main(argv: [][*:0]const u8, envp: [][*:0]const u8) noreturn {
    msg.prog = "flong init";
    msg.mode = .whole;

    // The argv, in the C's order; nothing is called until all of it holds.
    const w = words(argv) orelse
        refuse("usage: flong init GATE READY FILES GROUPS TTY TRACE DIR -- COMMAND...", .{});
    const gate = fdArg(w.gate, "gate");
    const ready = fdArg(w.ready, "ready");
    if (gate == ready) refuse("the gate and ready descriptors are the same", .{});
    const files = filesArg(w.files);
    if (files) |f| if (f == gate or f == ready) refuse("the files descriptor is the gate's or ready's", .{});
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

    // 7. The files, as the payload's user.
    if (files) |f| seed(f);

    // 8. DIR, and PWD with it.
    switch (sys.chdir(dir)) {
        .ok => {},
        .err => |e| fail(e, "changing to {s}", .{dir}),
    }
    setPwd(envp, std.mem.span(dir), &pwd_buf);
    // 9. Every descriptor above stderr, then the trace and the exec.
    must(sys.closeRange(3, ~@as(u32, 0), 0), "closing inherited descriptors");

    const exec_argv = tiniArgv(argv);
    const exec_envp: [*:null]const ?[*:0]const u8 = @ptrCast(envp.ptr);

    msg.trace("payload-exec");
    fail(sys.execve(tini, exec_argv, exec_envp), "executing {s}", .{tini});
}

// ---- tests ----

const testing = std.testing;

test "setPwd points PWD's slot at DIR, and leaves an environment without one" {
    var buf: ["PWD=".len + sys.path_max:0]u8 = undefined;
    var env = [_][*:0]const u8{ "HOME=/home/alice", "PWD=/home/alice", "PWDX=1" };
    setPwd(&env, "/srv/work", &buf);
    try testing.expectEqualStrings("HOME=/home/alice", std.mem.span(env[0]));
    try testing.expectEqualStrings("PWD=/srv/work", std.mem.span(env[1]));
    try testing.expectEqualStrings("PWDX=1", std.mem.span(env[2]));
    var none = [_][*:0]const u8{ "PWDX=1", "HOME=/h" };
    setPwd(&none, "/srv/work", &buf);
    try testing.expectEqualStrings("PWDX=1", std.mem.span(none[0]));
    try testing.expectEqualStrings("HOME=/h", std.mem.span(none[1]));
}

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
