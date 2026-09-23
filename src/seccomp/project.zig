//! project.zig: `flong-seccomp project DUMP NAMES DENY DIR < POLICY`, what
//! flong-seccomp-project did (policy.nix:141-206), in process (ZIG.md,
//! "Phase 2"). It reads a project's `allow X...` and `deny X...` lines on
//! stdin and prints the path of the tier filter they make of the
//! declaration's NAMES, compiled once into DIR and then reused.
//!
//! Step by step as the bash, each step citing its lines:
//!
//!   1. the policy's lines, each refused as the bash refused it, with its
//!      prefix, "flong-seccomp-project:", exit 1 (quirk 38);
//!   2. the expansion of NAMES and those entries, the project's denies
//!      winning; an unknown group or name prints the expander's unprefixed
//!      line, exit 1 (:173-176);
//!   3. the rendered policy, NAMES empty giving one empty name, `allow `
//!      (quirk 35); a DENY render refuses is render's message, exit 2;
//!   4. the key, sha256 of the compiler's own store path, "\n", and the
//!      policy without its trailing newline (quirk 36, :183-184);
//!   5. DIR/KEY.bpf if it exists, else DIR's parent and DIR made 0700, the
//!      filter compiled into `.KEY.<6 random>` (made O_CREAT|O_EXCL|O_WRONLY,
//!      0600, then opened again by name, as mktemp and the shell's `>` did)
//!      and renamed into place (quirk 37, :186-206); mktemp's refusal is
//!      its own unprefixed line.
//!
//! The compile is compile.zig's, under the compiler's prefix,
//! "flong-seccomp:", as the bash printed its captured lines (:201-205); it
//! reads the policy and one newline (`<<<`, :201). Its stats line is not
//! printed (quirk 34). On a refusal the temp file is unlinked, exit 1.
//!
//! seccomp/policy.nix's line numbers here are those of 0dc291c, before the
//! port (tests/seccomp-tools-transition/old.nix keeps its code).

const std = @import("std");
const sys = @import("sys");
const msg = @import("msg");
const fd = @import("fd");
const config = @import("config");
const compile = @import("compile.zig");
const expand = @import("expand.zig");
const render = @import("render.zig");
const scmp = @import("scmp.zig");

pub const prog = "flong-seccomp-project";

fn nomem() msg.Error {
    return msg.fail(.NOMEM, "out of memory", .{});
}

/// `flong-seccomp project DUMP NAMES DENY DIR < POLICY`: its exit status.
pub fn main(gpa: std.mem.Allocator, args: []const [*:0]const u8) u8 {
    if (args.len != 4) {
        msg.bare("usage: flong-seccomp project DUMP NAMES 1|13|38|log DIR < POLICY", .{});
        return 2;
    }
    msg.prog = prog;
    return run(gpa, args[0], args[1], std.mem.span(args[2]), std.mem.span(args[3])) catch |err| switch (err) {
        error.Reported => 1,
    };
}

/// `[[ $x =~ ^@?[a-z0-9_-]+$ ]]` (:155), in ASCII.
fn wordOk(x: []const u8) bool {
    const body = if (x.len > 0 and x[0] == '@') x[1..] else x;
    if (body.len == 0) return false;
    for (body) |ch| {
        const ok = (ch >= 'a' and ch <= 'z') or (ch >= '0' and ch <= '9') or ch == '_' or ch == '-';
        if (!ok) return false;
    }
    return true;
}

/// The policy's entries, each "X" or "-X" (:145-165): `read -r` drops NUL
/// bytes; `read -r -a` splits on IFS; a line with no word or a first word
/// starting with "#" is skipped; a last line with no newline is read when
/// it is not empty.
fn parse(gpa: std.mem.Allocator, input: []const u8, spec: *std.ArrayList(u8)) msg.Error!void {
    var line_no: u32 = 0;
    var records: expand.Records = .{ .rest = input };
    var buf: std.ArrayList(u8) = .empty;
    while (records.next()) |raw| {
        buf.clearRetainingCapacity();
        for (raw) |ch| {
            if (ch != 0) buf.append(gpa, ch) catch return nomem();
        }
        const text = buf.items;
        // `|| [[ -n $text ]]`: only the last record can lack its newline,
        // and an empty one ends the loop there.
        if (records.rest.len == 0 and input[input.len - 1] != '\n' and text.len == 0) break;
        line_no += 1;

        var words: std.ArrayList([]const u8) = .empty;
        // bash's default IFS: a word ends at a space, a tab or a newline.
        var it = std.mem.tokenizeAny(u8, text, " \t\n");
        while (it.next()) |w| words.append(gpa, w) catch return nomem();
        if (words.items.len == 0 or words.items[0][0] == '#') continue;
        const w0 = words.items[0];
        const sign: []const u8 = if (std.mem.eql(u8, w0, "allow"))
            ""
        else if (std.mem.eql(u8, w0, "deny"))
            "-"
        else
            return msg.refuse("line {d}: not an allow or deny line: {s}", .{ line_no, w0 });
        if (words.items.len < 2)
            return msg.refuse("line {d}: {s} names nothing", .{ line_no, w0 });
        for (words.items[1..]) |x| {
            if (!wordOk(x))
                return msg.refuse("line {d}: not a syscall or @group: {s}", .{ line_no, x });
            spec.appendSlice(gpa, sign) catch return nomem();
            spec.appendSlice(gpa, x) catch return nomem();
            spec.append(gpa, '\n') catch return nomem();
        }
    }
}

/// `${dir%/*}`: DIR up to its last "/", or DIR when it has none.
fn parentOf(dir: []const u8) []const u8 {
    const slash = std.mem.lastIndexOfScalar(u8, dir, '/') orelse return dir;
    return dir[0..slash];
}

fn z(gpa: std.mem.Allocator, s: []const u8) msg.Error![:0]const u8 {
    return gpa.dupeZ(u8, s) catch return nomem();
}

/// `[[ -d $d ]]`: a directory, following symlinks.
fn isDir(path: [*:0]const u8) bool {
    return switch (sys.fstatat(sys.AT.FDCWD, path, 0)) {
        .ok => |st| sys.S.ISDIR(st.mode),
        .err => false,
    };
}

/// `mkdir -m 0700 -- "$d" 2>/dev/null || [[ -d $d ]]` (:190-195). mkdir -m
/// gives the mode exactly, whatever the umask: coreutils chmods what the
/// umask took, which here it never does unless the umask names an owner
/// bit.
fn makeDir(gpa: std.mem.Allocator, d: []const u8) msg.Error!void {
    const path = try z(gpa, d);
    switch (sys.mkdirat(sys.AT.FDCWD, path, 0o700)) {
        .ok => switch (sys.fstatat(sys.AT.FDCWD, path, sys.AT.SYMLINK_NOFOLLOW)) {
            .ok => |st| if (st.mode & 0o7777 != 0o700) {
                // A failed chmod is mkdir's message, which the bash sent
                // to /dev/null; the directory is there.
                _ = sys.fchmodat(sys.AT.FDCWD, path, 0o700);
            },
            .err => {},
        },
        .err => if (!isDir(path)) return msg.refuse("cannot make {s}", .{d}),
    }
}

/// mktemp's letters (gen_tempname).
const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// `mktemp "$dir/.$key.XXXXXX"` (:199): a new file, 0600, O_CREAT|O_EXCL,
/// its path returned in `name`; a name taken is tried again with other
/// letters, as mktemp does. By path, as mktemp and mv work, so a DIR the
/// caller can write and search but not read is used as before.
fn tempFile(gpa: std.mem.Allocator, dir_name: []const u8, key: []const u8, name: *[:0]u8) msg.Error!fd.File {
    name.* = std.fmt.allocPrintSentinel(gpa, "{s}/.{s}.XXXXXX", .{ dir_name, key }, 0) catch return nomem();
    const x = name.*[name.len - 6 ..];
    var tries: u32 = 0;
    while (tries < 100) : (tries += 1) {
        var r: [6]u8 = undefined;
        try msg.check(sys.getrandom(&r), "cannot make {s}/.{s}.XXXXXX", .{ dir_name, key });
        for (r, 0..) |b, i| x[i] = letters[b % letters.len];
        const opened = fd.openFile(fd.cwd, name.*, .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true }, 0o600) catch
            return msg.refuse("cannot make {s}: too many open descriptors", .{name.*});
        switch (opened) {
            .ok => |f| return f,
            .err => |e| if (e != .EXIST) return mktempFailed(e, dir_name, key),
        }
    }
    return mktempFailed(.EXIST, dir_name, key);
}

/// mktemp's refusal, which the bash let through unprefixed (:199), in the C
/// locale's quotes: coreutils' mktemp.c "failed to create file via template
/// %s", the template quoted.
fn mktempFailed(e: sys.E, dir_name: []const u8, key: []const u8) msg.Error {
    msg.prog = "mktemp";
    defer msg.prog = prog;
    return msg.fail(e, "failed to create file via template '{s}/.{s}.XXXXXX'", .{ dir_name, key });
}

/// The run's exit status: 0 with the filter's path printed, or 2 when render
/// refused DENY, having said so; any other failure is said, then Reported,
/// exit 1 (ZIG.md, "Messages, errors and panics": Reported is the one
/// printed error).
fn run(gpa: std.mem.Allocator, dump_path: [*:0]const u8, names_path: [*:0]const u8, deny_word: []const u8, dir: []const u8) msg.Error!u8 {
    // 1. The policy on stdin (:145-165).
    const input = msg.check(fd.readAll(fd.Stdio.in, gpa) catch return nomem(), "reading the policy", .{}) catch
        return error.Reported;
    var spec: std.ArrayList(u8) = .empty;
    try parse(gpa, input, &spec);

    // 2. NAMES, then the entries, expanded and sorted (:169-176).
    // NAMES is awk's operand (:173), so a directory is skipped with its
    // warning. DUMP was built into the bash, so it has no awk precedent.
    const dump = expand.Dump.parse(gpa, (try expand.readOperand(gpa, dump_path)) orelse "") catch return nomem();
    var e: expand.Expansion = .init(gpa, &dump);
    try e.lines((try expand.readOperand(gpa, names_path)) orelse "");
    try e.lines(spec.items);
    const list = try e.names();

    // 3. The policy (:177). `printf '%s\n' "$list"` of no names is one
    // empty line, which mapfile reads as one empty name.
    msg.prog = render.prog;
    const deny = render.Deny.parse(deny_word) orelse {
        msg.say("not 1, 13, 38 or log: {s}", .{deny_word});
        return 2;
    };
    msg.prog = prog;
    const names: []const []const u8 = if (list.len == 0) &.{""} else list;
    const known = try expand.known(gpa, &dump);
    var text: std.ArrayList(u8) = .empty;
    // Sorted by construction, so comm never warns.
    _ = render.render(gpa, &text, known, names, deny) catch return nomem();
    const policy = std.mem.trimRight(u8, text.items, "\n");

    // 4. The key (:181-184).
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(config.self);
    hash.update("\n");
    hash.update(policy);
    const key = std.fmt.bytesToHex(hash.finalResult(), .lower);

    // 5. Reused, or compiled into place (:185-206).
    const path = std.fmt.allocPrint(gpa, "{s}/{s}.bpf", .{ dir, key }) catch return nomem();
    const path_z = try z(gpa, path);
    if (sys.fstatat(sys.AT.FDCWD, path_z, 0) == .ok) {
        try printPath(gpa, path);
        return 0;
    }

    // The policy runs before the launch prepares its state, so the
    // directories may not exist yet. Another launch may make them first.
    try makeDir(gpa, parentOf(dir));
    try makeDir(gpa, dir);

    // Two launches racing here compile the same bytes, so whichever rename
    // lands last is as good as the first.
    var tmp_name: [:0]u8 = undefined;
    (try tempFile(gpa, dir, &key, &tmp_name)).close();
    // `>"$tmp"` (:201): the shell opened mktemp's file again by its name,
    // which a umask taking the owner's write bit refuses; the bash printed
    // that with its own name and line, removed the file and exited 1.
    const tmp = msg.check(fd.openFile(fd.cwd, tmp_name, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o666), "{s}", .{tmp_name}) catch |err| {
        _ = sys.unlinkat(sys.AT.FDCWD, tmp_name, 0);
        return err;
    };
    const compiled = compileInto(gpa, policy, tmp);
    tmp.close();
    compiled catch |err| {
        _ = sys.unlinkat(sys.AT.FDCWD, tmp_name, 0);
        return err;
    };
    switch (sys.renameat(sys.AT.FDCWD, tmp_name, sys.AT.FDCWD, path_z)) {
        .ok => {},
        .err => |err| {
            _ = sys.unlinkat(sys.AT.FDCWD, tmp_name, 0);
            return msg.fail(err, "cannot rename {s} to {s}", .{ tmp_name, path });
        },
    }
    try printPath(gpa, path);
    return 0;
}

/// compile.zig over the policy and one newline, the filter into `out`,
/// under the compiler's prefix; no stats line.
fn compileInto(gpa: std.mem.Allocator, policy: []const u8, out: fd.File) msg.Error!void {
    const input = std.mem.concat(gpa, u8, &.{ policy, "\n" }) catch return nomem();
    msg.prog = "flong-seccomp";
    defer msg.prog = prog;
    const p = gpa.create(compile.Policy) catch return nomem();
    p.* = .{};
    defer if (p.ctx) |ctx| scmp.release(ctx);
    return compile.compile(p, gpa, .{ .text = input }, .{ .file = out });
}

/// `printf '%s\n' "$dir/$key.bpf"`.
fn printPath(gpa: std.mem.Allocator, path: []const u8) msg.Error!void {
    const line = std.mem.concat(gpa, u8, &.{ path, "\n" }) catch return nomem();
    return msg.check(fd.Stdio.out.writeAll(line), "writing the path", .{});
}

// ---- tests ----

const testing = std.testing;

test "a policy's lines become entries, denies with a minus" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var spec: std.ArrayList(u8) = .empty;
    try parse(a, "# a comment\n\n  \t\n  #indented\n", &spec);
    try testing.expectEqualStrings("", spec.items);
    try parse(a, "allow read  write\ndeny\t@swap\nallow -ptrace\nallow a\x00b", &spec);
    try testing.expectEqualStrings("read\nwrite\n-@swap\n-ptrace\nab\n", spec.items);
    // An empty last line with no newline, NULs only, ends the policy.
    spec.clearRetainingCapacity();
    try parse(a, "allow read\n\x00", &spec);
    try testing.expectEqualStrings("read\n", spec.items);
}

test "each refusal of a policy line" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Each prints its line to the test's stderr.
    for ([_][]const u8{
        "permit read\n",
        "allow\n",
        "allow read # why\n",
        "allow @\n",
        "allow Read\n",
        "allow read\r\n",
        "Allow read\n",
    }) |input| {
        var spec: std.ArrayList(u8) = .empty;
        try testing.expectError(error.Reported, parse(a, input, &spec));
    }
}

test "wordOk is ^@?[a-z0-9_-]+$" {
    for ([_][]const u8{ "read", "@clock", "-x", "_", "@-", "a1_b-2" }) |w| try testing.expect(wordOk(w));
    for ([_][]const u8{ "", "@", "@@x", "Read", "a.b", "read\r", "#", "caf\xc3\xa9" }) |w| try testing.expect(!wordOk(w));
}

test "parentOf is ${dir%/*}" {
    try testing.expectEqualStrings("a/b", parentOf("a/b/c"));
    try testing.expectEqualStrings("cache", parentOf("cache"));
    try testing.expectEqualStrings("", parentOf("/x"));
    try testing.expectEqualStrings("a/b", parentOf("a/b/"));
}
