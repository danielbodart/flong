//! render.zig: `flong-seccomp render DUMP NAMES DENY`, the tier filter's
//! policy, as flong-seccomp-render printed it (policy.nix:81-108): the
//! names allowed, the rest of @known refused with DENY or logged, and
//! everything else ENOSYS. DENY is 1, 13, 38 or log. The same code renders
//! at build time and, through project, at launch, so both compile the same
//! text. @known now comes from DUMP, which policy.nix's `known` held
//! (policy.nix:33).
//!
//! Its messages keep the bash's prefix, "flong-seccomp-render:" (quirk 38);
//! a DENY that is none of the four is refused before NAMES is read, exit 2.
//!
//! NAMES is read as `mapfile -t` reads it (policy.nix:98): a line per name,
//! the last with or without its newline, each cut at a NUL as bash's C
//! strings are. The refusals are `comm -23 KNOWN NAMES` (:102-103), its merge
//! of two sorted lists, so a NAMES that is not sorted gives what comm gives:
//! its lines, its two warnings, and exit 1 under the script's pipefail.
//!
//! seccomp/policy.nix's line numbers here are those of 0dc291c, before the
//! port; the bash was deleted in phase 2 (b).

const std = @import("std");
const sys = @import("sys");
const msg = @import("msg");
const fd = @import("fd");
const expand = @import("expand.zig");

pub const prog = "flong-seccomp-render";

fn nomem() msg.Error {
    return msg.fail(.NOMEM, "out of memory", .{});
}

/// What a @known call outside the names gets.
pub const Deny = enum {
    eperm,
    eacces,
    enosys,
    log,

    /// policy.nix:89-95: exactly "1", "13", "38" or "log".
    pub fn parse(s: []const u8) ?Deny {
        const words = [_]struct { []const u8, Deny }{
            .{ "1", .eperm }, .{ "13", .eacces }, .{ "38", .enosys }, .{ "log", .log },
        };
        for (words) |w| {
            if (std.mem.eql(u8, s, w[0])) return w[1];
        }
        return null;
    }

    fn rule(d: Deny) []const u8 {
        return switch (d) {
            .eperm => "errno 1",
            .eacces => "errno 13",
            .enosys => "errno 38",
            .log => "log",
        };
    }
};

/// The names of a NAMES file, as `mapfile -t` makes them.
pub fn mapfile(gpa: std.mem.Allocator, text: []const u8) error{OutOfMemory}![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var records: expand.Records = .{ .rest = text };
    while (records.next()) |r| try out.append(gpa, std.mem.sliceTo(r, 0));
    return out.toOwnedSlice(gpa);
}

/// The policy: "default 38", an allow per name, then a DENY rule per @known
/// name not among them, unless DENY is 38, the default already (:100-101).
/// Returns false when comm would have found either list out of order, having
/// said so as comm does.
pub fn render(gpa: std.mem.Allocator, out: *std.ArrayList(u8), known: []const []const u8, names: []const []const u8, deny: Deny) error{OutOfMemory}!bool {
    try out.appendSlice(gpa, "default 38\n");
    for (names) |n| {
        try out.appendSlice(gpa, "allow ");
        try out.appendSlice(gpa, n);
        try out.append(gpa, '\n');
    }
    if (deny == .enosys) return true;
    // `printf '%s\n' "${names[@]}"` with no names prints one empty line.
    const second: []const []const u8 = if (names.len == 0) &.{""} else names;
    var c: Comm = .{ .lists = .{ known, second } };
    while (c.next()) |n| {
        try out.appendSlice(gpa, deny.rule());
        try out.append(gpa, ' ');
        try out.appendSlice(gpa, n);
        try out.append(gpa, '\n');
    }
    if (c.warned[0] or c.warned[1]) {
        msg.bare("comm: input is not in sorted order", .{});
        return false;
    }
    return true;
}

/// coreutils' comm -23 under LC_ALL=C (comm.c, compare_files): the lines
/// of the first list the second lacks, by a merge that assumes both sorted,
/// with its order checks, which warn once a line has been unpairable.
const Comm = struct {
    lists: [2][]const []const u8,
    at: [2]usize = .{ 0, 0 },
    seen_unpairable: bool = false,
    warned: [2]bool = .{ false, false },

    fn order(a: []const u8, b: []const u8) std.math.Order {
        return std.mem.order(u8, a, b);
    }

    fn check(c: *Comm, i: usize, prev: []const u8, cur: []const u8) void {
        if (!c.seen_unpairable or c.warned[i]) return;
        if (order(prev, cur) == .gt) {
            if (i == 0) msg.bare("comm: file 1 is not in sorted order", .{}) else msg.bare("comm: file 2 is not in sorted order", .{});
            c.warned[i] = true;
        }
    }

    /// Steps list i past its line, rechecking as comm does: the next pair,
    /// or at the end the last pair, since an unpairable line may have been
    /// seen since it was first checked.
    fn step(c: *Comm, i: usize) void {
        const l = c.lists[i];
        const k = c.at[i];
        c.at[i] = k + 1;
        if (k + 1 < l.len) {
            c.check(i, l[k], l[k + 1]);
        } else if (l.len >= 2) {
            c.check(i, l[l.len - 2], l[l.len - 1]);
        }
    }

    /// The next line of column 1, or null at the end of both lists.
    fn next(c: *Comm) ?[]const u8 {
        while (c.at[0] < c.lists[0].len or c.at[1] < c.lists[1].len) {
            const o: std.math.Order = if (c.at[0] >= c.lists[0].len)
                .gt
            else if (c.at[1] >= c.lists[1].len)
                .lt
            else
                order(c.lists[0][c.at[0]], c.lists[1][c.at[1]]);
            var out: ?[]const u8 = null;
            if (o != .eq) {
                c.seen_unpairable = true;
                if (o == .lt) out = c.lists[0][c.at[0]];
            }
            if (o != .gt) c.step(0);
            if (o != .lt) c.step(1);
            if (out) |line| return line;
        }
        return null;
    }
};

/// `flong-seccomp render DUMP NAMES DENY`: its exit status.
pub fn main(gpa: std.mem.Allocator, args: []const [*:0]const u8) u8 {
    if (args.len != 3) {
        msg.bare("usage: flong-seccomp render DUMP NAMES 1|13|38|log", .{});
        return 2;
    }
    msg.prog = prog;
    const deny = Deny.parse(std.mem.span(args[2])) orelse {
        msg.say("not 1, 13, 38 or log: {s}", .{args[2]});
        return 2;
    };
    return run(gpa, args[0], args[1], deny) catch |err| switch (err) {
        error.Reported => 1,
    };
}

fn run(gpa: std.mem.Allocator, dump_path: [*:0]const u8, names_path: [*:0]const u8, deny: Deny) msg.Error!u8 {
    // NAMES is a path even when it is "-", as bash's `<"$1"` opens it.
    const names_file = try msg.check(fd.openFile(fd.cwd, names_path, .{}, 0), "{s}", .{names_path});
    // mapfile takes a read error for the end, silently: a directory is no
    // names.
    const text: []const u8 = switch (fd.readAll(names_file, gpa) catch return nomem()) {
        .ok => |t| t,
        .err => "",
    };
    names_file.close();
    const names = mapfile(gpa, text) catch return nomem();
    const known: []const []const u8 = if (deny == .enosys) &.{} else blk: {
        const dump = expand.Dump.parse(gpa, try expand.readPath(gpa, dump_path)) catch return nomem();
        break :blk try expand.known(gpa, &dump);
    };
    var out: std.ArrayList(u8) = .empty;
    const sorted = render(gpa, &out, known, names, deny) catch return nomem();
    try msg.check(fd.Stdio.out.writeAll(out.items), "writing the policy", .{});
    return if (sorted) 0 else 1;
}

// ---- tests ----

const testing = std.testing;

fn rendered(known: []const []const u8, names: []const []const u8, deny: Deny) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    _ = try render(testing.allocator, &out, known, names, deny);
    return out.toOwnedSlice(testing.allocator);
}

test "a policy: the names allowed, the rest of @known denied" {
    const known = [_][]const u8{ "brk", "exit", "read", "write" };
    const text = try rendered(&known, &.{ "exit", "read", "zzz" }, .eacces);
    defer testing.allocator.free(text);
    try testing.expectEqualStrings(
        "default 38\nallow exit\nallow read\nallow zzz\nerrno 13 brk\nerrno 13 write\n",
        text,
    );
    const enosys = try rendered(&known, &.{"read"}, .enosys);
    defer testing.allocator.free(enosys);
    try testing.expectEqualStrings("default 38\nallow read\n", enosys);
    const none = try rendered(&known, &.{}, .log);
    defer testing.allocator.free(none);
    try testing.expectEqualStrings("default 38\nlog brk\nlog exit\nlog read\nlog write\n", none);
    // An empty name, as a project that denies everything renders it
    // (quirk 35).
    const empty = try rendered(&known, &.{""}, .eperm);
    defer testing.allocator.free(empty);
    try testing.expectEqualStrings("default 38\nallow \nerrno 1 brk\nerrno 1 exit\nerrno 1 read\nerrno 1 write\n", empty);
}

test "comm's merge of an unsorted NAMES, and its warning" {
    const known = [_][]const u8{ "a", "b", "c", "d" };
    // comm pairs "c", then meets "a" after "c": unpairable lines follow, and
    // it says file 2 is out of order, and gives what its merge gives.
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    const sorted = try render(testing.allocator, &out, &known, &.{ "c", "a" }, .eperm);
    try testing.expect(!sorted);
    try testing.expectEqualStrings("default 38\nallow c\nallow a\nerrno 1 a\nerrno 1 b\nerrno 1 d\n", out.items);
}

test "mapfile cuts at a NUL and keeps an empty line" {
    const names = try mapfile(testing.allocator, "ab\x00cd\n\nx");
    defer testing.allocator.free(names);
    try testing.expectEqual(@as(usize, 3), names.len);
    try testing.expectEqualStrings("ab", names[0]);
    try testing.expectEqualStrings("", names[1]);
    try testing.expectEqualStrings("x", names[2]);
}

test "Deny takes exactly 1, 13, 38 and log" {
    try testing.expectEqual(Deny.eperm, Deny.parse("1").?);
    try testing.expectEqual(Deny.log, Deny.parse("log").?);
    for ([_][]const u8{ "", "01", " 1", "2", "LOG", "38 " }) |s| try testing.expectEqual(@as(?Deny, null), Deny.parse(s));
}
