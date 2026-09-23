//! expand.zig: `flong-seccomp expand DUMP SPEC...`, seccomp/expand.awk
//! (:7-30) exactly, with its output sorted bytewise in place of policy.nix's
//! `| LC_ALL=C sort` (policy.nix:29-30). render and project use the same
//! expansion in process (ZIG.md, "Phase 2").
//!
//! DUMP is the output of `systemd-analyze syscall-filter` with its comment
//! lines dropped (policy.nix:19-21): every group in one file. Each SPEC line
//! is "@group" or "name", with a leading "-" to subtract. It prints the adds
//! minus the subtractions, whatever their order, one per line. An unknown
//! group or name fails with exit 2 and the awk's own line, "unknown group X"
//! or "unknown syscall X", unprefixed (quirk 38), so a typo cannot quietly
//! drop a call from a filter.
//!
//! What the awk does, kept here because a SPEC is a user's file: a record is
//! a line, the last one with or without its newline; fields are split on
//! spaces and tabs, and only the first is read; a "#" and the blanks before
//! it end the line (`sub(/[ \t]*#.*/, "")`, :24); a line left empty is
//! skipped, a line of blanks is the name "" (unknown); a carriage return is
//! part of a name. A group is known only once a member line follows its
//! header, and `@known` is a group like any other: two names in groups,
//! fstatat and newfstat, are in no @known of systemd 261.2. An operand that
//! is a directory is skipped with gawk's warning, and an empty DUMP makes the
//! next operand with a record the dump (`FNR == NR`, :7); a `var=value`
//! operand is a file here, not an assignment.
//!
//! seccomp/expand.awk and seccomp/policy.nix's line numbers here are those
//! of 0dc291c, before the port; the awk and bash were deleted in phase 2 (b).

const std = @import("std");
const sys = @import("sys");
const msg = @import("msg");
const fd = @import("fd");

pub const Error = msg.Error;

fn nomem() msg.Error {
    return msg.fail(.NOMEM, "out of memory", .{});
}

/// awk's default field splitting: blanks are spaces, tabs and newlines.
fn blank(ch: u8) bool {
    return ch == ' ' or ch == '\t' or ch == '\n';
}

/// `$1`: the first field, or "" on a line of blanks.
fn firstField(line: []const u8) []const u8 {
    var i: usize = 0;
    while (i < line.len and blank(line[i])) i += 1;
    var j = i;
    while (j < line.len and !blank(line[j])) j += 1;
    return line[i..j];
}

/// The records of `text`: lines, the last with or without its newline, no
/// record after a final newline.
pub const Records = struct {
    rest: []const u8,

    pub fn next(self: *Records) ?[]const u8 {
        if (self.rest.len == 0) return null;
        if (std.mem.indexOfScalar(u8, self.rest, '\n')) |nl| {
            const line = self.rest[0..nl];
            self.rest = self.rest[nl + 1 ..];
            return line;
        }
        const line = self.rest;
        self.rest = self.rest[self.rest.len..];
        return line;
    }
};

/// The groups and names of a dump (expand.awk:7-16).
pub const Dump = struct {
    /// Each group's members, in the dump's order, "@group" or "name".
    groups: std.StringHashMapUnmanaged(std.ArrayListUnmanaged([]const u8)) = .empty,
    /// Every name that is a member of some group.
    known: std.StringHashMapUnmanaged(void) = .empty,

    /// Reads `text`, which the Dump then points into.
    pub fn parse(gpa: std.mem.Allocator, text: []const u8) error{OutOfMemory}!Dump {
        var d: Dump = .{};
        var group: ?[]const u8 = null;
        var records: Records = .{ .rest = text };
        while (records.next()) |line| {
            if (line.len > 0 and line[0] == '@') {
                group = firstField(line);
                continue;
            }
            // /^[ \t]*#/ or /^[ \t]*$/
            var i: usize = 0;
            while (i < line.len and (line[i] == ' ' or line[i] == '\t')) i += 1;
            if (i == line.len or line[i] == '#') continue;
            const g = group orelse continue;
            const m = firstField(line);
            const entry = try d.groups.getOrPut(gpa, g);
            if (!entry.found_existing) entry.value_ptr.* = .empty;
            try entry.value_ptr.append(gpa, m);
            if (m.len == 0 or m[0] != '@') try d.known.put(gpa, m, {});
        }
        return d;
    }
};

/// One expansion: the adds, the subtractions, and the groups already
/// expanded with each sign (expand.awk:17-30).
pub const Expansion = struct {
    gpa: std.mem.Allocator,
    dump: *const Dump,
    set: std.StringHashMapUnmanaged(void) = .empty,
    del: std.StringHashMapUnmanaged(void) = .empty,
    seen_add: std.StringHashMapUnmanaged(void) = .empty,
    seen_del: std.StringHashMapUnmanaged(void) = .empty,

    pub fn init(gpa: std.mem.Allocator, dump: *const Dump) Expansion {
        return .{ .gpa = gpa, .dump = dump };
    }

    /// One SPEC record (expand.awk:26-27).
    pub fn line(self: *Expansion, record: []const u8) Error!void {
        var text = record;
        if (std.mem.indexOfScalar(u8, text, '#')) |hash| {
            var end = hash;
            while (end > 0 and (text[end - 1] == ' ' or text[end - 1] == '\t')) end -= 1;
            text = text[0..end];
        }
        if (text.len == 0) return;
        const f = firstField(text);
        if (f.len > 0 and f[0] == '-')
            try self.add(f[1..], false)
        else
            try self.add(f, true);
    }

    /// Every record of `text`.
    pub fn lines(self: *Expansion, text: []const u8) Error!void {
        var records: Records = .{ .rest = text };
        while (records.next()) |r| try self.line(r);
    }

    /// add(e, sign) (expand.awk:17-25): a group's members, recursively, each
    /// group once per sign; a name into the adds or the subtractions. The
    /// first unknown one ends the expansion, as the awk's `exit` does.
    fn add(self: *Expansion, e: []const u8, plus: bool) Error!void {
        if (e.len > 0 and e[0] == '@') {
            const members = self.dump.groups.get(e) orelse {
                msg.bare("unknown group {s}", .{e});
                return error.Reported;
            };
            const seen = if (plus) &self.seen_add else &self.seen_del;
            const entry = seen.getOrPut(self.gpa, e) catch return nomem();
            if (entry.found_existing) return;
            for (members.items) |m| try self.add(m, plus);
        } else if (!self.dump.known.contains(e)) {
            msg.bare("unknown syscall {s}", .{e});
            return error.Reported;
        } else {
            (if (plus) &self.set else &self.del).put(self.gpa, e, {}) catch return nomem();
        }
    }

    /// The adds minus the subtractions, sorted bytewise (LC_ALL=C sort).
    pub fn names(self: *const Expansion) Error![]const []const u8 {
        var out: std.ArrayList([]const u8) = .empty;
        var it = self.set.keyIterator();
        while (it.next()) |k| {
            if (!self.del.contains(k.*)) out.append(self.gpa, k.*) catch return nomem();
        }
        std.mem.sort([]const u8, out.items, {}, lessThan);
        return out.items;
    }
};

fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

/// @known's names, sorted: what policy.nix's `known` held (policy.nix:33),
/// taken from the dump render reads.
pub fn known(gpa: std.mem.Allocator, dump: *const Dump) Error![]const []const u8 {
    var e: Expansion = .init(gpa, dump);
    try e.line("@known");
    return e.names();
}

/// A file's bytes, "-" being stdin as awk reads it. Refuses with the path
/// and the errno.
pub fn readPath(gpa: std.mem.Allocator, path: [*:0]const u8) Error![]const u8 {
    const p = std.mem.span(path);
    if (std.mem.eql(u8, p, "-")) {
        return msg.check(fd.readAll(fd.Stdio.in, gpa) catch return nomem(), "{s}", .{p});
    }
    const f = try msg.check(fd.openFile(fd.cwd, path, .{}, 0), "{s}", .{p});
    defer f.close();
    return msg.check(fd.readAll(f, gpa) catch return nomem(), "{s}", .{p});
}

/// An operand as gawk reads it: its bytes, "-" being stdin, or null for a
/// directory, which gawk skips with a warning, its status unchanged. Its
/// refusals are gawk's words (io.c), under the expander's prefix, "fatal:
/// cannot open file `X' for reading" and "fatal: error reading input file
/// `X'", each with the errno's text.
pub fn readOperand(gpa: std.mem.Allocator, path: [*:0]const u8) Error!?[]const u8 {
    const p = std.mem.span(path);
    // The expander's own lines, under project too, as gawk's were.
    const was = msg.prog;
    msg.prog = "flong-seccomp";
    defer msg.prog = was;
    const read = if (std.mem.eql(u8, p, "-"))
        fd.readAll(fd.Stdio.in, gpa)
    else blk: {
        const f = try msg.check(fd.openFile(fd.cwd, path, .{}, 0), "fatal: cannot open file `{s}' for reading", .{p});
        defer f.close();
        break :blk fd.readAll(f, gpa);
    };
    return switch (read catch return nomem()) {
        .ok => |t| t,
        .err => |e| if (e == .ISDIR) {
            msg.say("warning: command line argument `{s}' is a directory: skipped", .{p});
            return null;
        } else msg.fail(e, "fatal: error reading input file `{s}'", .{p}),
    };
}

/// `flong-seccomp expand DUMP SPEC...`: its exit status.
pub fn main(gpa: std.mem.Allocator, args: []const [*:0]const u8) u8 {
    if (args.len < 1) {
        msg.bare("usage: flong-seccomp expand DUMP SPEC...", .{});
        return 2;
    }
    run(gpa, args) catch |err| switch (err) {
        // awk's status for a refusal and for a file it cannot read.
        error.Reported => return 2,
    };
    return 0;
}

fn run(gpa: std.mem.Allocator, args: []const [*:0]const u8) Error!void {
    // The operands up to the dump: an empty DUMP makes the first SPEC with
    // a record the dump, as in awk.
    var first: []const u8 = "";
    var i: usize = 0;
    while (i < args.len and first.len == 0) : (i += 1) first = (try readOperand(gpa, args[i])) orelse "";
    const dump = Dump.parse(gpa, first) catch return nomem();
    var e: Expansion = .init(gpa, &dump);
    // Each SPEC in order, read when its turn comes, as awk reads them.
    for (args[i..]) |spec| try e.lines((try readOperand(gpa, spec)) orelse "");
    const names = try e.names();
    var out: std.ArrayList(u8) = .empty;
    for (names) |n| {
        out.appendSlice(gpa, n) catch return nomem();
        out.append(gpa, '\n') catch return nomem();
    }
    try msg.check(fd.Stdio.out.writeAll(out.items), "writing the names", .{});
}

// ---- tests ----

const testing = std.testing;

const test_dump =
    \\@default
    \\    @sandbox
    \\    brk
    \\    exit
    \\
    \\@sandbox
    \\    seccomp
    \\
    \\@empty
    \\@io
    \\    read # the first
    \\    write
    \\    @nosuch
    \\
    \\@known
    \\    brk
    \\    exit
    \\    read
    \\    seccomp
    \\    write
    \\    fstatat
;

test "firstField and Records read as awk does" {
    try testing.expectEqualStrings("read", firstField("  \tread  write"));
    try testing.expectEqualStrings("", firstField("   "));
    try testing.expectEqualStrings("read\r", firstField("read\r"));
    var r: Records = .{ .rest = "a\n\nb" };
    try testing.expectEqualStrings("a", r.next().?);
    try testing.expectEqualStrings("", r.next().?);
    try testing.expectEqualStrings("b", r.next().?);
    try testing.expectEqual(@as(?[]const u8, null), r.next());
    var one: Records = .{ .rest = "a\n" };
    try testing.expectEqualStrings("a", one.next().?);
    try testing.expectEqual(@as(?[]const u8, null), one.next());
}

test "a dump's groups and names" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const d = try Dump.parse(arena.allocator(), test_dump);
    try testing.expect(d.groups.get("@empty") == null);
    try testing.expectEqual(@as(usize, 3), d.groups.get("@default").?.items.len);
    try testing.expect(d.known.contains("read"));
    try testing.expect(d.known.contains("fstatat"));
    try testing.expect(!d.known.contains("@nosuch"));

    var e: Expansion = .init(arena.allocator(), &d);
    try e.lines("@default\n-exit\n# a comment\n\t# indented\nwrite close # two words\n");
    const names = try e.names();
    try testing.expectEqual(@as(usize, 3), names.len);
    try testing.expectEqualStrings("brk", names[0]);
    try testing.expectEqualStrings("seccomp", names[1]);
    try testing.expectEqualStrings("write", names[2]);

    // A subtraction wins whatever the order, and repeats of a group are one.
    var s: Expansion = .init(arena.allocator(), &d);
    try s.lines("-brk\n@default\n@default\n-@sandbox");
    const left = try s.names();
    try testing.expectEqual(@as(usize, 1), left.len);
    try testing.expectEqualStrings("exit", left[0]);

    const k = try known(arena.allocator(), &d);
    try testing.expectEqual(@as(usize, 6), k.len);
    try testing.expectEqualStrings("brk", k[0]);
    try testing.expectEqualStrings("write", k[5]);
}

test "unknown groups and names are refused" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const d = try Dump.parse(arena.allocator(), test_dump);
    // Each refusal prints its line to the test's stderr.
    for ([_][]const u8{ "@empty", "@io", "no_such_call", "   ", "-", "read\r", "-@nosuch" }) |spec| {
        var e: Expansion = .init(arena.allocator(), &d);
        try testing.expectError(error.Reported, e.lines(spec));
    }
}
