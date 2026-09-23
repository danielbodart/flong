//! compile.zig: compiles a policy on stdin to one BPF program on stdout. A
//! whole port of seccomp/flong-seccomp.c, function by function and in its
//! order; each function cites the C it ports.
//!
//!   default N|allow           first directive, once: the action for any call
//!                             no rule names, ERRNO(N) or ALLOW
//!   allow NAME [CMP...]       ALLOW
//!   errno N NAME [CMP...]     ERRNO(N), N from 1 to 4095
//!   log NAME [CMP...]         allowed, and logged by the kernel
//!   CMP is aI:OP:VALUE, OP one of eq ne lt le gt ge, or aI:masked_eq:VALUE:MASK
//!
//! libseccomp keeps the first of two unconditional rules for one call and
//! lets an unconditional rule swallow conditional ones, silently. Both are
//! refused here instead, so the filter says what the policy says. Nothing
//! reaches stdout unless the whole policy is accepted: the export is the
//! last step.
//!
//! The filter's bytes are libseccomp's, so they stay the C's only if the
//! same calls are made with the same values in the same order: init, the
//! i386 and x32 arches, the optimisation, then per rule a name resolved and
//! one rule added, then the export (ZIG.md, stop condition 2). Every message
//! is the C's, whole (msg.zig's `whole` mode, which main sets), since a
//! refusal quotes a word of up to 4095 bytes (flong-seccomp.c:75).

const std = @import("std");
const sys = @import("sys");
const msg = @import("msg");
const num = @import("num");
const scmp = @import("scmp.zig");

const max_line = 4095;
const max_words = 16;
const max_cmps = 6;
const max_nr = 4096;

// seen[nr] bits: the call has an unconditional rule, or a conditional one.
const unconditional: u8 = 1;
const conditional: u8 = 2;

/// struct policy (flong-seccomp.c:32-38). The C's counters are unsigned
/// ints, printed with %u.
pub const Policy = struct {
    ctx: ?*scmp.Filter = null,
    line: u32 = 0,
    rules: u32 = 0,
    unknown: u32 = 0,
    seen: [max_nr]u8 = @splat(0),
};

const ops = [_]struct { name: []const u8, op: scmp.Op }{
    .{ .name = "eq", .op = .eq },
    .{ .name = "ne", .op = .ne },
    .{ .name = "lt", .op = .lt },
    .{ .name = "le", .op = .le },
    .{ .name = "gt", .op = .gt },
    .{ .name = "ge", .op = .ge },
    .{ .name = "masked_eq", .op = .masked_eq },
};

/// The kernel reads these arguments as 32-bit ints, while a filter compares
/// all 64 bits: a comparison that looks at bits 32-63 is bypassed by setting
/// them. So they are compared only with masked_eq under a 32-bit mask. The
/// value is a bitmask of argument indices (flong-seccomp.c:53-70).
const int_args = [_]struct { name: []const u8, args: u32 }{
    .{ .name = "ioctl", .args = 0x03 },
    .{ .name = "fcntl", .args = 0x03 },
    .{ .name = "socket", .args = 0x07 },
    .{ .name = "socketpair", .args = 0x07 },
    .{ .name = "setns", .args = 0x03 },
    .{ .name = "prctl", .args = 0x01 },
    .{ .name = "personality", .args = 0x01 },
    .{ .name = "kill", .args = 0x03 },
    .{ .name = "tgkill", .args = 0x07 },
};

/// flong-seccomp.c:72-79.
fn refuse(p: *const Policy, what: []const u8, word: ?[]const u8) msg.Error {
    if (word) |w| return msg.refuse("line {d}: {s}: {s}", .{ p.line, what, w });
    return msg.refuse("line {d}: {s}", .{ p.line, what });
}

/// flong-seccomp.c:81-87: libseccomp's errno, as its text.
fn failed(p: *const Policy, what: []const u8, word: ?[]const u8, e: sys.E) msg.Error {
    if (word) |w| return msg.fail(e, "line {d}: {s} {s}", .{ p.line, what, w });
    return msg.fail(e, "line {d}: {s}", .{ p.line, what });
}

/// Reads a decimal errno from 1 to 4095, the range SCMP_ACT_ERRNO carries
/// (flong-seccomp.c:89-107).
fn parseErrno(s: []const u8) ?u32 {
    var v: u32 = 0;
    if (s.len == 0) return null;
    for (s) |ch| {
        if (ch < '0' or ch > '9') return null;
        v = v * 10 + (ch - '0');
        if (v > 4095) return null;
    }
    if (v < 1) return null;
    return v;
}

/// Parses aI:OP:VALUE or aI:masked_eq:VALUE:MASK (flong-seccomp.c:123-160).
/// The C copies the word to cut it at the colons; the slices here leave it
/// whole without one. Its length check (:130) cannot fail, since a line is
/// at most 4095 bytes. Values are parse_number's (:109-121), which is
/// num.strtoullBase0 (quirk 15).
fn parseCmp(word: []const u8) ?scmp.ArgCmp {
    if (word.len < 3 or word[0] != 'a' or word[1] < '0' or word[1] > '5' or word[2] != ':')
        return null;
    var c: scmp.ArgCmp = .{ .arg = word[1] - '0', .op = .eq, .datum_a = 0, .datum_b = 0 };
    const rest = word[3..];
    const colon = std.mem.indexOfScalar(u8, rest, ':') orelse return null;
    const op = rest[0..colon];
    var value = rest[colon + 1 ..];
    var mask: ?[]const u8 = null;
    if (std.mem.indexOfScalar(u8, value, ':')) |m| {
        mask = value[m + 1 ..];
        value = value[0..m];
    }
    const found = for (ops) |o| {
        if (std.mem.eql(u8, o.name, op)) break o.op;
    } else return null;
    c.op = found;
    if (c.op == .masked_eq) {
        // libseccomp takes the mask first and the value second.
        const m = mask orelse return null;
        c.datum_a = num.strtoullBase0(m) orelse return null;
        c.datum_b = num.strtoullBase0(value) orelse return null;
    } else {
        if (mask != null) return null;
        c.datum_a = num.strtoullBase0(value) orelse return null;
        c.datum_b = 0;
    }
    return c;
}

/// flong-seccomp.c:162-170.
fn intArgsOf(name: []const u8) u32 {
    for (int_args) |i| {
        if (std.mem.eql(u8, i.name, name)) return i.args;
    }
    return 0;
}

/// Starts the filter from `default N|allow` (flong-seccomp.c:172-203). The
/// x86_64 filter covers i386 and x32 too, because a payload can enter the
/// kernel through either ABI and nspawn's own filter covers all three.
fn start(p: *Policy, w: []const [:0]const u8) msg.Error!void {
    if (w.len != 2)
        return refuse(p, "the first directive must be `default N|allow`", null);
    const action = if (std.mem.eql(u8, w[1], "allow"))
        scmp.act_allow
    else if (parseErrno(w[1])) |err|
        scmp.actErrno(err)
    else
        return refuse(p, "default is neither allow nor an errno from 1 to 4095", w[1]);
    p.ctx = scmp.init(action);
    const ctx = p.ctx orelse return refuse(p, "libseccomp could not start a filter", null);
    if (scmp.archNative() == scmp.arch_x86_64) {
        if (scmp.archAdd(ctx, scmp.arch_x86)) |e|
            return failed(p, "libseccomp could not add the i386 arch", null, e);
        if (scmp.archAdd(ctx, scmp.arch_x32)) |e|
            return failed(p, "libseccomp could not add the x32 arch", null, e);
    }
    if (scmp.attrSet(ctx, .ctl_optimize, 2)) |e|
        return failed(p, "libseccomp could not set the binary-tree optimisation", null, e);
}

/// flong-seccomp.c:205-268.
fn rule(p: *Policy, ctx: *scmp.Filter, w: []const [:0]const u8) msg.Error!void {
    var cmp: [max_cmps]scmp.ArgCmp = undefined;
    var ncmp: usize = 0;
    var action: u32 = undefined;
    var k: usize = undefined;

    if (std.mem.eql(u8, w[0], "allow")) {
        action = scmp.act_allow;
        k = 1;
    } else if (std.mem.eql(u8, w[0], "log")) {
        action = scmp.act_log;
        k = 1;
    } else if (std.mem.eql(u8, w[0], "errno")) {
        if (w.len < 2)
            return refuse(p, "errno has no number", null);
        const err = parseErrno(w[1]) orelse
            return refuse(p, "errno is not a number from 1 to 4095", w[1]);
        action = scmp.actErrno(err);
        k = 2;
    } else if (std.mem.eql(u8, w[0], "default")) {
        return refuse(p, "default appears again", null);
    } else {
        return refuse(p, "unknown directive", w[0]);
    }
    if (k >= w.len)
        return refuse(p, "missing syscall name", null);
    const name = w[k];
    const ints = intArgsOf(name);
    for (w[k + 1 ..]) |word| {
        if (ncmp == max_cmps)
            return refuse(p, "more than 6 argument comparisons", word);
        cmp[ncmp] = parseCmp(word) orelse
            return refuse(p, "bad argument comparison", word);
        // Quirk 14: a mask of 0 passes.
        if (ints & (@as(u32, 1) << @intCast(cmp[ncmp].arg)) != 0 and
            (cmp[ncmp].op != .masked_eq or cmp[ncmp].datum_a > 0xffffffff))
            return refuse(p, "an int argument needs masked_eq with a mask of at most 0xffffffff", word);
        ncmp += 1;
    }

    // systemd lists names libseccomp does not know yet; nspawn skips them
    // too, and the count shows the skew.
    const nr = scmp.resolveName(name.ptr);
    if (nr == scmp.nr_error) {
        p.unknown +%= 1;
        return;
    }
    // Only native numbers are tracked: libseccomp 2.6.1 gives two ppc-only
    // names one negative pseudo number (quirk 13).
    if (nr >= 0 and nr < max_nr) {
        const i: usize = @intCast(nr);
        if (p.seen[i] & unconditional != 0 or (ncmp == 0 and p.seen[i] != 0))
            return refuse(p, "named twice, and one rule is unconditional", name);
        p.seen[i] |= if (ncmp != 0) conditional else unconditional;
    }
    if (scmp.ruleAddArray(ctx, action, nr, cmp[0..ncmp])) |e| {
        // libseccomp refuses a rule that would change nothing.
        if (e == .ACCES)
            return refuse(p, "the rule's action is the default's", name);
        return failed(p, "libseccomp refused the rule for", name, e);
    }
    p.rules +%= 1;
}

/// strtok(3)'s delimiters (flong-seccomp.c:276, 280).
fn blank(ch: u8) bool {
    return ch == ' ' or ch == '\t' or ch == '\r' or ch == '\n';
}

/// Splits one line on blanks and applies it (flong-seccomp.c:270-291).
/// Like strtok, this ends the line at its first NUL and writes a NUL after
/// each word, so a word is a C string for libseccomp.
fn directive(p: *Policy, buf: [:0]u8) msg.Error!void {
    const line: [:0]u8 = std.mem.sliceTo(buf, 0);
    var w: [max_words][:0]const u8 = undefined;
    var n: usize = 0;
    var i: usize = 0;
    while (true) {
        while (i < line.len and blank(line[i])) i += 1;
        if (i == line.len) break;
        const from = i;
        while (i < line.len and !blank(line[i])) i += 1;
        const to = i;
        if (i < line.len) {
            line[i] = 0;
            i += 1;
        }
        const t: [:0]const u8 = line[from..to :0];
        // A comment is prose, so the word limit does not apply to it.
        if (n == 0 and t[0] == '#') return;
        if (n == max_words)
            return refuse(p, "more than 16 words", null);
        w[n] = t;
        n += 1;
    }
    if (n == 0) return;
    const ctx = p.ctx orelse {
        if (!std.mem.eql(u8, w[0], "default"))
            return refuse(p, "the first directive must be `default N|allow`", w[0]);
        return start(p, w[0..n]);
    };
    return rule(p, ctx, w[0..n]);
}

/// Reads stdin as getline(3) does, a line at a time, each without its
/// newline and the last one with or without (flong-seccomp.c:293-325). A
/// line is kept only up to max_line bytes and counted beyond, since a
/// longer one is refused whatever it holds: the C's getline grew its buffer
/// to the whole line, which no answer depended on. The one buffer is the
/// arena's, taken before anything is read.
pub fn compile(p: *Policy, gpa: std.mem.Allocator) msg.Error!void {
    const line = gpa.alloc(u8, max_line + 1) catch
        return msg.fail(.NOMEM, "reading the policy", .{});
    var len: usize = 0; // the line's length so far, which may exceed max_line
    var pending = false; // bytes of a line read, its newline not yet
    var chunk: [4096]u8 = undefined;
    var read_error: ?sys.E = null;

    reading: while (true) {
        const got = switch (sys.read(0, &chunk)) {
            .ok => |n| n,
            .err => |e| {
                read_error = e;
                break :reading;
            },
        };
        if (got == 0) break;
        var rest = chunk[0..got];
        while (rest.len > 0) {
            const nl = std.mem.indexOfScalar(u8, rest, '\n');
            const part = rest[0 .. nl orelse rest.len];
            if (len < max_line) {
                const keep = @min(part.len, max_line - len);
                @memcpy(line[len..][0..keep], part[0..keep]);
            }
            len += part.len;
            pending = true;
            if (nl) |at| {
                try apply(p, line, len);
                len = 0;
                pending = false;
                rest = rest[at + 1 ..];
            } else break;
        }
    }
    // getline returns a last line with no newline, at the end of the file
    // or before a read error (glibc's getdelim returns what it has).
    if (pending) try apply(p, line, len);
    if (read_error) |e|
        return msg.fail(e, "reading the policy", .{});
    const ctx = p.ctx orelse return refuse(p, "empty policy: no default", null);
    if (scmp.exportBpf(ctx, .stdout)) |e|
        return msg.fail(e, "libseccomp could not export the filter", .{});
    msg.say("{d} rules, {d} names libseccomp does not know", .{ p.rules, p.unknown });
}

/// One line of `len` bytes, of which `line` holds the first max_line at
/// most, with room for a NUL after them (flong-seccomp.c:301-307).
fn apply(p: *Policy, line: []u8, len: usize) msg.Error!void {
    p.line +%= 1;
    if (len > max_line)
        return refuse(p, "longer than 4095 bytes", null);
    line[len] = 0;
    return directive(p, line[0..len :0]);
}

// ---- tests ----

const testing = std.testing;

test "parseErrno takes 1 to 4095 in decimal" {
    try testing.expectEqual(@as(?u32, 1), parseErrno("1"));
    try testing.expectEqual(@as(?u32, 4095), parseErrno("4095"));
    try testing.expectEqual(@as(?u32, 10), parseErrno("010"));
    try testing.expectEqual(@as(?u32, 4094), parseErrno("0004094"));
    for ([_][]const u8{ "", "0", "000", "4096", "99999999999", "+1", "-1", "0x1", "1_0", "EPERM" }) |s|
        try testing.expectEqual(@as(?u32, null), parseErrno(s));
}

test "parseCmp reads each form" {
    const c = parseCmp("a1:masked_eq:0x10:0xff").?;
    try testing.expectEqual(@as(c_uint, 1), c.arg);
    try testing.expectEqual(scmp.Op.masked_eq, c.op);
    try testing.expectEqual(@as(u64, 0xff), c.datum_a);
    try testing.expectEqual(@as(u64, 0x10), c.datum_b);
    const d = parseCmp("a5:ge:010").?;
    try testing.expectEqual(@as(c_uint, 5), d.arg);
    try testing.expectEqual(scmp.Op.ge, d.op);
    try testing.expectEqual(@as(u64, 8), d.datum_a);
    try testing.expectEqual(@as(u64, 0), d.datum_b);
    for ([_][]const u8{
        "",          "a",      "a0",              "a0:",     "a6:eq:1",        "b0:eq:1",            "a0eq:1",
        "a0:eq",     "a0:eq:", "a0:eq:1:2",       "a0:EQ:1", "a0:masked_eq:1", "a0:masked_eq:1:2:3", "a0:eq:+1",
        "a0:eq:1_0", "a0::1",  "a0:masked_eq::1",
    }) |s| try testing.expectEqual(@as(?scmp.ArgCmp, null), parseCmp(s));
}

test "intArgsOf" {
    try testing.expectEqual(@as(u32, 0x07), intArgsOf("tgkill"));
    try testing.expectEqual(@as(u32, 0), intArgsOf("read"));
}
