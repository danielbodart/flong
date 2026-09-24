//! flong check (STANDALONE.md, "The declaration"): judges a declaration
//! file before anything launches it, as each declaration's derivation does,
//! so a bad one fails the build with a line number rather than a launch.
//!
//!   flong check DECL.zon
//!
//! The parse is decl.zig's, the one `flong launch` reads with, so the two
//! cannot read a file differently: at most `decl.max_bytes`, into one
//! arena, and every parse error said as `flong check: PATH:LINE:COL: why`.
//! What parses is then judged by `validate`, which collects every refusal
//! rather than stopping at the first, and each is said as
//! `flong check: PATH: why`. Exit 0 when there is none, 1 when there is
//! any or the file cannot be read or parsed, 2 on a usage error.
//!
//! `validate` holds what module.nix's assertions judged of a declaration
//! and the launcher can judge without its caller: clean paths, a
//! destination mounted twice, the mask depth rule against the
//! declaration's own writable binds, sources reaching what no session may
//! reach, devices, the seccomp settings that need a tier, the container's
//! ids; with what Nix's types judged and a ZON file must be told: the
//! patterns and ranges decl.zig declares, commands that are not empty, and
//! strings without a NUL byte, which ZON can write and which an argv, a
//! path or the environment would cut short.
//! Each message is the assertion's, in one line, naming the declaration as
//! `flong.NAME`. Like the assertions, the path checks are lexical, on the
//! declaration's spelling: the launcher's canonical checks at launch stay
//! the authority.
//!
//! The file is a trust boundary (decl.zig), so nothing here may panic on
//! any declaration that parses: tests/zig/fuzz.zig holds it to that.

const std = @import("std");
const sys = @import("sys");
const msg = @import("msg");
const decl = @import("decl");
const decl_docs = @import("decl_docs");
const spec = @import("spec");

const Allocator = std.mem.Allocator;
const Declaration = decl.Declaration;

/// A usage error, as flong-seccomp's (quirk 16).
const usage_status = 2;
/// Any refusal, and a file that cannot be read or parsed.
const refused = 1;

const usage = "usage: flong check DECL.zon";

/// Names a declaration cannot have: its command is a link to flong named
/// after it (STANDALONE.md, "The declaration's command"), and flong reads
/// argv[0]'s basename as a subcommand first, so the link would run the
/// subcommand. `flong` itself reads its first argument instead. main.zig's
/// tests hold every subcommand to being here; `list` is to come.
pub const reserved = [_][]const u8{ "flong", "launch", "init", "sweeper", "version", "help", "check", "schema", "list" };

/// `argv` is the kernel's, from the subcommand's word on.
pub fn main(argv: []const [*:0]const u8) noreturn {
    msg.prog = "flong check";
    // A refusal lists every path it is about, however long.
    msg.mode = .whole;
    if (argv.len != 2) {
        msg.bare(usage, .{});
        sys.exitGroup(usage_status);
    }
    const path = std.mem.span(argv[1]);
    // One arena, never freed: the process ends with the check.
    var arena_state: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    const arena = arena_state.allocator();
    const d = decl.load(arena, path) catch |err| switch (err) {
        error.Reported => sys.exitGroup(refused),
        error.OutOfMemory => outOfMemory(),
    };
    const refusals = validate(arena, &d) catch outOfMemory();
    for (refusals) |r| msg.say("{s}: {s}", .{ path, r });
    sys.exitGroup(if (refusals.len == 0) 0 else refused);
}

fn outOfMemory() noreturn {
    msg.say("out of memory", .{});
    sys.exitGroup(refused);
}

/// Every refusal of `d`, in the order module.nix asserted them, after the
/// name's and the types'; each names the declaration by its `name`, as
/// `flong.NAME`. Empty when there is none. Each is one line, in `arena`.
pub fn validate(arena: Allocator, d: *const Declaration) Allocator.Error![]const []const u8 {
    var c: Checker = .{ .arena = arena, .d = d, .n = d.name };
    try c.reservedName();
    try c.walk(Declaration, d.*, "", false, .{});
    try c.sources();
    try c.depth();
    try c.devices();
    try c.devBinds();
    try c.ids();
    try c.clean();
    try c.twice();
    try c.noTier();
    return c.out.items;
}

const Checker = struct {
    arena: Allocator,
    d: *const Declaration,
    n: []const u8,
    out: std.ArrayList([]const u8) = .empty,

    fn say(c: *Checker, comptime fmt: []const u8, args: anytype) Allocator.Error!void {
        try c.out.append(c.arena, try std.fmt.allocPrint(c.arena, fmt, args));
    }

    fn reservedName(c: *Checker) Allocator.Error!void {
        for (reserved) |r| {
            if (!std.mem.eql(u8, r, c.n)) continue;
            const what = if (std.mem.eql(u8, r, "flong")) "flong itself" else "flong's own subcommand";
            return c.say("flong.{s} cannot be declared under that name: its command is a link to flong named after it, and running it would run {s} rather than the declaration. Name it something else.", .{ c.n, what });
        }
    }

    /// What decl.zig's types say and ZON cannot: a command is not empty,
    /// and a field with a pattern or a range (`patterns`, `ranges` on its
    /// container, as decl_docs.zig reads them) keeps to it. `path` is the
    /// option's, a list's elements under the list's; `in_list` says "has"
    /// of an element where a field "is".
    fn walk(c: *Checker, comptime T: type, v: T, comptime path: []const u8, comptime in_list: bool, comptime m: decl_docs.Meta) Allocator.Error!void {
        const verb = if (in_list) "has" else "is";
        if (T == decl.Command) {
            if (v.len == 0) try c.say("flong.{s}.{s} {s} an empty command, which names no program to run.", .{ c.n, path, verb });
            for (v) |word| if (hasNul(word))
                return c.say("flong.{s}.{s} {s} a command with a NUL byte in a word. A word ends at its first NUL, so the program would be given a different argument than the one declared.", .{ c.n, path, verb });
            return;
        }
        switch (@typeInfo(T)) {
            .optional => |o| if (v) |x| try c.walk(o.child, x, path, in_list, m),
            .bool, .@"enum", .void => {},
            .int => if (m.range) |r| {
                if (v < r[0] or v > r[1])
                    try c.say("flong.{s}.{s} {s} {d}, outside {d}-{d}.", .{ c.n, path, verb, v, r[0], r[1] });
            },
            .pointer => |p| if (p.child == u8) {
                // Said without the string, which the message would cut
                // short at the NUL as the launch would.
                if (hasNul(v))
                    return c.say("flong.{s}.{s} {s} a string with a NUL byte in it. A path, an argument or an environment value ends at its first NUL, so the launch would read a different one than the one declared.", .{ c.n, path, verb });
                if (m.pattern) |pattern| {
                    comptime supported(pattern);
                    if (!matches(pattern, v))
                        try c.say("flong.{s}.{s} {s} \"{s}\", which is not a string matching the pattern {s}.", .{ c.n, path, verb, v, pattern });
                }
            } else {
                for (v) |x| try c.walk(p.child, x, path, true, m);
            },
            .@"struct" => |s| inline for (s.fields) |f| {
                const sub = if (path.len == 0) f.name else path ++ "." ++ f.name;
                try c.walk(f.type, @field(v, f.name), sub, false, decl_docs.metaOf(T, f.name));
            },
            .@"union" => switch (v) {
                inline else => |x, tag| try c.walk(@TypeOf(x), x, path, in_list, decl_docs.metaOf(T, @tagName(tag))),
            },
            else => @compileError(path ++ ": nothing to check of " ++ @typeName(T)),
        }
    }

    /// No bind or overlay source may reach flong's state, the user
    /// manager's sockets, /proc, the cgroup filesystem or a `protect`
    /// entry, lexically (module.nix's badSources and reachesManager, until
    /// this took their place): the
    /// same path, one inside the other, spelt as module.nix's `norm`
    /// spells it.
    fn sources(c: *Checker) Allocator.Error!void {
        var protected: std.ArrayList([]const u8) = .empty;
        try protected.appendSlice(c.arena, &.{ "/proc", "/sys/fs/cgroup" });
        for (c.d.protect) |p| try protected.append(c.arena, try norm(c.arena, p));
        std.mem.sort([]const u8, protected.items, {}, lessThan);
        const p: Sorted = .{ .items = protected.items };
        var bad: std.ArrayList([]const u8) = .empty;
        for (c.d.containerMounts) |cm| {
            if (!isBind(cm)) continue;
            const s = try norm(c.arena, srcOf(cm));
            if (reachesManager(s) or try p.overlaps(c.arena, s)) try bad.append(c.arena, s);
        }
        for (c.d.overlays) |o| {
            const s = try norm(c.arena, o.lower);
            if (reachesManager(s) or try p.overlaps(c.arena, s)) try bad.append(c.arena, s);
        }
        if (bad.items.len == 0) return;
        try c.say("flong.{s} drives containers.{s}, and would bind {s} into a session. That reaches flong's state, the user manager's bus or private socket, /proc, the cgroup filesystem or a path in flong.{s}.protect, any of which lets a session act as the caller outside it. The check here is lexical; the launcher's canonical one refuses the rest at launch.", .{ c.n, c.d.container, try join(c.arena, bad.items), c.n });
    }

    /// THE DEPTH RULE (module.nix's maskHost, and its deepMasks until this
    /// took its place): a mask whose
    /// nearest enclosing destination is a bind's has a host path, that
    /// bind's source and then the rest of the mask, and is refused when
    /// the host path lies two or more levels below the source of a
    /// writable bind, whose session could rename the masked file's parent.
    /// Each refusal names every such source, in the binds' order.
    ///
    /// Every lookup is a search of a sorted list for one of the path's
    /// ancestors, so a long list of masks and binds costs n log n rather
    /// than n squared. A mask of PATH_MAX or more, which the clean-path
    /// check refuses, is not looked at.
    fn depth(c: *Checker) Allocator.Error!void {
        const d = c.d;
        const dests = try c.allDests();
        std.mem.sort([]const u8, dests, {}, lessThan);
        // Each bind with its normalised source, and the order it came in.
        var binds: std.ArrayList(Bind) = .empty;
        var writable: std.ArrayList(Bind) = .empty;
        for (d.containerMounts) |cm| {
            if (!isBind(cm)) continue;
            const b: Bind = .{ .dest = cm.dest, .src = try norm(c.arena, srcOf(cm)), .order = binds.items.len };
            try binds.append(c.arena, b);
            if (cm.kind == .bind_rw) try writable.append(c.arena, b);
        }
        // By destination, then by order: the first of equal ones is the
        // first declared, the one module.nix's findFirst took.
        std.mem.sort(Bind, binds.items, {}, Bind.byDest);
        std.mem.sort(Bind, writable.items, {}, Bind.bySrc);

        var deep: std.ArrayList([]const u8) = .empty;
        for (d.masks) |m| {
            if (m.len >= sys.path_max) continue;
            const host = try hostOf(c.arena, dests, binds.items, m) orelse continue;
            // The writable binds whose source holds the host path two or
            // more levels down, each source once, in the binds' order.
            var ws: std.ArrayList(Bind) = .empty;
            var left = components(host);
            var k: usize = 0;
            while (std.mem.indexOfScalarPos(u8, host, k, '/')) |slash| : (k = slash + 1) {
                // `left` is how many components follow this slash.
                if (slash > k) left -= 1;
                if (left < 2) break;
                const first = std.sort.lowerBound(Bind, writable.items, host[0..slash], Bind.srcOrder);
                if (first < writable.items.len and std.mem.eql(u8, writable.items[first].src, host[0..slash]))
                    try ws.append(c.arena, writable.items[first]);
            }
            if (ws.items.len == 0) continue;
            std.mem.sort(Bind, ws.items, {}, Bind.byOrder);
            const names = try c.arena.alloc([]const u8, ws.items.len);
            for (names, ws.items) |*n, w| n.* = w.src;
            try deep.append(c.arena, try std.fmt.allocPrint(c.arena, "{s} (in the writable bind of {s})", .{ m, try join(c.arena, names) }));
        }
        if (deep.items.len == 0) return;
        try c.say("flong.{s} masks {s}, two or more levels below the root of a writable bind. A session that can write the host directory can rename the masked file's parent and leave a decoy for the mask to cover, and the file shows through at the new name. Mask at most one level below the root of the writable bind named, or make that bind read-only.", .{ c.n, try join(c.arena, deep.items) });
    }

    /// A device is bound read-write, from under /dev/.
    fn devices(c: *Checker) Allocator.Error!void {
        var bad: std.ArrayList([]const u8) = .empty;
        for (c.d.containerMounts) |cm| {
            if (cm.kind != .dev) continue;
            const mode = cm.mode orelse "";
            if (std.mem.startsWith(u8, cm.dest, "/dev/") and (std.mem.eql(u8, mode, "rw") or std.mem.eql(u8, mode, "rwm"))) continue;
            try bad.append(c.arena, try std.fmt.allocPrint(c.arena, "{s} {s}", .{ cm.dest, mode }));
        }
        if (bad.items.len == 0) return;
        try c.say("flong.{s} drives containers.{s}, whose allowedDevices has {s}. A device is bound read-write, so the node must be under /dev/ and the modifier \"rw\" or \"rwm\" (m means nothing for a bound node).", .{ c.n, c.d.container, try join(c.arena, bad.items) });
    }

    /// A plain bind is nodev, so one of /dev or below it is refused.
    fn devBinds(c: *Checker) Allocator.Error!void {
        var bad: std.ArrayList([]const u8) = .empty;
        for (c.d.containerMounts) |cm| {
            if (!isBind(cm)) continue;
            const src = try norm(c.arena, srcOf(cm));
            if (std.mem.eql(u8, src, "/dev") or std.mem.startsWith(u8, src, "/dev/")) try bad.append(c.arena, src);
        }
        if (bad.items.len == 0) return;
        try c.say("flong.{s} drives containers.{s}, which binds {s}. A plain bind is nodev, so the device would mount and then refuse every open. List it in allowedDevices instead, and drop the bind.", .{ c.n, c.d.container, try join(c.arena, bad.items) });
    }

    fn ids(c: *Checker) Allocator.Error!void {
        if (c.d.cuid <= 65535 and c.d.cgid <= 65535) return;
        try c.say("flong.{s} drives containers.{s} as {s} ({d}:{d}), outside the container's ids 0-65535.", .{ c.n, c.d.container, c.d.user, c.d.cuid, c.d.cgid });
    }

    /// Every path a mount is made at or from, and every protected one, as
    /// the launcher's spec.clean takes it.
    fn clean(c: *Checker) Allocator.Error!void {
        var bad: std.ArrayList([]const u8) = .empty;
        const d = c.d;
        for (d.containerMounts) |cm| if (isBind(cm)) try unclean(c.arena, &bad, cm.dest);
        for (d.containerMounts) |cm| if (isBind(cm)) try unclean(c.arena, &bad, srcOf(cm));
        for (d.containerMounts) |cm| if (cm.kind == .tmpfs) try unclean(c.arena, &bad, cm.dest);
        for (d.overlays) |o| try unclean(c.arena, &bad, o.target);
        for (d.overlays) |o| try unclean(c.arena, &bad, o.lower);
        for (d.masks) |m| try unclean(c.arena, &bad, m);
        for (d.containerMounts) |cm| if (cm.kind == .dev) try unclean(c.arena, &bad, cm.dest);
        for (d.containerMounts) |cm| if (cm.kind == .dev) if (cm.src) |s| try unclean(c.arena, &bad, s);
        for (d.protect) |p| try unclean(c.arena, &bad, p);
        const list = try firstOfEach(c.arena, bad.items, .all);
        if (list.len == 0) return;
        try c.say("flong.{s} drives containers.{s}, and {s} is not a clean absolute path: it is /, or has a trailing slash, an empty, . or .. component, or a component over 255 bytes. The launcher would refuse it at launch.", .{ c.n, c.d.container, try join(c.arena, list) });
    }

    /// The launcher mounts one thing at each destination.
    fn twice(c: *Checker) Allocator.Error!void {
        const list = try firstOfEach(c.arena, try c.allDests(), .repeated);
        if (list.len == 0) return;
        try c.say("flong.{s} drives containers.{s}, and mounts something at {s} twice: as two of a bind, a mask, a tmpfs, an overlay or a device. The launcher mounts one thing at each path.", .{ c.n, c.d.container, try join(c.arena, list) });
    }

    /// What acts on a tier's allow-list has nothing to act on without one.
    fn noTier(c: *Checker) Allocator.Error!void {
        const s = c.d.seccomp;
        if (s.tier != null) return;
        var what: std.ArrayList([]const u8) = .empty;
        if (s.allow.len != 0) try what.append(c.arena, "seccomp.allow");
        if (s.deny.len != 0) try what.append(c.arena, "seccomp.deny");
        if (s.log) try what.append(c.arena, "seccomp.log");
        if (c.d.seccompPolicy.len != 0) try what.append(c.arena, "seccompPolicy");
        if (what.items.len == 0) return;
        try c.say("flong.{s} sets seccomp.tier = null and {s}, which change a tier's allow-list. With no tier there is no filter for them to act on. Set a tier, or drop them.", .{ c.n, try join(c.arena, what.items) });
    }

    /// Every destination the declaration mounts something at, in
    /// module.nix's order: binds, masks, tmpfs, overlays, devices.
    fn allDests(c: *Checker) Allocator.Error![][]const u8 {
        const d = c.d;
        var all: std.ArrayList([]const u8) = .empty;
        for (d.containerMounts) |cm| if (isBind(cm)) try all.append(c.arena, cm.dest);
        try all.appendSlice(c.arena, d.masks);
        for (d.containerMounts) |cm| if (cm.kind == .tmpfs) try all.append(c.arena, cm.dest);
        for (d.overlays) |o| try all.append(c.arena, o.target);
        for (d.containerMounts) |cm| if (cm.kind == .dev) try all.append(c.arena, cm.dest);
        return all.items;
    }
};

/// ZON's `\x00` puts a NUL in a string, which a Nix string cannot hold.
fn hasNul(s: []const u8) bool {
    return std.mem.indexOfScalar(u8, s, 0) != null;
}

fn isBind(cm: decl.ContainerMount) bool {
    return cm.kind == .bind_ro or cm.kind == .bind_rw;
}

/// A bind's source: its `src`, or its destination when it has none, as a
/// `bindMounts` entry's hostPath defaults to its mountPoint.
fn srcOf(cm: decl.ContainerMount) []const u8 {
    return cm.src orelse cm.dest;
}

fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

fn pathOrder(key: []const u8, x: []const u8) std.math.Order {
    return std.mem.order(u8, key, x);
}

/// A bind, its source as module.nix's `norm` spells it, and its place
/// among the binds.
const Bind = struct {
    dest: []const u8,
    src: []const u8,
    order: usize,

    fn byDest(_: void, a: Bind, b: Bind) bool {
        return switch (std.mem.order(u8, a.dest, b.dest)) {
            .lt => true,
            .gt => false,
            .eq => a.order < b.order,
        };
    }

    fn bySrc(_: void, a: Bind, b: Bind) bool {
        return switch (std.mem.order(u8, a.src, b.src)) {
            .lt => true,
            .gt => false,
            .eq => a.order < b.order,
        };
    }

    fn byOrder(_: void, a: Bind, b: Bind) bool {
        return a.order < b.order;
    }

    fn destOrder(key: []const u8, b: Bind) std.math.Order {
        return std.mem.order(u8, key, b.dest);
    }

    fn srcOrder(key: []const u8, b: Bind) std.math.Order {
        return std.mem.order(u8, key, b.src);
    }
};

/// Paths, sorted bytewise.
const Sorted = struct {
    items: []const []const u8,

    fn has(s: Sorted, x: []const u8) bool {
        return std.sort.binarySearch([]const u8, s.items, x, pathOrder) != null;
    }

    /// Whether `x` is one of them, lies inside one, or holds one, as
    /// module.nix's `overlaps` compared: `a == b`, or one starts with the
    /// other and a slash. Its ancestors are looked up one by one, and
    /// what lies inside it follows `x/` in the order.
    fn overlaps(s: Sorted, arena: Allocator, x: []const u8) Allocator.Error!bool {
        if (s.has(x)) return true;
        var k: usize = 0;
        while (std.mem.indexOfScalarPos(u8, x, k, '/')) |slash| : (k = slash + 1) {
            if (s.has(x[0..slash])) return true;
        }
        const inside = try std.fmt.allocPrint(arena, "{s}/", .{x});
        const at = std.sort.lowerBound([]const u8, s.items, inside, pathOrder);
        return at < s.items.len and std.mem.startsWith(u8, s.items[at], inside);
    }
};

/// The host path of mask `m` (module.nix's maskHost): when the nearest
/// destination above it, the longest of `dests` it starts with and then
/// a slash, is a bind's, the first such bind's source, a slash and the
/// rest of `m`. `dests` is sorted, `binds` by destination.
fn hostOf(arena: Allocator, dests: []const []const u8, binds: []const Bind, m: []const u8) Allocator.Error!?[]const u8 {
    const sorted: Sorted = .{ .items = dests };
    var end = m.len;
    const nearest = while (std.mem.lastIndexOfScalar(u8, m[0..end], '/')) |slash| {
        if (sorted.has(m[0..slash])) break m[0..slash];
        end = slash;
    } else return null;
    const first = std.sort.lowerBound(Bind, binds, nearest, Bind.destOrder);
    if (first == binds.len or !std.mem.eql(u8, binds[first].dest, nearest)) return null;
    return try std.fmt.allocPrint(arena, "{s}/{s}", .{ binds[first].src, m[nearest.len + 1 ..] });
}

fn unclean(arena: Allocator, bad: *std.ArrayList([]const u8), p: []const u8) Allocator.Error!void {
    if (spec.unclean(p, .absolute) != null) try bad.append(arena, p);
}

/// The user manager's state and sockets, and flong's own, by the lexical
/// spelling a declaration would use: `/`, `/run`, `/run/user`, or what
/// matches `/run/user/[^/]+(/(flong|bus|systemd)(/.*)?)?`.
pub fn reachesManager(s: []const u8) bool {
    for ([_][]const u8{ "/", "/run", "/run/user" }) |x| {
        if (std.mem.eql(u8, s, x)) return true;
    }
    const prefix = "/run/user/";
    if (!std.mem.startsWith(u8, s, prefix)) return false;
    const rest = s[prefix.len..];
    const uid_end = std.mem.indexOfScalar(u8, rest, '/') orelse return rest.len > 0;
    if (uid_end == 0) return false;
    const after = rest[uid_end + 1 ..];
    for ([_][]const u8{ "flong", "bus", "systemd" }) |x| {
        if (std.mem.eql(u8, after, x)) return true;
        if (std.mem.startsWith(u8, after, x) and after[x.len] == '/') return true;
    }
    return false;
}

/// A path as module.nix's `norm` compared it: repeated and trailing
/// slashes gone, and /var/run as /run. Lexical only.
pub fn norm(arena: Allocator, p: []const u8) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.ensureTotalCapacity(arena, p.len + 1);
    var it = std.mem.tokenizeScalar(u8, p, '/');
    while (it.next()) |part| {
        out.appendAssumeCapacity('/');
        out.appendSliceAssumeCapacity(part);
    }
    if (out.items.len == 0) out.appendAssumeCapacity('/');
    const q = out.items;
    const var_run = "/var/run";
    if (std.mem.eql(u8, q, var_run) or std.mem.startsWith(u8, q, var_run ++ "/")) return q["/var".len..];
    return q;
}

/// How many components a relative path has.
fn components(rel: []const u8) usize {
    var n: usize = 0;
    var it = std.mem.tokenizeScalar(u8, rel, '/');
    while (it.next()) |_| n += 1;
    return n;
}

fn join(arena: Allocator, items: []const []const u8) Allocator.Error![]const u8 {
    return std.mem.join(arena, ", ", items);
}

const Keep = enum { all, repeated };

/// Each distinct string of `items` once, in the order it first appears:
/// every one (`.all`, Nix's lib.unique) or those that appear more than
/// once (`.repeated`, as module.nix's twiceIn did). By a sort, so a long list
/// costs n log n and not n squared.
fn firstOfEach(arena: Allocator, items: []const []const u8, keep: Keep) Allocator.Error![]const []const u8 {
    const order = try arena.alloc(usize, items.len);
    for (order, 0..) |*o, i| o.* = i;
    const By = struct {
        items: []const []const u8,
        fn lt(ctx: @This(), a: usize, b: usize) bool {
            return switch (std.mem.order(u8, ctx.items[a], ctx.items[b])) {
                .lt => true,
                .gt => false,
                .eq => a < b,
            };
        }
    };
    std.mem.sort(usize, order, By{ .items = items }, By.lt);
    var firsts: std.ArrayList(usize) = .empty;
    var i: usize = 0;
    while (i < order.len) {
        var j = i + 1;
        while (j < order.len and std.mem.eql(u8, items[order[i]], items[order[j]])) j += 1;
        if (keep == .all or j - i > 1) try firsts.append(arena, order[i]);
        i = j;
    }
    std.mem.sort(usize, firsts.items, {}, std.sort.asc(usize));
    const out = try arena.alloc([]const u8, firsts.items.len);
    for (out, firsts.items) |*o, f| o.* = items[f];
    return out;
}

// ---- patterns ----

/// Whether the pattern stays within what `matches` reads: literal bytes,
/// `.`, bracket sets of bytes and ranges, each optionally followed by `?`,
/// `*` or `+`. decl.zig's patterns are Nix's strMatching, POSIX extended
/// regular expressions; one that needs more is a compile error here
/// rather than a pattern judged wrongly.
fn supported(comptime pattern: []const u8) void {
    for (pattern) |ch| switch (ch) {
        '(', ')', '|', '{', '}', '\\', '^', '$' => @compileError("check.zig cannot match the pattern " ++ pattern),
        else => {},
    };
}

/// Whether all of `s` matches `pattern`, as Nix's strMatching asks.
/// Backtracking over the pattern's atoms, so its depth is the pattern's
/// length, not the string's.
pub fn matches(pattern: []const u8, s: []const u8) bool {
    if (pattern.len == 0) return s.len == 0;
    const alen = atomLen(pattern);
    const atom = pattern[0..alen];
    const q: u8 = if (alen < pattern.len) pattern[alen] else 0;
    switch (q) {
        '?' => {
            const rest = pattern[alen + 1 ..];
            if (s.len > 0 and atomMatches(atom, s[0]) and matches(rest, s[1..])) return true;
            return matches(rest, s);
        },
        '*', '+' => {
            const rest = pattern[alen + 1 ..];
            const least: usize = if (q == '+') 1 else 0;
            var n: usize = 0;
            while (n < s.len and atomMatches(atom, s[n])) n += 1;
            if (n < least) return false;
            var k = n;
            while (true) : (k -= 1) {
                if (matches(rest, s[k..])) return true;
                if (k == least) return false;
            }
        },
        else => return s.len > 0 and atomMatches(atom, s[0]) and matches(pattern[alen..], s[1..]),
    }
}

/// The length of the atom `p` starts with: a bracket set up to its `]`,
/// or one byte. An unclosed set is the rest of the pattern.
fn atomLen(p: []const u8) usize {
    if (p[0] != '[') return 1;
    // A `]` first in the set is a member, not its end.
    const from: usize = if (p.len > 1 and p[1] == ']') 2 else 1;
    const close = std.mem.indexOfScalarPos(u8, p, from, ']') orelse return p.len;
    return close + 1;
}

fn atomMatches(atom: []const u8, ch: u8) bool {
    if (atom[0] == '.' and atom.len == 1) return true;
    if (atom[0] != '[') return atom[0] == ch;
    const set = atom[1 .. atom.len - @intFromBool(atom[atom.len - 1] == ']')];
    var i: usize = 0;
    while (i < set.len) {
        if (i + 2 < set.len and set[i + 1] == '-') {
            if (ch >= set[i] and ch <= set[i + 2]) return true;
            i += 3;
        } else {
            if (ch == set[i]) return true;
            i += 1;
        }
    }
    return false;
}

// ---- tests ----

const testing = std.testing;

test "matches: decl.zig's patterns, whole strings only" {
    try testing.expect(matches("/.*", "/"));
    try testing.expect(matches("/.*", "/a/b"));
    try testing.expect(!matches("/.*", "a/b"));
    try testing.expect(!matches("/.*", ""));
    try testing.expect(matches("@?[a-z0-9_-]+", "ptrace"));
    try testing.expect(matches("@?[a-z0-9_-]+", "@keyring"));
    try testing.expect(matches("@?[a-z0-9_-]+", "io_uring-x"));
    try testing.expect(!matches("@?[a-z0-9_-]+", "Ptrace"));
    try testing.expect(!matches("@?[a-z0-9_-]+", "@ keyring"));
    try testing.expect(!matches("@?[a-z0-9_-]+", "@"));
    try testing.expect(!matches("@?[a-z0-9_-]+", ""));
    try testing.expect(matches("[1-9][0-9]*%", "400%"));
    try testing.expect(matches("[1-9][0-9]*%", "5%"));
    try testing.expect(!matches("[1-9][0-9]*%", "0%"));
    try testing.expect(!matches("[1-9][0-9]*%", "40"));
    try testing.expect(!matches("[1-9][0-9]*%", "40%%"));
    try testing.expect(matches("[0-9]+[KMGT]", "8G"));
    try testing.expect(!matches("[0-9]+[KMGT]", "G"));
    try testing.expect(!matches("[0-9]+[KMGT]", "8g"));
    // Long strings cost their length, not a stack frame a byte.
    try testing.expect(matches("/.*", "/" ++ "a" ** 100_000));
}

test "reachesManager and norm, as module.nix spelt them" {
    for ([_][]const u8{ "/", "/run", "/run/user", "/run/user/1000", "/run/user/1000/flong", "/run/user/1000/bus", "/run/user/x/systemd/private" }) |s|
        try testing.expect(reachesManager(s));
    for ([_][]const u8{ "/run/user/1000/cc-socks", "/run/user/1000/busy", "/run/user/", "/srv", "/run/users" }) |s|
        try testing.expect(!reachesManager(s));
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualStrings("/run/user/1000/bus", try norm(a, "/var/run/user/1000//bus"));
    try testing.expectEqualStrings("/", try norm(a, ""));
    try testing.expectEqualStrings("/a", try norm(a, "a/"));
    try testing.expectEqualStrings("/var/runner", try norm(a, "/var/runner"));
    try testing.expectEqualStrings("/run", try norm(a, "/var/run"));
}

test "firstOfEach keeps first appearances in order" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const items = [_][]const u8{ "/c", "/a", "/c", "/b", "/a", "/a" };
    const all = try firstOfEach(a, &items, .all);
    try testing.expectEqual(3, all.len);
    try testing.expectEqualStrings("/c", all[0]);
    try testing.expectEqualStrings("/a", all[1]);
    try testing.expectEqualStrings("/b", all[2]);
    const rep = try firstOfEach(a, &items, .repeated);
    try testing.expectEqual(2, rep.len);
    try testing.expectEqualStrings("/c", rep[0]);
    try testing.expectEqualStrings("/a", rep[1]);
}

/// Only what has no default, as decl.zig's own `minimal`, but its
/// closing brace.
const minimal =
    \\.{
    \\    .user = "alice",
    \\    .command = .{"hello"},
    \\    .container = "agent",
    \\    .closure = "/nix/store/x-nixos-system-agent",
    \\    .cuid = 1000,
    \\    .cgid = 100,
    \\    .steps8 = "0123abcd",
    \\    .name = "agent",
    \\    .payload = "/nix/store/x-payload/bin/flong-payload-agent",
    \\
;

fn refusalsOf(a: Allocator, extra: []const u8) ![]const []const u8 {
    const source = try std.mem.concatWithSentinel(a, u8, &.{ minimal, extra, "}" }, 0);
    const d = try decl.parse(a, source, null);
    return validate(a, &d);
}

test "a declaration named as flong's own subcommand is refused" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    for (reserved) |r| {
        const source = try std.mem.concatWithSentinel(a, u8, &.{ ".{ .user = \"u\", .command = .{\"x\"}, .container = \"c\", .closure = \"/c\", .cuid = 1, .cgid = 1, .steps8 = \"s\", .payload = \"/p\", .name = \"", r, "\" }" }, 0);
        const d = try decl.parse(a, source, null);
        const got = try validate(a, &d);
        try testing.expectEqual(1, got.len);
        try testing.expect(std.mem.startsWith(u8, got[0], try std.fmt.allocPrint(a, "flong.{s} cannot be declared under that name", .{r})));
    }
    // Any other name is not.
    try testing.expectEqual(0, (try refusalsOf(a, "")).len);
}

test "a minimal declaration is refused nothing" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    try testing.expectEqual(0, (try refusalsOf(arena_state.allocator(), "")).len);
}

test "every refusal is collected, in order" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const r = try refusalsOf(arena_state.allocator(),
        \\    .guard = .{.{}},
        \\    .masks = .{ "/srv/b", "/srv/b/x/y" },
        \\    .seccomp = .{ .tier = null, .allow = .{"Ptrace"} },
        \\    .containerMounts = .{
        \\        .{ .kind = .bind_rw, .dest = "/srv/b", .src = "/srv/b" },
        \\        .{ .kind = .bind_ro, .dest = "/proc2", .src = "/proc/1" },
        \\    },
        \\
    );
    const want = [_][]const u8{
        "flong.agent.guard has an empty command",
        "flong.agent.seccomp.allow has \"Ptrace\"",
        "would bind /proc/1 into a session",
        "masks /srv/b/x/y (in the writable bind of /srv/b)",
        "mounts something at /srv/b twice",
        "sets seccomp.tier = null and seccomp.allow,",
    };
    try testing.expectEqual(want.len, r.len);
    for (want, r) |w, got| try testing.expect(std.mem.indexOf(u8, got, w) != null);
}

test "the depth rule and the sources, looked up rather than compared pairwise" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // A mask's nearest destination is the longest above it; the first
    // bind at it gives the host path; every writable source holding that
    // two levels down is named, once, in the binds' order.
    const r = try refusalsOf(a,
        \\    .masks = .{ "/w/x/y/z", "/other/one", "/t/a/b" },
        \\    .protect = .{ "/srv/p/" },
        \\    .containerMounts = .{
        \\        .{ .kind = .bind_rw, .dest = "/w", .src = "/h//w" },
        \\        .{ .kind = .bind_rw, .dest = "/other", .src = "/h" },
        \\        .{ .kind = .bind_rw, .dest = "/again", .src = "/h/w" },
        \\        .{ .kind = .bind_ro, .dest = "/w/x", .src = "/h/w/x" },
        \\        .{ .kind = .tmpfs, .dest = "/t" },
        \\        .{ .kind = .bind_ro, .dest = "/in", .src = "/srv" },
        \\        .{ .kind = .bind_ro, .dest = "/in2", .src = "/srv/p/q" },
        \\        .{ .kind = .bind_ro, .dest = "/in3", .src = "/srv/pq" },
        \\    },
        \\
    );
    try testing.expectEqual(3, r.len);
    try testing.expect(std.mem.indexOf(u8, r[0], "would bind /srv, /srv/p/q into") != null);
    try testing.expect(std.mem.indexOf(u8, r[1], "masks /w/x/y/z (in the writable bind of /h/w, /h), ") != null);
    try testing.expect(std.mem.indexOf(u8, r[2], "/h//w, /srv/p/ is not a clean") != null);

    // 20,000 masks under 20,000 writable binds: quadratic would be 4e8
    // comparisons; this is well under a second.
    var src: std.ArrayList(u8) = .empty;
    try src.appendSlice(a, minimal ++ "    .masks = .{");
    for (0..20_000) |i| try src.print(a, "\"/m{d}/a/b\",", .{i});
    try src.appendSlice(a, "},\n    .containerMounts = .{");
    for (0..20_000) |i| try src.print(a, ".{{ .kind = .bind_rw, .dest = \"/m{d}\", .src = \"/s{d}\" }},", .{ i, i });
    try src.appendSlice(a, "},\n}");
    const d = try decl.parse(a, try src.toOwnedSliceSentinel(a, 0), null);
    const many = try validate(a, &d);
    try testing.expectEqual(1, many.len);
    try testing.expect(std.mem.startsWith(u8, many[0], "flong.agent masks /m0/a/b (in the writable bind of /s0), /m1/a/b"));
}

test "the ranges decl.zig declares" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const r = try refusalsOf(a, "    .limits = .{ .CPUWeight = 0, .TasksMax = .{ .count = 0 }, .MemoryMax = .{ .size = \"8g\" } },\n");
    try testing.expectEqual(3, r.len);
    try testing.expectEqualStrings("flong.agent.limits.MemoryMax is \"8g\", which is not a string matching the pattern [0-9]+[KMGT].", r[0]);
    try testing.expectEqualStrings("flong.agent.limits.TasksMax is 0, outside 1-9223372036854775807.", r[1]);
    try testing.expectEqualStrings("flong.agent.limits.CPUWeight is 0, outside 1-10000.", r[2]);
}

test "a NUL byte in a command's word or in any string" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const r = try refusalsOf(arena_state.allocator(),
        \\    .guard = .{ .{ "test", "-d" }, .{ "a\x00b", "c\x00" } },
        \\    .masks = .{ "/a\x00b", "/c" },
        \\    .seccomp = .{ .allow = .{"ptrace\x00"} },
        \\
    );
    try testing.expectEqual(3, r.len);
    try testing.expect(std.mem.startsWith(u8, r[0], "flong.agent.guard has a command with a NUL byte in a word."));
    try testing.expect(std.mem.startsWith(u8, r[1], "flong.agent.masks has a string with a NUL byte in it."));
    try testing.expect(std.mem.startsWith(u8, r[2], "flong.agent.seccomp.allow has a string with a NUL byte in it."));
}
