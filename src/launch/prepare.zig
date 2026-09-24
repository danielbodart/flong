//! launch/prepare.zig: the prepared root (rootless-wrapper.bash:277-328),
//! for `flong launch DECL.zon`'s prologue (DESIGN.md, "Launch
//! sequence": the prepared root).
//!
//!   paths    the cache key, the cache and its prepared/ (:278-282)
//!   mapArgs  the cache tool's --map-users= and --map-groups= (:273-275)
//!   ensure   the cold path: the state directory, the cache made, opened
//!            and locked shared, still named, .prepare.lock, the cache
//!            tool's prepare, and its gc of superseded generations
//!            (:284-328); nothing on the warm path
//!
//! The cache tool is module.nix's flong-cache (cache.nix), compiled into
//! flong as -Dcache; ensure takes its path, so a test gives it a fake one.
//! It runs as the caller, in the commands' environment (cmd.environ), as
//! the wrapper's exported names reached it.
//!
//! The maps decide the root's on-disk owners, and the caller's primary
//! gid owns the container group's files, so all of them name the cache
//! (:278-279).
//!
//! Two of the wrapper's three relaunch points are here: the cache swept
//! before it was opened (:299) or between the mkdir and the lock
//! (:303-308); the third is identity.open's (:336-337). Each is `.swept`,
//! and the prologue answers it with prologue.relaunchSelf, which execs
//! flong again with its own argv, as `exec "$self"` did.
//!
//! The cache's shared lock is held across the prepare and kept into flong
//! launch's own (:294-297): `.cold` hands the prologue that open cache,
//! which it closes once checkpoint 1's prologue.cacheLock holds the cache
//! again, so no sweep renames the cache under a prepare or between the
//! two locks.
//!
//! Each refusal is said through msg under the declaration's name
//! (prologue.exit_refused); a terminating signal while waiting for a lock
//! or the tool is error.Aborted (sig.zig).

const std = @import("std");
const sys = @import("sys");
const fdt = @import("fd");
const msg = @import("msg");
const sig = @import("sig");
const proc = @import("proc");
const cmd = @import("cmd");
const subid = @import("subid");

const Allocator = std.mem.Allocator;

/// Where a prepared root is kept.
pub const Paths = struct {
    /// $key: cuid.cgid.sub.gsub.mygid
    key: []const u8,
    /// $cache: $state/$container-$closure8-$steps8-$key
    cache: [:0]const u8,
    /// $P: $cache/prepared
    prepared: [:0]const u8,
};

/// :280-282. `sub` and `gsub` are the /etc/subuid and /etc/subgid
/// entries' start fields as subid.find gave them, their text; `mygid` the
/// caller's primary gid. In `gpa`.
pub fn paths(
    gpa: Allocator,
    state: []const u8,
    container: []const u8,
    closure8: []const u8,
    steps8: []const u8,
    cuid: u32,
    cgid: u32,
    sub: []const u8,
    gsub: []const u8,
    mygid: u32,
) Allocator.Error!Paths {
    const key = try std.fmt.allocPrint(gpa, "{d}.{d}.{s}.{s}.{d}", .{ cuid, cgid, sub, gsub, mygid });
    const cache = try std.fmt.allocPrintSentinel(gpa, "{s}/{s}-{s}-{s}-{s}", .{ state, container, closure8, steps8, key }, 0);
    const prepared = try std.fmt.allocPrintSentinel(gpa, "{s}/prepared", .{cache}, 0);
    return .{ .key = key, .cache = cache, .prepared = prepared };
}

/// `mapargs` (:273-275): --map-users=IN:OUT:COUNT for each of `umap`'s
/// extents, then --map-groups= for each of `gmap`'s, each word as bash
/// expanded it (subid.Word). In `gpa`.
pub fn mapArgs(gpa: Allocator, umap: []const subid.Extent, gmap: []const subid.Extent) Allocator.Error![]const [:0]const u8 {
    var out: std.ArrayList([:0]const u8) = .empty;
    for ([_]struct { []const u8, []const subid.Extent }{ .{ "users", umap }, .{ "groups", gmap } }) |m| {
        for (m[1]) |e| try out.append(gpa, try std.fmt.allocPrintSentinel(gpa, "--map-{s}={f}:{f}:{f}", .{ m[0], e[0], e[1], e[2] }, 0));
    }
    return out.items;
}

/// The cache tool, and how it runs.
pub const Tool = struct {
    /// flong-cache's path (-Dcache)
    path: [:0]const u8,
    /// mapArgs'
    map_args: []const [:0]const u8,
    /// the commands' environment (cmd.environ)
    envp: cmd.Envp,
};

/// What ensure found.
pub const Outcome = union(enum) {
    /// prepared/ was there: the warm path, nothing opened or run
    warm,
    /// the cold path ran: the cache, open and locked shared, for the
    /// prologue to close once prologue.cacheLock holds it
    cold: fdt.Dir,
    /// the cache was swept before it was locked: relaunch
    swept,
};

/// :284-328 for the declaration's `container`, `closure` and `user`, on
/// `p` (from `paths`) under the state directory `state`. Cold only when
/// $P is not a directory (following symlinks, as `-d`). Refusals: "cannot
/// make <state>", "cannot make <cache>: <strerror>" (the wrapper's was
/// mkdir's own message), "cannot open <cache>", "<cache>/.prepare.lock:
/// <strerror>" (the wrapper's was bash's), and "preparing the root for
/// <container> failed, see <cache>/.prepare.*.log". A gc that fails is
/// said, "could not remove <old>, kept", and the launch goes on.
pub fn ensure(
    gpa: Allocator,
    state: [:0]const u8,
    container: []const u8,
    p: Paths,
    tool: Tool,
    closure: [:0]const u8,
    user: [:0]const u8,
) sig.Error!Outcome {
    if (isDir(p.prepared)) return .warm;

    // Cold: the only path with forks besides the commands, and the only
    // one that collects garbage. $rt exists, so only $state may need
    // making; a concurrent launch may make it first (:284-292). mkdir -m
    // set the mode whatever the umask.
    switch (sys.mkdirat(sys.AT.FDCWD, state, 0o700)) {
        .ok => _ = sys.fchmodat(sys.AT.FDCWD, state, 0o700),
        .err => if (!isDir(state)) return msg.refuse("cannot make {s}", .{state}),
    }
    // mkdir -p: made, or a directory there already (:293).
    switch (sys.mkdirat(sys.AT.FDCWD, p.cache, 0o777)) {
        .ok => {},
        .err => |e| if (e != .EXIST or !isDir(p.cache)) return msg.fail(e, "cannot make {s}", .{p.cache}),
    }

    // The cache's shared lock, held across the prepare and handed on. A
    // launch of another generation may have swept it since the mkdir
    // (:294-301).
    const cfd = switch (fdt.openDir(fdt.cwd, p.cache) catch return msg.refuse("cannot open {s}: too many open descriptors", .{p.cache})) {
        .ok => |h| h,
        .err => return if (!exists(p.cache)) .swept else msg.refuse("cannot open {s}", .{p.cache}),
    };
    const kept = prepareLocked(gpa, cfd, container, p, tool, closure, user) catch |err| {
        cfd.close();
        return err;
    };
    // Swept between the mkdir and the lock: start over, without the lock
    // on the swept inode, which would keep its deletion waiting
    // (:303-308).
    if (!kept) {
        cfd.close();
        return .swept;
    }
    try collect(gpa, state, container, p, tool);
    return .{ .cold = cfd };
}

/// :302-317 on the open cache `cfd`: false when the path no longer names
/// it once locked; true once $P is there.
fn prepareLocked(
    gpa: Allocator,
    cfd: fdt.Dir,
    container: []const u8,
    p: Paths,
    tool: Tool,
    closure: [:0]const u8,
    user: [:0]const u8,
) sig.Error!bool {
    try proc.lockWait(cfd, sys.LOCK.SH);
    // `[[ $cache -ef /proc/self/fd/$cfd ]]`: both stat'd, following
    // symlinks; either failing is not the same file.
    const locked = switch (cfd.fstat()) {
        .ok => |st| st,
        .err => return false,
    };
    const named = switch (sys.fstatat(sys.AT.FDCWD, p.cache, 0)) {
        .ok => |st| st,
        .err => return false,
    };
    if (named.dev != locked.dev or named.ino != locked.ino) return false;

    // One preparer at a time; the rest wait for it and find the root made
    // (:309-317).
    const lock_path = std.fmt.allocPrintSentinel(gpa, "{s}/.prepare.lock", .{p.cache}, 0) catch return oom();
    const pl = try msg.check(fdt.openFile(fdt.cwd, lock_path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o666), "{s}", .{lock_path});
    defer pl.close();
    try proc.lockWait(pl, sys.LOCK.EX);
    if (!isDir(p.prepared)) {
        const argv = command(gpa, tool, "prepare", &.{ p.cache, closure, user }) catch return oom();
        if (try cmd.run(gpa, argv, &.{}, tool.envp) != 0)
            return msg.refuse("preparing the root for {s} failed, see {s}/.prepare.*.log", .{ container, p.cache });
        msg.trace("prepared");
    }
    return true;
}

/// :318-327: superseded generations of this container with these maps,
/// `$state/$container-????????-????????-$key`, and the trash a killed
/// collection left, `$state/.trash.*`, each glob's matches in byte order
/// (bash sorts them by the locale's collation, which for these names, the
/// hashes being hex, differs only in a name no launch made). The fixed
/// widths keep another container whose name only starts with this one's
/// out. Each that is not this cache and is a directory goes to the tool's
/// gc; a cache still in use is kept, and goes at a later cold launch or
/// with the runtime directory at logout. A state directory that cannot be
/// listed matches nothing, as a glob that matches nothing names only
/// itself.
fn collect(gpa: Allocator, state: [:0]const u8, container: []const u8, p: Paths, tool: Tool) sig.Error!void {
    const found = superseded(gpa, state, container, p.key) catch return oom();
    for ([_][]const []const u8{ found.generations, found.trash }) |names| {
        for (names) |name| {
            const old = std.fmt.allocPrintSentinel(gpa, "{s}/{s}", .{ state, name }, 0) catch return oom();
            if (std.mem.eql(u8, old, p.cache) or !isDir(old)) continue;
            const argv = command(gpa, tool, "gc", &.{old}) catch return oom();
            if (try cmd.run(gpa, argv, &.{}, tool.envp) != 0) msg.say("could not remove {s}, kept", .{old});
        }
    }
}

/// The names in `state` each glob of :322 matches, sorted.
const Found = struct { generations: []const []const u8, trash: []const []const u8 };

fn superseded(gpa: Allocator, state: [:0]const u8, container: []const u8, key: []const u8) Allocator.Error!Found {
    var gens: std.ArrayList([]const u8) = .empty;
    var trash: std.ArrayList([]const u8) = .empty;
    const r = fdt.openDir(fdt.cwd, state) catch return .{ .generations = &.{}, .trash = &.{} };
    const d = switch (r) {
        .ok => |h| h,
        .err => return .{ .generations = &.{}, .trash = &.{} },
    };
    defer d.close();
    var buf: [4096]u8 align(8) = undefined;
    while (true) {
        const n = switch (d.getdents64(&buf)) {
            .ok => |n| n,
            .err => break,
        };
        if (n == 0) break;
        var it: fdt.Entries = .{ .buf = buf[0..n] };
        while (it.next()) |e| {
            if (isGeneration(e.name, container, key)) {
                try gens.append(gpa, try gpa.dupe(u8, e.name));
            } else if (std.mem.startsWith(u8, e.name, ".trash.")) {
                try trash.append(gpa, try gpa.dupe(u8, e.name));
            }
        }
    }
    std.mem.sort([]const u8, gens.items, {}, lessThan);
    std.mem.sort([]const u8, trash.items, {}, lessThan);
    return .{ .generations = gens.items, .trash = trash.items };
}

fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

/// `$container-????????-????????-$key` against a name: each `?` one byte.
pub fn isGeneration(name: []const u8, container: []const u8, key: []const u8) bool {
    const len = container.len + 1 + 8 + 1 + 8 + 1 + key.len;
    if (name.len != len) return false;
    if (!std.mem.startsWith(u8, name, container) or !std.mem.endsWith(u8, name, key)) return false;
    const at = container.len;
    return name[at] == '-' and name[at + 9] == '-' and name[at + 18] == '-';
}

/// The tool's argv: `path SUB MAPARG... -- ARG...` (:313, 324).
fn command(gpa: Allocator, tool: Tool, sub: [:0]const u8, args: []const [:0]const u8) Allocator.Error!cmd.Command {
    var argv: std.ArrayList([:0]const u8) = .empty;
    try argv.appendSlice(gpa, &.{ tool.path, sub });
    try argv.appendSlice(gpa, tool.map_args);
    try argv.append(gpa, "--");
    try argv.appendSlice(gpa, args);
    return argv.items;
}

/// `-d`: a directory, following symlinks.
fn isDir(path: [:0]const u8) bool {
    return switch (sys.fstatat(sys.AT.FDCWD, path, 0)) {
        .ok => |st| sys.S.ISDIR(st.mode),
        .err => false,
    };
}

/// `-e`: there, following symlinks.
fn exists(path: [:0]const u8) bool {
    return switch (sys.fstatat(sys.AT.FDCWD, path, 0)) {
        .ok => true,
        .err => false,
    };
}

fn oom() msg.Error {
    return msg.fail(.NOMEM, "malloc", .{});
}

// ---- tests ----

const testing = std.testing;

test "paths: the key and the cache, as the wrapper names them" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const got = try paths(arena.allocator(), "/run/user/1000/flong", "agent", "0123abcd", "89abcdef", 1000, 100, "100000", "0100000", 100);
    try testing.expectEqualStrings("1000.100.100000.0100000.100", got.key);
    try testing.expectEqualStrings("/run/user/1000/flong/agent-0123abcd-89abcdef-1000.100.100000.0100000.100", got.cache);
    try testing.expectEqualStrings("/run/user/1000/flong/agent-0123abcd-89abcdef-1000.100.100000.0100000.100/prepared", got.prepared);
}

test "mapArgs: users then groups, each extent's words as bash expanded them" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const u = subid.buildMap(1000, 1000, .{ .start = "100000", .count = "65536" }).map;
    const g = subid.buildMap(0, 100, .{ .start = "200000", .count = "70000" }).map;
    const got = try mapArgs(arena.allocator(), u.slice(), g.slice());
    const want = [_][]const u8{
        "--map-users=0:100000:1000",
        "--map-users=1000:1000:1",
        "--map-users=1001:101000:64536",
        "--map-groups=0:100:1",
        "--map-groups=1:200000:65536",
    };
    try testing.expectEqual(want.len, got.len);
    for (want, got) |w, x| try testing.expectEqualStrings(w, x);
}

test "isGeneration: the container's name, two eight-byte words and the key" {
    const key = "1000.100.100000.100000.100";
    try testing.expect(isGeneration("agent-0123abcd-89abcdef-" ++ key, "agent", key));
    try testing.expect(isGeneration("agent-????????-........-" ++ key, "agent", key));
    // Another container whose name starts with this one's.
    try testing.expect(!isGeneration("agent-x-0123abcd-89abcdef-" ++ key, "agent", key));
    try testing.expect(!isGeneration("agent-x-0123abc-89abcdef-" ++ key, "agent", key));
    // Other maps, other widths, other separators.
    try testing.expect(!isGeneration("agent-0123abcd-89abcdef-1000.100.100000.100000.101", "agent", key));
    try testing.expect(!isGeneration("agent-0123abcde-89abcde-" ++ key, "agent", key));
    try testing.expect(!isGeneration("agent-0123abcd-89abcdef-" ++ key ++ "x", "agent", key));
    try testing.expect(!isGeneration("agent_0123abcd-89abcdef-" ++ key, "agent", key));
    try testing.expect(!isGeneration("", "agent", key));
}
