//! spec.zig: what a launch is asked to do, parsed from argv, and every check
//! that needs nothing but the spec: launcher/flong-spec.c:417-708 and the
//! checks it calls (:106-415), with flong-spec.h's struct as `Spec` (the Zig
//! port's L1). The line numbers are those of 5f1f08e.
//!
//! The wrapper passes the whole spec as flong launch's arguments: a sequence
//! of keywords, each followed by a fixed number of fields, then "--" and the
//! payload's command. An argument is a NUL-terminated string, so a path may
//! hold a tab, a newline or anything else but NUL, and bash builds the list
//! with builtins alone (an array and exec). The grammar is in DESIGN.md,
//! "The input contract" (flong-spec.h:1-12).
//!
//! Parsing takes two passes over the same arities. The first reads only the
//! shape: each keyword is known, has its fields, appears as often as it may,
//! and "--" comes before a command. It counts every keyword, so the second
//! pass fills arrays allocated once at their final size, in the caller's
//! arena. The second pass checks each field's meaning. Checks that relate
//! fields of different keywords (a map covering the payload's ids, a keep-fd
//! named by a bwrap-arg) run last, once everything is filled (:4-10).
//!
//! A field is positional: "--" in a field's place is that field's value
//! (the wrapper's own argv, passed through `relaunch`, may hold one). Only
//! "--" in a keyword's place ends the spec (:12-14).
//!
//! Every string in a `Spec` is a slice of argv; nothing is copied, and the
//! command is argv's own tail (:447-450). Every refusal names the keyword and
//! the field, in the words the wrapper used, since a refusal here is a
//! wrapper bug or a declaration the module let through, and whoever reads it
//! has the spec in front of them (:16-18). Each is said once, in the
//! launcher's cut mode, and passed up as `error.Reported`.

const std = @import("std");
const sys = @import("sys");
const fd = @import("fd");
const msg = @import("msg");
const proc = @import("proc");
const names = @import("names");
const mount = @import("mount");

const Error = msg.Error;
const Allocator = std.mem.Allocator;

/// One extent of U1's uid_map or gid_map, in newuidmap's order
/// (flong-spec.h:20-23).
pub const IdMap = struct { inside: u64, outside: u64, count: u64 };

/// One opt-in cgroup limit: a file in the sandbox leaf and what to write
/// (flong-spec.h:46-51).
pub const Limit = struct { file: [:0]const u8, value: [:0]const u8 };

/// struct fl_spec (flong-spec.h:58-113). An argument vector is its words,
/// empty when the keyword was not given.
pub const Spec = struct {
    // the session
    /// its name: record, leaf cgroup, $machine
    machine: [:0]const u8,
    /// the cgroup level between the holder and sessions
    container: [:0]const u8,
    /// $XDG_RUNTIME_DIR/flong: the caller's, mode 0700
    state: [:0]const u8,
    /// the cache directory; the root is <cache>/prepared
    cache: [:0]const u8,
    /// run when the cache was swept; empty: exit 75
    relaunch: []const [:0]const u8 = &.{},
    /// bound at /run/current-system
    closure: [:0]const u8,

    // identity
    /// U1's maps; U2's are derived from them. Their number is not capped
    /// (quirk 28, kept): above 340 extents the kernel says EINVAL.
    uidmap: []const IdMap,
    gidmap: []const IdMap,
    /// the payload, as ids inside the container
    uid: u32,
    gid: u32,
    home: [:0]const u8,
    /// supplementary groups, from the container's /etc/group
    groups: []const u32 = &.{},
    /// where the payload starts; "/" unless given
    chdir: [:0]const u8 = "/",

    // mounts
    /// in the order given; the helper sorts
    mounts: []const mount.Mount = &.{},
    /// no mount source may equal, lie inside or contain these
    protect: []const [:0]const u8 = &.{},

    // lockdown
    /// compiled BPF programs, each an --add-seccomp-fd, in order
    seccomp: []const [:0]const u8 = &.{},
    /// U2's user.max_user_namespaces; 0: nested namespaces off
    nested_userns: u64 = 0,

    // containment
    /// the holder unit's cgroup, relative to user@UID.service
    holder: [:0]const u8,
    /// run when the holder's cgroup is absent
    holder_start: []const [:0]const u8 = &.{},
    limits: []const Limit = &.{},

    // hooks and network
    /// empty: no hook
    post_start: []const [:0]const u8 = &.{},
    /// a /nix/store program, or null
    post_stop: ?[:0]const u8 = null,
    /// start pasta
    network: bool = false,
    /// ports, --dns-forward, --no-map-gw ...
    pasta_args: []const [:0]const u8 = &.{},
    /// fixed forwardPorts bind host ports: wait for pasta's exit
    pasta_wait: bool = false,

    // bwrap
    /// only DESIGN.md's bwrap-arg allow-list
    bwrap_args: []const [:0]const u8 = &.{},
    /// descriptors those options name (--ro-bind-data 9 ...), each checked
    /// open by F_GETFD; the launcher adopts them after the parse
    keep_fds: []const sys.fd_t = &.{},

    trace: bool = false,
    /// what tini runs; never empty. argv's own tail, so argv[argc], the
    /// kernel's null, follows it (sys.argvSlots)
    command: []const [*:0]const u8,
};

const Kw = enum {
    machine,
    container,
    state,
    cache,
    relaunch,
    closure,
    uidmap,
    gidmap,
    user,
    group,
    chdir,
    mount,
    protect,
    seccomp,
    nested_userns,
    holder,
    holder_start,
    limit,
    post_start,
    post_stop,
    network,
    pasta_arg,
    pasta_wait,
    bwrap_arg,
    keep_fd,
    trace,
};
const kw_n = @typeInfo(Kw).@"enum".fields.len;

const once = 1; // at most once
const required = 2; // at least once

/// The keywords and how many fields follow each (flong-spec.c:44-75).
/// mount's count depends on its kind, the first field, and is read from
/// `mount_kinds`.
const keywords = [kw_n]struct { name: []const u8, nfields: usize, flags: u2 }{
    .{ .name = "machine", .nfields = 1, .flags = required | once },
    .{ .name = "container", .nfields = 1, .flags = required | once },
    .{ .name = "state", .nfields = 1, .flags = required | once },
    .{ .name = "cache", .nfields = 1, .flags = required | once },
    .{ .name = "relaunch", .nfields = 1, .flags = 0 },
    .{ .name = "closure", .nfields = 1, .flags = required | once },
    .{ .name = "uidmap", .nfields = 3, .flags = required },
    .{ .name = "gidmap", .nfields = 3, .flags = required },
    .{ .name = "user", .nfields = 3, .flags = required | once },
    .{ .name = "group", .nfields = 1, .flags = 0 },
    .{ .name = "chdir", .nfields = 1, .flags = once },
    .{ .name = "mount", .nfields = 0, .flags = 0 },
    .{ .name = "protect", .nfields = 1, .flags = 0 },
    .{ .name = "seccomp", .nfields = 1, .flags = 0 },
    .{ .name = "nested-userns", .nfields = 1, .flags = once },
    .{ .name = "holder", .nfields = 1, .flags = required | once },
    .{ .name = "holder-start", .nfields = 1, .flags = 0 },
    .{ .name = "limit", .nfields = 2, .flags = 0 },
    .{ .name = "post-start", .nfields = 1, .flags = 0 },
    .{ .name = "post-stop", .nfields = 1, .flags = once },
    .{ .name = "network", .nfields = 0, .flags = once },
    .{ .name = "pasta-arg", .nfields = 1, .flags = 0 },
    .{ .name = "pasta-wait", .nfields = 0, .flags = once },
    .{ .name = "bwrap-arg", .nfields = 1, .flags = 0 },
    .{ .name = "keep-fd", .nfields = 1, .flags = 0 },
    .{ .name = "trace", .nfields = 0, .flags = once },
};

/// Each mount kind and how many fields follow the kind
/// (flong-spec.c:78-91).
const mount_kinds = [_]struct { name: []const u8, kind: mount.Kind, nfields: usize }{
    .{ .name = "bind-ro", .kind = .bind_ro, .nfields = 2 }, // DEST SRC
    .{ .name = "bind-rw", .kind = .bind_rw, .nfields = 2 },
    .{ .name = "bind-ro-exact", .kind = .bind_ro_exact, .nfields = 2 },
    .{ .name = "bind-rw-exact", .kind = .bind_rw_exact, .nfields = 2 },
    .{ .name = "dev", .kind = .dev, .nfields = 2 },
    .{ .name = "tmpfs", .kind = .tmpfs, .nfields = 4 }, // DEST MODE SIZE OWNER
    .{ .name = "overlay", .kind = .overlay, .nfields = 2 }, // DEST LOWER
    .{ .name = "mask", .kind = .mask, .nfields = 1 }, // DEST
};

/// The limits a spec may set: the opt-in ones module.nix types. Anything
/// else in a cgroup (cgroup.procs, cgroup.kill, cgroup.subtree_control) is
/// the launcher's own machinery, not a limit (flong-spec.c:94-100).
/// `io.weight` is accepted and never emitted (quirk 12, kept).
const limit_files = [_][]const u8{
    "memory.max", "memory.high", "memory.swap.max", "memory.oom.group",
    "pids.max",   "cpu.max",     "cpu.weight",      "io.weight",
};

/// The largest id a map may name: (uid_t)-1 is "no id" to the kernel
/// (flong-spec.c:103-104).
pub const id_max: u64 = 4294967294;
/// INT_MAX, the bound of a descriptor and of nested-userns.
const int_max: u64 = std.math.maxInt(i32);
/// NAME_MAX, the longest component a path may have.
const name_max = 255;

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn keyword(word: []const u8) ?Kw {
    for (keywords, 0..) |k, i| {
        if (eql(word, k.name)) return @enumFromInt(i);
    }
    return null;
}

fn mountKind(word: []const u8) ?usize {
    for (mount_kinds, 0..) |m, i| {
        if (eql(word, m.name)) return i;
    }
    return null;
}

/// How many fields follow keyword `k` at argv[i], or the refusal when they
/// run out or a mount's kind is unknown. Both passes use it, so they agree
/// on every arity (flong-spec.c:122-144).
fn arity(argv: []const [*:0]const u8, i: usize, k: Kw) Error!usize {
    var n = keywords[@intFromEnum(k)].nfields;
    if (k == .mount) {
        if (i + 1 >= argv.len) return msg.refuse("spec: mount: the kind is missing", .{});
        const m = mountKind(std.mem.span(argv[i + 1])) orelse
            return msg.refuse("spec: mount: unknown kind '{s}'", .{argv[i + 1]});
        n = 1 + mount_kinds[m].nfields;
    }
    if (argv.len - 1 - i < n) {
        if (k == .mount)
            return msg.refuse("spec: mount {s}: {d} field{s} expected", .{ argv[i + 1], n - 1, if (n == 2) "" else "s" });
        return msg.refuse("spec: {s}: {d} field{s} expected", .{ keywords[@intFromEnum(k)].name, n, if (n == 1) "" else "s" });
    }
    return n;
}

// ---- field checks: each says its refusal and returns it ----

/// A decimal number of at most `max`: digits only, so no sign, no space and
/// no base prefix slip through as they would with strtoul alone
/// (flong-spec.c:148-165).
fn number(what: []const u8, v: []const u8, max: u64) Error!u64 {
    if (v.len == 0) return msg.refuse("spec: {s} is empty", .{what});
    var n: u64 = 0;
    for (v) |c| {
        if (c < '0' or c > '9') return msg.refuse("spec: {s} is not a decimal number: '{s}'", .{ what, v });
        const d: u64 = c - '0';
        if (n > (max - d) / 10) return msg.refuse("spec: {s} is larger than {d}: '{s}'", .{ what, max, v });
        n = n * 10 + d;
    }
    return n;
}

/// A permission mode: octal digits, at most 07777 (flong-spec.c:167-182).
fn octal(what: []const u8, v: []const u8) Error!void {
    if (v.len == 0 or v.len > 5) return msg.refuse("spec: {s} is not an octal mode: '{s}'", .{ what, v });
    var n: u64 = 0;
    for (v) |c| {
        if (c < '0' or c > '7') return msg.refuse("spec: {s} is not an octal mode: '{s}'", .{ what, v });
        n = n * 8 + (c - '0');
    }
    if (n > 0o7777) return msg.refuse("spec: {s} is larger than 07777: '{s}'", .{ what, v });
}

/// A machine or container name (names.isName; flong-spec.c:184-191).
fn name(what: []const u8, v: []const u8) Error!void {
    if (names.isName(v)) return;
    return msg.refuse("spec: {s} '{s}' is not a name: 1 to {d} of A-Z a-z 0-9 _ - ., not starting with .", .{ what, v, names.name_max });
}

/// An absolute path that fits PATH_MAX (flong-spec.c:193-201).
fn absolute(what: []const u8, v: []const u8) Error!void {
    if (v.len == 0 or v[0] != '/') return msg.refuse("spec: {s} is not an absolute path: '{s}'", .{ what, v });
    if (v.len >= sys.path_max) return msg.refuse("spec: {s} is longer than PATH_MAX", .{what});
}

/// Absolute or relative, for `clean`.
pub const Rooted = enum { relative, absolute };

/// What `clean` finds wrong with a path, the first fault found.
pub const Unclean = enum { not_absolute, too_long, not_relative, component, long_component };

/// `clean`'s judgement without its message: null for a clean path. flong
/// check (check.zig) judges a declaration's paths by it, and says a
/// refusal in the declaration's words.
pub fn unclean(v: []const u8, rooted: Rooted) ?Unclean {
    var p: usize = 0;
    switch (rooted) {
        .absolute => {
            if (v.len == 0 or v[0] != '/') return .not_absolute;
            if (v.len >= sys.path_max) return .too_long;
            p = 1;
        },
        .relative => if (v.len > 0 and v[0] == '/') return .not_relative,
    }
    while (true) {
        const n = (std.mem.indexOfScalarPos(u8, v, p, '/') orelse v.len) - p;
        const c = v[p..][0..n];
        if (n == 0 or eql(c, ".") or eql(c, "..")) return .component;
        if (n > name_max) return .long_component;
        if (p + n == v.len) return null;
        p += n + 1;
    }
}

/// A path taken one component at a time, by the walker or in cgroupfs:
/// every component is non-empty, neither "." nor "..", and at most NAME_MAX
/// bytes. `.absolute`, it is absolute, shorter than PATH_MAX and is not "/"
/// alone; `.relative`, it is relative. A canonical path from realpath
/// passes, and so does nothing that would name a different place than it
/// spells (flong-spec.c:203-229). flong check asks `unclean`, this
/// without the message, of every path a declaration mounts (src/check.zig;
/// tests/golden/decl/'s paths-clean-* cases).
pub fn clean(what: []const u8, v: []const u8, rooted: Rooted) Error!void {
    return switch (unclean(v, rooted) orelse return) {
        .not_absolute, .too_long => absolute(what, v),
        .not_relative => msg.refuse("spec: {s} is not a relative path: '{s}'", .{ what, v }),
        .component => msg.refuse("spec: {s} has an empty, '.' or '..' component: '{s}'", .{ what, v }),
        .long_component => msg.refuse("spec: {s} has a component longer than NAME_MAX", .{what}),
    };
}

const store = "/nix/store/";

/// A path under /nix/store/, spelled without an empty, '.' or '..'
/// component that could climb back out (flong-spec.c:231-238).
fn storePath(what: []const u8, v: []const u8) Error!void {
    if (!std.mem.startsWith(u8, v, store) or v.len == store.len)
        return msg.refuse("spec: {s} is not under /nix/store/: '{s}'", .{ what, v });
    return clean(what, v, .absolute);
}

/// The container's toplevel, which bwrap binds at /run/current-system by
/// path, following symlinks, outside the walker and its protected-path
/// check. It must lead into the store, whose paths never change once made,
/// so it can never put the state directory or the holder's cgroup in the
/// payload's view (flong-spec.c:240-255). realpath by quirk 21's mechanism:
/// an O_PATH open, following symlinks, and the kernel's name for it, the
/// readlink of its selfPath; a name that does not fit PATH_MAX with its NUL
/// is ENAMETOOLONG, as glibc's realpath says. The descriptor is closed
/// before the parse goes on, so a keep-fd checked after it cannot be it.
fn closure(v: [:0]const u8) Error!void {
    try storePath("closure", v);
    const h = try msg.check(fd.openPath(fd.cwd, v, .{}), "spec: closure '{s}'", .{v});
    defer h.close();
    var real: [sys.path_max]u8 = undefined;
    const link = fd.selfPath(h);
    const n = try msg.check(sys.readlinkat(sys.AT.FDCWD, link.path(), &real), "spec: closure '{s}'", .{v});
    if (n >= real.len) return msg.fail(.NAMETOOLONG, "spec: closure '{s}'", .{v});
    if (!std.mem.startsWith(u8, real[0..n], store) or n == store.len)
        return msg.refuse("spec: closure '{s}' leads out of /nix/store/, to '{s}'", .{ v, real[0..n] });
}

/// tmpfs's size= value: a number with at most one unit suffix, as tmpfs
/// reads it. Nothing else, so the value cannot carry a second option
/// (flong-spec.c:257-267).
fn tmpfsSize(v: []const u8) Error!void {
    var n: usize = 0;
    while (n < v.len and std.ascii.isDigit(v[n])) n += 1;
    if (n == 0 or (n < v.len and (std.mem.indexOfScalar(u8, "kKmMgGtTpPeE%", v[n]) == null or n + 1 != v.len)))
        return msg.refuse("spec: mount tmpfs size is not a number with an optional k, m, g, t, p, e or % suffix: '{s}'", .{v});
}

/// One extent of a map. None reaches host id 0: container root is a subuid
/// on the host, never host root, whatever the wrapper computed
/// (flong-spec.c:269-285).
fn idmap(what: []const u8, f: []const [*:0]const u8) Error!IdMap {
    const e: IdMap = .{
        .inside = try number(what, std.mem.span(f[0]), id_max),
        .outside = try number(what, std.mem.span(f[1]), id_max),
        .count = try number(what, std.mem.span(f[2]), id_max),
    };
    if (e.count == 0)
        return msg.refuse("spec: {s} {s} {s} {s}: the count is 0", .{ what, f[0], f[1], f[2] });
    if (e.count > id_max + 1 - e.inside or e.count > id_max + 1 - e.outside)
        return msg.refuse("spec: {s} {s} {s} {s}: the extent runs past id {d}", .{ what, f[0], f[1], f[2], id_max });
    if (e.outside == 0)
        return msg.refuse("spec: {s} {s} {s} {s} reaches host id 0: flong never maps host root", .{ what, f[0], f[1], f[2] });
    return e;
}

/// The kernel refuses extents that overlap on either side; saying so here
/// names the extents, where newuidmap would say only EINVAL
/// (flong-spec.c:287-299).
fn idmapDisjoint(what: []const u8, m: []const IdMap) Error!void {
    for (m, 0..) |a, i| {
        for (m[i + 1 ..]) |b| {
            if ((a.inside < b.inside + b.count and b.inside < a.inside + a.count) or
                (a.outside < b.outside + b.count and b.outside < a.outside + a.count))
                return msg.refuse("spec: {s} extents {d} {d} {d} and {d} {d} {d} overlap", .{
                    what, a.inside, a.outside, a.count, b.inside, b.outside, b.count,
                });
        }
    }
}

/// Whether `id`, inside the container, is in one of m's extents: an
/// unmapped id is one bwrap and setgroups would fail on after the session
/// is built (flong-spec.c:301-309).
fn idmapCovers(m: []const IdMap, id: u64) bool {
    for (m) |e| {
        if (id >= e.inside and id - e.inside < e.count) return true;
    }
    return false;
}

/// An environment variable's name, for --setenv and --unsetenv
/// (flong-spec.c:311-317).
fn envName(v: []const u8) Error!void {
    if (v.len == 0 or std.mem.indexOfScalar(u8, v, '=') != null)
        return msg.refuse("spec: bwrap-arg: '{s}' is not a variable name", .{v});
}

/// The bwrap options a spec may pass, and how many arguments follow each
/// (flong-spec.c:340-352).
const Opt = enum { clearenv, setenv, unsetenv, hostname, perms, ro_bind_data };
const bwrap_options = [_]struct { name: []const u8, need: usize }{
    .{ .name = "--clearenv", .need = 0 },
    .{ .name = "--setenv", .need = 2 }, // VAR VALUE
    .{ .name = "--unsetenv", .need = 1 }, // VAR
    .{ .name = "--hostname", .need = 1 }, // NAME
    .{ .name = "--perms", .need = 1 }, // OCTAL, before --ro-bind-data
    .{ .name = "--ro-bind-data", .need = 2 }, // FD DEST
};

/// Walks the bwrap-args with their arities and refuses anything outside the
/// allow-list. Every flong-level mount goes through the walker (condition
/// 1), so a path mount here is a wrapper bug; --ro-bind-data writes a fixed
/// file in the fresh root from a keep-fd, before the payload runs. used[i]
/// is set for each keep-fd a --ro-bind-data names (flong-spec.c:354-415).
fn bwrapAllowed(s: *const Spec, used: []bool) Error!void {
    const a = s.bwrap_args;
    var i: usize = 0;
    while (i < a.len) {
        const opt = a[i];
        const o: Opt = for (bwrap_options, 0..) |b, n| {
            if (eql(opt, b.name)) break @enumFromInt(n);
        } else return msg.refuse("spec: bwrap-arg '{s}' is not allowed: flong passes bwrap only --clearenv, " ++
            "--setenv, --unsetenv, --hostname and --perms before --ro-bind-data", .{opt});
        const need = bwrap_options[@intFromEnum(o)].need;
        if (a.len - i - 1 < need)
            return msg.refuse("spec: bwrap-arg {s}: {d} argument{s} expected", .{ opt, need, if (need == 1) "" else "s" });
        switch (o) {
            .clearenv => {},
            .setenv, .unsetenv => try envName(a[i + 1]),
            .hostname => if (a[i + 1].len == 0) return msg.refuse("spec: bwrap-arg --hostname is empty", .{}),
            .perms => {
                try octal("bwrap-arg --perms", a[i + 1]);
                if (i + 2 >= a.len or !eql(a[i + 2], bwrap_options[@intFromEnum(Opt.ro_bind_data)].name))
                    return msg.refuse("spec: bwrap-arg --perms is allowed only before --ro-bind-data", .{});
            },
            .ro_bind_data => {
                const n = try number("bwrap-arg --ro-bind-data's descriptor", a[i + 1], int_max);
                const k = std.mem.indexOfScalar(sys.fd_t, s.keep_fds, @intCast(n)) orelse
                    return msg.refuse("spec: bwrap-arg --ro-bind-data names descriptor {d}, which is no keep-fd", .{n});
                used[k] = true;
                try clean("bwrap-arg --ro-bind-data's destination", a[i + 2], .absolute);
            },
        }
        i += 1 + need;
    }
}

/// fcntl(2)'s F_GETFD: whether a descriptor is open (asm-generic/fcntl.h).
const F_GETFD = 1;

/// spec_parse (flong-spec.c:417-708): argv[1..] into a Spec whose strings
/// are argv's, its arrays in `arena`, sized by the first pass. Refuses to
/// run as root first (:423); then an unknown keyword, a missing field, a
/// singleton keyword given twice, a missing required keyword, a relative
/// path, a bad name, a limit file not in the list, a map that reaches host
/// id 0, a post-stop outside /nix/store/, a keep-fd that is not open and a
/// bwrap-arg outside the allowed options, each said once and returned as
/// `error.Reported` (flong-spec.h:115-120). Nothing is in the descriptor
/// table yet (ordering checkpoint 1): the keep-fds are checked by number,
/// and adopted by the caller after.
pub fn parse(arena: Allocator, argv: []const [*:0]const u8) Error!Spec {
    std.debug.assert(fd.liveCount() == 0);
    try proc.refuseRoot();

    // Pass 1: the shape.
    var count = [_]usize{0} ** kw_n;
    var end: usize = 1;
    while (end < argv.len and !eql(std.mem.span(argv[end]), "--")) {
        const k = keyword(std.mem.span(argv[end])) orelse
            return msg.refuse("spec: unknown keyword '{s}'", .{argv[end]});
        const n = try arity(argv, end, k);
        count[@intFromEnum(k)] += 1;
        if (count[@intFromEnum(k)] > 1 and keywords[@intFromEnum(k)].flags & once != 0)
            return msg.refuse("spec: {s} given more than once", .{keywords[@intFromEnum(k)].name});
        end += 1 + n;
    }
    if (end >= argv.len) return msg.refuse("spec: no '--' before the command", .{});
    if (end + 1 == argv.len) return msg.refuse("spec: the command after '--' is empty", .{});
    for (keywords, count) |k, c| {
        if (k.flags & required != 0 and c == 0) return msg.refuse("spec: {s} is missing", .{k.name});
    }

    // The arrays, each at its final size.
    const t = tables(arena, &count) catch return msg.fail(.NOMEM, "spec", .{});
    var n_relaunch: usize = 0;
    var n_uidmap: usize = 0;
    var n_gidmap: usize = 0;
    var n_groups: usize = 0;
    var n_mounts: usize = 0;
    var n_protect: usize = 0;
    var n_seccomp: usize = 0;
    var n_holder_start: usize = 0;
    var n_limits: usize = 0;
    var n_post_start: usize = 0;
    var n_pasta_args: usize = 0;
    var n_bwrap_args: usize = 0;
    var n_keep_fds: usize = 0;
    var s: Spec = .{
        .machine = undefined,
        .container = undefined,
        .state = undefined,
        .cache = undefined,
        .closure = undefined,
        .uidmap = t.uidmap,
        .gidmap = t.gidmap,
        .uid = undefined,
        .gid = undefined,
        .home = undefined,
        .holder = undefined,
        .relaunch = t.relaunch,
        .groups = t.groups,
        .mounts = t.mounts,
        .protect = t.protect,
        .seccomp = t.seccomp,
        .holder_start = t.holder_start,
        .limits = t.limits,
        .post_start = t.post_start,
        .pasta_args = t.pasta_args,
        .bwrap_args = t.bwrap_args,
        .keep_fds = t.keep_fds,
        // argv[argc] is null, so the command is argv's own tail.
        .command = argv[end + 1 ..],
    };

    // Pass 2: the meaning of each field.
    var i: usize = 1;
    while (i < end) {
        const k = keyword(std.mem.span(argv[i])).?; // pass 1 knew it
        const n = try arity(argv, i, k);
        const fields = argv[i + 1 ..][0..n];
        const f0: [:0]const u8 = if (n > 0) std.mem.span(fields[0]) else "";
        switch (k) {
            .machine => {
                try name("machine", f0);
                s.machine = f0;
            },
            .container => {
                try name("container", f0);
                s.container = f0;
            },
            .state => {
                try absolute("state", f0);
                s.state = f0;
            },
            .cache => {
                try absolute("cache", f0);
                s.cache = f0;
            },
            .relaunch => {
                t.relaunch[n_relaunch] = f0;
                n_relaunch += 1;
            },
            .closure => {
                try closure(f0);
                s.closure = f0;
            },
            .uidmap => {
                t.uidmap[n_uidmap] = try idmap("uidmap", fields);
                n_uidmap += 1;
            },
            .gidmap => {
                t.gidmap[n_gidmap] = try idmap("gidmap", fields);
                n_gidmap += 1;
            },
            .user => {
                s.uid = @intCast(try number("user's uid", f0, id_max));
                s.gid = @intCast(try number("user's gid", std.mem.span(fields[1]), id_max));
                // The helper decides what lies inside home by its
                // components, so home spells its place exactly.
                const home = std.mem.span(fields[2]);
                try clean("user's home", home, .absolute);
                s.home = home;
            },
            .group => {
                t.groups[n_groups] = @intCast(try number("group", f0, id_max));
                n_groups += 1;
            },
            .chdir => {
                try absolute("chdir", f0);
                s.chdir = f0;
            },
            .mount => {
                const kind = f0;
                const m = &t.mounts[n_mounts];
                n_mounts += 1;
                m.* = .{ .kind = mount_kinds[mountKind(kind).?].kind, .dest = std.mem.span(fields[1]) };
                // A kind's name, a known one, is at most 13 bytes.
                var dest_buf: [64]u8 = undefined;
                const dest_what = std.fmt.bufPrint(&dest_buf, "mount {s} destination", .{kind}) catch unreachable; // proven: 6 + 13 + 12 bytes fit 64
                try clean(dest_what, m.dest, .absolute);
                var src_buf: [64]u8 = undefined;
                const src_what = std.fmt.bufPrint(&src_buf, "mount {s} source", .{kind}) catch unreachable; // proven: 6 + 13 + 7 bytes fit 64
                // A mask has its destination alone.
                const f2: [:0]const u8 = if (n > 2) std.mem.span(fields[2]) else "";
                switch (m.kind) {
                    .bind_ro_exact, .bind_rw_exact => {
                        // The source is canonical: the helper opens it
                        // with RESOLVE_NO_SYMLINKS, and a '..' would walk
                        // it somewhere its spelling does not say.
                        try clean(src_what, f2, .absolute);
                        m.src = f2;
                    },
                    .bind_ro, .bind_rw, .dev, .overlay => {
                        try absolute(src_what, f2);
                        m.src = f2;
                    },
                    .tmpfs => {
                        try octal("mount tmpfs mode", f2);
                        m.mode = f2;
                        const size = std.mem.span(fields[3]);
                        if (size.len != 0) {
                            try tmpfsSize(size);
                            m.size = size;
                        }
                        const owner = std.mem.span(fields[4]);
                        if (eql(owner, "user")) {
                            m.owner_user = true;
                        } else if (!eql(owner, "root")) {
                            return msg.refuse("spec: mount tmpfs owner is neither root nor user: '{s}'", .{owner});
                        }
                    },
                    .mask => {},
                }
            },
            .protect => {
                // clean: a part that does not exist yet is compared as
                // spelled, so it must not spell a ".." there.
                try clean("protect", f0, .absolute);
                t.protect[n_protect] = f0;
                n_protect += 1;
            },
            .seccomp => {
                try absolute("seccomp", f0);
                t.seccomp[n_seccomp] = f0;
                n_seccomp += 1;
            },
            .nested_userns => {
                // 0 would mean nested namespaces off while dropping
                // --assert-userns-disabled: off is the absence of the
                // keyword, never a number.
                s.nested_userns = try number("nested-userns", f0, int_max);
                if (s.nested_userns == 0)
                    return msg.refuse("spec: nested-userns is 0: leave it out to keep nested namespaces off", .{});
            },
            .holder => {
                try clean("holder", f0, .relative);
                s.holder = f0;
            },
            .holder_start => {
                t.holder_start[n_holder_start] = f0;
                n_holder_start += 1;
            },
            .limit => {
                const value = std.mem.span(fields[1]);
                for (limit_files) |l| {
                    if (eql(f0, l)) break;
                } else return msg.refuse("spec: limit '{s}' is not one of memory.max memory.high memory.swap.max " ++
                    "memory.oom.group pids.max cpu.max cpu.weight io.weight", .{f0});
                for (t.limits[0..n_limits]) |l| {
                    if (eql(l.file, f0)) return msg.refuse("spec: limit {s} given more than once", .{f0});
                }
                if (value.len == 0) return msg.refuse("spec: limit {s} has an empty value", .{f0});
                t.limits[n_limits] = .{ .file = f0, .value = value };
                n_limits += 1;
            },
            .post_start => {
                t.post_start[n_post_start] = f0;
                n_post_start += 1;
            },
            .post_stop => {
                // The sweep runs it as the caller from a record the caller
                // can edit, so only a store path, spelled without a '..'
                // that could climb back out. Where a symlink leads is
                // checked when it runs (record.poststop), since the sweep
                // reads the path from the record.
                try storePath("post-stop", f0);
                s.post_stop = f0;
            },
            .network => s.network = true,
            .pasta_arg => {
                t.pasta_args[n_pasta_args] = f0;
                n_pasta_args += 1;
            },
            .pasta_wait => s.pasta_wait = true,
            .bwrap_arg => {
                t.bwrap_args[n_bwrap_args] = f0;
                n_bwrap_args += 1;
            },
            .keep_fd => {
                // 0 to 2 are stdio, which bwrap gets from the terminal's
                // stdio (flong-tty.c).
                const v = try number("keep-fd", f0, int_max);
                if (v < 3) return msg.refuse("spec: keep-fd {d} is stdio", .{v});
                const keep: sys.fd_t = @intCast(v);
                if (std.mem.indexOfScalar(sys.fd_t, t.keep_fds[0..n_keep_fds], keep) != null)
                    return msg.refuse("spec: keep-fd {d} given more than once", .{v});
                _ = try msg.check(sys.fcntl(keep, F_GETFD, 0), "spec: keep-fd {d}", .{v});
                t.keep_fds[n_keep_fds] = keep;
                n_keep_fds += 1;
            },
            .trace => s.trace = true,
        }
        i += 1 + n;
    }

    // Across keywords.
    try idmapDisjoint("uidmap", s.uidmap);
    try idmapDisjoint("gidmap", s.gidmap);
    if (!idmapCovers(s.uidmap, s.uid)) return msg.refuse("spec: user's uid {d} is in no uidmap extent", .{s.uid});
    if (!idmapCovers(s.gidmap, s.gid)) return msg.refuse("spec: user's gid {d} is in no gidmap extent", .{s.gid});
    for (s.groups) |g| {
        if (!idmapCovers(s.gidmap, g)) return msg.refuse("spec: group {d} is in no gidmap extent", .{g});
    }
    // Spawn execs without a PATH search. relaunch is exec'd from the
    // wrapper's own working directory, so its "$0" may be relative, and
    // has no check here (quirk 30, kept: nothing chdirs before the cache
    // lock, ordering checkpoint 1).
    if (s.holder_start.len > 0 and s.holder_start[0][0] != '/')
        return msg.refuse("spec: holder-start's program is not an absolute path: '{s}'", .{s.holder_start[0]});
    if (s.post_start.len > 0 and s.post_start[0][0] != '/')
        return msg.refuse("spec: post-start's program is not an absolute path: '{s}'", .{s.post_start[0]});
    if (!s.network and (s.pasta_args.len > 0 or s.pasta_wait))
        return msg.refuse("spec: pasta-arg or pasta-wait without network", .{});
    // used[j] is set when a --ro-bind-data names keep-fd j.
    const used = arena.alloc(bool, s.keep_fds.len) catch return msg.fail(.NOMEM, "spec", .{});
    @memset(used, false);
    try bwrapAllowed(&s, used);
    // bwrap passes whatever it inherits on to the payload, so a keep-fd
    // that no option consumes would reach the payload open.
    for (s.keep_fds, used) |k, u| {
        if (!u) return msg.refuse("spec: keep-fd {d} is named by no bwrap-arg --ro-bind-data", .{k});
    }
    return s;
}

/// The arrays pass 2 fills, allocated once at the counts pass 1 made
/// (flong-spec.c:452-468). An empty one allocates nothing.
const Tables = struct {
    relaunch: [][:0]const u8,
    uidmap: []IdMap,
    gidmap: []IdMap,
    groups: []u32,
    mounts: []mount.Mount,
    protect: [][:0]const u8,
    seccomp: [][:0]const u8,
    holder_start: [][:0]const u8,
    limits: []Limit,
    post_start: [][:0]const u8,
    pasta_args: [][:0]const u8,
    bwrap_args: [][:0]const u8,
    keep_fds: []sys.fd_t,
};

fn tables(arena: Allocator, count: *const [kw_n]usize) Allocator.Error!Tables {
    const c = struct {
        fn of(counts: *const [kw_n]usize, k: Kw) usize {
            return counts[@intFromEnum(k)];
        }
    }.of;
    return .{
        .relaunch = try arena.alloc([:0]const u8, c(count, .relaunch)),
        .uidmap = try arena.alloc(IdMap, c(count, .uidmap)),
        .gidmap = try arena.alloc(IdMap, c(count, .gidmap)),
        .groups = try arena.alloc(u32, c(count, .group)),
        .mounts = try arena.alloc(mount.Mount, c(count, .mount)),
        .protect = try arena.alloc([:0]const u8, c(count, .protect)),
        .seccomp = try arena.alloc([:0]const u8, c(count, .seccomp)),
        .holder_start = try arena.alloc([:0]const u8, c(count, .holder_start)),
        .limits = try arena.alloc(Limit, c(count, .limit)),
        .post_start = try arena.alloc([:0]const u8, c(count, .post_start)),
        .pasta_args = try arena.alloc([:0]const u8, c(count, .pasta_arg)),
        .bwrap_args = try arena.alloc([:0]const u8, c(count, .bwrap_arg)),
        .keep_fds = try arena.alloc(sys.fd_t, c(count, .keep_fd)),
    };
}

// ---- bwrap's argv ----

/// bwrap's argv after its program, in DESIGN.md's order ("The input
/// contract"; flong-launch.c:269-332): the fixed part, the wrapper's
/// bwrap-args, then flong init and its protocol. The fixed part comes first
/// so nothing the wrapper adds can undo it, and flong init's protocol is
/// its argv, after everything, so a --clearenv among the wrapper's options
/// cannot drop it.
///
/// `sp` is where the words go: a proc.Spawn begun with bwrap's path, or
/// anything with its `arg` and `passFd`. Each descriptor is named only
/// through `passFd`, which keeps it in bwrap at that number: `fds` holds
/// U1, U2, the info pipe's write end, the seccomp files (a slice, in the
/// spec's order), the gate's read end and the ready pipe's write end.
/// `relay` is the terminal's (tty.zig), `self` the flong binary's path,
/// which bwrap runs with the word "init". The words made here (numbers,
/// joined paths) are `gpa`'s.
pub fn bwrapArgv(gpa: Allocator, sp: anytype, s: *const Spec, fds: anytype, relay: bool, self: [*:0]const u8) Allocator.Error!void {
    const a = struct {
        fn z(al: Allocator, comptime fmt: []const u8, args: anytype) Allocator.Error![*:0]const u8 {
            return (try std.fmt.allocPrintSentinel(al, fmt, args, 0)).ptr;
        }
    };
    try sp.arg("--userns");
    try sp.passFd(fds.u1);
    try sp.arg("--userns2");
    try sp.passFd(fds.u2);
    // nestedSandbox gives U2 user namespaces of its own; bwrap would
    // refuse them otherwise.
    if (s.nested_userns == 0) try sp.arg("--assert-userns-disabled");
    for ([_][*:0]const u8{ "--unshare-net", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup", "--die-with-parent", "--as-pid-1", "--info-fd" }) |w| try sp.arg(w);
    try sp.passFd(fds.info_w);
    // Only a relayed pty gets a session of its own: in passthrough a new
    // session would break ^C, SIGWINCH and job control on the caller's
    // terminal.
    if (relay) try sp.arg("--new-session");
    for (fds.seccomp) |h| {
        try sp.arg("--add-seccomp-fd");
        try sp.passFd(h);
    }
    // For flong init's setgroups and capability drop, which leaves the
    // payload with none.
    for ([_][*:0]const u8{ "--cap-add", "CAP_SETGID", "--cap-add", "CAP_SETPCAP", "--uid" }) |w| try sp.arg(w);
    try sp.arg(try a.z(gpa, "{d}", .{s.uid}));
    try sp.arg("--gid");
    try sp.arg(try a.z(gpa, "{d}", .{s.gid}));
    try sp.arg("--overlay-src");
    try sp.arg(try a.z(gpa, "{s}/prepared", .{s.cache}));
    for ([_][*:0]const u8{
        "--tmp-overlay",   "/",
        "--ro-bind",       "/nix/store",
        "/nix/store",      "--ro-bind",
        "/nix/var/nix/db", "/nix/var/nix/db",
        "--proc",          "/proc",
        "--dev",           "/dev",
        "--perms",         "0755",
        "--tmpfs",         "/run",
        "--ro-bind",
    }) |w| try sp.arg(w);
    try sp.arg(s.closure.ptr);
    for ([_][*:0]const u8{ "/run/current-system", "--perms", "0755", "--dir", "/run/user", "--perms", "0700", "--tmpfs" }) |w| try sp.arg(w);
    try sp.arg(try a.z(gpa, "/run/user/{d}", .{s.uid}));
    for ([_][*:0]const u8{ "--perms", "1777", "--tmpfs", "/tmp" }) |w| try sp.arg(w);
    // The kernel mounts a fresh sysfs only where one is already visible.
    // The mount helper mounts the session's own /sys and detaches this.
    for ([_][*:0]const u8{ "--ro-bind", "/sys", "/.hostsys" }) |w| try sp.arg(w);

    for (s.bwrap_args) |w| try sp.arg(w.ptr);

    try sp.arg("--");
    try sp.arg(self);
    try sp.arg("init");
    try sp.passFd(fds.gate_r);
    try sp.passFd(fds.ready_w);
    try sp.arg(try groupsArg(gpa, s.groups));
    try sp.arg(if (relay) "ctty" else "-");
    try sp.arg(if (s.trace) "trace" else "-");
    try sp.arg(s.chdir.ptr);
    try sp.arg("--");
    for (s.command) |w| try sp.arg(w);
}

/// flong init's <groups> argument: comma-separated gids, or "-"
/// (flong-launch.c:252-267).
fn groupsArg(gpa: Allocator, groups: []const u32) Allocator.Error![*:0]const u8 {
    if (groups.len == 0) return "-";
    var out: std.ArrayList(u8) = .empty;
    for (groups, 0..) |g, i| try out.print(gpa, "{s}{d}", .{ if (i > 0) "," else "", g });
    return (try out.toOwnedSliceSentinel(gpa, 0)).ptr;
}

// ---- tests ----
// Parsing from outside, the model property, each refusal and bwrapArgv's
// golden argv are tests/zig/spec_test.zig's, which has a store path for
// the closure.

const testing = std.testing;

test "number, octal and tmpfs sizes accept what the C accepts" {
    msg.prog = "spec-test";
    try testing.expectEqual(@as(u64, 4294967294), try number("n", "4294967294", id_max));
    try testing.expectEqual(@as(u64, 7), try number("n", "0007", id_max));
    try testing.expectEqual(@as(u64, 2147483647), try number("n", "2147483647", int_max));
    try octal("m", "07777");
    try octal("m", "00000");
    try tmpfsSize("100%");
    try tmpfsSize("1E");
    try tmpfsSize("0");
}

test "clean takes plain components only" {
    msg.prog = "spec-test";
    try clean("p", "/a/b", .absolute);
    try clean("p", "a/b.c", .relative);
    try clean("p", "/" ++ "a" ** 255, .absolute);
    try clean("p", "/...", .absolute);
}

test "the extents' overlap and cover" {
    const m = [_]IdMap{ .{ .inside = 0, .outside = 100000, .count = 65536 }, .{ .inside = 65536, .outside = 1, .count = 1 } };
    try idmapDisjoint("uidmap", &m);
    try testing.expect(idmapCovers(&m, 0));
    try testing.expect(idmapCovers(&m, 65536));
    try testing.expect(!idmapCovers(&m, 65537));
    try testing.expect(idmapCovers(&.{.{ .inside = id_max, .outside = 1, .count = 1 }}, id_max));
}

test "groupsArg joins with commas, or says -" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqualStrings("-", std.mem.span(try groupsArg(arena.allocator(), &.{})));
    try testing.expectEqualStrings("0,4294967294,7", std.mem.span(try groupsArg(arena.allocator(), &.{ 0, 4294967294, 7 })));
}
