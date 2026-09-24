//! spec.zig: what a launch is asked to do, as a value, and every check that
//! needs nothing but it: launcher/flong-spec.c's checks (:106-415, 676-708
//! of 5f1f08e), with flong-spec.h's struct as `Spec` (the Zig port's L1).
//!
//! `flong launch DECL.zon|NAME` builds the spec in process from the
//! declaration and what only the launch can know (launch/assemble.zig), and
//! hands it to `validate` before anything is in the descriptor table
//! (ordering checkpoint 1). Until STANDALONE.md's S3 the spec was
//! rootless-wrapper.bash's argv, a sequence of keywords each followed by
//! its fields; that parser went with the wrapper, and its checks are
//! `validate`'s, run over the value.
//!
//! Every refusal names the field in the words the argv spec used for it
//! (`uidmap`, `user's home`, `mount bind-ro source`, `post-stop`...), since
//! a refusal here is a bug in the assembly or a declaration flong check
//! let through, and the words are the ones DESIGN.md's "Kept behaviour"
//! and the tests quote. Each is said once, in the launcher's cut mode, and
//! passed up as `error.Reported`.

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

/// A command: its argv, the program first, never empty. Nothing searches
/// PATH, so the program is an absolute path.
pub const Command = []const [:0]const u8;

/// One variable of the payload's environment (Spec.env).
pub const Var = struct { name: [:0]const u8, value: [:0]const u8 };

/// struct fl_spec (flong-spec.h:58-113). A list is empty when the launch
/// has none of it.
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
    /// postStart's commands, run in order, the first failure ending the
    /// launch; empty: no hook
    post_start: []const Command = &.{},
    /// postStop's commands, in order, each's program under /nix/store/;
    /// recorded for the sweep (record.zig); empty: none
    post_stop: []const Command = &.{},
    /// start pasta
    network: bool = false,
    /// ports, --dns-forward, --no-map-gw ...
    pasta_args: []const [:0]const u8 = &.{},
    /// fixed forwardPorts bind host ports: wait for pasta's exit
    pasta_wait: bool = false,

    // bwrap
    /// The payload's environment, built from nothing: bwrap's --clearenv,
    /// then a --setenv for each, in order. null: no --clearenv, and the
    /// payload inherits bwrap's environment (only tests leave it null)
    env: ?[]const Var = null,
    /// bwrap's --hostname; null: none
    hostname: ?[:0]const u8 = null,
    /// A networked session's /etc/resolv.conf, whole: bwrap binds it there
    /// read-only, mode 0644, from a memfd the spawn writes it into
    /// (launch/bwrap.zig). null: none
    resolv_conf: ?[]const u8 = null,

    trace: bool = false,
    /// what tini runs; never empty. A null follows its last word, as
    /// argv[argc] follows argv's (assemble.zig allocates it with the
    /// sentinel; sys.argvSlots)
    command: []const [*:0]const u8,
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

// ---- field checks: each says its refusal and returns it ----

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
/// before `validate` goes on.
fn closure(v: [:0]const u8) Error!void {
    try storePath("closure", v);
    const h = try msg.check(fd.openPath(fd.cwd, v, .{}), "spec: closure '{s}'", .{v});
    defer h.close();
    var real: [sys.path_max]u8 = undefined;
    const link = fd.selfPath(h);
    const n = try msg.check(sys.readlinkat(sys.AT.FDCWD, link.path(), &real), "spec: closure '{s}'", .{v});
    if (n >= real.len) return msg.fail(.NAMETOOLONG, "spec: closure '{s}'", .{v});
    if (outOfStore(real[0..n]))
        return msg.refuse("spec: closure '{s}' leads out of /nix/store/, to '{s}'", .{ v, real[0..n] });
}

/// Whether a closure's canonical path leads out of the store: it is not
/// under /nix/store/, prefix checked with its slash, or it is the store's
/// own directory (the golden cases closure-leads-out and closure-to-store,
/// a store symlink to / and one to /nix/store, until S3).
fn outOfStore(real: []const u8) bool {
    return !std.mem.startsWith(u8, real, store) or real.len == store.len;
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

/// An environment variable's name, for --setenv (flong-spec.c:311-317),
/// refused in the words of the argv spec's bwrap-arg.
fn envName(v: []const u8) Error!void {
    if (v.len == 0 or std.mem.indexOfScalar(u8, v, '=') != null)
        return msg.refuse("spec: bwrap-arg: '{s}' is not a variable name", .{v});
}

/// The checks across fields (flong-spec.c:680-706), `validate`'s tail: a
/// map covering the payload's ids, the programs absolute, pasta's words
/// with a network.
fn across(s: *const Spec) Error!void {
    try idmapDisjoint("uidmap", s.uidmap);
    try idmapDisjoint("gidmap", s.gidmap);
    if (!idmapCovers(s.uidmap, s.uid)) return msg.refuse("spec: user's uid {d} is in no uidmap extent", .{s.uid});
    if (!idmapCovers(s.gidmap, s.gid)) return msg.refuse("spec: user's gid {d} is in no gidmap extent", .{s.gid});
    for (s.groups) |g| {
        if (!idmapCovers(s.gidmap, g)) return msg.refuse("spec: group {d} is in no gidmap extent", .{g});
    }
    // Spawn execs without a PATH search.
    if (s.holder_start.len > 0 and (s.holder_start[0].len == 0 or s.holder_start[0][0] != '/'))
        return msg.refuse("spec: holder-start's program is not an absolute path: '{s}'", .{s.holder_start[0]});
    for (s.post_start) |cmd| {
        if (cmd[0].len == 0 or cmd[0][0] != '/')
            return msg.refuse("spec: post-start's program is not an absolute path: '{s}'", .{cmd[0]});
    }
    if (!s.network and (s.pasta_args.len > 0 or s.pasta_wait))
        return msg.refuse("spec: pasta-arg or pasta-wait without network", .{});
}

/// The spec's checks over a value (flong-spec.c:417-708 without the
/// parse), refusing root first: each field's, in the order the argv spec's
/// parse checked them, then `across`. A number is printed as the value it
/// is. The typed environment's names and the hostname are checked as the
/// bwrap-args that once said them were. Nothing is opened but the
/// closure, which is closed again.
pub fn validate(s: *const Spec) Error!void {
    try proc.refuseRoot();
    try name("machine", s.machine);
    try name("container", s.container);
    try absolute("state", s.state);
    try absolute("cache", s.cache);
    try closure(s.closure);
    if (s.uidmap.len == 0) return msg.refuse("spec: uidmap is missing", .{});
    if (s.gidmap.len == 0) return msg.refuse("spec: gidmap is missing", .{});
    for (s.uidmap) |e| try idmapValue("uidmap", e);
    for (s.gidmap) |e| try idmapValue("gidmap", e);
    try idValue("user's uid", s.uid);
    try idValue("user's gid", s.gid);
    try clean("user's home", s.home, .absolute);
    for (s.groups) |g| try idValue("group", g);
    try absolute("chdir", s.chdir);
    for (s.mounts) |*m| try mountValue(m);
    for (s.protect) |p| try clean("protect", p, .absolute);
    for (s.seccomp) |p| try absolute("seccomp", p);
    if (s.nested_userns > int_max)
        return msg.refuse("spec: nested-userns is larger than {d}: '{d}'", .{ int_max, s.nested_userns });
    try clean("holder", s.holder, .relative);
    for (s.limits, 0..) |l, i| {
        for (limit_files) |f| {
            if (eql(l.file, f)) break;
        } else return msg.refuse("spec: limit '{s}' is not one of memory.max memory.high memory.swap.max " ++
            "memory.oom.group pids.max cpu.max cpu.weight io.weight", .{l.file});
        for (s.limits[0..i]) |o| {
            if (eql(o.file, l.file)) return msg.refuse("spec: limit {s} given more than once", .{l.file});
        }
        if (l.value.len == 0) return msg.refuse("spec: limit {s} has an empty value", .{l.file});
    }
    for (s.post_start) |cmd| {
        if (cmd.len == 0) return msg.refuse("spec: post-start's word count is 0", .{});
    }
    for (s.post_stop) |cmd| {
        if (cmd.len == 0) return msg.refuse("spec: post-stop's word count is 0", .{});
        try storePath("post-stop", cmd[0]);
    }
    if (s.env) |env| for (env) |v| try envName(v.name);
    if (s.hostname) |h| if (h.len == 0) return msg.refuse("spec: bwrap-arg --hostname is empty", .{});
    if (s.command.len == 0) return msg.refuse("spec: the command after '--' is empty", .{});
    try across(s);
}

/// An id, at most id_max.
fn idValue(what: []const u8, v: u64) Error!void {
    if (v > id_max) return msg.refuse("spec: {s} is larger than {d}: '{d}'", .{ what, id_max, v });
}

/// One extent of a map. None reaches host id 0: container root is a subuid
/// on the host, never host root, whatever the assembly computed
/// (flong-spec.c:269-285).
fn idmapValue(what: []const u8, e: IdMap) Error!void {
    inline for (.{ "inside", "outside", "count" }) |f| {
        if (@field(e, f) > id_max)
            return msg.refuse("spec: {s} {d} {d} {d}: the {s} is larger than {d}", .{ what, e.inside, e.outside, e.count, f, id_max });
    }
    if (e.count == 0)
        return msg.refuse("spec: {s} {d} {d} {d}: the count is 0", .{ what, e.inside, e.outside, e.count });
    if (e.count > id_max + 1 - e.inside or e.count > id_max + 1 - e.outside)
        return msg.refuse("spec: {s} {d} {d} {d}: the extent runs past id {d}", .{ what, e.inside, e.outside, e.count, id_max });
    if (e.outside == 0)
        return msg.refuse("spec: {s} {d} {d} {d} reaches host id 0: flong never maps host root", .{ what, e.inside, e.outside, e.count });
}

/// A mount kind as the argv spec named it, for the refusals.
fn kindName(k: mount.Kind) []const u8 {
    return switch (k) {
        .bind_ro => "bind-ro",
        .bind_rw => "bind-rw",
        .bind_ro_exact => "bind-ro-exact",
        .bind_rw_exact => "bind-rw-exact",
        .dev => "dev",
        .tmpfs => "tmpfs",
        .overlay => "overlay",
        .mask => "mask",
    };
}

/// A mount's fields: its destination clean, its source as its kind needs,
/// a tmpfs's mode and size (flong-spec.c:520-575).
fn mountValue(m: *const mount.Mount) Error!void {
    const kind = kindName(m.kind);
    var dest_buf: [64]u8 = undefined;
    const dest_what = std.fmt.bufPrint(&dest_buf, "mount {s} destination", .{kind}) catch unreachable; // proven: 6 + 13 + 12 bytes fit 64
    try clean(dest_what, m.dest, .absolute);
    var src_buf: [64]u8 = undefined;
    const src_what = std.fmt.bufPrint(&src_buf, "mount {s} source", .{kind}) catch unreachable; // proven: 6 + 13 + 7 bytes fit 64
    switch (m.kind) {
        .bind_ro_exact, .bind_rw_exact => try clean(src_what, m.src orelse "", .absolute),
        .bind_ro, .bind_rw, .dev, .overlay => try absolute(src_what, m.src orelse ""),
        .tmpfs => {
            try octal("mount tmpfs mode", m.mode orelse "");
            if (m.size) |size| try tmpfsSize(size);
        },
        .mask => {},
    }
}

// ---- bwrap's argv ----

/// bwrap's argv after its program, in DESIGN.md's order ("bwrap's argv";
/// flong-launch.c:269-332): the fixed part, the typed options (the
/// resolver, the environment, the hostname), then flong init and its
/// protocol. The fixed part comes first so nothing after it can undo it,
/// and flong init's protocol is its argv, after everything, so the
/// --clearenv cannot drop it.
///
/// `sp` is where the words go: a proc.Spawn begun with bwrap's path, or
/// anything with its `arg` and `passFd`. Each descriptor is named only
/// through `passFd`, which keeps it in bwrap at that number: `fds` holds
/// U1, U2, the info pipe's write end, the seccomp files (a slice, in the
/// spec's order), the resolver's memfd (null without a resolv_conf), the
/// gate's read end and the ready pipe's write end.
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

    // The typed options, in the order the wrapper's bwrap-args gave them
    // before S3: the resolver's file from its memfd, the environment from
    // nothing, the hostname.
    if (s.resolv_conf != null) {
        for ([_][*:0]const u8{ "--perms", "0644", "--ro-bind-data" }) |w| try sp.arg(w);
        try sp.passFd(fds.resolv.?);
        try sp.arg("/etc/resolv.conf");
    }
    if (s.env) |env| {
        try sp.arg("--clearenv");
        for (env) |v| {
            try sp.arg("--setenv");
            try sp.arg(v.name.ptr);
            try sp.arg(v.value.ptr);
        }
    }
    if (s.hostname) |h| {
        try sp.arg("--hostname");
        try sp.arg(h.ptr);
    }

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
// validate's refusals over values, and bwrapArgv's golden argv, are
// tests/zig/spec_test.zig's, which has a store path for the closure.

const testing = std.testing;

test "octal and tmpfs sizes accept what the C accepts" {
    msg.prog = "spec-test";
    try octal("m", "07777");
    try octal("m", "00000");
    try tmpfsSize("100%");
    try tmpfsSize("1E");
    try tmpfsSize("0");
}

test "a closure leads out of the store to /, to the store itself, or beside it" {
    try testing.expect(outOfStore("/"));
    try testing.expect(outOfStore("/nix/store"));
    try testing.expect(outOfStore("/nix/store/"));
    try testing.expect(outOfStore("/nix/storex/y"));
    try testing.expect(outOfStore("/tmp/nix/store/x"));
    try testing.expect(!outOfStore("/nix/store/x"));
    try testing.expect(!outOfStore("/nix/store/x-closure/sw"));
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
