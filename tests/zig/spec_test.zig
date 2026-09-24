//! spec.zig from outside (minish, the `test` step; DESIGN.md, "Tests";
//! the Zig port's L1): bwrapArgv's golden argv per branch (plain, relay,
//! nestedSandbox, a project filter, the typed options, trace); and
//! spec.validate over values: a spec with every field at an edge that
//! passes, each refusal the argv spec's golden cases pinned that a value
//! can still reach (tests/golden/spec/ until S3 deleted the argv spec;
//! each case below keeps its name), specs drawn from a model passing, and
//! each single-rule mutation of one refused with its message, one line on
//! stderr, cut as the launcher cuts it (quirk 22).
//!
//! The closure must be a real path in the store: options.store is one
//! (build.zig: the directory of the zig that builds this), and
//! options.store_file a file in it.

const std = @import("std");
const linux = std.os.linux;
const minish = @import("minish");
const fd = @import("fd");
const msg = @import("msg");
const mount = @import("mount");
const spec = @import("spec");
const options = @import("options");
const testing = std.testing;
const Allocator = std.mem.Allocator;

/// NUL-terminated, as a spec's paths are.
const store = options.store ++ "";

// ---- stderr, by raw calls ----

/// What a call wrote on stderr: fd 2 is a memfd for its length.
const Capture = struct {
    saved: i32,
    file: i32,

    fn begin() !Capture {
        const mf = linux.memfd_create("spec-test", linux.MFD.CLOEXEC);
        if (linux.E.init(mf) != .SUCCESS) return error.Memfd;
        const saved = linux.fcntl(2, 1030, 10); // F_DUPFD_CLOEXEC
        if (linux.E.init(saved) != .SUCCESS) return error.Dup;
        if (linux.E.init(linux.dup2(@intCast(mf), 2)) != .SUCCESS) return error.Dup;
        return .{ .saved = @intCast(saved), .file = @intCast(mf) };
    }

    fn end(self: Capture, buf: []u8) ![]const u8 {
        _ = linux.dup2(self.saved, 2);
        _ = linux.close(self.saved);
        defer _ = linux.close(self.file);
        const n = linux.pread(self.file, buf.ptr, buf.len, 0);
        if (linux.E.init(n) != .SUCCESS) return error.Read;
        return buf[0..n];
    }
};

/// Validates `s` as flong launch does, in its cut mode, and returns what it
/// said on stderr: empty when it passed. Nothing is left open.
fn validateSaid(s: *const spec.Spec, errbuf: []u8) !struct { ok: bool, err: []const u8 } {
    msg.prog = "flong launch";
    msg.mode = .cut;
    const cap = try Capture.begin();
    const r = spec.validate(s);
    const err = try cap.end(errbuf);
    try testing.expectEqual(@as(usize, 0), fd.liveCount());
    return .{ .ok = if (r) |_| true else |_| false, .err = err };
}

/// `want`'s line as the launcher's cut mode writes it: "flong launch: ",
/// the refusal, the whole cut at msg.cut_len bytes, and a newline.
fn line(a: Allocator, want: []const u8) ![]const u8 {
    const whole = try std.mem.concat(a, u8, &.{ "flong launch: ", want });
    return std.mem.concat(a, u8, &.{ whole[0..@min(whole.len, msg.cut_len)], "\n" });
}

fn expectRefused(a: Allocator, s: *const spec.Spec, want: []const u8) !void {
    var errbuf: [4096]u8 = undefined;
    const r = try validateSaid(s, &errbuf);
    try testing.expectEqualStrings(try line(a, want), r.err);
    try testing.expect(!r.ok);
}

fn expectPasses(s: *const spec.Spec) !void {
    var errbuf: [4096]u8 = undefined;
    const r = try validateSaid(s, &errbuf);
    try testing.expectEqualStrings("", r.err);
    try testing.expect(r.ok);
}

// ---- bwrapArgv's golden argv ----

/// A Spawn's `arg` and `passFd`, recording the words; a descriptor is its
/// name.
const Recorder = struct {
    gpa: Allocator,
    words: std.ArrayList([]const u8) = .empty,

    pub fn arg(self: *Recorder, a: [*:0]const u8) Allocator.Error!void {
        try self.words.append(self.gpa, std.mem.span(a));
    }

    pub fn passFd(self: *Recorder, h: Named) Allocator.Error!void {
        try self.words.append(self.gpa, h.name);
    }
};

const Named = struct { name: []const u8 };

const seccomp_fds = [_]Named{ .{ .name = "@SECCOMP0@" }, .{ .name = "@SECCOMP1@" }, .{ .name = "@SECCOMP2@" } };

const uidmap = [_]spec.IdMap{
    .{ .inside = 0, .outside = 100000, .count = 1000 },
    .{ .inside = 1000, .outside = 1000, .count = 1 },
    .{ .inside = 1001, .outside = 101001, .count = 64535 },
};
const gidmap = [_]spec.IdMap{
    .{ .inside = 0, .outside = 100000, .count = 100 },
    .{ .inside = 100, .outside = 100, .count = 1 },
    .{ .inside = 101, .outside = 100101, .count = 65435 },
};
const command = [_][*:0]const u8{ "sh", "-c", "exec \"$@\"", "--" };

/// The spec every branch starts from: a caller's usual one, two groups.
fn base() spec.Spec {
    return .{
        .machine = "m",
        .container = "c",
        .state = "/run/user/1000/flong",
        .cache = "/home/u/.cache/flong/c",
        .closure = store,
        .uidmap = &uidmap,
        .gidmap = &gidmap,
        .uid = 1000,
        .gid = 100,
        .home = "/home/u",
        .groups = &.{ 100, 27 },
        .chdir = "/home/u/w",
        .holder = "flong.slice/s",
        .command = &command,
    };
}

/// `s`'s argv against `want`, @CLOSURE@ standing for the closure and
/// @X@ for each descriptor bwrap is passed.
fn expectArgv(s: spec.Spec, relay: bool, want: []const []const u8) !void {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try expectPasses(&s);

    var rec: Recorder = .{ .gpa = arena };
    try spec.bwrapArgv(arena, &rec, &s, .{
        .u1 = Named{ .name = "@U1@" },
        .u2 = Named{ .name = "@U2@" },
        .info_w = Named{ .name = "@INFO@" },
        .seccomp = seccomp_fds[0..s.seccomp.len],
        .resolv = if (s.resolv_conf != null) @as(?Named, .{ .name = "@RESOLV@" }) else null,
        .gate_r = Named{ .name = "@GATE@" },
        .ready_w = Named{ .name = "@READY@" },
    }, relay, "/nix/store/test-only-flong");

    for (want, 0..) |w, i| {
        if (i >= rec.words.items.len) break;
        const x = try std.mem.replaceOwned(u8, arena, w, "@CLOSURE@", store);
        testing.expectEqualStrings(x, rec.words.items[i]) catch |err| {
            std.debug.print("bwrap argv word {d} differs\n", .{i});
            return err;
        };
    }
    try testing.expectEqual(want.len, rec.words.items.len);
}

/// The fixed part up to --info-fd's number, as the C's bwrap_argv pushes it
/// (flong-launch.c:274-294), nested namespaces off.
const head = [_][]const u8{
    "--userns",          "@U1@",          "--userns2",     "@U2@",          "--assert-userns-disabled",
    "--unshare-net",     "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup",
    "--die-with-parent", "--as-pid-1",    "--info-fd",     "@INFO@",
};
/// From the capabilities to /.hostsys (:299-317).
const middle = [_][]const u8{
    "--cap-add",           "CAP_SETGID",                      "--cap-add",     "CAP_SETPCAP",
    "--uid",               "1000",                            "--gid",         "100",
    "--overlay-src",       "/home/u/.cache/flong/c/prepared", "--tmp-overlay", "/",
    "--ro-bind",           "/nix/store",                      "/nix/store",    "--ro-bind",
    "/nix/var/nix/db",     "/nix/var/nix/db",                 "--proc",        "/proc",
    "--dev",               "/dev",                            "--perms",       "0755",
    "--tmpfs",             "/run",                            "--ro-bind",     "@CLOSURE@",
    "/run/current-system", "--perms",                         "0755",          "--dir",
    "/run/user",           "--perms",                         "0700",          "--tmpfs",
    "/run/user/1000",      "--perms",                         "1777",          "--tmpfs",
    "/tmp",                "--ro-bind",                       "/sys",          "/.hostsys",
};
const init_plain = [_][]const u8{ "--", "/nix/store/test-only-flong", "init", "@GATE@", "@READY@", "100,27", "-", "-", "/home/u/w" };
const tail_command = [_][]const u8{ "--", "sh", "-c", "exec \"$@\"", "--" };

fn cat(comptime parts: []const []const []const u8) []const []const u8 {
    comptime var out: []const []const u8 = &.{};
    inline for (parts) |p| out = out ++ p;
    return out;
}

test "bwrapArgv: plain" {
    try expectArgv(base(), false, comptime cat(&.{ &head, &middle, &init_plain, &tail_command }));
}

test "bwrapArgv: relay, a session of its own and flong init's ctty" {
    try expectArgv(base(), true, comptime cat(&.{
        &head,
        &.{"--new-session"},
        &middle,
        &.{ "--", "/nix/store/test-only-flong", "init", "@GATE@", "@READY@", "100,27", "ctty", "-", "/home/u/w" },
        &tail_command,
    }));
}

test "bwrapArgv: nestedSandbox drops --assert-userns-disabled" {
    var s = base();
    s.nested_userns = 128;
    try expectArgv(s, false, comptime cat(&.{
        &.{ "--userns", "@U1@", "--userns2", "@U2@" },
        head[5..],
        &middle,
        &init_plain,
        &tail_command,
    }));
}

test "bwrapArgv: the tier's filters and a project filter, one --add-seccomp-fd each, in order" {
    var s = base();
    s.seccomp = &.{ "/nix/store/a-tier.bpf", "/nix/store/b-audit.bpf", "/home/u/.cache/flong/seccomp/k" };
    try expectArgv(s, false, comptime cat(&.{
        &head,
        &.{ "--add-seccomp-fd", "@SECCOMP0@", "--add-seccomp-fd", "@SECCOMP1@", "--add-seccomp-fd", "@SECCOMP2@" },
        &middle,
        &init_plain,
        &tail_command,
    }));
}

test "bwrapArgv: the resolver from its memfd, the environment from nothing, the hostname, after the fixed part" {
    var s = base();
    s.resolv_conf = "nameserver 169.254.1.1\n";
    s.env = &.{ .{ .name = "HOME", .value = "/home/u" }, .{ .name = "TERM", .value = "" } };
    s.hostname = "c";
    try expectArgv(s, false, comptime cat(&.{
        &head,
        &middle,
        &.{ "--perms", "0644", "--ro-bind-data", "@RESOLV@", "/etc/resolv.conf" },
        &.{ "--clearenv", "--setenv", "HOME", "/home/u", "--setenv", "TERM", "", "--hostname", "c" },
        &init_plain,
        &tail_command,
    }));
}

test "bwrapArgv: trace, and no groups" {
    var s = base();
    s.groups = &.{};
    s.trace = true;
    s.command = &.{"true"};
    try expectArgv(s, false, comptime cat(&.{
        &head,
        &middle,
        &.{ "--", "/nix/store/test-only-flong", "init", "@GATE@", "@READY@", "-", "-", "trace", "/home/u/w", "--", "true" },
    }));
}

// ---- validate: the argv spec's golden cases, as values ----

/// golden/spec's valid spec: machine m, container c, state /state, cache
/// /cache, the closure, uidmap and gidmap 0 100000 65536, user 1000 100
/// /home/u, holder flong.slice/s, -- /bin/true.
const one_map = [_]spec.IdMap{.{ .inside = 0, .outside = 100000, .count = 65536 }};
const bin_true = [_][*:0]const u8{"/bin/true"};

fn valid() spec.Spec {
    return .{
        .machine = "m",
        .container = "c",
        .state = "/state",
        .cache = "/cache",
        .closure = store,
        .uidmap = &one_map,
        .gidmap = &one_map,
        .uid = 1000,
        .gid = 100,
        .home = "/home/u",
        .holder = "flong.slice/s",
        .command = &bin_true,
    };
}

/// A golden case: the valid spec, changed by `change`, refused with `want`.
const Case = struct {
    name: []const u8,
    change: *const fn (*spec.Spec) void,
    want: []const u8,
};

fn case(comptime name: []const u8, comptime change: fn (*spec.Spec) void, comptime want: []const u8) Case {
    return .{ .name = name, .change = &change, .want = want };
}

/// A change that sets one field.
fn set(comptime field: []const u8, comptime v: anytype) fn (*spec.Spec) void {
    return struct {
        fn f(s: *spec.Spec) void {
            @field(s, field) = v;
        }
    }.f;
}

fn maps(comptime m: []const spec.IdMap) []const spec.IdMap {
    return m;
}

fn mounts(comptime m: mount.Mount) []const mount.Mount {
    return &.{m};
}

const name_max = "a" ** 255;
const name_over = "a" ** 256;

/// The unmapped id the cross-order cases use, and their other faults.
fn crossOrder(comptime n: usize) fn (*spec.Spec) void {
    return struct {
        fn f(s: *spec.Spec) void {
            // Each case breaks the Nth check across fields and every one
            // after it, so the first said is the Nth: the checks keep
            // their order.
            if (n <= 1) s.uidmap = maps(&.{ .{ .inside = 0, .outside = 100000, .count = 65536 }, .{ .inside = 1000, .outside = 300000, .count = 1 } });
            if (n <= 2) s.gidmap = maps(&.{ .{ .inside = 0, .outside = 100000, .count = 65536 }, .{ .inside = 1000, .outside = 300000, .count = 1 } });
            if (n <= 3) s.uid = 70000;
            if (n <= 4) s.gid = 70000;
            if (n <= 5) s.groups = &.{70000};
            if (n <= 6) s.holder_start = &.{"sh"};
            if (n <= 7) s.post_start = &.{&.{"sh"}};
            if (n <= 8) s.pasta_wait = true;
        }
    }.f;
}

const cases = [_]Case{
    case("cache-relative", set("cache", "cache"), "spec: cache is not an absolute path: 'cache'"),
    case("chdir-relative", set("chdir", "work"), "spec: chdir is not an absolute path: 'work'"),
    case("closure-absent", set("closure", "/nix/store/00000000000000000000000000000000-absent"), "spec: closure '/nix/store/00000000000000000000000000000000-absent': No such file or directory"),
    case("closure-dotdot", set("closure", "/nix/store/x/../y"), "spec: closure has an empty, '.' or '..' component: '/nix/store/x/../y'"),
    case("closure-empty-component", set("closure", "/nix/store/x//y"), "spec: closure has an empty, '.' or '..' component: '/nix/store/x//y'"),
    case("closure-name-max", set("closure", "/nix/store/" ++ name_over), "spec: closure has a component longer than NAME_MAX"),
    case("closure-outside", set("closure", "/tmp/x"), "spec: closure is not under /nix/store/: '/tmp/x'"),
    case("closure-store-itself", set("closure", "/nix/store/"), "spec: closure is not under /nix/store/: '/nix/store/'"),
    case("closure-store-no-slash", set("closure", "/nix/store"), "spec: closure is not under /nix/store/: '/nix/store'"),
    case("closure-through-file", set("closure", options.store_file ++ "/x"), "spec: closure '" ++ options.store_file ++ "/x': Not a directory"),
    case("command-empty", set("command", @as([]const [*:0]const u8, &.{})), "spec: the command after '--' is empty"),
    case("container-space", set("container", "a b"), "spec: container 'a b' is not a name: 1 to 128 of A-Z a-z 0-9 _ - ., not starting with ."),
    case("cross-order-1", crossOrder(1), "spec: uidmap extents 0 100000 65536 and 1000 300000 1 overlap"),
    case("cross-order-2", crossOrder(2), "spec: gidmap extents 0 100000 65536 and 1000 300000 1 overlap"),
    case("cross-order-3", crossOrder(3), "spec: user's uid 70000 is in no uidmap extent"),
    case("cross-order-4", crossOrder(4), "spec: user's gid 70000 is in no gidmap extent"),
    case("cross-order-5", crossOrder(5), "spec: group 70000 is in no gidmap extent"),
    case("cross-order-6", crossOrder(6), "spec: holder-start's program is not an absolute path: 'sh'"),
    case("cross-order-7", crossOrder(7), "spec: post-start's program is not an absolute path: 'sh'"),
    case("cross-order-8", crossOrder(8), "spec: pasta-arg or pasta-wait without network"),
    case("gidmap-count-0", set("gidmap", maps(&.{.{ .inside = 0, .outside = 100000, .count = 0 }})), "spec: gidmap 0 100000 0: the count is 0"),
    case("gidmap-host-root", set("gidmap", maps(&.{.{ .inside = 0, .outside = 0, .count = 65536 }})), "spec: gidmap 0 0 65536 reaches host id 0: flong never maps host root"),
    case("gidmap-overlap", set("gidmap", maps(&.{ .{ .inside = 0, .outside = 100000, .count = 65536 }, .{ .inside = 65535, .outside = 200000, .count = 2 } })), "spec: gidmap extents 0 100000 65536 and 65535 200000 2 overlap"),
    case("group-over-id-max", set("groups", @as([]const u32, &.{4294967295})), "spec: group is larger than 4294967294: '4294967295'"),
    case("group-unmapped", set("groups", @as([]const u32, &.{65536})), "spec: group 65536 is in no gidmap extent"),
    case("holder-absolute", set("holder", "/flong.slice/s"), "spec: holder is not a relative path: '/flong.slice/s'"),
    case("holder-dotdot", set("holder", "flong.slice/../s"), "spec: holder has an empty, '.' or '..' component: 'flong.slice/../s'"),
    case("holder-empty", set("holder", ""), "spec: holder has an empty, '.' or '..' component: ''"),
    case("holder-name-max", set("holder", name_over), "spec: holder has a component longer than NAME_MAX"),
    case("holder-start-relative", set("holder_start", @as([]const [:0]const u8, &.{"sh"})), "spec: holder-start's program is not an absolute path: 'sh'"),
    case("limit-empty", set("limits", @as([]const spec.Limit, &.{.{ .file = "memory.max", .value = "" }})), "spec: limit memory.max has an empty value"),
    case("limit-twice", set("limits", @as([]const spec.Limit, &.{ .{ .file = "pids.max", .value = "1" }, .{ .file = "pids.max", .value = "2" } })), "spec: limit pids.max given more than once"),
    case("limit-unknown", set("limits", @as([]const spec.Limit, &.{.{ .file = "cgroup.procs", .value = "1" }})), "spec: limit 'cgroup.procs' is not one of memory.max memory.high memory.swap.max memory.oom.group pids.max cpu.max cpu.weight io.weight"),
    case("machine-129", set("machine", "a" ** 129), "spec: machine '" ++ "a" ** 129 ++ "' is not a name: 1 to 128 of A-Z a-z 0-9 _ - ., not starting with ."),
    case("machine-dot", set("machine", ".m"), "spec: machine '.m' is not a name: 1 to 128 of A-Z a-z 0-9 _ - ., not starting with ."),
    case("machine-empty", set("machine", ""), "spec: machine '' is not a name: 1 to 128 of A-Z a-z 0-9 _ - ., not starting with ."),
    case("machine-slash", set("machine", "a/b"), "spec: machine 'a/b' is not a name: 1 to 128 of A-Z a-z 0-9 _ - ., not starting with ."),
    case("missing-gidmap", set("gidmap", maps(&.{})), "spec: gidmap is missing"),
    case("missing-uidmap", set("uidmap", maps(&.{})), "spec: uidmap is missing"),
    case("mount-dest-dotdot", set("mounts", mounts(.{ .kind = .bind_rw, .dest = "/a/../b", .src = "/s" })), "spec: mount bind-rw destination has an empty, '.' or '..' component: '/a/../b'"),
    case("mount-dest-relative", set("mounts", mounts(.{ .kind = .bind_ro, .dest = "d", .src = "/s" })), "spec: mount bind-ro destination is not an absolute path: 'd'"),
    case("mount-dest-root", set("mounts", mounts(.{ .kind = .mask, .dest = "/" })), "spec: mount mask destination has an empty, '.' or '..' component: '/'"),
    case("mount-dev-src-relative", set("mounts", mounts(.{ .kind = .dev, .dest = "/dev/kvm", .src = "dev" })), "spec: mount dev source is not an absolute path: 'dev'"),
    case("mount-exact-src-dotdot", set("mounts", mounts(.{ .kind = .bind_ro_exact, .dest = "/d", .src = "/s/../t" })), "spec: mount bind-ro-exact source has an empty, '.' or '..' component: '/s/../t'"),
    case("mount-exact-src-relative", set("mounts", mounts(.{ .kind = .bind_rw_exact, .dest = "/d", .src = "s" })), "spec: mount bind-rw-exact source is not an absolute path: 's'"),
    case("mount-overlay-src-relative", set("mounts", mounts(.{ .kind = .overlay, .dest = "/o", .src = "lower" })), "spec: mount overlay source is not an absolute path: 'lower'"),
    case("mount-src-relative", set("mounts", mounts(.{ .kind = .bind_ro, .dest = "/d", .src = "s" })), "spec: mount bind-ro source is not an absolute path: 's'"),
    case("mount-tmpfs-mode-8", set("mounts", mounts(.{ .kind = .tmpfs, .dest = "/t", .mode = "0785" })), "spec: mount tmpfs mode is not an octal mode: '0785'"),
    case("mount-tmpfs-mode-empty", set("mounts", mounts(.{ .kind = .tmpfs, .dest = "/t", .mode = "" })), "spec: mount tmpfs mode is not an octal mode: ''"),
    case("mount-tmpfs-mode-large", set("mounts", mounts(.{ .kind = .tmpfs, .dest = "/t", .mode = "17777" })), "spec: mount tmpfs mode is larger than 07777: '17777'"),
    case("mount-tmpfs-mode-long", set("mounts", mounts(.{ .kind = .tmpfs, .dest = "/t", .mode = "000755" })), "spec: mount tmpfs mode is not an octal mode: '000755'"),
    case("mount-tmpfs-size-no-digits", set("mounts", mounts(.{ .kind = .tmpfs, .dest = "/t", .mode = "0755", .size = "k" })), "spec: mount tmpfs size is not a number with an optional k, m, g, t, p, e or % suffix: 'k'"),
    case("mount-tmpfs-size-option", set("mounts", mounts(.{ .kind = .tmpfs, .dest = "/t", .mode = "0755", .size = "1m,mode=777" })), "spec: mount tmpfs size is not a number with an optional k, m, g, t, p, e or % suffix: '1m,mode=777'"),
    case("mount-tmpfs-size-two-units", set("mounts", mounts(.{ .kind = .tmpfs, .dest = "/t", .mode = "0755", .size = "10kk" })), "spec: mount tmpfs size is not a number with an optional k, m, g, t, p, e or % suffix: '10kk'"),
    case("mount-tmpfs-size-unit", set("mounts", mounts(.{ .kind = .tmpfs, .dest = "/t", .mode = "0755", .size = "10x" })), "spec: mount tmpfs size is not a number with an optional k, m, g, t, p, e or % suffix: '10x'"),
    case("nested-userns-over-int-max", set("nested_userns", @as(u64, 2147483648)), "spec: nested-userns is larger than 2147483647: '2147483648'"),
    case("order-limit-file", set("limits", @as([]const spec.Limit, &.{.{ .file = "cgroup.procs", .value = "" }})), "spec: limit 'cgroup.procs' is not one of memory.max memory.high memory.swap.max memory.oom.group pids.max cpu.max cpu.weight io.weight"),
    case("order-limit-twice", set("limits", @as([]const spec.Limit, &.{ .{ .file = "pids.max", .value = "1" }, .{ .file = "pids.max", .value = "" } })), "spec: limit pids.max given more than once"),
    case("order-mount-dest", set("mounts", mounts(.{ .kind = .bind_ro, .dest = "d", .src = "s" })), "spec: mount bind-ro destination is not an absolute path: 'd'"),
    case("order-state-relative", set("state", "s" ** 5000), "spec: state is not an absolute path: '" ++ "s" ** 5000 ++ "'"),
    case("order-tmpfs-mode", set("mounts", mounts(.{ .kind = .tmpfs, .dest = "/t", .mode = "8", .size = "x" })), "spec: mount tmpfs mode is not an octal mode: '8'"),
    case("order-tmpfs-size", set("mounts", mounts(.{ .kind = .tmpfs, .dest = "/t", .mode = "0755", .size = "x" })), "spec: mount tmpfs size is not a number with an optional k, m, g, t, p, e or % suffix: 'x'"),
    case("order-uidmap-count", set("uidmap", maps(&.{.{ .inside = 0, .outside = 0, .count = 0 }})), "spec: uidmap 0 0 0: the count is 0"),
    case("order-uidmap-past", set("uidmap", maps(&.{.{ .inside = 2, .outside = 0, .count = 4294967294 }})), "spec: uidmap 2 0 4294967294: the extent runs past id 4294967294"),
    case("pasta-arg-without-network", set("pasta_args", @as([]const [:0]const u8, &.{"-t"})), "spec: pasta-arg or pasta-wait without network"),
    case("pasta-wait-without-network", set("pasta_wait", true), "spec: pasta-arg or pasta-wait without network"),
    case("post-start-empty-program", set("post_start", @as([]const spec.Command, &.{&.{""}})), "spec: post-start's program is not an absolute path: ''"),
    case("post-start-relative", set("post_start", @as([]const spec.Command, &.{&.{ "./hook", "x" }})), "spec: post-start's program is not an absolute path: './hook'"),
    case("post-start-second-relative", set("post_start", @as([]const spec.Command, &.{ &.{"/h"}, &.{"hook"} })), "spec: post-start's program is not an absolute path: 'hook'"),
    case("post-stop-count-zero", set("post_stop", @as([]const spec.Command, &.{&.{}})), "spec: post-stop's word count is 0"),
    case("post-stop-dotdot", set("post_stop", @as([]const spec.Command, &.{&.{"/nix/store/x/../../bin/sh"}})), "spec: post-stop has an empty, '.' or '..' component: '/nix/store/x/../../bin/sh'"),
    case("post-stop-outside", set("post_stop", @as([]const spec.Command, &.{&.{"/bin/sh"}})), "spec: post-stop is not under /nix/store/: '/bin/sh'"),
    case("post-stop-second-outside", set("post_stop", @as([]const spec.Command, &.{ &.{"/nix/store/x"}, &.{"/bin/sh"} })), "spec: post-stop is not under /nix/store/: '/bin/sh'"),
    case("protect-dotdot", set("protect", @as([]const [:0]const u8, &.{"/a/.."})), "spec: protect has an empty, '.' or '..' component: '/a/..'"),
    case("protect-relative", set("protect", @as([]const [:0]const u8, &.{"p"})), "spec: protect is not an absolute path: 'p'"),
    case("seccomp-relative", set("seccomp", @as([]const [:0]const u8, &.{"policy.bpf"})), "spec: seccomp is not an absolute path: 'policy.bpf'"),
    case("state-empty", set("state", ""), "spec: state is not an absolute path: ''"),
    case("state-path-max", set("state", "/" ++ "s" ** 4095), "spec: state is longer than PATH_MAX"),
    case("state-relative", set("state", "state"), "spec: state is not an absolute path: 'state'"),
    case("uidmap-count-0", set("uidmap", maps(&.{.{ .inside = 0, .outside = 100000, .count = 0 }})), "spec: uidmap 0 100000 0: the count is 0"),
    case("uidmap-host-root", set("uidmap", maps(&.{.{ .inside = 0, .outside = 0, .count = 65536 }})), "spec: uidmap 0 0 65536 reaches host id 0: flong never maps host root"),
    case("uidmap-over-id-max", set("uidmap", maps(&.{.{ .inside = 4294967295, .outside = 100000, .count = 65536 }})), "spec: uidmap 4294967295 100000 65536: the inside is larger than 4294967294"),
    case("uidmap-overflow", set("uidmap", maps(&.{.{ .inside = 0, .outside = std.math.maxInt(u64), .count = 65536 }})), "spec: uidmap 0 18446744073709551615 65536: the outside is larger than 4294967294"),
    case("uidmap-overlap-inside", set("uidmap", maps(&.{ .{ .inside = 0, .outside = 100000, .count = 65536 }, .{ .inside = 1000, .outside = 300000, .count = 1 } })), "spec: uidmap extents 0 100000 65536 and 1000 300000 1 overlap"),
    case("uidmap-overlap-outside", set("uidmap", maps(&.{ .{ .inside = 0, .outside = 100000, .count = 65536 }, .{ .inside = 70000, .outside = 165535, .count = 1 } })), "spec: uidmap extents 0 100000 65536 and 70000 165535 1 overlap"),
    case("uidmap-past-inside", set("uidmap", maps(&.{.{ .inside = 4294967294, .outside = 100000, .count = 2 }})), "spec: uidmap 4294967294 100000 2: the extent runs past id 4294967294"),
    case("uidmap-past-outside", set("uidmap", maps(&.{.{ .inside = 0, .outside = 4294967294, .count = 2 }})), "spec: uidmap 0 4294967294 2: the extent runs past id 4294967294"),
    case("user-gid-unmapped", set("gid", @as(u32, 65536)), "spec: user's gid 65536 is in no gidmap extent"),
    case("user-home-dot", set("home", "/home/./u"), "spec: user's home has an empty, '.' or '..' component: '/home/./u'"),
    case("user-home-name-max", set("home", "/home/" ++ name_over), "spec: user's home has a component longer than NAME_MAX"),
    case("user-home-relative", set("home", "home/u"), "spec: user's home is not an absolute path: 'home/u'"),
    case("user-home-root", set("home", "/"), "spec: user's home has an empty, '.' or '..' component: '/'"),
    case("user-home-trailing-slash", set("home", "/home/u/"), "spec: user's home has an empty, '.' or '..' component: '/home/u/'"),
    case("user-uid-id-max", set("uid", @as(u32, 4294967294)), "spec: user's uid 4294967294 is in no uidmap extent"),
    case("user-uid-over-id-max", set("uid", @as(u32, 4294967295)), "spec: user's uid is larger than 4294967294: '4294967295'"),
    case("user-uid-unmapped", set("uid", @as(u32, 65536)), "spec: user's uid 65536 is in no uidmap extent"),
    // The typed options, which the argv spec's bwrap-args said.
    case("bwrap-arg-setenv-empty", set("env", @as(?[]const spec.Var, &.{.{ .name = "", .value = "v" }})), "spec: bwrap-arg: '' is not a variable name"),
    case("bwrap-arg-unsetenv-equals", set("env", @as(?[]const spec.Var, &.{.{ .name = "A=B", .value = "v" }})), "spec: bwrap-arg: 'A=B' is not a variable name"),
    case("bwrap-arg-hostname-empty", set("hostname", @as(?[:0]const u8, "")), "spec: bwrap-arg --hostname is empty"),
    // A field's refusal before any across fields (pass2-before-cross), and
    // the fields in validate's order (pass2-in-order).
    case("pass2-before-cross", struct {
        fn f(s: *spec.Spec) void {
            s.pasta_wait = true;
            s.home = "home";
        }
    }.f, "spec: user's home is not an absolute path: 'home'"),
    case("pass2-in-order", struct {
        fn f(s: *spec.Spec) void {
            s.groups = &.{4294967295};
            s.chdir = "work";
        }
    }.f, "spec: group is larger than 4294967294: '4294967295'"),
};

test "validate: the valid spec passes" {
    try expectPasses(&valid());
}

test "validate: each golden case's refusal, as a value" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    for (cases) |c| {
        var s = valid();
        c.change(&s);
        expectRefused(arena_state.allocator(), &s, c.want) catch |err| {
            std.debug.print("case {s}\n", .{c.name});
            return err;
        };
    }
}

test "validate: every field set, each at an edge that passes (accepted-all)" {
    var s = valid();
    s.machine = "a" ** 128;
    s.container = "c.-_9";
    s.state = "/";
    s.cache = "/c";
    s.uidmap = &.{
        .{ .inside = 4294967294, .outside = 100000, .count = 1 },
        .{ .inside = 1000, .outside = 200000, .count = 1 },
        .{ .inside = 0, .outside = 300000, .count = 1000 },
        .{ .inside = 1001, .outside = 4294967294, .count = 1 },
    };
    s.gidmap = &.{ .{ .inside = 0, .outside = 100000, .count = 65536 }, .{ .inside = 4294967294, .outside = 1, .count = 1 } };
    s.uid = 4294967294;
    s.gid = 100;
    s.home = "/home/" ++ name_max;
    s.groups = &.{ 0, 4294967294 };
    s.chdir = "/w";
    s.mounts = &.{
        .{ .kind = .bind_ro, .dest = "/a", .src = "/x/../y" },
        .{ .kind = .bind_rw, .dest = "/b", .src = "//x/./" },
        .{ .kind = .bind_ro_exact, .dest = "/c", .src = "/s" },
        .{ .kind = .bind_rw_exact, .dest = "/d", .src = "/s" },
        .{ .kind = .dev, .dest = "/dev", .src = "/dev" },
        .{ .kind = .tmpfs, .dest = "/t", .mode = "07777", .owner_user = true },
        .{ .kind = .tmpfs, .dest = "/u", .mode = "0", .size = "100%" },
        .{ .kind = .tmpfs, .dest = "/v", .mode = "00000", .size = "1E" },
        .{ .kind = .overlay, .dest = "/o", .src = "/" },
        .{ .kind = .mask, .dest = "/m" },
    };
    s.protect = &.{ "/p", "/p" };
    s.seccomp = &.{ "/s.bpf", "/s.bpf" };
    s.nested_userns = 2147483647;
    s.holder = "a/b.c";
    s.holder_start = &.{ "/bin/sh", "--" };
    s.limits = &.{ .{ .file = "memory.max", .value = "max" }, .{ .file = "pids.max", .value = "0" } };
    s.post_start = &.{ &.{ "/h", "--", "" }, &.{"/g"} };
    s.post_stop = &.{ &.{"/nix/store/x/y"}, &.{ "/nix/store/x/z", "--" } };
    s.network = true;
    s.pasta_args = &.{ "--", "pasta" };
    s.pasta_wait = true;
    s.env = &.{ .{ .name = "A", .value = "" }, .{ .name = "-", .value = "=" } };
    s.hostname = "h";
    s.resolv_conf = "";
    s.trace = true;
    try expectPasses(&s);
}

// ---- validate over drawn values ----

const name_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.";
const any_chars = "abcXYZ019_-.= \t\n@:,+~$\"'*";

const Gen = struct {
    r: std.Random,
    a: Allocator,

    fn below(g: Gen, n: usize) usize {
        return g.r.uintLessThan(usize, n);
    }

    fn chance(g: Gen, one_in: usize) bool {
        return g.below(one_in) == 0;
    }

    fn charsFrom(g: Gen, set_: []const u8, len: usize) ![:0]u8 {
        const out = try g.a.allocSentinel(u8, len, 0);
        for (out) |*c| c.* = set_[g.below(set_.len)];
        return out;
    }

    fn z(g: Gen, v: []const u8) ![:0]const u8 {
        return g.a.dupeZ(u8, v);
    }

    fn name(g: Gen) ![:0]const u8 {
        const len = if (g.chance(20)) 128 else 1 + g.below(12);
        const out = try g.charsFrom(name_chars, len);
        while (out[0] == '.') out[0] = name_chars[g.below(name_chars.len)];
        return out;
    }

    fn component(g: Gen) ![]const u8 {
        while (true) {
            const len = if (g.chance(40)) 255 else 1 + g.below(10);
            const c = try g.charsFrom(any_chars, len);
            if (std.mem.eql(u8, c, ".") or std.mem.eql(u8, c, "..")) continue;
            return c;
        }
    }

    fn cleanPath(g: Gen, rooted: spec.Rooted) ![:0]const u8 {
        var out: std.ArrayList(u8) = .empty;
        const n = 1 + g.below(4);
        for (0..n) |i| {
            if (i > 0 or rooted == .absolute) try out.append(g.a, '/');
            try out.appendSlice(g.a, try g.component());
        }
        return g.z(out.items);
    }

    /// An absolute path, spelled any way: "//", "..", a trailing slash.
    fn absPath(g: Gen) ![:0]const u8 {
        if (g.chance(3)) return g.cleanPath(.absolute);
        const rest = try g.charsFrom(any_chars ++ "//..", g.below(30));
        return g.z(try std.mem.concat(g.a, u8, &.{ "/", rest }));
    }

    /// Any word, "--" and the empty one included.
    fn word(g: Gen) ![:0]const u8 {
        return switch (g.below(8)) {
            0 => "--",
            1 => "",
            2 => "machine",
            else => g.charsFrom(any_chars, 1 + g.below(12)),
        };
    }

    fn words(g: Gen, max: usize) ![][:0]const u8 {
        const out = try g.a.alloc([:0]const u8, g.below(max + 1));
        for (out) |*w| w.* = try g.word();
        return out;
    }

    /// A command: `program`, then up to three words.
    fn command(g: Gen, program: [:0]const u8) !spec.Command {
        const rest = try g.words(3);
        return std.mem.concat(g.a, [:0]const u8, &.{ &.{program}, rest });
    }

    /// Disjoint extents, none reaching host id 0.
    fn idmap(g: Gen) ![]spec.IdMap {
        const out = try g.a.alloc(spec.IdMap, 1 + g.below(3));
        var in_at: u64 = g.below(1000);
        var out_at: u64 = 1 + g.below(200000);
        for (out) |*e| {
            const count: u64 = 1 + g.below(70000);
            e.* = .{ .inside = in_at, .outside = out_at, .count = count };
            in_at += count + g.below(100);
            out_at += count + g.below(100);
        }
        // Sometimes one ends at the last id.
        if (g.chance(8)) {
            const last = &out[out.len - 1];
            last.count = spec.id_max + 1 - @max(last.inside, last.outside);
        }
        g.r.shuffle(spec.IdMap, out);
        return out;
    }

    fn inMap(g: Gen, m: []const spec.IdMap) u32 {
        const e = m[g.below(m.len)];
        return @intCast(e.inside + g.r.uintLessThan(u64, e.count));
    }

    fn octal(g: Gen) ![:0]const u8 {
        const v = g.below(0o7777 + 1);
        const digits = try std.fmt.allocPrint(g.a, "{o}", .{v});
        const pad = g.below(5 - digits.len + 1);
        return g.z(try std.mem.concat(g.a, u8, &.{ "0000"[0..pad], digits }));
    }

    fn mountOf(g: Gen) !mount.Mount {
        const kinds = [_]mount.Kind{ .bind_ro, .bind_rw, .bind_ro_exact, .bind_rw_exact, .dev, .tmpfs, .overlay, .mask };
        var m: mount.Mount = .{ .kind = kinds[g.below(kinds.len)], .dest = try g.cleanPath(.absolute) };
        switch (m.kind) {
            .bind_ro_exact, .bind_rw_exact => m.src = try g.cleanPath(.absolute),
            .bind_ro, .bind_rw, .dev, .overlay => m.src = try g.absPath(),
            .tmpfs => {
                m.mode = try g.octal();
                m.size = switch (g.below(3)) {
                    0 => null,
                    1 => try std.fmt.allocPrintSentinel(g.a, "{d}", .{g.below(1 << 20)}, 0),
                    else => try std.fmt.allocPrintSentinel(g.a, "{d}{c}", .{ g.below(100), "kKmMgGtTpPeE%"[g.below(13)] }, 0),
                };
                m.owner_user = g.r.boolean();
            },
            .mask => {},
        }
        return m;
    }

    /// A spec every check passes.
    fn spec_(g: Gen) !spec.Spec {
        const umap = try g.idmap();
        const gmap = try g.idmap();
        const groups = try g.a.alloc(u32, g.below(4));
        for (groups) |*x| x.* = g.inMap(gmap);
        const ms = try g.a.alloc(mount.Mount, g.below(5));
        for (ms) |*m| m.* = try g.mountOf();
        const protect = try g.a.alloc([:0]const u8, g.below(3));
        for (protect) |*p| p.* = try g.cleanPath(.absolute);
        const seccomp = try g.a.alloc([:0]const u8, g.below(4));
        for (seccomp) |*p| p.* = try g.absPath();
        const holder_start = try g.words(2);
        if (holder_start.len > 0) holder_start[0] = try g.absPath();
        const post_start = try g.a.alloc(spec.Command, g.below(3));
        for (post_start) |*c| c.* = try g.command(try g.absPath());
        const post_stop = try g.a.alloc(spec.Command, g.below(3));
        for (post_stop) |*c| c.* = try g.command(try g.z(try std.mem.concat(g.a, u8, &.{ "/nix/store/", try g.cleanPath(.relative) })));

        var limits: std.ArrayList(spec.Limit) = .empty;
        var files = [_][:0]const u8{ "memory.max", "memory.high", "memory.swap.max", "memory.oom.group", "pids.max", "cpu.max", "cpu.weight", "io.weight" };
        g.r.shuffle([:0]const u8, &files);
        for (files[0..g.below(files.len + 1)]) |f| {
            var v = try g.word();
            if (v.len == 0) v = "max";
            try limits.append(g.a, .{ .file = f, .value = v });
        }

        const network = g.r.boolean();
        const env = try g.a.alloc(spec.Var, g.below(4));
        for (env) |*v| {
            var n = try g.component();
            while (std.mem.indexOfScalar(u8, n, '=') != null) n = try g.component();
            v.* = .{ .name = try g.z(n), .value = try g.word() };
        }

        const cmd_words = try g.words(3);
        const cmd = try g.a.allocSentinel(?[*:0]const u8, @max(1, cmd_words.len), null);
        if (cmd_words.len == 0) cmd[0] = "true" else for (cmd_words, cmd) |w, *c| {
            c.* = w.ptr;
        }

        return .{
            .machine = try g.name(),
            .container = try g.name(),
            .state = try g.absPath(),
            .cache = try g.absPath(),
            .closure = store,
            .uidmap = umap,
            .gidmap = gmap,
            .uid = g.inMap(umap),
            .gid = g.inMap(gmap),
            .home = try g.cleanPath(.absolute),
            .groups = groups,
            .chdir = if (g.r.boolean()) try g.absPath() else "/",
            .mounts = ms,
            .protect = protect,
            .seccomp = seccomp,
            .nested_userns = if (g.r.boolean()) 0 else 1 + g.r.uintLessThan(u64, std.math.maxInt(i32)),
            .holder = try g.cleanPath(.relative),
            .holder_start = holder_start,
            .limits = limits.items,
            .post_start = post_start,
            .post_stop = post_stop,
            .network = network,
            .pasta_args = if (network) try g.words(2) else &.{},
            .pasta_wait = network and g.r.boolean(),
            .env = if (g.r.boolean()) env else null,
            .hostname = if (g.r.boolean()) try g.name() else null,
            .resolv_conf = if (network and g.r.boolean()) "nameserver 169.254.1.1\n" else null,
            .trace = g.r.boolean(),
            .command = @ptrCast(cmd[0..cmd.len]),
        };
    }
};

fn passes(seed: u64) !void {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    var prng: std.Random.DefaultPrng = .init(seed);
    const g: Gen = .{ .r = prng.random(), .a = arena_state.allocator() };
    const s = try g.spec_();
    try expectPasses(&s);
}

test "property: a spec drawn from the model passes validate" {
    try minish.check(testing.allocator, minish.gen.int(u64), passes, .{ .num_runs = 10_000, .seed = 0x5bec });
    try minish.check(testing.allocator, minish.gen.int(u64), passes, .{ .num_runs = 2_000 });
}

// ---- single-rule mutations ----

const Rule = enum {
    machine_not_name,
    container_not_name,
    state_relative,
    cache_too_long,
    closure_outside,
    closure_unclean,
    closure_absent,
    idmap_missing,
    idmap_count_0,
    idmap_host_0,
    idmap_past,
    idmap_too_large,
    idmap_overlap,
    id_too_large,
    uid_unmapped,
    gid_unmapped,
    group_unmapped,
    home_unclean,
    chdir_relative,
    mount_dest_unclean,
    tmpfs_mode_not_octal,
    tmpfs_mode_large,
    tmpfs_size_bad,
    exact_src_unclean,
    bind_src_relative,
    protect_relative,
    seccomp_relative,
    nested_too_large,
    holder_absolute,
    limit_unknown,
    limit_twice,
    limit_empty,
    command_empty_list,
    post_stop_outside,
    env_name_bad,
    hostname_empty,
    command_empty,
    pasta_without_network,
    holder_start_relative,
    post_start_relative,
};

fn append(a: Allocator, comptime T: type, list: []const T, x: T) ![]const T {
    return std.mem.concat(a, T, &.{ list, &.{x} });
}

/// Applies `rule` to a valid spec and returns the one line validate must
/// say, "flong launch: " and the newline aside.
fn mutate(g: Gen, rule: Rule, s: *spec.Spec) ![]const u8 {
    const a = g.a;
    switch (rule) {
        .machine_not_name, .container_not_name => {
            const bad = [_][:0]const u8{ "", ".m", "a/b", "a b", "a" ** 129 };
            const v = bad[g.below(bad.len)];
            const what = if (rule == .machine_not_name) "machine" else "container";
            if (rule == .machine_not_name) s.machine = v else s.container = v;
            return std.fmt.allocPrint(a, "spec: {s} '{s}' is not a name: 1 to 128 of A-Z a-z 0-9 _ - ., not starting with .", .{ what, v });
        },
        .state_relative => {
            s.state = "run/user";
            return "spec: state is not an absolute path: 'run/user'";
        },
        .cache_too_long => {
            s.cache = "/" ++ "c" ** 4095;
            return "spec: cache is longer than PATH_MAX";
        },
        .closure_outside => {
            s.closure = "/tmp/x";
            return "spec: closure is not under /nix/store/: '/tmp/x'";
        },
        .closure_unclean => {
            s.closure = store ++ "/../x";
            return "spec: closure has an empty, '.' or '..' component: '" ++ store ++ "/../x'";
        },
        .closure_absent => {
            s.closure = "/nix/store/00000000000000000000000000000000-absent";
            return "spec: closure '/nix/store/00000000000000000000000000000000-absent': No such file or directory";
        },
        .idmap_missing => {
            if (g.r.boolean()) {
                s.uidmap = &.{};
                return "spec: uidmap is missing";
            }
            s.gidmap = &.{};
            return "spec: gidmap is missing";
        },
        .idmap_count_0, .idmap_host_0, .idmap_past, .idmap_too_large => {
            // uidmap's are checked before gidmap's, so a gidmap fault is
            // said only when every uidmap extent passes, as it does here.
            const uid = g.r.boolean();
            const what = if (uid) "uidmap" else "gidmap";
            const m = try a.dupe(spec.IdMap, if (uid) s.uidmap else s.gidmap);
            const i = g.below(m.len);
            // Earlier extents pass, so this one's fault is the first said.
            switch (rule) {
                .idmap_count_0 => m[i].count = 0,
                .idmap_host_0 => m[i].outside = 0,
                .idmap_past => {
                    m[i].inside = spec.id_max;
                    m[i].count = 2;
                },
                else => m[i].outside = spec.id_max + 1 + g.r.uintLessThan(u64, 1 << 40),
            }
            if (uid) s.uidmap = m else s.gidmap = m;
            const e = m[i];
            return switch (rule) {
                .idmap_count_0 => std.fmt.allocPrint(a, "spec: {s} {d} {d} 0: the count is 0", .{ what, e.inside, e.outside }),
                .idmap_host_0 => std.fmt.allocPrint(a, "spec: {s} {d} 0 {d} reaches host id 0: flong never maps host root", .{ what, e.inside, e.count }),
                .idmap_past => std.fmt.allocPrint(a, "spec: {s} 4294967294 {d} 2: the extent runs past id 4294967294", .{ what, e.outside }),
                else => std.fmt.allocPrint(a, "spec: {s} {d} {d} {d}: the outside is larger than 4294967294", .{ what, e.inside, e.outside, e.count }),
            };
        },
        .idmap_overlap => {
            const uid = g.r.boolean();
            const m = if (uid) s.uidmap else s.gidmap;
            const e = m[0];
            if (uid) s.uidmap = try append(a, spec.IdMap, m, e) else s.gidmap = try append(a, spec.IdMap, m, e);
            return std.fmt.allocPrint(a, "spec: {s} extents {d} {d} {d} and {d} {d} {d} overlap", .{ if (uid) "uidmap" else "gidmap", e.inside, e.outside, e.count, e.inside, e.outside, e.count });
        },
        .id_too_large => {
            switch (g.below(3)) {
                0 => {
                    s.uid = std.math.maxInt(u32);
                    return "spec: user's uid is larger than 4294967294: '4294967295'";
                },
                1 => {
                    s.gid = std.math.maxInt(u32);
                    return "spec: user's gid is larger than 4294967294: '4294967295'";
                },
                else => {
                    s.groups = try append(a, u32, s.groups, std.math.maxInt(u32));
                    return "spec: group is larger than 4294967294: '4294967295'";
                },
            }
        },
        .uid_unmapped, .gid_unmapped, .group_unmapped => {
            const map = if (rule == .uid_unmapped) s.uidmap else s.gidmap;
            // Above every extent, or below them when one ends at the last
            // id.
            var id: u64 = 0;
            for (map) |e| id = @max(id, e.inside + e.count);
            if (id > spec.id_max) {
                var low: u64 = spec.id_max;
                for (map) |e| low = @min(low, e.inside);
                if (low == 0) return error.SkipZigTest;
                id = low - 1;
            }
            switch (rule) {
                .uid_unmapped => {
                    s.uid = @intCast(id);
                    return std.fmt.allocPrint(a, "spec: user's uid {d} is in no uidmap extent", .{id});
                },
                .gid_unmapped => {
                    s.gid = @intCast(id);
                    return std.fmt.allocPrint(a, "spec: user's gid {d} is in no gidmap extent", .{id});
                },
                else => {
                    s.groups = try append(a, u32, s.groups, @intCast(id));
                    return std.fmt.allocPrint(a, "spec: group {d} is in no gidmap extent", .{id});
                },
            }
        },
        .home_unclean => {
            const v = try g.z(try std.mem.concat(a, u8, &.{ s.home, "/" }));
            s.home = v;
            return std.fmt.allocPrint(a, "spec: user's home has an empty, '.' or '..' component: '{s}'", .{v});
        },
        .chdir_relative => {
            s.chdir = "w";
            return "spec: chdir is not an absolute path: 'w'";
        },
        .mount_dest_unclean, .tmpfs_mode_not_octal, .tmpfs_mode_large, .tmpfs_size_bad, .exact_src_unclean, .bind_src_relative => {
            var want: []const u8 = undefined;
            const m: mount.Mount = switch (rule) {
                .mount_dest_unclean => blk: {
                    want = "spec: mount overlay destination has an empty, '.' or '..' component: '/a/./b'";
                    break :blk .{ .kind = .overlay, .dest = "/a/./b", .src = "/l" };
                },
                .tmpfs_mode_not_octal => blk: {
                    want = "spec: mount tmpfs mode is not an octal mode: '0758'";
                    break :blk .{ .kind = .tmpfs, .dest = "/t", .mode = "0758" };
                },
                .tmpfs_mode_large => blk: {
                    want = "spec: mount tmpfs mode is larger than 07777: '17777'";
                    break :blk .{ .kind = .tmpfs, .dest = "/t", .mode = "17777" };
                },
                .tmpfs_size_bad => blk: {
                    const bad = [_][:0]const u8{ "1kk", "k", "1,mode=0777", " 1", "" };
                    const v = bad[g.below(bad.len)];
                    want = try std.fmt.allocPrint(a, "spec: mount tmpfs size is not a number with an optional k, m, g, t, p, e or % suffix: '{s}'", .{v});
                    break :blk .{ .kind = .tmpfs, .dest = "/t", .mode = "0755", .size = v, .owner_user = true };
                },
                .exact_src_unclean => blk: {
                    want = "spec: mount bind-rw-exact source has an empty, '.' or '..' component: '/home/u/w/'";
                    break :blk .{ .kind = .bind_rw_exact, .dest = "/w", .src = "/home/u/w/" };
                },
                else => blk: {
                    want = "spec: mount dev source is not an absolute path: 'dev/kvm'";
                    break :blk .{ .kind = .dev, .dest = "/dev/kvm", .src = "dev/kvm" };
                },
            };
            // After the spec's own mounts, each checked first.
            s.mounts = try append(a, mount.Mount, s.mounts, m);
            return want;
        },
        .protect_relative => {
            s.protect = try append(a, [:0]const u8, s.protect, "p");
            return "spec: protect is not an absolute path: 'p'";
        },
        .seccomp_relative => {
            s.seccomp = try append(a, [:0]const u8, s.seccomp, "f.bpf");
            return "spec: seccomp is not an absolute path: 'f.bpf'";
        },
        .nested_too_large => {
            const v = @as(u64, std.math.maxInt(i32)) + 1 + g.r.uintLessThan(u64, 1 << 40);
            s.nested_userns = v;
            return std.fmt.allocPrint(a, "spec: nested-userns is larger than 2147483647: '{d}'", .{v});
        },
        .holder_absolute => {
            s.holder = "/flong.slice";
            return "spec: holder is not a relative path: '/flong.slice'";
        },
        .limit_unknown => {
            s.limits = try append(a, spec.Limit, s.limits, .{ .file = "cgroup.procs", .value = "1" });
            return "spec: limit 'cgroup.procs' is not one of memory.max memory.high memory.swap.max memory.oom.group pids.max cpu.max cpu.weight io.weight";
        },
        .limit_twice => {
            if (s.limits.len > 0) {
                const f = s.limits[0].file;
                s.limits = try append(a, spec.Limit, s.limits, .{ .file = f, .value = "1" });
                return std.fmt.allocPrint(a, "spec: limit {s} given more than once", .{f});
            }
            s.limits = &.{ .{ .file = "pids.max", .value = "1" }, .{ .file = "pids.max", .value = "2" } };
            return "spec: limit pids.max given more than once";
        },
        .limit_empty => {
            // A file the spec does not set, or its first set twice would
            // say that first.
            const file: [:0]const u8 = unset: for ([_][:0]const u8{ "memory.max", "memory.high", "memory.swap.max", "memory.oom.group", "pids.max", "cpu.max", "cpu.weight", "io.weight" }) |f| {
                for (s.limits) |l| {
                    if (std.mem.eql(u8, l.file, f)) break;
                } else break :unset f;
            } else return error.SkipZigTest;
            s.limits = try append(a, spec.Limit, s.limits, .{ .file = file, .value = "" });
            return std.fmt.allocPrint(a, "spec: limit {s} has an empty value", .{file});
        },
        .command_empty_list => {
            if (g.r.boolean()) {
                s.post_start = try append(a, spec.Command, s.post_start, &.{});
                return "spec: post-start's word count is 0";
            }
            s.post_stop = try append(a, spec.Command, s.post_stop, &.{});
            return "spec: post-stop's word count is 0";
        },
        .post_stop_outside => {
            s.post_stop = try append(a, spec.Command, s.post_stop, &.{ "/usr/bin/stop", "x" });
            return "spec: post-stop is not under /nix/store/: '/usr/bin/stop'";
        },
        .env_name_bad => {
            const bad = [_][:0]const u8{ "", "A=B", "=" };
            const v = bad[g.below(bad.len)];
            s.env = try append(a, spec.Var, s.env orelse &.{}, .{ .name = v, .value = "x" });
            return std.fmt.allocPrint(a, "spec: bwrap-arg: '{s}' is not a variable name", .{v});
        },
        .hostname_empty => {
            s.hostname = "";
            return "spec: bwrap-arg --hostname is empty";
        },
        .command_empty => {
            s.command = &.{};
            return "spec: the command after '--' is empty";
        },
        .pasta_without_network => {
            s.network = false;
            s.resolv_conf = null;
            if (g.r.boolean()) {
                s.pasta_args = &.{"--no-map-gw"};
                s.pasta_wait = false;
            } else {
                s.pasta_args = &.{};
                s.pasta_wait = true;
            }
            return "spec: pasta-arg or pasta-wait without network";
        },
        .holder_start_relative => {
            s.holder_start = &.{ "bin/start", "/x" };
            return "spec: holder-start's program is not an absolute path: 'bin/start'";
        },
        .post_start_relative => {
            s.post_start = try append(a, spec.Command, s.post_start, &.{ "hook", "/x" });
            return "spec: post-start's program is not an absolute path: 'hook'";
        },
    }
}

fn refusedWith(seed: u64, rule: Rule) !void {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    var prng: std.Random.DefaultPrng = .init(seed);
    const g: Gen = .{ .r = prng.random(), .a = arena_state.allocator() };
    var s = try g.spec_();
    const want = mutate(g, rule, &s) catch |err| switch (err) {
        error.SkipZigTest => return, // the spec leaves no room for it
        else => return err,
    };
    expectRefused(g.a, &s, want) catch |err| {
        std.debug.print("rule {s}, seed {d}\n", .{ @tagName(rule), seed });
        return err;
    };
}

fn anyRule(seed: u64) !void {
    const rules = std.enums.values(Rule);
    try refusedWith(seed, rules[seed % rules.len]);
}

test "each single-rule mutation is refused with its message" {
    for (std.enums.values(Rule)) |rule| {
        for (0..20) |i| try refusedWith(0x5bec + i, rule);
    }
}

test "property: any single-rule mutation of any drawn spec is refused with its message" {
    try minish.check(testing.allocator, minish.gen.int(u64), anyRule, .{ .num_runs = 10_000, .seed = 0x5bec });
    try minish.check(testing.allocator, minish.gen.int(u64), anyRule, .{ .num_runs = 2_000 });
}
