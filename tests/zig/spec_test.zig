//! spec.zig from outside (minish, the `test` step; DESIGN.md, "Tests";
//! the Zig port's L1): bwrapArgv's golden argv per branch (plain, relay,
//! nestedSandbox, a project filter, keep-fds, trace); valid specs drawn
//! from a model parse back to the model; and each single-rule mutation of a
//! valid spec is refused with its message, one line on stderr.
//!
//! The closure must be a real path in the store: options.store is one
//! (build.zig: the directory of the zig that builds this). The keep-fds are
//! descriptors this test opens itself, by raw calls, outside the table, as
//! the wrapper's are.

const std = @import("std");
const linux = std.os.linux;
const minish = @import("minish");
const sys = @import("sys");
const fd = @import("fd");
const msg = @import("msg");
const mount = @import("mount");
const spec = @import("spec");
const options = @import("options");
const testing = std.testing;
const Allocator = std.mem.Allocator;

const store = options.store;

// ---- descriptors and stderr, by raw calls ----

fn openNull() !i32 {
    const rc = linux.open("/dev/null", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.E.init(rc) != .SUCCESS) return error.Open;
    return @intCast(rc);
}

fn isOpen(n: i32) bool {
    return linux.E.init(linux.fcntl(n, 1, 0)) == .SUCCESS;
}

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

const Parsed = struct { spec: ?spec.Spec, err: []const u8 };

/// Parses `words` as argv[1..] (argv[0] "launch", the subcommand's word
/// flong launch's argv starts at), in `arena`, and returns what it said on
/// stderr.
fn parseWords(arena: Allocator, words: []const []const u8, errbuf: []u8) !Parsed {
    const argv = try arena.alloc([*:0]const u8, words.len + 1);
    argv[0] = "launch";
    for (words, 1..) |w, i| argv[i] = (try arena.dupeZ(u8, w)).ptr;
    msg.prog = "flong launch";
    msg.mode = .cut;
    const cap = try Capture.begin();
    const r = spec.parse(arena, argv);
    const err = try cap.end(errbuf);
    try testing.expectEqual(@as(usize, 0), fd.liveCount());
    return .{ .spec = r catch null, .err = err };
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

/// The spec every branch starts from: a caller's usual one, two groups.
const base = [_][]const u8{
    "machine", "m",                    "container", "c",
    "state",   "/run/user/1000/flong", "cache",     "/home/u/.cache/flong/c",
    "closure", "@CLOSURE@",            "uidmap",    "0",
    "100000",  "1000",                 "uidmap",    "1000",
    "1000",    "1",                    "uidmap",    "1001",
    "101001",  "64535",                "gidmap",    "0",
    "100000",  "100",                  "gidmap",    "100",
    "100",     "1",                    "gidmap",    "101",
    "100101",  "65435",                "user",      "1000",
    "100",     "/home/u",              "group",     "100",
    "group",   "27",                   "holder",    "flong.slice/s",
    "chdir",   "/home/u/w",
};
const command = [_][]const u8{ "--", "sh", "-c", "exec \"$@\"", "--" };

/// Each branch's words beyond `base`, the terminal, and its argv, @X@
/// standing for what only the run knows: the closure, a keep-fd's number,
/// and each descriptor bwrap is passed.
fn expectArgv(extra: []const []const u8, relay: bool, want: []const []const u8) !void {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const keep = try openNull();
    defer _ = linux.close(keep);
    const keep_text = try std.fmt.allocPrint(arena, "{d}", .{keep});
    const vars = [_][2][]const u8{ .{ "@CLOSURE@", store }, .{ "@KEEP@", keep_text } };

    var words: std.ArrayList([]const u8) = .empty;
    for ([_][]const []const u8{ &base, extra, &command }) |part| {
        for (part) |w| try words.append(arena, try substitute(arena, w, &vars));
    }
    var errbuf: [4096]u8 = undefined;
    const p = try parseWords(arena, words.items, &errbuf);
    try testing.expectEqualStrings("", p.err);
    const s = p.spec.?;

    var rec: Recorder = .{ .gpa = arena };
    try spec.bwrapArgv(arena, &rec, &s, .{
        .u1 = Named{ .name = "@U1@" },
        .u2 = Named{ .name = "@U2@" },
        .info_w = Named{ .name = "@INFO@" },
        .seccomp = seccomp_fds[0..s.seccomp.len],
        .gate_r = Named{ .name = "@GATE@" },
        .ready_w = Named{ .name = "@READY@" },
    }, relay, "/nix/store/test-only-flong");

    var expected: std.ArrayList([]const u8) = .empty;
    for (want) |w| try expected.append(arena, try substitute(arena, w, &vars));
    for (expected.items, 0..) |w, i| {
        if (i >= rec.words.items.len) break;
        testing.expectEqualStrings(w, rec.words.items[i]) catch |err| {
            std.debug.print("bwrap argv word {d} differs\n", .{i});
            return err;
        };
    }
    try testing.expectEqual(expected.items.len, rec.words.items.len);
}

fn substitute(arena: Allocator, w: []const u8, vars: []const [2][]const u8) ![]const u8 {
    var out = w;
    for (vars) |v| out = try std.mem.replaceOwned(u8, arena, out, v[0], v[1]);
    return out;
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
const tail_command = [_][]const u8{ "--", "sh", "-c", "exec \"$@\"", "--" };

fn cat(comptime parts: []const []const []const u8) []const []const u8 {
    comptime var out: []const []const u8 = &.{};
    inline for (parts) |p| out = out ++ p;
    return out;
}

test "bwrapArgv: plain" {
    try expectArgv(&.{}, false, comptime cat(&.{
        &head,
        &middle,
        &.{ "--", "/nix/store/test-only-flong", "init", "@GATE@", "@READY@", "100,27", "-", "-", "/home/u/w" },
        &tail_command,
    }));
}

test "bwrapArgv: relay, a session of its own and flong init's ctty" {
    try expectArgv(&.{}, true, comptime cat(&.{
        &head,
        &.{"--new-session"},
        &middle,
        &.{ "--", "/nix/store/test-only-flong", "init", "@GATE@", "@READY@", "100,27", "ctty", "-", "/home/u/w" },
        &tail_command,
    }));
}

test "bwrapArgv: nestedSandbox drops --assert-userns-disabled" {
    try expectArgv(&.{ "nested-userns", "128" }, false, comptime cat(&.{
        &.{ "--userns", "@U1@", "--userns2", "@U2@" },
        head[5..],
        &middle,
        &.{ "--", "/nix/store/test-only-flong", "init", "@GATE@", "@READY@", "100,27", "-", "-", "/home/u/w" },
        &tail_command,
    }));
}

test "bwrapArgv: the tier's filters and a project filter, one --add-seccomp-fd each, in order" {
    try expectArgv(&.{ "seccomp", "/nix/store/a-tier.bpf", "seccomp", "/nix/store/b-audit.bpf", "seccomp", "/home/u/.cache/flong/seccomp/k" }, false, comptime cat(&.{
        &head,
        &.{ "--add-seccomp-fd", "@SECCOMP0@", "--add-seccomp-fd", "@SECCOMP1@", "--add-seccomp-fd", "@SECCOMP2@" },
        &middle,
        &.{ "--", "/nix/store/test-only-flong", "init", "@GATE@", "@READY@", "100,27", "-", "-", "/home/u/w" },
        &tail_command,
    }));
}

test "bwrapArgv: keep-fds' bwrap-args go verbatim, after the fixed part" {
    try expectArgv(&.{
        "keep-fd",   "@KEEP@",
        "bwrap-arg", "--clearenv",
        "bwrap-arg", "--setenv",
        "bwrap-arg", "HOME",
        "bwrap-arg", "/home/u",
        "bwrap-arg", "--perms",
        "bwrap-arg", "0644",
        "bwrap-arg", "--ro-bind-data",
        "bwrap-arg", "@KEEP@",
        "bwrap-arg", "/etc/resolv.conf",
    }, false, comptime cat(&.{
        &head,
        &middle,
        &.{ "--clearenv", "--setenv", "HOME", "/home/u", "--perms", "0644", "--ro-bind-data", "@KEEP@", "/etc/resolv.conf" },
        &.{ "--", "/nix/store/test-only-flong", "init", "@GATE@", "@READY@", "100,27", "-", "-", "/home/u/w" },
        &tail_command,
    }));
}

test "bwrapArgv: trace, and no groups" {
    var no_groups: [base.len - 4][]const u8 = undefined;
    // base without its two `group`s (the four words before `holder`).
    @memcpy(no_groups[0..38], base[0..38]);
    @memcpy(no_groups[38..], base[42..]);
    try testing.expectEqualStrings("holder", no_groups[38]);
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var words: std.ArrayList([]const u8) = .empty;
    for (no_groups) |w| try words.append(arena, if (std.mem.eql(u8, w, "@CLOSURE@")) store else w);
    try words.appendSlice(arena, &.{ "trace", "--", "true" });
    var errbuf: [4096]u8 = undefined;
    const p = try parseWords(arena, words.items, &errbuf);
    try testing.expectEqualStrings("", p.err);
    var rec: Recorder = .{ .gpa = arena };
    try spec.bwrapArgv(arena, &rec, &p.spec.?, .{
        .u1 = Named{ .name = "@U1@" },
        .u2 = Named{ .name = "@U2@" },
        .info_w = Named{ .name = "@INFO@" },
        .seccomp = seccomp_fds[0..0],
        .gate_r = Named{ .name = "@GATE@" },
        .ready_w = Named{ .name = "@READY@" },
    }, false, "/flong");
    const got = rec.words.items;
    try testing.expectEqualStrings("--", got[got.len - 11]);
    const init_tail = [_][]const u8{ "/flong", "init", "@GATE@", "@READY@", "-", "-", "trace", "/home/u/w", "--", "true" };
    for (init_tail, got[got.len - 10 ..]) |w, g| try testing.expectEqualStrings(w, g);
}

// ---- the model ----

const name_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.";
const any_chars = "abcXYZ019_-.= \t\n@:,+~$\"'*";

const MountM = struct {
    kind: mount.Kind,
    kind_name: []const u8,
    dest: []const u8,
    src: ?[]const u8 = null,
    mode: ?[]const u8 = null,
    size: []const u8 = "",
    owner: []const u8 = "root",
};

const Model = struct {
    machine: []const u8,
    container: []const u8,
    state: []const u8,
    cache: []const u8,
    relaunch: [][]const u8,
    uidmap: []spec.IdMap,
    gidmap: []spec.IdMap,
    uid: u32,
    gid: u32,
    home: []const u8,
    groups: []u32,
    chdir: ?[]const u8,
    mounts: []MountM,
    protect: [][]const u8,
    seccomp: [][]const u8,
    nested: u64,
    holder: []const u8,
    holder_start: [][]const u8,
    limits: []spec.Limit,
    /// commands, each its words, the program first
    post_start: [][]const []const u8,
    post_stop: [][]const []const u8,
    network: bool,
    pasta_args: [][]const u8,
    pasta_wait: bool,
    /// the bwrap-args, grouped by option (--perms goes with its
    /// --ro-bind-data), in order
    bwrap: [][]const []const u8,
    keep_fds: []i32,
    /// each keep-fd's word, perhaps with leading zeros
    keep_words: [][]const u8,
    trace: bool,
    command: [][]const u8,
};

const Gen = struct {
    r: std.Random,
    a: Allocator,

    fn below(g: Gen, n: usize) usize {
        return g.r.uintLessThan(usize, n);
    }

    fn chance(g: Gen, one_in: usize) bool {
        return g.below(one_in) == 0;
    }

    fn charsFrom(g: Gen, set: []const u8, len: usize) ![]u8 {
        const out = try g.a.alloc(u8, len);
        for (out) |*c| c.* = set[g.below(set.len)];
        return out;
    }

    fn name(g: Gen) ![]const u8 {
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

    fn cleanPath(g: Gen, rooted: spec.Rooted) ![]const u8 {
        var out: std.ArrayList(u8) = .empty;
        const n = 1 + g.below(4);
        for (0..n) |i| {
            if (i > 0 or rooted == .absolute) try out.append(g.a, '/');
            try out.appendSlice(g.a, try g.component());
        }
        return out.items;
    }

    /// An absolute path, spelled any way: "//", "..", a trailing slash.
    fn absPath(g: Gen) ![]const u8 {
        if (g.chance(3)) return g.cleanPath(.absolute);
        const rest = try g.charsFrom(any_chars ++ "//..", g.below(30));
        return std.mem.concat(g.a, u8, &.{ "/", rest });
    }

    /// Any word, "--" and the empty one included.
    fn word(g: Gen) ![]const u8 {
        return switch (g.below(8)) {
            0 => "--",
            1 => "",
            2 => "machine",
            else => g.charsFrom(any_chars, 1 + g.below(12)),
        };
    }

    fn words(g: Gen, max: usize) ![][]const u8 {
        const out = try g.a.alloc([]const u8, g.below(max + 1));
        for (out) |*w| w.* = try g.word();
        return out;
    }

    /// A command: `program`, then up to three words.
    fn command(g: Gen, program: []const u8) ![]const []const u8 {
        const rest = try g.words(3);
        return std.mem.concat(g.a, []const u8, &.{ &.{program}, rest });
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

    fn octal(g: Gen) ![]const u8 {
        const v = g.below(0o7777 + 1);
        const digits = try std.fmt.allocPrint(g.a, "{o}", .{v});
        const pad = g.below(5 - digits.len + 1);
        return std.mem.concat(g.a, u8, &.{ "0000"[0..pad], digits });
    }

    fn decimal(g: Gen, v: u64) ![]const u8 {
        const zeros = if (g.chance(4)) "00" else "";
        return std.fmt.allocPrint(g.a, "{s}{d}", .{ zeros, v });
    }

    fn mountM(g: Gen) !MountM {
        const kinds = [_]struct { []const u8, mount.Kind }{
            .{ "bind-ro", .bind_ro },             .{ "bind-rw", .bind_rw },
            .{ "bind-ro-exact", .bind_ro_exact }, .{ "bind-rw-exact", .bind_rw_exact },
            .{ "dev", .dev },                     .{ "tmpfs", .tmpfs },
            .{ "overlay", .overlay },             .{ "mask", .mask },
        };
        const k = kinds[g.below(kinds.len)];
        var m: MountM = .{ .kind = k[1], .kind_name = k[0], .dest = try g.cleanPath(.absolute) };
        switch (m.kind) {
            .bind_ro_exact, .bind_rw_exact => m.src = try g.cleanPath(.absolute),
            .bind_ro, .bind_rw, .dev, .overlay => m.src = try g.absPath(),
            .tmpfs => {
                m.mode = try g.octal();
                m.size = switch (g.below(3)) {
                    0 => "",
                    1 => try g.decimal(g.below(1 << 20)),
                    else => try std.fmt.allocPrint(g.a, "{d}{c}", .{ g.below(100), "kKmMgGtTpPeE%"[g.below(13)] }),
                };
                m.owner = if (g.r.boolean()) "user" else "root";
            },
            .mask => {},
        }
        return m;
    }

    fn model(g: Gen, fds: []const i32) !Model {
        const uidmap = try g.idmap();
        const gidmap = try g.idmap();
        const groups = try g.a.alloc(u32, g.below(4));
        for (groups) |*x| x.* = g.inMap(gidmap);
        const mounts = try g.a.alloc(MountM, g.below(5));
        for (mounts) |*m| m.* = try g.mountM();
        const protect = try g.a.alloc([]const u8, g.below(3));
        for (protect) |*p| p.* = try g.cleanPath(.absolute);
        const seccomp = try g.a.alloc([]const u8, g.below(4));
        for (seccomp) |*p| p.* = try g.absPath();
        const holder_start = try g.words(2);
        if (holder_start.len > 0) holder_start[0] = try g.absPath();
        const post_start = try g.a.alloc([]const []const u8, g.below(3));
        for (post_start) |*c| c.* = try g.command(try g.absPath());
        const post_stop = try g.a.alloc([]const []const u8, g.below(3));
        for (post_stop) |*c| c.* = try g.command(try std.mem.concat(g.a, u8, &.{ "/nix/store/", try g.cleanPath(.relative) }));

        var limits: std.ArrayList(spec.Limit) = .empty;
        const files = [_][:0]const u8{ "memory.max", "memory.high", "memory.swap.max", "memory.oom.group", "pids.max", "cpu.max", "cpu.weight", "io.weight" };
        var order = files;
        g.r.shuffle([:0]const u8, &order);
        for (order[0..g.below(files.len + 1)]) |f| {
            var v = try g.word();
            if (v.len == 0) v = "max";
            try limits.append(g.a, .{ .file = f, .value = try g.a.dupeZ(u8, v) });
        }

        const network = g.r.boolean();
        const pasta_args = if (network) try g.words(2) else try g.a.alloc([]const u8, 0);

        // The keep-fds, a subset of the pool, each named by a
        // --ro-bind-data; and other options around them.
        var keep: std.ArrayList(i32) = .empty;
        var keep_words: std.ArrayList([]const u8) = .empty;
        var groups_b: std.ArrayList([]const []const u8) = .empty;
        var shuffled_fds: [8]i32 = undefined;
        @memcpy(shuffled_fds[0..fds.len], fds);
        g.r.shuffle(i32, shuffled_fds[0..fds.len]);
        for (shuffled_fds[0..g.below(fds.len)]) |n| {
            try keep.append(g.a, n);
            try keep_words.append(g.a, try g.decimal(@intCast(n)));
            const dest = try g.cleanPath(.absolute);
            const text = try g.decimal(@intCast(n));
            if (g.r.boolean()) {
                try groups_b.append(g.a, try g.a.dupe([]const u8, &.{ "--perms", try g.octal(), "--ro-bind-data", text, dest }));
            } else {
                try groups_b.append(g.a, try g.a.dupe([]const u8, &.{ "--ro-bind-data", text, dest }));
            }
        }
        for (0..g.below(4)) |_| {
            const opt: []const []const u8 = switch (g.below(4)) {
                0 => &.{"--clearenv"},
                1 => try g.a.dupe([]const u8, &.{ "--setenv", try g.component(), try g.word() }),
                2 => try g.a.dupe([]const u8, &.{ "--unsetenv", try g.component() }),
                else => try g.a.dupe([]const u8, &.{ "--hostname", try g.name() }),
            };
            // No '=' in a variable's name.
            if (opt.len > 1 and std.mem.indexOfScalar(u8, opt[1], '=') != null) continue;
            try groups_b.append(g.a, opt);
        }
        g.r.shuffle([]const []const u8, groups_b.items);

        const command_words = try g.words(3);
        const cmd = if (command_words.len == 0) try g.a.dupe([]const u8, &.{"true"}) else command_words;

        return .{
            .machine = try g.name(),
            .container = try g.name(),
            .state = try g.absPath(),
            .cache = try g.absPath(),
            .relaunch = try g.words(3),
            .uidmap = uidmap,
            .gidmap = gidmap,
            .uid = g.inMap(uidmap),
            .gid = g.inMap(gidmap),
            .home = try g.cleanPath(.absolute),
            .groups = groups,
            .chdir = if (g.r.boolean()) try g.absPath() else null,
            .mounts = mounts,
            .protect = protect,
            .seccomp = seccomp,
            .nested = if (g.r.boolean()) 0 else 1 + g.r.uintLessThan(u64, std.math.maxInt(i32)),
            .holder = try g.cleanPath(.relative),
            .holder_start = holder_start,
            .limits = limits.items,
            .post_start = post_start,
            .post_stop = post_stop,
            .network = network,
            .pasta_args = pasta_args,
            .pasta_wait = network and g.r.boolean(),
            .bwrap = groups_b.items,
            .keep_fds = keep.items,
            .keep_words = keep_words.items,
            .trace = g.r.boolean(),
            .command = cmd,
        };
    }
};

/// One keyword and its fields.
const Item = struct { kw: []const u8, fields: []const []const u8 };

fn item(a: Allocator, kw: []const u8, fields: []const []const u8) !Item {
    return .{ .kw = kw, .fields = try a.dupe([]const u8, fields) };
}

fn num(a: Allocator, v: u64) ![]const u8 {
    return std.fmt.allocPrint(a, "{d}", .{v});
}

/// A post-start or post-stop: its word count, then its words.
fn commandItem(a: Allocator, kw: []const u8, cmd: []const []const u8) !Item {
    return .{ .kw = kw, .fields = try std.mem.concat(a, []const u8, &.{ &.{try num(a, cmd.len)}, cmd }) };
}

/// The model as the wrapper would pass it, keyword by keyword.
fn items(a: Allocator, m: *const Model) !std.ArrayList(Item) {
    var out: std.ArrayList(Item) = .empty;
    try out.append(a, try item(a, "machine", &.{m.machine}));
    try out.append(a, try item(a, "container", &.{m.container}));
    try out.append(a, try item(a, "state", &.{m.state}));
    try out.append(a, try item(a, "cache", &.{m.cache}));
    for (m.relaunch) |w| try out.append(a, try item(a, "relaunch", &.{w}));
    try out.append(a, try item(a, "closure", &.{store}));
    for (m.uidmap) |e| try out.append(a, try item(a, "uidmap", &.{ try num(a, e.inside), try num(a, e.outside), try num(a, e.count) }));
    for (m.gidmap) |e| try out.append(a, try item(a, "gidmap", &.{ try num(a, e.inside), try num(a, e.outside), try num(a, e.count) }));
    try out.append(a, try item(a, "user", &.{ try num(a, m.uid), try num(a, m.gid), m.home }));
    for (m.groups) |x| try out.append(a, try item(a, "group", &.{try num(a, x)}));
    if (m.chdir) |c| try out.append(a, try item(a, "chdir", &.{c}));
    for (m.mounts) |x| {
        const f: []const []const u8 = switch (x.kind) {
            .tmpfs => &.{ x.kind_name, x.dest, x.mode.?, x.size, x.owner },
            .mask => &.{ x.kind_name, x.dest },
            else => &.{ x.kind_name, x.dest, x.src.? },
        };
        try out.append(a, try item(a, "mount", f));
    }
    for (m.protect) |p| try out.append(a, try item(a, "protect", &.{p}));
    for (m.seccomp) |p| try out.append(a, try item(a, "seccomp", &.{p}));
    if (m.nested != 0) try out.append(a, try item(a, "nested-userns", &.{try num(a, m.nested)}));
    try out.append(a, try item(a, "holder", &.{m.holder}));
    for (m.holder_start) |w| try out.append(a, try item(a, "holder-start", &.{w}));
    for (m.limits) |l| try out.append(a, try item(a, "limit", &.{ l.file, l.value }));
    for (m.post_start) |c| try out.append(a, try commandItem(a, "post-start", c));
    for (m.post_stop) |c| try out.append(a, try commandItem(a, "post-stop", c));
    if (m.network) try out.append(a, try item(a, "network", &.{}));
    for (m.pasta_args) |w| try out.append(a, try item(a, "pasta-arg", &.{w}));
    if (m.pasta_wait) try out.append(a, try item(a, "pasta-wait", &.{}));
    for (m.bwrap) |grp| {
        for (grp) |w| try out.append(a, try item(a, "bwrap-arg", &.{w}));
    }
    for (m.keep_words) |w| try out.append(a, try item(a, "keep-fd", &.{w}));
    if (m.trace) try out.append(a, try item(a, "trace", &.{}));
    return out;
}

/// The words: the items in a random order that keeps each keyword's own,
/// then "--" and the command.
fn render(g: Gen, its: []const Item, command_words: ?[]const []const u8) ![]const []const u8 {
    var queues: std.StringArrayHashMapUnmanaged(std.ArrayList(Item)) = .empty;
    for (its) |it| {
        const q = try queues.getOrPut(g.a, it.kw);
        if (!q.found_existing) q.value_ptr.* = .empty;
        try q.value_ptr.append(g.a, it);
    }
    var heads = try g.a.alloc(usize, queues.count());
    @memset(heads, 0);
    var out: std.ArrayList([]const u8) = .empty;
    var left = its.len;
    while (left > 0) {
        const qi = g.below(queues.count());
        const q = queues.values()[qi];
        if (heads[qi] == q.items.len) continue;
        const it = q.items[heads[qi]];
        heads[qi] += 1;
        left -= 1;
        try out.append(g.a, it.kw);
        try out.appendSlice(g.a, it.fields);
    }
    if (command_words) |c| {
        try out.append(g.a, "--");
        try out.appendSlice(g.a, c);
    }
    return out.items;
}

fn expectSlicesOfStrings(want: []const []const u8, got: []const [:0]const u8) !void {
    try testing.expectEqual(want.len, got.len);
    for (want, got) |w, x| try testing.expectEqualStrings(w, x);
}

/// The Spec equals the model it was rendered from.
fn expectModel(m: *const Model, s: *const spec.Spec) !void {
    try testing.expectEqualStrings(m.machine, s.machine);
    try testing.expectEqualStrings(m.container, s.container);
    try testing.expectEqualStrings(m.state, s.state);
    try testing.expectEqualStrings(m.cache, s.cache);
    try expectSlicesOfStrings(m.relaunch, s.relaunch);
    try testing.expectEqualStrings(store, s.closure);
    try testing.expectEqualSlices(spec.IdMap, m.uidmap, s.uidmap);
    try testing.expectEqualSlices(spec.IdMap, m.gidmap, s.gidmap);
    try testing.expectEqual(m.uid, s.uid);
    try testing.expectEqual(m.gid, s.gid);
    try testing.expectEqualStrings(m.home, s.home);
    try testing.expectEqualSlices(u32, m.groups, s.groups);
    try testing.expectEqualStrings(m.chdir orelse "/", s.chdir);
    try testing.expectEqual(m.mounts.len, s.mounts.len);
    for (m.mounts, s.mounts) |x, y| {
        try testing.expectEqual(x.kind, y.kind);
        try testing.expectEqualStrings(x.dest, y.dest);
        try testing.expectEqual(x.src == null, y.src == null);
        if (x.src) |src| try testing.expectEqualStrings(src, y.src.?);
        try testing.expectEqual(x.mode == null, y.mode == null);
        if (x.mode) |mode| try testing.expectEqualStrings(mode, y.mode.?);
        try testing.expectEqual(x.size.len == 0, y.size == null);
        if (y.size) |size| try testing.expectEqualStrings(x.size, size);
        try testing.expectEqual(std.mem.eql(u8, x.owner, "user"), y.owner_user);
    }
    try expectSlicesOfStrings(m.protect, s.protect);
    try expectSlicesOfStrings(m.seccomp, s.seccomp);
    try testing.expectEqual(m.nested, s.nested_userns);
    try testing.expectEqualStrings(m.holder, s.holder);
    try expectSlicesOfStrings(m.holder_start, s.holder_start);
    try testing.expectEqual(m.limits.len, s.limits.len);
    for (m.limits, s.limits) |x, y| {
        try testing.expectEqualStrings(x.file, y.file);
        try testing.expectEqualStrings(x.value, y.value);
    }
    try testing.expectEqual(m.post_start.len, s.post_start.len);
    for (m.post_start, s.post_start) |x, y| try expectSlicesOfStrings(x, y);
    try testing.expectEqual(m.post_stop.len, s.post_stop.len);
    for (m.post_stop, s.post_stop) |x, y| try expectSlicesOfStrings(x, y);
    try testing.expectEqual(m.network, s.network);
    try expectSlicesOfStrings(m.pasta_args, s.pasta_args);
    try testing.expectEqual(m.pasta_wait, s.pasta_wait);
    var n: usize = 0;
    for (m.bwrap) |grp| {
        for (grp) |w| {
            try testing.expectEqualStrings(w, s.bwrap_args[n]);
            n += 1;
        }
    }
    try testing.expectEqual(n, s.bwrap_args.len);
    try testing.expectEqualSlices(i32, m.keep_fds, s.keep_fds);
    try testing.expectEqual(m.trace, s.trace);
    try testing.expectEqual(m.command.len, s.command.len);
    for (m.command, s.command) |w, x| try testing.expectEqualStrings(w, std.mem.span(x));
}

/// The descriptors keep-fds may name: open here, by raw calls, for the
/// test's life.
var pool_buf: [4]i32 = undefined;
var pool: []const i32 = &.{};

fn openPool() !void {
    if (pool.len > 0) return;
    for (&pool_buf) |*n| n.* = try openNull();
    pool = &pool_buf;
}

fn parsesBack(seed: u64) !void {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    var prng: std.Random.DefaultPrng = .init(seed);
    const g: Gen = .{ .r = prng.random(), .a = arena_state.allocator() };
    const m = try g.model(pool);
    const its = try items(g.a, &m);
    const words = try render(g, its.items, m.command);
    var errbuf: [4096]u8 = undefined;
    const p = try parseWords(g.a, words, &errbuf);
    try testing.expectEqualStrings("", p.err);
    try expectModel(&m, &(p.spec orelse return error.Refused));
}

test "property: a spec drawn from the model parses back to the model" {
    try openPool();
    try minish.check(testing.allocator, minish.gen.int(u64), parsesBack, .{ .num_runs = 10_000, .seed = 0x5bec });
    try minish.check(testing.allocator, minish.gen.int(u64), parsesBack, .{ .num_runs = 2_000 });
}

// ---- single-rule mutations ----

const Rule = enum {
    unknown_keyword,
    missing_required,
    once_twice,
    no_separator,
    empty_command,
    fields_short,
    mount_kind_missing,
    mount_kind_unknown,
    mount_fields_short,
    machine_not_name,
    container_not_name,
    state_relative,
    cache_too_long,
    closure_outside,
    closure_unclean,
    closure_absent,
    idmap_count_0,
    idmap_host_0,
    idmap_past,
    idmap_not_decimal,
    idmap_too_large,
    idmap_overlap,
    uid_unmapped,
    gid_unmapped,
    group_unmapped,
    home_unclean,
    chdir_relative,
    mount_dest_unclean,
    tmpfs_mode_not_octal,
    tmpfs_mode_large,
    tmpfs_size_bad,
    tmpfs_owner_bad,
    exact_src_unclean,
    bind_src_relative,
    protect_relative,
    seccomp_relative,
    nested_zero,
    holder_absolute,
    limit_unknown,
    limit_twice,
    limit_empty,
    post_stop_outside,
    keep_fd_stdio,
    keep_fd_twice,
    keep_fd_closed,
    keep_fd_unused,
    bwrap_not_allowed,
    bwrap_no_keep_fd,
    bwrap_perms_alone,
    bwrap_setenv_name,
    bwrap_short,
    bwrap_hostname_empty,
    pasta_without_network,
    holder_start_relative,
    post_start_relative,
    command_count_bad,
};

/// A descriptor number no test holds.
const closed_fd = 900;

fn firstOf(its: []Item, kw: []const u8) *Item {
    for (its) |*it| {
        if (std.mem.eql(u8, it.kw, kw)) return it;
    }
    unreachable;
}

fn setField(a: Allocator, its: []Item, kw: []const u8, i: usize, v: []const u8) !void {
    const it = firstOf(its, kw);
    const f = try a.dupe([]const u8, it.fields);
    f[i] = v;
    it.fields = f;
}

/// Applies `rule` to a valid model and returns the words and the one line
/// the parse must say.
fn mutate(g: Gen, rule: Rule, m: *Model) !struct { words: []const []const u8, want: []const u8 } {
    const a = g.a;
    var cmd: ?[]const []const u8 = m.command;
    var want: []const u8 = undefined;
    // Model-level changes first, then the items.
    switch (rule) {
        .pasta_without_network => {
            m.network = false;
            m.pasta_args = try a.dupe([]const u8, &.{"--no-map-gw"});
            m.pasta_wait = false;
            want = "spec: pasta-arg or pasta-wait without network";
        },
        .holder_start_relative => {
            m.holder_start = try a.dupe([]const u8, &.{ "bin/start", "/x" });
            want = "spec: holder-start's program is not an absolute path: 'bin/start'";
        },
        .post_start_relative => {
            // After the model's commands, each checked.
            const bad: []const []const u8 = &.{ "hook", "/x" };
            m.post_start = try std.mem.concat(a, []const []const u8, &.{ m.post_start, &.{bad} });
            want = "spec: post-start's program is not an absolute path: 'hook'";
        },
        .bwrap_not_allowed, .bwrap_no_keep_fd, .bwrap_setenv_name, .bwrap_hostname_empty, .bwrap_perms_alone, .bwrap_short => {
            const bad: []const []const u8 = switch (rule) {
                .bwrap_not_allowed => &.{ "--bind", "/", "/" },
                .bwrap_no_keep_fd => &.{ "--ro-bind-data", "901", "/x" },
                .bwrap_setenv_name => &.{ "--setenv", "A=B", "v" },
                .bwrap_hostname_empty => &.{ "--hostname", "" },
                .bwrap_perms_alone => &.{ "--perms", "0644" },
                else => &.{ "--setenv", "X" },
            };
            want = switch (rule) {
                .bwrap_not_allowed => "spec: bwrap-arg '--bind' is not allowed: flong passes bwrap only --clearenv, --setenv, --unsetenv, --hostname and --perms before --ro-bind-data",
                .bwrap_no_keep_fd => "spec: bwrap-arg --ro-bind-data names descriptor 901, which is no keep-fd",
                .bwrap_setenv_name => "spec: bwrap-arg: 'A=B' is not a variable name",
                .bwrap_hostname_empty => "spec: bwrap-arg --hostname is empty",
                .bwrap_perms_alone => "spec: bwrap-arg --perms is allowed only before --ro-bind-data",
                else => "spec: bwrap-arg --setenv: 2 arguments expected",
            };
            // At a group's boundary; last where the rule needs nothing
            // after it.
            const at = if (rule == .bwrap_perms_alone or rule == .bwrap_short) m.bwrap.len else g.below(m.bwrap.len + 1);
            var groups: std.ArrayList([]const []const u8) = .empty;
            try groups.appendSlice(a, m.bwrap[0..at]);
            try groups.append(a, bad);
            try groups.appendSlice(a, m.bwrap[at..]);
            m.bwrap = groups.items;
        },
        .keep_fd_closed => {
            try testing.expect(!isOpen(closed_fd));
            m.keep_fds = try std.mem.concat(a, i32, &.{ m.keep_fds, &.{closed_fd} });
            m.keep_words = try std.mem.concat(a, []const u8, &.{ m.keep_words, &.{"900"} });
            m.bwrap = try std.mem.concat(a, []const []const u8, &.{ m.bwrap, &.{&.{ "--ro-bind-data", "900", "/x" }} });
            want = "spec: keep-fd 900: Bad file descriptor";
        },
        .keep_fd_unused => {
            const free = for (pool) |n| {
                if (std.mem.indexOfScalar(i32, m.keep_fds, n) == null) break n;
            } else unreachable; // the model takes fewer than the pool
            // Last, so every other keep-fd, used, is checked before it.
            m.keep_fds = try std.mem.concat(a, i32, &.{ m.keep_fds, &.{free} });
            m.keep_words = try std.mem.concat(a, []const u8, &.{ m.keep_words, &.{try num(a, @intCast(free))} });
            want = try std.fmt.allocPrint(a, "spec: keep-fd {d} is named by no bwrap-arg --ro-bind-data", .{free});
        },
        else => {},
    }
    var its = try items(a, m);
    switch (rule) {
        .pasta_without_network, .holder_start_relative, .post_start_relative, .keep_fd_closed, .keep_fd_unused => {},
        .bwrap_not_allowed, .bwrap_no_keep_fd, .bwrap_setenv_name, .bwrap_hostname_empty, .bwrap_perms_alone, .bwrap_short => {},
        .unknown_keyword => {
            try its.append(a, try item(a, "Machine", &.{}));
            want = "spec: unknown keyword 'Machine'";
        },
        .missing_required => {
            const req = [_][]const u8{ "machine", "container", "state", "cache", "closure", "uidmap", "gidmap", "user", "holder" };
            const kw = req[g.below(req.len)];
            var kept: std.ArrayList(Item) = .empty;
            for (its.items) |it| {
                if (!std.mem.eql(u8, it.kw, kw)) try kept.append(a, it);
            }
            its = kept;
            want = try std.fmt.allocPrint(a, "spec: {s} is missing", .{kw});
        },
        .once_twice => {
            const onces = [_]Item{
                try item(a, "machine", &.{"m"}),   try item(a, "container", &.{"c"}),
                try item(a, "state", &.{"/s"}),    try item(a, "cache", &.{"/c"}),
                try item(a, "closure", &.{store}), try item(a, "user", &.{ "0", "0", "/h" }),
                try item(a, "chdir", &.{"/"}),     try item(a, "nested-userns", &.{"1"}),
                try item(a, "holder", &.{"h"}),    try item(a, "network", &.{}),
                try item(a, "pasta-wait", &.{}),   try item(a, "trace", &.{}),
            };
            const it = onces[g.below(onces.len)];
            try its.append(a, it);
            try its.append(a, it);
            // Present once already, the second is the first refused; once
            // the model had it, the first.
            want = try std.fmt.allocPrint(a, "spec: {s} given more than once", .{it.kw});
        },
        .no_separator => {
            cmd = null;
            want = "spec: no '--' before the command";
        },
        .empty_command => {
            cmd = &.{};
            want = "spec: the command after '--' is empty";
        },
        .fields_short, .mount_kind_missing, .mount_fields_short => {
            const Short = struct { []const u8, []const []const u8, []const u8 };
            const shorts = [_]Short{
                .{ "uidmap", &.{ "0", "1" }, "spec: uidmap: 3 fields expected" },
                .{ "user", &.{}, "spec: user: 3 fields expected" },
                .{ "limit", &.{"pids.max"}, "spec: limit: 2 fields expected" },
                .{ "machine", &.{}, "spec: machine: 1 field expected" },
                .{ "keep-fd", &.{}, "spec: keep-fd: 1 field expected" },
                .{ "post-start", &.{}, "spec: post-start: the word count is missing" },
                .{ "post-stop", &.{ "3", "/nix/store/x", "--" }, "spec: post-stop: 4 fields expected" },
            };
            const s: Short = switch (rule) {
                .mount_kind_missing => .{ "mount", &.{}, "spec: mount: the kind is missing" },
                .mount_fields_short => if (g.r.boolean())
                    .{ "mount", &.{ "tmpfs", "/t", "0755", "" }, "spec: mount tmpfs: 4 fields expected" }
                else
                    .{ "mount", &.{"mask"}, "spec: mount mask: 1 field expected" },
                else => shorts[g.below(shorts.len)],
            };
            want = s[2];
            // Last in argv, with its fields running out at its end.
            const words = try render(g, its.items, null);
            var all: std.ArrayList([]const u8) = .empty;
            try all.appendSlice(a, words);
            try all.append(a, s[0]);
            try all.appendSlice(a, s[1]);
            return .{ .words = all.items, .want = want };
        },
        .command_count_bad => {
            const kw = if (g.r.boolean()) "post-start" else "post-stop";
            const Bad = struct { []const []const u8, []const u8 };
            const bads = [_]Bad{
                .{ &.{ "0", "/nix/store/x" }, "'s word count is 0" },
                .{ &.{"000"}, "'s word count is 0" },
                .{ &.{ "x", "/nix/store/x" }, "'s word count is not a decimal number: 'x'" },
                .{ &.{ "+1", "/nix/store/x" }, "'s word count is not a decimal number: '+1'" },
                .{ &.{ "", "/nix/store/x" }, "'s word count is empty" },
                // A program where the count goes, as the grammar before
                // the list had it.
                .{ &.{"/nix/store/x"}, "'s word count is not a decimal number: '/nix/store/x'" },
                .{ &.{ "2147483648", "/nix/store/x" }, "'s word count is larger than 2147483647: '2147483648'" },
            };
            const bad = bads[g.below(bads.len)];
            try its.append(a, try item(a, kw, bad[0]));
            want = try std.fmt.allocPrint(a, "spec: {s}{s}", .{ kw, bad[1] });
        },
        .mount_kind_unknown => {
            try its.append(a, try item(a, "mount", &.{ "bind", "/a", "/b" }));
            want = "spec: mount: unknown kind 'bind'";
        },
        .machine_not_name, .container_not_name => {
            const kw = if (rule == .machine_not_name) "machine" else "container";
            const bad = [_][]const u8{ "", ".m", "a/b", "a b", "a" ** 129 };
            const v = bad[g.below(bad.len)];
            try setField(a, its.items, kw, 0, v);
            want = try std.fmt.allocPrint(a, "spec: {s} '{s}' is not a name: 1 to 128 of A-Z a-z 0-9 _ - ., not starting with .", .{ kw, v });
        },
        .state_relative => {
            try setField(a, its.items, "state", 0, "run/user");
            want = "spec: state is not an absolute path: 'run/user'";
        },
        .cache_too_long => {
            try setField(a, its.items, "cache", 0, "/" ++ "c" ** 4095);
            want = "spec: cache is longer than PATH_MAX";
        },
        .closure_outside => {
            try setField(a, its.items, "closure", 0, "/tmp/x");
            want = "spec: closure is not under /nix/store/: '/tmp/x'";
        },
        .closure_unclean => {
            const v = try std.mem.concat(a, u8, &.{ store, "/../x" });
            try setField(a, its.items, "closure", 0, v);
            want = try std.fmt.allocPrint(a, "spec: closure has an empty, '.' or '..' component: '{s}'", .{v});
        },
        .closure_absent => {
            const v = "/nix/store/00000000000000000000000000000000-absent";
            try setField(a, its.items, "closure", 0, v);
            want = "spec: closure '" ++ v ++ "': No such file or directory";
        },
        .idmap_count_0, .idmap_host_0, .idmap_past, .idmap_not_decimal, .idmap_too_large => {
            const kw = if (g.r.boolean()) "uidmap" else "gidmap";
            const it = firstOf(its.items, kw);
            const f = try a.dupe([]const u8, it.fields);
            switch (rule) {
                .idmap_count_0 => {
                    f[2] = "0";
                    want = try std.fmt.allocPrint(a, "spec: {s} {s} {s} 0: the count is 0", .{ kw, f[0], f[1] });
                },
                .idmap_host_0 => {
                    f[1] = "0";
                    want = try std.fmt.allocPrint(a, "spec: {s} {s} 0 {s} reaches host id 0: flong never maps host root", .{ kw, f[0], f[2] });
                },
                .idmap_past => {
                    f[0] = "4294967294";
                    f[2] = "2";
                    want = try std.fmt.allocPrint(a, "spec: {s} 4294967294 {s} 2: the extent runs past id 4294967294", .{ kw, f[1] });
                },
                .idmap_not_decimal => {
                    f[1] = "+1";
                    want = try std.fmt.allocPrint(a, "spec: {s} is not a decimal number: '+1'", .{kw});
                },
                else => {
                    f[0] = "4294967295";
                    want = try std.fmt.allocPrint(a, "spec: {s} is larger than 4294967294: '4294967295'", .{kw});
                },
            }
            it.fields = f;
        },
        .idmap_overlap => {
            const uid = g.r.boolean();
            const kw = if (uid) "uidmap" else "gidmap";
            const map = if (uid) m.uidmap else m.gidmap;
            const e = map[0];
            try its.append(a, try item(a, kw, &.{ try num(a, e.inside), try num(a, e.outside), try num(a, e.count) }));
            want = try std.fmt.allocPrint(a, "spec: {s} extents {d} {d} {d} and {d} {d} {d} overlap", .{ kw, e.inside, e.outside, e.count, e.inside, e.outside, e.count });
        },
        .uid_unmapped, .gid_unmapped, .group_unmapped => {
            const map = if (rule == .uid_unmapped) m.uidmap else m.gidmap;
            // Above every extent, or the last id when one ends there.
            var id: u64 = 0;
            for (map) |e| id = @max(id, e.inside + e.count);
            if (id > spec.id_max) {
                // One ends at the last id: below every extent, or none.
                var low: u64 = spec.id_max;
                for (map) |e| low = @min(low, e.inside);
                if (low == 0) return error.SkipZigTest;
                id = low - 1;
            }
            switch (rule) {
                .uid_unmapped => {
                    try setField(a, its.items, "user", 0, try num(a, id));
                    want = try std.fmt.allocPrint(a, "spec: user's uid {d} is in no uidmap extent", .{id});
                },
                .gid_unmapped => {
                    try setField(a, its.items, "user", 1, try num(a, id));
                    want = try std.fmt.allocPrint(a, "spec: user's gid {d} is in no gidmap extent", .{id});
                },
                else => {
                    try its.append(a, try item(a, "group", &.{try num(a, id)}));
                    want = try std.fmt.allocPrint(a, "spec: group {d} is in no gidmap extent", .{id});
                },
            }
        },
        .home_unclean => {
            const v = try std.mem.concat(a, u8, &.{ m.home, "/" });
            try setField(a, its.items, "user", 2, v);
            want = try std.fmt.allocPrint(a, "spec: user's home has an empty, '.' or '..' component: '{s}'", .{v});
        },
        .chdir_relative => {
            try its.append(a, try item(a, "chdir", &.{"w"}));
            if (m.chdir != null) {
                want = "spec: chdir given more than once";
            } else {
                want = "spec: chdir is not an absolute path: 'w'";
            }
        },
        .mount_dest_unclean => {
            try its.append(a, try item(a, "mount", &.{ "overlay", "/a/./b", "/l" }));
            want = "spec: mount overlay destination has an empty, '.' or '..' component: '/a/./b'";
        },
        .tmpfs_mode_not_octal => {
            try its.append(a, try item(a, "mount", &.{ "tmpfs", "/t", "0758", "", "root" }));
            want = "spec: mount tmpfs mode is not an octal mode: '0758'";
        },
        .tmpfs_mode_large => {
            try its.append(a, try item(a, "mount", &.{ "tmpfs", "/t", "17777", "", "root" }));
            want = "spec: mount tmpfs mode is larger than 07777: '17777'";
        },
        .tmpfs_size_bad => {
            const bad = [_][]const u8{ "1kk", "k", "1,mode=0777", " 1" };
            const v = bad[g.below(bad.len)];
            try its.append(a, try item(a, "mount", &.{ "tmpfs", "/t", "0755", v, "user" }));
            want = try std.fmt.allocPrint(a, "spec: mount tmpfs size is not a number with an optional k, m, g, t, p, e or % suffix: '{s}'", .{v});
        },
        .tmpfs_owner_bad => {
            try its.append(a, try item(a, "mount", &.{ "tmpfs", "/t", "0755", "", "nobody" }));
            want = "spec: mount tmpfs owner is neither root nor user: 'nobody'";
        },
        .exact_src_unclean => {
            try its.append(a, try item(a, "mount", &.{ "bind-rw-exact", "/w", "/home/u/w/" }));
            want = "spec: mount bind-rw-exact source has an empty, '.' or '..' component: '/home/u/w/'";
        },
        .bind_src_relative => {
            try its.append(a, try item(a, "mount", &.{ "dev", "/dev/kvm", "dev/kvm" }));
            want = "spec: mount dev source is not an absolute path: 'dev/kvm'";
        },
        .protect_relative => {
            try its.append(a, try item(a, "protect", &.{"p"}));
            want = "spec: protect is not an absolute path: 'p'";
        },
        .seccomp_relative => {
            try its.append(a, try item(a, "seccomp", &.{"f.bpf"}));
            want = "spec: seccomp is not an absolute path: 'f.bpf'";
        },
        .nested_zero => {
            if (m.nested != 0) {
                try setField(a, its.items, "nested-userns", 0, "0");
            } else {
                try its.append(a, try item(a, "nested-userns", &.{"000"}));
            }
            want = "spec: nested-userns is 0: leave it out to keep nested namespaces off";
        },
        .holder_absolute => {
            try setField(a, its.items, "holder", 0, "/flong.slice");
            want = "spec: holder is not a relative path: '/flong.slice'";
        },
        .limit_unknown => {
            try its.append(a, try item(a, "limit", &.{ "cgroup.procs", "1" }));
            want = "spec: limit 'cgroup.procs' is not one of memory.max memory.high memory.swap.max memory.oom.group pids.max cpu.max cpu.weight io.weight";
        },
        .limit_twice => {
            if (m.limits.len > 0) {
                try its.append(a, try item(a, "limit", &.{ m.limits[0].file, "1" }));
                want = try std.fmt.allocPrint(a, "spec: limit {s} given more than once", .{m.limits[0].file});
            } else {
                try its.append(a, try item(a, "limit", &.{ "pids.max", "1" }));
                try its.append(a, try item(a, "limit", &.{ "pids.max", "2" }));
                want = "spec: limit pids.max given more than once";
            }
        },
        .limit_empty => {
            // A file the model does not set, or its first set twice would
            // say that first.
            var file: []const u8 = "";
            for ([_][]const u8{ "memory.max", "memory.high", "memory.swap.max", "memory.oom.group", "pids.max", "cpu.max", "cpu.weight", "io.weight" }) |f| {
                for (m.limits) |l| {
                    if (std.mem.eql(u8, l.file, f)) break;
                } else {
                    file = f;
                    break;
                }
            }
            if (file.len == 0) return error.SkipZigTest;
            try its.append(a, try item(a, "limit", &.{ file, "" }));
            want = try std.fmt.allocPrint(a, "spec: limit {s} has an empty value", .{file});
        },
        .post_stop_outside => {
            // The first command's program, or a command after the model's:
            // each is checked.
            if (m.post_stop.len > 0 and g.r.boolean()) {
                try setField(a, its.items, "post-stop", 1, "/usr/bin/stop");
            } else {
                try its.append(a, try item(a, "post-stop", &.{ "2", "/usr/bin/stop", "x" }));
            }
            want = "spec: post-stop is not under /nix/store/: '/usr/bin/stop'";
        },
        .keep_fd_stdio => {
            try its.append(a, try item(a, "keep-fd", &.{"2"}));
            want = "spec: keep-fd 2 is stdio";
        },
        .keep_fd_twice => {
            if (m.keep_fds.len > 0) {
                try its.append(a, try item(a, "keep-fd", &.{m.keep_words[0]}));
                want = try std.fmt.allocPrint(a, "spec: keep-fd {d} given more than once", .{m.keep_fds[0]});
            } else {
                const n = try num(a, @intCast(pool[0]));
                try its.append(a, try item(a, "keep-fd", &.{n}));
                try its.append(a, try item(a, "keep-fd", &.{n}));
                want = try std.fmt.allocPrint(a, "spec: keep-fd {d} given more than once", .{pool[0]});
            }
        },
    }
    return .{ .words = try render(g, its.items, cmd), .want = want };
}

fn refusedWith(seed: u64, rule: Rule) !void {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    var prng: std.Random.DefaultPrng = .init(seed);
    const g: Gen = .{ .r = prng.random(), .a = arena_state.allocator() };
    var m = try g.model(pool);
    const mut = mutate(g, rule, &m) catch |err| switch (err) {
        error.SkipZigTest => return, // the model leaves no room for it
        else => return err,
    };
    var errbuf: [4096]u8 = undefined;
    const p = try parseWords(g.a, mut.words, &errbuf);
    const want = try std.fmt.allocPrint(g.a, "flong launch: {s}\n", .{mut.want});
    testing.expectEqualStrings(want, p.err) catch |err| {
        std.debug.print("rule {s}, seed {d}\n", .{ @tagName(rule), seed });
        return err;
    };
    try testing.expect(p.spec == null);
}

fn anyRule(seed: u64) !void {
    const rules = std.enums.values(Rule);
    try refusedWith(seed, rules[seed % rules.len]);
}

test "each single-rule mutation is refused with its message" {
    try openPool();
    for (std.enums.values(Rule)) |rule| {
        for (0..20) |i| try refusedWith(0x5bec + i, rule);
    }
}

test "property: any single-rule mutation of any model is refused with its message" {
    try openPool();
    try minish.check(testing.allocator, minish.gen.int(u64), anyRule, .{ .num_runs = 10_000, .seed = 0x5bec });
    try minish.check(testing.allocator, minish.gen.int(u64), anyRule, .{ .num_runs = 2_000 });
}
