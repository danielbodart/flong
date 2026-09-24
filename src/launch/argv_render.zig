//! launch/argv_render.zig: TRANSITION ONLY (STANDALONE.md, S3, "Transition"),
//! deleted with rootless-wrapper.bash. A spec.Spec value rendered as the
//! argv spec the wrapper handed flong launch, in the old keywords'
//! spellings, for `flong launch --dump-argv`: tests/transition.nix diffs it
//! with what the wrapper builds for the same declaration and the same
//! caller-side outcomes (the wrapper's FLONG_DUMP_SPEC).
//!
//! The words, each ending in a NUL: first `resolv:` and the session's
//! resolv.conf (empty without a network), then the spec's keywords and
//! their fields, `--` and the command. Keywords come grouped by kind, not
//! in the wrapper's order across kinds, which the launcher does not read
//! either; the diff compares each keyword's fields in order. The typed
//! resolver, environment and hostname are rendered as the wrapper's
//! keep-fd and bwrap-args said them, the descriptor as `FD`, and
//! relaunch_self as `relaunch` words.

const std = @import("std");
const spec = @import("spec");
const mount = @import("mount");

const Allocator = std.mem.Allocator;

/// Every word, in `gpa`.
pub fn render(gpa: Allocator, s: *const spec.Spec) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    const W = struct {
        out: *std.ArrayList(u8),
        gpa: Allocator,
        fn w(self: @This(), word: []const u8) Allocator.Error!void {
            try self.out.appendSlice(self.gpa, word);
            try self.out.append(self.gpa, 0);
        }
        fn kw(self: @This(), k: []const u8, fields: []const []const u8) Allocator.Error!void {
            try self.w(k);
            for (fields) |f| try self.w(f);
        }
        fn n(self: @This(), v: u64) Allocator.Error![]const u8 {
            return std.fmt.allocPrint(self.gpa, "{d}", .{v});
        }
    };
    const o: W = .{ .out = &out, .gpa = gpa };

    try o.w(try std.fmt.allocPrint(gpa, "resolv:{s}", .{s.resolv_conf orelse ""}));
    try o.kw("machine", &.{s.machine});
    try o.kw("container", &.{s.container});
    try o.kw("state", &.{s.state});
    try o.kw("cache", &.{s.cache});
    try o.kw("closure", &.{s.closure});
    for (s.relaunch) |r| try o.kw("relaunch", &.{r});
    if (s.relaunch_self) |argv| for (argv) |r| try o.kw("relaunch", &.{std.mem.span(r)});
    for (s.uidmap) |e| try o.kw("uidmap", &.{ try o.n(e.inside), try o.n(e.outside), try o.n(e.count) });
    for (s.gidmap) |e| try o.kw("gidmap", &.{ try o.n(e.inside), try o.n(e.outside), try o.n(e.count) });
    try o.kw("user", &.{ try o.n(s.uid), try o.n(s.gid), s.home });
    for (s.groups) |g| try o.kw("group", &.{try o.n(g)});
    try o.kw("chdir", &.{s.chdir});
    for (s.mounts) |m| {
        const kind: []const u8 = switch (m.kind) {
            .bind_ro => "bind-ro",
            .bind_rw => "bind-rw",
            .bind_ro_exact => "bind-ro-exact",
            .bind_rw_exact => "bind-rw-exact",
            .dev => "dev",
            .tmpfs => "tmpfs",
            .overlay => "overlay",
            .mask => "mask",
        };
        switch (m.kind) {
            .tmpfs => try o.kw("mount", &.{ kind, m.dest, m.mode orelse "", m.size orelse "", if (m.owner_user) "user" else "root" }),
            .mask => try o.kw("mount", &.{ kind, m.dest }),
            else => try o.kw("mount", &.{ kind, m.dest, m.src orelse "" }),
        }
    }
    for (s.protect) |p| try o.kw("protect", &.{p});
    for (s.seccomp) |p| try o.kw("seccomp", &.{p});
    if (s.nested_userns > 0) try o.kw("nested-userns", &.{try o.n(s.nested_userns)});
    try o.kw("holder", &.{s.holder});
    for (s.holder_start) |h| try o.kw("holder-start", &.{h});
    for (s.limits) |l| try o.kw("limit", &.{ l.file, l.value });
    for (s.post_start) |c| {
        try o.kw("post-start", &.{try o.n(c.len)});
        for (c) |x| try o.w(x);
    }
    for (s.post_stop) |c| {
        try o.kw("post-stop", &.{try o.n(c.len)});
        for (c) |x| try o.w(x);
    }
    if (s.network) try o.w("network");
    for (s.pasta_args) |a| try o.kw("pasta-arg", &.{a});
    if (s.pasta_wait) try o.w("pasta-wait");
    if (s.resolv_conf != null) {
        try o.kw("keep-fd", &.{"FD"});
        for ([_][]const u8{ "--perms", "0644", "--ro-bind-data", "FD", "/etc/resolv.conf" }) |a| try o.kw("bwrap-arg", &.{a});
    }
    if (s.env) |env| {
        try o.kw("bwrap-arg", &.{"--clearenv"});
        for (env) |v| {
            try o.kw("bwrap-arg", &.{"--setenv"});
            try o.kw("bwrap-arg", &.{v.name});
            try o.kw("bwrap-arg", &.{v.value});
        }
    }
    if (s.hostname) |h| {
        try o.kw("bwrap-arg", &.{"--hostname"});
        try o.kw("bwrap-arg", &.{h});
    }
    for (s.bwrap_args) |a| try o.kw("bwrap-arg", &.{a});
    for (s.keep_fds) |k| try o.kw("keep-fd", &.{try o.n(@intCast(k))});
    if (s.trace) try o.w("trace");
    try o.w("--");
    for (s.command) |c| try o.w(std.mem.span(c));
    return out.items;
}

// ---- tests ----

const testing = std.testing;

test "render: the old keywords, NUL-separated, the resolver first" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const argv = [_][*:0]const u8{ "agent", "x" };
    const s: spec.Spec = .{
        .machine = "agent-1-2",
        .container = "agent",
        .state = "/run/user/1000/flong",
        .cache = "/c",
        .relaunch_self = &argv,
        .closure = "/nix/store/x",
        .uidmap = &.{.{ .inside = 0, .outside = 100000, .count = 65536 }},
        .gidmap = &.{.{ .inside = 0, .outside = 100000, .count = 65536 }},
        .uid = 1000,
        .gid = 100,
        .home = "/home/a",
        .mounts = &.{ .{ .kind = .tmpfs, .dest = "/t", .mode = "0700", .owner_user = true }, .{ .kind = .mask, .dest = "/m" } },
        .holder = "h",
        .network = true,
        .env = &.{.{ .name = "HOME", .value = "/home/a" }},
        .hostname = "agent",
        .resolv_conf = "nameserver 169.254.1.1\n",
        .command = &.{ "/p", "/w" },
    };
    const got = try render(a, &s);
    const want = "resolv:nameserver 169.254.1.1\n\x00machine\x00agent-1-2\x00container\x00agent\x00state\x00/run/user/1000/flong\x00" ++
        "cache\x00/c\x00closure\x00/nix/store/x\x00relaunch\x00agent\x00relaunch\x00x\x00" ++
        "uidmap\x000\x00100000\x0065536\x00gidmap\x000\x00100000\x0065536\x00user\x001000\x00100\x00/home/a\x00chdir\x00/\x00" ++
        "mount\x00tmpfs\x00/t\x000700\x00\x00user\x00mount\x00mask\x00/m\x00holder\x00h\x00network\x00" ++
        "keep-fd\x00FD\x00bwrap-arg\x00--perms\x00bwrap-arg\x000644\x00bwrap-arg\x00--ro-bind-data\x00bwrap-arg\x00FD\x00bwrap-arg\x00/etc/resolv.conf\x00" ++
        "bwrap-arg\x00--clearenv\x00bwrap-arg\x00--setenv\x00bwrap-arg\x00HOME\x00bwrap-arg\x00/home/a\x00" ++
        "bwrap-arg\x00--hostname\x00bwrap-arg\x00agent\x00--\x00/p\x00/w\x00";
    try testing.expectEqualStrings(want, got);
}
