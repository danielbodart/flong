const std = @import("std");
const linux = std.os.linux;
const fd = @import("fd.zig");
const procfds = @import("procfds.zig");
const options = @import("options");
const minish = @import("minish");
const testing = std.testing;

const probe_path = std.fmt.comptimePrint("{s}", .{options.probe});

// Any file every Linux has, the Nix build sandbox included, which has no
// /etc/hostname (spike/proofs/p1).
const test_file = "/etc/passwd";

// ---- helpers ----

/// The kernel holds exactly baseline plus the table's live handles.
fn expectKernelMatches(baseline: *const procfds.Set) !void {
    var buf: [fd.capacity]std.posix.fd_t = undefined;
    const live = fd.snapshot(&buf);
    const kernel = try procfds.read();
    var want: procfds.Set = baseline.*;
    for (live) |n| {
        want.fds[want.n] = n;
        want.n += 1;
    }
    std.mem.sort(i32, want.fds[0..want.n], {}, std.sort.asc(i32));
    try testing.expectEqualSlices(i32, want.slice(), kernel.slice());
}

/// Runs body in a forked child that keeps only keep, and returns its status.
fn inChild(keep: []const fd.AnyFd, comptime body: fn () u8) !u8 {
    if (try fd.fork(keep)) |c| {
        var child = c;
        defer child.deinit();
        return child.wait();
    }
    linux.exit_group(body());
}

// ---- bug class 1: a stale number reaching a reused descriptor ----

test "a closed handle is stale in every copy, even after its number and slot are reused" {
    const f = try fd.openFile(null, test_file, .{ .ACCMODE = .RDONLY });
    const Holder = struct { h: fd.File };
    const copy = Holder{ .h = f };
    const old_number = f.raw();
    f.close();
    try testing.expect(!copy.h.isLive());

    const g = try fd.openFile(null, test_file, .{ .ACCMODE = .RDONLY });
    defer g.close();
    // The kernel handed out the same number and the table the same slot:
    // with a bare int, copy would now silently name g's file.
    try testing.expectEqual(old_number, g.raw());
    try testing.expectEqual(f.slot, g.slot);
    try testing.expect(!copy.h.isLive());
    try testing.expect(g.isLive());
}

var stale_for_child: fd.File = undefined;

test "using a stale handle panics rather than touching the reused number" {
    stale_for_child = try fd.openFile(null, test_file, .{ .ACCMODE = .RDONLY });
    stale_for_child.close();
    const reuse = try fd.openFile(null, test_file, .{ .ACCMODE = .RDONLY });
    defer reuse.close();
    const status = try inChild(&.{reuse.any()}, struct {
        fn body() u8 {
            var b: [1]u8 = undefined;
            _ = stale_for_child.read(&b) catch return 2;
            return 1; // read through a stale handle: the bug got through
        }
    }.body);
    try testing.expectEqual(@as(u8, 128 + 6), status); // SIGABRT from the panic
}

// ---- bug class 2: a fork child holding stale numbers ----

var kept_for_child: fd.File = undefined;
var dropped_for_child: fd.Dir = undefined;
var pipe_for_child: fd.Pipe = undefined;

test "a forked helper holds only what it keeps, and every other handle is stale in it" {
    kept_for_child = try fd.openFile(null, test_file, .{ .ACCMODE = .RDONLY });
    defer kept_for_child.close();
    dropped_for_child = try fd.openDir(null, "/");
    defer dropped_for_child.close();
    pipe_for_child = try fd.pipe();
    defer pipe_for_child.r.close();
    defer pipe_for_child.w.close();

    const status = try inChild(&.{kept_for_child.any()}, struct {
        fn body() u8 {
            if (!kept_for_child.isLive()) return 1;
            if (dropped_for_child.isLive()) return 2;
            if (pipe_for_child.r.isLive() or pipe_for_child.w.isLive()) return 3;
            const k = procfds.read() catch return 4;
            for (k.slice()) |n| {
                if (n >= 3 and n != kept_for_child.raw()) return 5;
            }
            if (!k.contains(kept_for_child.raw())) return 6;
            return 0;
        }
    }.body);
    try testing.expectEqual(@as(u8, 0), status);
}

// ---- bug class 3: argv numbers and the keep set disagreeing ----

const Probe = struct { held: procfds.Set, named: procfds.Set };

fn runProbe(plan: *fd.Spawn) !Probe {
    const out = try fd.pipe();
    defer out.r.close();
    plan.stdout = out.w;
    var child = plan.start() catch |err| {
        out.w.close();
        return err;
    };
    defer child.deinit();
    out.w.close();

    var text: [1024]u8 = undefined;
    var len: usize = 0;
    while (true) {
        const n = try out.r.read(text[len..]);
        if (n == 0) break;
        len += n;
    }
    try testing.expectEqual(@as(u8, 0), try child.wait());

    var p: Probe = .{ .held = .{}, .named = .{} };
    var halves = std.mem.splitSequence(u8, std.mem.trimRight(u8, text[0..len], "\n"), " |");
    var held = std.mem.tokenizeScalar(u8, halves.next() orelse return error.Probe, ' ');
    while (held.next()) |t| {
        p.held.fds[p.held.n] = try std.fmt.parseInt(i32, t, 10);
        p.held.n += 1;
    }
    var named = std.mem.tokenizeScalar(u8, halves.next() orelse "", ' ');
    while (named.next()) |t| {
        const n = std.fmt.parseInt(i32, t, 10) catch continue; // a plain argument
        p.named.fds[p.named.n] = n;
        p.named.n += 1;
    }
    std.mem.sort(i32, p.named.fds[0..p.named.n], {}, std.sort.asc(i32));
    return p;
}

/// Descriptors >= 3 the probe held must be exactly the ones its argv named.
fn expectHeldIsNamed(p: Probe) !void {
    var above: procfds.Set = .{};
    for (p.held.slice()) |n| {
        if (n < 3) continue;
        above.fds[above.n] = n;
        above.n += 1;
    }
    try testing.expectEqualSlices(i32, p.named.slice(), above.slice());
}

test "a spawned program holds exactly the descriptors its argv names" {
    const passed = try fd.openFile(null, test_file, .{ .ACCMODE = .RDONLY });
    defer passed.close();
    const dir = try fd.openDir(null, "/");
    defer dir.close();
    const not_passed = try fd.openPath(null, "/etc");
    defer not_passed.close();

    var plan = fd.Spawn.init(probe_path);
    try plan.arg("--file");
    try plan.passFd(passed);
    try plan.arg("--dir");
    try plan.passFd(dir);
    const p = try runProbe(&plan);
    try expectHeldIsNamed(p);
    try testing.expect(!p.held.contains(not_passed.raw()));
}

// ---- the property: table, model and kernel agree after any sequence ----

const Held = union(enum) {
    file: fd.File,
    dir: fd.Dir,
    path: fd.Path,
    r: fd.PipeR,
    w: fd.PipeW,

    fn any(self: Held) fd.AnyFd {
        return switch (self) {
            inline else => |h| h.any(),
        };
    }
    fn close(self: Held) void {
        switch (self) {
            inline else => |h| h.close(),
        }
    }
    fn isLive(self: Held) bool {
        return switch (self) {
            inline else => |h| h.isLive(),
        };
    }
};

const Model = struct {
    held: [48]Held = undefined,
    nheld: usize = 0,
    dead: [256]Held = undefined,
    ndead: usize = 0,

    fn add(m: *Model, h: Held) void {
        m.held[m.nheld] = h;
        m.nheld += 1;
    }

    fn closeAt(m: *Model, i: usize) void {
        const h = m.held[i];
        // Remembered before the close, so each step can check it went stale.
        if (m.ndead < m.dead.len) {
            m.dead[m.ndead] = h;
            m.ndead += 1;
        }
        h.close();
        m.held[i] = m.held[m.nheld - 1];
        m.nheld -= 1;
    }

    /// The handles bit i of mask picks, among the first eight held.
    fn pick(m: *const Model, mask: u16, out: []fd.AnyFd) []fd.AnyFd {
        var n: usize = 0;
        for (0..@min(m.nheld, 8)) |i| {
            if (mask & (@as(u16, 1) << @intCast(i)) != 0) {
                out[n] = m.held[i].any();
                n += 1;
            }
        }
        return out[0..n];
    }
};

var prop_baseline: procfds.Set = undefined;
var prop_model: Model = .{};

fn forkChildBody() u8 {
    // In the child: the kept ones are live, every other held one is stale,
    // and the kernel holds nothing else above stderr.
    const k = procfds.read() catch return 10;
    var kept: usize = 0;
    for (prop_model.held[0..prop_model.nheld]) |h| {
        if (h.isLive()) {
            kept += 1;
            if (!k.contains(h.any().raw())) return 11;
        }
    }
    var above: usize = 0;
    for (k.slice()) |n| above += @intFromBool(n >= 3);
    return if (above == kept) 0 else 12;
}

fn step(m: *Model, op: u16) !void {
    const arg = op / 8;
    switch (op % 8) {
        0 => if (m.nheld < m.held.len) m.add(.{ .file = try fd.openFile(null, test_file, .{ .ACCMODE = .RDONLY }) }),
        1 => if (m.nheld < m.held.len) m.add(.{ .dir = try fd.openDir(null, "/") }),
        2 => if (m.nheld < m.held.len) m.add(.{ .path = try fd.openPath(null, "/etc") }),
        3 => if (m.nheld + 2 <= m.held.len) {
            const p = try fd.pipe();
            m.add(.{ .r = p.r });
            m.add(.{ .w = p.w });
        },
        4, 5 => if (m.nheld > 0) m.closeAt(arg % m.nheld),
        6 => {
            var buf: [8]fd.AnyFd = undefined;
            const keep = m.pick(arg, &buf);
            try testing.expectEqual(@as(u8, 0), try inChild(keep, forkChildBody));
        },
        7 => {
            var buf: [8]fd.AnyFd = undefined;
            const keep = m.pick(arg, &buf);
            var plan = fd.Spawn.init(probe_path);
            for (keep) |h| try plan.passFd(h);
            try expectHeldIsNamed(try runProbe(&plan));
        },
        else => unreachable,
    }
}

fn prop(ops: []const u16) !void {
    prop_model = .{};
    const m = &prop_model;
    const start = fd.liveCount();
    defer {
        while (m.nheld > 0) m.closeAt(m.nheld - 1);
        std.debug.assert(fd.liveCount() == start);
    }
    for (ops) |op| {
        try step(m, op);
        try expectKernelMatches(&prop_baseline);
        for (m.held[0..m.nheld]) |h| try testing.expect(h.isLive());
        for (m.dead[0..m.ndead]) |h| try testing.expect(!h.isLive());
    }
}

test "property: after any sequence of opens, closes, forks and spawns, table, model and kernel agree" {
    prop_baseline = try procfds.read();
    var buf: [fd.capacity]std.posix.fd_t = undefined;
    try testing.expectEqual(@as(usize, 0), fd.snapshot(&buf).len);
    try minish.check(testing.allocator, minish.gen.list(u16, minish.gen.int(u16), 0, 40), prop, .{ .num_runs = 150 });
    try expectKernelMatches(&prop_baseline);
}
