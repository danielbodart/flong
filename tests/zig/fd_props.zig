//! fd.zig from outside (minish, the `test` step; DESIGN.md, "Tests"): the
//! spike's model property, that after any sequence of opens and closes the
//! table, a model of it and the kernel's /proc/self/fd agree, every closed
//! handle stale and every open one live; a stale or wrong-kind handle
//! panicking in a child rather than reaching a descriptor; and TableFull at
//! the table's capacity, leaving nothing open behind it. fork is proc.zig's
//! (phase 5), so the children here are raw forks.

const std = @import("std");
const linux = std.os.linux;
const minish = @import("minish");
const sys = @import("sys");
const fd = @import("fd");
const testing = std.testing;

// Any file every Linux has, the Nix build sandbox included, which has no
// /etc/hostname (found in the port's phase 0).
const test_file = "/etc/passwd";

// ---- the kernel's view ----

/// The descriptors /proc/self/fd lists, sorted, without the one used to
/// read it: raw calls, outside the table.
const KernelFds = struct {
    fds: [2048]i32 = undefined,
    n: usize = 0,

    fn slice(self: *const KernelFds) []const i32 {
        return self.fds[0..self.n];
    }

    fn read() !KernelFds {
        const rc = linux.open("/proc/self/fd", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
        if (linux.E.init(rc) != .SUCCESS) return error.ProcFd;
        const dir: i32 = @intCast(rc);
        defer _ = linux.close(dir);
        var k: KernelFds = .{};
        var buf: [4096]u8 align(8) = undefined;
        while (true) {
            const got = linux.getdents64(dir, &buf, buf.len);
            if (linux.E.init(got) != .SUCCESS) return error.ProcFd;
            if (got == 0) break;
            var it: fd.Entries = .{ .buf = buf[0..got] };
            while (it.next()) |e| {
                const n = std.fmt.parseInt(i32, e.name, 10) catch continue;
                if (n == dir) continue;
                k.fds[k.n] = n;
                k.n += 1;
            }
        }
        std.mem.sort(i32, k.fds[0..k.n], {}, std.sort.asc(i32));
        return k;
    }
};

/// The kernel holds exactly `baseline` and the table's live handles.
fn expectKernelMatches(baseline: *const KernelFds) !void {
    var buf: [fd.capacity]sys.fd_t = undefined;
    const live = fd.snapshot(&buf);
    var want: KernelFds = baseline.*;
    for (live) |n| {
        want.fds[want.n] = n;
        want.n += 1;
    }
    std.mem.sort(i32, want.fds[0..want.n], {}, std.sort.asc(i32));
    const kernel = try KernelFds.read();
    try testing.expectEqualSlices(i32, want.slice(), kernel.slice());
}

fn opened(r: anytype) !@FieldType(@typeInfo(@TypeOf(r)).error_union.payload, "ok") {
    return switch (try r) {
        .ok => |h| h,
        .err => error.TestUnexpectedResult,
    };
}

// ---- the property ----

const Held = union(enum) {
    file: fd.File,
    dir: fd.Dir,

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
    fn any(self: Held) fd.AnyFd {
        return switch (self) {
            inline else => |h| h.any(),
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
        // Remembered before the close, so each step checks it went stale.
        if (m.ndead < m.dead.len) {
            m.dead[m.ndead] = h;
            m.ndead += 1;
        }
        h.close();
        m.held[i] = m.held[m.nheld - 1];
        m.nheld -= 1;
    }

    /// The first directory held, if any.
    fn aDir(m: *const Model) ?fd.Dir {
        for (m.held[0..m.nheld]) |h| switch (h) {
            .dir => |d| return d,
            .file => {},
        };
        return null;
    }
};

var prop_baseline: KernelFds = undefined;
var prop_model: Model = .{};

fn step(m: *Model, op: u16) !void {
    const arg = op / 8;
    switch (op % 8) {
        0, 1 => if (m.nheld < m.held.len) m.add(.{ .file = try opened(fd.openFile(fd.cwd, test_file, .{}, 0)) }),
        2 => if (m.nheld < m.held.len) m.add(.{ .dir = try opened(fd.openDir(fd.cwd, "/")) }),
        // An open relative to a held directory, as project opens its temp
        // file under DIR.
        3 => if (m.nheld < m.held.len) {
            if (m.aDir()) |d| m.add(.{ .file = try opened(fd.openFile(d, "etc/passwd", .{}, 0)) });
        },
        // A failing open changes nothing.
        4 => try testing.expect((try fd.openFile(fd.cwd, "/nonexistent", .{}, 0)) == .err),
        5, 6, 7 => if (m.nheld > 0) m.closeAt(arg % m.nheld),
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
        try testing.expectEqual(start + m.nheld, fd.liveCount());
        for (m.held[0..m.nheld]) |h| try testing.expect(h.isLive());
        for (m.dead[0..m.ndead]) |h| {
            try testing.expect(!h.isLive());
            try testing.expect(!h.any().isLive());
        }
    }
}

test "property: after any sequence of opens and closes, table, model and kernel agree" {
    prop_baseline = try KernelFds.read();
    try testing.expectEqual(@as(usize, 0), fd.liveCount());
    try minish.check(testing.allocator, minish.gen.list(u16, minish.gen.int(u16), 0, 40), prop, .{ .num_runs = 300 });
    try expectKernelMatches(&prop_baseline);
}

// ---- stale and wrong-kind handles, in a child ----

/// Runs `body` in a forked child with stderr on a pipe; returns the signal
/// that ended it (0 for an exit) and what it said.
fn inChild(comptime body: fn () void, said: *[512]u8) !struct { signal: u32, text: []const u8 } {
    var p: [2]i32 = undefined;
    if (linux.E.init(linux.pipe2(&p, .{ .CLOEXEC = true })) != .SUCCESS) return error.Pipe;
    const pid: i32 = @intCast(@as(isize, @bitCast(linux.fork())));
    if (pid < 0) return error.Fork;
    if (pid == 0) {
        _ = linux.dup2(p[1], 2);
        body();
        linux.exit_group(0);
    }
    _ = linux.close(p[1]);
    var n: usize = 0;
    while (n < said.len) {
        const got = linux.read(p[0], said[n..].ptr, said.len - n);
        if (linux.E.init(got) != .SUCCESS or got == 0) break;
        n += got;
    }
    _ = linux.close(p[0]);
    var status: u32 = 0;
    _ = linux.waitpid(pid, &status, 0);
    return .{ .signal = if (linux.W.IFSIGNALED(status)) linux.W.TERMSIG(status) else 0, .text = said[0..n] };
}

var stale: fd.File = undefined;
var reused: fd.File = undefined;

test "a stale handle panics rather than touching the file that reused its number" {
    stale = try opened(fd.openFile(fd.cwd, test_file, .{}, 0));
    stale.close();
    reused = try opened(fd.openFile(fd.cwd, test_file, .{}, 0));
    defer reused.close();
    // The same number and the same slot: only the generation tells them
    // apart.
    try testing.expectEqual(stale.slot, reused.slot);
    var said: [512]u8 = undefined;
    const got = try inChild(struct {
        fn body() void {
            var b: [1]u8 = undefined;
            _ = stale.read(&b); // must not return
        }
    }.body, &said);
    try testing.expectEqual(@as(u32, linux.SIG.ABRT), got.signal);
    try testing.expect(std.mem.indexOf(u8, got.text, "stale descriptor handle") != null);
}

var of_a_kind: fd.File = undefined;

test "a handle of the wrong kind panics" {
    of_a_kind = try opened(fd.openFile(fd.cwd, test_file, .{}, 0));
    defer of_a_kind.close();
    var said: [512]u8 = undefined;
    const got = try inChild(struct {
        fn body() void {
            // Forged: only a test can name a handle's fields.
            const forged: fd.AnyFd = .{ .slot = of_a_kind.slot, .gen = of_a_kind.gen, .kind = .dir };
            _ = forged.raw();
        }
    }.body, &said);
    try testing.expectEqual(@as(u32, linux.SIG.ABRT), got.signal);
    try testing.expect(std.mem.indexOf(u8, got.text, "descriptor handle of the wrong kind") != null);
}

test "the control: a live handle's child exits normally" {
    of_a_kind = try opened(fd.openFile(fd.cwd, test_file, .{}, 0));
    defer of_a_kind.close();
    var said: [512]u8 = undefined;
    const got = try inChild(struct {
        fn body() void {
            var b: [1]u8 = undefined;
            _ = of_a_kind.read(&b);
        }
    }.body, &said);
    try testing.expectEqual(@as(u32, 0), got.signal);
    try testing.expectEqualStrings("", got.text);
}

// ---- TableFull ----

test "TableFull at the capacity, the descriptor the kernel gave closed" {
    // Room for the table and the baseline under RLIMIT_NOFILE; a hard limit
    // below that cannot test it.
    var lim: linux.rlimit = undefined;
    _ = linux.getrlimit(.NOFILE, &lim);
    const want = fd.capacity + 64;
    if (lim.max < want) return error.SkipZigTest;
    const old = lim;
    if (lim.cur < want) {
        lim.cur = want;
        _ = linux.setrlimit(.NOFILE, &lim);
    }
    defer _ = linux.setrlimit(.NOFILE, &old);

    // Nothing open, so the baseline is the kernel's alone.
    const start = fd.liveCount();
    try testing.expectEqual(@as(usize, 0), start);
    const baseline = try KernelFds.read();
    var all: [fd.capacity]fd.File = undefined;
    var n: usize = 0;
    while (true) {
        const r = fd.openFile(fd.cwd, test_file, .{}, 0) catch |err| {
            try testing.expectEqual(error.TableFull, err);
            break;
        };
        all[n] = switch (r) {
            .ok => |f| f,
            .err => return error.TestUnexpectedResult,
        };
        n += 1;
    }
    try testing.expectEqual(fd.capacity - start, n);
    try testing.expectEqual(@as(usize, fd.capacity), fd.liveCount());
    try expectKernelMatches(&baseline);
    for (all[0..n]) |f| f.close();
    try testing.expectEqual(start, fd.liveCount());
    try expectKernelMatches(&baseline);
}
