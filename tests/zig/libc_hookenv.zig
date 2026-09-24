//! hook.env against glibc (the `test-libc` step): run_hook's four setenv
//! calls (flong-launch.c:597-599) made by glibc's own setenv on an
//! environment, and by hook.env on a copy of it, give the same entries in
//! the same order. The environments are drawn from names near the four
//! (a prefix, a suffix, another case, none at all, no '='), with repeats,
//! under a fixed seed and a random one, printed on a failure.

const std = @import("std");
const linux = std.os.linux;
const sys = @import("sys");
const fd = @import("fd");
const hook = @import("hook");
const testing = std.testing;

extern var environ: ?[*:null]?[*:0]u8;
extern fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;

const names = [_][]const u8{ "leader", "userns", "netns", "machine", "lead", "leaderx", "netns2", "Machine", "userns_", "PATH", "", "=" };
const values = [_][]const u8{ "", "x", "=y", "/proc/1/fd/3", "a b" };

fn rawOpen(path: [*:0]const u8) !i32 {
    const rc = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.E.init(rc) != .SUCCESS) return error.Open;
    return @intCast(rc);
}

fn one(arena: std.mem.Allocator, rand: std.Random, userns: fd.Fd(.userns), netns: fd.Fd(.netns)) !void {
    const n = rand.uintLessThan(usize, 9);
    const entries = try arena.alloc([*:0]const u8, n);
    for (entries) |*e| {
        const name = names[rand.uintLessThan(usize, names.len)];
        e.* = if (rand.uintLessThan(u8, 5) == 0)
            (try arena.dupeZ(u8, name)).ptr
        else
            (try std.fmt.allocPrintSentinel(arena, "{s}={s}", .{ name, values[rand.uintLessThan(usize, values.len)] }, 0)).ptr;
    }
    const leader: sys.pid_t = @intCast(rand.intRangeAtMost(i32, 1, std.math.maxInt(i32)));
    const machine = if (rand.boolean()) "m-1" else "a.b_c";
    const pid = sys.getpid();

    // glibc's, on a copy of its own: setenv copies the array before it
    // changes it, as __environ is not the array it last made.
    const copy = try arena.alloc(?[*:0]u8, n + 1);
    for (entries, 0..) |e, i| copy[i] = @constCast(e);
    copy[n] = null;
    const saved = environ;
    defer environ = saved;
    environ = @ptrCast(copy.ptr);
    const vals = [_][:0]const u8{
        try std.fmt.allocPrintSentinel(arena, "{d}", .{leader}, 0),
        try std.fmt.allocPrintSentinel(arena, "/proc/{d}/fd/{d}", .{ pid, userns.raw() }, 0),
        try std.fmt.allocPrintSentinel(arena, "/proc/{d}/fd/{d}", .{ pid, netns.raw() }, 0),
        machine,
    };
    for ([_][*:0]const u8{ "leader", "userns", "netns", "machine" }, vals) |name, v|
        try testing.expectEqual(@as(c_int, 0), setenv(name, v.ptr, 1));
    var want: std.ArrayList([]const u8) = .empty;
    var i: usize = 0;
    while (environ.?[i]) |e| : (i += 1) try want.append(arena, try arena.dupe(u8, std.mem.span(e)));

    const envp = try hook.env(arena, entries, .{ .leader = leader, .self_pid = pid, .machine = machine }, userns, netns);
    var got: std.ArrayList([]const u8) = .empty;
    i = 0;
    while (envp[i]) |e| : (i += 1) try got.append(arena, std.mem.span(e));

    testing.expectEqual(want.items.len, got.items.len) catch |err| {
        dump(entries, want.items, got.items);
        return err;
    };
    for (want.items, got.items) |w, g| testing.expectEqualStrings(w, g) catch |err| {
        dump(entries, want.items, got.items);
        return err;
    };
}

fn dump(entries: []const [*:0]const u8, want: []const []const u8, got: []const []const u8) void {
    std.debug.print("environ:", .{});
    for (entries) |e| std.debug.print(" '{s}'", .{e});
    std.debug.print("\nglibc:", .{});
    for (want) |e| std.debug.print(" '{s}'", .{e});
    std.debug.print("\nhook.env:", .{});
    for (got) |e| std.debug.print(" '{s}'", .{e});
    std.debug.print("\n", .{});
}

test "hook.env equals glibc's setenv, leader, userns, netns, machine, over 5,000 environments per seed" {
    const userns = try fd.adoptForeign(.userns, try rawOpen("/proc/self/ns/user"));
    defer userns.close();
    const netns = try fd.adoptForeign(.netns, try rawOpen("/proc/self/ns/net"));
    defer netns.close();
    var random_seed: u64 = undefined;
    std.crypto.random.bytes(std.mem.asBytes(&random_seed));
    for ([_]u64{ 0x5eed_4f10_6e71, random_seed }) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        for (0..5000) |_| {
            var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
            defer arena_state.deinit();
            one(arena_state.allocator(), prng.random(), userns, netns) catch |err| {
                std.debug.print("seed {x}\n", .{seed});
                return err;
            };
        }
    }
}
