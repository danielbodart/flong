//! tests/golden/paths.txt against the launcher's functions (DESIGN.md,
//! "Tests": mirrors of the spec in Nix): each case's verdict is what spec.clean,
//! mount.overlaps or the mount helper's duplicate refusal says, whatever
//! module.nix says of it (module.nix asserts its own side against the same
//! file). Built and run by tests/integration.nix's spec-paths, the only
//! derivation whose sources hold both this and tests/golden/.

const std = @import("std");
const linux = std.os.linux;
const mount = @import("mount");
const spec = @import("spec");
const testing = std.testing;

const cases = @embedFile("paths.txt");

/// mount.sortRefusingTwice's element, which mount.zig does not name.
const Src = @typeInfo(@typeInfo(@TypeOf(mount.sortRefusingTwice)).@"fn".params[0].type.?).pointer.child;

/// Runs `f` with stderr on /dev/null: a refusal says why, and here only
/// the verdict counts.
fn quietly(comptime f: anytype, args: anytype) bool {
    const devnull = linux.open("/dev/null", .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
    const saved = linux.fcntl(2, 1030, 10); // F_DUPFD_CLOEXEC
    _ = linux.dup2(@intCast(devnull), 2);
    const ok = if (@call(.auto, f, args)) |_| true else |_| false;
    _ = linux.dup2(@intCast(saved), 2);
    _ = linux.close(@intCast(saved));
    _ = linux.close(@intCast(devnull));
    return ok;
}

/// Any failure is the duplicate refusal: sortRefusingTwice does no I/O and
/// fails only by refusing a destination mounted twice (src/mount.zig:577-583).
fn twice(a: [:0]const u8, b: [:0]const u8) bool {
    const ms = [_]mount.Mount{ .{ .kind = .mask, .dest = a }, .{ .kind = .mask, .dest = b } };
    var srcs = [_]Src{ .{ .m = &ms[0] }, .{ .m = &ms[1] } };
    return !quietly(mount.sortRefusingTwice, .{&srcs});
}

test "the launcher's verdict on every case of tests/golden/paths.txt" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var n: usize = 0;
    var differs: usize = 0;
    var lines = std.mem.splitScalar(u8, cases, '\n');
    var line_no: usize = 0;
    while (lines.next()) |line| {
        line_no += 1;
        if (line.len == 0 or line[0] == '#') continue;
        var fields: std.ArrayList([:0]const u8) = .empty;
        var it = std.mem.splitScalar(u8, line, '\t');
        while (it.next()) |f| try fields.append(arena, try arena.dupeZ(u8, f));
        const f = fields.items;
        if (f.len < 4) return error.MalformedCase;
        const want = if (std.mem.eql(u8, f[1], "yes")) true else if (std.mem.eql(u8, f[1], "no")) false else return error.MalformedCase;
        if (!std.mem.eql(u8, f[2], "same") and !std.mem.eql(u8, f[2], "differs")) return error.MalformedCase;
        const got = if (std.mem.eql(u8, f[0], "clean") and f.len == 4)
            quietly(spec.clean, .{ "path", f[3], spec.Rooted.absolute })
        else if (std.mem.eql(u8, f[0], "overlaps") and f.len == 5)
            mount.overlaps(f[3], f[4])
        else if (std.mem.eql(u8, f[0], "twice") and f.len == 5)
            twice(f[3], f[4])
        else
            return error.MalformedCase;
        if (got != want) {
            std.debug.print("paths.txt:{d}: {s} says {s}, the launcher {s}\n", .{ line_no, f[0], f[1], if (got) "yes" else "no" });
            return error.TestUnexpectedResult;
        }
        n += 1;
        differs += @intFromBool(std.mem.eql(u8, f[2], "differs"));
    }
    // Controls: the file was read, and it holds each check and a difference.
    try testing.expect(n >= 40);
    try testing.expect(differs > 0);
    try testing.expect(std.mem.indexOf(u8, cases, "\ntwice\t") != null);
    std.debug.print("paths.txt: {d} cases, {d} meant to differ in module.nix\n", .{ n, differs });
}
