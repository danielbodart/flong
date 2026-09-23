//! fdlint: the rules zwanzig cannot express, over Zig tokens (so comments
//! and strings never match).
//!
//!   fdlint [--allow FILE]... FILE...
//!
//! Outside the allowed files (the syscall layer: fd.zig and its peers):
//!   raw-namespace  `.posix`, `.os`, `.fs` or `.c` after a period: every raw
//!                  descriptor call lives in std.posix, std.os.linux, std.fs
//!                  or libc, and naming the namespace is the only way in, so
//!                  an alias (`const P = std.posix`) is caught where it is made
//!   cimport        `@cImport`, the other way to reach libc
//!   handle-guts    `.slot` or `.gen`: a handle's fields are the table's
//!
//! Exits 1 when anything is found.

const std = @import("std");

const Rule = struct { name: []const u8, after_period: []const []const u8, why: []const u8 };

const rules = [_]Rule{
    .{ .name = "raw-namespace", .after_period = &.{ "posix", "os", "fs", "c" }, .why = "raw descriptor APIs belong in the syscall layer; use fd.zig" },
    .{ .name = "handle-guts", .after_period = &.{ "slot", "gen" }, .why = "a handle's fields are fd.zig's; use raw(), isLive() or any()" },
};

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const a = gpa.allocator();
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);

    var allowed: std.ArrayList([]const u8) = .empty;
    defer allowed.deinit(a);
    var files: std.ArrayList([]const u8) = .empty;
    defer files.deinit(a);
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--allow") and i + 1 < args.len) {
            i += 1;
            try allowed.append(a, std.fs.path.basename(args[i]));
        } else try files.append(a, args[i]);
    }

    var out_buf: [4096]u8 = undefined;
    var w = std.fs.File.stdout().writer(&out_buf);
    const out = &w.interface;
    var found: usize = 0;
    for (files.items) |path| {
        const base = std.fs.path.basename(path);
        if (for (allowed.items) |x| {
            if (std.mem.eql(u8, x, base)) break true;
        } else false) continue;
        const src = try std.fs.cwd().readFileAllocOptions(a, path, 16 << 20, null, .of(u8), 0);
        defer a.free(src);
        found += try lint(out, path, src);
    }
    try out.flush();
    if (found > 0) std.process.exit(1);
}

fn lint(out: *std.Io.Writer, path: []const u8, src: [:0]const u8) !usize {
    var found: usize = 0;
    var t = std.zig.Tokenizer.init(src);
    var prev: std.zig.Token.Tag = .invalid;
    while (true) {
        const tok = t.next();
        if (tok.tag == .eof) break;
        defer prev = tok.tag;
        const text = src[tok.loc.start..tok.loc.end];
        if (tok.tag == .builtin and std.mem.eql(u8, text, "@cImport")) {
            try report(out, path, src, tok.loc.start, "cimport", "libc belongs in the syscall layer");
            found += 1;
            continue;
        }
        if (tok.tag != .identifier or prev != .period) continue;
        for (rules) |r| {
            for (r.after_period) |name| {
                if (std.mem.eql(u8, text, name)) {
                    try report(out, path, src, tok.loc.start, r.name, r.why);
                    found += 1;
                }
            }
        }
    }
    return found;
}

fn report(out: *std.Io.Writer, path: []const u8, src: []const u8, at: usize, rule: []const u8, why: []const u8) !void {
    const line = std.mem.count(u8, src[0..at], "\n") + 1;
    const col = at - (if (std.mem.lastIndexOfScalar(u8, src[0..at], '\n')) |n| n + 1 else 0) + 1;
    try out.print("{s}:{d}:{d}: {s}: {s}\n", .{ path, line, col, rule, why });
}
