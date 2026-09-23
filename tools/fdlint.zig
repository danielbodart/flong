//! fdlint: the rules the compiler and zwanzig cannot express (ZIG.md, "Lint
//! and analysis"), over Zig's own tokens, so comments and strings never
//! match and an alias is caught where it is made.
//!
//!   fdlint [--skip DIR]... [--as LABEL FILE]... PATH...
//!
//! Each PATH is a file or a directory walked for .zig files, named relative
//! to the working directory (the package root): the rules go by that name.
//! `--as` lints FILE under LABEL's name, as the lint's own check does with
//! tests/zig/lint/. `--skip` leaves a directory out of the walk. Prints
//! "NAME:LINE:COL: RULE: why" per finding and exits 1 when there is any.
//!
//! The rules, each with the files it does not apply to. "tests" is every
//! file under tests/, test code needing raw access to check flong from
//! outside; the syscall layer is src/sys.zig, fd.zig, proc.zig and sig.zig.
//!
//!   raw-namespace  std.os, std.fs, std.c, std.posix, std.process: the raw
//!                  calls, and std.process.exit, which skips the teardown.
//!                  Only after `std.`, so callconv(.c) and builtin.os pass.
//!                  Not in the syscall layer, src/fixtures/, tests
//!   posix          .posix anywhere, which makes real errnos unreachable
//!                  (ZIG.md, "The syscall layer"). Not in tests
//!   extern         extern fn, var or const, extern "lib", @extern, export,
//!                  @cImport; extern struct, union and enum pass. Not in
//!                  src/seccomp/scmp.zig, src/hybrid/mount_c.zig,
//!                  tests/zig/abi.zig, tests/zig/libc_*.zig
//!   raw-number     .raw, a descriptor's number. Not in the syscall layer,
//!                  src/seccomp/scmp.zig, tests
//!   argv           sys.argv, sys.argvSlots, sys.environ. Not in the roots
//!                  (src/seccomp/main.zig, init.zig, sweeper.zig,
//!                  launch.zig), src/proc.zig (Spawn's default envp), tests
//!   handle-guts    .slot, .gen: a handle's fields. Not in src/fd.zig, tests
//!   adopt-foreign  .adoptForeign. Not in src/hybrid/mount_c.zig, tests
//!   debug-output   debug.print, std.log: messages go through msg.zig. Not
//!                  in tests
//!   catch-unreachable
//!                  catch unreachable, unless its line says `// proven: `
//!                  and why. Not in tests
//!   alloc          GeneralPurposeAllocator, DebugAllocator. Not in tests

const std = @import("std");
const Tag = std.zig.Token.Tag;

const syscall_layer = [_][]const u8{ "src/sys.zig", "src/fd.zig", "src/proc.zig", "src/sig.zig" };
const roots = [_][]const u8{ "src/seccomp/main.zig", "src/init.zig", "src/sweeper.zig", "src/launch.zig" };

const Rule = enum {
    @"raw-namespace",
    posix,
    @"extern",
    @"raw-number",
    argv,
    @"handle-guts",
    @"adopt-foreign",
    @"debug-output",
    @"catch-unreachable",
    alloc,

    fn why(r: Rule) []const u8 {
        return switch (r) {
            .@"raw-namespace" => "raw calls belong in the syscall layer (sys.zig)",
            .posix => "std.posix makes real errnos unreachable; use sys.zig",
            .@"extern" => "a C symbol belongs in scmp.zig or mount_c.zig",
            .@"raw-number" => "a descriptor's number leaves the table only through passFd, selfPath, pidPath or setFd",
            .argv => "argv and environ are read by the roots and proc.zig only",
            .@"handle-guts" => "a handle's fields are fd.zig's",
            .@"adopt-foreign" => "adoptForeign is for the mount-helper shim only",
            .@"debug-output" => "messages go through msg.zig, one write each",
            .@"catch-unreachable" => "say why it cannot happen: `// proven: <why>` on the line",
            .alloc => "no general-purpose allocator in flong's programs",
        };
    }
};

fn in(name: []const u8, list: []const []const u8) bool {
    for (list) |x| {
        if (std.mem.eql(u8, x, name)) return true;
    }
    return false;
}

/// Whether `rule` applies to the file named `name`.
fn applies(rule: Rule, name: []const u8) bool {
    if (std.mem.startsWith(u8, name, "tests/")) {
        if (rule != .@"extern") return false;
        const base = std.fs.path.basename(name);
        return !(std.mem.eql(u8, name, "tests/zig/abi.zig") or
            (std.mem.eql(u8, std.fs.path.dirname(name) orelse "", "tests/zig") and
                std.mem.startsWith(u8, base, "libc_")));
    }
    return switch (rule) {
        .@"raw-namespace" => !in(name, &syscall_layer) and !std.mem.startsWith(u8, name, "src/fixtures/"),
        .posix => true,
        .@"extern" => !in(name, &.{ "src/seccomp/scmp.zig", "src/hybrid/mount_c.zig" }),
        .@"raw-number" => !in(name, &syscall_layer) and !std.mem.eql(u8, name, "src/seccomp/scmp.zig"),
        .argv => !in(name, &roots) and !std.mem.eql(u8, name, "src/proc.zig"),
        .@"handle-guts" => !std.mem.eql(u8, name, "src/fd.zig"),
        .@"adopt-foreign" => !std.mem.eql(u8, name, "src/hybrid/mount_c.zig"),
        .@"debug-output", .@"catch-unreachable", .alloc => true,
    };
}

pub fn main() !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const args = try std.process.argsAlloc(a);

    const File = struct { name: []const u8, path: []const u8 };
    var files: std.ArrayList(File) = .empty;
    var skips: std.ArrayList([]const u8) = .empty;
    var paths: std.ArrayList([]const u8) = .empty;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--skip") and i + 1 < args.len) {
            i += 1;
            try skips.append(a, std.mem.trimRight(u8, args[i], "/"));
        } else if (std.mem.eql(u8, args[i], "--as") and i + 2 < args.len) {
            try files.append(a, .{ .name = args[i + 1], .path = args[i + 2] });
            i += 2;
        } else try paths.append(a, std.mem.trimRight(u8, args[i], "/"));
    }
    for (paths.items) |p| {
        const st = try std.fs.cwd().statFile(p);
        if (st.kind != .directory) {
            try files.append(a, .{ .name = p, .path = p });
            continue;
        }
        var dir = try std.fs.cwd().openDir(p, .{ .iterate = true });
        defer dir.close();
        var walk = try dir.walk(a);
        defer walk.deinit();
        var found: std.ArrayList([]const u8) = .empty;
        while (try walk.next()) |e| {
            if (e.kind != .file or !std.mem.endsWith(u8, e.path, ".zig")) continue;
            const name = try std.fs.path.join(a, &.{ p, e.path });
            const skipped = for (skips.items) |s| {
                if (std.mem.startsWith(u8, name, s) and name.len > s.len and name[s.len] == '/') break true;
            } else false;
            if (!skipped) try found.append(a, name);
        }
        std.mem.sort([]const u8, found.items, {}, struct {
            fn lt(_: void, x: []const u8, y: []const u8) bool {
                return std.mem.order(u8, x, y) == .lt;
            }
        }.lt);
        for (found.items) |name| try files.append(a, .{ .name = name, .path = name });
    }

    var out_buf: [4096]u8 = undefined;
    var w = std.fs.File.stdout().writer(&out_buf);
    const out = &w.interface;
    var findings: usize = 0;
    for (files.items) |f| {
        const src = try std.fs.cwd().readFileAllocOptions(a, f.path, 16 << 20, null, .of(u8), 0);
        findings += try lint(a, out, f.name, src);
    }
    try out.flush();
    if (findings > 0) std.process.exit(1);
}

const Tok = struct { tag: Tag, start: usize, text: []const u8 };

fn lint(a: std.mem.Allocator, out: *std.Io.Writer, name: []const u8, src: [:0]const u8) !usize {
    var toks: std.ArrayList(Tok) = .empty;
    var t = std.zig.Tokenizer.init(src);
    while (true) {
        const tok = t.next();
        if (tok.tag == .eof) break;
        try toks.append(a, .{ .tag = tok.tag, .start = tok.loc.start, .text = src[tok.loc.start..tok.loc.end] });
    }
    const ts = toks.items;

    var found: usize = 0;
    for (ts, 0..) |tok, k| {
        const prev: ?Tok = if (k >= 1) ts[k - 1] else null;
        const prev2: ?Tok = if (k >= 2) ts[k - 2] else null;
        const next: ?Tok = if (k + 1 < ts.len) ts[k + 1] else null;
        const after_period = prev != null and prev.?.tag == .period;
        const after_std = after_period and prev2 != null and prev2.?.tag == .identifier and
            std.mem.eql(u8, prev2.?.text, "std");
        const after = struct {
            fn is(p2: ?Tok, word: []const u8) bool {
                return p2 != null and p2.?.tag == .identifier and std.mem.eql(u8, p2.?.text, word);
            }
        };

        var rules: [2]?Rule = .{ null, null };
        switch (tok.tag) {
            .identifier => {
                const x = tok.text;
                if (after_std and in(x, &.{ "os", "fs", "c", "posix", "process" })) rules[0] = .@"raw-namespace";
                if (after_period and std.mem.eql(u8, x, "posix")) rules[1] = .posix;
                if (after_period and std.mem.eql(u8, x, "raw")) rules[0] = .@"raw-number";
                if (after_period and after.is(prev2, "sys") and in(x, &.{ "argv", "argvSlots", "environ" })) rules[0] = .argv;
                if (after_period and in(x, &.{ "slot", "gen" })) rules[0] = .@"handle-guts";
                if (after_period and std.mem.eql(u8, x, "adoptForeign")) rules[0] = .@"adopt-foreign";
                if (after_period and after.is(prev2, "debug") and std.mem.eql(u8, x, "print")) rules[0] = .@"debug-output";
                if (after_std and std.mem.eql(u8, x, "log")) rules[0] = .@"debug-output";
                if (in(x, &.{ "GeneralPurposeAllocator", "DebugAllocator" })) rules[0] = .alloc;
            },
            .keyword_extern => {
                const typed = next != null and switch (next.?.tag) {
                    .keyword_struct, .keyword_union, .keyword_enum => true,
                    else => false,
                };
                if (!typed) rules[0] = .@"extern";
            },
            .keyword_export => rules[0] = .@"extern",
            .builtin => if (in(tok.text, &.{ "@extern", "@cImport" })) {
                rules[0] = .@"extern";
            },
            .keyword_unreachable => if (prev != null and prev.?.tag == .keyword_catch) {
                const line_end = std.mem.indexOfScalarPos(u8, src, tok.start, '\n') orelse src.len;
                if (std.mem.indexOf(u8, src[tok.start..line_end], "// proven: ") == null)
                    rules[0] = .@"catch-unreachable";
            },
            else => {},
        }
        for (rules) |maybe| {
            const r = maybe orelse continue;
            if (!applies(r, name)) continue;
            try report(out, name, src, tok.start, r);
            found += 1;
        }
    }
    return found;
}

fn report(out: *std.Io.Writer, name: []const u8, src: []const u8, at: usize, rule: Rule) !void {
    const line = std.mem.count(u8, src[0..at], "\n") + 1;
    const col = at - (if (std.mem.lastIndexOfScalar(u8, src[0..at], '\n')) |n| n + 1 else 0) + 1;
    try out.print("{s}:{d}:{d}: {s}: {s}\n", .{ name, line, col, @tagName(rule), rule.why() });
}
