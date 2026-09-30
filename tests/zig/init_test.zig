//! flong init's argv slots from outside (the `test` step; DESIGN.md,
//! "Conventions": allocation). flong init execs tini from the kernel's own
//! argv, so which slot holds what is its protocol with bwrap: a slot read
//! from the wrong place, or tini's words written over COMMAND, would run
//! something else as the payload. The kernel's argv is built here as
//! `flong init` gets it, and handed over from the subcommand's word as
//! src/main.zig's dispatch hands it.

const std = @import("std");
const init = @import("init");

const testing = std.testing;

const gate = "4";
const ready = "5";
const files = "6";
const groups = "100,27";
const tty = "ctty";
const trace = "-";
const dir = "/home/u/w";

test "flong init: the words are the kernel's slots 2-8, and tini's argv is slots 7 on" {
    // The kernel's argv as bwrap execs it, and its NULL.
    var kernel = [_:null]?[*:0]const u8{
        "/nix/store/x-flong-launcher-0/bin/flong", "init",
        gate,                                      ready,
        files,                                     groups,
        tty,                                       trace,
        dir,                                       "--",
        "sh",                                      "-c",
        "exec \"$@\"",
    };
    const slots: [][*:0]const u8 = @ptrCast(kernel[0..]);
    const argv = slots[1..];

    const w = init.words(argv).?;
    try testing.expectEqual(kernel[2].?, w.gate);
    try testing.expectEqual(kernel[3].?, w.ready);
    try testing.expectEqual(kernel[4].?, w.files);
    try testing.expectEqual(kernel[5].?, w.groups);
    try testing.expectEqual(kernel[6].?, w.tty);
    try testing.expectEqual(kernel[7].?, w.trace);
    try testing.expectEqual(kernel[8].?, w.dir);

    const exec_argv = init.tiniArgv(argv);
    try testing.expectEqual(@as([*]const ?[*:0]const u8, kernel[7..].ptr), @as([*]const ?[*:0]const u8, exec_argv));
    const want = [_][]const u8{ "tini", "-g", "--", "sh", "-c", "exec \"$@\"" };
    for (want, 0..) |word, i| try testing.expectEqualStrings(word, std.mem.span(exec_argv[i].?));
    try testing.expectEqual(@as(?[*:0]const u8, null), exec_argv[want.len]);
    // The words read before the rewrite are the arguments still: the
    // pointers, not the slots.
    try testing.expectEqualStrings(trace, std.mem.span(w.trace));
    try testing.expectEqualStrings(dir, std.mem.span(w.dir));
    // What bwrap's own argv and the subcommand's word left is untouched.
    try testing.expectEqualStrings("init", std.mem.span(kernel[1].?));
    try testing.expectEqualStrings(files, std.mem.span(kernel[4].?));
    try testing.expectEqualStrings(tty, std.mem.span(kernel[6].?));
}

test "flong init: the shape, counted from the subcommand's word" {
    const ok = [_][*:0]const u8{ "init", gate, ready, files, groups, tty, trace, dir, "--", "true" };
    try testing.expect(init.words(&ok) != null);
    // No command.
    try testing.expect(init.words(ok[0..9]) == null);
    // "--" one slot early or late, as it would be were the word not counted.
    const early = [_][*:0]const u8{ "init", gate, ready, files, groups, tty, trace, "--", dir, "true" };
    try testing.expect(init.words(&early) == null);
    const late = [_][*:0]const u8{ "flong", "init", gate, ready, files, groups, tty, trace, dir, "--", "true" };
    try testing.expect(init.words(&late) == null);
    // FILES left out, as before it was a word: "--" where DIR is.
    const without = [_][*:0]const u8{ "init", gate, ready, groups, tty, trace, dir, "--", "true" };
    try testing.expect(init.words(&without) == null);
}

test "flong init: FILES's fields, its modes and the paths the walk takes" {
    var f: init.Fields = .{ .data = "/home/u\x00600\x00.c/x\x00{}\x00" ++ "644\x00e\x00\x00" };
    try testing.expectEqualStrings("/home/u", f.next().?);
    try testing.expectEqualStrings("600", f.next().?);
    try testing.expectEqualStrings(".c/x", f.next().?);
    try testing.expectEqualStrings("{}", f.next().?);
    try testing.expectEqualStrings("644", f.next().?);
    try testing.expectEqualStrings("e", f.next().?);
    try testing.expect(!f.done());
    try testing.expectEqualStrings("", f.next().?);
    try testing.expect(f.done());
    try testing.expectEqual(null, f.next());
    // A last field with no NUL after it is no field.
    var cut: init.Fields = .{ .data = "/home/u\x00600" };
    _ = cut.next();
    try testing.expectEqual(null, cut.next());
    try testing.expect(!cut.done());

    try testing.expectEqual(@as(?u32, 0o600), init.octalMode("600"));
    try testing.expectEqual(@as(?u32, 0), init.octalMode("0"));
    try testing.expectEqual(@as(?u32, 0o777), init.octalMode("777"));
    for ([_][]const u8{ "", "1000", "4755", "8", "6a", "0600" }) |m| try testing.expectEqual(@as(?u32, null), init.octalMode(m));

    for ([_][]const u8{ "x", ".c/x", "a/b/c", "..x", "a/..b", "x" ** 255 }) |p| try testing.expect(init.walkable(p));
    for ([_][]const u8{ "", "/x", "x/", "a//b", ".", "..", "a/./b", "a/../b", "x" ** 256 }) |p| try testing.expect(!init.walkable(p));
}
