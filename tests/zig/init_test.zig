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
const groups = "100,27";
const tty = "ctty";
const trace = "-";
const dir = "/home/u/w";

test "flong init: the words are the kernel's slots 2-7, and tini's argv is slots 6 on" {
    // The kernel's argv as bwrap execs it, and its NULL.
    var kernel = [_:null]?[*:0]const u8{
        "/nix/store/x-flong-launcher-0/bin/flong", "init",
        gate,                                      ready,
        groups,                                    tty,
        trace,                                     dir,
        "--",                                      "sh",
        "-c",                                      "exec \"$@\"",
    };
    const slots: [][*:0]const u8 = @ptrCast(kernel[0..]);
    const argv = slots[1..];

    const w = init.words(argv).?;
    try testing.expectEqual(kernel[2].?, w.gate);
    try testing.expectEqual(kernel[3].?, w.ready);
    try testing.expectEqual(kernel[4].?, w.groups);
    try testing.expectEqual(kernel[5].?, w.tty);
    try testing.expectEqual(kernel[6].?, w.trace);
    try testing.expectEqual(kernel[7].?, w.dir);

    const exec_argv = init.tiniArgv(argv);
    try testing.expectEqual(@as([*]const ?[*:0]const u8, kernel[6..].ptr), @as([*]const ?[*:0]const u8, exec_argv));
    const want = [_][]const u8{ "tini", "-g", "--", "sh", "-c", "exec \"$@\"" };
    for (want, 0..) |word, i| try testing.expectEqualStrings(word, std.mem.span(exec_argv[i].?));
    try testing.expectEqual(@as(?[*:0]const u8, null), exec_argv[want.len]);
    // The words read before the rewrite are the arguments still: the
    // pointers, not the slots.
    try testing.expectEqualStrings(trace, std.mem.span(w.trace));
    try testing.expectEqualStrings(dir, std.mem.span(w.dir));
    // What bwrap's own argv and the subcommand's word left is untouched.
    try testing.expectEqualStrings("init", std.mem.span(kernel[1].?));
    try testing.expectEqualStrings(tty, std.mem.span(kernel[5].?));
}

test "flong init: the shape, counted from the subcommand's word" {
    const ok = [_][*:0]const u8{ "init", gate, ready, groups, tty, trace, dir, "--", "true" };
    try testing.expect(init.words(&ok) != null);
    // No command.
    try testing.expect(init.words(ok[0..8]) == null);
    // "--" one slot early or late, as it would be were the word not counted.
    const early = [_][*:0]const u8{ "init", gate, ready, groups, tty, trace, "--", dir, "true" };
    try testing.expect(init.words(&early) == null);
    const late = [_][*:0]const u8{ "flong", "init", gate, ready, groups, tty, trace, dir, "--", "true" };
    try testing.expect(init.words(&late) == null);
}
