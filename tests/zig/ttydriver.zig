//! flong-tty: src/tty.zig driven as the launcher drives it, for
//! checks.native's pty tests (DESIGN.md, "Tests": checks.native; the
//! Zig port's L3). flong-launch itself has built tty.zig in since L4.
//!
//!   flong-tty [--report] PROGRAM ARG...
//!
//! PROGRAM (an absolute path) stands in for bwrap and the payload both: it
//! is spawned with tty.stdio's 0-2, and its pidfd is bwrap's and the
//! leader's. The calls are the launcher's, in its order
//! (flong-launch.c:709-767, 785-790): the signals blocked and read from a
//! signalfd; prepare (the container "flong-tty", the caller's uid); the
//! spawn, then spawned; the gate's start, take(0) and resize
//! (flong-launch.c:686-692); wait; finish; the reap. It exits with wait's
//! status, 125 when something failed (having said why), or 128+n for a
//! terminating signal before the wait. --report says on stderr, before the
//! spawn, where the relay's output goes: `tty.out: reopened` (quirk 42's
//! reopen), `tty.out: fd 1` (its fallback) or `tty.out: passthrough`.
//!
//! A payload that should see a hang-up needs the pty as its controlling
//! terminal, which flong-init gives it in a launch: `setsid -c` does here.

const std = @import("std");
const sys = @import("sys");
const fdt = @import("fd");
const msg = @import("msg");
const sig = @import("sig");
const proc = @import("proc");
const tty = @import("tty");

pub const std_options: std.Options = .{
    .enable_segfault_handler = false,
    .keep_sigpipe = true,
};

pub const panic = std.debug.FullPanic(msg.onPanic(125));

pub fn main() noreturn {
    msg.prog = "flong-tty";
    msg.mode = .cut;
    _ = sig.block() catch proc.exit(125);
    sig.ignorePipe();
    sig.defaultChld();
    sig.openSignalfd() catch proc.exit(125);

    var args = sys.argv()[1..];
    var report = false;
    if (args.len > 0 and std.mem.eql(u8, std.mem.span(args[0]), "--report")) {
        report = true;
        args = args[1..];
    }
    if (args.len == 0 or args[0][0] != '/') {
        msg.bare("usage: flong-tty [--report] /PROGRAM ARG...", .{});
        proc.exit(2);
    }

    var t: tty.Tty = .{};
    var child: ?proc.Child = null;
    const status: u8 = run(&t, &child, args, report) catch |err| switch (err) {
        error.Reported => 125,
        error.Aborted => 128 +% sig.abort_signal,
    };
    // The teardown's order (flong-launch.c:790-799): the terminal, then
    // the reap; a payload still running is killed.
    tty.finish(&t);
    if (child) |c| c.reapNow(.kill);
    proc.exit(status);
}

fn run(t: *tty.Tty, child: *?proc.Child, args: []const [*:0]const u8, report: bool) sig.Error!u8 {
    try tty.prepare(t, "flong-tty", sys.getuid());
    if (report) msg.say("tty.out: {s}", .{if (!t.relay) "passthrough" else if (t.out != null) "reopened" else "fd 1"});

    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    const gpa = arena.allocator();
    var sp = proc.Spawn.init(gpa, args[0]) catch return msg.refuse("out of memory", .{});
    for (args[1..]) |a| sp.arg(a) catch return msg.refuse("out of memory", .{});
    sp.stdio = tty.stdio(t);
    const c = try sp.start();
    child.* = c;
    tty.spawned(t);

    // The gate (flong-launch.c:686-692): the watchdog, then raw; the
    // signals queued meanwhile; the size once more.
    try tty.start(t, c.pidfd);
    _ = try sig.take(0);
    tty.resize(t);

    return tty.wait(t, c, c.pidfd);
}
