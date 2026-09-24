//! flong-launch's root (ZIG.md, "Per binary"; launcher/flong-launch.c:847-928
//! of 5f1f08e), as far as L1 of phase 7 goes: the prologue's first two steps,
//! the signals and the spec (ordering checkpoint 1). It is not yet built into
//! the launcher: the installed flong-launch is still the C, and this root is
//! built only as tests/integration.nix's spec-probe, which the golden spec
//! set runs beside the C (tests/golden.nix). The rest of the prologue and
//! the launch, `run` and `teardown`, are L2-L4's.
//!
//! A refusal exits 125, EXIT_NOT_RUN, having said why (flong-launch.c:43-45,
//! 880-881); a spec that passes every check exits 0 here, where the launcher
//! would go on to open the state directory.

const std = @import("std");
const sys = @import("sys");
const msg = @import("msg");
const sig = @import("sig");
const proc = @import("proc");
const spec = @import("spec");

/// A launch that did not reach its payload (DESIGN.md, "Exit codes";
/// flong-launch.c:43-45). It collides with a payload's own 125 (quirk 32,
/// kept).
const not_run = 125;

// No SIGSEGV handler, and SIGPIPE left as it came for main to ignore, as
// the C does (start.zig:687-719).
pub const std_options: std.Options = .{
    .enable_segfault_handler = false,
    .keep_sigpipe = true,
};

pub const panic = std.debug.FullPanic(msg.onPanic(not_run));

pub fn main() noreturn {
    // Ordering checkpoint 1, the prologue, in flong-launch.c:847-925's
    // order. The time is main's first statement: `launcher-start` is
    // stamped now and printed once the trace flag is known (quirk 45; the
    // print is L4's, after the signalfd).
    const start = sys.clockRealtime();
    msg.prog = "flong-launch";
    msg.mode = .cut;

    // 1. Signals are read from a signalfd, so every wait can end on one as
    // an event, and none interrupts a step half done. They are blocked now
    // and stay queued; the signalfd is made after the spec is read, so
    // that its number is never one a keep-fd names: a keep-fd the wrapper
    // does not hold would otherwise pass as open (:857-862).
    _ = sig.block() catch proc.exit(not_run);
    sig.ignorePipe();
    // An ignored SIGCHLD survives execve, and under it the kernel reaps our
    // children itself: waitid would then say ECHILD, and a helper's or a
    // hook's failure would be lost (:875-878).
    sig.defaultChld();

    // 2. The spec, refusing root first; nothing is in the descriptor table
    // yet. Its strings are argv's, its arrays in an arena over
    // page_allocator that lives as long as the process (flong-launch.c:
    // 97-99's allocations, never freed).
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    const s = spec.parse(arena.allocator(), sys.argv()) catch proc.exit(not_run);

    // 3. onward: adopting the keep-fds, the signalfd, traceAt(start,
    // "launcher-start"), state_open, cache_lock and closeUntracked are L4's.
    _ = s;
    _ = start;
    proc.exit(0);
}
