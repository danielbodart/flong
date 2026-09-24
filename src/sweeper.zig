//! flong-sweeper's root (DESIGN.md, "Files"): launcher/flong-sweeper.c,
//! line by line (:18-42). The C was deleted in phase 5 (b), and its line
//! numbers here are those of c9571be.
//!
//!   flong-sweeper STATE-DIR
//!
//! The holder unit's process. It runs in the unit's
//! DelegateSubgroup=supervisor leaf, so the unit's cgroup, which every
//! session lives under, stays up while no session does. It sweeps sessions/
//! at start and again each time a record is closed, so a SIGKILLed
//! launcher's postStop and hook daemons go within milliseconds of its
//! death, not at the next launch. It runs until it is killed, and exits 125
//! when it cannot start or cannot go on (:1-11).
//!
//! It has no signalfd, so SIGTERM kills it, and no allocator: fixed
//! buffers (record.zig). Its exit stops the holder and every session
//! (module.nix:936-941), so it must not panic on any record a caller can
//! write; a panic says one line, "flong-sweeper: internal error: <msg>",
//! and exits 125 (DESIGN.md, open decision 2). Messages are cut at 1023
//! bytes, as the C's (quirk 22).

const std = @import("std");
const sys = @import("sys");
const msg = @import("msg");
const sig = @import("sig");
const proc = @import("proc");
const record = @import("record");
const cgroup = @import("cgroup");

/// The sweeper's one failure status (flong-sweeper.c:10).
const failed = 125;

// No SIGSEGV handler, and SIGPIPE left as it came for main to set, as the
// C does (start.zig:687-719).
pub const std_options: std.Options = .{
    .enable_segfault_handler = false,
    .keep_sigpipe = true,
};

pub const panic = std.debug.FullPanic(msg.onPanic(failed));

pub fn main() noreturn {
    msg.prog = "flong-sweeper";
    msg.mode = .cut;
    // stderr is the journal's pipe: if it goes, a message is lost, not the
    // sweeper.
    sig.ignorePipe();
    // An ignored SIGCHLD survives execve, and postStop's waitid needs the
    // status the kernel would then discard.
    sig.defaultChld();
    const argv = sys.argv();
    if (argv.len != 2) {
        msg.say("usage: flong-sweeper STATE-DIR", .{});
        proc.exit(failed);
    }
    proc.refuseRoot() catch proc.exit(failed);
    const state = record.stateOpen(std.mem.span(argv[1])) catch proc.exit(failed);
    const h = cgroup.holderSelf() catch proc.exit(failed);
    // The watch returns only when it cannot go on, having said why.
    record.watch(state.sessions, &h) catch proc.exit(failed);
}
