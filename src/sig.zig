//! sig.zig: signals, and waiting on a descriptor (ZIG.md, "Signals and
//! processes"): flong-util.c:244-322 and the signal setup of
//! flong-launch.c:861-881 and flong-sweeper.c:24-29 (c9571be's; the
//! sweeper's C was deleted in phase 5 (b)).
//!
//! The launcher blocks the signals it cares about at start and reads them
//! from a signalfd, so every wait is a poll that a terminating signal ends
//! as an event (flong-util.h:88-97). A program without one (flong-sweeper)
//! leaves `fd` null: its waits poll the descriptor alone and SIGTERM kills
//! it. A fork child that did not keep the signalfd has a stale handle here,
//! which every wait tests with `isLive`, never `raw` (flong-util.c:476-479).
//!
//! Two failures: `error.Reported`, printed where it happened (msg.zig),
//! and `error.Aborted`, a terminating signal, which prints nothing and
//! leaves the signal in `abort_signal` for the exit status 128+n
//! (flong-util.c:251-256).

const std = @import("std");
const sys = @import("sys");
const fdt = @import("fd");
const msg = @import("msg");

pub const Error = error{ Reported, Aborted };

/// fl_sigfd (flong-util.c:28): null in a program without one, and stale in
/// a fork child that did not keep it.
pub var fd: ?fdt.Fd(.signalfd) = null;

/// fl_abort_signal (flong-util.c:29): the terminating signal that ended a
/// wait, or 0.
pub var abort_signal: u8 = 0;

/// The signals the launcher blocks and reads from its signalfd
/// (flong-launch.c:863-869): TERM, HUP, INT, QUIT, WINCH, CONT.
pub const blocked: u64 = sys.sigBit(sys.SIGTERM) | sys.sigBit(sys.SIGHUP) | sys.sigBit(sys.SIGINT) |
    sys.sigBit(sys.SIGQUIT) | sys.sigBit(sys.SIGWINCH) | sys.sigBit(sys.SIGCONT);

/// Blocks `blocked` (sigprocmask(SIG_BLOCK), flong-launch.c:870-873) and
/// returns the mask before, which relaunch restores.
pub fn block() msg.Error!u64 {
    return msg.check(sys.sigprocmask(sys.SIG_BLOCK, blocked), "sigprocmask", .{});
}

/// sigprocmask(SIG_SETMASK, mask): relaunch's restore of the mask
/// (flong-launch.c:171), whose failure the C does not check.
pub fn setMask(mask: u64) void {
    _ = sys.sigprocmask(sys.SIG_SETMASK, mask);
}

/// signal(SIGPIPE, SIG_IGN) (flong-launch.c:874, flong-sweeper.c:26): a
/// write to a closed pipe is EPIPE, and a lost stderr loses a message, not
/// the process. Unchecked, as the C's.
pub fn ignorePipe() void {
    _ = sys.signal(sys.SIGPIPE, sys.sig_ign);
}

/// signal(SIGPIPE, SIG_DFL): relaunch puts it back before its exec
/// (flong-launch.c:170).
pub fn defaultPipe() void {
    _ = sys.signal(sys.SIGPIPE, sys.SIG.DFL);
}

/// signal(SIGCHLD, SIG_DFL) (flong-launch.c:878, flong-sweeper.c:29): an
/// ignored SIGCHLD survives execve, and under it the kernel reaps children
/// itself, so waitid would say ECHILD and a child's status would be lost.
pub fn defaultChld() void {
    _ = sys.signal(sys.SIGCHLD, sys.SIG.DFL);
}

/// Makes `fd`: signalfd4 of `blocked`, close-on-exec and non-blocking
/// (flong-launch.c:881-885), after the spec is read so its number is never
/// a keep-fd's.
pub fn openSignalfd() msg.Error!void {
    fd = try msg.check(fdt.openSignalfd(blocked), "signalfd", .{});
}

/// fl_terminating (flong-util.c:246-249): the signals that end a launch
/// before the gate.
pub fn terminating(s: u32) bool {
    return s == sys.SIGTERM or s == sys.SIGHUP or s == sys.SIGINT or s == sys.SIGQUIT;
}

/// fl_abort (flong-util.c:251-256): records the signal, nothing printed.
fn abort(s: u32) error{Aborted} {
    abort_signal = @intCast(s);
    return error.Aborted;
}

/// fl_next_signal (flong-util.c:258-269): one signal off `fd`, or 0 when
/// none is queued. `fd` must be live.
pub fn next() msg.Error!u32 {
    var si: sys.SignalfdSiginfo = undefined;
    return switch (fd.?.readSiginfo(&si)) {
        .ok => |n| if (n == @sizeOf(sys.SignalfdSiginfo)) si.signo else msg.fail(.IO, "read signalfd", .{}),
        .err => |e| if (e == .AGAIN) 0 else msg.fail(e, "read signalfd", .{}),
    };
}

/// fl_take_signal (flong-util.c:271-282): takes the queued signals, without
/// waiting, until `want` comes off (0: until none is left). A terminating
/// one on the way aborts; the others are dropped. True when `want` was
/// taken.
pub fn take(want: u32) Error!bool {
    while (true) {
        const s = try next();
        if (s == 0) return false;
        if (s == want) return true;
        if (terminating(s)) return abort(s);
    }
}

/// fl_await (flong-util.c:284-322): waits, with no timeout, until `h`
/// reports one of `events` (POLLHUP and POLLERR count as ready: a pipe
/// whose writers are gone is the EOF a caller waits to read, and the
/// caller's next call reports an error), or a terminating signal arrives on
/// `fd`. Other signals are taken and dropped. The signal is looked at
/// first: once a terminating one has arrived, the wait is aborted whatever
/// else became ready. `h` is any handle.
pub fn awaitFd(h: anytype, events: i16) Error!void {
    const with_sig = if (fd) |s| s.isLive() else false;
    var p = [2]sys.pollfd{
        .{ .fd = h.raw(), .events = events, .revents = 0 },
        .{ .fd = if (with_sig) fd.?.raw() else -1, .events = sys.POLL.IN, .revents = 0 },
    };
    const n: usize = if (with_sig) 2 else 1;
    while (true) {
        switch (sys.poll(p[0..n], -1)) {
            .ok => {},
            .err => |e| if (e == .INTR) continue else return msg.fail(e, "poll", .{}),
        }
        if (n == 2 and p[1].revents != 0) {
            if (p[1].revents & sys.POLL.NVAL != 0) return msg.fail(.BADF, "poll signalfd", .{});
            // One signal per wake-up: any behind it make the next poll
            // return at once.
            const s = try next();
            if (terminating(s)) return abort(s);
        }
        if (p[0].revents & sys.POLL.NVAL != 0) return msg.fail(.BADF, "poll {d}", .{p[0].fd});
        if (p[0].revents & (events | sys.POLL.HUP | sys.POLL.ERR) != 0) return;
    }
}

// ---- tests ----

const testing = std.testing;

test "the blocked set is the launcher's six" {
    try testing.expectEqual(@as(u64, (1 << 14) | (1 << 0) | (1 << 1) | (1 << 2) | (1 << 27) | (1 << 17)), blocked);
    try testing.expect(terminating(sys.SIGTERM) and terminating(sys.SIGHUP) and terminating(sys.SIGINT) and terminating(sys.SIGQUIT));
    try testing.expect(!terminating(sys.SIGWINCH) and !terminating(sys.SIGCONT) and !terminating(sys.SIGPIPE));
}
