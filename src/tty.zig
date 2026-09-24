//! tty.zig: the caller's terminal, and the launcher's wait for bwrap
//! (the Zig port's L3): a port of launcher/flong-tty.c, as far as the
//! launcher uses it (flong-launch.c:386, 394, 686-692, 713, 762, 790).
//! src/launch.zig makes those calls since L4; flong-tty
//! (tests/zig/ttydriver.zig), checks.native's pty driver, makes them too.
//!
//! Two modes, chosen once in `prepare`. In a relay the payload has a pty of
//! its own, the caller's terminal is raw while the payload runs, and the
//! launcher copies bytes both ways. In passthrough the payload uses the
//! caller's descriptors 0-2 directly, and tini -g takes the terminal's
//! foreground for the payload's group, so the launcher has to give it back
//! afterwards. Either way the caller's modes are restored when the session
//! ends, by the launcher or, when the launcher was killed, by the watchdog
//! (flong-tty.c:1-14).
//!
//! Every wait here is on an event with no timeout: a signal on sig.fd, a
//! pidfd, a readable descriptor, a byte or EOF on a pipe. The one clock
//! read is the ^]^]^] check, which compares keystrokes and waits for
//! nothing (`Escape`).
//!
//! The kept quirks: the relay's output goes to the caller's terminal opened
//! again, or through fd 1 when that open fails (42); a redirected stderr
//! stays where the caller sent it (43); a hang-up closes the master and
//! sets it null, and resize and the drain look (44); the watchdog's pidfd
//! is kept and reaped in `finish`, where the C closed it at once and
//! reaped by pid (9); stdin is polled only while no input waits for the
//! payload, so ^]^]^] stalls behind a payload that reads nothing (10).
//! `Tty{}` is the C's zero struct (39: moot, the handles are optionals).
//!
//! SIGTTOU: the terminal calls that restore (the modes, the foreground, the
//! container marks) ignore it for their scope, put back by a `defer`
//! (`ttouIgnore`), so a launcher in the background of its terminal still
//! restores instead of being stopped. `makeRaw` deliberately does not
//! (flong-tty.c:315-317): from the background it stops the launcher until
//! the caller's shell brings it back, as any job's would. Restore paths
//! ignore every errno: there is nothing left to do about one.

const std = @import("std");
const sys = @import("sys");
const fdt = @import("fd");
const msg = @import("msg");
const sig = @import("sig");
const proc = @import("proc");

const Stdio = fdt.Stdio;
const POLL = sys.POLL;

/// struct fl_tty (flong-tty.h:26-40). `Tty{}` is the state before
/// `prepare`, which `finish` takes too.
pub const Tty = struct {
    /// a pty is relayed; false: fds 0-2 pass through
    relay: bool = false,
    /// relay: the pty master, O_NONBLOCK; null once closed (quirk 44)
    master: ?fdt.Fd(.pty_master) = null,
    /// relay: the pty slave, until bwrap has it
    slave: ?fdt.Fd(.pty_slave) = null,
    /// relay: the caller's terminal opened again, O_NONBLOCK, for the
    /// output; null: fd 1 as it is (quirk 42)
    out: ?fdt.Fd(.tty_out) = null,
    /// relay: bwrap's 0-2, stderr only when it is a terminal (quirk 43);
    /// null inherits the launcher's
    stdio: [3]?fdt.AnyFd = .{ null, null, null },
    /// stdin is a terminal whose foreground the launcher's group had
    was_fg: bool = false,
    /// the caller's modes, saved by `start`; null before, and after
    /// `finish` has put them back (the C's `saved`)
    modes: ?sys.Termios = null,
    /// the caller's terminal is raw
    raw_mode: bool = false,
    /// the watchdog's pipe, the write end, and the watchdog
    guard: ?fdt.Fd(.pipe_w) = null,
    guard_child: ?proc.Child = null,
    /// the terminal was told it shows a container
    marked: bool = false,
};

// ---- SIGTTOU, the modes, the foreground (flong-tty.c:38-117) ----

/// ttou_stops (flong-tty.c:38-48): whether SIGTTOU would stop this
/// process, which it does only with the default action and unblocked. A
/// caller that ignores it lets a background process use the terminal, so
/// there is nothing to wait for.
fn ttouStops() bool {
    var cur: sys.KSigaction = undefined;
    if (sys.sigaction(sys.SIGTTOU, null, &cur) == .err) return false;
    const mask = switch (sys.sigmask()) {
        .ok => |m| m,
        .err => return false,
    };
    return cur.handler == sys.SIG.DFL and mask & sys.sigBit(sys.SIGTTOU) == 0;
}

/// wait_foreground (flong-tty.c:50-80): waits until the launcher's group
/// has the terminal's foreground, the way a job that needs the terminal
/// does: SIGTTOU stops the group until the caller's shell brings it to the
/// foreground and continues it. The SIGCONT that continues it stays queued
/// on sig.fd, which tells a stop from a discard: the kernel drops SIGTTOU
/// for an orphaned group, whose shell is gone and would never continue it.
/// Such a group could not make the terminal raw or read from it either, so
/// the launch gives up at once, before any session state exists. sig.fd
/// must be open.
fn waitForeground() sig.Error!void {
    if (!ttouStops()) return;
    while (true) {
        // Not our controlling terminal, or already ours.
        const fg = switch (Stdio.in.tcgetpgrp()) {
            .ok => |g| g,
            .err => return,
        };
        if (fg == sys.getpgrp()) return;
        // A SIGCONT from before this stop says nothing about it.
        _ = try sig.take(sys.SIGCONT);
        switch (sys.kill(0, sys.SIGTTOU)) {
            .ok => {},
            .err => |e| return msg.fail(e, "SIGTTOU", .{}),
        }
        if (!try sig.take(sys.SIGCONT))
            return msg.refuse("the launcher's job is in the background of its terminal, and orphaned: no shell will bring it to the foreground", .{});
    }
}

/// ttou_ignore (flong-tty.c:82-92): SIGTTOU ignored, for a terminal call
/// that must not stop a launcher in the background of its terminal (in
/// passthrough the payload's group has the foreground by then). The action
/// before, for `ttouRestore` in a `defer`; null when none was set, and then
/// nothing is put back.
fn ttouIgnore() ?sys.KSigaction {
    const ign = sys.ignoreAction();
    var old: sys.KSigaction = undefined;
    return if (sys.sigaction(sys.SIGTTOU, &ign, &old) == .ok) old else null;
}

fn ttouRestore(old: ?sys.KSigaction) void {
    if (old) |o| _ = sys.sigaction(sys.SIGTTOU, &o, null);
}

/// make_raw (flong-tty.c:94-100): the caller's terminal raw, from the
/// modes `start` saved. SIGTTOU is not ignored (:315-317).
fn makeRaw(modes: sys.Termios) sys.Result(void) {
    var raw = modes;
    sys.cfmakeraw(&raw);
    return Stdio.in.tcsetattr(.now, &raw);
}

/// restore_modes (flong-tty.c:102-107).
fn restoreModes(modes: sys.Termios) void {
    const old = ttouIgnore();
    defer ttouRestore(old);
    _ = Stdio.in.tcsetattr(.flush, &modes);
}

/// take_foreground (flong-tty.c:109-117): the terminal's foreground back
/// to the launcher's group, the caller's job.
fn takeForeground() void {
    const old = ttouIgnore();
    defer ttouRestore(old);
    const fg = Stdio.in.tcgetpgrp();
    if (fg == .err or fg.ok != sys.getpgrp())
        _ = Stdio.in.tcsetpgrp(sys.getpgrp());
}

/// OSC 666's vte.container termprops, ST-terminated: VTE rejects the BEL
/// form, silently. The clearing form names no property, which unsets them
/// all (flong-tty.c:119-121).
pub const unmark = "\x1b]666;vte.container.\x1b\\";

/// The mark `prepare` writes, in `buf`: the container's name, flong, and
/// the uid inside. snprintf into 256 bytes, so a mark of 256 bytes or more
/// is not written at all: null (flong-tty.c:157-161). The name is the
/// spec's, which holds no byte a terminal would read as the sequence's end.
pub fn mark(buf: *[256]u8, container: []const u8, uid: u32) ?[]const u8 {
    const text = std.fmt.bufPrint(buf, "\x1b]666;vte.container.name={s};vte.container.runtime=flong;vte.container.uid={d}\x1b\\", .{ container, uid }) catch return null;
    return if (text.len < buf.len) text else null;
}

/// write_terminal (flong-tty.c:123-139): a terminal sequence to fd 1, with
/// SIGTTOU ignored. A failure leaves only the terminal's border wrong, so
/// it is not reported.
fn writeTerminal(bytes: []const u8) void {
    const old = ttouIgnore();
    defer ttouRestore(old);
    var rest = bytes;
    while (rest.len > 0) {
        switch (Stdio.out.write(rest)) {
            .ok => |n| {
                if (n == 0) break;
                rest = rest[n..];
            },
            .err => break,
        }
    }
}

// ---- prepare, stdio, spawned ----

/// tty_prepare (flong-tty.c:141-213), first thing after the spec is read.
/// When stdin is a terminal and the launcher was started in the
/// background, stops itself with SIGTTOU until the caller's shell brings it
/// to the foreground, and refuses an orphaned group. When stdout is a
/// terminal, marks it as showing the container, for `uid` inside (OSC 666,
/// as toolbox and distrobox do). Then decides the mode: a relay when stdin
/// and stdout are both terminals, which opens the pty and gives the slave
/// the caller's modes and window size. On a failure what was marked stays
/// for `finish`, as in the C.
pub fn prepare(t: *Tty, container: []const u8, uid: u32) sig.Error!void {
    t.* = .{};

    if (Stdio.in.isatty()) {
        try waitForeground();
        t.was_fg = switch (Stdio.in.tcgetpgrp()) {
            .ok => |fg| fg == sys.getpgrp(),
            .err => false,
        };
    }
    // The launcher, not the wrapper, marks the terminal, since only the
    // launcher is there at the end to clear it: the wrapper execs it. Only
    // on a terminal, or the bytes land in whatever stdout was redirected
    // to (:151-165).
    if (Stdio.out.isatty()) {
        var buf: [256]u8 = undefined;
        if (mark(&buf, container, uid)) |text| {
            writeTerminal(text);
            t.marked = true;
        }
    }
    if (!Stdio.in.isatty() or !Stdio.out.isatty()) return;

    // The pty, as glibc's posix_openpt, grantpt, unlockpt and ptsname_r
    // make it (:174-186): /dev/ptmx, TIOCSPTLCK, TIOCGPTN, and the slave by
    // its path (grantpt only asks TIOCGPTN whether this is a master, glibc
    // 2.33 on). The master is non-blocking so the relay never stalls on a
    // payload that is not reading its input while it still has output to
    // drain (:169-170).
    t.master = try msg.check(fdt.openPtmx(), "open /dev/ptmx", .{});
    const master = t.master.?;
    const number: sys.Result(u32) = switch (master.unlock()) {
        .ok => master.ptyNumber(),
        .err => |e| .{ .err = e },
    };
    const n = switch (number) {
        .ok => |v| v,
        .err => |e| {
            const err = msg.fail(e, "unlock the pty", .{});
            closePty(t);
            return err;
        },
    };
    var name_buf: [32]u8 = undefined;
    const name = std.fmt.bufPrintZ(&name_buf, "/dev/pts/{d}", .{n}) catch unreachable; // proven: 9 + 10 digits < 32
    t.slave = msg.check(fdt.openSlave(name), "open {s}", .{name}) catch |err| {
        closePty(t);
        return err;
    };
    const slave = t.slave.?;

    // The payload starts with the caller's modes and window size.
    const modes: sys.Result(void) = switch (Stdio.in.tcgetattr()) {
        .ok => |m| slave.tcsetattr(.now, &m),
        .err => |e| .{ .err = e },
    };
    if (modes == .err) {
        const err = msg.fail(modes.err, "copy the terminal's modes", .{});
        closePty(t);
        return err;
    }
    switch (Stdio.in.getWinsize()) {
        .ok => |ws| switch (slave.setWinsize(&ws)) {
            .ok => {},
            .err => |e| {
                const err = msg.fail(e, "copy the terminal's size", .{});
                closePty(t);
                return err;
            },
        },
        .err => {},
    }

    // The relay's output goes to the caller's terminal through a
    // descriptor of its own, non-blocking, so a terminal that stops
    // draining never blocks the relay in a write while signals and the
    // escape wait. Opening it again makes a new open file description:
    // O_NONBLOCK on fd 1 itself would change the caller's shell's too. A
    // terminal the caller cannot open (after su, say) is written through
    // fd 1 as it is, only when poll says it takes output (quirk 42). A full
    // table is the C's EMFILE, and falls back the same way (quirk 41).
    const out = fdt.reopenOut() catch sys.Result(fdt.Fd(.tty_out)){ .err = .MFILE };
    t.out = switch (out) {
        .ok => |h| h,
        .err => null,
    };
    t.relay = true;
    // A redirected stderr stays where the caller sent it (quirk 43).
    t.stdio = .{ slave.any(), slave.any(), if (Stdio.err.isatty()) slave.any() else null };
}

/// prepare's `fail:` (flong-tty.c:209-212): the slave, then the master.
fn closePty(t: *Tty) void {
    if (t.slave) |s| s.close();
    t.slave = null;
    if (t.master) |m| m.close();
    t.master = null;
}

/// tty_stdio (flong-tty.c:215-218): bwrap's 0-2, for Spawn.stdio. All null
/// in passthrough, which inherits the launcher's.
pub fn stdio(t: *const Tty) [3]?fdt.AnyFd {
    return t.stdio;
}

/// tty_spawned (flong-tty.c:220-226): bwrap has the slave, so the launcher
/// lets its copy go, and the relay sees EIO once every process of the
/// session has let the pty go.
pub fn spawned(t: *Tty) void {
    if (!t.relay) return;
    if (t.slave) |s| s.close();
    t.slave = null;
    t.stdio = .{ null, null, null };
}

// ---- the watchdog, and start ----

/// What the watchdog needs, copied into its memory by the fork.
const Watch = struct {
    relay: bool,
    marked: bool,
    was_fg: bool,
    modes: sys.Termios,
    pipe_r: fdt.Fd(.pipe_r),
    leader: fdt.AnyFd,
};

/// The watchdog's life (flong-tty.c:228-274): it holds the caller's
/// terminal as fd 0, the read end of a pipe only the launcher writes, and
/// the leader's pidfd. A "done" byte means the launcher restored everything
/// itself. EOF without it means the launcher was killed: the modes are put
/// back, and in passthrough the foreground is taken back once the
/// payload's group is gone, which it is when the leader's pidfd is readable
/// (the session's pid namespace dies with its pid 1). It only takes the
/// foreground from a group with no process left, so a caller's shell that
/// took it back first keeps it.
///
/// It keeps the caller's stdout and stderr until it exits. A launcher
/// killed in a pipeline (`launcher | cat`) ends its job only when every
/// writer of the pipe is gone; were the watchdog not one of them, the
/// caller's shell could resume, and save the terminal's modes while they
/// are still raw, before the watchdog had restored them. It outlives the
/// launcher only as long as the payload does, which holds the same pipe.
fn watchdog(w: Watch) noreturn {
    // Ignored for good: nothing here may stop it.
    _ = ttouIgnore();
    _ = sys.prctl(sys.PR_SET_NAME, @intFromPtr("flong-ttyguard"));

    var c: [1]u8 = undefined;
    switch (w.pipe_r.read(&c)) {
        .ok => |n| if (n != 0) proc.exit(0),
        .err => proc.exit(0),
    }

    if (w.relay) {
        _ = Stdio.in.tcsetattr(.flush, &w.modes);
        if (w.marked) writeTerminal(unmark);
        proc.exit(0);
    }
    // Passthrough: the payload may set modes until it is gone.
    var p = [1]sys.pollfd{fdt.pollEntry(w.leader, POLL.IN)};
    while (true) {
        switch (sys.poll(&p, -1)) {
            .ok => break,
            .err => |e| if (e != .INTR) break,
        }
    }
    _ = Stdio.in.tcsetattr(.flush, &w.modes);
    if (w.marked) writeTerminal(unmark);
    if (w.was_fg) {
        switch (Stdio.in.tcgetpgrp()) {
            .ok => |fg| if (fg > 0 and fg != sys.getpgrp()) {
                const gone = switch (sys.kill(-fg, 0)) {
                    .ok => false,
                    .err => |e| e == .SRCH,
                };
                if (gone) _ = Stdio.in.tcsetpgrp(sys.getpgrp());
            },
            .err => {},
        }
    }
    proc.exit(0);
}

/// tty_start (flong-tty.c:284-323), just before the gate opens: saves the
/// caller's modes, starts the watchdog with the leader's pidfd (`leader`,
/// an owned or held pidfd), and only then makes the terminal raw (relay),
/// so the terminal is never raw without a watchdog.
///
/// Ordering checkpoint 8 (DESIGN.md): the watchdog forks before raw mode, only
/// when stdin is a terminal, keeping 0-2, its pipe's read end and the
/// leader, nothing else: a copy of the pty master there would keep the
/// session's terminal from hanging up. One linear function.
pub fn start(t: *Tty, leader: anytype) msg.Error!void {
    if (comptime @TypeOf(leader).kind != .pidfd) @compileError("tty.start takes the leader's pidfd");

    // 1. Nothing to restore when stdin is not a terminal (:286-288).
    if (!Stdio.in.isatty()) return;

    // 2. The caller's modes, saved (:289-291).
    const modes = try msg.check(Stdio.in.tcgetattr(), "read the terminal's modes", .{});
    t.modes = modes;

    // 3. The watchdog's pipe (:296-298).
    const p = try msg.check(fdt.pipe(), "pipe", .{});

    // 4. The watchdog first, so the terminal is never raw without one to
    // restore it: a launcher SIGKILLed at any point after makeRaw leaves a
    // watchdog that reads EOF and puts the saved modes back (:293-303). It
    // keeps {pipe_r, leader} and 0-2; retainOnly closes every other
    // descriptor in it, the master's included.
    const child = proc.fork(.{ .keep = &.{ p.r.any(), leader.any() } }, Watch{
        .relay = t.relay,
        .marked = t.marked,
        .was_fg = t.was_fg,
        .modes = modes,
        .pipe_r = p.r,
        .leader = leader.any(),
    }, watchdog) catch |err| {
        p.r.close();
        p.w.close();
        return err;
    };

    // 5. The read end is the watchdog's alone, so the launcher's death is
    // its EOF (:304). Its pidfd is kept, and `finish` reaps it (quirk 9).
    p.r.close();
    t.guard = p.w;
    t.guard_child = child;

    // 6. Only now raw, in relay. From the background this stops the
    // launcher with SIGTTOU until the caller's shell brings it back, as any
    // job's would (:315-321).
    if (t.relay) {
        switch (makeRaw(modes)) {
            .ok => {},
            .err => |e| return msg.fail(e, "make the terminal raw", .{}),
        }
        t.raw_mode = true;
    }
}

/// tty_resize (flong-tty.c:276-282): in a relay, the caller's window size
/// to the pty, unless the master is closed (quirk 44). A terminal that
/// reports no size leaves the pty's as it is.
pub fn resize(t: *const Tty) void {
    if (!t.relay) return;
    const master = t.master orelse return;
    switch (Stdio.in.getWinsize()) {
        .ok => |ws| _ = master.setWinsize(&ws),
        .err => {},
    }
}

// ---- the escape ----

/// nspawn's escape (flong-tty.c:33-36, 360-372, 479-486) as a state
/// machine over keystrokes: ^] three times within a second ends the
/// session. Any other byte starts it over, and so does a ^] more than a
/// second after the first of the run. The clock is read at each ^] alone,
/// and nothing waits on it.
pub const Escape = struct {
    presses: u32 = 0,
    /// when the run's first ^] was read, in nanoseconds
    first: i64 = 0,

    pub const key = 0x1d;
    pub const presses_needed = 3;
    pub const window_ns = std.time.ns_per_s;

    /// One byte of input; `clock.now()` gives the time in nanoseconds and
    /// is asked for a ^] only. True when this byte completes the escape.
    pub fn byte(self: *Escape, b: u8, clock: anytype) bool {
        if (b != key) {
            self.presses = 0;
            return false;
        }
        const now: i64 = clock.now();
        if (self.presses == 0 or now -| self.first > window_ns) {
            self.presses = 0;
            self.first = now;
        }
        self.presses +|= 1;
        return self.presses == presses_needed;
    }

    /// One read's bytes, in order: how many of them completed the escape,
    /// each a SIGKILL of the leader and bwrap (:479-486).
    pub fn feed(self: *Escape, bytes: []const u8, clock: anytype) usize {
        var n: usize = 0;
        for (bytes) |b| n += @intFromBool(self.byte(b, clock));
        return n;
    }
};

const monotonic = struct {
    fn now(_: @This()) i64 {
        return sys.clockMonotonic();
    }
}{};

// ---- the wait ----

/// The relay's output target: the reopened terminal, or fd 1 (quirk 42).
fn outWrite(t: *const Tty, bytes: []const u8) sys.Result(usize) {
    return if (t.out) |o| o.write(bytes) else Stdio.out.write(bytes);
}

fn outEntry(t: *const Tty, events: i16) sys.pollfd {
    return if (t.out) |o| fdt.pollEntry(o, events) else fdt.pollEntry(Stdio.out, events);
}

/// The master closed early: the session's terminal hangs up, and the
/// handle is gone (quirk 44).
fn closeMaster(t: *Tty) void {
    if (t.master) |m| m.close();
    t.master = null;
}

/// write_all (flong-tty.c:325-347): all of `bytes` to the output, waiting
/// with poll while it is full. Only for the drain, after bwrap has exited,
/// when there is nothing left to forward a signal to. False when the
/// terminal has gone (nothing printed: that is a hang-up, not an error).
fn outWriteAll(t: *const Tty, bytes: []const u8) bool {
    var rest = bytes;
    while (rest.len > 0) {
        switch (outWrite(t, rest)) {
            .ok => |n| {
                if (n == 0) return false;
                rest = rest[n..];
            },
            .err => |e| {
                if (e != .AGAIN) return false;
                var p = [1]sys.pollfd{outEntry(t, POLL.OUT)};
                switch (sys.poll(&p, -1)) {
                    .ok => {},
                    .err => |pe| if (pe != .INTR) return false,
                }
            },
        }
    }
    return true;
}

/// tty_wait (flong-tty.c:374-513): the launcher's wait, from gate-open
/// until bwrap exits, in both modes. Polls bwrap's pidfd, sig.fd and, in a
/// relay, the master and stdin, all with no timeout. SIGTERM, SIGHUP,
/// SIGINT and SIGQUIT go to the leader through `leader`, its pidfd, never
/// by its pid, which bwrap may have reaped and the kernel given to another
/// process (tini -g passes them to the payload's group). SIGWINCH copies
/// the window size to the pty; SIGCONT puts raw mode back. Each direction
/// of the relay is a buffer written only when poll says its target takes
/// bytes, so a caller's terminal that stops draining never keeps a signal
/// or the escape waiting. Stdin at EOF hangs the session up by closing the
/// master. bwrap's status (0-255, or 128+n for a signal), bwrap left
/// unreaped for the teardown, which reaps everything the launcher started.
pub fn wait(t: *Tty, bwrap: proc.Child, leader: anytype) msg.Error!u8 {
    if (comptime @TypeOf(leader).kind != .pidfd) @compileError("tty.wait takes the leader's pidfd");
    const bwrap_i = 0;
    const signals_i = 1;
    const master_i = 2;
    const stdin_i = 3;
    const stdout_i = 4;
    var out: [65536]u8 = undefined;
    var in: [4096]u8 = undefined;
    // Each direction has one buffer, filled by one read and emptied by as
    // many writes as the other side takes. Its source is not read again
    // until it is empty, so a side that does not drain holds the other
    // back and never the loop: every write is to a descriptor poll has
    // reported writable.
    var out_len: usize = 0;
    var out_off: usize = 0;
    var in_len: usize = 0;
    var in_off: usize = 0;
    // The relay copies between the terminal and the pty. It ends when
    // every slave is closed (EIO) or when the caller's terminal goes and
    // the session is hung up by closing the master. Open implies the
    // master is not null.
    var master_open = t.relay and t.master != null;
    var escape: Escape = .{};

    while (true) {
        var p = [5]sys.pollfd{
            fdt.pollEntry(bwrap.pidfd, POLL.IN),
            fdt.pollEntry(sig.fd, POLL.IN),
            // Left out while it has nothing to take and output waits: a
            // hung-up master reports POLLHUP whatever the events asked,
            // and would wake the loop until the caller's terminal drained.
            fdt.pollEntry(if (master_open and (out_len == 0 or in_len > 0)) t.master else null, @as(i16, if (out_len == 0) POLL.IN else 0) | @as(i16, if (in_len > 0) POLL.OUT else 0)),
            fdt.pollEntry(if (master_open and in_len == 0) @as(?Stdio, .in) else null, POLL.IN),
            if (out_len > 0) outEntry(t, POLL.OUT) else fdt.pollEntry(@as(?Stdio, null), POLL.OUT),
        };
        switch (sys.poll(&p, -1)) {
            .ok => {},
            .err => |e| {
                if (e == .INTR or e == .AGAIN) continue;
                return msg.fail(e, "poll", .{});
            },
        }
        for (p) |e| {
            if (e.revents & POLL.NVAL != 0) return msg.fail(.BADF, "poll", .{});
        }

        if (p[signals_i].revents & POLL.IN != 0) {
            const s = try sig.next();
            // tini -g passes it on to the payload's group. The pidfd never
            // names another process once the leader is gone: then the send
            // fails, and bwrap's exit is next.
            if (sig.terminating(s)) {
                _ = leader.sendSignal(@intCast(s));
            } else if (s == sys.SIGWINCH) {
                resize(t);
            } else if (s == sys.SIGCONT and t.raw_mode) {
                // The caller's shell may have put its own modes back while
                // the launcher was stopped.
                _ = makeRaw(t.modes.?);
            }
        }

        if (out_len == 0 and p[master_i].revents & (POLL.IN | POLL.HUP | POLL.ERR) != 0) {
            switch (t.master.?.read(&out)) {
                .ok => |n| {
                    if (n > 0) out_len = n else master_open = false;
                },
                // EIO: every slave is closed.
                .err => |e| if (e != .AGAIN) {
                    master_open = false;
                },
            }
        }

        if (p[stdout_i].revents & (POLL.OUT | POLL.HUP | POLL.ERR) != 0) {
            switch (outWrite(t, out[out_off..out_len])) {
                .ok => |n| if (n > 0) {
                    out_off += n;
                    if (out_off == out_len) {
                        out_len = 0;
                        out_off = 0;
                    }
                },
                // The caller's terminal has gone: hang the session up, and
                // drop what it cannot show.
                .err => |e| if (e != .AGAIN) {
                    closeMaster(t);
                    master_open = false;
                    out_len = 0;
                    out_off = 0;
                },
            }
        }

        if (master_open and in_len > 0 and p[master_i].revents & (POLL.OUT | POLL.HUP | POLL.ERR) != 0) {
            switch (t.master.?.write(in[in_off..in_len])) {
                .ok => |n| if (n > 0) {
                    in_off += n;
                    if (in_off == in_len) {
                        in_len = 0;
                        in_off = 0;
                    }
                },
                // EIO: every slave is closed, and nothing will read the
                // input. The master is still read until it says so
                // itself, for the output.
                .err => |e| if (e != .AGAIN) {
                    in_len = 0;
                    in_off = 0;
                },
            }
        }

        if (master_open and p[stdin_i].revents & (POLL.IN | POLL.HUP | POLL.ERR) != 0) {
            switch (Stdio.in.read(&in)) {
                .ok => |n| if (n > 0) {
                    in_len = n;
                    var kills = escape.feed(in[0..n], monotonic);
                    while (kills > 0) : (kills -= 1) {
                        _ = leader.sendSignal(sys.SIGKILL);
                        _ = bwrap.pidfd.sendSignal(sys.SIGKILL);
                    }
                } else {
                    // The caller's terminal hung up: hang the session up.
                    closeMaster(t);
                    master_open = false;
                },
                .err => |e| if (e != .AGAIN) {
                    closeMaster(t);
                    master_open = false;
                },
            }
        }

        if (p[bwrap_i].revents & POLL.IN != 0) break;
    }

    // bwrap is gone, and with it every process of the session: what the
    // payload wrote last is in the out buffer and the master. A
    // non-blocking read flushes the pty's pending buffer before it reports
    // EIO or EAGAIN, so this drains everything without waiting for the
    // session. A terminal that does not drain delays only the teardown.
    if (out_len > 0 and !outWriteAll(t, out[out_off..out_len])) master_open = false;
    while (master_open) {
        const m = t.master orelse break;
        switch (m.read(&out)) {
            .ok => |n| if (n == 0 or !outWriteAll(t, out[0..n])) {
                master_open = false;
            },
            .err => master_open = false,
        }
    }
    // exit_status (:349-358): WNOWAIT leaves bwrap to the teardown.
    return switch (bwrap.peek()) {
        .ok => |s| s,
        .err => |e| msg.fail(e, "wait for bwrap", .{}),
    };
}

// ---- finish ----

/// tty_finish (flong-tty.c:515-545), from the one teardown path whatever
/// stage the launch reached, `Tty{}` included: puts the caller's modes
/// back, tells the watchdog it is done and reaps it, hands the foreground
/// back (passthrough, when the launcher's group had it: tini -g gave it to
/// the payload's group, which is gone), closes the pty, and clears the
/// container from the terminal. Infallible and idempotent, in the C's
/// order.
pub fn finish(t: *Tty) void {
    // 1. The caller's modes.
    if (t.modes) |modes| {
        restoreModes(modes);
        t.modes = null;
        t.raw_mode = false;
    }
    // 2. The watchdog exits on this byte, at once; reaped, as the C reaped
    // it by pid (quirk 9).
    if (t.guard_child) |child| {
        if (t.guard) |g| {
            _ = g.write("d");
            g.close();
        }
        t.guard = null;
        child.reapNow(.wait);
        t.guard_child = null;
    }
    // 3. The foreground, in passthrough.
    if (t.was_fg and !t.relay) {
        takeForeground();
        t.was_fg = false;
    }
    // 4. The pty and the reopened terminal.
    if (t.relay) {
        if (t.slave) |s| s.close();
        t.slave = null;
        closeMaster(t);
        if (t.out) |o| o.close();
        t.out = null;
    }
    // 5. The container's marks.
    if (t.marked) {
        writeTerminal(unmark);
        t.marked = false;
    }
}

// ---- tests ----

const testing = std.testing;

/// A clock that answers the times it is given, one per call.
const Script = struct {
    times: []const i64,
    i: usize = 0,

    fn now(self: *Script) i64 {
        const t = self.times[self.i];
        self.i += 1;
        return t;
    }
};

test "the escape: three ^] within a second, nothing between" {
    const s = std.time.ns_per_s;
    {
        var e: Escape = .{};
        var c: Script = .{ .times = &.{ 0, 0, 0 } };
        try testing.expectEqual(@as(usize, 1), e.feed("\x1d\x1d\x1d", &c));
    }
    {
        // Another key between starts it over, and asks no time.
        var e: Escape = .{};
        var c: Script = .{ .times = &.{ 0, 0, 0 } };
        try testing.expectEqual(@as(usize, 0), e.feed("\x1d\x1dx\x1d", &c));
        try testing.expectEqual(@as(usize, 3), c.i);
    }
    {
        // Exactly a second after the first still counts; a nanosecond more
        // starts a new run at that press.
        var e: Escape = .{};
        var c: Script = .{ .times = &.{ 0, s / 2, s } };
        try testing.expectEqual(@as(usize, 1), e.feed("\x1d\x1d\x1d", &c));
        e = .{};
        c = .{ .times = &.{ 0, s / 2, s + 1, s + 2, s + 3 } };
        try testing.expectEqual(@as(usize, 1), e.feed("\x1d\x1d\x1d\x1d\x1d", &c));
        try testing.expectEqual(@as(u32, 3), e.presses);
    }
    {
        // A fourth ^] in the run completes nothing more.
        var e: Escape = .{};
        var c: Script = .{ .times = &.{ 0, 1, 2, 3 } };
        try testing.expectEqual(@as(usize, 1), e.feed("\x1d\x1d\x1d\x1d", &c));
    }
    {
        // Chunks are one stream: a run split across reads counts whole.
        var e: Escape = .{};
        var c: Script = .{ .times = &.{ 0, 1, 2 } };
        try testing.expectEqual(@as(usize, 0), e.feed("\x1d", &c));
        try testing.expectEqual(@as(usize, 0), e.feed("\x1d", &c));
        try testing.expectEqual(@as(usize, 1), e.feed("\x1d", &c));
    }
}

test "the mark: written whole below 256 bytes, not at all from 256" {
    var buf: [256]u8 = undefined;
    const text = mark(&buf, "box", 1000).?;
    try testing.expectEqualStrings("\x1b]666;vte.container.name=box;vte.container.runtime=flong;vte.container.uid=1000\x1b\\", text);
    // The frame around the name is 82 bytes with a 4-digit uid.
    const frame = text.len - 3;
    var name: [256]u8 = @splat('n');
    try testing.expectEqual(@as(usize, 255), mark(&buf, name[0 .. 255 - frame], 1000).?.len);
    try testing.expect(mark(&buf, name[0 .. 256 - frame], 1000) == null);
    try testing.expect(mark(&buf, name[0 .. 300 - frame], 1000) == null);
}

test "cfmakeraw clears glibc's bits and sets eight bits, VMIN 1, VTIME 0" {
    var t: sys.Termios = .{ .iflag = ~@as(u32, 0), .oflag = ~@as(u32, 0), .cflag = ~@as(u32, 0), .lflag = ~@as(u32, 0), .line = 7, .cc = @splat(9) };
    sys.cfmakeraw(&t);
    try testing.expectEqual(~@as(u32, 0o2753), t.iflag);
    try testing.expectEqual(~@as(u32, 1), t.oflag);
    try testing.expectEqual(~@as(u32, 0o100113), t.lflag);
    try testing.expectEqual(~@as(u32, 0o400), t.cflag);
    try testing.expectEqual(@as(u8, 1), t.cc[sys.VMIN]);
    try testing.expectEqual(@as(u8, 0), t.cc[sys.VTIME]);
    try testing.expectEqual(@as(u8, 7), t.line);
}

test "SIGTTOU: ignored for a restore's scope, put back as it was; ttouStops only at the default, unblocked" {
    // Stdin here is no terminal, so the terminal calls fail with ENOTTY and
    // only the disposition around them is looked at (flong-tty.c:38-48,
    // 86-117).
    if (Stdio.in.isatty()) return error.SkipZigTest;
    var before: sys.KSigaction = undefined;
    try testing.expect(sys.sigaction(sys.SIGTTOU, null, &before) == .ok);
    defer _ = sys.sigaction(sys.SIGTTOU, &before, null);
    const mask = sys.sigprocmask(sys.SIG_SETMASK, 0).ok;
    defer _ = sys.sigprocmask(sys.SIG_SETMASK, mask);

    var now: sys.KSigaction = undefined;
    for ([_]usize{ sys.SIG.DFL, sys.sig_ign }) |handler| {
        if (handler == sys.SIG.DFL) {
            try testing.expect(sys.sigDefault(sys.SIGTTOU) == .ok);
        } else {
            const ign = sys.ignoreAction();
            try testing.expect(sys.sigaction(sys.SIGTTOU, &ign, null) == .ok);
        }
        try testing.expectEqual(handler == sys.SIG.DFL, ttouStops());
        // Within the scope it is ignored, and the defer puts it back.
        {
            const old = ttouIgnore();
            try testing.expect(old != null);
            try testing.expect(sys.sigaction(sys.SIGTTOU, null, &now) == .ok);
            try testing.expectEqual(@as(usize, sys.sig_ign), now.handler);
            ttouRestore(old);
        }
        try testing.expect(sys.sigaction(sys.SIGTTOU, null, &now) == .ok);
        try testing.expectEqual(handler, now.handler);
        // finish's restores (the modes, the foreground) leave it as it was.
        var t: Tty = .{ .modes = std.mem.zeroes(sys.Termios), .was_fg = true };
        finish(&t);
        try testing.expect(t.modes == null and !t.was_fg);
        try testing.expect(sys.sigaction(sys.SIGTTOU, null, &now) == .ok);
        try testing.expectEqual(handler, now.handler);
        // makeRaw does not ignore it (:315-317).
        _ = makeRaw(std.mem.zeroes(sys.Termios));
        try testing.expect(sys.sigaction(sys.SIGTTOU, null, &now) == .ok);
        try testing.expectEqual(handler, now.handler);
    }
    // Blocked, it stops nothing.
    try testing.expect(sys.sigDefault(sys.SIGTTOU) == .ok);
    _ = sys.sigprocmask(sys.SIG_SETMASK, sys.sigBit(sys.SIGTTOU));
    try testing.expect(!ttouStops());
}
