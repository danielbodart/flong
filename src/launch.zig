//! flong-launch: one session, from the wrapper's spec to the payload's exit
//! (ZIG.md, "Per binary" and "Phase 7", L4; launcher/flong-launch.c of
//! a7919be, whose line numbers these are). The wrapper execs this with the
//! whole spec as arguments (DESIGN.md, "The input contract"). `main` is the
//! prologue, steps 1-5 of DESIGN.md's "The launch, in order" (ordering
//! checkpoint 1), then `proc.exit(teardown(&l, run(&l)))`: `run` is steps
//! 6-18, returning at the first failure, and `teardown` step 19, undoing
//! whatever exists whatever stage was reached (flong-launch.c:1-19).
//!
//! Every resource a launch holds is in `Launch`: a handle that may not
//! exist yet is optional, one kept until the process exits is `Held` (the
//! state and sessions directories, the cache, U1, the info pipe's read end,
//! the leader's pidfd, the network namespace, pasta's pid file; ZIG.md,
//! "The descriptor layer"), and each child is a `?proc.Child`, null once it
//! is reaped (flong-launch.c:47-80). The payload runs only once the gate
//! byte is written, and the gate is written only after every earlier step
//! succeeded: flong-init reads EOF otherwise and exits 125.
//!
//! The steps are modules: spec (the input contract, bwrap's argv), ns (U1
//! and U2), cgroup (the holder and the session), record (the state
//! directory, the sweep, the record, postStop), tty (the terminal and the
//! wait for bwrap), mount (the mount helper, a fork body here), passwd
//! (cgroup's refusal), and src/launch/: prologue (the relaunch, the cache,
//! the close of what the wrapper left open, the protected paths), bwrap
//! (its spawn), childpid (--info-fd), hook (postStart) and pasta. This file
//! owns the order: ordering checkpoints 1, 2, 3, 5 and 6 are `main`, `run`
//! and `teardown`, each one linear function with numbered comments, never
//! a helper (checkpoint 4 is ns.zig's).
//!
//! No wait here has a timeout. Each is on a pipe, a pidfd or cgroup.events,
//! and a terminating signal ends it as an event, through the signalfd
//! (sig.zig): error.Aborted, and 128+n as the launch's status.

const std = @import("std");
const sys = @import("sys");
const fdt = @import("fd");
const msg = @import("msg");
const sig = @import("sig");
const proc = @import("proc");
const spec = @import("spec");
const ns = @import("ns");
const cgroup = @import("cgroup");
const record = @import("record");
const tty = @import("tty");
const mount = @import("mount");
const prologue = @import("prologue");
const bwrap = @import("bwrap");
const childpid = @import("childpid");
const hook = @import("hook");
const pasta = @import("pasta");
const config = @import("config");

const Allocator = std.mem.Allocator;

/// A launch that did not reach its payload (DESIGN.md, "Exit codes";
/// flong-launch.c:43-45). It collides with a payload's own 125 (quirk 32,
/// kept).
const not_run = prologue.exit_not_run;

// The programs a launch runs, compiled in (-Dbwrap, -Dinit, -Dpasta,
// -Dnewuidmap, -Dnewgidmap; FLONG_BWRAP and the rest in the C), so the
// wrapper cannot point the launcher at another bwrap.
const paths: bwrap.Paths = .{
    .bwrap = std.fmt.comptimePrint("{s}", .{config.bwrap}),
    .init = std.fmt.comptimePrint("{s}", .{config.init}),
};
const pasta_path = std.fmt.comptimePrint("{s}", .{config.pasta});
const maps: ns.Programs = .{
    .newuidmap = std.fmt.comptimePrint("{s}", .{config.newuidmap}),
    .newgidmap = std.fmt.comptimePrint("{s}", .{config.newgidmap}),
};

// No SIGSEGV handler, and SIGPIPE left as it came for main to ignore, as
// the C does (start.zig:687-719).
pub const std_options: std.Options = .{
    .enable_segfault_handler = false,
    .keep_sigpipe = true,
};

/// "flong-launch: internal error: <msg>", 125. The main process then skips
/// the teardown: the sweeper releases the session, the watchdog restores
/// the terminal and --die-with-parent ends the payload (ZIG.md, "Per
/// binary"). In the mount helper, a fork of this process, 125 reads as a
/// failed mount (flong-launch.c:570-575).
pub const panic = std.debug.FullPanic(msg.onPanic(not_run));

/// The session's cgroup leaves, in cgroup.leaf_names' order
/// (flong-cgroup.h's FL_LEAF_*).
const sandbox = 0;
const hooks = 1;
const pasta_leaf = 2;

/// struct launch (flong-launch.c:47-80): everything a launch holds.
const Launch = struct {
    /// The launch's allocations, never freed (flong-launch.c:97-99).
    arena: Allocator,
    s: *const spec.Spec,

    // What the prologue made, held until the process exits.
    state: record.State,
    cache: fdt.Held(.dir),
    /// the keep-fds, adopted after the spec, until bwrap has them
    keep: []const fdt.Fd(.inherited),

    tty: tty.Tty = .{},
    holder: ?cgroup.Holder = null,
    rec: ?record.Record = null,
    /// U1, from ns.create, until the process exits
    u1: ?fdt.Held(.userns) = null,
    cg: ?cgroup.Session = null,
    /// the spec's protect paths, the state directory and the holder, made
    /// canonical
    protect: []const [:0]const u8 = &.{},

    /// read end of bwrap's --info-fd, open until exit (quirk 31)
    info: ?fdt.Held(.pipe_r) = null,
    /// read end of flong-init's ready pipe, until the mount helper has it
    ready: ?fdt.Fd(.pipe_r) = null,
    /// write end of the gate
    gate: ?fdt.Fd(.pipe_w) = null,
    bwrap: ?proc.Child = null,
    /// bwrap's child: flong-init, the session's pid 1
    leader_pid: sys.pid_t = 0,
    leader: ?fdt.Held(.pidfd) = null,
    /// the session's network namespace
    netns: ?fdt.Held(.netns) = null,
    helper: ?proc.Child = null,
    hook: ?proc.Child = null,
    /// the spawned pasta; its daemon lives on in the pasta leaf
    pasta: ?proc.Child = null,
    /// the memfd pasta writes its pid into
    pasta_pid_file: ?fdt.Held(.file) = null,

    /// the payload may have run: its status is the launch's
    gate_opened: bool = false,
};

pub fn main() noreturn {
    // Ordering checkpoint 1, the prologue (flong-launch.c:847-925). The
    // time is main's first statement: `launcher-start` is stamped now and
    // printed once the trace flag is known (quirk 45). Nothing here changes
    // directory: relaunch's argv may be relative to the wrapper's (quirk
    // 30).
    const start = sys.clockRealtime();
    msg.prog = "flong-launch";
    msg.mode = .cut;

    // 1. Signals are read from a signalfd, so every wait can end on one as
    // an event, and none interrupts a step half done. They are blocked now
    // and stay queued; the signalfd is made after the spec is read, so
    // that its number is never one a keep-fd names: a keep-fd the wrapper
    // does not hold would otherwise pass as open (:857-873). SIGPIPE is
    // ignored. An ignored SIGCHLD survives execve, and under it the kernel
    // reaps our children itself: waitid would then say ECHILD, and a
    // helper's or a hook's failure would be lost (:874-877).
    const old_mask = sig.block() catch proc.exit(not_run);
    sig.ignorePipe();
    sig.defaultChld();

    // 2. The spec, refusing root first; nothing is in the descriptor table
    // yet. Its strings are argv's, its arrays in an arena over
    // page_allocator that lives as long as the process (:879-881).
    var arena_state: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    const arena = arena_state.allocator();
    const s = spec.parse(arena, sys.argv()) catch proc.exit(not_run);

    // 3. The keep-fds into the table, which the spec checked open by
    // F_GETFD: kept by bwrap's spawn, closed right after it (checkpoint 2),
    // and kept by closeUntracked below (:909-921).
    const keep = arena.alloc(fdt.Fd(.inherited), s.keep_fds.len) catch {
        msg.sayErrno(.NOMEM, "malloc", .{});
        proc.exit(not_run);
    };
    for (s.keep_fds, keep) |n, *h| h.* = fdt.adoptInherited(n) catch {
        msg.say("keep-fd {d}: too many open descriptors", .{n});
        proc.exit(not_run);
    };

    // 4. The signalfd, after the spec and the keep-fds (:882-886).
    sig.openSignalfd() catch proc.exit(not_run);

    // 5. The trace flag is known only now; the stage is when main began
    // (:887-889).
    msg.tracing = s.trace;
    msg.traceAt(start, "launcher-start");

    // 6. DESIGN.md's step 3: the state directory and its sessions/
    // (:891-893).
    const state = prologue.stateOpen(s.state) catch proc.exit(not_run);

    // 7. Step 4, before inherited descriptors are closed: a cold wrapper's
    // own shared lock on the cache must not go before this one is held.
    // Swept: relaunch, or 75. A terminating signal ends the wait for a
    // cache being swept, and the launch then exits the way teardown would
    // say (:895-907).
    const cache = switch (prologue.cacheLock(s.cache) catch |err| proc.exit(switch (err) {
        error.Aborted => 128 + sig.abort_signal,
        error.Reported => not_run,
    })) {
        .locked => |h| h,
        .swept => proc.exit(prologue.relaunch(arena, s.cache, s.relaunch, old_mask, @ptrCast(sys.environ().ptr))),
    };
    msg.trace("cache-locked");

    // 8. Step 5: whatever the wrapper held that bwrap-args do not name. The
    // table holds exactly the C's keep list here: the keep-fds, the
    // signalfd, the state and sessions directories and the cache
    // (:909-924).
    prologue.closeUntracked() catch proc.exit(not_run);

    var l: Launch = .{ .arena = arena, .s = &s, .state = state, .cache = cache, .keep = keep };
    proc.exit(teardown(&l, run(&l)));
}

/// What childpid.wait reads: the info pipe, waited for with bwrap's exit
/// (await_or_bwrap, flong-launch.c:414-448).
const Info = struct {
    info: fdt.Held(.pipe_r),
    bwrap: fdt.Fd(.pidfd),

    pub fn ready(self: Info) sig.Error!bool {
        return try sig.awaitFdOrExit(self.info, self.bwrap) == .ready;
    }

    pub fn read(self: Info, buf: []u8) sys.Result(usize) {
        return self.info.read(buf);
    }
};

/// The mount helper's life, in the fork child (flong-launch.c:533-557 and
/// phase 4's shim, deleted in L5): mount.run, then 0, or 1
/// having said why; a panic says one line and exits 125, which the launcher
/// reads as a failed mount too. Nothing is freed: exit owns everything
/// (flong-mount.c:3-5).
fn mountHelper(job: mount.Job) noreturn {
    mount.run(&job) catch proc.exit(1);
    proc.exit(0);
}

/// Steps 6 to 18 of DESIGN.md, "The launch, in order" (flong-launch.c:
/// 709-767): bwrap's status once the gate has opened, or the first failure,
/// said where it happened (error.Reported), or a terminating signal
/// (error.Aborted). What it makes is in `l` as soon as it exists, for the
/// teardown. Ordering checkpoints 2, 3 and 5 are here, in line.
fn run(l: *Launch) sig.Error!u8 {
    const s = l.s;

    // 6. The foreground, relay or passthrough, the pty (:713-714).
    try tty.prepare(&l.tty, s.container, s.uid);

    // 7. nsdelegate; the holder, found or started (:716-718).
    try cgroup.checkNsdelegate(l.arena);
    l.holder = try cgroup.holderFind(l.arena, s.holder, s.holder_start, s.limits.len > 0);
    const holder = &l.holder.?;

    // 8. The inline sweep (:720-722).
    _ = try record.sweep(l.state.sessions, holder);
    msg.trace("swept");

    // 9. The record, locked, naming the cgroup the session will have
    // (:724-730).
    const cg_path = try cgroup.sessionPath(holder, s.container, s.machine);
    l.rec = try record.create(l.state.sessions, holder, s.machine, s.post_stop, cg_path.slice());
    msg.trace("recorded");

    // 10. U1, then U2 (:732-733). U1 is held until exit; U2 is bwrap's
    // alone, and goes in checkpoint 2. The mount helper's job takes U1 as
    // the owned handle ns made, of which `outer` is the held copy: the
    // fork body keeps it and closes nothing (flong-mount.c:3-5).
    const two = try ns.create(l.arena, .{ .uidmap = s.uidmap, .gidmap = s.gidmap, .nested_userns = s.nested_userns }, maps);
    const outer = two.u1.holdUntilExit();
    l.u1 = outer;

    // 11. The session cgroup, its limits and leaves (:735-738).
    l.cg = try cgroup.sessionCreate(holder, s.container, s.machine, s.limits);
    const cg = &l.cg.?;
    msg.trace("cgroup-made");

    // 12a. The protected paths, before bwrap, so nothing between child-pid
    // and the helper's fork but the fork itself (:740-743).
    l.protect = try prologue.protectPaths(l.arena, s.protect, s.state, holder.path.slice());

    // 12b. bwrap, in the sandbox leaf (:745-746), with ordering checkpoint 2.
    var ends: bwrap.ChildEnds = .{ .u2 = two.u2, .keep = l.keep };
    const spawned = bwrap.spawn(l.arena, s, paths, outer, l.tty.relay, tty.stdio(&l.tty), cg.leaf[sandbox].?, &ends);
    if (spawned) |b| {
        l.bwrap = b.child;
        l.info = b.info_r.holdUntilExit();
        l.ready = b.ready_r;
        l.gate = b.gate_w;
        // bwrap has the pty's slave: the relay sees EIO once every process
        // of the session has let it go (:394).
        tty.spawned(&l.tty);
    } else |_| {}
    // Checkpoint 2: the child's ends go at once, whether or not the spawn
    // succeeded, in flong-launch.c:396-408's order. A copy the launcher
    // kept of a write end would hide bwrap's death from the info and ready
    // readers, and one of the gate's read end would never let flong-init
    // see EOF.
    // 1. The info pipe's write end.
    if (ends.info_w) |h| h.close();
    // 2. The ready pipe's write end.
    if (ends.ready_w) |h| h.close();
    // 3. The gate's read end.
    if (ends.gate_r) |h| h.close();
    // 4. The seccomp programs opened.
    for (ends.seccomp) |h| h.close();
    // 5. U2.
    ends.u2.close();
    // 6. The keep-fds.
    for (ends.keep) |h| h.close();
    _ = try spawned;
    const bw = l.bwrap.?;

    // 13. --info-fd until child-pid; bwrap's exit also ends the wait. The
    // leader's pidfd and network namespace are held, and leader= appended
    // to the record (:748-750, 485-523).
    const pid = try childpid.wait(Info{ .info = l.info.?, .bwrap = bw.pidfd });
    l.leader_pid = pid;
    const leader_fd = switch (fdt.pidfdOpen(pid) catch return msg.refuse("the session's pid 1 ({d}): too many open descriptors", .{pid})) {
        .ok => |h| h,
        .err => |e| {
            // fl_pidfd_open says a failure but ESRCH, and the caller says
            // it again (flong-util.c:326-334, flong-launch.c:514-516).
            if (e != .SRCH) msg.sayErrno(e, "pidfd_open {d}", .{pid});
            return msg.fail(e, "the session's pid 1 ({d})", .{pid});
        },
    };
    // Held, as U1 is; the mount helper's job takes the owned handle.
    const leader = leader_fd.holdUntilExit();
    l.leader = leader;
    const netns = (try msg.check(fdt.openNetns(pid), "open /proc/{d}/ns/net", .{pid})).holdUntilExit();
    l.netns = netns;
    try l.rec.?.setLeader(pid);
    msg.trace("bwrap-child");

    // 14a. The mount helper, forked into the sandbox leaf at child-pid, so
    // it prepares every source while bwrap is still building the root; it
    // touches the session's mount namespace only after the ready byte,
    // which it reads itself. It keeps U1, the ready pipe and the leader's
    // pidfd and nothing else: a copy of the record's lock there would keep
    // a dead session alive for the sweep (:527-557).
    const ready = l.ready.?;
    l.helper = try proc.fork(.{ .cgroup = cg.leaf[sandbox].?, .keep = &.{ outer.any(), ready.any(), leader.any() } }, mount.Job{
        .u1 = two.u1,
        .leader = leader_fd,
        .ready = ready,
        .mounts = s.mounts,
        .uid = s.uid,
        .gid = s.gid,
        .home = s.home,
        .protect = l.protect,
    }, mountHelper);
    // Checkpoint 3: the helper holds the only read end now, so it alone
    // sees the ready byte, or EOF when bwrap dies first (:554-556).
    ready.close();
    l.ready = null;

    // 14b. The helper waited for, bwrap's exit ending the wait too. The gate
    // opens only when every mount, /sys and /run's read-only remount are
    // done; the helper said why when not (:559-577).
    if (try sig.awaitFdOrExit(l.helper.?.pidfd, bw.pidfd) == .exited)
        return msg.refuse("bwrap exited before the session was ready; the payload does not run", .{});
    const mounted = try l.helper.?.await();
    l.helper = null;
    if (mounted != 0) return msg.refuse("the session's mounts failed; the payload does not run", .{});
    msg.trace("mounts-done");

    // 15. postStart in the hooks leaf, waited for, with $leader, $userns,
    // $netns and $machine; its environment is pasta's too (quirk 3)
    // (:579-620).
    var envp: ?hook.Envp = null;
    const self_pid = sys.getpid();
    if (try hook.build(l.arena, s, sys.environ(), .{ .leader = pid, .self_pid = self_pid, .machine = s.machine }, outer, netns, cg.leaf[hooks].?)) |built| {
        var h = built;
        envp = h.envp;
        l.hook = try h.spawn.start();
        const st = try l.hook.?.await();
        l.hook = null;
        try hook.done(st);
    }

    // 16. pasta in the pasta leaf, ready when the spawned pasta exits 0
    // (:622-675).
    if (try pasta.build(l.arena, s, pasta_path, self_pid, outer, pid, envp, cg.leaf[pasta_leaf].?)) |built| {
        var p = built;
        l.pasta_pid_file = p.pid_file;
        l.pasta = try p.start();
        const st = try l.pasta.?.await();
        l.pasta = null;
        try pasta.done(st);
    }

    // 17. Checkpoint 5, the gate (:677-703). A terminating signal that
    // arrived since the last wait is still queued on the signalfd. Before
    // the gate it aborts the launch, as it would have during a wait; after
    // the gate, tty.wait would forward it to a payload that had only just
    // started. sig.take takes it off the queue, which costs no wait, so the
    // teardown's waits end only on a signal that comes later. A SIGWINCH
    // taken there or in any earlier wait was dropped, so the window size is
    // copied once more after it: a resize from here on is tty.wait's.
    // 1. The terminal: its modes saved, the watchdog, then raw (relay).
    try tty.start(&l.tty, leader);
    // 2. The queued signals.
    _ = try sig.take(0);
    // 3. The window size.
    tty.resize(&l.tty);
    // 4. The byte.
    const gate = l.gate.?;
    const w = write: while (true) {
        switch (gate.write("g")) {
            .ok => |n| break :write n,
            .err => |e| if (e != .INTR) return msg.fail(e, "open the gate", .{}),
        }
    };
    if (w != 1) return msg.refuse("open the gate", .{});
    gate.close();
    l.gate = null;
    // 5. Only then is the payload's status the launch's.
    l.gate_opened = true;
    msg.trace("gate-open");

    // 18. The wait for bwrap; tty.wait leaves bwrap unreaped, and the
    // teardown reaps it with the rest (:761-766).
    const st = try tty.wait(&l.tty, bw, leader);
    msg.trace("bwrap-exited");
    return st;
}

/// reap (flong-launch.c:769-778): a child spawned or forked and not yet
/// reaped, reaped now; its pidfd closed even when the wait was cut short (a
/// signal during teardown). False when it was.
fn reap(child: *?proc.Child) bool {
    const c = child.* orelse return true;
    child.* = null;
    _ = c.await() catch {
        c.release();
        return false;
    };
    return true;
}

/// The one teardown path, whatever stage the launch reached (DESIGN.md,
/// "Teardown"; flong-launch.c:780-845). Each step happens only for what
/// exists. When a wait is cut short (a signal during teardown), the session
/// may not be empty yet: then postStop does not run here and the record is
/// closed, not removed, so the sweeper, woken by that close, kills, waits,
/// runs postStop and removes. The status: bwrap's once the gate opened,
/// else 128+n for a terminating signal, else 125.
fn teardown(l: *Launch, result: sig.Error!u8) u8 {
    // Ordering checkpoint 6, in flong-launch.c:785-845's order.
    var settled = true;

    // 1. The terminal: hooks and postStop then print to a cooked one.
    tty.finish(&l.tty);

    // 2. The gate: flong-init reads EOF and exits 125, and the payload
    // never runs.
    if (l.gate) |g| g.close();
    l.gate = null;

    // 3. Kill the session, reap every child (short-circuiting: the rest
    // stay zombies until exit, quirk 7), and wait for the sandbox and hooks
    // leaves to empty.
    if (l.cg) |*cg| {
        cgroup.kill(cg) catch {
            settled = false;
        };
        if (!reap(&l.bwrap) or !reap(&l.helper) or !reap(&l.hook) or !reap(&l.pasta))
            settled = false;
        for ([_]usize{ sandbox, hooks }) |leaf| {
            if (!settled) break;
            cgroup.waitEmpty(cg.leaf[leaf].?) catch {
                settled = false;
            };
        }
    }

    // 4. postStop. A failing one is reported and does not change the status
    // (quirk 6); an aborted one keeps poststop= in the record, which is
    // closed, so the sweeper runs it again.
    if (l.rec) |*rec| {
        if (settled and l.s.post_stop != null) {
            if (record.poststop(l.s.post_stop.?, l.s.machine)) |_| {
                if (rec.poststopDone()) |_| {
                    msg.trace("poststop-done");
                } else |_| settled = false;
            } else |_| settled = false;
        }
    }

    // 5. Fixed forwardPorts bind host ports: pasta must have let them go
    // before the next launch binds them again. Nothing else waits for
    // pasta, which takes 20-40 ms to remove its tap device.
    if (l.cg) |*cg| {
        if (settled and l.s.pasta_wait) {
            if (cgroup.waitEmpty(cg.leaf[pasta_leaf].?)) |_| {
                msg.trace("pasta-gone");
            } else |_| settled = false;
        }
    }

    // 6. Remove the cgroup and the record, or close the record for the
    // sweep; then the session's descriptors.
    var removed = true;
    if (l.cg) |*cg| removed = settled and (cgroup.remove(cg) catch .busy) == .gone;
    if (l.rec) |*rec| {
        if (removed) rec.remove() else rec.closeKeeping();
    }
    // The C tests `cg.fd >= 0 || rec.fd >= 0` (:836-837) after rec_remove or
    // rec_close has set rec.fd to -1 (flong-record.c:416, 422), so only the
    // cgroup decides: a launch that made the record but no cgroup (U1, U2
    // or the session cgroup failed) prints no `released`.
    if (l.cg != null) msg.trace("released");
    l.rec = null;
    if (l.cg) |*cg| cg.closeAll();
    l.cg = null;

    // 7. The status.
    if (l.gate_opened) {
        if (result) |st| return st else |_| {}
    }
    if (sig.abort_signal != 0) return 128 + sig.abort_signal;
    return not_run;
}
