//! flong launch: one session, from a declaration to the payload's exit
//! (DESIGN.md, "Files"; the Zig port's L4; launcher/flong-launch.c of
//! a7919be, whose line numbers these are). `flong launch DECL.zon|NAME [--
//! ARGS...]`, or a declaration's link `NAME -> flong` (src/main.zig), loads
//! the declaration and judges it as flong check does; launch/assemble.zig
//! then does, in its order, what rootless-wrapper.bash did before
//! STANDALONE.md's S3 and builds the spec as a value (DESIGN.md, "The
//! input contract"). `launch` is ordering checkpoint 1, that prologue and
//! steps 1-5 of DESIGN.md's "The launch, in order", then
//! `proc.exit(teardown(&l, run(&l)))`: `run` is steps 6-18, returning at
//! the first failure, and `teardown` step 19, undoing whatever exists
//! whatever stage was reached (flong-launch.c:1-19).
//!
//! Every resource a launch holds is in `Launch`: a handle that may not
//! exist yet is optional, one kept until the process exits is `Held` (the
//! state and sessions directories, the cache, U1, the info pipe's read end,
//! the leader's pidfd, the network namespace, pasta's pid file; DESIGN.md,
//! "Conventions"), and each child is a `?proc.Child`, null once it
//! is reaped (flong-launch.c:47-80). The payload runs only once the gate
//! byte is written, and the gate is written only after every earlier step
//! succeeded: flong init reads EOF otherwise and exits 125.
//!
//! The steps are modules: spec (the spec's checks, bwrap's argv), ns (U1
//! and U2), cgroup (the holder and the session), record (the state
//! directory, the sweep, the record, postStop), tty (the terminal and the
//! wait for bwrap), mount (the mount helper, a fork body here), passwd
//! (cgroup's refusal), and src/launch/: assemble (the prologue that builds
//! the spec) and its pieces, prologue (the relaunch, the cache, the close
//! of what was inherited, the protected paths), bwrap (its spawn),
//! childpid (--info-fd), hook (postStart) and pasta. This file owns the
//! order: ordering checkpoints 1, 2, 3, 5 and 6 are `launch`, `run` and
//! `teardown`, each one linear function with numbered comments, never a
//! helper (checkpoint 4 is ns.zig's).
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
const decl = @import("decl");
const check = @import("check");
const assemble = @import("assemble");
const lookup = @import("lookup");

const Allocator = std.mem.Allocator;

/// A launch that did not reach its payload (DESIGN.md, "Exit codes";
/// flong-launch.c:43-45). It collides with a payload's own 125 (quirk 32,
/// kept).
const not_run = prologue.exit_not_run;

// The programs a launch runs, compiled in (-Dbwrap, -Dself, -Dpasta,
// -Dnewuidmap, -Dnewgidmap; FLONG_BWRAP and the rest in the C), so no
// caller can point the launcher at another bwrap. -Dself is this
// binary's own installed path, which bwrap runs as `flong init`.
const paths: bwrap.Paths = .{
    .bwrap = std.fmt.comptimePrint("{s}", .{config.bwrap}),
    .self = std.fmt.comptimePrint("{s}", .{config.self}),
};
const pasta_path = std.fmt.comptimePrint("{s}", .{config.pasta});
const maps: ns.Programs = .{
    .newuidmap = std.fmt.comptimePrint("{s}", .{config.newuidmap}),
    .newgidmap = std.fmt.comptimePrint("{s}", .{config.newgidmap}),
};
// What a declaration's prologue runs (-Dcache, -Dseccomp): module.nix's
// cache tool and the project policy's compiler.
const tools: assemble.Tools = .{
    .cache = std.fmt.comptimePrint("{s}", .{config.cache}),
    .seccomp = std.fmt.comptimePrint("{s}", .{config.seccomp}),
};

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
    /// the environment the hook adds to: the prologue's (assemble.zig), the
    /// caller's with what the prologue exported
    environ: []const [*:0]const u8,
    /// what pasta gets when no hook ran: `environ`, as the wrapper's exec
    /// handed it on (quirk 3)
    default_envp: hook.Envp,

    // What the prologue made, held until the process exits.
    state: record.State,
    cache: fdt.Held(.dir),

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
    /// read end of flong init's ready pipe, until the mount helper has it
    ready: ?fdt.Fd(.pipe_r) = null,
    /// write end of the gate
    gate: ?fdt.Fd(.pipe_w) = null,
    bwrap: ?proc.Child = null,
    /// bwrap's child: flong init, the session's pid 1
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

const usage = "usage: flong launch DECL.zon|NAME [-- ARGS...]";
const usage_status = 2;

/// `argv` is the kernel's whole, flong launch's own word at `at`, and
/// `envp` its environ, which a relaunch passes on. `flong launch
/// DECL.zon|NAME [-- ARGS...]` launches the declaration, a file when the
/// word has a '/' or ends in `.zon`, else a name (launch/lookup.zig);
/// anything else is a usage error, 2.
pub fn main(argv: []const [*:0]const u8, at: usize, envp: []const [*:0]const u8) noreturn {
    // The time is main's first statement: `prologue-start` is stamped now
    // and printed once the trace flag is known (quirk 45).
    const start = sys.clockRealtime();
    msg.prog = "flong launch";
    msg.mode = .cut;
    const own = argv[at..];
    if (own.len >= 2) {
        const w = std.mem.span(own[1]);
        if (isFile(w) or lookup.isName(w)) {
            if (own.len == 2) fromDeclaration(start, argv, w, &.{}, envp);
            if (std.mem.eql(u8, std.mem.span(own[2]), "--")) fromDeclaration(start, argv, w, own[3..], envp);
        }
    }
    msg.bare(usage, .{});
    proc.exit(usage_status);
}

/// A declaration named by its file: a '/' in it, or a `.zon` name.
fn isFile(w: []const u8) bool {
    return std.mem.indexOfScalar(u8, w, '/') != null or std.mem.endsWith(u8, w, ".zon");
}

/// A declaration's link, `NAME -> flong` (STANDALONE.md, "The
/// declaration's command"): argv[0]'s basename is its name, and every
/// argument after it is the launcher's, as `flong launch NAME -- ARGS`.
pub fn named(argv: []const [*:0]const u8, name: []const u8, envp: []const [*:0]const u8) noreturn {
    const start = sys.clockRealtime();
    msg.prog = "flong launch";
    msg.mode = .cut;
    fromDeclaration(start, argv, name, argv[1..], envp);
}

/// `what`'s declaration, loaded and judged as flong check judges it, then
/// launched (`launch`). A name that no directory has is said as
/// `flong: no declaration "NAME" (looked for PATH...)`, 2; a file that
/// cannot be read or parsed, or that flong check refuses, as flong check
/// says it, under "flong launch", 1.
fn fromDeclaration(start: sys.timespec, argv: []const [*:0]const u8, what: []const u8, args: []const [*:0]const u8, envp: []const [*:0]const u8) noreturn {
    var arena_state: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    const arena = arena_state.allocator();
    const path: [:0]const u8 = if (isFile(what)) arena.dupeZ(u8, what) catch outOfMemory() else switch (lookup.find(arena, what, envp) catch outOfMemory()) {
        .path => |p| p,
        .missing => |looked| {
            msg.prog = "flong";
            msg.mode = .whole;
            msg.say("no declaration \"{s}\" ({s})", .{ what, lookup.lookedFor(arena, looked) catch outOfMemory() });
            proc.exit(usage_status);
        },
    };
    msg.mode = .whole;
    const d = decl.load(arena, path) catch |err| switch (err) {
        error.Reported => proc.exit(prologue.exit_refused),
        error.OutOfMemory => outOfMemory(),
    };
    const refusals = check.validate(arena, &d) catch outOfMemory();
    for (refusals) |r| msg.say("{s}: {s}", .{ path, r });
    if (refusals.len > 0) proc.exit(prologue.exit_refused);
    launch(start, arena, &d, argv, args, envp);
}

fn outOfMemory() noreturn {
    msg.sayErrno(.NOMEM, "malloc", .{});
    proc.exit(prologue.exit_refused);
}

/// Ordering checkpoint 1 (flong-launch.c:847-925): the prologue, which
/// does the wrapper's work in its order (launch/assemble.zig), then the
/// launcher's own steps on the spec it assembled, as a value. The prologue
/// runs before the signals are blocked, as the wrapper ran before flong
/// launch; SIGCHLD's default comes first, so a command's status is seen
/// whatever the caller left it as. `argv` is the process's whole, a
/// relaunch's; the relaunch at the cache lock execs this binary with it
/// (quirk 2), as each of the prologue's own does. Nothing here changes
/// directory: `argv` may be relative to the caller's (quirk 30).
fn launch(start: sys.timespec, arena: Allocator, d: *const decl.Declaration, argv: []const [*:0]const u8, args: []const [*:0]const u8, envp: []const [*:0]const u8) noreturn {
    // 1. SIGCHLD's default, which an ignored one inherited through execve
    // is not: the commands' statuses would be lost, and under it the
    // kernel reaps our children itself, so waitid would say ECHILD
    // (:874-877).
    sig.defaultChld();

    // 2. The prologue: the caller, the workspace, the commands, the maps,
    // the prepared root and the payload's identity, then the spec. Its
    // refusals are the wrapper's, 1; the spec's, 125.
    msg.tracing = if (assemble.getenv(envp, "FLONG_TRACE")) |t| t.len > 0 else false;
    msg.traceAt(start, "prologue-start");
    const a = assemble.run(arena, d, .{ .argv = argv, .args = args, .environ = envp }, tools) catch |err| proc.exit(switch (err) {
        error.Reported, error.Aborted => prologue.exit_refused,
        error.NotRun => not_run,
    });
    const s = &a.spec;

    // 3. Signals are read from a signalfd, so every wait can end on one as
    // an event, and none interrupts a step half done. They are blocked now
    // and stay queued. SIGPIPE is ignored (:857-877).
    const old_mask = sig.block() catch proc.exit(not_run);
    sig.ignorePipe();

    // 4. The spec's checks, over the value, refusing root first
    // (spec.validate; :879-881).
    spec.validate(s) catch proc.exit(not_run);

    // 5. The signalfd (:882-886).
    sig.openSignalfd() catch proc.exit(not_run);

    // 6. The trace flag; the stage is when the launch proper began.
    msg.tracing = s.trace;
    msg.trace("launcher-start");

    // 7. DESIGN.md's step 3: the state directory and its sessions/
    // (:891-893).
    const state = prologue.stateOpen(s.state) catch proc.exit(not_run);

    // 8. Step 4, before the prologue's own shared lock goes: swept,
    // relaunch this binary with the process's argv. A terminating signal
    // ends the wait for a cache being swept, and the launch then exits the
    // way teardown would say (:895-907).
    const cache = switch (prologue.cacheLock(s.cache) catch |err| proc.exit(switch (err) {
        error.Aborted => 128 + sig.abort_signal,
        error.Reported => not_run,
    })) {
        .locked => |h| h,
        .swept => proc.exit(prologue.relaunchSwept(arena, s.cache, argv, old_mask, @ptrCast(envp.ptr))),
    };
    msg.trace("cache-locked");

    // 9. The cold path's shared lock, which held the cache from the
    // prepare to here, as the wrapper's descriptor did into flong launch.
    if (a.cold) |c| c.close();

    // 10. Step 5: whatever else was inherited. The table holds the
    // signalfd, the state and sessions directories and the cache
    // (:909-924).
    prologue.closeUntracked() catch proc.exit(not_run);

    var l: Launch = .{ .arena = arena, .s = s, .environ = a.environ, .default_envp = @ptrCast(a.environ.ptr), .state = state, .cache = cache };
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
    var ends: bwrap.ChildEnds = .{ .u2 = two.u2 };
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
    // readers, and one of the gate's read end would never let flong init
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
    // 6. The resolver's memfd.
    if (ends.resolv) |h| h.close();
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

    // 15. postStart's commands in the hooks leaf, in order, each waited
    // for, the first failure ending the launch, all with one environment:
    // $leader, $userns, $netns and $machine; it is pasta's too (quirk 3)
    // (:579-620).
    var envp: ?hook.Envp = null;
    const self_pid = sys.getpid();
    if (try hook.build(l.arena, s, l.environ, .{ .leader = pid, .self_pid = self_pid, .machine = s.machine }, outer, netns, cg.leaf[hooks].?)) |built| {
        envp = built.envp;
        for (built.spawns) |*sp| {
            l.hook = try sp.start();
            const st = try l.hook.?.await();
            l.hook = null;
            try hook.done(st);
        }
    }

    // 16. pasta in the pasta leaf, ready when the spawned pasta exits 0
    // (:622-675).
    if (try pasta.build(l.arena, s, pasta_path, self_pid, outer, pid, envp orelse l.default_envp, cg.leaf[pasta_leaf].?)) |built| {
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

    // 2. The gate: flong init reads EOF and exits 125, and the payload
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

    // 4. postStop's commands, in order, as the record lists them. A
    // failing one is reported, ends the list and does not change the status
    // (quirk 6); an aborted one keeps poststop= in the record, which is
    // closed, so the sweeper runs the list again.
    if (l.rec) |*rec| {
        if (settled and rec.poststopList() != null) {
            if (record.poststop(rec.poststopList().?, l.s.machine)) |_| {
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
