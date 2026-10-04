//! launch/assemble.zig: `flong launch DECL.zon`'s prologue (DESIGN.md,
//! "Launch sequence"), which does what rootless-wrapper.bash did, in its
//! order, and assembles the spec as a value (spec.Spec) for launch.zig to
//! hand to ordering checkpoint 1: no argv spec, no exec. `run` is that
//! order, one linear function with numbered comments, each step one of the
//! wrapper's sections (its line numbers are the wrapper's as it stood
//! before S3):
//!
//!   1  the caller and the runtime directory (:67-97)    caller.zig
//!   2  the signals and the session's name (:205-223)
//!   3  the workspace (:99-150)                          workspace.zig
//!   4  the caller's binds (:152-195)                    binds.zig
//!   5  the guard (:197-203), the project's policy
//!      (:205-223), the payload's `exec`                 cmd.zig
//!   6  the depth rule (:225-247)                        depth.zig
//!   7  the maps (:249-290)                              subid.zig
//!   8  the prepared root (:292-343)                     prepare.zig
//!   9  the payload's identity (:345-375), and the
//!      home `exec`'s files must be under                identity.zig
//!  10  $home/tmp (:377-389)                             hometmp.zig
//!  11  the spec (:391-474)                              resolv.zig
//!
//! Steps 1 to 10 are the wrapper's, and refuse as it did: under the
//! declaration's name (msg.prog), whole, and error.Reported, which the
//! launch exits 1 with (prologue.exit_refused). A command's own failure is
//! its own to explain, as the wrapper's `|| exit 1` left it. Step 11 is the
//! spec the wrapper handed flong launch: what it cannot say as a spec's
//! number is refused as the argv spec's parse refused it, "flong launch: spec:
//! ...", and error.NotRun, which the launch exits 125 with.
//!
//! The three points where the wrapper found its cache swept before it held
//! it (:314, 322, 352) relaunch flong with the process's own argv
//! (prologue.relaunchSelf), so a declaration's link name is looked up again.
//!
//! From step 2 on the session has a name, `$machine`, and every command
//! that sees it -- `workspace`, `binds`, `guard`, `seccompPolicy` and
//! `exec` -- may have staged something for it on the host that only
//! `postStop` releases: `binds` a kept overlay's layers, keyed by it. The
//! wrapper named the session after the guard; it is named before the
//! workspace now, so a consumer keys anything per launch by `$machine` and
//! finds it again in `postStop`, rather than inventing a name of its own
//! and sweeping what a crash left. So from there every way the
//! prologue ends but a spec releases it: a refusal, a signal, and a
//! relaunch, which runs the commands again under a new name, run postStop's
//! commands for this one first (`Early`), as the record would have; once
//! the spec is built, the launch takes that over (launch.zig). And the
//! signals the launch reads from its signalfd are blocked, and the
//! signalfd opened, at step 2 rather than after the prologue, so a
//! terminating signal during the commands or the prepare ends a wait and
//! is released from, where it would have killed the launcher outright. A
//! terminating signal still queued when a relaunch releases the name ends
//! the launch there, 128+n, rather than relaunching (`Early.beforeRelaunch`):
//! the relaunch would restore the mask with the signal already taken, and
//! run every command again as if the caller had not asked it to stop.
//! What the launcher cannot catch -- a SIGKILL, the OOM killer, a crash --
//! before the record exists leaves nothing that knows the name, and what
//! the commands staged for it stays (PLAN.md).
//!
//! The name is `<container>-<pid>-<16 hex digits of getrandom>`: the pid
//! keeps it apart from every other live launcher's, and 64 random bits
//! from every ended session's whose record a sweep has yet to release,
//! pid reused or not. A launch never meets its own name held, so the
//! record's refusal of a taken name is not a case `Early` has to tell
//! apart: whatever fails before the record runs postStop for the name.
//!
//! What the wrapper exported, the commands, the cache tool, flong-seccomp
//! and the launch see in their environment, each from the step that set
//! it on: XDG_RUNTIME_DIR, workspace, workspace_mode, binds, machine, uid,
//! gid and home, with the declaration's commandPath in front of PATH, as
//! writeShellApplication's runtimeInputs put `path` there. The wrapper
//! also un-exported the header's names and its own (:25-32, module.nix's
//! `export -n`), so that a variable of the caller's named, say, `cache`
//! did not reach the launch; there is no header now, and every variable of
//! the caller's but those reaches the commands and the launch as it came.
//!
//! The warm path forks nothing the declaration did not ask for: its
//! commands, and on the cold path the cache tool; everything else is
//! reads, as the wrapper's builtins were.

const std = @import("std");
const sys = @import("sys");
const fdt = @import("fd");
const msg = @import("msg");
const sig = @import("sig");
const spec = @import("spec");
const mount = @import("mount");
const decl = @import("decl");
const check = @import("check");
const prologue = @import("prologue");
const caller = @import("caller");
const workspace = @import("workspace");
const cmd = @import("cmd");
const binds = @import("binds");
const subid = @import("subid");
const prepare = @import("prepare");
const identity = @import("identity");
const depth = @import("depth");
const hometmp = @import("hometmp");
const record = @import("record");
const resolv = @import("resolv");

const Allocator = std.mem.Allocator;
const Declaration = decl.Declaration;

/// The programs the prologue runs, compiled into flong (-Dcache,
/// -Dseccomp): module.nix's cache tool and the project policy's compiler.
pub const Tools = struct {
    cache: [:0]const u8,
    seccomp: [:0]const u8,
};

/// What the process was started with.
pub const Process = struct {
    /// the whole argv, as the kernel gave it: what a relaunch execs again
    argv: []const [*:0]const u8,
    /// the launcher's own arguments, after the declaration's name (and
    /// its "--"): every command's, the payload's and postStart's
    args: []const [*:0]const u8,
    /// the environment it started with (main's environ)
    environ: []const [*:0]const u8,
};

/// A session's spec, as the wrapper would have handed it to flong launch.
pub const Assembled = struct {
    spec: spec.Spec,
    /// The cache, open and locked shared, when the cold path prepared it:
    /// the wrapper kept its descriptor open into flong launch (:309-312),
    /// and the launch closes it once checkpoint 1 holds the cache itself.
    cold: ?fdt.Dir,
    /// The environment the launch goes on with, the hooks' and pasta's
    /// base: the caller's, with what the wrapper exported.
    environ: []const [*:0]const u8,
    /// The signal mask before step 5 blocked the launch's signals, which a
    /// relaunch restores.
    old_mask: u64,
};

pub const Error = error{
    /// the prologue refused, having said why: exit 1
    Reported,
    /// a terminating signal ended a wait
    Aborted,
    /// the spec refused, having said why: exit 125
    NotRun,
};

/// The declaration's `commands` environment, as each step exports more.
const Env = struct {
    gpa: Allocator,
    base: []const [*:0]const u8,
    vars: std.ArrayList(cmd.Var) = .empty,

    fn set(e: *Env, name: []const u8, value: []const u8) Error!void {
        for (e.vars.items) |*v| {
            if (std.mem.eql(u8, v.name, name)) {
                v.value = value;
                return;
            }
        }
        e.vars.append(e.gpa, .{ .name = name, .value = value }) catch return oom();
    }

    fn envp(e: *const Env) Error!cmd.Envp {
        return cmd.environ(e.gpa, e.base, e.vars.items);
    }
};

/// postStop's commands for a session named before its record exists
/// (the header): run once, from the first failure, or before a relaunch,
/// and never again.
pub const Early = struct {
    post_stop: []const spec.Command,
    machine: []const u8,
    done: bool = false,

    /// postStop's commands for `machine`, as the teardown and the sweep
    /// run them (record.poststopCommands), unless they already ran. A
    /// terminating signal already queued is taken off first, as the
    /// launch's teardown finds it taken, so it does not end postStop's
    /// first wait: it is the launch's status still (sig.abort_signal).
    pub fn runPostStop(e: *Early) void {
        if (e.done) return;
        e.done = true;
        if (sig.fd != null) while (true) {
            const more = sig.take(0) catch |err| switch (err) {
                // One taken; there may be more behind it.
                error.Aborted => continue,
                // The signalfd cannot be read, and postStop's waits will
                // say so if it matters.
                error.Reported => break,
            };
            if (!more) break;
        };
        record.poststopCommands(e.post_stop, e.machine) catch |err| switch (err) {
            // A second signal ended a command's wait: it was killed, and
            // the signal is the launch's status (sig.abort_signal). There
            // is no record for a sweep to run the list again from.
            error.Aborted => return,
        };
    }

    /// runPostStop before a relaunch, which names the session anew and
    /// runs every command again: error.Aborted, the launch's status 128+n
    /// (sig.abort_signal), when a terminating signal was queued, or
    /// arrived while postStop ran. runPostStop takes it off the signalfd so
    /// postStop's waits run, and the relaunch would restore the mask with
    /// nothing pending: the caller's ^C would be lost, and the launch go on
    /// under a new name.
    pub fn beforeRelaunch(e: *Early) error{Aborted}!void {
        e.runPostStop();
        if (sig.abort_signal != 0) return error.Aborted;
    }
};

/// The wrapper's order (the table above), for the declaration `d`, whose
/// check.validate has passed, run by `p` with `tools`. Everything is
/// `gpa`'s, an arena's that lives as long as the process.
pub fn run(gpa: Allocator, d: *const Declaration, p: Process, tools: Tools) Error!Assembled {
    msg.prog = d.name;
    msg.mode = .whole;
    const args = p.args;

    // 1. The caller: uid 0 and primary gid 0 refused, the passwd name, and
    // /run/user/$UID the caller's (:67-97). XDG_RUNTIME_DIR is exported
    // as it, and `commandPath` goes in front of PATH, as the wrapper's
    // runtimeInputs put `path` there.
    const who = try caller.get(gpa);
    var env: Env = .{ .gpa = gpa, .base = p.environ };
    if (d.commandPath.len > 0) try env.set("PATH", try commandPath(gpa, d.commandPath, getenv(p.environ, "PATH")));
    try env.set("XDG_RUNTIME_DIR", who.runtime);
    const dests = try normAll(gpa, check.declaredDests(gpa, d) catch return oom());

    // 2. The launch's signals, blocked and read from the signalfd from
    // here on, SIGPIPE ignored (the header); the session's name, exported
    // for every command from the workspace's on, and released from
    // whatever ends the prologue now.
    const old_mask = try sig.block();
    sig.ignorePipe();
    try sig.openSignalfd();
    const machine = std.fmt.allocPrintSentinel(gpa, "{s}-{d}-{x:0>16}", .{ d.container, sys.getpid(), try randomWord() }, 0) catch return oom();
    const post_stop = postStopCommands(gpa, d) catch return oom();
    var early: Early = .{ .post_stop = post_stop, .machine = machine };
    errdefer early.runPostStop();
    try env.set("machine", machine);

    // 3. The workspace: the caller's directory, or what the workspace
    // command prints, with its :ro or :rw; resolved, then refused as
    // refuse_path refuses it (:99-150).
    const raw = if (d.workspace) |w| blk: {
        const o = try cmd.capture(gpa, w, args, try env.envp(), cmd.output_max);
        if (o.status != 0) return error.Reported;
        break :blk cmd.substitute(o.out);
    } else try workspace.current(gpa);
    const ws = try workspace.resolve(gpa, raw, dests);
    try env.set("workspace", ws.path);
    try env.set("workspace_mode", @tagName(ws.mode));

    // 4. The caller's binds, the commands' outputs concatenated: merged,
    // folded into the workspace, $binds (:152-195); a kept overlay's line
    // among them.
    const b = if (d.binds.len > 0)
        try binds.parse(gpa, try cmd.outputOf(gpa, d.binds, args, try env.envp()), ws, dests)
    else
        binds.none(ws);
    try env.set("workspace_mode", @tagName(b.workspace_mode));
    try env.set("binds", b.text);

    // 5. The guard: each command must pass, in order (:197-203); the
    // project's policy, compiled when it says anything (:205-223); the
    // payload's `exec`, when it has one.
    if (d.guard.len > 0) try cmd.pass(gpa, d.guard, args, try env.envp());
    var tier_bpf: []const u8 = d.seccompTierFilter orelse "";
    if (d.seccompPolicy.len > 0) {
        const policy = cmd.substitute(try cmd.outputOf(gpa, d.seccompPolicy, args, try env.envp()));
        if (!blank(policy)) tier_bpf = try compilePolicy(gpa, d, tools, who.state, policy, try env.envp());
    }
    const exec: ?cmd.Exec = if (d.exec) |x| try execOf(gpa, d, x, args, try env.envp()) else null;

    // 6. The depth rule, for the workspace and the caller's writable binds
    // (:225-247).
    const hosts = check.maskHosts(gpa, d) catch return oom();
    const masks = gpa.alloc(depth.Mask, d.masks.len) catch return oom();
    for (masks, d.masks, hosts) |*m, path, host| m.* = .{ .path = path, .host = host };
    const roots = gpa.alloc(depth.Root, b.list.len) catch return oom();
    // An overlay is not checked: a rename under it moves only where the
    // container's own writes land.
    for (roots, b.list) |*r, x| r.* = .{ .path = x.path, .rw = x.mode == .rw and x.layers == null };
    if (depth.check(.{ .path = ws.path, .rw = b.workspace_mode == .rw }, roots, masks)) |h|
        return msg.refuse(depth.refusal, .{ h.mask, h.hidden, h.root });

    // 7. The maps: the caller's first /etc/subuid and /etc/subgid entry
    // 65536 wide, each id map built from it (:249-290).
    const sub = subid.find(gpa, readOrEmpty(gpa, "/etc/subuid"), who.name, who.uid) catch return oom();
    const gsub = subid.find(gpa, readOrEmpty(gpa, "/etc/subgid"), who.name, who.uid) catch return oom();
    if (sub == null or gsub == null)
        return msg.refuse("{s} has no /etc/subuid and /etc/subgid range 65536 wide: give it users.users.{s}.subUidRanges and subGidRanges, or autoSubUidGidRange = true", .{ who.name, who.name });
    const umap = try mapOf(d.cuid, who.uid, sub.?);
    const gmap = try mapOf(d.cgid, who.gid, gsub.?);

    // 8. The prepared root: the cache the maps name, prepared on the cold
    // path, superseded generations collected; swept before it was held,
    // relaunched (:292-343).
    const base = d.closure[if (std.mem.lastIndexOfScalar(u8, d.closure, '/')) |i| i + 1 else 0..];
    const paths = prepare.paths(gpa, who.state, d.container, base[0..@min(8, base.len)], d.steps8, d.cuid, d.cgid, sub.?.start, gsub.?.start, who.gid) catch return oom();
    const tool: prepare.Tool = .{
        .path = tools.cache,
        .map_args = prepare.mapArgs(gpa, umap.slice(), gmap.slice()) catch return oom(),
        .envp = try env.envp(),
    };
    const closure = gpa.dupeZ(u8, d.closure) catch return oom();
    const user = gpa.dupeZ(u8, d.user) catch return oom();
    const cold: ?fdt.Dir = switch (try prepare.ensure(gpa, who.state, d.container, paths, tool, closure, user)) {
        .warm => null,
        .cold => |cfd| cfd,
        .swept => {
            try early.beforeRelaunch();
            return prologue.relaunchSelf(gpa, p.argv, old_mask, @ptrCast(p.environ.ptr));
        },
    };

    // 9. The payload's identity, from the prepared root's passwd and
    // group; swept, relaunched (:345-375).
    const files = switch (try identity.open(gpa, paths.prepared)) {
        .files => |f| f,
        .swept => {
            try early.beforeRelaunch();
            return prologue.relaunchSelf(gpa, p.argv, old_mask, @ptrCast(p.environ.ptr));
        },
    };
    const id = try identity.of(gpa, files, paths.prepared, d.user, d.cuid, d.cgid);
    try env.set("uid", id.uid);
    try env.set("gid", id.gid);
    try env.set("home", id.home);
    // `exec`'s files, now that the home they must be under is known.
    const seeded: []const spec.File = if (exec) |x| try homeFiles(gpa, d.exec.?, id.home, x.files) else &.{};

    // 10. $home/tmp, a private tmpfs unless a bind or a declared mount is
    // there (:377-389).
    const bind_paths = gpa.alloc([]const u8, b.list.len) catch return oom();
    for (bind_paths, b.list) |*x, y| x.* = y.path;
    var declared_binds: std.ArrayList([]const u8) = .empty;
    for (d.containerMounts) |cm| {
        if (cm.kind == .bind_ro or cm.kind == .bind_rw)
            declared_binds.append(gpa, check.norm(gpa, cm.dest) catch return oom()) catch return oom();
    }
    const home_tmp = hometmp.private(id.home, ws.path, bind_paths, declared_binds.items, dests);
    const home_tmp_path = std.fmt.allocPrintSentinel(gpa, "{s}/tmp", .{id.home}, 0) catch return oom();

    // 11. The spec, the launcher's input: from here a refusal is the
    // spec's, as flong launch said it (:391-474).
    msg.prog = "flong launch";
    msg.mode = .cut;
    const environ = cmd.environ(gpa, env.base, env.vars.items) catch return error.NotRun;
    return .{
        .spec = try specOf(gpa, d, p, .{
            .who = who,
            .ws = ws,
            .b = b,
            .machine = machine,
            .post_stop = post_stop,
            .tier_bpf = tier_bpf,
            .umap = umap.slice(),
            .gmap = gmap.slice(),
            .cache = paths.cache,
            .id = id,
            .home_tmp = if (home_tmp) home_tmp_path else null,
            .exec = exec,
            .files = seeded,
        }),
        .cold = cold,
        .environ = @ptrCast(environ[0..envLen(environ)]),
        .old_mask = old_mask,
    };
}

/// How many entries an envp has before its null.
fn envLen(envp: cmd.Envp) usize {
    var n: usize = 0;
    while (envp[n] != null) n += 1;
    return n;
}

/// What steps 1 to 10 found, for the spec.
const Found = struct {
    who: caller.Caller,
    ws: workspace.Workspace,
    b: binds.Binds,
    machine: [:0]const u8,
    /// postStop's commands, as `Early` holds them: the one list the
    /// record and the launch's own `Early` then hold too
    post_stop: []const spec.Command,
    tier_bpf: []const u8,
    umap: []const subid.Extent,
    gmap: []const subid.Extent,
    cache: [:0]const u8,
    id: identity.Identity,
    /// $home/tmp when it is a private tmpfs
    home_tmp: ?[:0]const u8,
    /// what `exec` printed, when the declaration has it
    exec: ?cmd.Exec,
    /// its files, relative to the home
    files: []const spec.File,
};

/// The holder unit's cgroup, relative to user@UID.service, and how the
/// launch starts it when absent (module.nix's holderUnit).
pub const holder = "app.slice/flong-sessions.service";
pub const holder_start = [_][:0]const u8{ "/run/current-system/sw/bin/systemctl", "--user", "start", "flong-sessions.service" };

/// How many user namespaces a nestedSandbox session may make below its
/// own: a ceiling, not a need (Chromium's sandbox, `codex sandbox` and a
/// nested bwrap ran under 16).
pub const nested_user_namespaces = 128;

/// The spec (:391-474), with the declaration's static part, which
/// module.nix's staticTokens rendered for the wrapper's header.
fn specOf(gpa: Allocator, d: *const Declaration, p: Process, f: Found) Error!spec.Spec {
    var mounts: std.ArrayList(mount.Mount) = .empty;
    var protect: std.ArrayList([:0]const u8) = .empty;
    var seccomp: std.ArrayList([:0]const u8) = .empty;
    var limits: std.ArrayList(spec.Limit) = .empty;
    var post_start: std.ArrayList(spec.Command) = .empty;
    var pasta_args: std.ArrayList([:0]const u8) = .empty;
    var env: std.ArrayList(spec.Var) = .empty;
    return specAlloc(gpa, d, p, f, .{
        .mounts = &mounts,
        .protect = &protect,
        .seccomp = &seccomp,
        .limits = &limits,
        .post_start = &post_start,
        .pasta_args = &pasta_args,
        .env = &env,
    }) catch |err| switch (err) {
        error.OutOfMemory => {
            msg.sayErrno(.NOMEM, "spec", .{});
            return error.NotRun;
        },
        error.NotRun => return error.NotRun,
    };
}

const Lists = struct {
    mounts: *std.ArrayList(mount.Mount),
    protect: *std.ArrayList([:0]const u8),
    seccomp: *std.ArrayList([:0]const u8),
    limits: *std.ArrayList(spec.Limit),
    post_start: *std.ArrayList(spec.Command),
    pasta_args: *std.ArrayList([:0]const u8),
    env: *std.ArrayList(spec.Var),
};

fn specAlloc(gpa: Allocator, d: *const Declaration, p: Process, f: Found, l: Lists) (Allocator.Error || error{NotRun})!spec.Spec {
    const z = struct {
        fn of(a: Allocator, s: []const u8) Allocator.Error![:0]const u8 {
            return a.dupeZ(u8, s);
        }
        fn print(a: Allocator, comptime fmt: []const u8, args: anytype) Allocator.Error![:0]const u8 {
            return std.fmt.allocPrintSentinel(a, fmt, args, 0);
        }
    };

    // The declaration's mounts, in staticTokens' order: its binds, its
    // tmpfs, its overlays, its devices, its masks.
    for (d.containerMounts) |cm| switch (cm.kind) {
        .bind_ro, .bind_rw => try l.mounts.append(gpa, .{
            .kind = if (cm.kind == .bind_ro) .bind_ro else .bind_rw,
            .dest = try z.of(gpa, cm.dest),
            .src = try z.of(gpa, cm.src orelse cm.dest),
        }),
        else => {},
    };
    for (d.containerMounts) |cm| if (cm.kind == .tmpfs) try l.mounts.append(gpa, .{
        .kind = .tmpfs,
        .dest = try z.of(gpa, cm.dest),
        .mode = try z.of(gpa, cm.mode orelse "0755"),
        .size = if (cm.size) |s| try z.of(gpa, s) else null,
        .owner_user = cm.ownerUser,
    });
    for (d.overlays) |o| try l.mounts.append(gpa, .{ .kind = .overlay, .dest = try z.of(gpa, o.target), .src = try z.of(gpa, o.lower) });
    for (d.containerMounts) |cm| if (cm.kind == .dev) try l.mounts.append(gpa, .{
        .kind = .dev,
        .dest = try z.of(gpa, cm.dest),
        .src = try z.of(gpa, cm.src orelse cm.dest),
    });
    for (d.masks) |m| try l.mounts.append(gpa, .{ .kind = .mask, .dest = try z.of(gpa, m) });
    // The workspace and the caller's binds are canonical, so they are
    // bound exact: a symlink the launcher meets on the way is a race, and
    // refused (:406-411). Then $home/tmp.
    try l.mounts.append(gpa, .{ .kind = if (f.b.workspace_mode == .rw) .bind_rw_exact else .bind_ro_exact, .dest = f.ws.path, .src = f.ws.path });
    for (f.b.list) |x| try l.mounts.append(gpa, if (x.layers) |layers|
        .{ .kind = .overlay_kept, .dest = x.path, .src = x.path, .layers = layers }
    else
        .{ .kind = if (x.mode == .rw) .bind_rw_exact else .bind_ro_exact, .dest = x.path, .src = x.path });
    if (f.home_tmp) |t| try l.mounts.append(gpa, .{ .kind = .tmpfs, .dest = t, .mode = "0700", .owner_user = true });

    // What no mount may reach: the kernel's, the declaration's, and the
    // user manager's bus and private socket (:392-395).
    for ([_][]const u8{ "/proc", "/sys/fs/cgroup" }) |x| try l.protect.append(gpa, try z.of(gpa, x));
    for (d.protect) |x| try l.protect.append(gpa, try z.of(gpa, x));
    try l.protect.append(gpa, try z.print(gpa, "{s}/bus", .{f.who.runtime}));
    try l.protect.append(gpa, try z.print(gpa, "{s}/systemd", .{f.who.runtime}));

    // The tier's filter, then audit, tty and the namespace mask, in this
    // order (:396-400).
    if (f.tier_bpf.len > 0) try l.seccomp.append(gpa, try z.of(gpa, f.tier_bpf));
    for (d.seccompFixedFilters) |x| try l.seccomp.append(gpa, try z.of(gpa, x));

    // The limits, as systemd names them and the cgroup files take them
    // (module.nix's limitTokens, in its order).
    const lim = d.limits;
    if (lim.CPUWeight) |w| try l.limits.append(gpa, .{ .file = "cpu.weight", .value = try z.print(gpa, "{d}", .{w}) });
    inline for (.{ .{ "MemoryHigh", "memory.high" }, .{ "MemoryMax", "memory.max" }, .{ "MemorySwapMax", "memory.swap.max" } }) |x| {
        if (@field(lim, x[0])) |v| try l.limits.append(gpa, .{ .file = x[1], .value = switch (v) {
            .infinity => "max",
            .bytes => |n| try z.print(gpa, "{d}", .{n}),
            .size => |s| try z.of(gpa, s),
        } });
    }
    if (lim.TasksMax) |v| try l.limits.append(gpa, .{ .file = "pids.max", .value = switch (v) {
        .infinity => "max",
        .count => |n| try z.print(gpa, "{d}", .{n}),
    } });
    // A percentage of one CPU is that many thousandths of a 100 ms period.
    if (lim.CPUQuota) |q| try l.limits.append(gpa, .{ .file = "cpu.max", .value = try z.print(gpa, "{s}000 100000", .{q[0 .. q.len - 1]}) });
    if (lim.oomGroup) try l.limits.append(gpa, .{ .file = "memory.oom.group", .value = "1" });

    // postStart's commands, each through the declaration's program, with
    // the launcher's arguments after it (:413-421). postStop's, through
    // its own, are the list step 5 made for `Early` (`f.post_stop`), so
    // what the record holds is what a launch that failed before it ran.
    for (d.postStart) |c| {
        var w: std.ArrayList([:0]const u8) = .empty;
        if (d.postStartProgram) |prog| try w.append(gpa, try z.of(gpa, prog));
        try w.appendSlice(gpa, c);
        for (p.args) |a| try w.append(gpa, std.mem.span(a));
        try l.post_start.append(gpa, w.items);
    }

    // The network: pasta's ports (portList, hostPorts) and
    // --no-map-gw, then the resolver, read once (:423-461).
    var resolv_conf: ?[]const u8 = null;
    if (d.network) |n| {
        const fp = n.forwardPorts;
        const at = try bindPrefix(gpa, forwardBind(n, f.exec));
        try l.pasta_args.append(gpa, "-t");
        try l.pasta_args.append(gpa, try bound(gpa, at, if (fp == .auto) "auto" else try portList(gpa, fp.ports, .tcp)));
        try l.pasta_args.append(gpa, "-u");
        try l.pasta_args.append(gpa, try bound(gpa, at, if (fp == .auto) "none" else try portList(gpa, fp.ports, .udp)));
        const host = try hostPorts(gpa, n.hostPorts);
        for ([_][:0]const u8{ "-T", host, "-U", host }) |x| try l.pasta_args.append(gpa, x);
        if (n.hostLoopbackToSession) try l.pasta_args.append(gpa, "--host-lo-to-ns-lo");
        try l.pasta_args.append(gpa, "--no-map-gw");
        const r = try resolv.read(gpa, readOrEmpty(gpa, "/etc/resolv.conf"));
        for (r.pastaArgs()) |x| try l.pasta_args.append(gpa, try z.of(gpa, x));
        resolv_conf = r.text;
    }

    // The payload's environment, built from nothing, so the caller's
    // tokens and agent sockets never reach it (:463-473): the launch's own
    // (spec.fixed_env), then the container's, from its /etc/set-environment
    // (the declaration's `environment`), whose PATH replaces the launch's,
    // then what `exec` printed. flong check has refused a declared name of
    // the launch's other than PATH, and execOf a name of `exec`'s that
    // either sets, so no name is set twice.
    const tmpdir: []const u8 = if (f.home_tmp) |t| t else "/tmp";
    const term = getenv(p.environ, "TERM") orelse "";
    const runtime = try z.print(gpa, "/run/user/{s}", .{f.id.uid});
    // spec.expandable's values, in its order.
    const known = [spec.expandable.len][]const u8{ f.id.home, d.user, d.user, f.id.shell, runtime, tmpdir };
    var path: [:0]const u8 = try z.print(gpa, "{s}/sw/bin", .{d.closure});
    for (d.environment) |v| if (std.mem.eql(u8, v.name, "PATH")) {
        path = try spec.expand(gpa, v.value, &known);
    };
    const vars = [_][2][]const u8{
        .{ "PATH", path },
        .{ "HOME", f.id.home },
        .{ "USER", d.user },
        .{ "LOGNAME", d.user },
        .{ "SHELL", f.id.shell },
        .{ "XDG_RUNTIME_DIR", runtime },
        .{ "TMPDIR", tmpdir },
        .{ "FLONG_BINDS", f.b.text },
        .{ "container", "flong" },
        .{ "TERM", if (term.len > 0) term else "dumb" },
    };
    for (vars) |v| try l.env.append(gpa, .{ .name = try z.of(gpa, v[0]), .value = try z.of(gpa, v[1]) });
    if (getenv(p.environ, "COLORTERM")) |c| if (c.len > 0) try l.env.append(gpa, .{ .name = "COLORTERM", .value = try z.of(gpa, c) });
    for (d.environment) |v| if (!std.mem.eql(u8, v.name, "PATH")) {
        try l.env.append(gpa, .{ .name = try z.of(gpa, v.name), .value = try spec.expand(gpa, v.value, &known) });
    };
    if (f.exec) |x| for (x.env) |v| try l.env.append(gpa, .{ .name = try z.of(gpa, v.name), .value = try z.of(gpa, v.value) });

    // The payload, exec'd by tini as it is, in the workspace flong init
    // changes to: what `exec` printed, or `command` and the launcher's
    // arguments.
    const words: []const [:0]const u8 = if (f.exec) |x| x.argv else d.command.?;
    const extra: []const [*:0]const u8 = if (f.exec != null) &.{} else p.args;
    const command = try gpa.allocSentinel(?[*:0]const u8, words.len + extra.len, null);
    for (command[0..words.len], words) |*c, w| c.* = w.ptr;
    for (command[words.len..], extra) |*c, a| c.* = a;

    const groups = try gpa.alloc(u32, f.id.groups.len);
    for (groups, f.id.groups) |*g, t| g.* = try idOf("group", t);

    return .{
        .machine = f.machine,
        .container = try z.of(gpa, d.container),
        .state = f.who.state,
        .cache = f.cache,
        .closure = try z.of(gpa, d.closure),
        .uidmap = try idmaps(gpa, "uidmap", f.umap),
        .gidmap = try idmaps(gpa, "gidmap", f.gmap),
        .uid = d.cuid,
        .gid = d.cgid,
        .home = try z.of(gpa, f.id.home),
        .groups = groups,
        .chdir = f.ws.path,
        .mounts = l.mounts.items,
        .protect = l.protect.items,
        .seccomp = l.seccomp.items,
        .nested_userns = if (d.seccomp.nestedSandbox) nested_user_namespaces else 0,
        .holder = holder,
        .holder_start = &holder_start,
        .limits = l.limits.items,
        .post_start = l.post_start.items,
        .post_stop = f.post_stop,
        .network = d.network != null,
        .pasta_args = l.pasta_args.items,
        // Fixed ports are bound on the host, so teardown waits for pasta
        // to let them go, and the next session can have them.
        .pasta_wait = if (d.network) |n| n.forwardPorts == .ports and n.forwardPorts.ports.len > 0 else false,
        .env = l.env.items,
        .hostname = try z.of(gpa, d.container),
        .label = if (f.exec) |x| if (x.label) |t| try z.of(gpa, t) else null else null,
        .resolv_conf = resolv_conf,
        .files = f.files,
        .trace = if (getenv(p.environ, "FLONG_TRACE")) |t| t.len > 0 else false,
        .command = @ptrCast(command[0 .. words.len + extra.len]),
    };
}

/// postStop's commands as the spec and the record hold them: each through
/// the declaration's program, when it has one (:413-421; module.nix's
/// post-stop tokens).
fn postStopCommands(gpa: Allocator, d: *const Declaration) Allocator.Error![]const spec.Command {
    const out = try gpa.alloc(spec.Command, d.postStop.len);
    for (out, d.postStop) |*o, c| {
        var w: std.ArrayList([:0]const u8) = .empty;
        if (d.postStopProgram) |prog| try w.append(gpa, try gpa.dupeZ(u8, prog));
        try w.appendSlice(gpa, c);
        o.* = w.items;
    }
    return out;
}

/// The declaration's `exec`, run as the other commands are, with the
/// launcher's arguments after its own, its stdout captured as theirs is
/// (at most cmd.output_max) and read as its protocol (cmd.parseExec). Its
/// failure, output of another shape, an empty name (an `env:` field is
/// split at its first `=`), one printed twice, one tini reads
/// (spec.init_prefix) and one the session already sets -- the launch's
/// own (spec.fixed_env) or the container's (`environment`) -- are each
/// refused, saying so: nothing it prints overrides anything silently. So
/// is a file's path that is not absolute and clean (spec.unclean), one
/// printed twice, and one inside another's, which could not be both a
/// file and a directory; whether each is under the payload's home is
/// `homeFiles`', once the home is known. The names and paths are held in
/// sets as they are judged, so a caller whose arguments the hook echoes as
/// variables, a MiB of them, costs a pass over them rather than a
/// comparison of each with every earlier one.
fn execOf(gpa: Allocator, d: *const Declaration, x: decl.Command, args: []const [*:0]const u8, envp: cmd.Envp) Error!cmd.Exec {
    const o = try cmd.capture(gpa, x, args, envp, cmd.output_max);
    if (o.status != 0) return msg.refuse("exec: {s} failed (status {d}); the payload does not run", .{ x[0], o.status });
    const e = switch (cmd.parseExec(gpa, o.out) catch return oom()) {
        .ok => |e| e,
        .bad => |bad| return switch (bad) {
            .unterminated => msg.refuse("exec: {s} printed a field without the NUL that ends it: every field, the last one too, ends with a NUL", .{x[0]}),
            .untagged => |field| msg.refuse("exec: {s} printed \"{s}\", where each field is env:NAME=VALUE, arg:WORD, file:MODE:PATH followed by the file's content, forward:BIND, or label:TEXT", .{ x[0], field }),
            .not_a_variable => |field| msg.refuse("exec: {s} printed \"{s}\", which has no `=`: a variable is env:NAME=VALUE", .{ x[0], field }),
            .bad_mode => |field| msg.refuse("exec: {s} printed \"{s}\", whose mode is not one to four octal digits of at most 0777: a file is file:MODE:PATH, and its mode permission bits alone, never setuid, setgid or sticky", .{ x[0], field }),
            .no_path => |field| msg.refuse("exec: {s} printed \"{s}\", which has no `:` after its mode: a file is file:MODE:PATH", .{ x[0], field }),
            .no_content => |path| msg.refuse("exec: {s} printed the file {s} with no field after it for its content", .{ x[0], path }),
            .no_argv => msg.refuse("exec: {s} printed no arg: field: the payload needs at least its program", .{x[0]}),
            .empty_program => msg.refuse("exec: {s} printed an empty program as the payload's", .{x[0]}),
            .forward_twice => |field| msg.refuse("exec: {s} printed \"{s}\", a second forward: field", .{ x[0], field }),
            .label_twice => |field| msg.refuse("exec: {s} printed \"{s}\", a second label: field", .{ x[0], field }),
        },
    };
    if (e.label) |t| if (decl.labelBad(t)) |why| return switch (why) {
        .empty => msg.refuse("exec: {s} printed an empty label: field: a label names the container to the terminal", .{x[0]}),
        .too_long => msg.refuse("exec: {s} printed a label: of {d} bytes, more than {d}", .{ x[0], t.len, decl.label_max }),
        .not_utf8 => msg.refuse("exec: {s} printed a label: that is not UTF-8", .{x[0]}),
        .control => msg.refuse("exec: {s} printed a label: with a control character in it, which the terminal could read as the end of the mark", .{x[0]}),
    };
    if (e.forward) |f| {
        if (d.network == null)
            return msg.refuse("exec: {s} printed \"forward:{s}\", but the container has no network to forward ports from", .{ x[0], f });
        const b = splitBind(f);
        if (decl.bindBad(b.address, b.interface)) |why| return switch (why) {
            .address => msg.refuse("exec: {s} printed \"forward:{s}\", whose address is not an IPv4 or IPv6 address: a bind is forward:ADDRESS, forward:ADDRESS%INTERFACE, forward:%INTERFACE, or forward: for every address", .{ x[0], f }),
            .interface => msg.refuse("exec: {s} printed \"forward:{s}\", whose interface is not a name of 1 to {d} letters, digits, '.', '_' or '-'", .{ x[0], f, decl.interface_max }),
        };
    }
    var declared: std.StringHashMapUnmanaged(void) = .empty;
    for (d.environment) |w| declared.put(gpa, w.name, {}) catch return oom();
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    for (e.env) |v| {
        if (!spec.isEnvName(v.name))
            return msg.refuse("exec: {s} printed a variable with an empty name", .{x[0]});
        if (spec.isOneOf(&spec.fixed_env, v.name))
            return msg.refuse("exec: {s} sets {s}, which the launch sets for every session", .{ x[0], v.name });
        if (spec.isInitName(v.name))
            return msg.refuse("exec: {s} sets {s}, which tini, the session's init, reads", .{ x[0], v.name });
        if (declared.contains(v.name))
            return msg.refuse("exec: {s} sets {s}, which the container's environment already sets", .{ x[0], v.name });
        if ((seen.getOrPut(gpa, v.name) catch return oom()).found_existing)
            return msg.refuse("exec: {s} sets {s} twice", .{ x[0], v.name });
    }
    var paths: std.StringHashMapUnmanaged(void) = .empty;
    for (e.files) |f| {
        if (spec.unclean(f.path, .absolute)) |why| return switch (why) {
            .not_absolute, .not_relative => msg.refuse("exec: {s} printed the file \"{s}\", which is not an absolute path", .{ x[0], f.path }),
            .too_long => msg.refuse("exec: {s} printed a file whose path is PATH_MAX bytes or longer", .{x[0]}),
            .component => msg.refuse("exec: {s} printed the file \"{s}\", which has an empty, '.' or '..' component", .{ x[0], f.path }),
            .long_component => msg.refuse("exec: {s} printed the file \"{s}\", which has a component longer than NAME_MAX, 255 bytes", .{ x[0], f.path }),
        };
        if ((paths.getOrPut(gpa, f.path) catch return oom()).found_existing)
            return msg.refuse("exec: {s} printed the file {s} twice", .{ x[0], f.path });
    }
    // A file inside another's path: each path's every parent looked up in
    // the set, which is the whole of it once all are in.
    for (e.files) |f| {
        var i = f.path.len;
        while (std.mem.lastIndexOfScalar(u8, f.path[0..i], '/')) |slash| : (i = slash) {
            if (slash == 0) break;
            if (paths.contains(f.path[0..slash]))
                return msg.refuse("exec: {s} printed the file {s} inside the file {s}", .{ x[0], f.path, f.path[0..slash] });
        }
    }
    return e;
}

/// `exec`'s files, each of whose paths must be under the payload's `home`
/// (`/home/u/x`, never `/home/u` itself), as the spec holds them: relative
/// to it. A path elsewhere is refused, saying so: a seeded file is the
/// session's own, and the home the one place a session keeps its own.
/// Where under it a file may not go -- through a symbolic link, across a
/// mount -- flong init finds, as it walks (init.zig).
fn homeFiles(gpa: Allocator, x: decl.Command, home: []const u8, files: []const cmd.File) Error![]const spec.File {
    const out = gpa.alloc(spec.File, files.len) catch return oom();
    for (out, files) |*o, f| {
        const below = underHome(home, f.path) orelse
            return msg.refuse("exec: {s} printed the file {s}, which is not under the payload's home, {s}", .{ x[0], f.path, home });
        o.* = .{
            .mode = f.mode,
            .path = gpa.dupeZ(u8, below) catch return oom(),
            .content = f.content,
        };
    }
    return out;
}

/// `path` relative to `home` when it is below it, a component or more
/// down: `/home/u/x` of `/home/u`, never `/home/u` itself, nor
/// `/home/u2/x`, whose bytes merely start with the home's.
fn underHome(home: []const u8, path: []const u8) ?[]const u8 {
    if (path.len > home.len + 1 and std.mem.startsWith(u8, path, home) and path[home.len] == '/')
        return path[home.len + 1 ..];
    return null;
}

/// A port class of pasta's: "none", or each forward HOST:CONTAINER of
/// `protocol`, comma-separated.
///
/// EVERY PORT CLASS IS SPELT OUT, "none" included, because -t, -u, -T and
/// -U all default to `auto`, and `auto` forwards every port bound on the
/// other side, which for -T means everything listening on the host's
/// loopback. A session asks for what it gets, port by port. hostPorts go
/// out as TCP and UDP both (`hostPorts`): a port on the host's loopback is
/// the thing named, and a resolver there is as likely a reason to name one
/// as a database. forwardPorts `auto` is pasta's own: every second it reads
/// what is listening in the session and publishes the same TCP port on the
/// host, for as long as it is listening, outside the host's ephemeral
/// range. Either is bound where `forwardBind` says (`bound`).
fn portList(gpa: Allocator, ports: []const decl.ForwardPort, protocol: decl.Protocol) Allocator.Error![:0]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (ports) |x| {
        if (x.protocol != protocol) continue;
        if (out.items.len > 0) try out.append(gpa, ',');
        try out.print(gpa, "{d}:{d}", .{ x.hostPort, x.containerPort orelse x.hostPort });
    }
    if (out.items.len == 0) return "none";
    return out.toOwnedSliceSentinel(gpa, 0);
}

/// Where the forwarded ports bind: `exec`'s `forward:` when it printed
/// one, which replaces the declaration's address and interface both, or
/// the declaration's `forwardAddress` and `forwardInterface`. Each null is
/// every address, or every interface.
pub const Bind = struct { address: ?[]const u8 = null, interface: ?[]const u8 = null };

fn forwardBind(n: decl.Network, exec: ?cmd.Exec) Bind {
    if (exec) |x| if (x.forward) |f| return splitBind(f);
    return .{ .address = n.forwardAddress, .interface = n.forwardInterface };
}

/// `forward:`'s value split at its first `%`: ADDRESS, then INTERFACE,
/// either part empty being none. A `%` with nothing after it is an empty
/// interface, which `decl.bindBad` refuses.
pub fn splitBind(f: []const u8) Bind {
    const pct = std.mem.indexOfScalar(u8, f, '%') orelse
        return .{ .address = if (f.len > 0) f else null };
    return .{ .address = if (pct > 0) f[0..pct] else null, .interface = f[pct + 1 ..] };
}

/// pasta's `ADDRESS%INTERFACE/` before a port class, or "" for every
/// address on every interface.
fn bindPrefix(gpa: Allocator, b: Bind) Allocator.Error![]const u8 {
    if (b.address == null and b.interface == null) return "";
    return std.fmt.allocPrint(gpa, "{s}{s}{s}/", .{ b.address orelse "", if (b.interface != null) "%" else "", b.interface orelse "" });
}

/// A port class bound at `at`: "none" binds nothing, so it stays as it is.
fn bound(gpa: Allocator, at: []const u8, class: [:0]const u8) Allocator.Error![:0]const u8 {
    if (at.len == 0 or std.mem.eql(u8, class, "none")) return class;
    return std.mem.concatWithSentinel(gpa, u8, &.{ at, class }, 0);
}

fn hostPorts(gpa: Allocator, ports: []const u16) Allocator.Error![:0]const u8 {
    if (ports.len == 0) return "none";
    var out: std.ArrayList(u8) = .empty;
    for (ports, 0..) |x, i| try out.print(gpa, "{s}{d}", .{ if (i > 0) "," else "", x });
    return out.toOwnedSliceSentinel(gpa, 0);
}

/// An id from text the prepared root gave, as the argv spec's parse read it: a
/// decimal number of at most spec.id_max, or its refusal.
fn idOf(what: []const u8, t: []const u8) error{NotRun}!u32 {
    if (t.len == 0) return spec_refuse("spec: {s} is empty", .{what});
    var n: u64 = 0;
    for (t) |c| {
        if (c < '0' or c > '9') return spec_refuse("spec: {s} is not a decimal number: '{s}'", .{ what, t });
        n = n * 10 + (c - '0');
        if (n > spec.id_max) return spec_refuse("spec: {s} is larger than {d}: '{s}'", .{ what, spec.id_max, t });
    }
    return @intCast(n);
}

/// A map's extents as the spec's numbers (subid.Word.number): a word that
/// is no decimal number, which only a negative result of the wrapper's
/// arithmetic is, is refused as the argv spec's parse refused it.
fn idmaps(gpa: Allocator, what: []const u8, extents: []const subid.Extent) (Allocator.Error || error{NotRun})![]const spec.IdMap {
    const out = try gpa.alloc(spec.IdMap, extents.len);
    for (out, extents) |*o, e| {
        var n: [3]u64 = undefined;
        for (&n, e) |*x, w| x.* = w.number() orelse
            return spec_refuse("spec: {s} is not a decimal number: '{f}'", .{ what, w });
        o.* = .{ .inside = n[0], .outside = n[1], .count = n[2] };
    }
    return out;
}

fn spec_refuse(comptime fmt: []const u8, args: anytype) error{NotRun} {
    msg.say(fmt, args);
    return error.NotRun;
}

/// fl_map for a container id onto the caller's, from their entry; bash's
/// "value too great for base" where its arithmetic could not read the
/// entry, which ended the wrapper with 1 (subid.Built).
fn mapOf(container: u32, host: u32, range: subid.Range) Error!subid.Map {
    return switch (subid.buildMap(container, host, range)) {
        .map => |m| m,
        .not_a_number => |t| msg.refuse("{s}: value too great for base (error token is \"{s}\")", .{ t, t }),
    };
}

/// `flong-seccomp project DUMP NAMES DENY $state/seccomp <<<"$policy"`
/// (:217-222): the compiled filter's path, from its stdout; a failure is
/// "the project's seccomp policy was refused", after what the compiler
/// said.
fn compilePolicy(gpa: Allocator, d: *const Declaration, tools: Tools, state: []const u8, policy: []const u8, envp: cmd.Envp) Error![]const u8 {
    const project = d.seccompProject orelse return msg.refuse("the project's seccomp policy was refused", .{});
    const argv = [_][:0]const u8{
        tools.seccomp,
        "project",
        gpa.dupeZ(u8, project.dump) catch return oom(),
        gpa.dupeZ(u8, project.names) catch return oom(),
        gpa.dupeZ(u8, project.deny) catch return oom(),
        std.fmt.allocPrintSentinel(gpa, "{s}/seccomp", .{state}, 0) catch return oom(),
    };
    // A here-string is its text and a newline.
    const input = std.mem.concat(gpa, u8, &.{ policy, "\n" }) catch return oom();
    const o = try cmd.captureInput(gpa, &argv, envp, input, cmd.output_max);
    if (o.status != 0) return msg.refuse("the project's seccomp policy was refused", .{});
    return cmd.substitute(o.out);
}

/// `[[ -n ${policy//[[:space:]]/} ]]`, false: nothing but space, tab,
/// newline, vertical tab, form feed and carriage return.
fn blank(s: []const u8) bool {
    for (s) |c| if (std.mem.indexOfScalar(u8, " \t\n\x0b\x0c\r", c) == null) return false;
    return true;
}

/// The session name's last part: 64 bits from the kernel's pool, so no
/// two names meet (the header). The wrapper's was bash's $RANDOM, 15 bits,
/// which a reused pid met once in 32768 launches, with the ended session's
/// record still there to find; and a launch that cannot have its bits is
/// refused rather than named from the clock, which would make that case
/// ordinary again.
fn randomWord() Error!u64 {
    var buf: [8]u8 = undefined;
    switch (sys.getrandom(&buf)) {
        .ok => return std.mem.readInt(u64, &buf, .little),
        .err => |e| return msg.fail(e, "getrandom, for the session's name", .{}),
    }
}

/// `commandPath`'s directories, then the caller's PATH, as
/// writeShellApplication writes `export PATH="DIRS:$PATH"`; with no PATH,
/// the directories alone.
fn commandPath(gpa: Allocator, dirs: []const []const u8, path: ?[]const u8) Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (dirs, 0..) |x, i| {
        if (i > 0) out.append(gpa, ':') catch return oom();
        out.appendSlice(gpa, x) catch return oom();
    }
    if (path) |p| out.print(gpa, ":{s}", .{p}) catch return oom();
    return out.items;
}

pub const getenv = cmd.getenv;

/// module.nix's `norm` of each path: what the header's declared_dests
/// held.
fn normAll(gpa: Allocator, paths: []const []const u8) Error![]const []const u8 {
    const out = gpa.alloc([]const u8, paths.len) catch return oom();
    for (out, paths) |*o, x| o.* = check.norm(gpa, x) catch return oom();
    return out;
}

/// A file's bytes, or none when it cannot be read: the wrapper's `while
/// read ... done <FILE` read nothing from a file it could not open, and
/// `[[ -r /etc/resolv.conf ]]` skipped the loop.
fn readOrEmpty(gpa: Allocator, path: [:0]const u8) []const u8 {
    const r = fdt.openFile(fdt.cwd, path, .{}, 0) catch return "";
    const f = switch (r) {
        .ok => |f| f,
        .err => return "",
    };
    defer f.close();
    return switch (fdt.readAll(f, gpa) catch return "") {
        .ok => |t| t,
        .err => "",
    };
}

fn oom() error{Reported} {
    return msg.fail(.NOMEM, "malloc", .{});
}

// ---- tests ----

const testing = std.testing;

test "portList and hostPorts: pasta's port classes, none when empty" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const ports = [_]decl.ForwardPort{
        .{ .hostPort = 8080, .containerPort = 80 },
        .{ .protocol = .udp, .hostPort = 5353 },
        .{ .hostPort = 18200 },
    };
    try testing.expectEqualStrings("8080:80,18200:18200", try portList(a, &ports, .tcp));
    try testing.expectEqualStrings("5353:5353", try portList(a, &ports, .udp));
    try testing.expectEqualStrings("none", try portList(a, &.{}, .tcp));
    try testing.expectEqualStrings("none", try hostPorts(a, &.{}));
    try testing.expectEqualStrings("18123,19999", try hostPorts(a, &.{ 18123, 19999 }));
}

test "forwardBind: exec's forward: replaces the declaration's address and interface, each part bound as pasta reads it" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const none: decl.Network = .{};
    const both: decl.Network = .{ .forwardAddress = "192.0.2.1", .forwardInterface = "eth0" };
    const x = struct {
        fn exec(f: ?[]const u8) cmd.Exec {
            return .{ .env = &.{}, .argv = &.{}, .files = &.{}, .forward = f };
        }
    };
    const P = struct {
        fn of(al: Allocator, n: decl.Network, e: ?cmd.Exec) ![]const u8 {
            return bindPrefix(al, forwardBind(n, e));
        }
    };
    // Neither: every address, as before.
    try testing.expectEqualStrings("", try P.of(a, none, null));
    try testing.expectEqualStrings("", try P.of(a, none, x.exec(null)));
    // The declaration's: address, interface, both.
    try testing.expectEqualStrings("127.9.9.9/", try P.of(a, .{ .forwardAddress = "127.9.9.9" }, null));
    try testing.expectEqualStrings("%lo/", try P.of(a, .{ .forwardInterface = "lo" }, null));
    try testing.expectEqualStrings("192.0.2.1%eth0/", try P.of(a, both, null));
    // exec's replaces both, `forward:` alone with every address.
    try testing.expectEqualStrings("127.101.170.171/", try P.of(a, both, x.exec("127.101.170.171")));
    try testing.expectEqualStrings("::1%lo/", try P.of(a, none, x.exec("::1%lo")));
    try testing.expectEqualStrings("%lo/", try P.of(a, both, x.exec("%lo")));
    try testing.expectEqualStrings("", try P.of(a, both, x.exec("")));
    // An exec that printed none leaves the declaration's.
    try testing.expectEqualStrings("192.0.2.1%eth0/", try P.of(a, both, x.exec(null)));

    // The port classes, bound; none stays none.
    try testing.expectEqualStrings("auto", try bound(a, "", "auto"));
    try testing.expectEqualStrings("127.9.9.9/auto", try bound(a, "127.9.9.9/", "auto"));
    try testing.expectEqualStrings("none", try bound(a, "127.9.9.9/", "none"));
    try testing.expectEqualStrings("::1%lo/8080:80,18200:18200", try bound(a, "::1%lo/", "8080:80,18200:18200"));

    // splitBind: at the first %, an empty part none.
    try testing.expectEqualDeep(Bind{ .address = "a" }, splitBind("a"));
    try testing.expectEqualDeep(Bind{ .interface = "i" }, splitBind("%i"));
    try testing.expectEqualDeep(Bind{ .address = "a", .interface = "" }, splitBind("a%"));
    try testing.expectEqualDeep(Bind{ .address = "a", .interface = "i%j" }, splitBind("a%i%j"));
    try testing.expectEqualDeep(Bind{}, splitBind(""));
}

test "underHome: a component or more below the home, relative to it" {
    try testing.expectEqualStrings("x", underHome("/home/u", "/home/u/x").?);
    try testing.expectEqualStrings(".config/t/token", underHome("/home/u", "/home/u/.config/t/token").?);
    for ([_][]const u8{ "/home/u", "/home/u/", "/home/u2/x", "/home/ux", "/home", "/srv/x", "/home/v/x" }) |p|
        try testing.expectEqual(@as(?[]const u8, null), underHome("/home/u", p));
}

test "blank is [[:space:]] alone" {
    try testing.expect(blank(""));
    try testing.expect(blank(" \t\n\x0b\x0c\r"));
    try testing.expect(!blank(" allow read\n"));
    try testing.expect(!blank("#"));
}

test "commandPath goes in front of PATH, or stands alone" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings("/a/bin:/b/bin:/usr/bin", try commandPath(a, &.{ "/a/bin", "/b/bin" }, "/usr/bin"));
    try testing.expectEqualStrings("/a/bin:", try commandPath(a, &.{"/a/bin"}, ""));
    try testing.expectEqualStrings("/a/bin", try commandPath(a, &.{"/a/bin"}, null));
}

/// What `f` said on stderr, through a memfd at fd 2, in the launcher's cut
/// mode.
fn said(buf: []u8, comptime f: anytype, args: anytype) ![]const u8 {
    msg.prog = "flong launch";
    msg.mode = .cut;
    const mf = switch (sys.memfdCreate("assemble-test", sys.MFD_CLOEXEC)) {
        .ok => |n| n,
        .err => return error.Memfd,
    };
    defer sys.close(mf);
    const saved = switch (sys.fcntl(2, sys.F_DUPFD_CLOEXEC, 10)) {
        .ok => |n| n,
        .err => return error.Dup,
    };
    if (sys.dup2(mf, 2) != .ok) return error.Dup;
    const r = @call(.auto, f, args);
    _ = sys.dup2(saved, 2);
    sys.close(saved);
    try testing.expectError(error.NotRun, r);
    return switch (sys.pread(mf, buf, 0)) {
        .ok => |n| buf[0..n],
        .err => error.Read,
    };
}

test "idOf: a group's id from the prepared root, refused as the argv spec's parse refused it" {
    // The spec's golden cases group-letters and group-over-id-max, and an
    // empty id: a group's id is text from the prepared root's /etc/group.
    try testing.expectEqual(@as(u32, 4294967294), try idOf("group", "4294967294"));
    try testing.expectEqual(@as(u32, 7), try idOf("group", "0007"));
    var b: [512]u8 = undefined;
    try testing.expectEqualStrings("flong launch: spec: group is not a decimal number: 'g'\n", try said(&b, idOf, .{ "group", "g" }));
    try testing.expectEqualStrings("flong launch: spec: group is larger than 4294967294: '4294967295'\n", try said(&b, idOf, .{ "group", "4294967295" }));
    try testing.expectEqualStrings("flong launch: spec: group is larger than 4294967294: '99999999999999999999999'\n", try said(&b, idOf, .{ "group", "99999999999999999999999" }));
    try testing.expectEqualStrings("flong launch: spec: group is empty\n", try said(&b, idOf, .{ "group", "" }));
    try testing.expectEqualStrings("flong launch: spec: group is not a decimal number: '-1'\n", try said(&b, idOf, .{ "group", "-1" }));
}

test "idmaps: a negative result of fl_map's arithmetic, refused as the argv spec's parse refused it" {
    // The spec's golden cases uidmap-sign and user-gid-negative: a start
    // past 2^63 - 1 in /etc/subuid wraps an extent's start negative
    // (subid.zig's buildMap), which is no decimal number.
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const ok = [_]subid.Extent{.{ .{ .text = "0" }, .{ .value = 100000 }, .{ .text = "65536" } }};
    try testing.expectEqualSlices(spec.IdMap, &.{.{ .inside = 0, .outside = 100000, .count = 65536 }}, try idmaps(a, "uidmap", &ok));
    const negative = [_]subid.Extent{
        .{ .{ .text = "0" }, .{ .value = 100000 }, .{ .text = "1000" } },
        .{ .{ .value = 1001 }, .{ .value = -9223372036854774809 }, .{ .value = 64536 } },
    };
    var b: [512]u8 = undefined;
    try testing.expectEqualStrings("flong launch: spec: uidmap is not a decimal number: '-9223372036854774809'\n", try said(&b, idmaps, .{ a, "uidmap", &negative }));
    const letters = [_]subid.Extent{.{ .{ .text = "0" }, .{ .text = "x" }, .{ .text = "1" } }};
    try testing.expectEqualStrings("flong launch: spec: gidmap is not a decimal number: 'x'\n", try said(&b, idmaps, .{ a, "gidmap", &letters }));
}

test "Early.beforeRelaunch: a terminating signal queued ends the launch after postStop, in place of the relaunch" {
    const old = try sig.block();
    defer sig.setMask(old);
    try sig.openSignalfd();
    defer {
        sig.fd.?.close();
        sig.fd = null;
        sig.abort_signal = 0;
    }
    // Nothing queued: postStop runs, and the relaunch goes ahead.
    var quiet: Early = .{ .post_stop = &.{}, .machine = "box-1-0000000000000000" };
    try quiet.beforeRelaunch();
    try testing.expect(quiet.done);
    try testing.expectEqual(@as(u8, 0), sig.abort_signal);

    // A SIGINT behind a SIGWINCH: taken off the signalfd, so postStop's
    // waits run, and kept as the launch's status, where a relaunch would
    // restore the mask with nothing pending and go on under a new name.
    _ = sys.kill(sys.getpid(), sys.SIGWINCH);
    _ = sys.kill(sys.getpid(), sys.SIGINT);
    var early: Early = .{ .post_stop = &.{}, .machine = "box-1-0000000000000001" };
    try testing.expectError(error.Aborted, early.beforeRelaunch());
    try testing.expect(early.done);
    try testing.expectEqual(@as(u8, sys.SIGINT), sig.abort_signal);
    try testing.expectEqual(false, try sig.take(0));
    // Once: the teardown's errdefer finds it done.
    early.runPostStop();
}
