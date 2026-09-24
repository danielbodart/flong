//! pasta.zig: step 16 of a launch, pasta, as far as building what it runs
//! (launcher/flong-launch.c:622-675 of a7919be, start_pasta). The
//! launcher's root starts it with `Pasta.start`, awaits the Child and
//! judges its status with `done`; this module waits for nothing. One
//! module per piece of flong launch under src/launch/, a small deviation
//! from the port's plan of one launch.zig (hook.zig says why).
//!
//! pasta runs in the pasta leaf, as the caller. --userns names U1, the
//! network namespace's owner (U2 is EPERM). The spawned pasta exits 0 once
//! the namespace is configured and its daemon is running; a host port it
//! cannot bind (in use, or below ip_unprivileged_port_start) fails it at
//! once, and the launch fails closed. The pid file is a memfd the launcher
//! holds: nothing on disk, and a path in pasta's cmdline unique to this
//! session. The launcher never signals pasta by pid; cgroup.kill ends it
//! (:624-630).
//!
//! argv is fixed but for the spec's pasta_args, appended verbatim: the
//! ports (-t, -u, -T, -U, --host-lo-to-ns-lo) and --no-map-gw, and a
//! --dns-forward per nameserver family (launch/assemble.zig,
//! launch/resolv.zig), whose resolv.conf goes to bwrap in a memfd; pasta
//! keeps no descriptor, that one included. pasta-wait
//! changes nothing here: it is teardown's (flong-launch.c:816-825).
//!
//! Quirk 4, kept: --netns names the session's network namespace by the
//! leader's pid, /proc/<leader>/ns/net, where the hook's $netns is the
//! launcher's own descriptor of it (hook.zig). Quirk 3, kept: pasta's
//! environment is the one the hook got when a hook ran, the launcher's own
//! otherwise.

const std = @import("std");
const sys = @import("sys");
const fd = @import("fd");
const msg = @import("msg");
const proc = @import("proc");
const spec = @import("spec");

const Allocator = std.mem.Allocator;

/// pasta, ready to start.
pub const Pasta = struct {
    /// argv as `build` says; the environment its `envp`; stdin `dev_null`,
    /// stdout and stderr the launcher's; no descriptor kept; the
    /// launcher's working directory; in the pasta leaf
    /// (flong-launch.c:654-662).
    spawn: proc.Spawn,
    /// /dev/null, O_RDONLY, pasta's stdin until it has started (:650-652)
    dev_null: fd.File,
    /// the memfd pasta writes its pid into, held until the launcher exits
    /// (:635-637; DESIGN.md, "Conventions": `Held`)
    pid_file: fd.Held(.file),

    /// fl_spawn, then /dev/null closed whether or not it started
    /// (flong-launch.c:663-666): pasta's Child for the root to await and
    /// judge with `done`, or error.Reported having said why ("clone3
    /// <pasta>").
    pub fn start(self: *Pasta) msg.Error!proc.Child {
        const child = self.spawn.start();
        self.dev_null.close();
        return child;
    }
};

/// start_pasta up to fl_spawn (flong-launch.c:631-662): null when the spec
/// asks for no network (:633-634). Otherwise, in the C's order, the pid
/// file (memfd_create("pasta.pid", MFD_CLOEXEC)), argv, and /dev/null:
///
///   <program> --quiet --config-net
///     --userns /proc/<self_pid>/fd/<userns>
///     --netns /proc/<leader>/ns/net
///     --pid /proc/<self_pid>/fd/<pid file>
///     <pasta-arg>...
///
/// `program` is the compiled-in pasta (-Dpasta; FLONG_PASTA); `self_pid`
/// this process's (sys.getpid()); `userns` the launcher's handle of U1;
/// `leader` flong init's pid; `envp` hook.Hook's `envp` when the hook ran,
/// else null (quirk 3); `pasta_leaf` the session's pasta cgroup. The
/// strings are `gpa`'s (the launcher's arena, never freed). A failure is
/// said as the C says it: "memfd_create: <text>", "open /dev/null:
/// <text>"; the pid file, once made, stays open, as the C leaves it.
pub fn build(
    gpa: Allocator,
    s: *const spec.Spec,
    program: [*:0]const u8,
    self_pid: sys.pid_t,
    userns: anytype,
    leader: sys.pid_t,
    envp: ?[*:null]const ?[*:0]const u8,
    pasta_leaf: fd.Fd(.cgroup),
) msg.Error!?Pasta {
    comptime if (!@hasDecl(@TypeOf(userns), "kind") or @TypeOf(userns).kind != .userns) @compileError("userns is U1's handle, not " ++ @typeName(@TypeOf(userns)));
    if (!s.network) return null;
    const pid_file = (try msg.check(fd.memfd("pasta.pid"), "memfd_create", .{})).holdUntilExit();

    var sp = proc.Spawn.init(gpa, program) catch return oom();
    argv(gpa, &sp, s, self_pid, userns, leader, pid_file) catch return oom();

    const dev_null = try msg.check(fd.openFile(fd.cwd, "/dev/null", .{ .ACCMODE = .RDONLY }, 0), "open /dev/null", .{});
    sp.envp = envp;
    sp.stdio[0] = dev_null.any();
    sp.cgroup = pasta_leaf;
    return .{ .spawn = sp, .dev_null = dev_null, .pid_file = pid_file };
}

/// The words after the program (flong-launch.c:640-645).
fn argv(gpa: Allocator, sp: *proc.Spawn, s: *const spec.Spec, self_pid: sys.pid_t, userns: anytype, leader: sys.pid_t, pid_file: fd.Held(.file)) Allocator.Error!void {
    const userns_path = fd.pidPath(self_pid, userns);
    const pid_path = fd.pidPath(self_pid, pid_file);
    try sp.arg("--quiet");
    try sp.arg("--config-net");
    try sp.arg("--userns");
    try sp.arg((try gpa.dupeZ(u8, userns_path.path())).ptr);
    try sp.arg("--netns");
    try sp.arg((try std.fmt.allocPrintSentinel(gpa, "/proc/{d}/ns/net", .{leader}, 0)).ptr);
    try sp.arg("--pid");
    try sp.arg((try gpa.dupeZ(u8, pid_path.path())).ptr);
    for (s.pasta_args) |w| try sp.arg(w.ptr);
}

/// After pasta is reaped (flong-launch.c:667-674): a failure's refusal, or
/// the trace stage.
pub fn done(status: u8) msg.Error!void {
    if (status != 0) return msg.refuse("pasta failed (status {d}); the payload does not run", .{status});
    msg.trace("pasta-up");
}

/// The C's str() when vasprintf fails (flong-launch.c:98-107), or push's
/// realloc: the only failure an allocation in the launcher's arena can
/// have, said as the first.
fn oom() msg.Error {
    return msg.fail(.NOMEM, "asprintf", .{});
}
