//! hook.zig: step 15 of a launch, the postStart hook, as far as building
//! what it runs (launcher/flong-launch.c:579-620 of a7919be, run_hook).
//! postStart is a list of commands (spec.Spec's post_start), run in order:
//! the launcher's root starts each Spawn this returns, awaits it and
//! judges its status with `done`, the first failure ending the launch as
//! the C's one hook's did; this module starts nothing.
//!
//! One module per piece of flong launch under src/launch/ (hook, pasta,
//! ...), each a set of functions with explicit parameters, where the port's
//! plan listed one launch.zig: a small deviation, so that each
//! piece is written and tested apart and launch.zig composes them.
//!
//! The hook runs as the caller in the hooks leaf, so whatever it leaves
//! running dies with the session, with the launcher's stdio and working
//! directory, and the launcher's environment plus $leader, $userns, $netns
//! and $machine (:581-585). The C puts those four into its own environment
//! with setenv (:597-599), after the early return for a spec without a
//! hook, so every later child spawned with the default environment gets
//! them too, and the only such child is pasta (quirk 3, kept): `env` builds
//! that environment as a value, once, only when the list has a command,
//! every command gets it, and the root hands the same value to
//! pasta.build, or null (the environment as it came) when there is no hook.

const std = @import("std");
const sys = @import("sys");
const fd = @import("fd");
const msg = @import("msg");
const proc = @import("proc");
const spec = @import("spec");

const Allocator = std.mem.Allocator;

/// An environment for execve: its strings, then a null.
pub const Envp = [*:null]const ?[*:0]const u8;

/// The postStart hook's commands, ready to start in order, and the
/// environment pasta gets after them (quirk 3).
pub const Hook = struct {
    /// one per command, in the spec's order: argv the command's words; the
    /// environment `envp`; stdio, the working directory and the kept
    /// descriptors the launcher's own (none kept: every descriptor of the
    /// launcher is close-on-exec); in the hooks leaf (flong-launch.c:600-609)
    spawns: []proc.Spawn,
    /// what `env` built: pasta.build's `envp`
    envp: Envp,
};

/// The four variables' values, as run_hook formats them (:590-595). The
/// hook names the namespaces by the launcher's descriptors, through
/// /proc/<launcher>/fd/N: a namespace the launcher holds, with nothing on
/// disk. $netns is the launcher's descriptor of the session's network
/// namespace, where pasta's --netns names it by the leader's pid (quirk 4,
/// kept; pasta.zig).
pub const Vars = struct {
    /// bwrap's child, flong init, the session's pid 1
    leader: sys.pid_t,
    /// this process's pid (sys.getpid()), for /proc/<pid>/fd/N
    self_pid: sys.pid_t,
    /// the spec's machine
    machine: [:0]const u8,
};

/// run_hook's four setenv calls (flong-launch.c:597-599), made on a copy
/// of `environ` (the launcher's, which src/main.zig hands flong launch,
/// the lint keeping environ to the roots and proc.zig) as glibc's setenv
/// makes them on its own: in the order leader, userns, netns, machine,
/// each replacing the first entry named `<name>=` in place, or appended at
/// the end when there is none; a later entry of the same name is left as
/// it is, and an entry with no `=` names nothing. `userns` and `netns` are the
/// launcher's handles of U1 and of the session's network namespace. The
/// strings and the array are `gpa`'s (the launcher's arena, never freed).
pub fn env(gpa: Allocator, environ: []const [*:0]const u8, v: Vars, userns: anytype, netns: anytype) msg.Error!Envp {
    return envAlloc(gpa, environ, v, userns, netns) catch return oom();
}

fn envAlloc(gpa: Allocator, environ: []const [*:0]const u8, v: Vars, userns: anytype, netns: anytype) Allocator.Error!Envp {
    comptime ofKind(.userns, @TypeOf(userns));
    comptime ofKind(.netns, @TypeOf(netns));
    const userns_path = fd.pidPath(v.self_pid, userns);
    const netns_path = fd.pidPath(v.self_pid, netns);
    const vars = [_][2][]const u8{
        .{ "leader", try std.fmt.allocPrint(gpa, "{d}", .{v.leader}) },
        .{ "userns", userns_path.path() },
        .{ "netns", netns_path.path() },
        .{ "machine", v.machine },
    };
    var list: std.ArrayList(?[*:0]const u8) = try .initCapacity(gpa, environ.len + vars.len + 1);
    for (environ) |e| list.appendAssumeCapacity(e);
    for (vars) |nv| {
        const entry = (try std.fmt.allocPrintSentinel(gpa, "{s}={s}", .{ nv[0], nv[1] }, 0)).ptr;
        if (named(list.items, nv[0])) |i| {
            list.items[i] = entry;
        } else {
            list.appendAssumeCapacity(entry);
        }
    }
    list.appendAssumeCapacity(null);
    return @ptrCast(list.items.ptr);
}

/// A handle (owned or held) of kind `k`: the kind is in the type, so U1
/// and the network namespace cannot trade places.
fn ofKind(comptime k: fd.Kind, comptime T: type) void {
    if (!@hasDecl(T, "kind") or T.kind != k) @compileError("a " ++ @tagName(k) ++ " handle, not " ++ @typeName(T));
}

/// The index of the first entry that is `<name>=...`, as glibc's
/// __add_to_environ finds it (strncmp of the name, then '=').
fn named(entries: []const ?[*:0]const u8, name: []const u8) ?usize {
    for (entries, 0..) |e, i| {
        const s = std.mem.span(e.?);
        if (s.len > name.len and std.mem.startsWith(u8, s, name) and s[name.len] == '=') return i;
    }
    return null;
}

/// run_hook up to fl_spawn (flong-launch.c:586-609): null when the spec
/// has no hook (:588-589), and then no environment is built and pasta
/// gets the launcher's own. Otherwise the environment (`env`), built once,
/// and a Spawn per command, which the root starts, awaits and judges with
/// `done` in order. `hooks_leaf` is the session's hooks cgroup.
pub fn build(gpa: Allocator, s: *const spec.Spec, environ: []const [*:0]const u8, v: Vars, userns: anytype, netns: anytype, hooks_leaf: fd.Fd(.cgroup)) msg.Error!?Hook {
    if (s.post_start.len == 0) return null;
    const envp = try env(gpa, environ, v, userns, netns);
    const spawns = gpa.alloc(proc.Spawn, s.post_start.len) catch return oom();
    for (spawns, s.post_start) |*sp, cmd| {
        sp.* = proc.Spawn.init(gpa, cmd[0].ptr) catch return oom();
        for (cmd[1..]) |w| sp.arg(w.ptr) catch return oom();
        sp.envp = envp;
        sp.cgroup = hooks_leaf;
    }
    return .{ .spawns = spawns, .envp = envp };
}

/// After one command is reaped (flong-launch.c:613-619): a failure's
/// refusal, which rootless.nix asserts and which ends the launch before
/// the next command, or the trace stage, once per command.
pub fn done(status: u8) msg.Error!void {
    if (status != 0) return msg.refuse("postStart failed (status {d}); the payload does not run", .{status});
    msg.trace("hook-done");
}

/// The C's str() when vasprintf fails (flong-launch.c:98-107): the only
/// failure an allocation in the launcher's arena can have.
fn oom() msg.Error {
    return msg.fail(.NOMEM, "asprintf", .{});
}
