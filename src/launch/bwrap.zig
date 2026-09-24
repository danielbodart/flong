//! launch/bwrap.zig: bwrap's spawn, step 12 of a launch (DESIGN.md, "The
//! launch, in order"; launcher/flong-launch.c:334-410 of 5f1f08e,
//! spawn_bwrap). The seccomp programs are opened, the info, ready and gate
//! pipes made, the resolver's file written into a memfd, and bwrap spawned
//! from spec.bwrapArgv, every descriptor it is given named in its argv by
//! Spawn.passFd: U1, U2, info, the seccomp programs, the resolver's memfd,
//! gate and ready.
//!
//! One module per piece, where the port's plan had flong-launch as one
//! root module: launch.zig's helpers are split by concern into src/launch/,
//! one module each, so that each is written and tested on its own before
//! the root composes them. Each takes its handles, the spec and the arena
//! as parameters and returns values or error.Reported/error.Aborted; none
//! holds a Launch struct. The order the launch keeps stays the root's
//! (DESIGN.md, "The ordering checkpoints": each one linear function there).
//!
//! Ordering checkpoint 2 is the root's: right after `spawn` returns,
//! whether or not it succeeded, the root closes every descriptor in
//! ChildEnds, bwrap's alone, in flong-launch.c:396-408's order. `spawn`
//! only records them there as it makes them. The walk, in the root:
//!
//!     if (ends.info_w) |h| h.close();
//!     if (ends.ready_w) |h| h.close();
//!     if (ends.gate_r) |h| h.close();
//!     for (ends.seccomp) |h| h.close();
//!     ends.u2.close();
//!     if (ends.resolv) |h| h.close();
//!
//! A copy the launcher kept of a write end would hide bwrap's death from
//! the info and ready readers, and one of the gate's read end would never
//! let flong init see EOF (:397-399).

const std = @import("std");
const fd = @import("fd");
const msg = @import("msg");
const proc = @import("proc");
const spec = @import("spec");

const Allocator = std.mem.Allocator;

/// The two programs bwrap's argv names, compiled in (-Dbwrap and -Dself,
/// FLONG_BWRAP and FLONG_INIT in the C): launch.zig reads its build
/// options and passes them (DESIGN.md, "The native launcher"). `self` is
/// the flong binary, which bwrap runs as `flong init`.
pub const Paths = struct {
    bwrap: [*:0]const u8,
    self: [*:0]const u8,
};

/// Checkpoint 2's list: every descriptor bwrap alone needs, which the
/// launcher closes at once after the spawn, whether or not it succeeded
/// (flong-launch.c:396-408), in that order. The root fills `u2` and hands
/// it over here; `spawn` adds the rest as it makes them, so the list is whole at
/// whatever step it failed. A pipe end is null until its pipe exists;
/// `seccomp` holds the programs opened so far.
pub const ChildEnds = struct {
    info_w: ?fd.Fd(.pipe_w) = null,
    ready_w: ?fd.Fd(.pipe_w) = null,
    gate_r: ?fd.Fd(.pipe_r) = null,
    seccomp: []const fd.File = &.{},
    u2: fd.Fd(.userns),
    /// the memfd holding the spec's resolv_conf, once it is written
    resolv: ?fd.File = null,
};

/// bwrap, and the launcher's ends of the three pipes (flong-launch.c:
/// 67-70). `info_r` is never closed in the C (quirk 31): the root holds it
/// (`holdUntilExit`). `ready_r` goes to the mount helper (checkpoint 3),
/// `gate_w` is the gate (checkpoint 5).
pub const Spawned = struct {
    child: proc.Child,
    info_r: fd.Fd(.pipe_r),
    ready_r: fd.Fd(.pipe_r),
    gate_w: fd.Fd(.pipe_w),
};

/// spawn_bwrap (flong-launch.c:334-410) but for its closes, which are
/// checkpoint 2's (ChildEnds): opens the seccomp programs in the spec's
/// order (:345-354), makes the info, ready and gate pipes (:356-362) and
/// spawns bwrap with spec.bwrapArgv's argv in `cgroup` (the sandbox leaf),
/// with `stdio` as its 0-2 (the terminal's, tty_stdio) and this process's
/// environment (:379-391). It inherits U1 (`outer`, any userns handle), U2,
/// its ends of the three pipes, the seccomp descriptors and the resolver's
/// memfd, and nothing else (:364-377). `relay` is a relayed pty's: a session of
/// its own, flong init's ctty.
///
/// On a failure it has said why (`open seccomp program P: <text>`,
/// `pipe: <text>`, `malloc: <text>` as the C; a failed clone3 as
/// Spawn.start says it), and the launcher's own ends are closed; what is in
/// `ends` is the root's to close, as on success. The root calls
/// tty_spawned's port after a success, before that walk (:394).
pub fn spawn(
    arena: Allocator,
    s: *const spec.Spec,
    paths: Paths,
    outer: anytype,
    relay: bool,
    stdio: [3]?fd.AnyFd,
    cgroup: ?fd.Fd(.cgroup),
    ends: *ChildEnds,
) msg.Error!Spawned {
    if (@TypeOf(outer).kind != .userns) @compileError("U1 is a userns handle, not " ++ @typeName(@TypeOf(outer)));

    // The seccomp programs, one descriptor each, until bwrap has them
    // (:345-354).
    const files = arena.alloc(fd.File, s.seccomp.len) catch return msg.fail(.NOMEM, "malloc", .{});
    for (s.seccomp, 0..) |path, i| {
        files[i] = try msg.check(fd.openFile(fd.cwd, path.ptr, .{}, 0), "open seccomp program {s}", .{path});
        ends.seccomp = files[0 .. i + 1];
    }

    // The session's /etc/resolv.conf, whole, in a memfd bwrap reads from
    // its start: a value where the wrapper handed over a here-string's
    // descriptor (STANDALONE.md's phase S3, in git at bed8750).
    if (s.resolv_conf) |text| {
        const f = try msg.check(fd.memfd("resolv.conf"), "memfd_create", .{});
        ends.resolv = f;
        const n = try msg.check(f.pwrite(text, 0), "write the session's resolv.conf", .{});
        if (n != text.len) return msg.fail(.IO, "write the session's resolv.conf", .{});
    }

    // The three pipes, both ends close-on-exec: bwrap is given its ends
    // at their numbers (:356-362).
    const info = try msg.check(fd.pipe(), "pipe", .{});
    ends.info_w = info.w;
    const ready = msg.check(fd.pipe(), "pipe", .{}) catch |err| {
        info.r.close();
        return err;
    };
    ends.ready_w = ready.w;
    const gate = msg.check(fd.pipe(), "pipe", .{}) catch |err| {
        info.r.close();
        ready.r.close();
        return err;
    };
    ends.gate_r = gate.r;

    const child = start(arena, s, paths, outer, relay, stdio, cgroup, ends) catch |err| {
        info.r.close();
        ready.r.close();
        gate.w.close();
        return err;
    };
    return .{ .child = child, .info_r = info.r, .ready_r = ready.r, .gate_w = gate.w };
}

/// bwrap's Spawn from `ends`' descriptors, and its start: bwrap_argv and
/// the keep list (:364-391). Every descriptor in argv is a passFd, so
/// bwrap holds each at the number its argv says.
fn start(
    arena: Allocator,
    s: *const spec.Spec,
    paths: Paths,
    outer: anytype,
    relay: bool,
    stdio: [3]?fd.AnyFd,
    cgroup: ?fd.Fd(.cgroup),
    ends: *const ChildEnds,
) msg.Error!proc.Child {
    var sp = proc.Spawn.init(arena, paths.bwrap) catch return msg.fail(.NOMEM, "malloc", .{});
    // bwrap_argv grows its vector with push, which says "realloc" when it
    // cannot (flong-launch.c:131-133); its asprintf'd elements are the
    // rarer failure and share this word.
    spec.bwrapArgv(arena, &sp, s, .{
        .u1 = outer,
        .u2 = ends.u2,
        .info_w = ends.info_w.?,
        .seccomp = ends.seccomp,
        .resolv = ends.resolv,
        .gate_r = ends.gate_r.?,
        .ready_w = ends.ready_w.?,
    }, relay, paths.self) catch return msg.fail(.NOMEM, "realloc", .{});
    sp.stdio = stdio;
    sp.cgroup = cgroup;
    return sp.start();
}
