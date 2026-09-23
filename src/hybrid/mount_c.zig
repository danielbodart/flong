//! mount_c.zig: the mount-helper shim (ZIG.md, "The mount-helper shim"),
//! the root of libflong-mount.a, which the C launcher links. Its one
//! export, flong_mount_main, is what flong-launch.c:553 calls in the
//! fl_fork child where it called `_exit(mount_run(&job))`.
//!
//! No Zig start code runs: the child is the C launcher's, on its stack, in
//! its copy of memory. This file sets what a root sets (msg's program name,
//! cut mode and the trace flag), adopts the three descriptors the child
//! kept (flong-util.c:467-482: U1, the ready pipe's read end and the
//! leader's pidfd), turns struct fl_mount_job into a mount.Job, runs
//! mount.run and ends the process: 0, or 1 after saying why, as mount_run
//! returned (flong-mount.c:617-620); a panic says one line and exits 125,
//! which the launcher reads as a failed mount (flong-launch.c:570-575).
//! Nothing is freed: exit owns everything (flong-mount.c:3-5).
//!
//! The only user of fd.adoptForeign (the lint's `adopt-foreign`) and, with
//! scmp.zig, the only file that exports. The library links no libc and no
//! compiler-rt: memcpy and memset are the C's glibc's (build.zig,
//! `mountlib`; the clash check in native.nix). Deleted with the C launcher
//! (phase 7, L5).

const std = @import("std");
const sys = @import("sys");
const fd = @import("fd");
const msg = @import("msg");
const mount = @import("mount");

/// "flong-launch: internal error: <msg>", 125: one line, as the helper's
/// every other failure, and the status fl_die's children use for "said
/// why" (flong-util.c:98-105).
pub const panic = std.debug.FullPanic(msg.onPanic(125));

/// struct fl_mount (flong-spec.h:37-44), as the C lays it out; checked
/// against translate-c of the header (tests/zig/libc_mount.zig).
pub const FlMount = extern struct {
    kind: c_uint,
    dest: ?[*:0]const u8,
    src: ?[*:0]const u8,
    mode: ?[*:0]const u8,
    size: ?[*:0]const u8,
    owner_user: c_int,
};

/// struct fl_mount_job (flong-mount.h:67-81), as the C lays it out.
pub const FlMountJob = extern struct {
    u1: c_int,
    leader_pidfd: c_int,
    ready: c_int,
    mounts: ?[*]const FlMount,
    nmounts: usize,
    uid: u32,
    gid: u32,
    home: ?[*:0]const u8,
    protect: ?[*]const [*:0]const u8,
    nprotect: usize,
};

/// enum fl_mount_kind's values (flong-spec.h:26-35), in mount.Kind's order.
pub const kinds = [_]mount.Kind{ .bind_ro, .bind_rw, .bind_ro_exact, .bind_rw_exact, .dev, .tmpfs, .overlay, .mask };

fn span(p: ?[*:0]const u8) ?[:0]const u8 {
    return if (p) |s| std.mem.span(s) else null;
}

/// The job in mount.zig's terms, its arrays from page_allocator in the
/// child. A full table here is the launcher's bug: it kept three.
fn job(c: *const FlMountJob) msg.Error!mount.Job {
    const mounts = std.heap.page_allocator.alloc(mount.Mount, c.nmounts) catch return msg.fail(.NOMEM, "calloc", .{});
    for (mounts, 0..) |*m, i| {
        const cm = c.mounts.?[i];
        if (cm.kind >= kinds.len) @panic("unknown mount kind");
        m.* = .{
            .kind = kinds[cm.kind],
            .dest = span(cm.dest).?,
            .src = span(cm.src),
            .mode = span(cm.mode),
            .size = span(cm.size),
            .owner_user = cm.owner_user != 0,
        };
    }
    const protect = std.heap.page_allocator.alloc([:0]const u8, c.nprotect) catch return msg.fail(.NOMEM, "calloc", .{});
    for (protect, 0..) |*p, i| p.* = std.mem.span(c.protect.?[i]);
    return .{
        .u1 = fd.adoptForeign(.userns, c.u1) catch @panic("no slot for U1"),
        .ready = fd.adoptForeign(.pipe_r, c.ready) catch @panic("no slot for the ready pipe"),
        .leader = fd.adoptForeign(.pidfd, c.leader_pidfd) catch @panic("no slot for the leader's pidfd"),
        .mounts = mounts,
        .uid = c.uid,
        .gid = c.gid,
        .home = span(c.home).?,
        .protect = protect,
    };
}

/// The mount helper's whole life, called in the fl_fork child
/// (flong-mount.h's prototype). `tracing` is fl_tracing (flong-util.h:43).
pub export fn flong_mount_main(c: *const FlMountJob, tracing: c_int) callconv(.c) noreturn {
    msg.prog = "flong-launch";
    msg.mode = .cut;
    msg.tracing = tracing != 0;
    const j = job(c) catch sys.exitGroup(1);
    mount.run(&j) catch sys.exitGroup(1);
    sys.exitGroup(0);
}
