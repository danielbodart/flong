//! launch/prologue.zig: the pieces of flong launch's prologue, ordering
//! checkpoint 1 (DESIGN.md; launcher/flong-launch.c:847-925 of 5f1f08e), but
//! not the prologue itself: the relaunch of a swept launch (quirk 2), the
//! cache's shared lock, the close of what the wrapper left open, and the
//! protected paths made canonical (quirk 21). launch.zig's main calls them
//! in the C's order, one linear function; none of them decides that order.
//! `flong launch DECL.zon`'s own prologue, which stands in for the wrapper
//! ahead of checkpoint 1 (STANDALONE.md, S3), shares three things here:
//! exit_refused, relaunchSelf (the wrapper's `exec "$self"`) and
//! kernelName (quirk 21's readlink, which launch/workspace.zig's canon
//! uses).
//!
//! A small deviation from the port's plan, which had flong-launch's
//! own code in one launch.zig: its helpers are split by concern into
//! src/launch/, one module per piece, each taking what it needs as
//! parameters (no Launch struct), so each is tested alone. launch.zig stays
//! the root and holds the order and the teardown.
//!
//! state_open is record.stateOpen, ported with the sweeper in phase 5
//! (flong-record.c:58-89), re-exported here with its State. Quirk 21's
//! access(X_OK) is sys.access, faccessat(AT_FDCWD), which record.poststop
//! already makes; the launcher itself makes no access call.
//!
//! Failures are printed where they happen and come back as error.Reported,
//! or error.Aborted for a terminating signal during the cache's wait
//! (sig.zig); a swept cache is a value, not an error.

const std = @import("std");
const sys = @import("sys");
const fdt = @import("fd");
const msg = @import("msg");
const sig = @import("sig");
const proc = @import("proc");
const record = @import("record");

const Allocator = std.mem.Allocator;
const path_max = sys.path_max;

/// A launch that did not reach its payload (flong-launch.c:43-45).
pub const exit_not_run = 125;
/// A launch whose cache was swept, with no relaunch to run
/// (flong-launch.c:43-45; DESIGN.md, "Exit codes").
pub const exit_swept = 75;
/// A refusal of `flong launch DECL.zon`'s own prologue, the part that
/// stands in for rootless-wrapper.bash (STANDALONE.md, S3): the wrapper's
/// die (:41-44) printed "$name: <text>" and exited 1, and its callers
/// assert both. Its modules (caller, workspace, cmd, binds, identity,
/// prepare) say a refusal through msg with msg.prog set to the
/// declaration's name, and pass error.Reported up; the prologue exits
/// with this. The launcher's own refusals, after it, keep "flong launch:"
/// and 125.
pub const exit_refused = 1;

// ---- step 3: the state directory (flong-launch.c:891-893) ----

/// state_open (flong-record.c:58-89): the state directory and its
/// sessions/, held until exit.
pub const stateOpen = record.stateOpen;
pub const State = record.State;

// ---- step 4: the cache (flong-launch.c:895-908) ----

/// What cache_lock found (flong-record.c:91-149): the cache, locked shared
/// and held for the launcher's life (flong-launch.c:55), or swept.
pub const CacheLock = union(enum) {
    locked: fdt.Held(.dir),
    /// A sweep took the cache away before the lock was granted, or the
    /// path names a cache another wrapper is still preparing: relaunch.
    swept,
};

/// cache_lock (flong-record.c:91-149): opens `cache`, following symlinks
/// (O_RDONLY|O_DIRECTORY|O_CLOEXEC), and takes a shared lock on it. The one
/// exclusive holder is a sweep of a superseded cache, which holds the lock
/// while it renames the cache away and deletes it, as long as that takes,
/// so the wait is proc.lockWait's, which a terminating signal ends
/// (error.Aborted). Then the cache is swept when the path no longer names
/// what was locked (the sweep renamed it away before the lock was granted)
/// or names a cache without prepared/ (another launch's wrapper made a cache
/// in its place and is still preparing it: its shared lock is granted
/// beside this one, and prepared/ appears only once it is done; the wrapper,
/// run again, waits for that preparer's lock). Once prepared/ is seen under
/// this shared lock it stays, since a sweep must hold the lock exclusively
/// to take the cache away. Called before closeUntracked: a cold wrapper's
/// own shared lock on the cache must not go before this one is held
/// (flong-launch.c:895-896).
pub fn cacheLock(cache: [:0]const u8) sig.Error!CacheLock {
    const cfd = switch (fdt.openDir(fdt.cwd, cache) catch return msg.refuse("cache {s}: too many open descriptors", .{cache})) {
        .ok => |h| h,
        .err => |e| return if (e == .NOENT) .swept else msg.fail(e, "cache {s}", .{cache}),
    };
    const kept = stillNamed(cfd, cache) catch |err| {
        cfd.close();
        return err;
    };
    if (!kept) {
        cfd.close();
        return .swept;
    }
    return .{ .locked = cfd.holdUntilExit() };
}

/// cache_lock's lock and checks (flong-record.c:103-142), on the open
/// `cfd`: true when the path still names it and it holds prepared/.
fn stillNamed(cfd: fdt.Dir, cache: [:0]const u8) sig.Error!bool {
    try proc.lockWait(cfd, sys.LOCK.SH);
    // The lock is on what was opened (:106-108).
    const locked = try msg.check(cfd.fstat(), "stat {s}", .{cache});
    const named = switch (sys.fstatat(sys.AT.FDCWD, cache, 0)) {
        .ok => |st| st,
        .err => |e| return if (e == .NOENT) false else msg.fail(e, "stat {s}", .{cache}),
    };
    if (named.dev != locked.dev or named.ino != locked.ino) return false;
    // The path naming what was locked is not enough (:127-136).
    switch (cfd.fstatat("prepared", 0)) {
        .ok => return true,
        .err => |e| return if (e == .NOENT) false else msg.fail(e, "stat {s}/prepared", .{cache}),
    }
}

/// relaunch (flong-launch.c:156-175): the answer to a swept cache. Each turn
/// follows a sweep's rename, an event, so there is no count. With no
/// relaunch argv it says so and returns 75. Otherwise it says it is
/// relaunching and execs `argv` (the wrapper, run again, prepares afresh or
/// waits for the preparer's lock) with `envp`, having put back SIGPIPE's
/// default and `old_mask`, which survive exec (quirk 2, kept: before
/// closeUntracked, so the wrapper's inherited descriptors reach it; the
/// launcher's own are close-on-exec). The path is not checked absolute:
/// the launcher has not changed directory, and the wrapper's $0 may be
/// relative (quirk 30). It returns only when the exec failed, having said
/// why: 125. The argv vector is built in `gpa`; if that fails the exec is
/// said to fail with ENOMEM, where the C had no allocation to fail.
pub fn relaunch(
    gpa: Allocator,
    cache: []const u8,
    argv: []const [:0]const u8,
    old_mask: u64,
    envp: [*:null]const ?[*:0]const u8,
) u8 {
    if (argv.len == 0) {
        msg.say("the cache {s} was swept before this launch locked it", .{cache});
        return exit_swept;
    }
    msg.say("the cache {s} was swept before this launch locked it; relaunching", .{cache});
    execArgv(gpa, argv[0], argv, old_mask, envp);
    return exit_not_run;
}

/// relaunch for a launch from a declaration, which has no relaunch argv:
/// says it is relaunching, as `relaunch` does, and execs this binary again
/// with the process's own `argv` (relaunchSelf), with `envp` and
/// `old_mask` back. It returns only when the exec failed, having said
/// why: 125.
pub fn relaunchSwept(
    gpa: Allocator,
    cache: []const u8,
    argv: []const [*:0]const u8,
    old_mask: u64,
    envp: [*:null]const ?[*:0]const u8,
) u8 {
    msg.say("the cache {s} was swept before this launch locked it; relaunching", .{cache});
    return switch (relaunchSelf(gpa, argv, old_mask, envp)) {
        error.Reported => exit_not_run,
    };
}

/// The wrapper's own relaunch (rootless-wrapper.bash:299, 307, 337:
/// `exec "$self" "${launcher_args[@]}"`), for the three points where
/// `flong launch DECL.zon`'s prologue finds its cache swept before it
/// holds it (launch/prepare.zig, launch/identity.zig). Silent, as the
/// wrapper's was: it execs this very binary, readlink(/proc/self/exe), with
/// `argv`, the process's whole argv as the kernel gave it, argv[0]
/// untouched, so a declaration's symlink name is looked up again
/// (STANDALONE.md, "The declaration's command"), and with `envp`, the
/// environment it started with. SIGPIPE's default is put back, and the
/// mask `old_mask` when there is one, as relaunch does (quirk 2). It
/// returns only when it could not exec, having said why: error.Reported,
/// which the prologue exits 1 with, as the wrapper's failed exec ended it.
pub fn relaunchSelf(
    gpa: Allocator,
    argv: []const [*:0]const u8,
    old_mask: ?u64,
    envp: [*:null]const ?[*:0]const u8,
) msg.Error {
    var buf: [path_max]u8 = undefined;
    const n = switch (sys.readlinkat(sys.AT.FDCWD, "/proc/self/exe", &buf)) {
        .ok => |n| n,
        .err => |e| return msg.fail(e, "readlink /proc/self/exe", .{}),
    };
    if (n >= buf.len) return msg.fail(.NAMETOOLONG, "readlink /proc/self/exe", .{});
    buf[n] = 0;
    execArgv(gpa, buf[0..n :0], argv, old_mask, envp);
    return error.Reported;
}

/// execve(path, argv, envp) with SIGPIPE's default and `old_mask` back,
/// saying why when it returns. The argv vector is built in `gpa`; if that
/// fails the exec is said to fail with ENOMEM.
fn execArgv(
    gpa: Allocator,
    path: [*:0]const u8,
    argv: anytype,
    old_mask: ?u64,
    envp: [*:null]const ?[*:0]const u8,
) void {
    const v = gpa.allocSentinel(?[*:0]const u8, argv.len, null) catch {
        msg.sayErrno(.NOMEM, "exec {s}", .{path});
        return;
    };
    for (argv, v) |a, *slot| slot.* = switch (@typeInfo(@TypeOf(a)).pointer.size) {
        .slice => a.ptr,
        else => a,
    };
    sig.defaultPipe();
    if (old_mask) |m| sig.setMask(m);
    msg.sayErrno(sys.execve(path, v.ptr, envp), "exec {s}", .{path});
}

// ---- step 5: what the wrapper held (flong-launch.c:909-925) ----

/// Closes every descriptor from 3 up that the table does not hold
/// (fd.closeUntracked): at this step the table is flong-launch.c:910-914's
/// keep list, the keep-fds (adopted), the signalfd, the state and sessions
/// directories and the cache, so whatever else the wrapper held goes.
/// Failure: "close_range <low>: <strerror>" (flong-util.c:160).
pub fn closeUntracked() msg.Error!void {
    if (fdt.closeUntracked()) |f| return msg.fail(f.err, "close_range {d}", .{f.low});
}

// ---- the protected paths (flong-launch.c:177-248) ----

/// realpath(3) by quirk 21's mechanism (as spec.closure and
/// record.realPath): an O_PATH open of `at`, following symlinks, and the
/// kernel's name for it, the readlink of its selfPath. A name that does not
/// fit PATH_MAX with its NUL is ENAMETOOLONG, as glibc's realpath says. The
/// open needs a free descriptor and /proc, where glibc's needs neither
/// (quirk 21): a full table is said as "realpath <path>: too many open
/// descriptors", `path` being the one canonical was given.
fn realPath(path: []const u8, at: [:0]const u8, buf: *[path_max]u8) msg.Error!sys.Result([:0]const u8) {
    const r = fdt.openPath(fdt.cwd, at, .{}) catch return msg.refuse("realpath {s}: too many open descriptors", .{path});
    const h = switch (r) {
        .ok => |h| h,
        .err => |e| return .{ .err = e },
    };
    defer h.close();
    return kernelName(h, buf);
}

/// The kernel's name for what `h`, an O_PATH handle, names: the readlink
/// of its selfPath, quirk 21's mechanism, which realPath and the
/// workspace's resolution (launch/workspace.zig) share. A name that does
/// not fit PATH_MAX with its NUL is ENAMETOOLONG.
pub fn kernelName(h: fdt.Fd(.path), buf: *[path_max]u8) sys.Result([:0]const u8) {
    const link = fdt.selfPath(h);
    const n = switch (sys.readlinkat(sys.AT.FDCWD, link.path(), buf)) {
        .ok => |n| n,
        .err => |e| return .{ .err = e },
    };
    if (n >= buf.len) return .{ .err = .NAMETOOLONG };
    buf[n] = 0;
    return .{ .ok = buf[0..n :0] };
}

/// canonical (flong-launch.c:179-229): a protected path in the form the
/// mount helper compares sources with, the canonical path, so a bind
/// through a symlink to it is still caught. A path that does not exist yet
/// (a socket directory made later) is canonical up to its longest prefix
/// that exists, with the rest appended as given: a bind of a directory that
/// will contain it must still be caught, and the sources the helper
/// compares are the kernel's resolved paths. The prefix is cut at each '/'
/// from the right until it resolves; "/" always does, so the walk ends. Any
/// failure but ENOENT, of the path or of a prefix, is "realpath <path>:
/// <strerror>"; so is a path with no '/' left to cut at, as ENOENT. The
/// result is `gpa`'s; an allocation failure is said as the C's strdup or
/// asprintf.
pub fn canonical(gpa: Allocator, path: [:0]const u8) msg.Error![:0]const u8 {
    var buf: [path_max]u8 = undefined;
    switch (try realPath(path, path, &buf)) {
        .ok => |p| return gpa.dupeZ(u8, p) catch return msg.fail(.NOMEM, "realpath {s}", .{path}),
        .err => |e| if (e != .NOENT) return msg.fail(e, "realpath {s}", .{path}),
    }

    const prefix = gpa.dupeZ(u8, path) catch return msg.fail(.NOMEM, "strdup", .{});
    defer gpa.free(prefix);
    var end = path.len;
    const real = while (true) {
        const slash = std.mem.lastIndexOfScalar(u8, prefix[0..end], '/') orelse
            return msg.fail(.NOENT, "realpath {s}", .{path});
        end = slash;
        prefix[slash] = 0;
        switch (try realPath(path, if (slash == 0) "/" else prefix[0..slash :0], &buf)) {
            .ok => |p| break p,
            .err => |e| if (e != .NOENT) return msg.fail(e, "realpath {s}", .{path}),
        }
    };
    const rest = path[end + 1 ..];
    const sep: []const u8 = if (std.mem.eql(u8, real, "/")) "" else "/";
    return std.fmt.allocPrintSentinel(gpa, "{s}{s}{s}", .{ real, sep, rest }, 0) catch
        return msg.fail(.NOMEM, "asprintf", .{});
}

/// protect_paths (flong-launch.c:231-248): the spec's protect paths, then
/// the state directory (records make the sweep run programs) and the
/// holder's cgroup (cgroup.kill), which the launcher adds itself, each made
/// canonical, in that order, stopping at the first failure. The mount
/// helper's job.protect (mount.zig). The slice is `gpa`'s.
pub fn protectPaths(
    gpa: Allocator,
    protect: []const [:0]const u8,
    state: [:0]const u8,
    holder: [:0]const u8,
) msg.Error![]const [:0]const u8 {
    const out = gpa.alloc([:0]const u8, protect.len + 2) catch return msg.fail(.NOMEM, "calloc", .{});
    var n: usize = 0;
    errdefer {
        for (out[0..n]) |p| gpa.free(p);
        gpa.free(out);
    }
    for (protect) |p| {
        out[n] = try canonical(gpa, p);
        n += 1;
    }
    out[n] = try canonical(gpa, state);
    n += 1;
    out[n] = try canonical(gpa, holder);
    return out;
}
