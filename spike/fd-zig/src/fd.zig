//! fd.zig: every descriptor the launcher holds, in one table.
//!
//! A handle is a slot and a generation, never a descriptor number. Closing a
//! handle bumps its slot's generation, so every copy of it (in a struct, a
//! keep list, a forked child's globals) is stale from then on, and using one
//! panics instead of reaching whatever file reused the number. The kind is
//! part of the handle's type: a pidfd cannot be passed where a cgroup
//! directory is wanted, and a read on a write end does not compile.
//!
//! The launcher is single-threaded, so the table is a process global with no
//! lock, and a fixed array, so a forked child can use it without allocating.
//! Every open here is close-on-exec. Nothing outside this file touches a raw
//! descriptor except through `raw()`, which the lint confines to syscall
//! wrappers.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

pub const Kind = enum(u8) { file, dir, path, pipe_r, pipe_w, pidfd };

pub const capacity = 64;

const Slot = struct {
    raw: posix.fd_t = -1,
    gen: u32 = 0,
    kind: Kind = .file,
};

var slots = [_]Slot{.{}} ** capacity;

/// A handle of any kind, for keep lists.
pub const AnyFd = struct {
    slot: u8,
    gen: u32,
    kind: Kind,

    pub fn raw(self: AnyFd) posix.fd_t {
        return live(self.slot, self.gen, self.kind).raw;
    }

    pub fn any(self: AnyFd) AnyFd {
        return self;
    }
};

pub fn Fd(comptime k: Kind) type {
    return struct {
        slot: u8,
        gen: u32,

        const Self = @This();
        pub const kind = k;

        /// The descriptor number, for a syscall made now. Panics when the
        /// handle has been closed, or dropped by `retainOnly`.
        pub fn raw(self: Self) posix.fd_t {
            return live(self.slot, self.gen, k).raw;
        }

        pub fn close(self: Self) void {
            const s = live(self.slot, self.gen, k);
            posix.close(s.raw);
            release(s);
        }

        pub fn isLive(self: Self) bool {
            const s = &slots[self.slot];
            return s.raw >= 0 and s.gen == self.gen;
        }

        pub fn any(self: Self) AnyFd {
            return .{ .slot = self.slot, .gen = self.gen, .kind = k };
        }

        pub fn read(self: Self, buf: []u8) posix.ReadError!usize {
            comptime if (k != .file and k != .pipe_r) @compileError("read on a " ++ @tagName(k) ++ " descriptor");
            return posix.read(self.raw(), buf);
        }

        pub fn write(self: Self, bytes: []const u8) posix.WriteError!usize {
            comptime if (k != .file and k != .pipe_w) @compileError("write on a " ++ @tagName(k) ++ " descriptor");
            return posix.write(self.raw(), bytes);
        }
    };
}

pub const File = Fd(.file);
pub const Dir = Fd(.dir);
pub const Path = Fd(.path);
pub const PipeR = Fd(.pipe_r);
pub const PipeW = Fd(.pipe_w);
pub const PidFd = Fd(.pidfd);

fn live(slot: u8, gen: u32, k: Kind) *Slot {
    const s = &slots[slot];
    if (s.raw < 0 or s.gen != gen) @panic("stale fd handle");
    if (s.kind != k) @panic("fd handle of the wrong kind");
    return s;
}

fn release(s: *Slot) void {
    s.raw = -1;
    s.gen +%= 1;
}

pub const Error = error{TableFull};

/// Takes ownership of raw. On TableFull raw is closed, so the caller never
/// has a descriptor the table does not know about.
fn adopt(comptime k: Kind, raw: posix.fd_t) Error!Fd(k) {
    for (&slots, 0..) |*s, i| {
        if (s.raw < 0) {
            s.raw = raw;
            s.kind = k;
            return .{ .slot = @intCast(i), .gen = s.gen };
        }
    }
    posix.close(raw);
    return error.TableFull;
}

fn dirRaw(dir: ?Dir) posix.fd_t {
    return if (dir) |d| d.raw() else posix.AT.FDCWD;
}

pub fn openFile(dir: ?Dir, path: [*:0]const u8, flags: posix.O) (Error || posix.OpenError)!File {
    var f = flags;
    f.CLOEXEC = true;
    return adopt(.file, try posix.openatZ(dirRaw(dir), path, f, 0));
}

pub fn openDir(dir: ?Dir, path: [*:0]const u8) (Error || posix.OpenError)!Dir {
    return adopt(.dir, try posix.openatZ(dirRaw(dir), path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0));
}

pub fn openPath(dir: ?Dir, path: [*:0]const u8) (Error || posix.OpenError)!Path {
    return adopt(.path, try posix.openatZ(dirRaw(dir), path, .{ .PATH = true, .CLOEXEC = true }, 0));
}

pub const Pipe = struct { r: PipeR, w: PipeW };

pub fn pipe() (Error || posix.PipeError)!Pipe {
    const p = try posix.pipe2(.{ .CLOEXEC = true });
    const r = adopt(.pipe_r, p[0]) catch |err| {
        posix.close(p[1]);
        return err;
    };
    errdefer r.close();
    return .{ .r = r, .w = try adopt(.pipe_w, p[1]) };
}

/// The number of live handles.
pub fn liveCount() usize {
    var n: usize = 0;
    for (slots) |s| n += @intFromBool(s.raw >= 0);
    return n;
}

/// The descriptor numbers of every live handle, for tests that compare the
/// table with /proc/self/fd.
pub fn snapshot(buf: *[capacity]posix.fd_t) []posix.fd_t {
    var n: usize = 0;
    for (slots) |s| {
        if (s.raw < 0) continue;
        buf[n] = s.raw;
        n += 1;
    }
    return buf[0..n];
}

// ---- fork ----

/// For a forked child: closes every descriptor >= 3 but keep's, in the
/// kernel and in the table. Every other handle, in any variable, is stale
/// from here on. Allocates nothing.
pub fn retainOnly(keep: []const AnyFd) !void {
    var kept: [capacity]posix.fd_t = undefined;
    var n: usize = 0;
    for (keep) |h| {
        kept[n] = h.raw();
        n += 1;
    }
    for (&slots, 0..) |*s, i| {
        if (s.raw < 0) continue;
        const wanted = for (keep) |h| {
            if (h.slot == i) break true;
        } else false;
        if (!wanted) release(s);
    }
    std.mem.sort(posix.fd_t, kept[0..n], {}, std.sort.asc(posix.fd_t));
    var low: posix.fd_t = 3;
    for (kept[0..n]) |k| {
        if (k > low) try closeRange(low, k - 1);
        if (k >= low) low = k + 1;
    }
    try closeRange(low, std.math.maxInt(posix.fd_t));
}

const close_range_cloexec = 1 << 2; // CLOSE_RANGE_CLOEXEC, not in std

fn closeRange(first: posix.fd_t, last: posix.fd_t) !void {
    const rc = linux.syscall3(.close_range, @intCast(first), @intCast(last), 0);
    if (linux.E.init(rc) != .SUCCESS) return error.CloseRange;
}

const CloneArgs = extern struct {
    flags: u64 = 0,
    pidfd: u64 = 0,
    child_tid: u64 = 0,
    parent_tid: u64 = 0,
    exit_signal: u64 = 0,
    stack: u64 = 0,
    stack_size: u64 = 0,
    tls: u64 = 0,
    set_tid: u64 = 0,
    set_tid_size: u64 = 0,
    cgroup: u64 = 0,
};

/// clone3 with CLONE_PIDFD: 0 in the child, the pid in the parent.
fn clonePidfd(pidfd: *posix.fd_t) !posix.pid_t {
    var ca: CloneArgs = .{
        .flags = linux.CLONE.PIDFD,
        .pidfd = @intFromPtr(pidfd),
        .exit_signal = linux.SIG.CHLD,
    };
    const rc = linux.syscall2(.clone3, @intFromPtr(&ca), @sizeOf(CloneArgs));
    if (linux.E.init(rc) != .SUCCESS) return error.Clone;
    return @intCast(rc);
}

/// A child of ours, owned through its pidfd. It is reaped exactly once:
/// `wait` reaps it, and `deinit` kills and reaps it if nothing has.
pub const Child = struct {
    pidfd: PidFd,
    pid: posix.pid_t,
    status: ?u8 = null,

    /// Blocks until the child exits and reaps it. The exit code, or 128+n
    /// for a signal, as a shell reports it.
    pub fn wait(self: *Child) !u8 {
        if (self.status) |s| return s;
        var info: linux.siginfo_t = undefined;
        while (true) {
            const rc = linux.waitid(.PIDFD, self.pidfd.raw(), &info, linux.W.EXITED);
            switch (linux.E.init(rc)) {
                .SUCCESS => break,
                .INTR => continue,
                else => return error.Wait,
            }
        }
        const st: u8 = @truncate(@as(u32, @bitCast(info.fields.common.second.sigchld.status)));
        const s: u8 = if (info.code == 1) st else 128 +% st; // CLD_EXITED
        self.status = s;
        return s;
    }

    pub fn deinit(self: *Child) void {
        if (self.status == null) {
            _ = linux.pidfd_send_signal(self.pidfd.raw(), linux.SIG.KILL, null, 0);
            // A cleanup path: the child was just killed, and a failed wait
            // leaves nothing to do but close the pidfd.
            // zwanzig-disable-next-line: empty-catch-engine
            _ = self.wait() catch {};
        }
        self.pidfd.close();
    }
};

/// Forks a helper that runs our code. Returns null in the child, which
/// holds only keep (see retainOnly) and must end in exit.
pub fn fork(keep: []const AnyFd) !?Child {
    var raw: posix.fd_t = -1;
    const pid = try clonePidfd(&raw);
    if (pid == 0) {
        retainOnly(keep) catch linux.exit_group(125);
        return null;
    }
    return .{ .pidfd = try adopt(.pidfd, raw), .pid = pid };
}

// ---- spawn ----

/// A program to start. The only way to name a descriptor in its argv is
/// `passFd`, which also keeps it, so an argv number the child does not hold,
/// or a kept descriptor argv does not name, cannot be written.
pub const Spawn = struct {
    argv: [max_args:null]?[*:0]const u8 = .{null} ** max_args,
    argc: usize = 0,
    numbers: [max_keep][12:0]u8 = undefined,
    keep: [max_keep]AnyFd = undefined,
    nkeep: usize = 0,
    stdout: ?PipeW = null,

    const max_args = 64;
    const max_keep = 16;

    pub fn init(program: [*:0]const u8) Spawn {
        var s: Spawn = .{};
        s.argv[0] = program;
        s.argc = 1;
        return s;
    }

    pub fn arg(self: *Spawn, a: [*:0]const u8) !void {
        if (self.argc == max_args) return error.TooManyArgs;
        self.argv[self.argc] = a;
        self.argc += 1;
    }

    /// Appends h's number to argv and keeps h at that number in the child.
    pub fn passFd(self: *Spawn, h: anytype) !void {
        if (self.nkeep == max_keep) return error.TooManyFds;
        const buf = &self.numbers[self.nkeep];
        const text = std.fmt.bufPrintZ(buf, "{d}", .{h.raw()}) catch unreachable;
        self.keep[self.nkeep] = h.any();
        self.nkeep += 1;
        try self.arg(text.ptr);
    }

    pub fn start(self: *Spawn) !Child {
        var raw: posix.fd_t = -1;
        const pid = try clonePidfd(&raw);
        if (pid == 0) self.child();
        return .{ .pidfd = try adopt(.pidfd, raw), .pid = pid };
    }

    fn child(self: *Spawn) noreturn {
        if (self.stdout) |w| {
            if (linux.E.init(linux.dup2(w.raw(), 1)) != .SUCCESS) linux.exit_group(127);
        }
        // Everything >= 3 close-on-exec, then only the kept ones cleared.
        if (linux.E.init(linux.syscall3(.close_range, 3, std.math.maxInt(u32), close_range_cloexec)) != .SUCCESS)
            linux.exit_group(127);
        for (self.keep[0..self.nkeep]) |h| {
            if (linux.E.init(linux.fcntl(h.raw(), linux.F.SETFD, 0)) != .SUCCESS) linux.exit_group(127);
        }
        const envp: [*:null]const ?[*:0]const u8 = @ptrCast(std.os.environ.ptr);
        _ = linux.execve(self.argv[0].?, &self.argv, envp);
        linux.exit_group(127);
    }
};
