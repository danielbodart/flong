//! fd.zig: every descriptor a flong program opens, in one table (ZIG.md,
//! "The descriptor layer"). The spike's table (spike/fd-zig/src/fd.zig, now
//! in ~/Projects/flong-spikes-archive/zig), moved onto sys.zig.
//!
//! A handle is a slot and a generation, never a descriptor number. Closing a
//! handle bumps its slot's generation, so every copy of it (in a struct, a
//! keep list, a forked child's globals) is stale from then on, and `raw()`
//! on a stale copy panics instead of reaching whatever file reused the
//! number. The kind is part of the handle's type: an operation a kind does
//! not have is a compile error, and a handle of one kind is not another's.
//!
//! The programs are single-threaded, so the table is a process global with
//! no lock, and a fixed array, so a forked child can use it without
//! allocating. Every open here is O_CLOEXEC. Nothing outside the syscall
//! layer touches a descriptor's number but through `raw()`, which the lint
//! confines (tools/fdlint.zig, `raw-number`); `selfPath` is one of the ways
//! out.
//!
//! Phase 2 has the kinds flong-seccomp needs, `file` and `dir` (ZIG.md,
//! "Descriptor kinds"); each later phase adds its own, with its minting
//! functions and zwanzig's open model for each (.zwanzig.json). Phase 4
//! adds the mount helper's (flong-mount.c): `path` (O_PATH), `tree` (a
//! detached mount), `fsctx` (a filesystem being configured), the four
//! namespaces it enters, `pipe_r` (the ready pipe) and `pidfd` (the
//! leader's, adopted); and `adoptForeign`, for the shim alone. Phase 5
//! adds flong-sweeper's and the process layer's (flong-util.c,
//! flong-cgroup.c, flong-record.c): `cgroup` (an O_PATH cgroup directory,
//! the only kind fork and Spawn create a child in), `inotify`, `pipe_w`,
//! `signalfd`, `inherited` (a descriptor the caller handed over, which
//! Spawn keeps), pidfds of its own children (`proc.zig`, whose slot is
//! reserved before clone3) and `retainOnly`, a fork child's close of all
//! but its keep list. Phase 7's L2 adds the launch's: `record` (a session's
//! record, made unnamed with O_TMPFILE, flong-record.c:343-386) and U1's
//! and U2's `userns` by /proc/<pid>/ns/user (flong-ns.c:141-150). L3 adds
//! the terminal's (flong-tty.c): `pty_master`, `pty_slave` and `tty_out`,
//! the terminal calls on Stdio, and `pollEntry`, for a poll over several
//! descriptors.
//!
//!   Fd(k)       an owned handle: `close` once, then every copy is stale
//!   Held(k)     `h.holdUntilExit()`: the same descriptor, no `close`, for
//!               what the C never closes (flong-launch.c:52-78, 785-845)
//!   AnyFd       a handle of any kind, for keep lists
//!   Stdio       0-2, outside the table: read and write, no `close`
//!   cwd         the working directory, where a directory is taken
//!
//! An open returns `Error!sys.Result(Fd(k))`: the kernel's errno as a
//! value, or `error.TableFull` when every slot is taken ("too many open
//! descriptors", where the C would get EMFILE: quirk 41), with the
//! descriptor the kernel gave already closed. msg.check says either.

const std = @import("std");
const sys = @import("sys");

pub const Kind = enum(u8) {
    file,
    dir,
    /// O_PATH: a place, not its contents (flong-mount.c:145, 314-353).
    path,
    /// A detached mount: open_tree's clone or fsmount's new one.
    tree,
    /// fsopen's filesystem context.
    fsctx,
    userns,
    mntns,
    netns,
    cgroupns,
    pipe_r,
    pidfd,
    /// O_PATH|O_DIRECTORY|O_NOFOLLOW of a cgroup (flong-cgroup.c:123-126).
    cgroup,
    inotify,
    pipe_w,
    signalfd,
    /// A descriptor the caller handed over at a number the spec named
    /// (flong-launch.c:407-408; ZIG.md, "The descriptor layer").
    inherited,
    /// A session's record (flong-record.c:343-417): made unnamed with
    /// O_TMPFILE|O_RDWR, locked, written at its offset (never O_APPEND),
    /// read and blanked at 0, linked by its selfPath, unlinked before its
    /// close (ZIG.md, ordering checkpoint 10).
    record,
    /// The relay's pty master, O_NONBLOCK (flong-tty.c:169-175).
    pty_master,
    /// The pty's slave, opened by path: the payload's terminal.
    pty_slave,
    /// The caller's terminal opened again, O_NONBLOCK, for the relay's
    /// output (flong-tty.c:196-203).
    tty_out,
};

/// A namespace setns enters, with the kind of descriptor naming it.
pub const Ns = enum {
    user,
    mnt,
    net,
    cgroup,

    fn kind(comptime ns: Ns) Kind {
        return switch (ns) {
            .user => .userns,
            .mnt => .mntns,
            .net => .netns,
            .cgroup => .cgroupns,
        };
    }

    fn flag(comptime ns: Ns) u32 {
        return switch (ns) {
            .user => sys.CLONE.NEWUSER,
            .mnt => sys.CLONE.NEWNS,
            .net => sys.CLONE.NEWNET,
            .cgroup => sys.CLONE.NEWCGROUP,
        };
    }
};

/// Slots in the table: 1024, the default soft RLIMIT_NOFILE, where the C
/// would get EMFILE (quirk 41). The spike had 64 (fd.zig:22).
pub const capacity = 1024;

pub const Error = error{TableFull};

/// A slot's raw value when it holds no descriptor, and when fork or
/// Spawn.start has reserved it for the pidfd clone3 is about to make
/// (quirk 26). Neither is live.
const free: sys.fd_t = -1;
const reserved: sys.fd_t = -2;

const Slot = struct {
    raw: sys.fd_t = free,
    gen: u32 = 0,
    kind: Kind = .file,
};

var slots: [capacity]Slot = @splat(.{});

/// The slot a live handle names, or a panic: a stale handle (closed, or
/// dropped by a fork child) or one of another kind reaching a descriptor
/// fails closed rather than touching the file that reused its number
/// (quirk 40).
fn live(slot: u16, gen: u32, k: Kind) *Slot {
    const s = &slots[slot];
    if (s.raw < 0 or s.gen != gen) @panic("stale descriptor handle");
    if (s.kind != k) @panic("descriptor handle of the wrong kind");
    return s;
}

fn release(s: *Slot) void {
    s.raw = free;
    s.gen +%= 1;
}

/// Takes ownership of `raw`. On TableFull `raw` is closed, so no caller
/// holds a descriptor the table does not know.
fn adopt(comptime k: Kind, raw: sys.fd_t) Error!Fd(k) {
    for (&slots, 0..) |*s, i| {
        if (s.raw == free) {
            s.raw = raw;
            s.kind = k;
            return .{ .slot = @intCast(i), .gen = s.gen };
        }
    }
    sys.close(raw);
    return error.TableFull;
}

/// An open's result: adopted into the table, or the kernel's errno.
fn adopted(comptime k: Kind, r: sys.Result(sys.fd_t)) Error!sys.Result(Fd(k)) {
    return switch (r) {
        .ok => |raw| .{ .ok = try adopt(k, raw) },
        .err => |e| .{ .err = e },
    };
}

/// A handle of any kind, as a keep list holds it.
pub const AnyFd = struct {
    slot: u16,
    gen: u32,
    kind: Kind,

    pub fn raw(self: AnyFd) sys.fd_t {
        return live(self.slot, self.gen, self.kind).raw;
    }

    pub fn isLive(self: AnyFd) bool {
        const s = &slots[self.slot];
        return s.raw >= 0 and s.gen == self.gen and s.kind == self.kind;
    }

    /// Itself, so a keep list or Spawn.passFd takes it as any handle.
    pub fn any(self: AnyFd) AnyFd {
        return self;
    }
};

const Ownership = enum { owned, held };

/// An owned handle of kind `k`.
pub fn Fd(comptime k: Kind) type {
    return Handle(k, .owned);
}

/// A handle of kind `k` kept until the process exits: no `close`. A fork
/// child that does not keep it drops it, as any other (phase 5).
pub fn Held(comptime k: Kind) type {
    return Handle(k, .held);
}

pub const File = Fd(.file);
pub const Dir = Fd(.dir);

fn Handle(comptime k: Kind, comptime own: Ownership) type {
    return struct {
        slot: u16,
        gen: u32,

        const Self = @This();
        pub const kind = k;

        /// The descriptor's number, for a syscall made now. Panics when the
        /// handle has been closed.
        pub fn raw(self: Self) sys.fd_t {
            return live(self.slot, self.gen, k).raw;
        }

        pub fn isLive(self: Self) bool {
            const s = &slots[self.slot];
            return s.raw >= 0 and s.gen == self.gen;
        }

        pub fn any(self: Self) AnyFd {
            return .{ .slot = self.slot, .gen = self.gen, .kind = k };
        }

        /// Closes it; every copy of the handle is stale from here on.
        pub fn close(self: Self) void {
            if (own == .held) @compileError("close on a Held descriptor: it is kept until the process exits");
            const s = live(self.slot, self.gen, k);
            sys.close(s.raw);
            release(s);
        }

        /// `close`, answering close(2)'s errno, as flong-mount.c:285 reads
        /// it. The handle is stale whatever it answers.
        pub fn closeChecked(self: Self) sys.Result(void) {
            if (own == .held) @compileError("close on a Held descriptor: it is kept until the process exits");
            const s = live(self.slot, self.gen, k);
            const r = sys.closeChecked(s.raw);
            release(s);
            return r;
        }

        /// The same descriptor, kept until the process exits: the Held
        /// handle has no `close`. This one stays usable, a copy of it.
        pub fn holdUntilExit(self: Self) Held(k) {
            if (own == .held) @compileError("already held");
            _ = live(self.slot, self.gen, k);
            return .{ .slot = self.slot, .gen = self.gen };
        }

        fn need(comptime what: []const u8, comptime kinds: []const Kind) void {
            for (kinds) |x| {
                if (x == k) return;
            }
            @compileError(what ++ " on a " ++ @tagName(k) ++ " descriptor");
        }

        // ---- file ----

        pub fn read(self: Self, buf: []u8) sys.Result(usize) {
            comptime need("read", &.{ .file, .pipe_r, .pty_master });
            return sys.read(self.raw(), buf);
        }

        pub fn write(self: Self, bytes: []const u8) sys.Result(usize) {
            comptime need("write", &.{ .file, .pipe_w, .record, .pty_master, .tty_out });
            return sys.write(self.raw(), bytes);
        }

        /// Writes all of `bytes`, going on after a short write.
        pub fn writeAll(self: Self, bytes: []const u8) sys.Result(void) {
            comptime need("write", &.{ .file, .pipe_w });
            return writeAllTo(self.raw(), bytes);
        }

        pub fn pread(self: Self, buf: []u8, offset: u64) sys.Result(usize) {
            comptime need("pread", &.{ .file, .record });
            return sys.pread(self.raw(), buf, offset);
        }

        pub fn pwrite(self: Self, bytes: []const u8, offset: u64) sys.Result(usize) {
            comptime need("pwrite", &.{ .file, .record });
            return sys.pwrite(self.raw(), bytes, offset);
        }

        pub fn fstat(self: Self) sys.Result(sys.Stat) {
            comptime need("fstat", &.{ .file, .dir, .path, .tree, .cgroup, .record });
            return sys.fstat(self.raw());
        }

        /// flock(2): `op` is LOCK.SH, LOCK.EX or LOCK.UN, with LOCK.NB.
        pub fn flock(self: Self, op: i32) sys.Result(void) {
            comptime need("flock", &.{ .file, .dir, .record });
            return sys.flock(self.raw(), op);
        }

        // ---- record ----

        /// linkat(AT_FDCWD, "/proc/self/fd/N", dir, name,
        /// AT_SYMLINK_FOLLOW) (flong-record.c:353-356): names the unnamed
        /// file without the capability AT_EMPTY_PATH needs, and refuses a
        /// name that exists (EEXIST), as O_EXCL would.
        pub fn linkInto(self: Self, dir: anytype, name: [*:0]const u8) sys.Result(void) {
            comptime need("linkInto", &.{.record});
            const p = selfPath(self);
            return sys.linkat(sys.AT.FDCWD, p.path(), dirRaw(dir), name, sys.AT.SYMLINK_FOLLOW);
        }

        // ---- dir: calls on paths relative to it ----

        pub fn mkdirat(self: Self, path: [*:0]const u8, mode: sys.mode_t) sys.Result(void) {
            comptime need("mkdirat", &.{ .dir, .path, .tree, .cgroup });
            return sys.mkdirat(self.raw(), path, mode);
        }

        /// unlinkat(2); `flags` is 0 or AT.REMOVEDIR.
        pub fn unlinkat(self: Self, path: [*:0]const u8, flags: u32) sys.Result(void) {
            comptime need("unlinkat", &.{ .dir, .path, .cgroup });
            return sys.unlinkat(self.raw(), path, flags);
        }

        /// renameat(2) from `old` here to `new` in `to`, a directory handle
        /// or `cwd`.
        pub fn renameat(self: Self, old: [*:0]const u8, to: anytype, new: [*:0]const u8) sys.Result(void) {
            comptime need("renameat", &.{.dir});
            return sys.renameat(self.raw(), old, dirRaw(to), new);
        }

        pub fn fstatat(self: Self, path: [*:0]const u8, flags: u32) sys.Result(sys.Stat) {
            comptime need("fstatat", &.{.dir});
            return sys.fstatat(self.raw(), path, flags);
        }

        /// getdents64(2): entries into `buf`, read with `Entries`.
        pub fn getdents64(self: Self, buf: []align(8) u8) sys.Result(usize) {
            comptime need("getdents64", &.{.dir});
            return sys.getdents64(self.raw(), buf);
        }

        /// fchownat(2) of `path` under it; "" with AT.EMPTY_PATH is the
        /// file itself (flong-mount.c:219, 336).
        pub fn fchownat(self: Self, path: [*:0]const u8, uid: u32, gid: u32, flags: u32) sys.Result(void) {
            comptime need("fchownat", &.{ .dir, .path, .tree });
            return sys.fchownat(self.raw(), path, uid, gid, flags);
        }

        // ---- path and tree: mounts ----

        /// The unique id of the mount the file is on (flong-mount.c:57-64).
        pub fn mountId(self: Self) sys.Result(u64) {
            comptime need("mountId", &.{ .path, .tree });
            return sys.mountId(self.raw());
        }

        /// mount_setattr(2) of the mount the file is on (AT_EMPTY_PATH),
        /// with AT_RECURSIVE when `recursive` (flong-mount.c:157, 395, 492).
        pub fn mountSetattr(self: Self, recursive: bool, attr: *const sys.MountAttr) sys.Result(void) {
            comptime need("mountSetattr", &.{ .path, .tree });
            const flags = sys.AT.EMPTY_PATH | (if (recursive) sys.AT_RECURSIVE else 0);
            return sys.mountSetattr(self.raw(), "", flags, attr);
        }

        /// move_mount(2) of this detached tree onto `to` (both
        /// MOVE_MOUNT_*_EMPTY_PATH, flong-mount.c:431, 448): nothing is
        /// resolved by name.
        pub fn moveTo(self: Self, to: Fd(.path)) sys.Result(void) {
            comptime need("moveTo", &.{.tree});
            return sys.moveMount(self.raw(), "", to.raw(), "", sys.MOVE_MOUNT_F_EMPTY_PATH | sys.MOVE_MOUNT_T_EMPTY_PATH);
        }

        // ---- fsctx: fsconfig ----

        /// FSCONFIG_SET_STRING key=value.
        pub fn setString(self: Self, key: [*:0]const u8, value: [*:0]const u8) sys.Result(void) {
            comptime need("setString", &.{.fsctx});
            return sys.fsconfig(self.raw(), sys.FSCONFIG.SET_STRING, key, value, 0);
        }

        /// FSCONFIG_SET_FLAG key.
        pub fn setFlag(self: Self, key: [*:0]const u8) sys.Result(void) {
            comptime need("setFlag", &.{.fsctx});
            return sys.fsconfig(self.raw(), sys.FSCONFIG.SET_FLAG, key, null, 0);
        }

        /// FSCONFIG_SET_FD key to `dir`'s descriptor: a directory only, as
        /// FSCONFIG_SET_FD's fget refuses an O_PATH one (flong-mount.c:221,
        /// 226-228). One of the ways a number leaves the table.
        pub fn setFd(self: Self, key: [*:0]const u8, dir: anytype) sys.Result(void) {
            comptime need("setFd", &.{.fsctx});
            const T = @TypeOf(dir);
            if (!@hasDecl(T, "kind") or T.kind != .dir)
                @compileError("FsCtx.setFd of a " ++ (if (@hasDecl(T, "kind")) @tagName(T.kind) else @typeName(T)) ++ " descriptor: FSCONFIG_SET_FD takes a directory, never O_PATH");
            return sys.fsconfig(self.raw(), sys.FSCONFIG.SET_FD, key, null, dir.raw());
        }

        /// FSCONFIG_CMD_CREATE: the superblock.
        pub fn create(self: Self) sys.Result(void) {
            comptime need("create", &.{.fsctx});
            return sys.fsconfig(self.raw(), sys.FSCONFIG.CMD_CREATE, null, null, 0);
        }

        // ---- namespaces ----

        /// setns(2) into `ns`, which must be the namespace this descriptor
        /// names: entering a network namespace's descriptor as a mount
        /// namespace does not compile.
        pub fn setns(self: Self, comptime ns: Ns) sys.Result(void) {
            comptime need("setns", &.{ .userns, .mntns, .netns, .cgroupns });
            if (comptime ns.kind() != k)
                @compileError("setns(." ++ @tagName(ns) ++ ") of a " ++ @tagName(k) ++ " descriptor");
            return sys.setns(self.raw(), ns.flag());
        }

        // ---- pidfd ----

        /// waitid(P_PIDFD) with `flags` (WEXITED, WNOWAIT, WNOHANG), EINTR
        /// retried.
        pub fn waitid(self: Self, flags: u32) sys.Result(sys.ChildInfo) {
            comptime need("waitid", &.{.pidfd});
            return sys.waitidPidfd(self.raw(), flags);
        }

        pub fn sendSignal(self: Self, sig: i32) sys.Result(void) {
            comptime need("sendSignal", &.{.pidfd});
            return sys.pidfdSendSignal(self.raw(), sig);
        }

        // ---- inotify ----

        /// inotify_add_watch(2) of `path` (a selfPath, flong-record.c:770-771).
        pub fn addWatch(self: Self, path: [*:0]const u8, mask: u32) sys.Result(i32) {
            comptime need("addWatch", &.{.inotify});
            return sys.inotifyAddWatch(self.raw(), path, mask);
        }

        /// One read of events into `buf`, read with `InotifyEvents`.
        pub fn readEvents(self: Self, buf: []align(@alignOf(InotifyEvent)) u8) sys.Result(usize) {
            comptime need("readEvents", &.{.inotify});
            return sys.read(self.raw(), buf);
        }

        // ---- signalfd ----

        /// One read of a queued signal: 128 bytes, or EAGAIN when none is
        /// (the descriptor is non-blocking, flong-util.c:258-269).
        pub fn readSiginfo(self: Self, si: *sys.SignalfdSiginfo) sys.Result(usize) {
            comptime need("readSiginfo", &.{.signalfd});
            return sys.read(self.raw(), std.mem.asBytes(si));
        }

        // ---- the terminal ----

        /// unlockpt(3), TIOCSPTLCK (flong-tty.c:177).
        pub fn unlock(self: Self) sys.Result(void) {
            comptime need("unlock", &.{.pty_master});
            return sys.unlockpt(self.raw());
        }

        /// TIOCGPTN: the N of the slave's /dev/pts/N (flong-tty.c:178).
        pub fn ptyNumber(self: Self) sys.Result(u32) {
            comptime need("ptyNumber", &.{.pty_master});
            return sys.ptyNumber(self.raw());
        }

        /// TIOCSWINSZ: the pty's window size (flong-tty.c:192, 281).
        pub fn setWinsize(self: Self, ws: *const sys.Winsize) sys.Result(void) {
            comptime need("setWinsize", &.{ .pty_master, .pty_slave });
            return sys.setWinsize(self.raw(), ws);
        }

        /// tcsetattr(3) of the payload's terminal (flong-tty.c:188).
        pub fn tcsetattr(self: Self, when: sys.Tcsa, t: *const sys.Termios) sys.Result(void) {
            comptime need("tcsetattr", &.{.pty_slave});
            return sys.tcsetattr(self.raw(), when, t);
        }
    };
}

/// The working directory, where a directory handle is taken: `cwd` is
/// AT_FDCWD.
pub const Cwd = struct {
    pub const kind: Kind = .dir;

    fn raw(_: Cwd) sys.fd_t {
        return sys.AT.FDCWD;
    }
};
pub const cwd: Cwd = .{};

/// The number of `at`, a directory handle (owned or held), `cwd`, or an
/// O_PATH handle, a detached tree or a cgroup, which name a directory as
/// well (flong-mount.c:283-284, 384; flong-cgroup.c:352, 466, 497).
fn dirRaw(at: anytype) sys.fd_t {
    const T = @TypeOf(at);
    if (!@hasDecl(T, "kind") or (T.kind != .dir and T.kind != .path and T.kind != .tree and T.kind != .cgroup))
        @compileError("a directory handle or fd.cwd, not " ++ @typeName(T));
    return at.raw();
}

// ---- minting ----

/// openat(2) of a file under `at` (a directory handle or `cwd`), with
/// O_CLOEXEC added to `flags`.
pub fn openFile(at: anytype, path: [*:0]const u8, flags: sys.O, mode: sys.mode_t) Error!sys.Result(File) {
    var f = flags;
    f.CLOEXEC = true;
    return adopted(.file, sys.openat(dirRaw(at), path, f, mode));
}

/// A directory under `at`, `O_RDONLY|O_DIRECTORY|O_CLOEXEC`.
pub fn openDir(at: anytype, path: [*:0]const u8) Error!sys.Result(Dir) {
    return adopted(.dir, sys.openat(dirRaw(at), path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0));
}

/// A directory under `at` that is not a symlink,
/// `O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`: the state directory and
/// sessions/ (flong-record.c:61, 74), and a cgroup to list
/// (flong-cgroup.c:546).
pub fn openDirNoFollow(at: anytype, path: [*:0]const u8) Error!sys.Result(Dir) {
    return adopted(.dir, sys.openat(dirRaw(at), path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0));
}

/// A cgroup directory (flong-cgroup.c:119-126): `path` absolute under
/// `cwd`, or one component under a cgroup already open, with
/// O_PATH|O_DIRECTORY|O_NOFOLLOW, so a symlink as the last component is
/// refused. The only kind fork and Spawn create a child in.
pub fn openCgroup(at: anytype, path: [*:0]const u8) Error!sys.Result(Fd(.cgroup)) {
    const T = @TypeOf(at);
    if (T != Cwd and (!@hasDecl(T, "kind") or T.kind != .cgroup))
        @compileError("a cgroup is opened under fd.cwd or a cgroup, not " ++ @typeName(T));
    return adopted(.cgroup, sys.openat(at.raw(), path, .{ .PATH = true, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0));
}

/// A pipe, both ends O_CLOEXEC.
pub const Pipe = struct { r: Fd(.pipe_r), w: Fd(.pipe_w) };

pub fn pipe() Error!sys.Result(Pipe) {
    var p: [2]sys.fd_t = undefined;
    switch (sys.pipe2(&p)) {
        .err => |e| return .{ .err = e },
        .ok => {},
    }
    const r = adopt(.pipe_r, p[0]) catch |err| {
        sys.close(p[1]);
        return err;
    };
    const w = adopt(.pipe_w, p[1]) catch |err| {
        r.close();
        return err;
    };
    return .{ .ok = .{ .r = r, .w = w } };
}

/// pidfd_open(2) of `pid` (flong-util.c:326-334): ESRCH, the process gone,
/// is an answer in `.err`, as every other errno.
pub fn pidfdOpen(pid: sys.pid_t) Error!sys.Result(Fd(.pidfd)) {
    return adopted(.pidfd, sys.pidfdOpen(pid));
}

/// inotify_init1(IN_CLOEXEC) (flong-record.c:765).
pub fn inotifyInit() Error!sys.Result(Fd(.inotify)) {
    return adopted(.inotify, sys.inotifyInit1(sys.IN.CLOEXEC));
}

/// signalfd4(-1, mask, SFD_CLOEXEC|SFD_NONBLOCK) (flong-launch.c:881):
/// sig.openSignalfd's, which keeps it in sig.fd.
pub fn openSignalfd(mask: u64) Error!sys.Result(Fd(.signalfd)) {
    return adopted(.signalfd, sys.signalfd(mask, sys.SFD_CLOEXEC | sys.SFD_NONBLOCK));
}

/// An unnamed file in the directory `dir` (flong-record.c:343):
/// openat(dir, ".", O_TMPFILE|O_RDWR|O_CLOEXEC, 0600), sys.O_TMPFILE being
/// the kernel's __O_TMPFILE|O_DIRECTORY. Nobody else can see it until it
/// is linked.
pub fn openRecord(dir: anytype) Error!sys.Result(Fd(.record)) {
    var f = sys.O_TMPFILE;
    f.ACCMODE = .RDWR;
    f.CLOEXEC = true;
    return adopted(.record, sys.openat(dirRaw(dir), ".", f, 0o600));
}

/// /proc/<pid>/ns/user, O_RDONLY|O_CLOEXEC (flong-ns.c:141-150): the user
/// namespace a child of the caller's is in. The child is unreaped while
/// this opens, so `pid` names no other process.
pub fn openUserns(pid: sys.pid_t) Error!sys.Result(Fd(.userns)) {
    var buf: [32]u8 = undefined;
    // "/proc/" and an i32 and "/ns/user" are at most 25 bytes.
    const path = std.fmt.bufPrintZ(&buf, "/proc/{d}/ns/user", .{pid}) catch unreachable; // proven: 25 < 32
    return adopted(.userns, sys.openat(sys.AT.FDCWD, path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0));
}

/// memfd_create(name, MFD_CLOEXEC) (flong-launch.c:616): a file with
/// nothing on disk, as pasta's pid file is.
pub fn memfd(name: [*:0]const u8) Error!sys.Result(File) {
    return adopted(.file, sys.memfdCreate(name, sys.MFD_CLOEXEC));
}

/// A descriptor the caller handed over at number `n`, once the spec has
/// checked it is open (flong-spec.c:656-667; ZIG.md, "The descriptor
/// layer"): Spawn.keepInherited passes it on, and `close` closes it.
pub fn adoptInherited(n: sys.fd_t) Error!Fd(.inherited) {
    return adopt(.inherited, n);
}

/// openat(2) with O_PATH under `at`, O_CLOEXEC added: `flags` may add
/// O_DIRECTORY and O_NOFOLLOW (flong-mount.c:599).
pub fn openPath(at: anytype, path: [*:0]const u8, flags: sys.O) Error!sys.Result(Fd(.path)) {
    var f = flags;
    f.PATH = true;
    f.CLOEXEC = true;
    return adopted(.path, sys.openat(dirRaw(at), path, f, 0));
}

/// One component of a walk (flong-mount.c:29, 49-53, 318-335): openat2 of
/// `name` under `at` with O_PATH, O_DIRECTORY when `directory`, and
/// RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_BENEATH, so a symlink,
/// the last component's included, is ELOOP and nothing leaves `at`. The
/// only RESOLVE_BENEATH caller.
pub fn walkOpen(at: Fd(.path), name: [*:0]const u8, directory: bool) Error!sys.Result(Fd(.path)) {
    const flags: sys.O = .{ .PATH = true, .DIRECTORY = directory, .CLOEXEC = true };
    const how: sys.OpenHow = .{
        .flags = @as(u32, @bitCast(flags)),
        .mode = 0,
        .resolve = sys.RESOLVE.NO_SYMLINKS | sys.RESOLVE.NO_MAGICLINKS | sys.RESOLVE.BENEATH,
    };
    return adopted(.path, sys.openat2(at.raw(), name, &how));
}

/// The flags an exact or following source open takes for kind `k`: O_PATH
/// for a bind (flong-mount.c:145), O_RDONLY|O_DIRECTORY for an overlay's
/// lower (:221).
fn sourceFlags(comptime k: Kind) sys.O {
    return switch (k) {
        .path => .{ .PATH = true, .CLOEXEC = true },
        .dir => .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true },
        else => @compileError("a mount source is opened as a path or a dir, not a " ++ @tagName(k)),
    };
}

/// An exact source (flong-mount.c:120): openat2 from AT_FDCWD with
/// RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS, so a symlink anywhere on it
/// is ELOOP. `k` is .path or .dir.
pub fn openExact(comptime k: Kind, path: [*:0]const u8) Error!sys.Result(Fd(k)) {
    const how: sys.OpenHow = .{
        .flags = @as(u32, @bitCast(sourceFlags(k))),
        .mode = 0,
        .resolve = sys.RESOLVE.NO_SYMLINKS | sys.RESOLVE.NO_MAGICLINKS,
    };
    return adopted(k, sys.openat2(sys.AT.FDCWD, path, &how));
}

/// Any other source (flong-mount.c:121): open(2), following symlinks as
/// its author intended. `k` is .path or .dir.
pub fn openFollowing(comptime k: Kind, path: [*:0]const u8) Error!sys.Result(Fd(k)) {
    return adopted(k, sys.openat(sys.AT.FDCWD, path, sourceFlags(k), 0));
}

/// open_tree(2) of `path` under `at` (a path or a tree), with
/// OPEN_TREE_CLOEXEC added: `flags` holds OPEN_TREE_CLONE, AT_EMPTY_PATH,
/// AT_RECURSIVE (flong-mount.c:148, 392).
pub fn openTree(at: anytype, path: [*:0]const u8, flags: u32) Error!sys.Result(Fd(.tree)) {
    const T = @TypeOf(at);
    if (!@hasDecl(T, "kind") or (T.kind != .path and T.kind != .tree))
        @compileError("open_tree under a path or a tree, not " ++ @typeName(T));
    return adopted(.tree, sys.openTree(at.raw(), path, flags | sys.OPEN_TREE_CLOEXEC));
}

/// fsopen(2) of the filesystem type `name`, FSOPEN_CLOEXEC.
pub fn fsopen(name: [*:0]const u8) Error!sys.Result(Fd(.fsctx)) {
    return adopted(.fsctx, sys.fsopen(name, sys.FSOPEN_CLOEXEC));
}

/// fsmount(2) of a created context, FSMOUNT_CLOEXEC, with the mount
/// attributes `attrs`: a detached tree.
pub fn fsmount(ctx: Fd(.fsctx), attrs: u32) Error!sys.Result(Fd(.tree)) {
    return adopted(.tree, sys.fsmount(ctx.raw(), sys.FSMOUNT_CLOEXEC, attrs));
}

/// The pidfd's process's namespace of kind `k`, through the pidfd
/// ioctls (flong-mount.c:546-551): only the caller may ask, and the
/// process is never looked up by number.
pub fn openNs(pidfd: Fd(.pidfd), comptime k: Kind) Error!sys.Result(Fd(k)) {
    const request = switch (k) {
        .mntns => sys.PIDFD_GET_MNT_NAMESPACE,
        .netns => sys.PIDFD_GET_NET_NAMESPACE,
        .cgroupns => sys.PIDFD_GET_CGROUP_NAMESPACE,
        else => @compileError("no pidfd ioctl answers a " ++ @tagName(k)),
    };
    return adopted(k, sys.ioctlFd(pidfd.raw(), request, 0));
}

/// posix_openpt(O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK), glibc's open of
/// /dev/ptmx (flong-tty.c:174): a new pty's master.
pub fn openPtmx() Error!sys.Result(Fd(.pty_master)) {
    return adopted(.pty_master, sys.openat(sys.AT.FDCWD, "/dev/ptmx", .{ .ACCMODE = .RDWR, .NOCTTY = true, .CLOEXEC = true, .NONBLOCK = true }, 0));
}

/// The pty's slave by its path, O_RDWR|O_NOCTTY|O_CLOEXEC
/// (flong-tty.c:182).
pub fn openSlave(path: [*:0]const u8) Error!sys.Result(Fd(.pty_slave)) {
    return adopted(.pty_slave, sys.openat(sys.AT.FDCWD, path, .{ .ACCMODE = .RDWR, .NOCTTY = true, .CLOEXEC = true }, 0));
}

/// The caller's terminal opened again through /proc/self/fd/1,
/// O_WRONLY|O_NOCTTY|O_NONBLOCK|O_CLOEXEC (flong-tty.c:196-203): a new
/// open file description, non-blocking without changing fd 1's. A terminal
/// the caller may not open (after su) refuses it (quirk 42).
pub fn reopenOut() Error!sys.Result(Fd(.tty_out)) {
    return adopted(.tty_out, sys.openat(sys.AT.FDCWD, "/proc/self/fd/1", .{ .ACCMODE = .WRONLY, .NOCTTY = true, .NONBLOCK = true, .CLOEXEC = true }, 0));
}

/// A descriptor a C caller opened and handed over, as kind `k`: the
/// mount-helper shim's (src/hybrid/mount_c.zig) U1, ready read end and
/// leader's pidfd (ZIG.md, "The mount-helper shim"). The lint allows it
/// there alone. It is not checked: the C knows what it passed.
pub fn adoptForeign(comptime k: Kind, raw: sys.fd_t) Error!Fd(k) {
    return adopt(k, raw);
}

// ---- fork and spawn: the pidfd's slot, and the child's descriptors ----

/// A slot held for the pidfd clone3 is about to make, so a full table is
/// found before the child exists, never after (quirk 26: the spike leaked
/// the child when its pidfd could not be adopted, fd.zig:280, 326). The
/// child drops it with every other slot it does not keep (`retainOnly`,
/// or its exec).
pub const Reservation = struct {
    slot: u16,

    /// The parent's pidfd, in the reserved slot.
    pub fn fill(self: Reservation, comptime k: Kind, raw: sys.fd_t) Fd(k) {
        const s = &slots[self.slot];
        std.debug.assert(s.raw == reserved);
        s.raw = raw;
        s.kind = k;
        return .{ .slot = self.slot, .gen = s.gen };
    }

    /// clone3 failed: the slot is free again.
    pub fn cancel(self: Reservation) void {
        const s = &slots[self.slot];
        std.debug.assert(s.raw == reserved);
        release(s);
    }
};

pub fn reserve() Error!Reservation {
    for (&slots, 0..) |*s, i| {
        if (s.raw == free) {
            s.raw = reserved;
            return .{ .slot = @intCast(i) };
        }
    }
    return error.TableFull;
}

/// Where retainOnly's close_range failed: its first descriptor, as
/// fl_close_from says it ("close_range %d", flong-util.c:160), and the
/// errno.
pub const CloseRangeFailure = struct { low: u32, err: sys.E };

/// For a fork child (flong-util.c:154-165, 467-482): closes every
/// descriptor from 3 up that `keep` does not hold, in the kernel and in the
/// table. Every other handle, in any variable, is stale from here on: the
/// parent's signalfd among them unless kept, so a wait in the child polls
/// nothing that may be reused (flong-util.c:476-479). A reserved slot goes
/// too. One close_range per gap between kept numbers, the last up to ~0U,
/// in the C's order (next_kept, not a sort). Allocates nothing. A stale
/// keep handle panics.
pub fn retainOnly(keep: []const AnyFd) ?CloseRangeFailure {
    var kept: [capacity]sys.fd_t = undefined;
    const n = @min(keep.len, capacity);
    for (keep[0..n], 0..) |h, i| kept[i] = h.raw();
    for (&slots, 0..) |*s, i| {
        if (s.raw == free) continue;
        const wanted = for (keep) |h| {
            if (h.slot == i) break true;
        } else false;
        if (!wanted) release(s);
    }
    return closeGaps(kept[0..n]);
}

/// closeUntracked (flong-launch.c:907-925): closes every descriptor from 3
/// up that the table does not hold. Every handle stays live: the table is
/// what is kept. For the launcher's prologue, whose table at that step is
/// the C's keep list exactly (the keep-fds, adopted; the signalfd; the
/// state and sessions directories; the cache): what the wrapper left open
/// and bwrap-args do not name goes. A reserved slot is not live and holds
/// no number. Allocates nothing.
pub fn closeUntracked() ?CloseRangeFailure {
    var kept: [capacity]sys.fd_t = undefined;
    var n: usize = 0;
    for (slots) |s| {
        if (s.raw < 0) continue;
        kept[n] = s.raw;
        n += 1;
    }
    return closeGaps(kept[0..n]);
}

/// fl_close_from(3, kept) (flong-util.c:154-165): one close_range per gap
/// between kept numbers, the last up to ~0U, in the C's order (next_kept,
/// not a sort).
fn closeGaps(kept: []const sys.fd_t) ?CloseRangeFailure {
    var low: u32 = 3;
    while (true) {
        const next = nextKept(low, kept);
        const last: u32 = if (next) |k| k -% 1 else std.math.maxInt(u32);
        if (next == null or next.? != low) {
            switch (sys.closeRange(low, last, 0)) {
                .ok => {},
                .err => |e| return .{ .low = low, .err = e },
            }
        }
        low = (next orelse return null) + 1;
    }
}

/// next_kept (flong-util.c:143-152): the smallest number in `kept` that is
/// at least `low`, or null.
fn nextKept(low: u32, kept: []const sys.fd_t) ?u32 {
    var best: ?u32 = null;
    for (kept) |k| {
        if (k < 0) continue;
        const u: u32 = @intCast(k);
        if (u >= low and (best == null or u < best.?)) best = u;
    }
    return best;
}

// ---- stdio ----

/// Descriptors 0-2, which are not in the table: read and write only, never
/// closed, never made non-blocking (ZIG.md, "The descriptor layer").
pub const Stdio = enum(u2) {
    in = 0,
    out = 1,
    err = 2,

    fn raw(self: Stdio) sys.fd_t {
        return @intFromEnum(self);
    }

    pub fn read(self: Stdio, buf: []u8) sys.Result(usize) {
        return sys.read(self.raw(), buf);
    }

    pub fn write(self: Stdio, bytes: []const u8) sys.Result(usize) {
        return sys.write(self.raw(), bytes);
    }

    /// Writes all of `bytes`, going on after a short write.
    pub fn writeAll(self: Stdio, bytes: []const u8) sys.Result(void) {
        return writeAllTo(self.raw(), bytes);
    }

    // ---- the caller's terminal (flong-tty.c) ----

    pub fn isatty(self: Stdio) bool {
        return sys.isatty(self.raw());
    }

    pub fn tcgetattr(self: Stdio) sys.Result(sys.Termios) {
        return sys.tcgetattr(self.raw());
    }

    pub fn tcsetattr(self: Stdio, when: sys.Tcsa, t: *const sys.Termios) sys.Result(void) {
        return sys.tcsetattr(self.raw(), when, t);
    }

    pub fn getWinsize(self: Stdio) sys.Result(sys.Winsize) {
        return sys.getWinsize(self.raw());
    }

    pub fn tcgetpgrp(self: Stdio) sys.Result(sys.pid_t) {
        return sys.tcgetpgrp(self.raw());
    }

    pub fn tcsetpgrp(self: Stdio, pgrp: sys.pid_t) sys.Result(void) {
        return sys.tcsetpgrp(self.raw(), pgrp);
    }
};

/// A pollfd for `h`, a handle of any kind, Stdio, or an optional of
/// either, null being an entry poll skips (fd -1): for a poll over several
/// descriptors outside the syscall layer, the relay's (flong-tty.c:393-405).
/// The number goes into the kernel's array and nowhere else.
pub fn pollEntry(h: anytype, events: i16) sys.pollfd {
    if (@typeInfo(@TypeOf(h)) == .optional) {
        return if (h) |x| pollEntry(x, events) else .{ .fd = -1, .events = events, .revents = 0 };
    }
    return .{ .fd = h.raw(), .events = events, .revents = 0 };
}

fn writeAllTo(raw: sys.fd_t, bytes: []const u8) sys.Result(void) {
    var rest = bytes;
    while (rest.len > 0) {
        switch (sys.write(raw, rest)) {
            .ok => |n| {
                // A write of 0 to a regular file or pipe does not happen
                // with bytes left, but it would loop forever.
                if (n == 0) return .{ .err = .IO };
                rest = rest[n..];
            },
            .err => |e| return .{ .err = e },
        }
    }
    return .{ .ok = {} };
}

/// Reads `h` (a file or Stdio.in) to its end, into memory from `gpa`.
pub fn readAll(h: anytype, gpa: std.mem.Allocator) error{OutOfMemory}!sys.Result([]u8) {
    var buf: std.ArrayList(u8) = .empty;
    while (true) {
        try buf.ensureUnusedCapacity(gpa, 4096);
        switch (h.read(buf.unusedCapacitySlice())) {
            .ok => |n| {
                if (n == 0) return .{ .ok = try buf.toOwnedSlice(gpa) };
                buf.items.len += n;
            },
            .err => |e| {
                buf.deinit(gpa);
                return .{ .err = e };
            },
        }
    }
}

// ---- paths ----

/// "/proc/self/fd/N", the way a descriptor is named to a call that takes a
/// path (ZIG.md, "Lint and analysis": one of the ways a number leaves the
/// table).
pub const SelfPath = struct {
    buf: [32]u8 = undefined,
    len: usize = 0,

    pub fn path(self: *const SelfPath) [:0]const u8 {
        return self.buf[0..self.len :0];
    }
};

pub fn selfPath(h: anytype) SelfPath {
    var p: SelfPath = .{};
    // "/proc/self/fd/" and an i32 are at most 25 bytes.
    const text = std.fmt.bufPrintZ(&p.buf, "/proc/self/fd/{d}", .{h.raw()}) catch unreachable; // proven: 25 < 32
    p.len = text.len;
    return p;
}

/// "/proc/<pid>/fd/N": descriptor `h` of this process, named to another
/// process by this one's pid, `pid` (sys.getpid()), where /proc/self would
/// name the reader's own: the postStart hook's $userns and $netns, and
/// pasta's --userns and --pid (flong-launch.c:590-591, 622-624; ZIG.md,
/// "The descriptor layer"). One of the ways a number leaves the table.
pub const PidPath = struct {
    buf: [40]u8 = undefined,
    len: usize = 0,

    pub fn path(self: *const PidPath) [:0]const u8 {
        return self.buf[0..self.len :0];
    }
};

pub fn pidPath(pid: sys.pid_t, h: anytype) PidPath {
    var p: PidPath = .{};
    // "/proc/", "/fd/" and two i32s are at most 32 bytes.
    const text = std.fmt.bufPrintZ(&p.buf, "/proc/{d}/fd/{d}", .{ pid, h.raw() }) catch unreachable; // proven: 32 < 40
    p.len = text.len;
    return p;
}

// ---- directory entries ----

/// The entries of one getdents64 buffer, each name, inode and type.
pub const Entries = struct {
    buf: []align(8) const u8,
    off: usize = 0,

    pub const Entry = struct { name: []const u8, ino: u64, type: u8 };

    /// d_type's value for a directory (DT_DIR, dirent.h).
    pub const dt_dir = 4;

    pub fn next(self: *Entries) ?Entry {
        if (self.off >= self.buf.len) return null;
        const at = self.buf[self.off..];
        const ino = std.mem.readInt(u64, at[0..8], .little);
        const reclen = std.mem.readInt(u16, at[16..18], .little);
        const name_at = @offsetOf(sys.Dirent64, "name");
        const name = std.mem.sliceTo(at[name_at..reclen], 0);
        self.off += reclen;
        return .{ .name = name, .ino = ino, .type = at[18] };
    }
};

// ---- inotify events ----

/// struct inotify_event's fixed part (linux/inotify.h): 16 bytes, then
/// `len` bytes of NUL-padded name.
pub const InotifyEvent = extern struct {
    wd: i32,
    mask: u32,
    cookie: u32,
    len: u32,
};

comptime {
    std.debug.assert(@sizeOf(InotifyEvent) == 16);
}

/// The events of one inotify read (flong-record.c:800-821), each mask and
/// name (up to its first NUL; empty when `len` is 0). The kernel writes
/// whole events, but this reads any bytes without a panic: a fixed part
/// or a name that would run past the end ends the iteration.
pub const InotifyEvents = struct {
    buf: []const u8,
    off: usize = 0,

    pub const Event = struct { mask: u32, name: []const u8 };

    pub fn next(self: *InotifyEvents) ?Event {
        const rest = self.buf[self.off..];
        if (rest.len < @sizeOf(InotifyEvent)) return null;
        const mask = std.mem.readInt(u32, rest[4..8], builtin_endian);
        const len = std.mem.readInt(u32, rest[12..16], builtin_endian);
        if (len > rest.len - @sizeOf(InotifyEvent)) return null;
        const name = std.mem.sliceTo(rest[@sizeOf(InotifyEvent)..][0..len], 0);
        self.off += @sizeOf(InotifyEvent) + len;
        return .{ .mask = mask, .name = name };
    }
};

const builtin_endian = @import("builtin").cpu.arch.endian();

// ---- for tests ----

/// The number of live handles; a reserved slot is not one.
pub fn liveCount() usize {
    var n: usize = 0;
    for (slots) |s| n += @intFromBool(s.raw >= 0);
    return n;
}

/// The descriptor numbers of every live handle, for tests that compare the
/// table with /proc/self/fd.
pub fn snapshot(buf: *[capacity]sys.fd_t) []sys.fd_t {
    var n: usize = 0;
    for (slots) |s| {
        if (s.raw < 0) continue;
        buf[n] = s.raw;
        n += 1;
    }
    return buf[0..n];
}

// ---- tests ----

const testing = std.testing;

// Any file every Linux has, the Nix build sandbox included, which has no
// /etc/hostname (ZIG.md, "Measured": P1).
const test_file = "/etc/passwd";

fn Opened(comptime T: type) type {
    return @FieldType(@typeInfo(T).error_union.payload, "ok");
}

/// An open's handle, or the test's failure.
fn ok(r: anytype) !Opened(@TypeOf(r)) {
    return switch (try r) {
        .ok => |v| v,
        .err => error.TestUnexpectedResult,
    };
}

test "a closed handle is stale in every copy, even after its number and slot are reused" {
    const start = liveCount();
    const f = try ok(openFile(cwd, test_file, .{}, 0));
    const Holder = struct { h: File };
    const copy = Holder{ .h = f };
    const number = f.raw();
    f.close();
    try testing.expect(!copy.h.isLive());
    try testing.expect(!f.any().isLive());

    const g = try ok(openFile(cwd, test_file, .{}, 0));
    defer g.close();
    // The kernel handed out the same number and the table the same slot:
    // with a bare int, `copy` would now name g's file.
    try testing.expectEqual(number, g.raw());
    try testing.expectEqual(f.slot, g.slot);
    try testing.expect(f.gen != g.gen);
    try testing.expect(!copy.h.isLive());
    try testing.expect(g.isLive());
    try testing.expectEqual(start + 1, liveCount());
}

test "a file reads, writes, preads, pwrites, fstats and locks" {
    var dir_buf: [64]u8 = undefined;
    const dir_name = try std.fmt.bufPrintZ(&dir_buf, "fd-test-{d}", .{std.os.linux.getpid()});
    const tmp = switch (sys.mkdirat(sys.AT.FDCWD, dir_name, 0o700)) {
        .ok => try ok(openDir(cwd, dir_name)),
        .err => return error.TestUnexpectedResult, // the test's working directory is its own
    };
    defer {
        _ = sys.unlinkat(sys.AT.FDCWD, dir_name, sys.AT.REMOVEDIR);
    }
    defer tmp.close();

    const f = try ok(openFile(tmp, "f", .{ .ACCMODE = .RDWR, .CREAT = true, .EXCL = true }, 0o600));
    defer {
        _ = tmp.unlinkat("f", 0);
    }
    defer f.close();
    try testing.expectEqual(sys.Result(void){ .ok = {} }, f.writeAll("hello"));
    try testing.expectEqual(sys.Result(usize){ .ok = 5 }, f.pwrite("HELLO", 5));
    var b: [16]u8 = undefined;
    try testing.expectEqual(sys.Result(usize){ .ok = 10 }, f.pread(&b, 0));
    try testing.expectEqualStrings("helloHELLO", b[0..10]);
    const st = f.fstat();
    try testing.expect(st == .ok);
    try testing.expectEqual(@as(u32, 0o100600), st.ok.mode & 0o177777);
    try testing.expectEqual(sys.Result(void){ .ok = {} }, f.flock(sys.LOCK.EX | sys.LOCK.NB));

    // O_CLOEXEC is added to every open.
    const flags = std.os.linux.fcntl(f.raw(), std.os.linux.F.GETFD, 0);
    try testing.expect(flags & std.os.linux.FD_CLOEXEC != 0);

    // A second open of the file, as the table sees it and the kernel does.
    const again = try ok(openFile(tmp, "f", .{}, 0));
    defer again.close();
    try testing.expect(again.slot != f.slot);
    try testing.expectEqual(sys.Result(usize){ .ok = 10 }, again.read(&b));
}

test "a directory makes, renames, stats, lists and unlinks under itself" {
    var dir_buf: [64]u8 = undefined;
    const dir_name = try std.fmt.bufPrintZ(&dir_buf, "fd-test-dir-{d}", .{std.os.linux.getpid()});
    const d = switch (sys.mkdirat(sys.AT.FDCWD, dir_name, 0o700)) {
        .ok => try ok(openDir(cwd, dir_name)),
        .err => return error.TestUnexpectedResult,
    };
    defer {
        _ = sys.unlinkat(sys.AT.FDCWD, dir_name, sys.AT.REMOVEDIR);
    }
    defer d.close();

    try testing.expectEqual(sys.Result(void){ .ok = {} }, d.mkdirat("sub", 0o700));
    try testing.expectEqual(sys.Result(void){ .err = .EXIST }, d.mkdirat("sub", 0o700));
    try testing.expectEqual(sys.Result(void){ .ok = {} }, d.renameat("sub", d, "moved"));
    try testing.expect(d.fstatat("sub", 0) == .err);
    const st = d.fstatat("moved", sys.AT.SYMLINK_NOFOLLOW);
    try testing.expect(st == .ok and sys.S.ISDIR(st.ok.mode));

    // A directory under a directory handle.
    const sub = try ok(openDir(d, "moved"));
    try testing.expect(sub.fstat() == .ok);
    sub.close();

    var buf: [1024]u8 align(8) = undefined;
    var names: usize = 0;
    var seen = false;
    while (true) {
        const n = switch (d.getdents64(&buf)) {
            .ok => |n| n,
            .err => return error.TestUnexpectedResult,
        };
        if (n == 0) break;
        var it: Entries = .{ .buf = buf[0..n] };
        while (it.next()) |e| {
            names += 1;
            if (std.mem.eql(u8, e.name, "moved")) {
                seen = true;
                try testing.expect(e.ino != 0);
            }
        }
    }
    try testing.expect(seen);
    try testing.expectEqual(@as(usize, 3), names); // ., .., moved
    try testing.expectEqual(sys.Result(void){ .ok = {} }, d.unlinkat("moved", sys.AT.REMOVEDIR));
    try testing.expectEqual(sys.Result(void){ .ok = {} }, d.flock(sys.LOCK.SH));
}

test "an open that fails leaves the table as it was" {
    const start = liveCount();
    try testing.expectEqual(sys.E.NOENT, (try openFile(cwd, "/nonexistent/x", .{}, 0)).err);
    try testing.expectEqual(sys.E.NOTDIR, (try openDir(cwd, test_file)).err);
    try testing.expectEqual(start, liveCount());
}

test "a held handle is the same descriptor, and has no close" {
    const f = try ok(openFile(cwd, test_file, .{}, 0));
    const h = f.holdUntilExit();
    try testing.expectEqual(f.raw(), h.raw());
    try testing.expect(h.isLive());
    var b: [4]u8 = undefined;
    try testing.expect(h.read(&b) == .ok);
    // Tests only: the owned handle closes it, and the held copy is stale.
    f.close();
    try testing.expect(!h.isLive());
}

test "selfPath names the descriptor under /proc/self/fd" {
    const f = try ok(openFile(cwd, test_file, .{}, 0));
    defer f.close();
    const p = selfPath(f);
    var want: [32]u8 = undefined;
    try testing.expectEqualStrings(try std.fmt.bufPrint(&want, "/proc/self/fd/{d}", .{f.raw()}), p.path());
    // It names the same file.
    const again = try ok(openFile(cwd, p.path(), .{}, 0));
    defer again.close();
    try testing.expectEqual(f.fstat().ok.ino, again.fstat().ok.ino);
}

test "pidPath names the descriptor under /proc/<pid>/fd, the pid given" {
    const f = try ok(memfd("fd-test"));
    defer f.close();
    const me = sys.getpid();
    const p = pidPath(me, f);
    var want: [40]u8 = undefined;
    try testing.expectEqualStrings(try std.fmt.bufPrint(&want, "/proc/{d}/fd/{d}", .{ me, f.raw() }), p.path());
    // Through this process's pid it names the same file.
    const again = try ok(openFile(cwd, p.path(), .{}, 0));
    defer again.close();
    try testing.expectEqual(f.fstat().ok.ino, again.fstat().ok.ino);
    // The widest pid and number fit.
    const wide = pidPath(std.math.minInt(i32), f);
    try testing.expect(std.mem.startsWith(u8, wide.path(), "/proc/-2147483648/fd/"));
}

test "memfd is a close-on-exec file with nothing on disk" {
    const f = try ok(memfd("fd-test"));
    defer f.close();
    try testing.expectEqual(@as(usize, 3), f.write("abc").ok);
    var buf: [8]u8 = undefined;
    try testing.expectEqualStrings("abc", buf[0..f.pread(&buf, 0).ok]);
    // F_GETFD (1): FD_CLOEXEC set.
    try testing.expectEqual(@as(sys.fd_t, 1), sys.fcntl(f.raw(), 1, 0).ok & 1);
    const link = selfPath(f);
    var target: [64]u8 = undefined;
    const n = sys.readlinkat(sys.AT.FDCWD, link.path(), &target).ok;
    try testing.expectEqualStrings("/memfd:fd-test (deleted)", target[0..n]);
}

test "stdio writes and reads 0-2, outside the table" {
    try testing.expectEqual(sys.Result(void){ .ok = {} }, Stdio.err.writeAll(""));
    try testing.expectEqual(@as(sys.fd_t, 2), Stdio.err.raw());
}

test "readAll reads a file to its end" {
    const f = try ok(openFile(cwd, test_file, .{}, 0));
    defer f.close();
    const text = switch (try readAll(f, testing.allocator)) {
        .ok => |t| t,
        .err => return error.TestUnexpectedResult,
    };
    defer testing.allocator.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "root:") != null);
}
