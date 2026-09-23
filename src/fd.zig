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
//! functions and zwanzig's open model for each (.zwanzig.json).
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

pub const Kind = enum(u8) { file, dir };

/// Slots in the table: 1024, the default soft RLIMIT_NOFILE, where the C
/// would get EMFILE (quirk 41). The spike had 64 (fd.zig:22).
pub const capacity = 1024;

pub const Error = error{TableFull};

const Slot = struct {
    raw: sys.fd_t = -1,
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
    s.raw = -1;
    s.gen +%= 1;
}

/// Takes ownership of `raw`. On TableFull `raw` is closed, so no caller
/// holds a descriptor the table does not know.
fn adopt(comptime k: Kind, raw: sys.fd_t) Error!Fd(k) {
    for (&slots, 0..) |*s, i| {
        if (s.raw < 0) {
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
            comptime need("read", &.{.file});
            return sys.read(self.raw(), buf);
        }

        pub fn write(self: Self, bytes: []const u8) sys.Result(usize) {
            comptime need("write", &.{.file});
            return sys.write(self.raw(), bytes);
        }

        /// Writes all of `bytes`, going on after a short write.
        pub fn writeAll(self: Self, bytes: []const u8) sys.Result(void) {
            comptime need("write", &.{.file});
            return writeAllTo(self.raw(), bytes);
        }

        pub fn pread(self: Self, buf: []u8, offset: u64) sys.Result(usize) {
            comptime need("pread", &.{.file});
            return sys.pread(self.raw(), buf, offset);
        }

        pub fn pwrite(self: Self, bytes: []const u8, offset: u64) sys.Result(usize) {
            comptime need("pwrite", &.{.file});
            return sys.pwrite(self.raw(), bytes, offset);
        }

        pub fn fstat(self: Self) sys.Result(sys.Stat) {
            comptime need("fstat", &.{ .file, .dir });
            return sys.fstat(self.raw());
        }

        /// flock(2): `op` is LOCK.SH, LOCK.EX or LOCK.UN, with LOCK.NB.
        pub fn flock(self: Self, op: i32) sys.Result(void) {
            comptime need("flock", &.{ .file, .dir });
            return sys.flock(self.raw(), op);
        }

        // ---- dir: calls on paths relative to it ----

        pub fn mkdirat(self: Self, path: [*:0]const u8, mode: sys.mode_t) sys.Result(void) {
            comptime need("mkdirat", &.{.dir});
            return sys.mkdirat(self.raw(), path, mode);
        }

        /// unlinkat(2); `flags` is 0 or AT.REMOVEDIR.
        pub fn unlinkat(self: Self, path: [*:0]const u8, flags: u32) sys.Result(void) {
            comptime need("unlinkat", &.{.dir});
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

/// The number of `at`, a directory handle (owned or held) or `cwd`.
fn dirRaw(at: anytype) sys.fd_t {
    const T = @TypeOf(at);
    if (!@hasDecl(T, "kind") or T.kind != .dir)
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
};

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

// ---- directory entries ----

/// The entries of one getdents64 buffer, each name and inode.
pub const Entries = struct {
    buf: []align(8) const u8,
    off: usize = 0,

    pub const Entry = struct { name: []const u8, ino: u64 };

    pub fn next(self: *Entries) ?Entry {
        if (self.off >= self.buf.len) return null;
        const at = self.buf[self.off..];
        const ino = std.mem.readInt(u64, at[0..8], .little);
        const reclen = std.mem.readInt(u16, at[16..18], .little);
        const name_at = @offsetOf(sys.Dirent64, "name");
        const name = std.mem.sliceTo(at[name_at..reclen], 0);
        self.off += reclen;
        return .{ .name = name, .ino = ino };
    }
};

// ---- for tests ----

/// The number of live handles.
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
