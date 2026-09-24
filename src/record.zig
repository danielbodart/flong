//! record.zig: the state directory, records, liveness, the sweep and
//! postStop (flong-record.h). Phase 5 ports the sweep's half of
//! launcher/flong-record.c: state_open (:41-89), reading and parsing a
//! record (:169-308), postStop (:425-484), the sweep (:486-734) and the
//! sweeper's watch (:736-825). Phase 7's L2 ports the launch's half: the
//! cache lock (:91-149) and the launcher's own record (:151-167, 310-423),
//! whose bytes tests/golden/records/ pins, the C launcher's before L4, so
//! a sweeper reads a record whichever launcher wrote it (DESIGN.md,
//! "Tests": the record contract).
//!
//! A record's lock is the launcher's life, and a record is only ever seen
//! locked: it is made unnamed with O_TMPFILE, locked and filled, and only
//! then linked into sessions/. The sweep releases a record once it holds
//! the lock itself, the name still names the inode it locked, and the
//! session's pid 1 has exited. Every wait is on an event: a held flock
//! (proc.lockWait, a pidfd), a pidfd, a cgroup's cgroup.events, an inotify
//! descriptor (:4-10).
//!
//! The sweep opens records read-only. inotify reports IN_CLOSE_WRITE only
//! for a descriptor that was open for writing, so the sweeper wakes when a
//! launcher's record is closed, and its own looks at live records do not
//! wake it again. A launcher's close is reported under the O_TMPFILE name
//! "#<inode>", and only that close makes the sweep wait for a lock. A
//! sweep's one writable open, to drop poststop= from a dead session's
//! record, is reported by the record's name; it wakes the sweeper once
//! more, to a sweep that tries every lock with LOCK_NB and finds nothing to
//! do (:12-19).
//!
//! Records are the caller's files, so anything running as the caller can
//! write one: the parser takes any bytes without a panic, and the sweep
//! checks what a record names before it acts on it (flong-record.h:10-14).
//! No allocator: fixed buffers, REC_MAX and 256 waits (DESIGN.md,
//! "Conventions").

const std = @import("std");
const sys = @import("sys");
const fdt = @import("fd");
const msg = @import("msg");
const sig = @import("sig");
const num = @import("num");
const proc = @import("proc");
const names = @import("names");
const cgroup = @import("cgroup");

const Error = msg.Error;
const path_max = sys.path_max;

/// REC_MAX (flong-record.c:38-39): a record holds two paths and a pid;
/// anything longer is not one of ours.
pub const rec_max = 2 * path_max + 64;

// ---- poststop='s list ----
//
// poststop= holds postStop's commands, in order: the commands separated by
// 0x1E (ASCII's record separator), each command's words by 0x1F (its unit
// separator). A record is lines of text with no escaping: a value is its
// bytes up to the newline, and holds neither a newline nor a NUL. The two
// separators are bytes no store path, and no word the module writes, holds,
// so the list needs no escaping either: `create` refuses a word holding a
// newline or either separator, and the value is then unambiguous. A value
// is at most PATH_MAX - 1 bytes, as every value in a record is.
//
// There is no compatibility layer: a record written before the list, one
// path and no separator, reads as a list of one command of one word, the
// same program run the same way, since that is how the format falls out.

/// Between two commands of poststop=.
pub const command_sep: u8 = 0x1e;
/// Between two words of one command of poststop=.
pub const word_sep: u8 = 0x1f;

// ---- the state directory (flong-record.c:41-89) ----

/// The state directory and its sessions/, kept until the process exits.
pub const State = struct {
    state: fdt.Held(.dir),
    sessions: fdt.Held(.dir),
};

/// check_private (flong-record.c:43-56): refuses a directory that is not
/// the caller's or not mode 0700. Anything running as another user that
/// could write here could make the sweep run its choice of program as the
/// caller.
fn checkPrivate(d: fdt.Dir, path: []const u8, sub: []const u8) Error!void {
    const st = try msg.check(d.fstat(), "stat {s}{s}", .{ path, sub });
    const mode = st.mode & 0o7777;
    if (st.uid != sys.getuid() or mode != 0o700)
        return msg.refuse("{s}{s} must be a directory of the caller's with mode 0700 (it is uid {d}, mode {o:0>4})", .{ path, sub, st.uid, mode });
}

/// state_open (flong-record.c:58-89): the state directory (the caller's,
/// mode exactly 0700, a directory, not a symlink) and its sessions/ (made
/// 0700 when absent, checked the same). The umask may take bits away from
/// mkdir's mode but never adds any, so a sessions/ made here is at most
/// 0700; check_private catches one made narrower, or one already there and
/// wider.
pub fn stateOpen(state: [:0]const u8) Error!State {
    const sfd = try msg.check(fdt.openDirNoFollow(fdt.cwd, state), "state directory {s}", .{state});
    errdefer sfd.close();
    try checkPrivate(sfd, state, "");
    switch (sfd.mkdirat("sessions", 0o700)) {
        .ok => {},
        .err => |e| if (e != .EXIST) return msg.fail(e, "mkdir {s}/sessions", .{state}),
    }
    const dfd = try msg.check(fdt.openDirNoFollow(sfd, "sessions"), "open {s}/sessions", .{state});
    errdefer dfd.close();
    try checkPrivate(dfd, state, "/sessions");
    return .{ .state = sfd.holdUntilExit(), .sessions = dfd.holdUntilExit() };
}

// ---- the cache (flong-record.c:91-149) ----

/// cache_lock's answers but a failure (flong-record.h:31-42).
pub const Cache = union(enum) {
    /// the shared lock, held for the launcher's life
    locked: fdt.Held(.dir),
    /// the cache was swept: absent, renamed before the lock was granted, or
    /// made afresh in its place by a wrapper still preparing it; the launch
    /// starts over from the wrapper
    swept,
};

/// cache_lock (flong-record.c:91-149): a shared flock on the cache
/// directory, then the checks that the path still names the inode it
/// locked and that the inode holds the prepared root. Called before the
/// launcher closes inherited descriptors, so a cold wrapper's own shared
/// lock is never released before this one is held.
pub fn cacheLock(cache: [:0]const u8) sig.Error!Cache {
    const cfd = switch (fdt.openDir(fdt.cwd, cache) catch return msg.refuse("cache {s}: too many open descriptors", .{cache})) {
        .ok => |d| d,
        .err => |e| return if (e == .NOENT) .swept else msg.fail(e, "cache {s}", .{cache}),
    };
    const locked: sig.Error!bool = steps: {
        // The one exclusive holder is a sweep of a superseded cache, which
        // holds the lock while it renames the cache away and deletes it, as
        // long as that deletion takes. So the wait is proc.lockWait's,
        // which a terminating signal ends (:102-107).
        proc.lockWait(cfd, sys.LOCK.SH) catch |e| break :steps e;
        // The lock is on what was opened. If a sweep renamed the cache away
        // before the lock was granted, the path names another directory
        // now, or nothing, and this launch must start over from the
        // wrapper (:108-125).
        const held = msg.check(cfd.fstat(), "stat {s}", .{cache}) catch |e| break :steps e;
        const named = switch (sys.fstatat(sys.AT.FDCWD, cache, 0)) {
            .ok => |st| st,
            .err => |e| break :steps if (e == .NOENT) false else msg.fail(e, "stat {s}", .{cache}),
        };
        if (named.dev != held.dev or named.ino != held.ino) break :steps false;
        // The path naming what was locked is not enough. A sweep may have
        // taken the cache this launch was prepared against away and another
        // launch's wrapper made a cache of its own in its place: that one's
        // shared lock is granted beside this one, and its prepared/ appears
        // only once it has finished preparing. A cache without the root is
        // answered as a swept one is: the wrapper, run again, waits for the
        // preparer's lock and finds the root made. Once the root is seen
        // under this shared lock it stays, since a sweep must hold the lock
        // exclusively to take the cache away (:126-142).
        switch (cfd.fstatat("prepared", 0)) {
            .ok => {},
            .err => |e| break :steps if (e == .NOENT) false else msg.fail(e, "stat {s}/prepared", .{cache}),
        }
        break :steps true;
    };
    if (locked catch |e| {
        cfd.close();
        return e;
    }) return .{ .locked = cfd.holdUntilExit() };
    cfd.close();
    return .swept;
}

// ---- reading records ----

/// read_record (flong-record.c:169-191): a whole record into `buf`. EFBIG
/// when it is too long to be one; the read's errno otherwise. Prints
/// nothing: the caller says what the record was for. `f` is a record the
/// sweep opened (a file) or the launcher's own (a record).
pub fn readRecord(f: anytype, buf: *[rec_max + 1]u8) sys.Result(usize) {
    var len: usize = 0;
    while (true) {
        const n = switch (f.pread(buf[len..], len)) {
            .ok => |n| n,
            .err => |e| return .{ .err = e },
        };
        if (n == 0) return .{ .ok = len };
        len += n;
        if (len > rec_max) return .{ .err = .FBIG };
    }
}

/// What a record says, once it has been checked to be well formed
/// (struct rec_fields, flong-record.c:219-225): each value NUL-terminated
/// in a PATH_MAX buffer, as the C copies them.
pub const Fields = struct {
    poststop: [path_max]u8 = undefined,
    poststop_len: usize = 0,
    cgroup: [path_max]u8 = undefined,
    cgroup_len: usize = 0,
    /// 0 when absent
    leader: sys.pid_t = 0,
    starttime: u64 = 0,

    /// poststop='s list, or null when absent (or blanked).
    pub fn poststopList(self: *const Fields) ?[]const u8 {
        return if (self.poststop_len == 0) null else self.poststop[0..self.poststop_len];
    }

    pub fn cgroupPath(self: *const Fields) [:0]const u8 {
        return self.cgroup[0..self.cgroup_len :0];
    }
};

/// take_value (flong-record.c:227-235): a value of 1 to PATH_MAX - 1 bytes.
fn takeValue(out: *[path_max]u8, len: *usize, v: []const u8) bool {
    if (v.len == 0 or v.len >= path_max) return false;
    @memcpy(out[0..v.len], v);
    out[v.len] = 0;
    len.* = v.len;
    return true;
}

/// take_leader (flong-record.c:237-262): "<pid>:<starttime>", both
/// decimal. The C's checks leave strtol and strtoull no blank or sign to
/// take: the pid starts with 1-9 and is at most INT_MAX, then ':', then the
/// starttime starts with a digit and runs to the end, at most 2^64 - 1. A
/// starttime of 0 means bwrap's child was already gone when it was
/// recorded, which no live process can match.
fn takeLeader(f: *Fields, v: []const u8) bool {
    if (v.len == 0 or v.len >= 64) return false;
    if (v[0] < '1' or v[0] > '9') return false;
    const colon = std.mem.indexOfNone(u8, v, "0123456789") orelse return false;
    if (v[colon] != ':') return false;
    const pid = std.fmt.parseUnsigned(u64, v[0..colon], 10) catch return false;
    if (pid > std.math.maxInt(i32)) return false;
    const st = v[colon + 1 ..];
    if (st.len == 0 or !std.ascii.isDigit(st[0])) return false;
    const r = num.strtoull10(st);
    if (r.range or r.len != st.len) return false;
    f.leader = @intCast(pid);
    f.starttime = r.value;
    return true;
}

/// parse_record (flong-record.c:264-308): a record's form, "key=value"
/// lines, poststop= then cgroup= then leader=, each at most once, cgroup=
/// required, and nothing else but empty lines (a blanked poststop=). Null
/// with `f` filled, or why it is refused. What the values name is checked
/// by the sweep, poststop='s commands as `poststop` runs them. Any bytes
/// are read without a panic.
pub fn parse(buf: []const u8, f: *Fields) ?[]const u8 {
    const keys = [_][]const u8{ "poststop=", "cgroup=", "leader=" };
    f.* = .{};
    if (std.mem.indexOfScalar(u8, buf, 0) != null or (buf.len > 0 and buf[buf.len - 1] != '\n'))
        return "it is not lines of text";
    var next: usize = 0;
    var lines = std.mem.splitScalar(u8, buf, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var k = next;
        while (k < keys.len and !std.mem.startsWith(u8, line, keys[k])) k += 1;
        if (k == keys.len) return "it has an unknown, repeated or misplaced line";
        const v = line[keys[k].len..];
        const good = switch (k) {
            0 => takeValue(&f.poststop, &f.poststop_len, v),
            1 => takeValue(&f.cgroup, &f.cgroup_len, v),
            else => takeLeader(f, v),
        };
        if (!good) return if (k == 2) "its leader= is not <pid>:<starttime>" else "a path in it is empty or too long";
        next = k + 1;
    }
    if (f.cgroup_len == 0) return "it has no cgroup=";
    return null;
}

/// The length of blank_poststop's one write (flong-record.c:199-201): the
/// poststop= line and its newline, the line ending at a newline or at the
/// C string's end; 0 when the record does not start with poststop=.
pub fn poststopLineLen(rec: []const u8) usize {
    if (!std.mem.startsWith(u8, rec, "poststop=")) return 0;
    const c = rec[0 .. std.mem.indexOfScalar(u8, rec, 0) orelse rec.len];
    return (std.mem.indexOfScalar(u8, c, '\n') orelse c.len) + 1;
}

/// blank_poststop (flong-record.c:193-217): the poststop= line, always the
/// first, blanked with newlines in one write of at most a line, so the
/// record is then exactly what it was without the key, and a sweeper killed
/// at any moment leaves the old record or the new one, never half of each.
/// `w` is open for writing, a file or the launcher's record; `rec` is the
/// record as read.
fn blankPoststop(w: anytype, rec: []const u8, name: []const u8) Error!void {
    const len = poststopLineLen(rec);
    if (len == 0) return;
    var blank: [path_max + 16]u8 = undefined;
    if (len > blank.len) return msg.fail(.FBIG, "drop poststop= from the record of {s}", .{name});
    @memset(blank[0..len], '\n');
    const n = try msg.check(w.pwrite(blank[0..len], 0), "drop poststop= from the record of {s}", .{name});
    if (n != len) return msg.fail(.IO, "drop poststop= from the record of {s}", .{name});
}

// ---- the launcher's own record (flong-record.c:151-167, 310-423) ----

/// struct fl_record (flong-record.h:44-49): the launcher's record, locked
/// (LOCK_EX) for the launcher's life.
pub const Record = struct {
    /// sessions/, not the record's
    dir: fdt.Held(.dir),
    rec: fdt.Fd(.record),
    /// the machine's name
    name: [:0]const u8,
    /// once it is in the directory
    linked: bool,
    /// poststop='s list as written, for the teardown's `poststop`
    poststop: [path_max]u8 = undefined,
    poststop_len: usize = 0,

    /// The list the record was made with, or null when it has none.
    pub fn poststopList(self: *const Record) ?[]const u8 {
        return if (self.poststop_len == 0) null else self.poststop[0..self.poststop_len];
    }

    /// rec_set_leader (flong-record.c:391-398): appends
    /// leader=<pid>:<starttime>, once, at child-pid, at the descriptor's
    /// offset: one write, which a SIGKILL cannot split.
    pub fn setLeader(self: *const Record, leader: sys.pid_t) Error!void {
        var buf: [64]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, "leader={d}:{d}\n", .{ leader, proc.starttime(leader) }) catch unreachable; // proven: 7 + 11 + 1 + 20 + 1 < 64
        return writeRecord(self.rec, line, self.name);
    }

    /// rec_poststop_done (flong-record.c:400-406): rewrites the record
    /// without poststop=, once postStop has run, so a sweep of a record left
    /// behind does not run it again.
    pub fn poststopDone(self: *const Record) Error!void {
        var buf: [rec_max + 1]u8 = undefined;
        const len = try msg.check(readRecord(self.rec, &buf), "read the record of {s}", .{self.name});
        return blankPoststop(self.rec, buf[0..len], self.name);
    }

    /// rec_remove (flong-record.c:408-417): unlinked first, then closed,
    /// which unlocks it: a sweep that opened the record before the unlink
    /// and is granted the lock after the close finds it has no links and
    /// leaves it (ordering checkpoint 10). A failed unlink is said, and the
    /// record closed all the same. The last step of a teardown whose
    /// cgroup is gone.
    pub fn remove(self: *Record) void {
        if (self.linked) switch (self.dir.unlinkat(self.name, 0)) {
            .ok => {},
            .err => |e| msg.sayErrno(e, "remove the record of {s}", .{self.name}),
        };
        self.linked = false;
        self.rec.close();
    }

    /// rec_close (flong-record.c:419-423): closed without the unlink: its
    /// cgroup could not be removed yet (pasta still exiting), and the sweep
    /// finishes the job. What happens to a record, implicitly, when the
    /// launcher is killed.
    pub fn closeKeeping(self: *Record) void {
        self.linked = false;
        self.rec.close();
    }
};

/// write_record (flong-record.c:153-167): all of `bytes` at the record's
/// offset, in one write. A regular file takes a small write whole, so a
/// short write is an error (EIO), not something to go on from.
fn writeRecord(rec: fdt.Fd(.record), bytes: []const u8, name: []const u8) Error!void {
    const n = try msg.check(rec.write(bytes), "write the record of {s}", .{name});
    if (n != bytes.len) return msg.fail(.IO, "write the record of {s}", .{name});
}

/// poststop='s value for `commands` into `out`: the words joined by
/// word_sep, the commands by command_sep. What `create` refuses is said
/// there.
fn encode(commands: []const []const [:0]const u8, out: *[path_max]u8) union(enum) { ok: []const u8, newline, separator, too_long } {
    var n: usize = 0;
    for (commands, 0..) |cmd, i| {
        for (cmd, 0..) |w, j| {
            if (std.mem.indexOfScalar(u8, w, '\n') != null) return .newline;
            if (std.mem.indexOfAny(u8, w, &.{ command_sep, word_sep }) != null) return .separator;
            const sep: []const u8 = if (j > 0) &.{word_sep} else if (i > 0) &.{command_sep} else "";
            // Every value in a record is at most PATH_MAX - 1 bytes.
            if (sep.len + w.len >= out.len - n) return .too_long;
            @memcpy(out[n..][0..sep.len], sep);
            n += sep.len;
            @memcpy(out[n..][0..w.len], w);
            n += w.len;
        }
    }
    return .{ .ok = out[0..n] };
}

/// rec_create (flong-record.c:324-389; flong-record.h:51-63): the record,
/// already locked. Ordering checkpoint 10, in this one function: made
/// unnamed with O_TMPFILE in sessions/, locked, written (poststop= when
/// there is a postStop, and cgroup=) in one write, and only then linked as
/// <machine>, so a record is never seen unlocked or half-written. A name
/// already taken (EEXIST) is a refusal while that session runs: it has no
/// leader= yet, or its leader is alive. When its leader has exited, the
/// session is ending, and whoever holds its lock (its launcher's teardown,
/// or a sweep waiting for pasta) is releasing it: create waits for the
/// lock, releases the session itself if it is still there (with `h`, as
/// the sweep does), and links the name then. error.Aborted when a
/// terminating signal ended that wait.
/// `post_stop` is postStop's commands, in order (spec.Spec's), each at
/// least a word; none, no poststop=.
pub fn create(sessions: fdt.Held(.dir), h: *const cgroup.Holder, machine: [:0]const u8, post_stop: []const []const [:0]const u8, cgroup_path: []const u8) sig.Error!Record {
    // 1. The text. A newline in a value would be a line of its own
    // choosing (:333-341), and a separator in a word a command or a word of
    // its own.
    var list_buf: [path_max]u8 = undefined;
    const list: []const u8 = switch (encode(post_stop, &list_buf)) {
        .ok => |l| l,
        .newline => return msg.refuse("a newline is in the postStop path or the cgroup path of {s}", .{machine}),
        .separator => return msg.refuse("a 0x1E or 0x1F byte is in a postStop word of {s}", .{machine}),
        .too_long => return msg.refuse("the record of {s} is too long", .{machine}),
    };
    if (std.mem.indexOfScalar(u8, cgroup_path, '\n') != null)
        return msg.refuse("a newline is in the postStop path or the cgroup path of {s}", .{machine});
    var buf: [rec_max]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const fits = blk: {
        if (list.len > 0) w.print("poststop={s}\n", .{list}) catch break :blk false;
        w.print("cgroup={s}\n", .{cgroup_path}) catch break :blk false;
        // snprintf into REC_MAX: the text and its NUL must fit.
        break :blk w.end < buf.len;
    };
    if (!fits) return msg.refuse("the record of {s} is too long", .{machine});
    const text = buf[0..w.end];

    // 2. Unnamed, with O_TMPFILE (:343-345).
    const rec = try msg.check(fdt.openRecord(sessions), "make the record of {s}", .{machine});
    const linked: sig.Error!void = steps: {
        // 3. Locked: nobody else can see an unnamed file, so the lock is
        // granted at once (:346-350).
        _ = msg.check(rec.flock(sys.LOCK.EX | sys.LOCK.NB), "lock the record of {s}", .{machine}) catch |e| break :steps e;
        // 4. Written, in one write (:351-352).
        writeRecord(rec, text, machine) catch |e| break :steps e;
        // 5. Linked through /proc/self/fd/N, which names the unnamed file
        // without the capability AT_EMPTY_PATH needs, and refuses a name
        // that exists: the O_EXCL (:353-382).
        while (true) {
            switch (rec.linkInto(sessions, machine)) {
                .ok => break :steps,
                .err => |e| if (e != .EXIST) break :steps msg.fail(e, "record {s}", .{machine}),
            }
            // The name is taken. A session that has ended keeps it until it
            // is released: by its launcher's teardown, or by a sweep, which
            // holds the lock while it waits for pasta to go and runs
            // postStop, and which the inline sweep therefore took for a
            // live launcher. Running the same machine again right after it
            // exits waits for that release, on the lock, and takes the name
            // once it is free. There is no count: each turn follows the
            // release of the session that held the name, and a running one
            // refuses.
            switch (sweepOne(sessions, machine, h, .wait_ended) catch |e| break :steps e) {
                .released, .gone => continue,
                .running => break :steps msg.refuse("a session named {s} is already running", .{machine}),
                // A record the sweep left, a malformed one under the name
                // included (quirk 5, kept).
                .left => break :steps msg.refuse("a session named {s} has ended but cannot be released yet", .{machine}),
            }
        }
    };
    linked catch |e| {
        rec.close();
        return e;
    };
    var r: Record = .{ .dir = sessions, .rec = rec, .name = machine, .linked = true, .poststop_len = list.len };
    @memcpy(r.poststop[0..list.len], list);
    return r;
}

// ---- postStop (flong-record.c:425-484) ----

/// Whether `path` has a ".." component (flong-record.c:427-434).
fn hasDotdot(path: []const u8) bool {
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |c| {
        if (std.mem.eql(u8, c, "..")) return true;
    }
    return false;
}

/// realpath (flong-record.c:444), by quirk 21's mechanism: an O_PATH open,
/// following symlinks, and the kernel's name for it, the readlink of its
/// selfPath. Null when either fails or the name does not fit PATH_MAX with
/// its NUL: glibc's realpath takes a name of PATH_MAX - 1 bytes into its
/// PATH_MAX buffer, so a read that fills all PATH_MAX bytes is the one too
/// long (or cut).
fn realPath(path: [:0]const u8, buf: *[path_max]u8) ?[:0]const u8 {
    const r = fdt.openPath(fdt.cwd, path, .{}) catch return null;
    const h = switch (r) {
        .ok => |h| h,
        .err => return null,
    };
    defer h.close();
    const self_path = fdt.selfPath(h);
    const n = switch (sys.readlinkat(sys.AT.FDCWD, self_path.path(), buf[0..path_max])) {
        .ok => |n| n,
        .err => return null,
    };
    if (n >= path_max) return null;
    buf[n] = 0;
    return buf[0..n :0];
}

/// fl_poststop (flong-record.c:436-484), over a list: runs poststop='s
/// commands for `machine` in order, each waited for, and stops at the
/// first that fails. A command runs only when its program starts with
/// /nix/store/, holds no ".." component and is executable, its target
/// checked the same way (a symlink in the store may point anywhere); argv
/// {target, its other words..., machine}; environment exactly
/// {"machine=<machine>"}; stdin /dev/null, stdout and stderr inherited;
/// working directory /; in the caller's cgroup. A failure prints
/// "postStop failed for <machine>", and the list, as a whole, counts as
/// run; so does any reap error but an abort (quirk 6). error.Aborted when a
/// terminating signal ended a wait: that command is then killed and
/// reaped, the list has not finished, and the caller keeps poststop= so
/// the sweep runs the whole list again (postStop is idempotent). `list` is
/// at most PATH_MAX - 1 bytes (Fields', Record's); any bytes are run
/// without a panic.
pub fn poststop(list: []const u8, machine: []const u8) error{Aborted}!void {
    var it = std.mem.splitScalar(u8, list, command_sep);
    while (it.next()) |cmd| {
        if (!try poststopOne(cmd, machine)) return;
    }
}

/// One command of poststop='s list as its words, each NUL-terminated in
/// place of its word_sep, in a buffer of the caller's.
pub const Words = struct {
    /// the command's bytes, each word_sep a NUL, and a NUL after the last
    buf: [:0]const u8,
    /// how many words: one more than the separators, so never 0
    n: usize,
    /// where `next` reads from; past buf.len once every word is read
    at: usize = 0,

    /// The next word, the program first; null after the last.
    pub fn next(self: *Words) ?[:0]const u8 {
        if (self.at > self.buf.len) return null;
        const w = std.mem.sliceTo(self.buf[self.at..], 0);
        self.at += w.len + 1;
        return w;
    }
};

/// `cmd`'s words (Words) in `buf`, or null when it does not fit with its
/// NUL: a command of a record's value always does. Any bytes are taken
/// without a panic; a NUL in `cmd`, which no record holds, separates words
/// as word_sep does, so `n` is what `next` yields.
pub fn words(cmd: []const u8, buf: *[path_max]u8) ?Words {
    if (cmd.len >= buf.len) return null;
    @memcpy(buf[0..cmd.len], cmd);
    buf[cmd.len] = 0;
    var n: usize = 1;
    for (buf[0..cmd.len]) |*c| {
        if (c.* == word_sep or c.* == 0) {
            c.* = 0;
            n += 1;
        }
    }
    return .{ .buf = buf[0..cmd.len :0], .n = n };
}

/// One command of poststop's list, its words word_sep-separated: true when
/// it ran and exited 0, so the next may run.
fn poststopOne(cmd: []const u8, machine: []const u8) error{Aborted}!bool {
    var words_buf: [path_max]u8 = undefined;
    var ws = words(cmd, &words_buf) orelse {
        msg.say("postStop failed for {s}: a command is longer than PATH_MAX", .{machine});
        return false;
    };
    const nwords = ws.n;
    const path = ws.next().?; // proven: a command has at least one word

    var real_buf: [path_max]u8 = undefined;
    const checked: ?[:0]const u8 = blk: {
        if (!std.mem.startsWith(u8, path, "/nix/store/") or hasDotdot(path)) break :blk null;
        const r = realPath(path, &real_buf) orelse break :blk null;
        if (!std.mem.startsWith(u8, r, "/nix/store/") or sys.access(r, sys.X_OK) == .err) break :blk null;
        break :blk r;
    };
    const real = checked orelse {
        msg.say("postStop failed for {s}: {s} is not a program in /nix/store", .{ machine, path });
        return false;
    };
    // machine is a name (names.isName), so it fits.
    var env_buf: ["machine=".len + names.name_max + 1]u8 = undefined;
    const env = std.fmt.bufPrintZ(&env_buf, "machine={s}", .{machine}) catch unreachable; // proven: a name is at most name_max bytes
    var machine_buf: [names.name_max + 1]u8 = undefined;
    const machine_z = std.fmt.bufPrintZ(&machine_buf, "{s}", .{machine}) catch unreachable; // proven: as env

    const dev_null = msg.check(fdt.openFile(fdt.cwd, "/dev/null", .{}, 0), "postStop failed for {s}: open /dev/null", .{machine}) catch return false;
    const envp = [_:null]?[*:0]const u8{env.ptr};
    // Spawn's argv, in a buffer of its own: no allocator (DESIGN.md,
    // "Conventions"). A command of fewer than PATH_MAX bytes has at most
    // PATH_MAX words; with the machine and the null, init's two slots and
    // the one growth to all of them fit, whether or not the growth is in
    // place.
    var spawn_mem: [(path_max + 4) * 2 * @sizeOf(?[*:0]const u8)]u8 align(@alignOf(?[*:0]const u8)) = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&spawn_mem);
    const child = blk: {
        var s = proc.Spawn.init(fba.allocator(), real.ptr) catch unreachable; // proven: 2 slots fit spawn_mem
        s.argv.ensureTotalCapacityPrecise(fba.allocator(), nwords + 2) catch unreachable; // proven: path_max + 2 more slots fit spawn_mem
        while (ws.next()) |w| s.arg(w.ptr) catch unreachable; // proven: within the capacity reserved above
        s.arg(machine_z.ptr) catch unreachable; // proven: within the capacity reserved above
        s.envp = &envp;
        s.stdio[0] = dev_null.any();
        s.dir = "/";
        // fl_spawn has said why when it fails.
        break :blk s.start();
    };
    dev_null.close();
    const c = child catch return false;
    const rc = c.await() catch |err| {
        // An aborted postStop has not finished, so the caller must leave
        // the record able to run it again, and it is killed now, not left
        // behind to overlap that rerun (:471-478).
        c.reapNow(.kill);
        if (err == error.Aborted) return error.Aborted;
        return false;
    };
    if (rc != 0) {
        msg.say("postStop failed for {s} (status {d})", .{ machine, rc });
        return false;
    }
    return true;
}

// ---- the sweep (flong-record.c:486-734) ----

/// open_leader (flong-record.c:488-508): a pidfd for the session's
/// recorded pid 1 while it runs. The starttime is read after the pidfd is
/// open, so a pid reused since names another process and does not match,
/// and a match is the pidfd's own process. Null when the recorded process
/// is gone, or there is no leader= yet (the caller decides what that
/// means).
fn openLeader(f: *const Fields) Error!?fdt.Fd(.pidfd) {
    if (f.leader == 0) return null;
    const pidfd = (try proc.pidfdOpen(f.leader)) orelse return null;
    if (proc.starttime(f.leader) != f.starttime) {
        pidfd.close();
        return null;
    }
    return pidfd;
}

/// wait_leader (flong-record.c:510-520): waits for the session's recorded
/// pid 1 to exit.
fn waitLeader(f: *const Fields) sig.Error!void {
    const pidfd = (try openLeader(f)) orelse return;
    defer pidfd.close();
    try sig.awaitFd(pidfd, sys.POLL.IN);
}

/// leader_running (flong-record.c:606-619): whether a record's session is
/// still running, as far as its leader= says: one with no leader= yet is
/// starting, and one whose leader is the recorded process is running. An
/// error to ask counts as running, so the answer never ends a live session.
fn leaderRunning(f: *const Fields) bool {
    if (f.leader == 0) return true;
    const pidfd = (openLeader(f) catch return true) orelse return false;
    pidfd.close();
    return true;
}

/// release's answers but an abort (flong-record.c:522-526).
pub const Released = enum {
    /// the session is released and its record gone
    released,
    /// reported and left; another holder's, left for that holder's sweep;
    /// or not a launcher's record, and removed
    left,
};

/// What release does after its checks: drop the record (it was not a
/// launcher's), leave it, or it is released.
const Outcome = enum { drop, left, released };

/// release (flong-record.c:522-604): releases one dead session, whose
/// record's lock the sweep holds (`rec`, read-only). error.Aborted when a
/// terminating signal ended the sweep.
fn release(dfd: anytype, name: [:0]const u8, rec: fdt.File, h: *const cgroup.Holder) error{Aborted}!Released {
    var buf: [rec_max + 1]u8 = undefined;
    var f: Fields = .{};
    var session: ?cgroup.Session = null;
    const outcome = act(name, rec, h, &buf, &f, &session);
    defer if (session) |*s| s.closeAll();
    const rc: Released = switch (outcome) {
        .left => .left,
        .released, .drop => blk: {
            switch (dfd.unlinkat(name, 0)) {
                .ok => {},
                .err => |e| {
                    msg.sayErrno(e, "remove the record of {s}", .{name});
                    break :blk .left;
                },
            }
            break :blk if (outcome == .released) .released else .left;
        },
    };
    if (sig.abort_signal != 0) return error.Aborted;
    return rc;
}

/// release's steps up to the unlink, each failure said where it happens.
/// `session` is left open for release to close.
fn act(name: [:0]const u8, rec: fdt.File, h: *const cgroup.Holder, buf: *[rec_max + 1]u8, f: *Fields, session: *?cgroup.Session) Outcome {
    const len = switch (readRecord(rec, buf)) {
        .ok => |n| n,
        .err => |e| {
            msg.sayErrno(e, "read the record of {s}", .{name});
            return .left;
        },
    };
    // A record that is not well formed, or does not name a session's
    // cgroup, was not written by a launcher: nothing it says is acted on.
    if (parse(buf[0..len], f)) |why| {
        msg.say("the record of {s} is removed: {s}", .{ name, why });
        return .drop;
    }
    // A cgroup that could not be opened may be opened by the next sweep
    // (EMFILE, ENOMEM): the record is the only trace of what is left in
    // it, so it stays.
    const opened = cgroup.sessionOpen(h, f.cgroupPath(), name) catch return .left;
    switch (opened) {
        // A session under another holder (another unit's launch, or one
        // with and one without a user manager) is that holder's to
        // release: its cgroup is not ours to kill, and its postStop must
        // still run.
        .other_holder => return .left,
        .refused => {
            msg.say("the record of {s} is removed: its cgroup is refused", .{name});
            return .drop;
        },
        .absent => {},
        .session => |s| session.* = s,
    }

    if (session.*) |*s| {
        cgroup.kill(s) catch return .left;
        cgroup.waitEmpty(s.fd) catch return .left;
    }
    waitLeader(f) catch return .left;

    if (f.poststopList()) |ps| {
        // An aborted postStop keeps poststop=, for the next sweep.
        poststop(ps, name) catch return .left;
        // postStop runs once, even if the sweep dies before the unlink:
        // the record loses poststop= through a writable descriptor of its
        // own, which the sweep closes at once.
        const self_path = fdt.selfPath(rec);
        const w = msg.check(fdt.openFile(fdt.cwd, self_path.path(), .{ .ACCMODE = .WRONLY }, 0), "drop poststop= from the record of {s}", .{name}) catch return .left;
        const blanked = blankPoststop(w, buf[0..len], name);
        w.close();
        blanked catch return .left;
    }
    if (session.*) |*s| {
        const busy = cgroup.remove(s) catch return .left;
        if (busy == .busy) {
            msg.say("the cgroup of {s} is still busy; left for the next sweep", .{name});
            return .left;
        }
    }
    return .released;
}

/// record_ended (flong-record.c:621-631): whether the record behind `rec`
/// has ended: its lock is held, but its leader= says the session's pid 1
/// has exited, so the holder is a launcher in its teardown or a sweep
/// releasing it, and will let go.
fn recordEnded(rec: fdt.File) bool {
    var buf: [rec_max + 1]u8 = undefined;
    var f: Fields = .{};
    const len = switch (readRecord(rec, &buf)) {
        .ok => |n| n,
        .err => return false,
    };
    return parse(buf[0..len], &f) == null and !leaderRunning(&f);
}

/// How sweepOne takes a record's lock (flong-record.c:312-317).
pub const LockMode = enum {
    /// LOCK_NB: a held lock is a live launcher
    try_once,
    /// wait for it: its launcher is known to be gone
    wait,
    /// wait for it only when the recorded pid 1 has exited
    wait_ended,
};

/// sweepOne's answers but an abort (flong-record.c:319-320, 637-640).
pub const Swept = enum { released, left, gone, running };

/// sweep_one (flong-record.c:633-681): takes the lock of the record `name`
/// and releases its session when the name still names the inode it locked.
/// A lock granted is a dead launcher's only then: another sweeper may have
/// released the record, and a new session taken the name, between the open
/// and the lock. `.gone` when the name is gone or names another record
/// now; `.running` when the lock is held and `mode` does not wait for it. A
/// failure to open or lock is reported, and the record left. `dfd` is
/// sessions/, a directory handle of the sweep's own or the launcher's held
/// one (flong-record.c:369).
pub fn sweepOne(dfd: anytype, name: [:0]const u8, h: *const cgroup.Holder, mode: LockMode) error{Aborted}!Swept {
    // O_NONBLOCK: a FIFO planted here must not hang the open.
    const opened = fdt.openFile(dfd, name, .{ .NOFOLLOW = true, .NONBLOCK = true }, 0) catch {
        msg.say("open the record of {s}: too many open descriptors", .{name});
        return .left;
    };
    const rec = switch (opened) {
        .ok => |r| r,
        .err => |e| switch (e) {
            .NOENT => return .gone,
            // A symlink is not a record.
            .LOOP => return .left,
            else => {
                msg.sayErrno(e, "open the record of {s}", .{name});
                return .left;
            },
        },
    };
    defer rec.close();
    const a = switch (rec.fstat()) {
        .ok => |st| st,
        .err => return .left,
    };
    if (!sys.S.ISREG(a.mode)) return .left;
    switch (rec.flock(sys.LOCK.EX | sys.LOCK.NB)) {
        .ok => {},
        .err => |e| {
            if (e != .AGAIN) {
                msg.sayErrno(e, "lock the record of {s}", .{name});
                return .left;
            }
            if (mode == .try_once or (mode == .wait_ended and !recordEnded(rec))) return .running;
            proc.lockWait(rec, sys.LOCK.EX) catch {
                if (sig.abort_signal != 0) return error.Aborted;
                return .left;
            };
        },
    }
    const locked = switch (rec.fstat()) {
        .ok => |st| st,
        .err => return .gone,
    };
    if (locked.nlink == 0) return .gone;
    const named = switch (dfd.fstatat(name, sys.AT.SYMLINK_NOFOLLOW)) {
        .ok => |st| st,
        .err => return .gone,
    };
    if (locked.dev != named.dev or locked.ino != named.ino) return .gone;
    return switch (try release(dfd, name, rec, h)) {
        .released => .released,
        .left => .left,
    };
}

/// sweep_dir (flong-record.c:683-729): every record in sessions/, the
/// lock of each whose inode is in `waits` waited for (records a launcher
/// has just let go), every other tried with `rest`. Anything but a
/// machine's name is not one of ours and is left alone. The number
/// released.
pub fn sweepDir(sessions: anytype, h: *const cgroup.Holder, waits: []const u64, rest: LockMode) sig.Error!u32 {
    // A descriptor of its own, so each sweep reads from the start and the
    // caller's keeps no offset.
    const dfd = try msg.check(fdt.openDir(sessions, "."), "open sessions", .{});
    defer dfd.close();
    var released: u32 = 0;
    // glibc's readdir buffer, 32 KiB.
    var buf: [32768]u8 align(8) = undefined;
    while (true) {
        const n = try msg.check(dfd.getdents64(&buf), "read sessions", .{});
        if (n == 0) return released;
        var it: fdt.Entries = .{ .buf = buf[0..n] };
        while (it.next()) |e| {
            if (!names.isName(e.name)) continue;
            var mode = rest;
            for (waits) |w| {
                if (w == e.ino) mode = .wait;
            }
            var name_buf: [names.name_max + 1]u8 = undefined;
            @memcpy(name_buf[0..e.name.len], e.name);
            name_buf[e.name.len] = 0;
            if (try sweepOne(dfd, name_buf[0..e.name.len :0], h, mode) == .released) released += 1;
        }
    }
}

/// rec_sweep (flong-record.c:731-734): every record tried once.
pub fn sweep(sessions: anytype, h: *const cgroup.Holder) sig.Error!u32 {
    return sweepDir(sessions, h, &.{}, .try_once);
}

/// closed_inode (flong-record.c:736-753): the inode of the record whose
/// lock an IN_CLOSE_WRITE event says is being let go, or 0. A launcher's
/// record was made with O_TMPFILE, and its descriptor keeps the name the
/// kernel gave the unnamed file, "#<inode>", whatever name it was linked
/// under since: that is the name its final close reports. Any other name is
/// a sweep's writable open, closed after it blanked poststop=; it is not
/// resolved, but still wakes a sweep. Read as the C reads it, with
/// strtoull's blanks and sign, from a C string.
pub fn closedInode(name_in: []const u8) u64 {
    const name = name_in[0 .. std.mem.indexOfScalar(u8, name_in, 0) orelse name_in.len];
    if (name.len == 0 or name[0] != '#') return 0;
    const r = num.strtoull10(name[1..]);
    if (r.range or r.len == 0 or 1 + r.len != name.len) return 0;
    return r.value;
}

/// The inotify buffer (flong-record.c:758): 4096 bytes, aligned for the
/// events.
pub const events_len = 4096;

/// A batch of events names at most this many records: each takes more
/// than 16 bytes (flong-record.c:759-761; quirk 33).
pub const max_waits = events_len / @sizeOf(fdt.InotifyEvent);

/// What one batch of events asks of the next sweep (flong-record.c:
/// 789-821): the inodes whose locks to wait for, and how to take the rest.
pub const Batch = struct {
    waits: [max_waits]u64 = undefined,
    nwaits: usize = 0,
    rest: LockMode = .try_once,
    /// IN_IGNORED: sessions/ itself is gone
    ignored: bool = false,
};

/// The batch `events` asks for. The kernel queues IN_CLOSE_WRITE in
/// __fput before it drops the descriptor's flock, so a sweep that answers
/// the event can find the lock still held, and no later event would come
/// for that record. A close reported under "#<inode>" is a launcher's last
/// descriptor of its record, so that lock is being let go: the sweep waits
/// for it, an event with no timeout, instead of trying once. It waits only
/// for that inode, never for whatever the record's name names by then,
/// which may be a relaunch that is running. After IN_Q_OVERFLOW, when such
/// a close may have been dropped, the sweep waits for the lock of every
/// record whose pid 1 has exited; a record whose session runs is tried
/// once. Any bytes are read without a panic.
pub fn batch(events: []const u8) Batch {
    var b: Batch = .{};
    var it: fdt.InotifyEvents = .{ .buf = events };
    while (it.next()) |ev| {
        if (ev.mask & sys.IN.Q_OVERFLOW != 0) b.rest = .wait_ended;
        if (ev.mask & sys.IN.IGNORED != 0) {
            b.ignored = true;
            return b;
        }
        if (ev.mask & sys.IN.CLOSE_WRITE != 0) {
            const ino = closedInode(ev.name);
            if (ino != 0 and b.nwaits < max_waits) {
                b.waits[b.nwaits] = ino;
                b.nwaits += 1;
            }
        }
    }
    return b;
}

/// rec_watch (flong-record.c:755-825): the sweeper's loop, in the holder
/// unit's process: the inotify watch on sessions/ for IN_CLOSE_WRITE (a
/// launcher's last close of its record, on any exit, SIGKILL included),
/// then a sweep, and a sweep for each batch of events. The watch comes
/// before the first sweep, so a record closed between the two is not
/// missed (ordering checkpoint 11). Returns only on error, said.
pub fn watch(sessions: fdt.Held(.dir), h: *const cgroup.Holder) sig.Error!noreturn {
    const ifd = try msg.check(fdt.inotifyInit(), "inotify", .{});
    defer ifd.close();
    // 1. The watch.
    const self_path = fdt.selfPath(sessions);
    _ = try msg.check(ifd.addWatch(self_path.path(), sys.IN.CLOSE_WRITE | sys.IN.ONLYDIR), "watch sessions", .{});
    var buf: [events_len]u8 align(@alignOf(fdt.InotifyEvent)) = undefined;
    var b: Batch = .{};
    while (true) {
        // 2. The sweep, then 3. the events it answers next.
        const n = try sweepDir(sessions, h, b.waits[0..b.nwaits], b.rest);
        if (n > 0) msg.say("released {d} dead session{s}", .{ n, if (n == 1) "" else "s" });
        const got = try msg.check(ifd.readEvents(&buf), "read inotify", .{});
        // inotify never reads 0; the C says so with the errno it has.
        if (got == 0) return msg.fail(.SUCCESS, "read inotify", .{});
        b = batch(buf[0..got]);
        if (b.ignored) return msg.refuse("sessions/ was removed", .{});
    }
}

// ---- tests ----

const testing = std.testing;

fn parsed(text: []const u8) !Fields {
    var f: Fields = .{};
    try testing.expectEqual(@as(?[]const u8, null), parse(text, &f));
    return f;
}

test "parse: the writer's records, and a blanked poststop=" {
    var f = try parsed("poststop=/nix/store/x-stop\ncgroup=/sys/fs/cgroup/h/c/m\nleader=12:345\n");
    try testing.expectEqualStrings("/nix/store/x-stop", f.poststopList().?);
    try testing.expectEqualStrings("/sys/fs/cgroup/h/c/m", f.cgroupPath());
    try testing.expectEqual(@as(sys.pid_t, 12), f.leader);
    try testing.expectEqual(@as(u64, 345), f.starttime);
    f = try parsed("\n\n\ncgroup=/c\n");
    try testing.expectEqual(@as(?[]const u8, null), f.poststopList());
    try testing.expectEqual(@as(sys.pid_t, 0), f.leader);
    f = try parsed("cgroup=/c\nleader=2147483647:0\n");
    try testing.expectEqual(@as(sys.pid_t, std.math.maxInt(i32)), f.leader);
    f = try parsed("cgroup=/c\nleader=1:007\n");
    try testing.expectEqual(@as(u64, 7), f.starttime);
    f = try parsed("cgroup=/c\nleader=1:18446744073709551615\n");
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), f.starttime);
}

test "parse refuses what a launcher never writes" {
    const cases = [_]struct { []const u8, []const u8 }{
        .{ "", "it has no cgroup=" },
        .{ "\n", "it has no cgroup=" },
        .{ "cgroup=/c", "it is not lines of text" },
        .{ "cgroup=/c\x00\n", "it is not lines of text" },
        .{ "cgroup=/c\ncgroup=/d\n", "it has an unknown, repeated or misplaced line" },
        .{ "cgroup=/c\npoststop=/p\n", "it has an unknown, repeated or misplaced line" },
        .{ "leader=1:1\ncgroup=/c\n", "it has an unknown, repeated or misplaced line" },
        .{ "x=1\ncgroup=/c\n", "it has an unknown, repeated or misplaced line" },
        .{ "cgroup=\n", "a path in it is empty or too long" },
        .{ "poststop=\ncgroup=/c\n", "a path in it is empty or too long" },
        .{ "cgroup=/c\nleader=\n", "its leader= is not <pid>:<starttime>" },
        .{ "cgroup=/c\nleader=01:1\n", "its leader= is not <pid>:<starttime>" },
        .{ "cgroup=/c\nleader=+1:1\n", "its leader= is not <pid>:<starttime>" },
        .{ "cgroup=/c\nleader=-1:1\n", "its leader= is not <pid>:<starttime>" },
        .{ "cgroup=/c\nleader=1:+1\n", "its leader= is not <pid>:<starttime>" },
        .{ "cgroup=/c\nleader=1: 1\n", "its leader= is not <pid>:<starttime>" },
        .{ "cgroup=/c\nleader=1:\n", "its leader= is not <pid>:<starttime>" },
        .{ "cgroup=/c\nleader=1\n", "its leader= is not <pid>:<starttime>" },
        .{ "cgroup=/c\nleader=1:2x\n", "its leader= is not <pid>:<starttime>" },
        .{ "cgroup=/c\nleader=2147483648:1\n", "its leader= is not <pid>:<starttime>" },
        .{ "cgroup=/c\nleader=1:18446744073709551616\n", "its leader= is not <pid>:<starttime>" },
        .{ "cgroup=/c\nleader=99999999999999999999:1\n", "its leader= is not <pid>:<starttime>" },
    };
    for (cases) |c| {
        var f: Fields = .{};
        try testing.expectEqualStrings(c[1], parse(c[0], &f) orelse "accepted");
    }
    // Oversize values: PATH_MAX - 1 bytes is the most.
    var big: [path_max + 16]u8 = undefined;
    @memcpy(big[0..7], "cgroup=");
    @memset(big[7..][0 .. path_max - 1], 'a');
    big[7 + path_max - 1] = '\n';
    var f: Fields = .{};
    try testing.expectEqual(@as(?[]const u8, null), parse(big[0 .. 7 + path_max], &f));
    big[7 + path_max - 1] = 'a';
    big[7 + path_max] = '\n';
    try testing.expectEqualStrings("a path in it is empty or too long", parse(big[0 .. 8 + path_max], &f).?);
}

test "closedInode reads #<inode> as strtoull does" {
    try testing.expectEqual(@as(u64, 1234), closedInode("#1234"));
    try testing.expectEqual(@as(u64, 12), closedInode("# 12"));
    try testing.expectEqual(@as(u64, 3), closedInode("#+3"));
    try testing.expectEqual(@as(u64, std.math.maxInt(u64) - 4), closedInode("#-5"));
    try testing.expectEqual(@as(u64, 7), closedInode("#7\x00junk"));
    for ([_][]const u8{ "", "#", "demo", "#12x", "# ", "#18446744073709551616", "1234" }) |n|
        try testing.expectEqual(@as(u64, 0), closedInode(n));
}

test "batch: waits for #<inode> closes, and overflow and removal" {
    var buf: [256]u8 align(4) = @splat(0);
    var n: usize = 0;
    const put = struct {
        fn f(b: []u8, at: *usize, mask: u32, name: []const u8, len: u32) void {
            const ev: fdt.InotifyEvent = .{ .wd = 1, .mask = mask, .cookie = 0, .len = len };
            @memcpy(b[at.*..][0..16], std.mem.asBytes(&ev));
            @memcpy(b[at.* + 16 ..][0..name.len], name);
            at.* += 16 + len;
        }
    }.f;
    put(&buf, &n, sys.IN.CLOSE_WRITE, "#42", 16);
    put(&buf, &n, sys.IN.CLOSE_WRITE, "demo", 16);
    put(&buf, &n, sys.IN.CLOSE_NOWRITE, "#43", 16);
    var b = batch(buf[0..n]);
    try testing.expectEqual(@as(usize, 1), b.nwaits);
    try testing.expectEqual(@as(u64, 42), b.waits[0]);
    try testing.expectEqual(LockMode.try_once, b.rest);
    put(&buf, &n, sys.IN.Q_OVERFLOW, "", 0);
    b = batch(buf[0..n]);
    try testing.expectEqual(LockMode.wait_ended, b.rest);
    try testing.expect(!b.ignored);
    put(&buf, &n, sys.IN.IGNORED, "", 0);
    try testing.expect(batch(buf[0..n]).ignored);
    // A name that would run past the end ends the batch.
    try testing.expectEqual(@as(usize, 1), batch(buf[0 .. 16 + 15]).nwaits + 1);
}

test "poststopLineLen" {
    try testing.expectEqual(@as(usize, 14), poststopLineLen("poststop=/a/b\ncgroup=/c\n"));
    try testing.expectEqual(@as(usize, 0), poststopLineLen("cgroup=/c\n"));
    try testing.expectEqual(@as(usize, 12), poststopLineLen("poststop=/a"));
}

test "encode, then words: a list round-trips, command by command and word by word" {
    var out: [path_max]u8 = undefined;
    const list: []const []const [:0]const u8 = &.{ &.{ "/nix/store/a", "x y", "", "--" }, &.{"/nix/store/b"}, &.{ "/nix/store/c", "" } };
    const v = encode(list, &out).ok;
    try testing.expectEqualStrings("/nix/store/a\x1fx y\x1f\x1f--\x1e/nix/store/b\x1e/nix/store/c\x1f", v);
    var it = std.mem.splitScalar(u8, v, command_sep);
    var buf: [path_max]u8 = undefined;
    for (list) |cmd| {
        var ws = words(it.next().?, &buf).?;
        try testing.expectEqual(cmd.len, ws.n);
        for (cmd) |w| try testing.expectEqualStrings(w, ws.next().?);
        try testing.expectEqual(@as(?[:0]const u8, null), ws.next());
    }
    try testing.expectEqual(@as(?[]const u8, null), it.next());
    // None: no poststop=.
    try testing.expectEqualStrings("", encode(&.{}, &out).ok);
    try testing.expect(encode(&.{&.{"/a\nb"}}, &out) == .newline);
    try testing.expect(encode(&.{ &.{"/a"}, &.{ "/b", "\x1e" } }, &out) == .separator);
    try testing.expect(encode(&.{&.{ "/a", "x\x1fy" }}, &out) == .separator);
}

test "words: a record written before the list is one command of one word" {
    const f = try parsed("poststop=/nix/store/x-stop/bin/stop\ncgroup=/c\n");
    var it = std.mem.splitScalar(u8, f.poststopList().?, command_sep);
    var buf: [path_max]u8 = undefined;
    var ws = words(it.next().?, &buf).?;
    try testing.expectEqual(@as(usize, 1), ws.n);
    try testing.expectEqualStrings("/nix/store/x-stop/bin/stop", ws.next().?);
    try testing.expectEqual(@as(?[:0]const u8, null), ws.next());
    try testing.expectEqual(@as(?[]const u8, null), it.next());
}

test "words: an empty command is one empty word, a NUL a separator, and too long is null" {
    var buf: [path_max]u8 = undefined;
    var ws = words("", &buf).?;
    try testing.expectEqual(@as(usize, 1), ws.n);
    try testing.expectEqualStrings("", ws.next().?);
    try testing.expectEqual(@as(?[:0]const u8, null), ws.next());
    ws = words("a\x00b\x1f", &buf).?;
    try testing.expectEqual(@as(usize, 3), ws.n);
    for ([_][]const u8{ "a", "b", "" }) |w| try testing.expectEqualStrings(w, ws.next().?);
    try testing.expectEqual(@as(?[:0]const u8, null), ws.next());
    const long = [_]u8{'a'} ** path_max;
    try testing.expect(words(&long, &buf) == null);
    try testing.expect(words(long[1..], &buf) != null);
}
