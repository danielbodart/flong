//! The descriptors the kernel says this process holds, from /proc/self/fd,
//! without the one used to read it. Raw syscalls only, so it runs anywhere,
//! including a forked child and the probe.

const std = @import("std");
const linux = std.os.linux;

pub const Set = struct {
    fds: [256]i32 = undefined,
    n: usize = 0,

    pub fn slice(self: *const Set) []const i32 {
        return self.fds[0..self.n];
    }

    pub fn contains(self: *const Set, fd: i32) bool {
        return std.mem.indexOfScalar(i32, self.slice(), fd) != null;
    }
};

pub fn read() !Set {
    const dir_rc = linux.open("/proc/self/fd", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    if (linux.E.init(dir_rc) != .SUCCESS) return error.ProcFd;
    const dir: i32 = @intCast(dir_rc);
    defer _ = linux.close(dir);

    var set: Set = .{};
    var buf: [4096]u8 align(8) = undefined;
    while (true) {
        const rc = linux.getdents64(dir, &buf, buf.len);
        if (linux.E.init(rc) != .SUCCESS) return error.ProcFd;
        if (rc == 0) break;
        var off: usize = 0;
        while (off < rc) {
            const ent: *align(1) linux.dirent64 = @ptrCast(&buf[off]);
            const name = std.mem.sliceTo(@as([*:0]u8, @ptrCast(&buf[off + @offsetOf(linux.dirent64, "name")])), 0);
            off += ent.reclen;
            const fd = std.fmt.parseInt(i32, name, 10) catch continue;
            if (fd == dir) continue;
            if (set.n == set.fds.len) return error.TooMany;
            set.fds[set.n] = fd;
            set.n += 1;
        }
    }
    std.mem.sort(i32, set.fds[0..set.n], {}, std.sort.asc(i32));
    return set;
}
