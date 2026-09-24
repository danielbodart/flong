//! flong-fake-bwrap: bwrap's stand-in for tests/zig/bwrap_test.zig, which
//! spawns it through launch/bwrap.zig's spawn. It says what it was started
//! with on stdout, in one write, and exits 0:
//!
//!   arg WORD    each argv word after argv[0], one line each, in order
//!   fds N...    the descriptors it holds, from 0 up, its own listing's
//!               left out
//!
//! Static, no libc, as a flong program is. Exit 1 when it cannot list its
//! descriptors or its output does not fit.

const std = @import("std");
const linux = std.os.linux;

pub const std_options: std.Options = .{ .enable_segfault_handler = false, .keep_sigpipe = true };

var out: [1 << 16]u8 = undefined;

pub fn main() u8 {
    var n: usize = 0;
    for (std.os.argv[1..]) |w| {
        n += (std.fmt.bufPrint(out[n..], "arg {s}\n", .{std.mem.span(w)}) catch return 1).len;
    }

    const rc = linux.open("/proc/self/fd", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    if (linux.E.init(rc) != .SUCCESS) return 1;
    const dir: i32 = @intCast(rc);
    var fds: [1024]i32 = undefined;
    var nfds: usize = 0;
    var buf: [4096]u8 align(8) = undefined;
    while (true) {
        const got = linux.getdents64(dir, &buf, buf.len);
        if (linux.E.init(got) != .SUCCESS) return 1;
        if (got == 0) break;
        var off: usize = 0;
        while (off < got) {
            const d: *align(1) const linux.dirent64 = @ptrCast(&buf[off]);
            const name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(&buf[off + @offsetOf(linux.dirent64, "name")])), 0);
            off += d.reclen;
            const v = std.fmt.parseInt(i32, name, 10) catch continue;
            if (v == dir) continue;
            if (nfds == fds.len) return 1;
            fds[nfds] = v;
            nfds += 1;
        }
    }
    _ = linux.close(dir);
    std.mem.sort(i32, fds[0..nfds], {}, std.sort.asc(i32));
    n += (std.fmt.bufPrint(out[n..], "fds", .{}) catch return 1).len;
    for (fds[0..nfds]) |v| n += (std.fmt.bufPrint(out[n..], " {d}", .{v}) catch return 1).len;
    n += (std.fmt.bufPrint(out[n..], "\n", .{}) catch return 1).len;

    var done: usize = 0;
    while (done < n) {
        const w = linux.write(1, out[done..n].ptr, n - done);
        if (linux.E.init(w) != .SUCCESS) return 1;
        done += w;
    }
    return 0;
}
