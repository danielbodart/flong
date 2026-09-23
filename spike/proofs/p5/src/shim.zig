// P5's Zig half: what flong_mount_main will be (ZIG.md, "The mount-helper
// shim"), reduced to the things that could break in a C program's fork
// child. It runs with no Zig start code, on the C's stack, in memory the C
// owns; it takes the descriptors the C kept for it, reads, fstats, sorts,
// allocates with page_allocator, uses a 256 KiB frame, prints one line with
// one write and ends the process itself: exit_group(0), 1 after saying why,
// 125 on a panic.
const std = @import("std");
const linux = std.os.linux;

/// Mirrors struct p5_job in c/main.c. The first three stand for
/// struct fl_mount_job's u1, ready and leader_pidfd (flong-mount.h:67-81),
/// adopted as .userns, .pipe_r and .pidfd.
pub const Job = extern struct {
    userns: c_int,
    pipe_r: c_int,
    pidfd: c_int,
    /// A descriptor the parent had open and fl_fork's close_range closed in
    /// the child: it must be gone.
    closed: c_int,
    /// 0 runs; 1 plants a panic after adopting the descriptors.
    mode: c_int,
};

// Nothing of std.debug's default handler, which would walk DWARF and print
// a trace: one line on stderr in one write, then 125, the helpers' "said
// why" (flong-util.c:507-509).
pub const panic = std.debug.FullPanic(onPanic);

fn onPanic(msg: []const u8, _: ?usize) noreturn {
    @branchHint(.cold);
    const prefix = "p5: internal error: ";
    var buf: [256]u8 = undefined;
    const n = @min(msg.len, buf.len - prefix.len - 1);
    @memcpy(buf[0..prefix.len], prefix);
    @memcpy(buf[prefix.len..][0..n], msg[0..n]);
    buf[prefix.len + n] = '\n';
    _ = linux.write(2, &buf, prefix.len + n + 1);
    linux.exit_group(125);
}

fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    var buf: [256]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, "p5: " ++ fmt ++ "\n", args) catch "p5: failed\n";
    _ = linux.write(2, line.ptr, line.len);
    linux.exit_group(1);
}

fn check(rc: usize, what: []const u8) usize {
    const e = linux.E.init(rc);
    if (e != .SUCCESS) fail("{s}: {s}", .{ what, @tagName(e) });
    return rc;
}

/// A 256 KiB frame, touched from end to end. With stack_check off nothing
/// probes it page by page; the kernel grows the C's main stack under it.
noinline fn bigFrame(seed: u8) u64 {
    var big: [256 * 1024]u8 = undefined;
    @memset(&big, seed);
    std.mem.doNotOptimizeAway(&big);
    var sum: u64 = 0;
    var i: usize = 0;
    while (i < big.len) : (i += 4096) sum += big[i];
    return sum + big[big.len - 1];
}

export fn proof_main(job: *const Job, tracing: c_int) noreturn {
    // Adopt: the pipe's read end is read to EOF, which also shows the
    // child holds no copy of the write end.
    var msg_buf: [64]u8 = undefined;
    var len: usize = 0;
    while (true) {
        const n = check(linux.read(job.pipe_r, msg_buf[len..].ptr, msg_buf.len - len), "read pipe_r");
        if (n == 0) break;
        len += n;
        if (len == msg_buf.len) fail("pipe_r: message too long", .{});
    }
    var st: linux.Stat = undefined;
    _ = check(linux.fstat(job.userns, &st), "fstat userns");
    const userns_ino = st.ino;
    _ = check(linux.fstat(job.pidfd, &st), "fstat pidfd");
    const pidfd_ino = st.ino;
    const e = linux.E.init(linux.fcntl(job.closed, linux.F.GETFD, 0));
    if (e != .BADF) fail("descriptor {d} survived the fork's close_range: {s}", .{ job.closed, @tagName(e) });

    if (job.mode == 1) {
        // A runtime index past the end: ReleaseSafe's bounds check panics.
        const four = [4]u8{ 1, 2, 3, 4 };
        const i: usize = @as(usize, @intCast(job.mode)) + len;
        std.mem.doNotOptimizeAway(four[i]);
    }

    // Sort what the pipe carried.
    var sorted: [64]u8 = undefined;
    @memcpy(sorted[0..len], msg_buf[0..len]);
    std.mem.sort(u8, sorted[0..len], {}, std.sort.asc(u8));

    // 1 MiB from page_allocator (mmap), in the child's copy of memory.
    const words = std.heap.page_allocator.alloc(u64, 1 << 17) catch fail("page_allocator: out of memory", .{});
    for (words, 0..) |*w, i| w.* = i;
    var heap_sum: u64 = 0;
    for (words) |w| heap_sum +%= w;
    std.heap.page_allocator.free(words);

    const frame_sum = bigFrame(@truncate(len));

    var out: [256]u8 = undefined;
    const line = std.fmt.bufPrint(&out, "p5: child read '{s}', sorted '{s}', heap sum {d}, frame sum {d}, userns ino {d}, pidfd ino {d}, tracing {d}\n", .{
        msg_buf[0..len], sorted[0..len], heap_sum, frame_sum, userns_ino, pidfd_ino, tracing,
    }) catch fail("line too long", .{});
    const w = check(linux.write(1, line.ptr, line.len), "write");
    if (w != line.len) fail("short write", .{});
    linux.exit_group(0);
}
