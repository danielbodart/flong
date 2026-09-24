//! flong-fake-cmd: a declaration's command and the cache tool's stand-in
//! for tests/zig/wrapper_test.zig, which runs it through launch/cmd.zig
//! and launch/prepare.zig. What it does is its first argument's; every
//! argument after the ones a mode reads is the launcher's, appended by
//! cmd.zig, and ignored but by `show`.
//!
//!   print TEXT        writes TEXT, its escapes \n, \0 and \\ decoded, to
//!                     stdout; exit 0
//!   fail N            exit N
//!   show              "arg WORD" for each argument after `show`, then
//!                     "env ENTRY" for each environment entry, in order;
//!                     exit 0
//!   flood N           writes N bytes of 'x' to stdout; exit 0
//!   prepare MAP... -- CACHE CLOSURE USER
//!                     the cache tool's prepare: appends "prepare ARG..."
//!                     (everything after `prepare`) as one line to
//!                     $FLONG_FAKE_LOG; exits 1 when CLOSURE is "fail", else
//!                     makes CACHE/prepared with an etc/passwd naming USER
//!                     1000:100 and an etc/group naming USER in group 1
//!   gc MAP... -- OLD  the cache tool's gc: appends "gc ARG..." to
//!                     $FLONG_FAKE_LOG; exits 1 when OLD's name holds
//!                     "stuck", else removes the directory OLD (empty)
//!   relaunch N        with N above 0, prologue.relaunchSelf with this
//!                     argv, N one less; at 0, "argv0 A" and "exe E"
//!                     (readlink /proc/self/exe), exit 0
//!
//! Static, no libc, as a flong program is. Exit 2 on a usage error, 1 when
//! a call fails.

const std = @import("std");
const linux = std.os.linux;
const prologue = @import("prologue");

pub const std_options: std.Options = .{ .enable_segfault_handler = false, .keep_sigpipe = true };

fn write(fd: i32, bytes: []const u8) bool {
    var done: usize = 0;
    while (done < bytes.len) {
        const w = linux.write(fd, bytes[done..].ptr, bytes.len - done);
        if (linux.E.init(w) != .SUCCESS) return false;
        done += w;
    }
    return true;
}

fn arg(i: usize) ?[]const u8 {
    return if (i < std.os.argv.len) std.mem.span(std.os.argv[i]) else null;
}

var buf: [1 << 16]u8 = undefined;

pub fn main() u8 {
    const mode = arg(1) orelse return 2;
    if (std.mem.eql(u8, mode, "print")) {
        const text = arg(2) orelse return 2;
        var n: usize = 0;
        var i: usize = 0;
        while (i < text.len) : (i += 1) {
            if (text[i] == '\\' and i + 1 < text.len) {
                i += 1;
                buf[n] = switch (text[i]) {
                    'n' => '\n',
                    '0' => 0,
                    else => text[i],
                };
            } else buf[n] = text[i];
            n += 1;
        }
        return if (write(1, buf[0..n])) 0 else 1;
    }
    if (std.mem.eql(u8, mode, "fail")) {
        return std.fmt.parseInt(u8, arg(2) orelse return 2, 10) catch 2;
    }
    if (std.mem.eql(u8, mode, "show")) {
        var n: usize = 0;
        for (std.os.argv[2..]) |w| n += (std.fmt.bufPrint(buf[n..], "arg {s}\n", .{std.mem.span(w)}) catch return 1).len;
        for (std.os.environ) |e| n += (std.fmt.bufPrint(buf[n..], "env {s}\n", .{std.mem.span(e)}) catch return 1).len;
        return if (write(1, buf[0..n])) 0 else 1;
    }
    if (std.mem.eql(u8, mode, "flood")) {
        var left = std.fmt.parseInt(usize, arg(2) orelse return 2, 10) catch return 2;
        @memset(&buf, 'x');
        while (left > 0) {
            const n = @min(left, buf.len);
            if (!write(1, buf[0..n])) return 1;
            left -= n;
        }
        return 0;
    }
    if (std.mem.eql(u8, mode, "prepare") or std.mem.eql(u8, mode, "gc")) return cache(mode);
    if (std.mem.eql(u8, mode, "relaunch")) return relaunch();
    return 2;
}

fn cache(mode: []const u8) u8 {
    if (!log()) return 1;
    var dash: usize = 2;
    while (dash < std.os.argv.len and !std.mem.eql(u8, std.mem.span(std.os.argv[dash]), "--")) dash += 1;
    if (std.mem.eql(u8, mode, "gc")) {
        const old = arg(dash + 1) orelse return 2;
        if (std.mem.indexOf(u8, std.fs.path.basename(old), "stuck") != null) return 1;
        return if (linux.E.init(linux.rmdir(std.os.argv[dash + 1])) == .SUCCESS) 0 else 1;
    }
    const dir = arg(dash + 1) orelse return 2;
    const closure = arg(dash + 2) orelse return 2;
    const user = arg(dash + 3) orelse return 2;
    if (std.mem.eql(u8, closure, "fail")) return 1;
    var pb: [4096]u8 = undefined;
    for ([_][]const u8{ "prepared", "prepared/etc" }) |sub| {
        const p = std.fmt.bufPrintZ(&pb, "{s}/{s}", .{ dir, sub }) catch return 1;
        if (linux.E.init(linux.mkdir(p, 0o755)) != .SUCCESS) return 1;
    }
    var pw: [512]u8 = undefined;
    var gr: [512]u8 = undefined;
    const files = [_][2][]const u8{
        .{ "passwd", std.fmt.bufPrint(&pw, "root:x:0:0::/root:/bin/sh\n{s}:x:1000:100::/home/{s}:/bin/sh\n", .{ user, user }) catch return 1 },
        .{ "group", std.fmt.bufPrint(&gr, "users:x:100:\nwheel:x:1:{s}\n", .{user}) catch return 1 },
    };
    for (files) |f| {
        const p = std.fmt.bufPrintZ(&pb, "{s}/prepared/etc/{s}", .{ dir, f[0] }) catch return 1;
        const rc = linux.open(p, .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .CLOEXEC = true }, 0o644);
        if (linux.E.init(rc) != .SUCCESS) return 1;
        const fd: i32 = @intCast(rc);
        defer _ = linux.close(fd);
        if (!write(fd, f[1])) return 1;
    }
    return 0;
}

/// "MODE ARG..." as one line, appended to $FLONG_FAKE_LOG.
fn log() bool {
    const path = std.posix.getenv("FLONG_FAKE_LOG") orelse return false;
    var pb: [4096]u8 = undefined;
    const p = std.fmt.bufPrintZ(&pb, "{s}", .{path}) catch return false;
    var n: usize = 0;
    for (std.os.argv[1..], 0..) |w, i| {
        n += (std.fmt.bufPrint(buf[n..], "{s}{s}", .{ if (i == 0) "" else " ", std.mem.span(w) }) catch return false).len;
    }
    buf[n] = '\n';
    const rc = linux.open(p, .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true, .CLOEXEC = true }, 0o600);
    if (linux.E.init(rc) != .SUCCESS) return false;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    return write(fd, buf[0 .. n + 1]);
}

fn relaunch() u8 {
    const left = std.fmt.parseInt(u8, arg(2) orelse return 2, 10) catch return 2;
    if (left == 0) {
        var eb: [4096]u8 = undefined;
        const n = linux.readlink("/proc/self/exe", &eb, eb.len);
        if (linux.E.init(n) != .SUCCESS) return 1;
        const text = std.fmt.bufPrint(&buf, "argv0 {s}\nexe {s}\n", .{ arg(0).?, eb[0..n] }) catch return 1;
        return if (write(1, text)) 0 else 1;
    }
    var nb: [4]u8 = undefined;
    const next = std.fmt.bufPrintZ(&nb, "{d}", .{left - 1}) catch return 1;
    const argv = [_][*:0]const u8{ std.os.argv[0], "relaunch", next.ptr };
    var ab: [4096]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&ab);
    return switch (prologue.relaunchSelf(fba.allocator(), &argv, null, @ptrCast(std.os.environ.ptr))) {
        error.Reported => 1,
    };
}
