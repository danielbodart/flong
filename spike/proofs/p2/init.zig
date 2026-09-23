// P2's stand-in for flong-init (ZIG.md, "Phase 0: proofs"): the root-level
// declarations every Zig flong-init has ("Per binary"), and just enough of a
// body to observe them as pid 1 under bwrap and the strict seccomp stack.
//
//   p2-init stack COMMAND...   print "pid=P stack=S", S RLIMIT_STACK's soft
//                              limit in KiB as `ulimit -s` prints it, then
//                              exec COMMAND (an absolute path)
//   p2-init panic              a planted panic: one line, exit 125
//   p2-init logged             io_uring_setup, which the strict tier leaves
//                              out, so log = true writes an audit record:
//                              the VM's check that records do reach it
//
// Every mode's first syscall is getpid, which Zig's start code never makes
// (start.zig:480-590), so a trace in which the first call after execve is
// getpid shows that nothing ran before main.
const std = @import("std");
const linux = std.os.linux;

// No SIGSEGV handler and no SIG_IGN for SIGPIPE: the start code would
// otherwise install both (start.zig:687-719), and a payload inherits an
// ignored SIGPIPE through exec.
pub const std_options: std.Options = .{
    .enable_segfault_handler = false,
    .keep_sigpipe = true,
};

// The default panic ends in abort, and pid 1 drops its own SIGABRT, so it
// would end in SIGSEGV (posix.zig:680-727). Instead: one line, one writev,
// then exit_group(125), flong-init's "the payload never ran".
pub const panic = std.debug.FullPanic(onPanic);

const Iovec = extern struct { base: [*]const u8, len: usize };

fn onPanic(msg: []const u8, _: ?usize) noreturn {
    const prefix = "flong-init: internal error: ";
    const iov = [_]Iovec{
        .{ .base = prefix, .len = prefix.len },
        .{ .base = msg.ptr, .len = msg.len },
        .{ .base = "\n", .len = 1 },
    };
    _ = linux.syscall3(.writev, 2, @intFromPtr(&iov), iov.len);
    linux.exit_group(125);
}

fn say(fd: i32, text: []const u8) void {
    _ = linux.write(fd, text.ptr, text.len);
}

fn usage() noreturn {
    say(2, "usage: p2-init stack COMMAND... | panic | logged\n");
    linux.exit_group(2);
}

fn eql(a: [*:0]const u8, b: []const u8) bool {
    return std.mem.eql(u8, std.mem.span(a), b);
}

pub fn main() noreturn {
    const pid = linux.getpid();
    const argv = std.os.argv;
    if (argv.len < 2) usage();

    if (eql(argv[1], "panic")) {
        @panic("planted");
    }

    if (eql(argv[1], "logged")) {
        _ = linux.syscall2(.io_uring_setup, 0, 0);
        linux.exit_group(0);
    }

    if (!eql(argv[1], "stack") or argv.len < 3) usage();

    var lim: linux.rlimit = undefined;
    if (linux.E.init(linux.prlimit(0, .STACK, null, &lim)) != .SUCCESS) {
        say(2, "p2-init: prlimit64 failed\n");
        linux.exit_group(125);
    }
    var buf: [64]u8 = undefined;
    const line = if (lim.cur == linux.RLIM.INFINITY)
        std.fmt.bufPrint(&buf, "pid={d} stack=unlimited\n", .{pid})
    else
        std.fmt.bufPrint(&buf, "pid={d} stack={d}\n", .{ pid, lim.cur / 1024 });
    say(1, line catch unreachable); // proven: 64 bytes hold both lines

    // The kernel's argv and envp are each null-terminated, so the tail of
    // argv is an exec argv as it stands, as flong-init.c:222-237 reuses it.
    const tail: [*:null]const ?[*:0]const u8 = @ptrCast(argv.ptr + 2);
    const envp: [*:null]const ?[*:0]const u8 = @ptrCast(std.os.environ.ptr);
    const err = linux.E.init(linux.execve(argv[2], tail, envp));
    say(2, "p2-init: execve failed: ");
    say(2, @tagName(err));
    say(2, "\n");
    linux.exit_group(125);
}
