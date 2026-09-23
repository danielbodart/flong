//! flong-seccomp's root (ZIG.md, "Per binary"): seccomp/flong-seccomp.c's
//! main (:327-341). The compiler itself is compile.zig; libseccomp is
//! scmp.zig. Any argument is a usage error, as in the C: the subcommands
//! arrive in phase 2 (quirk 16).

const std = @import("std");
const sys = @import("sys");
const msg = @import("msg");
const compile = @import("compile.zig");
const scmp = @import("scmp.zig");

// No SIGSEGV handler and no ignored SIGPIPE: the start code would install
// both (start.zig:687-719), and flong-seccomp's caller reads its status.
pub const std_options: std.Options = .{
    .enable_segfault_handler = false,
    .keep_sigpipe = true,
};

// "flong-seccomp: internal error: <msg>", exit 1: a refusal to the callers,
// and nothing on stdout, since the export is the last step (ZIG.md, "Per
// binary").
pub const panic = std.debug.FullPanic(msg.onPanic(1));

// The C's `static struct policy p` (:329): 4 KiB of seen bits, off the
// stack.
var policy: compile.Policy = .{};

pub fn main() noreturn {
    msg.prog = "flong-seccomp";
    msg.mode = .whole;
    if (sys.argv().len != 1) {
        msg.bare("usage: flong-seccomp < POLICY > FILTER.bpf", .{});
        sys.exitGroup(2);
    }
    // One arena over libc's malloc, never freed: the process is short.
    var arena: std.heap.ArenaAllocator = .init(std.heap.c_allocator);
    // Reported is the one failure (ZIG.md, "Messages, errors and panics"),
    // printed where it happened; another error would not compile here.
    const ok = if (compile.compile(&policy, arena.allocator())) true else |err| switch (err) {
        error.Reported => false,
    };
    if (policy.ctx) |ctx| scmp.release(ctx);
    sys.exitGroup(if (ok) 0 else 1);
}
