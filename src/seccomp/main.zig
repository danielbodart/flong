//! flong-seccomp's root (ZIG.md, "Per binary"): seccomp/flong-seccomp.c's
//! main (:327-341), and the seccomp tooling's subcommands (ZIG.md,
//! "Phase 2"). With no argument it compiles a policy on stdin to a filter
//! on stdout (compile.zig; libseccomp is scmp.zig):
//!
//!   flong-seccomp < POLICY > FILTER.bpf
//!   flong-seccomp expand DUMP SPEC...              seccomp/expand.awk
//!   flong-seccomp render DUMP NAMES 1|13|38|log    flong-seccomp-render
//!   flong-seccomp project DUMP NAMES 1|13|38|log DIR < POLICY
//!                                                  flong-seccomp-project
//!
//! Anything else is a usage error, exit 2, which names them all (quirk 16).
//! Each subcommand prints its own usage line (quirk 38).

const std = @import("std");
const sys = @import("sys");
const msg = @import("msg");
const compile = @import("compile.zig");
const expand = @import("expand.zig");
const render = @import("render.zig");
const project = @import("project.zig");
const scmp = @import("scmp.zig");

// No SIGSEGV handler and no ignored SIGPIPE: the start code would install
// both (start.zig:687-719), and flong-seccomp's caller reads its status.
pub const std_options: std.Options = .{
    .enable_segfault_handler = false,
    .keep_sigpipe = true,
};

// "flong-seccomp: internal error: <msg>", exit 1: a refusal to the callers,
// and nothing on stdout, since the export is the last step (ZIG.md, "Per
// binary"). Under a subcommand the prefix is the one it prints with.
pub const panic = std.debug.FullPanic(msg.onPanic(1));

// The C's `static struct policy p` (:329): 4 KiB of seen bits, off the
// stack.
var policy: compile.Policy = .{};

const usage = "usage: flong-seccomp [expand DUMP SPEC... | render DUMP NAMES 1|13|38|log" ++
    " | project DUMP NAMES 1|13|38|log DIR] < POLICY";

pub fn main() noreturn {
    msg.prog = "flong-seccomp";
    msg.mode = .whole;
    // One arena over libc's malloc, never freed: the process is short.
    var arena: std.heap.ArenaAllocator = .init(std.heap.c_allocator);
    const gpa = arena.allocator();
    const argv = sys.argv();
    if (argv.len == 1) sys.exitGroup(compileStdin(gpa));
    const sub = std.mem.span(argv[1]);
    const args = argv[2..];
    const status: u8 = if (std.mem.eql(u8, sub, "expand"))
        expand.main(gpa, args)
    else if (std.mem.eql(u8, sub, "render"))
        render.main(gpa, args)
    else if (std.mem.eql(u8, sub, "project"))
        project.main(gpa, args)
    else blk: {
        msg.bare(usage, .{});
        break :blk 2;
    };
    sys.exitGroup(status);
}

/// flong-seccomp.c's main: the policy on stdin, the filter on stdout, the
/// stats line after it.
fn compileStdin(gpa: std.mem.Allocator) u8 {
    // Reported is the one failure (ZIG.md, "Messages, errors and panics"),
    // printed where it happened; another error would not compile here.
    const ok = if (compile.compile(&policy, gpa, .stdin, .stdout)) true else |err| switch (err) {
        error.Reported => false,
    };
    if (ok) compile.stats(&policy);
    if (policy.ctx) |ctx| scmp.release(ctx);
    return if (ok) 0 else 1;
}
