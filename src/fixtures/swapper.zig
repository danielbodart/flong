//! swapper DIR: exchanges DIR/sub and DIR/sublink until it is killed, as a
//! payload racing another session's mounts would (ZIG.md, "Phase 6"). The
//! C that tests/probes.nix held until phase 6 (b), line by line: chdir, then
//! renameat2(RENAME_EXCHANGE) of the two names in a loop; a usage error is
//! 2, a failed call perror's line and 1.
//!
//! Static, no libc; its tightest loop is one syscall, as the C's.

const std = @import("std");
const linux = std.os.linux;
const sys = @import("sys");
const errno = @import("errno");
const msg = @import("msg");

pub const std_options: std.Options = .{
    .enable_segfault_handler = false,
    .keep_sigpipe = true,
};

pub const panic = std.debug.FullPanic(msg.onPanic(125));

/// RENAME_EXCHANGE (linux/fs.h).
const rename_exchange = 2;

/// perror(3): "WHAT: <strerror(e)>", or the text alone when WHAT is "".
fn perror(what: []const u8, e: sys.E) void {
    var buf: [errno.max_len]u8 = undefined;
    if (what.len == 0) return msg.bare("{s}", .{errno.describe(e, &buf)});
    msg.bare("{s}: {s}", .{ what, errno.describe(e, &buf) });
}

pub fn main() noreturn {
    msg.prog = "swapper";
    msg.mode = .whole;
    const argv = sys.argv();
    if (argv.len != 2) {
        msg.bare("usage: swapper DIR", .{});
        sys.exitGroup(2);
    }
    switch (linux.E.init(linux.chdir(argv[1]))) {
        .SUCCESS => {},
        else => |e| {
            perror(std.mem.span(argv[1]), e);
            sys.exitGroup(1);
        },
    }
    while (true) {
        switch (linux.E.init(linux.renameat2(linux.AT.FDCWD, "sub", linux.AT.FDCWD, "sublink", rename_exchange))) {
            .SUCCESS => {},
            else => |e| {
                perror("renameat2", e);
                sys.exitGroup(1);
            },
        }
    }
}
