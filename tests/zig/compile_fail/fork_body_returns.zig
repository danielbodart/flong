// Must not compile: a fork body that can return. Were it allowed, the child
// would come back out of proc.fork into this function and run its defer,
// the parent's cleanup, in the child (DESIGN.md, "Conventions": children; P3's
// probe, tests/proofs/p3/probes/body_returns.zig until phase 5).
const proc = @import("proc");

fn body(_: u8) void {}

export fn bug() void {
    defer {}
    _ = proc.fork(.{}, @as(u8, 0), body) catch {};
}
