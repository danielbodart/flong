// P2's package: p2-init, a stand-in for flong-init built with ZIG.md's
// "Per binary" settings, and p2-init-default, the same source with Zig's
// defaults for the two settings under test, so the VM can show that its
// checks see what those settings remove.
const std = @import("std");

pub fn build(b: *std.Build) void {
    // x86_64-linux-none unless -Dtarget says otherwise; the hook adds
    // -Dcpu=baseline and --release=safe (zig generic.nix:158-160).
    const target = b.standardTargetOptions(.{ .default_target = .{ .os_tag = .linux, .abi = .none } });
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });

    // ZIG.md, "Per binary": static, no libc, stripped, single_threaded,
    // stack_size = 0. Without single_threaded the start code sets up TLS
    // with arch_prctl; with a stack size it reads RLIMIT_STACK and raises it
    // to that size (start.zig:545-578), which a child then inherits.
    const init = b.addExecutable(.{
        .name = "p2-init",
        .root_module = b.createModule(.{
            .root_source_file = b.path("init.zig"),
            .target = target,
            .optimize = optimize,
            .strip = true,
            .single_threaded = true,
        }),
    });
    init.stack_size = 0;
    b.installArtifact(init);

    // The control: Zig's default stack (16 MiB in PT_GNU_STACK) and threads.
    // Stripped too, or it would name Zig's lib/std (disallowedReferences).
    const default = b.addExecutable(.{
        .name = "p2-init-default",
        .root_module = b.createModule(.{
            .root_source_file = b.path("init.zig"),
            .target = target,
            .optimize = optimize,
            .strip = true,
        }),
    });
    b.installArtifact(default);
}
