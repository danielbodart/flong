// P5, the hybrid link (ZIG.md, "Phase 0: proofs"): a static library with
// exactly the mount-helper shim's settings (ZIG.md, "The mount-helper
// shim"), exporting one symbol, proof_main. `install` puts lib/libp5.a under
// the prefix; default.nix links it into a C program with $CC and runs the
// clash check.
const std = @import("std");

pub fn build(b: *std.Build) void {
    // No libc: the target's ABI is none, as in the measured link (ZIG.md,
    // "Measured"). -Dcpu=baseline from the hook still applies.
    const target = b.standardTargetOptions(.{ .default_target = .{ .abi = .none } });
    // Accepts the hook's --release=safe (ZIG.md, "build.zig").
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });

    const lib = b.addLibrary(.{
        .name = "p5",
        .linkage = .static,
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/shim.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = false,
            // The launcher is linked -pie by the cc-wrapper's hardening.
            .pic = true,
            .single_threaded = true,
            .strip = true,
            // Stack probing is what referenced __zig_probe_stack, which
            // only compiler-rt defines (ZIG.md, "Measured").
            .stack_check = false,
            .stack_protector = false,
        }),
    });
    // compiler_rt.o defines memcpy, memset, memmove, memcmp, bcmp,
    // __stack_chk_fail and __stack_chk_guard, which would take the C's calls
    // from glibc (ZIG.md, "Measured").
    lib.bundle_compiler_rt = false;
    b.installArtifact(lib);
}
