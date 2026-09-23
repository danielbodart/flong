const std = @import("std");

// P3, processes (ZIG.md, "Phase 0: proofs"). `install` is p3-proc, built as
// every flong binary is (ZIG.md, "build.zig", "Per binary"): ReleaseSafe from
// the hook, stripped, single-threaded, no libc, no stack size of its own.
// `compile-fail` checks that a fork body that can return does not compile.
// `cross` compiles p3-proc for aarch64-linux, so CloneArgs' size assert runs
// for both of the flake's systems.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });

    const exe = procExe(b, target, optimize);
    b.installArtifact(exe);

    const cf_step = b.step("compile-fail", "Check that a fork body that can return does not compile");
    {
        const run = b.addSystemCommand(&.{ b.graph.zig_exe, "build-obj", "-fno-emit-bin", "--dep", "proc" });
        run.addPrefixedFileArg("-Mroot=", b.path("probes/body_returns.zig"));
        run.addPrefixedFileArg("-Mproc=", b.path("src/proc.zig"));
        // The parameter's type is the whole mechanism: `comptime body: fn
        // (@TypeOf(ctx)) noreturn` (src/proc.zig) takes no other function.
        run.addCheck(.{ .expect_stderr_match = "expected type 'fn (u8) noreturn', found 'fn (u8) void'" });
        run.addCheck(.{ .expect_stderr_match = "return type 'void' cannot cast into return type 'noreturn'" });
        run.addCheck(.{ .expect_term = .{ .Exited = 1 } });
        cf_step.dependOn(&run.step);
    }

    const cross_step = b.step("cross", "Compile p3-proc for aarch64-linux (CloneArgs' asserts)");
    const arm = procExe(b, b.resolveTargetQuery(.{ .cpu_arch = .aarch64, .os_tag = .linux }), optimize);
    cross_step.dependOn(&arm.step);
}

fn procExe(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    const exe = b.addExecutable(.{
        .name = "p3-proc",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .strip = true,
            .single_threaded = true,
        }),
    });
    // RLIMIT_STACK passes through untouched: no prlimit64 at start
    // (ZIG.md, "Measured").
    exe.stack_size = 0;
    return exe;
}
