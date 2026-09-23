//! P4, the mount ABI (ZIG.md, "Phase 0: proofs"; default.nix says what each
//! step answers).
//!
//!   abi      src/abi_test.zig against Zig's bundled headers, compiled for
//!            x86_64 and aarch64 and run on the host's arch; -Dplant=arch or
//!            -Dplant=offset plants a mismatch, which must fail
//!   install  bin/p4-mount, the round trip of the calls (src/mount.zig)
const std = @import("std");

const Plant = enum { none, arch, offset };

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });
    const plant = b.option(Plant, "plant", "Plant a mismatch in the abi check: arch, offset") orelse .none;

    const abi_step = b.step("abi", "Check src/abi.zig against Zig's bundled headers, x86_64 and aarch64");
    for ([_]std.Target.Cpu.Arch{ .x86_64, .aarch64 }) |arch| {
        // musl: an explicit libc target, so translate-c's include path is
        // Zig's own lib/libc/include (<arch>-linux-musl, generic-musl,
        // <arch>-linux-any, any-linux-any), never the host's or
        // NIX_CFLAGS_COMPILE's, which Zig reads for a native target only.
        // Only the headers are used: the test itself links no libc.
        const t = b.resolveTargetQuery(.{ .cpu_arch = arch, .os_tag = .linux, .abi = .musl });
        const headers = b.addTranslateC(.{
            .root_source_file = b.path("src/abi.h"),
            .target = t,
            .optimize = optimize,
        });
        const opts = b.addOptions();
        opts.addOption(Plant, "plant", plant);
        const tests = b.addTest(.{
            .name = b.fmt("abi-{s}", .{@tagName(arch)}),
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/abi_test.zig"),
                .target = t,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "abi", .module = b.createModule(.{ .root_source_file = b.path("src/abi.zig"), .target = t, .optimize = optimize }) },
                    .{ .name = "c", .module = b.createModule(.{ .root_source_file = headers.getOutput(), .target = t, .optimize = optimize }) },
                    .{ .name = "options", .module = opts.createModule() },
                },
            }),
        });
        // Every check is comptime, so compiling is the check; the host's
        // arch also runs, to print what was compared.
        if (arch == b.graph.host.result.cpu.arch) {
            const run = b.addRunArtifact(tests);
            abi_step.dependOn(&run.step);
        } else {
            abi_step.dependOn(&tests.step);
        }
    }

    const mount = b.addExecutable(.{
        .name = "p4-mount",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/mount.zig"),
            .target = target,
            .optimize = optimize,
            .strip = true,
            .single_threaded = true,
            .imports = &.{
                .{ .name = "abi", .module = b.createModule(.{ .root_source_file = b.path("src/abi.zig"), .target = target, .optimize = optimize }) },
            },
        }),
    });
    b.installArtifact(mount);
}
