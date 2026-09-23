const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });

    // The probe a spawn test starts: prints what it holds and what argv named.
    const probe = b.addExecutable(.{
        .name = "fd-probe",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/probe.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    // ---- test: unit and property tests ----
    // minish is lazy, as in capsper: only the tests use it, so a plain build
    // needs no network, which a Nix derivation requires.
    const test_step = b.step("test", "Run unit and property tests");
    if (b.lazyDependency("minish", .{ .target = target, .optimize = optimize })) |minish| {
        const opts = b.addOptions();
        opts.addOptionPath("probe", probe.getEmittedBin());
        const tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/fd_test.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "minish", .module = minish.module("minish") },
                    .{ .name = "options", .module = opts.createModule() },
                },
            }),
        });
        test_step.dependOn(&b.addRunArtifact(tests).step);
    }

    // ---- compile-fail: kind confusion must not compile ----
    const cf_step = b.step("compile-fail", "Check that kind confusion is a compile error");
    const cases = [_]struct { file: []const u8, expect: []const u8 }{
        .{ .file = "probes/compile_fail/read_on_write_end.zig", .expect = "read on a pipe_w descriptor" },
        .{ .file = "probes/compile_fail/pidfd_as_dir.zig", .expect = "expected type '?fd.Fd(.dir)', found 'fd.Fd(.pidfd)'" },
    };
    for (cases) |c| {
        const run = b.addSystemCommand(&.{ b.graph.zig_exe, "build-obj", "-fno-emit-bin", "--dep", "fd" });
        run.addPrefixedFileArg("-Mroot=", b.path(c.file));
        run.addPrefixedFileArg("-Mfd=", b.path("src/fd.zig"));
        run.addCheck(.{ .expect_stderr_match = c.expect });
        run.addCheck(.{ .expect_term = .{ .Exited = 1 } });
        cf_step.dependOn(&run.step);
    }

    // ---- lint: the rules zwanzig cannot express ----
    const lint_step = b.step("lint", "Confine raw descriptor APIs to the syscall layer");
    const fdlint = b.addExecutable(.{
        .name = "fdlint",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/fdlint.zig"),
            .target = b.graph.host,
        }),
    });
    {
        // The code under the rules: everything but the syscall layer and the
        // test harness, which needs raw access to check the table from outside.
        const run = b.addRunArtifact(fdlint);
        for ([_][]const u8{ "fd.zig", "procfds.zig", "probe.zig", "fd_test.zig" }) |f| run.addArgs(&.{ "--allow", f });
        for ([_][]const u8{ "src/fd.zig", "src/procfds.zig", "src/probe.zig", "src/fd_test.zig", "probes/api/bugs.zig" }) |f| run.addFileArg(b.path(f));
        run.expectExitCode(0);
        lint_step.dependOn(&run.step);
    }
    {
        // The lint's own check: every planted line in bad.zig is reported.
        const run = b.addRunArtifact(fdlint);
        run.addFileArg(b.path("probes/lint/bad.zig"));
        for ([_][]const u8{
            "bad.zig:7:9: raw-namespace",
            "bad.zig:10:15: raw-namespace",
            "bad.zig:17:23: raw-namespace",
            "bad.zig:22:16: raw-namespace",
            "bad.zig:26:14: handle-guts",
            "bad.zig:30:16: handle-guts",
            "bad.zig:30:27: handle-guts",
            "bad.zig:33:11: cimport",
        }) |want| run.addCheck(.{ .expect_stdout_match = want });
        run.addCheck(.{ .expect_term = .{ .Exited = 1 } });
        lint_step.dependOn(&run.step);
    }

    // ---- analyze: zwanzig, lazy for the same reason ----
    // Resource models match on method name only: receiver_type and fqn do not
    // resolve a type imported from another file (checked in the spike).
    const analyze_step = b.step("analyze", "Run zwanzig on src/, and check it still catches the planted bugs");
    if (b.lazyDependency("zwanzig", .{ .target = b.graph.host, .optimize = .ReleaseFast })) |zw| {
        const exe = zw.artifact("zwanzig");
        {
            const run = b.addRunArtifact(exe);
            run.addArg("--config");
            run.addFileArg(b.path(".zwanzig.json"));
            run.addDirectoryArg(b.path("src"));
            run.expectExitCode(0);
            analyze_step.dependOn(&run.step);
        }
        {
            // B4 (leak) and B5 (a copy in a struct) are beyond it: the runtime
            // table and the property test cover those.
            const run = b.addRunArtifact(exe);
            run.addArg("--config");
            run.addFileArg(b.path(".zwanzig.json"));
            run.addFileArg(b.path("probes/api/bugs.zig"));
            for ([_][]const u8{
                "bugs.zig:10:12: error: [store-violations-engine] double-close", // B1
                "bugs.zig:18:13: error: [store-violations-engine] use after close", // B2
                "bugs.zig:25:12: error: [store-violations-engine] use after close", // B3
                "bugs.zig:49:14: error: [store-violations-engine] double-close", // B6
                "bugs.zig:57:13: error: [store-violations-engine] double-close", // B7
                "bugs.zig:65:12: error: [store-violations-engine] double-close", // B8
            }) |want| run.addCheck(.{ .expect_stdout_match = want });
            run.addCheck(.{ .expect_term = .{ .Exited = 1 } });
            analyze_step.dependOn(&run.step);
        }
    }

    b.installArtifact(probe);
}
