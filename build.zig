//! flong's native code, one package (ZIG.md, "build.zig"). One Nix
//! derivation per install set builds it over only the sources that set
//! imports (native.nix); every other step is a check.
//!
//!   install       -Dset=seccomp (flong-seccomp; needs -Dself), launcher
//!                 (phase 3) or fixtures (phase 6)
//!   test          unit and property tests, Debug, or ReleaseSafe with
//!                 -Drelease=true (as every step); needs -Ddev=true
//!   test-libc     errno.zig and num.zig against glibc, scmp.zig against
//!                 seccomp.h (tests/zig/libc_*.zig)
//!   compile-fail  what must not compile (tests/zig/compile_fail/)
//!   lint          tools/fdlint.zig over src/ and tests/zig/, and over its
//!                 own planted files (tests/zig/lint/)
//!   fmt           zig fmt --check over the package's Zig
//!   analyze       zwanzig over src/, and over its planted bugs
//!                 (tests/zig/analyze/); needs -Ddev=true
//!   cross         flong-seccomp compiled for aarch64-linux, not linked
//!
//! Every path a step reads is a lazy b.path, so an install set's derivation,
//! which holds build.zig, build.zig.zon and its own sources only, configures
//! (spike/proofs/p1, `outside`).
const std = @import("std");

const Set = enum { seccomp, launcher, fixtures };

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // Debug by default; ReleaseSafe under -Drelease=true, which this
    // declares, or the zig hook's --release=safe (generic.nix:158-160). A
    // plain -Doptimize=ReleaseSafe is refused.
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });
    // The lazy dependencies are fetched only under -Ddev=true: an unguarded
    // lazyDependency makes an offline `zig build install` fail fetching them
    // (build_runner.zig:370), and a Nix build is offline. Without it the
    // steps that need them fail and say why.
    const dev = b.option(bool, "dev", "Enable the steps that need lazy dependencies: test, analyze") orelse false;
    const set = b.option(Set, "set", "What install installs: seccomp, launcher or fixtures");
    // Compiled-in paths have no default: a missing one fails the install
    // that needs it, as flong-init.c:52-54's #error does.
    const self = b.option([]const u8, "self", "flong-seccomp's own store path, the seccomp derivation's $out");

    // ---- install ----
    const install = b.getInstallStep();
    if (set) |s| switch (s) {
        .seccomp => if (self) |path| {
            b.installArtifact(seccomp(b, target, optimize, path));
        } else {
            install.dependOn(&b.addFail("-Dset=seccomp needs -Dself=PATH, flong-seccomp's own store path").step);
        },
        .launcher => install.dependOn(&b.addFail("-Dset=launcher arrives in phase 3").step),
        .fixtures => install.dependOn(&b.addFail("-Dset=fixtures arrives in phase 6").step),
    } else {
        install.dependOn(&b.addFail("install needs -Dset=seccomp|launcher|fixtures").step);
    }

    // ---- test: unit and property tests ----
    const test_step = b.step("test", "Run the unit and property tests (-Drelease=true for ReleaseSafe)");
    if (!dev) {
        test_step.dependOn(&b.addFail("needs -Ddev=true").step);
    } else if (b.lazyDependency("minish", .{ .target = target, .optimize = optimize })) |minish| {
        // Each module's own tests, with the modules it imports.
        for ([_][]const u8{ "sys", "errno", "msg", "num" }) |name| {
            const m = modules(b, target, optimize);
            const t = b.addTest(.{ .name = name, .root_module = m.get(name) });
            test_step.dependOn(&b.addRunArtifact(t).step);
        }
        {
            // compile.zig's own tests, in flong-seccomp's root module,
            // linked as it is.
            const root = seccompModule(b, target, optimize, "/nix/store/test-only");
            root.root_source_file = b.path("src/seccomp/compile.zig");
            root.linkSystemLibrary("seccomp", .{});
            const t = b.addTest(.{ .name = "compile", .root_module = root });
            test_step.dependOn(&b.addRunArtifact(t).step);
        }
        const m = modules(b, target, optimize);
        const props = b.addTest(.{
            .name = "props",
            .root_module = b.createModule(.{
                .root_source_file = b.path("tests/zig/props.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "minish", .module = minish.module("minish") },
                    .{ .name = "num", .module = m.num },
                },
            }),
        });
        test_step.dependOn(&b.addRunArtifact(props).step);
    }

    // ---- test-libc: the tables and parsers that stand in for glibc ----
    const libc_step = b.step("test-libc", "Check errno.zig and num.zig against glibc, scmp.zig against seccomp.h");
    for ([_][]const u8{ "errno", "num" }) |name| {
        const m = modules(b, target, optimize);
        const t = b.addTest(.{
            .name = b.fmt("libc_{s}", .{name}),
            .root_module = b.createModule(.{
                .root_source_file = b.path(b.fmt("tests/zig/libc_{s}.zig", .{name})),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
                .imports = &.{
                    .{ .name = "sys", .module = m.sys },
                    .{ .name = name, .module = m.get(name) },
                },
            }),
        });
        libc_step.dependOn(&b.addRunArtifact(t).step);
    }
    {
        // scmp.zig against seccomp.h, through translate-c of the libseccomp
        // this build links, with the calls themselves run once.
        const m = modules(b, target, optimize);
        const header = b.addTranslateC(.{
            .root_source_file = b.path("tests/zig/scmp.h"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        // translate-c, unlike a compile, is given no native include paths,
        // so seccomp.h is found where a compile would find it: in the
        // -isystem entries of NIX_CFLAGS_COMPILE (NativePaths.zig), for any
        // native OS and ABI, whatever the CPU (the hook passes -Dcpu=baseline).
        if (target.query.isNativeOs() and target.query.isNativeAbi()) {
            const paths = std.zig.system.NativePaths.detect(b.allocator, &target.result) catch @panic("OOM");
            for (paths.include_dirs.items) |dir| header.addSystemIncludePath(.{ .cwd_relative = dir });
        }
        const scmp = b.createModule(.{
            .root_source_file = b.path("src/seccomp/scmp.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "sys", .module = m.sys }},
        });
        const root = b.createModule(.{
            .root_source_file = b.path("tests/zig/libc_scmp.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "scmp", .module = scmp },
                .{ .name = "seccomp_h", .module = header.createModule() },
            },
        });
        root.linkSystemLibrary("seccomp", .{});
        const t = b.addTest(.{ .name = "libc_scmp", .root_module = root });
        libc_step.dependOn(&b.addRunArtifact(t).step);
    }

    // ---- compile-fail: what must not compile, and the compiler's words ----
    const cf_step = b.step("compile-fail", "Check that each file in tests/zig/compile_fail/ fails to compile, and why");
    const cases = [_]struct { file: []const u8, expect: []const u8 }{
        .{ .file = "result_ignored.zig", .expect = "value of type 'sys.Result(usize)' ignored" },
        .{ .file = "result_unwrapped.zig", .expect = "expected type 'usize', found 'sys.Result(usize)'" },
        .{ .file = "msg_arguments.zig", .expect = "msg: \"line {d}: {s}\" takes 2 arguments, given 1" },
    };
    for (cases) |c| {
        // Every module of src/ is on the command line, each with its own
        // imports; the case imports what it needs.
        const run = b.addSystemCommand(&.{ b.graph.zig_exe, "build-obj", "-fno-emit-bin" });
        run.addArgs(&.{ "--dep", "sys", "--dep", "errno", "--dep", "msg", "--dep", "num" });
        run.addPrefixedFileArg("-Mroot=", b.path(b.fmt("tests/zig/compile_fail/{s}", .{c.file})));
        run.addPrefixedFileArg("-Msys=", b.path("src/sys.zig"));
        run.addArgs(&.{ "--dep", "sys" });
        run.addPrefixedFileArg("-Merrno=", b.path("src/errno.zig"));
        run.addArgs(&.{ "--dep", "sys", "--dep", "errno" });
        run.addPrefixedFileArg("-Mmsg=", b.path("src/msg.zig"));
        run.addPrefixedFileArg("-Mnum=", b.path("src/num.zig"));
        run.addCheck(.{ .expect_stderr_match = c.expect });
        run.addCheck(.{ .expect_term = .{ .Exited = 1 } });
        cf_step.dependOn(&run.step);
    }

    // ---- lint: the rules the compiler and zwanzig cannot express ----
    const lint_step = b.step("lint", "Run fdlint over src/ and tests/zig/, and check it on its planted files");
    const fdlint = b.addExecutable(.{
        .name = "fdlint",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/fdlint.zig"),
            .target = b.graph.host,
        }),
    });
    {
        // Run from the package root, where each file's name is the path its
        // rules go by. The walk is fdlint's, which the step's cache cannot
        // see, so it always runs; its findings go to the build's own output,
        // and a finding fails the step.
        const run = b.addRunArtifact(fdlint);
        run.setCwd(b.path("."));
        run.has_side_effects = true;
        run.stdio = .inherit;
        run.addArgs(&.{
            "--skip", "tests/zig/lint", "--skip", "tests/zig/analyze", "--skip", "tests/zig/compile_fail",
            "src",    "tests/zig",
        });
        lint_step.dependOn(&run.step);
    }
    {
        // Every planted line of bad.zig reported, at its column.
        const run = b.addRunArtifact(fdlint);
        run.addArgs(&.{ "--as", "src/lint/bad.zig" });
        run.addFileArg(b.path("tests/zig/lint/bad.zig"));
        for ([_][]const u8{
            "bad.zig:9:15: raw-namespace",
            "bad.zig:9:15: posix",
            "bad.zig:16:13: raw-namespace",
            "bad.zig:17:13: raw-namespace",
            "bad.zig:18:13: raw-namespace",
            "bad.zig:19:9: raw-namespace",
            "bad.zig:23:19: posix",
            "bad.zig:26:1: extern",
            "bad.zig:27:1: extern",
            "bad.zig:28:1: extern",
            "bad.zig:29:1: extern",
            "bad.zig:30:13: extern",
            "bad.zig:31:11: extern",
            "bad.zig:34:14: raw-number",
            "bad.zig:38:16: argv",
            "bad.zig:38:33: argv",
            "bad.zig:42:14: handle-guts",
            "bad.zig:42:23: handle-guts",
            "bad.zig:46:12: adopt-foreign",
            "bad.zig:50:15: debug-output",
            "bad.zig:51:9: debug-output",
            "bad.zig:55:47: catch-unreachable",
            "bad.zig:58:19: alloc",
            "bad.zig:59:19: alloc",
        }) |want| run.addCheck(.{ .expect_stdout_match = want });
        run.addCheck(.{ .expect_term = .{ .Exited = 1 } });
        lint_step.dependOn(&run.step);
    }
    {
        // And nothing in good.zig, linted as the file that may export.
        const run = b.addRunArtifact(fdlint);
        run.addArgs(&.{ "--as", "src/hybrid/mount_c.zig" });
        run.addFileArg(b.path("tests/zig/lint/good.zig"));
        run.addCheck(.{ .expect_stdout_exact = "" });
        run.addCheck(.{ .expect_term = .{ .Exited = 0 } });
        lint_step.dependOn(&run.step);
    }

    // ---- fmt ----
    // With no paths, addFmt runs a bare `zig fmt --check`, which exits 1
    // (Build/Step/Fmt.zig:16).
    const fmt_step = b.step("fmt", "Check the formatting of the package's Zig");
    fmt_step.dependOn(&b.addFmt(.{ .check = true, .paths = &.{ "build.zig", "build.zig.zon", "src", "tests/zig", "tools" } }).step);

    // ---- analyze: zwanzig ----
    // Resource models match on method name alone: receiver_type and fqn do
    // not resolve a type imported from another file (the spike's finding).
    const analyze_step = b.step("analyze", "Run zwanzig over src/, and check it still catches the planted bugs");
    if (!dev) {
        analyze_step.dependOn(&b.addFail("needs -Ddev=true").step);
    } else if (b.lazyDependency("zwanzig", .{ .target = b.graph.host, .optimize = .ReleaseFast })) |zw| {
        const exe = zw.artifact("zwanzig");
        {
            const run = b.addRunArtifact(exe);
            run.addArg("--config");
            run.addFileArg(b.path(".zwanzig.json"));
            run.addDirectoryArg(b.path("src"));
            // Its findings go to the build's output; one fails the step.
            run.has_side_effects = true;
            run.stdio = .inherit;
            analyze_step.dependOn(&run.step);
        }
        {
            const run = b.addRunArtifact(exe);
            run.addArg("--config");
            run.addFileArg(b.path(".zwanzig.json"));
            run.addFileArg(b.path("tests/zig/analyze/bugs.zig"));
            for ([_][]const u8{
                "bugs.zig:16:12: error: [store-violations-engine] double-close", // B1
                "bugs.zig:24:13: error: [store-violations-engine] use after close", // B2
                "bugs.zig:31:12: error: [store-violations-engine] use after close", // B3
                "bugs.zig:55:14: error: [store-violations-engine] double-close", // B6
                "bugs.zig:62:14: error: [store-violations-engine] double-close", // B7
                "bugs.zig:70:12: error: [store-violations-engine] double-close", // B8
            }) |want| run.addCheck(.{ .expect_stdout_match = want });
            // And those six only: the ok* controls stay quiet.
            run.addCheck(.{ .expect_stdout_match = "Found 6 issue(s):\n" });
            run.addCheck(.{ .expect_term = .{ .Exited = 1 } });
            analyze_step.dependOn(&run.step);
        }
    }

    // ---- cross: aarch64 ----
    // flong-seccomp for aarch64-linux, analysed and compiled but not linked
    // (-fno-emit-bin: nothing asks for the binary): the flake has no aarch64
    // libseccomp to link against on x86_64 (ZIG.md, "The Nix build").
    const cross_step = b.step("cross", "Compile flong-seccomp for aarch64-linux, without linking");
    const arm = b.resolveTargetQuery(.{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .gnu });
    cross_step.dependOn(&seccompUnlinked(b, arm, optimize).step);
}

/// The modules of src/ every program shares, each importing its own
/// (ZIG.md, "Per binary": sys; then msg, errno, num).
const Modules = struct {
    sys: *std.Build.Module,
    errno: *std.Build.Module,
    msg: *std.Build.Module,
    num: *std.Build.Module,

    fn get(m: Modules, name: []const u8) *std.Build.Module {
        inline for (@typeInfo(Modules).@"struct".fields) |f| {
            if (std.mem.eql(u8, f.name, name)) return @field(m, f.name);
        }
        unreachable;
    }
};

fn modules(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) Modules {
    const sys = b.createModule(.{ .root_source_file = b.path("src/sys.zig"), .target = target, .optimize = optimize });
    const errno = b.createModule(.{
        .root_source_file = b.path("src/errno.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "sys", .module = sys }},
    });
    const msg = b.createModule(.{
        .root_source_file = b.path("src/msg.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{ .{ .name = "sys", .module = sys }, .{ .name = "errno", .module = errno } },
    });
    const num = b.createModule(.{ .root_source_file = b.path("src/num.zig"), .target = target, .optimize = optimize });
    return .{ .sys = sys, .errno = errno, .msg = msg, .num = num };
}

/// flong-seccomp's root module, the settings every installed artifact has
/// (ZIG.md, "build.zig" and "Per binary"): stripped (Nix's fixup strips only
/// bin/, with -S, and no aarch64 ELF; unstripped, it names Zig's lib/std),
/// single-threaded (no TLS setup before main), and linked with libc, which
/// libseccomp needs.
fn seccompModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, self: []const u8) *std.Build.Module {
    const m = modules(b, target, optimize);
    const config = b.addOptions();
    config.addOption([]const u8, "self", self);
    return b.createModule(.{
        .root_source_file = b.path("src/seccomp/main.zig"),
        .target = target,
        .optimize = optimize,
        .strip = true,
        .single_threaded = true,
        .link_libc = true,
        .imports = &.{
            .{ .name = "sys", .module = m.sys },
            .{ .name = "errno", .module = m.errno },
            .{ .name = "msg", .module = m.msg },
            .{ .name = "num", .module = m.num },
            .{ .name = "config", .module = config.createModule() },
        },
    });
}

fn seccomp(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, self: []const u8) *std.Build.Step.Compile {
    const root = seccompModule(b, target, optimize, self);
    root.linkSystemLibrary("seccomp", .{});
    const exe = b.addExecutable(.{ .name = "flong-seccomp", .root_module = root });
    // No stack size in PT_GNU_STACK: the start code then leaves RLIMIT_STACK
    // alone (start.zig:545-578; spike/proofs/p2).
    exe.stack_size = 0;
    return exe;
}

/// The cross build: no libseccomp to name, since nothing is linked.
fn seccompUnlinked(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    const exe = b.addExecutable(.{
        .name = "flong-seccomp",
        .root_module = seccompModule(b, target, optimize, "/nix/store/cross-check-only"),
    });
    exe.stack_size = 0;
    return exe;
}
