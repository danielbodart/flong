//! flong's native code, one package (ZIG.md, "build.zig"). One Nix
//! derivation per install set builds it over only the sources that set
//! imports (native.nix); every other step is a check.
//!
//!   install       -Dset=seccomp (flong-seccomp and its subcommands; needs
//!                 -Dself, the project key's compiler path), launcher
//!                 (flong, whose subcommands are launch, init, sweeper, check and schema;
//!                 needs -Dself, its own installed path, -Dtini, the tini
//!                 flong init execs, and flong launch's -Dbwrap, -Dpasta,
//!                 -Dnewuidmap and -Dnewgidmap) or
//!                 fixtures (the tests' programs, src/fixtures/: bpfdump,
//!                 linked with libc and libseccomp; syscall-probe, swapper
//!                 and ioctl-probe, static and without libc)
//!   test          unit and property tests, Debug, or ReleaseSafe with
//!                 -Drelease=true (as every step); needs -Ddev=true
//!   test-libc     errno.zig and num.zig against glibc, scmp.zig against
//!                 seccomp.h, the fixtures' number readers against glibc's
//!                 (tests/zig/libc_*.zig), and the host's half of `abi`
//!   abi           tests/zig/abi.zig: the kernel structs and constants
//!                 against Zig's bundled headers, x86_64 and aarch64 (run on
//!                 the host's arch); -Dabi-plant=arch|offset plants a
//!                 mismatch, which must fail
//!   compile-fail  what must not compile (tests/zig/compile_fail/)
//!   lint          tools/fdlint.zig over src/ and tests/zig/, and over its
//!                 own planted files (tests/zig/lint/)
//!   fmt           zig fmt --check over the package's Zig
//!   analyze       zwanzig over src/, and over its planted bugs
//!                 (tests/zig/analyze/); needs -Ddev=true
//!   cross         flong-seccomp and bpfdump compiled for aarch64-linux,
//!                 not linked, flong (with dummy paths), syscall-probe,
//!                 swapper and ioctl-probe built for it (in cross/), and
//!                 abi's aarch64 half
//!   integration   the drivers checks.native runs (bin/flong-walker,
//!                 bin/flong-proc), built only by tests/integration.nix
//!   schema        decl-options.json at the package root, rewritten from
//!                 src/decl.zig's fields and their doc comments
//!
//! Every path a step reads is a lazy b.path, so an install set's derivation,
//! which holds build.zig, build.zig.zon and its own sources only, configures
//! (ZIG.md, "Measured": P1, `outside`).
const std = @import("std");

const Set = enum { seccomp, launcher, fixtures };
const AbiPlant = enum { none, arch, offset };

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
    const self = b.option([]const u8, "self", "The set's own installed path: flong-seccomp's store path (seccomp), or flong's (launcher)");
    // flong's compiled-in programs (FLONG_BWRAP and the rest in the C
    // launcher): all six, or the launcher set's install fails.
    const launch_paths = LaunchPaths.read(b, self);
    const abi_plant = b.option(AbiPlant, "abi-plant", "Plant a mismatch in tests/zig/abi.zig: arch, offset") orelse .none;

    // ---- install ----
    const install = b.getInstallStep();
    if (set) |s| switch (s) {
        .seccomp => if (self) |path| {
            b.installArtifact(seccomp(b, target, optimize, path));
        } else {
            install.dependOn(&b.addFail("-Dset=seccomp needs -Dself=PATH, flong-seccomp's own store path").step);
        },
        .launcher => if (launch_paths) |lp| {
            b.installArtifact(flong(b, target, optimize, lp));
        } else {
            install.dependOn(&b.addFail("-Dset=launcher needs -Dself, -Dtini, -Dbwrap, -Dpasta, -Dnewuidmap and -Dnewgidmap, flong's programs").step);
        },
        .fixtures => for (fixtures(b, target, optimize, .linked)) |exe| b.installArtifact(exe),
    } else {
        install.dependOn(&b.addFail("install needs -Dset=seccomp|launcher|fixtures").step);
    }

    // ---- test: unit and property tests ----
    const test_step = b.step("test", "Run the unit and property tests (-Drelease=true for ReleaseSafe)");
    if (!dev) {
        test_step.dependOn(&b.addFail("needs -Ddev=true").step);
    } else if (b.lazyDependency("minish", .{ .target = target, .optimize = optimize })) |minish| {
        // Each module's own tests, with the modules it imports.
        for ([_][]const u8{ "sys", "errno", "msg", "num", "fd", "mount", "sig", "proc", "names", "cgroup", "record" }) |name| {
            const m = modules(b, target, optimize);
            const t = b.addTest(.{ .name = name, .root_module = m.get(name) });
            test_step.dependOn(&b.addRunArtifact(t).step);
        }
        for ([_][]const u8{ "compile", "expand", "render", "project" }) |name| {
            // Each file's own tests, in flong-seccomp's root module, linked
            // as it is.
            const root = seccompModule(b, target, optimize, "/nix/store/test-only");
            root.root_source_file = b.path(b.fmt("src/seccomp/{s}.zig", .{name}));
            root.linkSystemLibrary("seccomp", .{});
            const t = b.addTest(.{ .name = name, .root_module = root });
            test_step.dependOn(&b.addRunArtifact(t).step);
        }
        {
            // fd.zig's model property: the table, a model of it and the
            // kernel's /proc/self/fd agree after any sequence.
            const m = modules(b, target, optimize);
            const t = b.addTest(.{
                .name = "fd_props",
                .root_module = b.createModule(.{
                    .root_source_file = b.path("tests/zig/fd_props.zig"),
                    .target = target,
                    .optimize = optimize,
                    .imports = &.{
                        .{ .name = "minish", .module = minish.module("minish") },
                        .{ .name = "sys", .module = m.sys },
                        .{ .name = "fd", .module = m.fd },
                    },
                }),
            });
            test_step.dependOn(&b.addRunArtifact(t).step);
        }
        {
            // flong init's argv parsing, in its own module.
            const t = b.addTest(.{ .name = "init", .root_module = Launcher.subcommands(b, target, optimize, false, LaunchPaths.dummy("/nix/store/test-only")).init });
            test_step.dependOn(&b.addRunArtifact(t).step);
        }
        {
            // flong init's argv slots, where dispatch hands them over.
            const t = b.addTest(.{
                .name = "init_test",
                .root_module = b.createModule(.{
                    .root_source_file = b.path("tests/zig/init_test.zig"),
                    .target = target,
                    .optimize = optimize,
                    .imports = &.{
                        .{ .name = "init", .module = Launcher.subcommands(b, target, optimize, false, LaunchPaths.dummy("/nix/store/test-only")).init },
                    },
                }),
            });
            test_step.dependOn(&b.addRunArtifact(t).step);
        }
        {
            // flong's dispatch, in its root module.
            const t = b.addTest(.{ .name = "main", .root_module = Launcher.flongModule(b, target, optimize, false, LaunchPaths.dummy("/nix/store/test-only")) });
            test_step.dependOn(&b.addRunArtifact(t).step);
        }
        {
            // proc.zig and sig.zig from outside: fork, Spawn against the
            // spawn probe (flong-proc, built for it), Child, lockWait, the
            // signalfd, and the property over forks and spawns.
            const m = modules(b, target, optimize);
            const opts = b.addOptions();
            opts.addOptionPath("driver", procDriver(b, target, optimize).getEmittedBin());
            const t = b.addTest(.{
                .name = "proc_props",
                .root_module = b.createModule(.{
                    .root_source_file = b.path("tests/zig/proc_props.zig"),
                    .target = target,
                    .optimize = optimize,
                    .imports = &.{
                        .{ .name = "minish", .module = minish.module("minish") },
                        .{ .name = "sys", .module = m.sys },
                        .{ .name = "fd", .module = m.fd },
                        .{ .name = "sig", .module = m.sig },
                        .{ .name = "proc", .module = m.proc },
                        .{ .name = "options", .module = opts.createModule() },
                    },
                }),
            });
            test_step.dependOn(&b.addRunArtifact(t).step);
        }
        {
            // The sweep's readers and the declaration's parser fuzzed, the
            // corpus replayed first.
            const m = modules(b, target, optimize);
            const spec = Launcher.specModule(b, m, target, optimize);
            const d = declModules(b, m, target, optimize, b.path("src/decl.zig"));
            const opts = b.addOptions();
            opts.addOptionPath("corpus", b.path("tests/zig/corpus"));
            const t = b.addTest(.{
                .name = "fuzz",
                .root_module = b.createModule(.{
                    .root_source_file = b.path("tests/zig/fuzz.zig"),
                    .target = target,
                    .optimize = optimize,
                    .imports = &.{
                        .{ .name = "minish", .module = minish.module("minish") },
                        .{ .name = "sys", .module = m.sys },
                        .{ .name = "fd", .module = m.fd },
                        .{ .name = "proc", .module = m.proc },
                        .{ .name = "cgroup", .module = m.cgroup },
                        .{ .name = "record", .module = m.record },
                        .{ .name = "decl", .module = d.decl },
                        .{ .name = "spec", .module = spec },
                        .{ .name = "check", .module = checkModule(b, m, spec, d, target, optimize) },
                        .{ .name = "inputs", .module = inputsModule(b, target, optimize) },
                        .{ .name = "options", .module = opts.createModule() },
                    },
                }),
            });
            test_step.dependOn(&b.addRunArtifact(t).step);
        }
        for ([_][]const u8{ "probe", "swapper", "ioctl_probe" }) |name| {
            // The fixtures' own tests, each in its root module.
            const t = b.addTest(.{ .name = name, .root_module = fixtureModule(b, modules(b, target, optimize), target, optimize, name) });
            test_step.dependOn(&b.addRunArtifact(t).step);
        }
        {
            // flong sweeper's module compiles as a test too.
            const t = b.addTest(.{ .name = "sweeper", .root_module = Launcher.subcommands(b, target, optimize, false, LaunchPaths.dummy("/nix/store/test-only")).sweeper });
            test_step.dependOn(&b.addRunArtifact(t).step);
        }
        {
            // The declaration: decl.zig's parse and load, and the schema
            // decl_docs.zig walks out of it.
            const dm = modules(b, target, optimize);
            const d = declModules(b, dm, target, optimize, b.path("src/decl.zig"));
            test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .name = "decl", .root_module = d.decl })).step);
            test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .name = "decl_docs", .root_module = d.docs })).step);
            // And flong check's judgement of it.
            const cm = checkModule(b, dm, Launcher.specModule(b, dm, target, optimize), d, target, optimize);
            test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .name = "check", .root_module = cm })).step);
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
            .imports = &.{ .{ .name = "sys", .module = m.sys }, .{ .name = "fd", .module = m.fd } },
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

    {
        // The fixtures' number readers against glibc's: ioctl-probe's
        // strtoul0 against the C23 strtoul its C called, bpfdump's atoi
        // against atoi.
        const m = modules(b, target, optimize);
        const t = b.addTest(.{
            .name = "libc_fixtures",
            .root_module = b.createModule(.{
                .root_source_file = b.path("tests/zig/libc_fixtures.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
                .imports = &.{
                    .{ .name = "ioctl_probe", .module = fixtureModule(b, m, target, optimize, "ioctl_probe") },
                    .{ .name = "bpfdump", .module = fixtureModule(b, m, target, optimize, "bpfdump") },
                },
            }),
        });
        libc_step.dependOn(&b.addRunArtifact(t).step);
    }

    // ---- compile-fail: what must not compile, and the compiler's words ----
    const cf_step = b.step("compile-fail", "Check that each file in tests/zig/compile_fail/ fails to compile, and why");
    const cases = [_]struct { file: []const u8, expect: []const u8 }{
        .{ .file = "result_ignored.zig", .expect = "value of type 'sys.Result(usize)' ignored" },
        .{ .file = "result_unwrapped.zig", .expect = "expected type 'usize', found 'sys.Result(usize)'" },
        .{ .file = "msg_arguments.zig", .expect = "msg: \"line {d}: {s}\" takes 2 arguments, given 1" },
        .{ .file = "held_close.zig", .expect = "close on a Held descriptor: it is kept until the process exits" },
        .{ .file = "stdio_close.zig", .expect = "no field or member function named 'close' in 'fd.Stdio'" },
        .{ .file = "read_on_dir.zig", .expect = "read on a dir descriptor" },
        .{ .file = "dir_for_file.zig", .expect = "expected type 'fd.Handle(.file,.owned)', found 'fd.Handle(.dir,.owned)'" },
        .{ .file = "file_as_at.zig", .expect = "a directory handle or fd.cwd, not fd.Handle(.file,.owned)" },
        .{ .file = "setns_wrong_ns.zig", .expect = "setns(.mnt) of a netns descriptor" },
        .{ .file = "setfd_path.zig", .expect = "FsCtx.setFd of a path descriptor: FSCONFIG_SET_FD takes a directory, never O_PATH" },
        .{ .file = "read_on_pipe_w.zig", .expect = "read on a pipe_w descriptor" },
        .{ .file = "dir_as_cgroup.zig", .expect = "expected type '?fd.Handle(.cgroup,.owned)', found 'fd.Handle(.dir,.owned)'" },
        .{ .file = "passfd_stdio.zig", .expect = "passFd of Stdio: 0-2 are the program's stdio, set in Spawn.stdio, not a descriptor to pass" },
        .{ .file = "fork_body_returns.zig", .expect = "expected type 'fn (u8) noreturn', found 'fn (u8) void'" },
    };
    for (cases) |c| {
        // Every module of src/ is on the command line, each with its own
        // imports; the case imports what it needs.
        const run = b.addSystemCommand(&.{ b.graph.zig_exe, "build-obj", "-fno-emit-bin" });
        run.addArgs(&.{ "--dep", "sys", "--dep", "errno", "--dep", "msg", "--dep", "num", "--dep", "fd", "--dep", "sig", "--dep", "proc" });
        run.addPrefixedFileArg("-Mroot=", b.path(b.fmt("tests/zig/compile_fail/{s}", .{c.file})));
        run.addPrefixedFileArg("-Msys=", b.path("src/sys.zig"));
        run.addArgs(&.{ "--dep", "sys" });
        run.addPrefixedFileArg("-Merrno=", b.path("src/errno.zig"));
        run.addArgs(&.{ "--dep", "sys", "--dep", "errno" });
        run.addPrefixedFileArg("-Mmsg=", b.path("src/msg.zig"));
        run.addPrefixedFileArg("-Mnum=", b.path("src/num.zig"));
        run.addArgs(&.{ "--dep", "sys" });
        run.addPrefixedFileArg("-Mfd=", b.path("src/fd.zig"));
        run.addArgs(&.{ "--dep", "sys", "--dep", "fd", "--dep", "msg" });
        run.addPrefixedFileArg("-Msig=", b.path("src/sig.zig"));
        run.addArgs(&.{ "--dep", "sys", "--dep", "fd", "--dep", "msg", "--dep", "sig", "--dep", "num" });
        run.addPrefixedFileArg("-Mproc=", b.path("src/proc.zig"));
        run.addCheck(.{ .expect_stderr_match = c.expect });
        run.addCheck(.{ .expect_term = .{ .Exited = 1 } });
        cf_step.dependOn(&run.step);
    }
    {
        // A declaration field without a doc comment: the harvest of a
        // planted decl.zig, walked by the real decl_docs.zig.
        const planted = b.path("tests/zig/compile_fail/decl_undocumented/decl.zig");
        const run = b.addSystemCommand(&.{ b.graph.zig_exe, "build-obj", "-fno-emit-bin", "--dep", "decl_docs" });
        run.addPrefixedFileArg("-Mroot=", b.path("tests/zig/compile_fail/decl_undocumented.zig"));
        run.addArgs(&.{ "--dep", "decl", "--dep", "decl_field_docs" });
        run.addPrefixedFileArg("-Mdecl_docs=", b.path("src/decl_docs.zig"));
        run.addPrefixedFileArg("-Mdecl=", planted);
        run.addPrefixedFileArg("-Mdecl_field_docs=", declFieldDocs(b, planted));
        run.addCheck(.{ .expect_stderr_match = "declaration field 'shell' has no doc comment. Every field needs one: it is the option's only description." });
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
            "bad.zig:62:16: argv",
        }) |want| run.addCheck(.{ .expect_stdout_match = want });
        run.addCheck(.{ .expect_term = .{ .Exited = 1 } });
        lint_step.dependOn(&run.step);
    }
    {
        // And nothing in good.zig, linted as the file that may export.
        const run = b.addRunArtifact(fdlint);
        run.addArgs(&.{ "--as", "src/seccomp/scmp.zig" });
        run.addFileArg(b.path("tests/zig/lint/good.zig"));
        run.addCheck(.{ .expect_stdout_exact = "" });
        run.addCheck(.{ .expect_term = .{ .Exited = 0 } });
        lint_step.dependOn(&run.step);
    }

    // ---- fmt ----
    // With no paths, addFmt runs a bare `zig fmt --check`, which exits 1
    // (Build/Step/Fmt.zig:16).
    const fmt_step = b.step("fmt", "Check the formatting of the package's Zig");
    fmt_step.dependOn(&b.addFmt(.{ .check = true, .paths = &.{ "build.zig", "build.zig.zon", "build", "src", "tests/zig", "tools" } }).step);

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
                "bugs.zig:19:12: error: [store-violations-engine] double-close", // B1
                "bugs.zig:27:9: error: [store-violations-engine] use after close", // B2
                "bugs.zig:34:12: error: [store-violations-engine] use after close", // B3
                "bugs.zig:57:12: error: [store-violations-engine] double-close", // B6
                "bugs.zig:64:14: error: [store-violations-engine] double-close", // B7
                "bugs.zig:72:12: error: [store-violations-engine] double-close", // B8
                "bugs.zig:79:9: error: [store-violations-engine] use after close", // B9, the rename
                "bugs.zig:79:28: error: [store-violations-engine] use after close", // B9, its target
                "bugs.zig:86:46: error: [store-violations-engine] double-close", // B10
                "bugs.zig:95:18: error: [store-violations-engine] double-close", // B11
                "bugs.zig:149:15: error: [store-violations-engine] double-close", // B12, walkOpen
                "bugs.zig:156:9: error: [store-violations-engine] use after close", // B13, openTree
                "bugs.zig:163:9: error: [store-violations-engine] use after close", // B14, fsopen
                "bugs.zig:172:12: error: [store-violations-engine] double-close", // B15, openExact
                "bugs.zig:190:13: error: [store-violations-engine] double-close", // B16, openCgroup
                "bugs.zig:197:9: error: [store-violations-engine] use after close", // B17, inotifyInit
                "bugs.zig:204:9: error: [store-violations-engine] use after close", // B18, pidfdOpen
                "bugs.zig:211:12: error: [store-violations-engine] double-close", // B19, openDirNoFollow
                "bugs.zig:232:14: error: [store-violations-engine] double-close", // B20, fork
                "bugs.zig:239:9: error: [store-violations-engine] use after close", // B21, start
                "bugs.zig:246:9: error: [store-violations-engine] use after close", // B22, openSignalfd
                "bugs.zig:254:14: error: [store-violations-engine] double-close", // B23, pipe
                "bugs.zig:263:12: error: [store-violations-engine] double-close", // B24, openPtmx
                "bugs.zig:270:9: error: [store-violations-engine] use after close", // B25, openSlave
                "bugs.zig:277:9: error: [store-violations-engine] use after close", // B26, reopenOut
                "bugs.zig:304:20: error: [store-violations-engine] double-close", // B27, bwrap.spawn's Child
                "bugs.zig:311:19: error: [store-violations-engine] double-close", // B28, its gate
            }) |want| run.addCheck(.{ .expect_stdout_match = want });
            // And those twenty-seven only: the ok* controls stay quiet.
            run.addCheck(.{ .expect_stdout_match = "Found 27 issue(s):\n" });
            run.addCheck(.{ .expect_term = .{ .Exited = 1 } });
            analyze_step.dependOn(&run.step);
        }
    }

    // ---- schema: decl-options.json ----
    // build/schema.zig, for the host, prints decl_docs.writeSchema, and its
    // output replaces the checked-in file.
    const schema_step = b.step("schema", "Write decl-options.json from src/decl.zig");
    {
        const d = declModules(b, modules(b, b.graph.host, .Debug), b.graph.host, .Debug, b.path("src/decl.zig"));
        const exe = b.addExecutable(.{
            .name = "flong-schema",
            .root_module = b.createModule(.{
                .root_source_file = b.path("build/schema.zig"),
                .target = b.graph.host,
                .optimize = .Debug,
                .imports = &.{.{ .name = "decl_docs", .module = d.docs }},
            }),
        });
        const update = b.addUpdateSourceFiles();
        update.addCopyFileToSource(b.addRunArtifact(exe).captureStdOut(), "decl-options.json");
        schema_step.dependOn(&update.step);
    }

    // ---- integration: the drivers checks.native runs ----
    const integration_step = b.step("integration", "Build the drivers checks.native runs: bin/flong-walker, bin/flong-proc");
    integration_step.dependOn(&b.addInstallArtifact(walker(b, target, optimize), .{}).step);
    integration_step.dependOn(&b.addInstallArtifact(procDriver(b, target, optimize), .{}).step);

    // ---- cross: aarch64 ----
    // flong-seccomp for aarch64-linux, analysed and compiled but not linked
    // (-fno-emit-bin: nothing asks for the binary): the flake has no aarch64
    // libseccomp to link against on x86_64 (ZIG.md, "The Nix build").
    const cross_step = b.step("cross", "Compile flong-seccomp for aarch64-linux, without linking, and abi's aarch64 half");
    const arm = b.resolveTargetQuery(.{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .gnu });
    cross_step.dependOn(&seccompUnlinked(b, arm, optimize).step);
    {
        // flong links no libc, so it is built whole, with dummy paths;
        // native.nix's cross-aarch64 reads its ELF header.
        const arm_flong = b.addInstallArtifact(flong(b, arm, optimize, LaunchPaths.dummy("/nix/store/cross-check-only")), .{
            .dest_dir = .{ .override = .{ .custom = "cross" } },
        });
        cross_step.dependOn(&arm_flong.step);
        // The fixtures: the three without libc built whole; bpfdump, which
        // needs libseccomp, compiled and not linked, as flong-seccomp.
        for (fixtures(b, arm, optimize, .unlinked)) |exe| {
            if (exe.root_module.link_libc == true) {
                cross_step.dependOn(&exe.step);
            } else {
                cross_step.dependOn(&b.addInstallArtifact(exe, .{ .dest_dir = .{ .override = .{ .custom = "cross" } } }).step);
            }
        }
    }

    // ---- abi: the kernel ABI against Zig's bundled headers ----
    const abi_step = b.step("abi", "Check tests/zig/abi.zig against Zig's bundled headers, x86_64 and aarch64");
    for ([_]std.Target.Cpu.Arch{ .x86_64, .aarch64 }) |arch| {
        // musl: an explicit libc target, so translate-c's include path is
        // Zig's own lib/libc/include (<arch>-linux-musl, generic-musl,
        // <arch>-linux-any, any-linux-any), never the host's or
        // NIX_CFLAGS_COMPILE's, which Zig reads for a native target only.
        // Only the headers are used: the test links no libc
        // (P4's build.zig, now in ~/Projects/flong-spikes-archive/zig).
        const t = b.resolveTargetQuery(.{ .cpu_arch = arch, .os_tag = .linux, .abi = .musl });
        const headers = b.addTranslateC(.{
            .root_source_file = b.path("tests/zig/abi.h"),
            .target = t,
            .optimize = optimize,
        });
        const opts = b.addOptions();
        opts.addOption(AbiPlant, "plant", abi_plant);
        const tests = b.addTest(.{
            .name = b.fmt("abi-{s}", .{@tagName(arch)}),
            .root_module = b.createModule(.{
                .root_source_file = b.path("tests/zig/abi.zig"),
                .target = t,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "sys", .module = b.createModule(.{ .root_source_file = b.path("src/sys.zig"), .target = t, .optimize = optimize }) },
                    .{ .name = "c", .module = headers.createModule() },
                    .{ .name = "options", .module = opts.createModule() },
                },
            }),
        });
        // Every check is comptime, so compiling is the check; the host's
        // arch also runs, printing what was compared.
        if (arch == b.graph.host.result.cpu.arch) {
            const run = b.addRunArtifact(tests);
            abi_step.dependOn(&run.step);
            libc_step.dependOn(&run.step);
        } else {
            abi_step.dependOn(&tests.step);
        }
        if (arch == .aarch64) cross_step.dependOn(&tests.step);
    }

    // ---- launcher (phase 7) ----
    // Phase 7's milestones, on trunk (ZIG.md, "How it runs"). L4 builds the
    // Zig flong-launch into the launcher set (src/launch.zig composing
    // src/launch/'s pieces, spec, ns, cgroup, record, tty and mount; the
    // modules are file-scope `Launcher` and `Terminal`, below); L5 deleted
    // the C launcher; S1 made it flong launch, a subcommand of bin/flong
    // (installed above). The steps of this block:
    //
    //   test           (-Ddev=true) spec.zig's and launch.zig's own tests,
    //                  and tests/zig/spec_test.zig: bwrapArgv's golden argv
    //                  per branch, the model property, each single-rule
    //                  mutation; ns.zig's and passwd.zig's own tests,
    //                  cgroup.zig's and record.zig's in the launch's graph
    //                  (`Launcher.launchModules`, whose cgroup imports proc
    //                  and passwd); src/launch/childpid.zig's own tests and
    //                  tests/zig/childpid_test.zig (the info loop over any
    //                  chunking, the 4095-byte bound, each refusal, the fuzz
    //                  and its corpus, tests/zig/corpus/launch-childpid/);
    //                  tests/zig/prologue_test.zig, against the spawn probe
    //                  (flong-proc) for relaunch's exec;
    //                  tests/zig/bwrap_test.zig (bwrap.spawn against
    //                  flong-fake-bwrap, tests/zig/fakebwrap.zig: its argv
    //                  per branch, what it holds, checkpoint 2's list;
    //                  sig.awaitFdOrExit); tests/zig/pasta_hook_test.zig
    //                  (the hook's and pasta's Spawns against golden tables
    //                  read from flong-launch.c:586-675); S3's
    //                  src/launch/depth.zig, hometmp.zig and resolv.zig,
    //                  each its own tests
    //   analyze        (-Ddev=true) B27 and B28 in tests/zig/analyze/
    //                  bugs.zig, bwrap.spawn's planted bugs
    //   test-launch    tests/zig/launch_test.zig: the record writer against
    //                  tests/golden/records/, the name taken, the cache
    //                  lock, the session made and undone; run only by
    //                  tests/integration.nix, whose fileset holds the
    //                  golden records
    //   test-libc      tests/zig/libc_launch.zig: sys.O_TMPFILE against
    //                  glibc's fcntl.h; tests/zig/libc_hookenv.zig:
    //                  hook.env against glibc's setenv
    //   launch-driver  bin/flong-launch-driver (tests/zig/launchdriver.zig),
    //                  built only by tests/integration.nix, for checks.native
    {
        if (dev) {
            const m = modules(b, target, optimize);
            const sm = Launcher.specModule(b, m, target, optimize);
            const t = b.addTest(.{
                .name = "pasta_hook_test",
                .root_module = b.createModule(.{
                    .root_source_file = b.path("tests/zig/pasta_hook_test.zig"),
                    .target = target,
                    .optimize = optimize,
                    .imports = &.{
                        .{ .name = "sys", .module = m.sys },
                        .{ .name = "fd", .module = m.fd },
                        .{ .name = "msg", .module = m.msg },
                        .{ .name = "proc", .module = m.proc },
                        .{ .name = "spec", .module = sm },
                        .{ .name = "hook", .module = Launcher.pieceModule(b, m, sm, "hook", target, optimize) },
                        .{ .name = "pasta", .module = Launcher.pieceModule(b, m, sm, "pasta", target, optimize) },
                    },
                }),
            });
            test_step.dependOn(&b.addRunArtifact(t).step);
        }
        {
            const m = modules(b, target, optimize);
            const sm = Launcher.specModule(b, m, target, optimize);
            const t = b.addTest(.{
                .name = "libc_hookenv",
                .root_module = b.createModule(.{
                    .root_source_file = b.path("tests/zig/libc_hookenv.zig"),
                    .target = target,
                    .optimize = optimize,
                    .link_libc = true,
                    .imports = &.{
                        .{ .name = "sys", .module = m.sys },
                        .{ .name = "fd", .module = m.fd },
                        .{ .name = "hook", .module = Launcher.pieceModule(b, m, sm, "hook", target, optimize) },
                    },
                }),
            });
            libc_step.dependOn(&b.addRunArtifact(t).step);
        }

        if (dev) {
            {
                // The prologue's pieces, each in a forked child where it
                // would touch the test's own descriptors, signals or stderr.
                const l = Launcher.launchModules(b, target, optimize);
                const m = l.m;
                const opts = b.addOptions();
                opts.addOptionPath("driver", procDriver(b, target, optimize).getEmittedBin());
                const t = b.addTest(.{
                    .name = "prologue_test",
                    .root_module = b.createModule(.{
                        .root_source_file = b.path("tests/zig/prologue_test.zig"),
                        .target = target,
                        .optimize = optimize,
                        .imports = &.{
                            .{ .name = "sys", .module = m.sys },
                            .{ .name = "fd", .module = m.fd },
                            .{ .name = "msg", .module = m.msg },
                            .{ .name = "sig", .module = m.sig },
                            .{ .name = "proc", .module = m.proc },
                            .{ .name = "prologue", .module = Launcher.prologueModule(b, l, target, optimize) },
                            .{ .name = "options", .module = opts.createModule() },
                        },
                    }),
                });
                test_step.dependOn(&b.addRunArtifact(t).step);
            }
            // S3: `flong launch`'s pure pieces, each with its own tests;
            // they import std alone.
            for ([_][]const u8{ "depth", "hometmp", "resolv" }) |name| {
                const t = b.addTest(.{
                    .name = b.fmt("launch_{s}", .{name}),
                    .root_module = b.createModule(.{
                        .root_source_file = b.path(b.fmt("src/launch/{s}.zig", .{name})),
                        .target = target,
                        .optimize = optimize,
                    }),
                });
                test_step.dependOn(&b.addRunArtifact(t).step);
            }
            if (b.lazyDependency("minish", .{ .target = target, .optimize = optimize })) |minish| {
                {
                    const m = modules(b, target, optimize);
                    const t = b.addTest(.{ .name = "spec", .root_module = Launcher.specModule(b, m, target, optimize) });
                    test_step.dependOn(&b.addRunArtifact(t).step);
                }
                {
                    const t = b.addTest(.{ .name = "launch", .root_module = Launcher.subcommands(b, target, optimize, false, LaunchPaths.dummy("/nix/store/test-only")).launch });
                    test_step.dependOn(&b.addRunArtifact(t).step);
                }
                {
                    // launch/bwrap.zig and sig.awaitFdOrExit, over one set
                    // of modules, so the test and the piece share fd's table.
                    const m = modules(b, target, optimize);
                    const spec_module = Launcher.specModule(b, m, target, optimize);
                    const opts = b.addOptions();
                    opts.addOptionPath("fake_bwrap", Launcher.fakeBwrap(b, target, optimize).getEmittedBin());
                    const t = b.addTest(.{
                        .name = "bwrap_test",
                        .root_module = b.createModule(.{
                            .root_source_file = b.path("tests/zig/bwrap_test.zig"),
                            .target = target,
                            .optimize = optimize,
                            .imports = &.{
                                .{ .name = "sys", .module = m.sys },
                                .{ .name = "fd", .module = m.fd },
                                .{ .name = "msg", .module = m.msg },
                                .{ .name = "sig", .module = m.sig },
                                .{ .name = "proc", .module = m.proc },
                                .{ .name = "spec", .module = spec_module },
                                .{ .name = "bwrap", .module = Launcher.bwrapModule(b, m, spec_module, target, optimize) },
                                .{ .name = "options", .module = opts.createModule() },
                            },
                        }),
                    });
                    test_step.dependOn(&b.addRunArtifact(t).step);
                }
                {
                    const m = modules(b, target, optimize);
                    const t = b.addTest(.{ .name = "childpid", .root_module = Launcher.childpidModule(b, m, target, optimize) });
                    test_step.dependOn(&b.addRunArtifact(t).step);
                }
                {
                    // The info loop driven from outside, and fuzzed, its
                    // corpus replayed first.
                    const m = modules(b, target, optimize);
                    const opts = b.addOptions();
                    opts.addOptionPath("corpus", b.path("tests/zig/corpus"));
                    const t = b.addTest(.{
                        .name = "childpid_test",
                        .root_module = b.createModule(.{
                            .root_source_file = b.path("tests/zig/childpid_test.zig"),
                            .target = target,
                            .optimize = optimize,
                            .imports = &.{
                                .{ .name = "minish", .module = minish.module("minish") },
                                .{ .name = "sys", .module = m.sys },
                                .{ .name = "msg", .module = m.msg },
                                .{ .name = "sig", .module = m.sig },
                                .{ .name = "childpid", .module = Launcher.childpidModule(b, m, target, optimize) },
                                .{ .name = "options", .module = opts.createModule() },
                            },
                        }),
                    });
                    test_step.dependOn(&b.addRunArtifact(t).step);
                }
                if (Launcher.storeDir(b)) |dir| {
                    const m = modules(b, target, optimize);
                    const opts = b.addOptions();
                    opts.addOption([]const u8, "store", dir);
                    const t = b.addTest(.{
                        .name = "spec_test",
                        .root_module = b.createModule(.{
                            .root_source_file = b.path("tests/zig/spec_test.zig"),
                            .target = target,
                            .optimize = optimize,
                            .imports = &.{
                                .{ .name = "minish", .module = minish.module("minish") },
                                .{ .name = "sys", .module = m.sys },
                                .{ .name = "fd", .module = m.fd },
                                .{ .name = "msg", .module = m.msg },
                                .{ .name = "mount", .module = m.mount },
                                .{ .name = "spec", .module = Launcher.specModule(b, m, target, optimize) },
                                .{ .name = "options", .module = opts.createModule() },
                            },
                        }),
                    });
                    test_step.dependOn(&b.addRunArtifact(t).step);
                } else {
                    test_step.dependOn(&b.addFail("tests/zig/spec_test.zig needs a zig in /nix/store: its closure is a store path").step);
                }
                // L2: each launch module's own tests, in the launch's graph.
                for ([_][]const u8{ "passwd", "cgroup", "record", "ns" }) |name| {
                    const l = Launcher.launchModules(b, target, optimize);
                    const module = if (std.mem.eql(u8, name, "passwd")) l.passwd else if (std.mem.eql(u8, name, "cgroup")) l.cgroup else if (std.mem.eql(u8, name, "record")) l.record else l.ns;
                    const t = b.addTest(.{ .name = b.fmt("launch_{s}", .{name}), .root_module = module });
                    test_step.dependOn(&b.addRunArtifact(t).step);
                }
            }
        }

        {
            // L2's test-libc: sys.O_TMPFILE against glibc's fcntl.h, through
            // translate-c, the header found as tests/zig/scmp.h's is.
            const l = Launcher.launchModules(b, target, optimize);
            const header = b.addTranslateC(.{
                .root_source_file = b.path("tests/zig/fcntl.h"),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            });
            if (target.query.isNativeOs() and target.query.isNativeAbi()) {
                const paths = std.zig.system.NativePaths.detect(b.allocator, &target.result) catch @panic("OOM");
                for (paths.include_dirs.items) |dir| header.addSystemIncludePath(.{ .cwd_relative = dir });
            }
            const root = b.createModule(.{
                .root_source_file = b.path("tests/zig/libc_launch.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
                .imports = &.{
                    .{ .name = "sys", .module = l.m.sys },
                    .{ .name = "fcntl_h", .module = header.createModule() },
                },
            });
            libc_step.dependOn(&b.addRunArtifact(b.addTest(.{ .name = "libc_launch", .root_module = root })).step);
        }

        const launch_step = b.step("test-launch", "Run tests/zig/launch_test.zig: the record writer against tests/golden/records/, and the launch's halves");
        {
            // Outside `test`: tests/golden/records/ is not in native-test's
            // fileset (native.nix is trunk's until L4), so
            // tests/integration.nix runs it. It needs no lazy dependency.
            const l = Launcher.launchModules(b, target, optimize);
            const opts = b.addOptions();
            opts.addOptionPath("records", b.path("tests/golden/records"));
            const t = b.addTest(.{
                .name = "launch_test",
                .root_module = b.createModule(.{
                    .root_source_file = b.path("tests/zig/launch_test.zig"),
                    .target = target,
                    .optimize = optimize,
                    .imports = &.{
                        .{ .name = "sys", .module = l.m.sys },
                        .{ .name = "fd", .module = l.m.fd },
                        .{ .name = "msg", .module = l.m.msg },
                        .{ .name = "proc", .module = l.m.proc },
                        .{ .name = "cgroup", .module = l.cgroup },
                        .{ .name = "record", .module = l.record },
                        .{ .name = "options", .module = opts.createModule() },
                    },
                }),
            });
            launch_step.dependOn(&b.addRunArtifact(t).step);
        }

        const driver_step = b.step("launch-driver", "Build bin/flong-launch-driver, the launch's halves for checks.native");
        driver_step.dependOn(&b.addInstallArtifact(Launcher.launchDriver(b, target, optimize), .{}).step);
    }
    // L3, the terminal: src/tty.zig (built into the launcher since L4).
    //
    //   test         (-Ddev=true) tty.zig's own tests, and
    //                tests/zig/tty_test.zig: the pty path, the ^] detector's
    //                property over any chunking
    //   test-libc    sys.cfmakeraw against glibc's (tests/zig/libc_tty.zig)
    //   integration  bin/flong-tty (tests/zig/ttydriver.zig), checks.native's
    //                pty driver
    // The terminal's minting functions' planted bugs are B24-B26 in
    // tests/zig/analyze/bugs.zig, checked by analyze above.
    {
        if (dev) {
            if (b.lazyDependency("minish", .{ .target = target, .optimize = optimize })) |minish| {
                {
                    const m = modules(b, target, optimize);
                    const t = b.addTest(.{ .name = "tty", .root_module = Terminal.module(b, m, target, optimize) });
                    test_step.dependOn(&b.addRunArtifact(t).step);
                }
                {
                    const m = modules(b, target, optimize);
                    const t = b.addTest(.{
                        .name = "tty_test",
                        .root_module = b.createModule(.{
                            .root_source_file = b.path("tests/zig/tty_test.zig"),
                            .target = target,
                            .optimize = optimize,
                            .imports = &.{
                                .{ .name = "minish", .module = minish.module("minish") },
                                .{ .name = "sys", .module = m.sys },
                                .{ .name = "fd", .module = m.fd },
                                .{ .name = "proc", .module = m.proc },
                                .{ .name = "tty", .module = Terminal.module(b, m, target, optimize) },
                            },
                        }),
                    });
                    test_step.dependOn(&b.addRunArtifact(t).step);
                }
            }
        }

        {
            // glibc's struct termios and cfmakeraw through translate-c, the
            // header found as tests/zig/scmp.h's is.
            const m = modules(b, target, optimize);
            const header = b.addTranslateC(.{
                .root_source_file = b.path("tests/zig/termios.h"),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            });
            if (target.query.isNativeOs() and target.query.isNativeAbi()) {
                const paths = std.zig.system.NativePaths.detect(b.allocator, &target.result) catch @panic("OOM");
                for (paths.include_dirs.items) |dir| header.addSystemIncludePath(.{ .cwd_relative = dir });
            }
            const t = b.addTest(.{
                .name = "libc_tty",
                .root_module = b.createModule(.{
                    .root_source_file = b.path("tests/zig/libc_tty.zig"),
                    .target = target,
                    .optimize = optimize,
                    .link_libc = true,
                    .imports = &.{
                        .{ .name = "sys", .module = m.sys },
                        .{ .name = "termios_h", .module = header.createModule() },
                    },
                }),
            });
            libc_step.dependOn(&b.addRunArtifact(t).step);
        }

        {
            // flong-tty: static, no libc, stripped, no stack size in
            // PT_GNU_STACK, as an installed artifact.
            const m = modules(b, target, optimize);
            const exe = b.addExecutable(.{
                .name = "flong-tty",
                .root_module = b.createModule(.{
                    .root_source_file = b.path("tests/zig/ttydriver.zig"),
                    .target = target,
                    .optimize = optimize,
                    .strip = true,
                    .single_threaded = true,
                    .imports = &.{
                        .{ .name = "sys", .module = m.sys },
                        .{ .name = "fd", .module = m.fd },
                        .{ .name = "msg", .module = m.msg },
                        .{ .name = "sig", .module = m.sig },
                        .{ .name = "proc", .module = m.proc },
                        .{ .name = "tty", .module = Terminal.module(b, m, target, optimize) },
                    },
                }),
            });
            exe.stack_size = 0;
            integration_step.dependOn(&b.addInstallArtifact(exe, .{}).step);
        }
    }
    // ---- end of launcher (phase 7) ----
}

// ---- launcher (phase 7): the modules of flong launch's graph ----

const Launcher = struct {
    /// src/spec.zig over `m`'s modules.
    fn specModule(bb: *std.Build, m: Modules, t: std.Build.ResolvedTarget, o: std.builtin.OptimizeMode) *std.Build.Module {
        return bb.createModule(.{
            .root_source_file = bb.path("src/spec.zig"),
            .target = t,
            .optimize = o,
            .imports = &.{
                .{ .name = "sys", .module = m.sys },
                .{ .name = "fd", .module = m.fd },
                .{ .name = "msg", .module = m.msg },
                .{ .name = "proc", .module = m.proc },
                .{ .name = "names", .module = m.names },
                .{ .name = "mount", .module = m.mount },
            },
        });
    }

    /// The subcommands' modules (src/launch.zig, src/init.zig,
    /// src/sweeper.zig), no libc, over one launch graph
    /// (`launchModules`), so every module shares fd's one table and
    /// msg's prog: flong launch's with tty and src/launch/'s pieces, and
    /// one `config` for all three, the compiled-in programs and the
    /// version. Each is a test's root as well as src/main.zig's import.
    /// Stripped for an installed artifact; a test's is not (a stripped
    /// module in an unstripped Debug test crashes the compiler).
    const Subcommands = struct {
        l: Launch,
        launch: *std.Build.Module,
        init: *std.Build.Module,
        sweeper: *std.Build.Module,
        config: *std.Build.Module,
    };

    fn subcommands(bb: *std.Build, t: std.Build.ResolvedTarget, o: std.builtin.OptimizeMode, strip: bool, lp: LaunchPaths) Subcommands {
        const l = launchModules(bb, t, o);
        const m = l.m;
        const options = bb.addOptions();
        inline for (@typeInfo(LaunchPaths).@"struct".fields) |f| options.addOption([]const u8, f.name, @field(lp, f.name));
        options.addOption([]const u8, "version", @import("build.zig.zon").version);
        const config = options.createModule();
        const launch = bb.createModule(.{
            .root_source_file = bb.path("src/launch.zig"),
            .target = t,
            .optimize = o,
            .strip = strip,
            .single_threaded = true,
            .imports = &.{
                .{ .name = "sys", .module = m.sys },
                .{ .name = "fd", .module = m.fd },
                .{ .name = "msg", .module = m.msg },
                .{ .name = "sig", .module = m.sig },
                .{ .name = "proc", .module = m.proc },
                .{ .name = "mount", .module = m.mount },
                .{ .name = "spec", .module = l.spec },
                .{ .name = "ns", .module = l.ns },
                .{ .name = "cgroup", .module = l.cgroup },
                .{ .name = "record", .module = l.record },
                .{ .name = "tty", .module = Terminal.module(bb, m, t, o) },
                .{ .name = "prologue", .module = prologueModule(bb, l, t, o) },
                .{ .name = "bwrap", .module = bwrapModule(bb, m, l.spec, t, o) },
                .{ .name = "childpid", .module = childpidModule(bb, m, t, o) },
                .{ .name = "hook", .module = pieceModule(bb, m, l.spec, "hook", t, o) },
                .{ .name = "pasta", .module = pieceModule(bb, m, l.spec, "pasta", t, o) },
                .{ .name = "config", .module = config },
            },
        });
        // flong init: sys, msg and tini's path compiled in
        // (flong-init.c:52-54).
        const init = bb.createModule(.{
            .root_source_file = bb.path("src/init.zig"),
            .target = t,
            .optimize = o,
            .strip = strip,
            .single_threaded = true,
            .imports = &.{
                .{ .name = "sys", .module = m.sys },
                .{ .name = "msg", .module = m.msg },
                .{ .name = "config", .module = config },
            },
        });
        // flong sweeper: record, cgroup, proc, sig, msg.
        const sweeper = bb.createModule(.{
            .root_source_file = bb.path("src/sweeper.zig"),
            .target = t,
            .optimize = o,
            .strip = strip,
            .single_threaded = true,
            .imports = &.{
                .{ .name = "msg", .module = m.msg },
                .{ .name = "sig", .module = m.sig },
                .{ .name = "proc", .module = m.proc },
                .{ .name = "record", .module = l.record },
                .{ .name = "cgroup", .module = l.cgroup },
            },
        });
        return .{ .l = l, .launch = launch, .init = init, .sweeper = sweeper, .config = config };
    }

    /// flong's root module (src/main.zig): the dispatch over the
    /// subcommands' modules; the settings every installed artifact has
    /// (DESIGN.md, "Conventions": start code).
    fn flongModule(bb: *std.Build, t: std.Build.ResolvedTarget, o: std.builtin.OptimizeMode, strip: bool, lp: LaunchPaths) *std.Build.Module {
        const sc = subcommands(bb, t, o, strip, lp);
        // flong check and flong schema: the declaration over the same
        // graph, so decl.zig's messages take flong check's prefix.
        const d = declModules(bb, sc.l.m, t, o, bb.path("src/decl.zig"));
        return bb.createModule(.{
            .root_source_file = bb.path("src/main.zig"),
            .target = t,
            .optimize = o,
            .strip = strip,
            .single_threaded = true,
            .imports = &.{
                .{ .name = "sys", .module = sc.l.m.sys },
                .{ .name = "msg", .module = sc.l.m.msg },
                .{ .name = "launch", .module = sc.launch },
                .{ .name = "init", .module = sc.init },
                .{ .name = "sweeper", .module = sc.sweeper },
                .{ .name = "check", .module = checkModule(bb, sc.l.m, sc.l.spec, d, t, o) },
                .{ .name = "decl_docs", .module = d.docs },
                .{ .name = "config", .module = sc.config },
            },
        });
    }

    /// The launch's modules: trunk's `modules`, and passwd, cgroup
    /// and record again with the launch's imports (cgroup's launch
    /// half needs proc and passwd), spec and ns. A compilation
    /// takes cgroup and record from here only, never from `m`.
    const Launch = struct {
        m: Modules,
        passwd: *std.Build.Module,
        cgroup: *std.Build.Module,
        record: *std.Build.Module,
        spec: *std.Build.Module,
        ns: *std.Build.Module,
    };

    fn launchModules(bb: *std.Build, t: std.Build.ResolvedTarget, o: std.builtin.OptimizeMode) Launch {
        const m = modules(bb, t, o);
        const passwd = bb.createModule(.{
            .root_source_file = bb.path("src/passwd.zig"),
            .target = t,
            .optimize = o,
            .imports = &.{.{ .name = "fd", .module = m.fd }},
        });
        const cgroup = bb.createModule(.{
            .root_source_file = bb.path("src/cgroup.zig"),
            .target = t,
            .optimize = o,
            .imports = &.{
                .{ .name = "sys", .module = m.sys },
                .{ .name = "fd", .module = m.fd },
                .{ .name = "msg", .module = m.msg },
                .{ .name = "sig", .module = m.sig },
                .{ .name = "names", .module = m.names },
                .{ .name = "proc", .module = m.proc },
                .{ .name = "passwd", .module = passwd },
            },
        });
        const record = bb.createModule(.{
            .root_source_file = bb.path("src/record.zig"),
            .target = t,
            .optimize = o,
            .imports = &.{
                .{ .name = "sys", .module = m.sys },
                .{ .name = "fd", .module = m.fd },
                .{ .name = "msg", .module = m.msg },
                .{ .name = "sig", .module = m.sig },
                .{ .name = "num", .module = m.num },
                .{ .name = "proc", .module = m.proc },
                .{ .name = "names", .module = m.names },
                .{ .name = "cgroup", .module = cgroup },
            },
        });
        const spec = specModule(bb, m, t, o);
        const ns = bb.createModule(.{
            .root_source_file = bb.path("src/ns.zig"),
            .target = t,
            .optimize = o,
            .imports = &.{
                .{ .name = "sys", .module = m.sys },
                .{ .name = "fd", .module = m.fd },
                .{ .name = "msg", .module = m.msg },
                .{ .name = "sig", .module = m.sig },
                .{ .name = "proc", .module = m.proc },
                .{ .name = "spec", .module = spec },
            },
        });
        return .{ .m = m, .passwd = passwd, .cgroup = cgroup, .record = record, .spec = spec, .ns = ns };
    }

    /// flong-launch-driver (tests/zig/launchdriver.zig): the
    /// launch's halves driven from a shell in checks.native. Static,
    /// no libc, stripped, no stack size, as an installed artifact.
    fn launchDriver(bb: *std.Build, t: std.Build.ResolvedTarget, o: std.builtin.OptimizeMode) *std.Build.Step.Compile {
        const l = launchModules(bb, t, o);
        const exe = bb.addExecutable(.{
            .name = "flong-launch-driver",
            .root_module = bb.createModule(.{
                .root_source_file = bb.path("tests/zig/launchdriver.zig"),
                .target = t,
                .optimize = o,
                .strip = true,
                .single_threaded = true,
                .imports = &.{
                    .{ .name = "sys", .module = l.m.sys },
                    .{ .name = "fd", .module = l.m.fd },
                    .{ .name = "msg", .module = l.m.msg },
                    .{ .name = "sig", .module = l.m.sig },
                    .{ .name = "proc", .module = l.m.proc },
                    .{ .name = "spec", .module = l.spec },
                    .{ .name = "ns", .module = l.ns },
                    .{ .name = "cgroup", .module = l.cgroup },
                    .{ .name = "record", .module = l.record },
                    .{ .name = "passwd", .module = l.passwd },
                },
            }),
        });
        exe.stack_size = 0;
        return exe;
    }

    /// src/launch/childpid.zig (step 13, bwrap's child-pid) over
    /// `m`'s modules.
    fn childpidModule(bb: *std.Build, m: Modules, t: std.Build.ResolvedTarget, o: std.builtin.OptimizeMode) *std.Build.Module {
        return bb.createModule(.{
            .root_source_file = bb.path("src/launch/childpid.zig"),
            .target = t,
            .optimize = o,
            .imports = &.{
                .{ .name = "sys", .module = m.sys },
                .{ .name = "msg", .module = m.msg },
                .{ .name = "sig", .module = m.sig },
            },
        });
    }

    /// src/launch/prologue.zig over the launch's modules (record
    /// from `l`, as launchModules requires): checkpoint 1's pieces
    /// (L4).
    fn prologueModule(bb: *std.Build, l: Launch, t: std.Build.ResolvedTarget, o: std.builtin.OptimizeMode) *std.Build.Module {
        const m = l.m;
        return bb.createModule(.{
            .root_source_file = bb.path("src/launch/prologue.zig"),
            .target = t,
            .optimize = o,
            .imports = &.{
                .{ .name = "sys", .module = m.sys },
                .{ .name = "fd", .module = m.fd },
                .{ .name = "msg", .module = m.msg },
                .{ .name = "sig", .module = m.sig },
                .{ .name = "proc", .module = m.proc },
                .{ .name = "record", .module = l.record },
            },
        });
    }

    /// src/launch/bwrap.zig over `m`'s modules and `spec`.
    fn bwrapModule(bb: *std.Build, m: Modules, spec: *std.Build.Module, t: std.Build.ResolvedTarget, o: std.builtin.OptimizeMode) *std.Build.Module {
        return bb.createModule(.{
            .root_source_file = bb.path("src/launch/bwrap.zig"),
            .target = t,
            .optimize = o,
            .imports = &.{
                .{ .name = "fd", .module = m.fd },
                .{ .name = "msg", .module = m.msg },
                .{ .name = "proc", .module = m.proc },
                .{ .name = "spec", .module = spec },
            },
        });
    }

    /// flong-fake-bwrap (tests/zig/fakebwrap.zig): bwrap's stand-in
    /// for bwrap_test. Static, no libc, stripped.
    fn fakeBwrap(bb: *std.Build, t: std.Build.ResolvedTarget, o: std.builtin.OptimizeMode) *std.Build.Step.Compile {
        const exe = bb.addExecutable(.{
            .name = "flong-fake-bwrap",
            .root_module = bb.createModule(.{
                .root_source_file = bb.path("tests/zig/fakebwrap.zig"),
                .target = t,
                .optimize = o,
                .strip = true,
                .single_threaded = true,
            }),
        });
        exe.stack_size = 0;
        return exe;
    }

    /// One of L4's pieces, src/launch/<name>.zig, over `m`'s
    /// modules and `spec`.
    fn pieceModule(bb: *std.Build, m: Modules, spec: *std.Build.Module, name: []const u8, t: std.Build.ResolvedTarget, o: std.builtin.OptimizeMode) *std.Build.Module {
        return bb.createModule(.{
            .root_source_file = bb.path(bb.fmt("src/launch/{s}.zig", .{name})),
            .target = t,
            .optimize = o,
            .imports = &.{
                .{ .name = "sys", .module = m.sys },
                .{ .name = "fd", .module = m.fd },
                .{ .name = "msg", .module = m.msg },
                .{ .name = "proc", .module = m.proc },
                .{ .name = "spec", .module = spec },
            },
        });
    }

    /// A directory in the store that exists wherever this builds:
    /// the one holding the zig that runs it. Null outside a store.
    fn storeDir(bb: *std.Build) ?[]const u8 {
        const exe = std.fs.realpathAlloc(bb.allocator, bb.graph.zig_exe) catch return null;
        const prefix = "/nix/store/";
        if (!std.mem.startsWith(u8, exe, prefix)) return null;
        const end = std.mem.indexOfScalarPos(u8, exe, prefix.len, '/') orelse exe.len;
        return exe[0..end];
    }
};

const Terminal = struct {
    /// src/tty.zig over `m`'s modules.
    fn module(bb: *std.Build, m: Modules, t: std.Build.ResolvedTarget, o: std.builtin.OptimizeMode) *std.Build.Module {
        return bb.createModule(.{
            .root_source_file = bb.path("src/tty.zig"),
            .target = t,
            .optimize = o,
            .imports = &.{
                .{ .name = "sys", .module = m.sys },
                .{ .name = "fd", .module = m.fd },
                .{ .name = "msg", .module = m.msg },
                .{ .name = "sig", .module = m.sig },
                .{ .name = "proc", .module = m.proc },
            },
        });
    }
};

/// flong's compiled-in programs (flong-launch.c's FLONG_BWRAP,
/// FLONG_INIT, FLONG_PASTA, FLONG_NEWUIDMAP and FLONG_NEWGIDMAP, and
/// flong-init.c's FLONG_TINI): options with no default. `self` is flong's
/// own installed path, which bwrap runs as `flong init`.
const LaunchPaths = struct {
    bwrap: []const u8,
    self: []const u8,
    pasta: []const u8,
    newuidmap: []const u8,
    newgidmap: []const u8,
    tini: []const u8,

    /// All six, or null when one is missing. -Dself is build()'s, which
    /// the seccomp set reads too.
    fn read(b: *std.Build, self: ?[]const u8) ?LaunchPaths {
        const bwrap = b.option([]const u8, "bwrap", "bwrap's store path, which flong launch runs");
        const pasta = b.option([]const u8, "pasta", "pasta's store path");
        const newuidmap = b.option([]const u8, "newuidmap", "newuidmap, NixOS's setuid wrapper");
        const newgidmap = b.option([]const u8, "newgidmap", "newgidmap, NixOS's setuid wrapper");
        const tini = b.option([]const u8, "tini", "tini's store path, which flong init execs");
        return .{
            .bwrap = bwrap orelse return null,
            .self = self orelse return null,
            .pasta = pasta orelse return null,
            .newuidmap = newuidmap orelse return null,
            .newgidmap = newgidmap orelse return null,
            .tini = tini orelse return null,
        };
    }

    /// Paths under `dir` that exist nowhere: for a build no one runs (the
    /// cross check, the modules' own tests).
    fn dummy(comptime dir: []const u8) LaunchPaths {
        return .{
            .bwrap = dir ++ "/bin/bwrap",
            .self = dir ++ "/bin/flong",
            .pasta = dir ++ "/bin/pasta",
            .newuidmap = dir ++ "/bin/newuidmap",
            .newgidmap = dir ++ "/bin/newgidmap",
            .tini = dir ++ "/bin/tini",
        };
    }
};

/// flong (src/main.zig): static, no libc, stripped, single-threaded, and
/// no stack size in PT_GNU_STACK, so the start code makes no syscall
/// before main and leaves RLIMIT_STACK to bwrap, flong init, tini, the
/// payload and postStop (quirk 20; ZIG.md, "Measured": P2), as every
/// installed artifact.
fn flong(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, lp: LaunchPaths) *std.Build.Step.Compile {
    const exe = b.addExecutable(.{ .name = "flong", .root_module = Launcher.flongModule(b, target, optimize, true, lp) });
    exe.stack_size = 0;
    return exe;
}

/// The modules of src/ every program shares, each importing its own
/// (ZIG.md, "Per binary": sys; then msg, errno, num, fd).
const Modules = struct {
    sys: *std.Build.Module,
    errno: *std.Build.Module,
    msg: *std.Build.Module,
    num: *std.Build.Module,
    fd: *std.Build.Module,
    mount: *std.Build.Module,
    sig: *std.Build.Module,
    proc: *std.Build.Module,
    names: *std.Build.Module,
    cgroup: *std.Build.Module,
    record: *std.Build.Module,

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
    const fd = b.createModule(.{
        .root_source_file = b.path("src/fd.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "sys", .module = sys }},
    });
    const mount = b.createModule(.{
        .root_source_file = b.path("src/mount.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{ .{ .name = "sys", .module = sys }, .{ .name = "fd", .module = fd }, .{ .name = "msg", .module = msg } },
    });
    const sig = b.createModule(.{
        .root_source_file = b.path("src/sig.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{ .{ .name = "sys", .module = sys }, .{ .name = "fd", .module = fd }, .{ .name = "msg", .module = msg } },
    });
    const proc = b.createModule(.{
        .root_source_file = b.path("src/proc.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "sys", .module = sys },
            .{ .name = "fd", .module = fd },
            .{ .name = "msg", .module = msg },
            .{ .name = "sig", .module = sig },
            .{ .name = "num", .module = num },
        },
    });
    const names = b.createModule(.{ .root_source_file = b.path("src/names.zig"), .target = target, .optimize = optimize });
    const cgroup = b.createModule(.{
        .root_source_file = b.path("src/cgroup.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "sys", .module = sys },
            .{ .name = "fd", .module = fd },
            .{ .name = "msg", .module = msg },
            .{ .name = "sig", .module = sig },
            .{ .name = "names", .module = names },
        },
    });
    const record = b.createModule(.{
        .root_source_file = b.path("src/record.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "sys", .module = sys },
            .{ .name = "fd", .module = fd },
            .{ .name = "msg", .module = msg },
            .{ .name = "sig", .module = sig },
            .{ .name = "num", .module = num },
            .{ .name = "proc", .module = proc },
            .{ .name = "names", .module = names },
            .{ .name = "cgroup", .module = cgroup },
        },
    });
    return .{
        .sys = sys,
        .errno = errno,
        .msg = msg,
        .num = num,
        .fd = fd,
        .mount = mount,
        .sig = sig,
        .proc = proc,
        .names = names,
        .cgroup = cgroup,
        .record = record,
    };
}

/// The declaration's modules: `decl`, src/decl.zig or a planted one in its
/// place, and `docs`, src/decl_docs.zig over it with its harvested doc
/// comments.
const Decl = struct { decl: *std.Build.Module, docs: *std.Build.Module };

fn declModules(b: *std.Build, m: Modules, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, src: std.Build.LazyPath) Decl {
    const decl = b.createModule(.{
        .root_source_file = src,
        .target = target,
        .optimize = optimize,
        .imports = &.{ .{ .name = "fd", .module = m.fd }, .{ .name = "msg", .module = m.msg } },
    });
    const docs = b.createModule(.{
        .root_source_file = b.path("src/decl_docs.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "decl", .module = decl }},
    });
    docs.addAnonymousImport("decl_field_docs", .{ .root_source_file = declFieldDocs(b, src) });
    return .{ .decl = decl, .docs = docs };
}

/// flong check's module (src/check.zig): the declaration `d` judged, with
/// spec.zig's `unclean` from `spec`, over `m`'s graph.
fn checkModule(b: *std.Build, m: Modules, spec: *std.Build.Module, d: Decl, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path("src/check.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "sys", .module = m.sys },
            .{ .name = "msg", .module = m.msg },
            .{ .name = "spec", .module = spec },
            .{ .name = "decl", .module = d.decl },
            .{ .name = "decl_docs", .module = d.docs },
        },
    });
}

/// build/gen_decl_docs.zig, for the host, over `src`: each field's doc
/// comment, as decl_field_docs.zig. `@typeInfo` cannot see a doc comment,
/// so this parses the source (build/gen_decl_docs.zig says why).
fn declFieldDocs(b: *std.Build, src: std.Build.LazyPath) std.Build.LazyPath {
    const gen = b.addExecutable(.{
        .name = "gen-decl-docs",
        .root_module = b.createModule(.{
            .root_source_file = b.path("build/gen_decl_docs.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });
    const run = b.addRunArtifact(gen);
    run.addFileArg(src);
    return run.addOutputFileArg("decl_field_docs.zig");
}

/// flong-walker (tests/zig/walker.zig): the mount helper's walk, masks and
/// protected-path check, driven from a shell in checks.native. Static, no
/// libc, stripped, as an installed artifact.
fn walker(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    const m = modules(b, target, optimize);
    const exe = b.addExecutable(.{
        .name = "flong-walker",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/zig/walker.zig"),
            .target = target,
            .optimize = optimize,
            .strip = true,
            .single_threaded = true,
            .imports = &.{
                .{ .name = "sys", .module = m.sys },
                .{ .name = "fd", .module = m.fd },
                .{ .name = "msg", .module = m.msg },
                .{ .name = "mount", .module = m.mount },
            },
        }),
    });
    exe.stack_size = 0;
    return exe;
}

/// flong-proc (tests/zig/procdriver.zig): proc.zig, sig.zig and
/// cgroup.zig's sweep half driven from a shell, and the spawn probe.
/// Static, no libc, stripped, as an installed artifact.
fn procDriver(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    const m = modules(b, target, optimize);
    const exe = b.addExecutable(.{
        .name = "flong-proc",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/zig/procdriver.zig"),
            .target = target,
            .optimize = optimize,
            .strip = true,
            .single_threaded = true,
            .imports = &.{
                .{ .name = "sys", .module = m.sys },
                .{ .name = "fd", .module = m.fd },
                .{ .name = "msg", .module = m.msg },
                .{ .name = "sig", .module = m.sig },
                .{ .name = "proc", .module = m.proc },
                .{ .name = "cgroup", .module = m.cgroup },
            },
        }),
    });
    exe.stack_size = 0;
    return exe;
}

/// tests/zig/inputs.zig, the fuzz inputs of fuzz.zig.
fn inputsModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    return b.createModule(.{ .root_source_file = b.path("tests/zig/inputs.zig"), .target = target, .optimize = optimize });
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
            .{ .name = "fd", .module = m.fd },
            .{ .name = "config", .module = config.createModule() },
        },
    });
}

fn seccomp(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, self: []const u8) *std.Build.Step.Compile {
    const root = seccompModule(b, target, optimize, self);
    root.linkSystemLibrary("seccomp", .{});
    const exe = b.addExecutable(.{ .name = "flong-seccomp", .root_module = root });
    // No stack size in PT_GNU_STACK: the start code then leaves RLIMIT_STACK
    // alone (start.zig:545-578; ZIG.md, "Measured": P2).
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

/// A fixture's root module (src/fixtures/<name>.zig; ZIG.md, "Phase 6"),
/// over `m`'s modules: single-threaded, and libc for bpfdump alone, which
/// links libseccomp for its syscall names (scmp.zig). `fixtures` strips it;
/// a test's is not (a stripped module in an unstripped Debug test crashes
/// the compiler: "missing dwarf relocation target").
fn fixtureModule(b: *std.Build, m: Modules, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, name: []const u8) *std.Build.Module {
    const bpfdump = std.mem.eql(u8, name, "bpfdump");
    const root = b.createModule(.{
        .root_source_file = b.path(b.fmt("src/fixtures/{s}.zig", .{name})),
        .target = target,
        .optimize = optimize,
        .single_threaded = true,
        .link_libc = if (bpfdump) true else null,
        .imports = &.{
            .{ .name = "sys", .module = m.sys },
            .{ .name = "errno", .module = m.errno },
            .{ .name = "msg", .module = m.msg },
        },
    });
    if (bpfdump) {
        root.addImport("scmp", b.createModule(.{
            .root_source_file = b.path("src/seccomp/scmp.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{ .{ .name = "sys", .module = m.sys }, .{ .name = "fd", .module = m.fd } },
        }));
    }
    return root;
}

const Linking = enum { linked, unlinked };

/// The fixtures set (tests/parity/default.nix, tests/probes.nix): bpfdump,
/// syscall-probe, swapper and ioctl-probe. Unlinked, bpfdump names no
/// libseccomp, for a target that has none to link (the cross build).
fn fixtures(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, linking: Linking) [4]*std.Build.Step.Compile {
    var out: [4]*std.Build.Step.Compile = undefined;
    for ([_][2][]const u8{
        .{ "bpfdump", "bpfdump" },
        .{ "syscall-probe", "probe" },
        .{ "swapper", "swapper" },
        .{ "ioctl-probe", "ioctl_probe" },
    }, 0..) |f, i| {
        const root = fixtureModule(b, modules(b, target, optimize), target, optimize, f[1]);
        // Stripped, as every installed artifact (ZIG.md, "build.zig").
        root.strip = true;
        if (i == 0 and linking == .linked) root.linkSystemLibrary("seccomp", .{});
        const exe = b.addExecutable(.{ .name = f[0], .root_module = root });
        // No stack size in PT_GNU_STACK, as every installed artifact.
        exe.stack_size = 0;
        out[i] = exe;
    }
    return out;
}
