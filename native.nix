# flong's native code as Nix builds it (ZIG.md, "The Nix build"): one
# builder, zigSet, and one derivation per install set, each over only the
# sources that set imports, so an edit elsewhere moves none of its store
# paths; the checks of the Zig package; the dependency fetch they share.
#
# Phase 1 has the seccomp set, which seccomp/default.nix imports; phase 3
# adds launcher, which launcher/default.nix imports; phase 6 fixtures.
# tests/integration.nix builds phase 0's proofs with the same zigSet.
#
# pkgs defaults to the flake's locked nixpkgs, as launcher/default.nix:11-20
# does, since zig_0_15 is that nixpkgs' (ZIG.md, "Decided").
{
  pkgs ?
    let
      locked = (builtins.fromJSON (builtins.readFile ./flake.lock)).nodes.nixpkgs.locked;
    in
    import (fetchTarball {
      url = "https://github.com/${locked.owner}/${locked.repo}/archive/${locked.rev}.tar.gz";
      sha256 = locked.narHash;
    }) { },
}:
let
  inherit (pkgs) lib;
  zig = pkgs.zig_0_15;

  # One Zig package, one install set.
  #
  #   root          the directory holding build.zig and build.zig.zon: this
  #                 one for flong's package, another for a phase 0 proof's
  #   files         what else the build reads, as paths or filesets under
  #                 root; nothing else is in src, so an edit elsewhere moves
  #                 nothing
  #   steps         the `zig build` steps the installPhase runs ("install")
  #   set           when not null, -Dset=<set>
  #   flags         more `zig build` arguments, spliced into the shell line
  #   optimizeFlag  the optimisation: the hook's --release=safe, or "" for
  #                 Debug, or -Drelease=true
  #   deps          a zigDeps result, linked into $ZIG_GLOBAL_CACHE_DIR/p,
  #                 for -Ddev=true builds only
  #   extra         shell run after the build, in the unpacked source; it
  #                 may write $out and fail the derivation, but set -e
  #                 ignores every command of an `a && b` list but the last,
  #                 so one assertion per line
  #
  # The hook's buildPhase would be a second full build and its checkPhase
  # runs `zig build test`, which needs -Ddev (zig setup-hook.sh:16-41,
  # 108-110), so both are off and the one build is the installPhase. $out is
  # created first, so a set that installs nothing still has an output. An
  # unstripped artifact names Zig's lib/std, which disallowedReferences
  # catches: every installed artifact is stripped by build.zig, since Nix's
  # fixup strips only bin/, with -S, and no aarch64 ELF (ZIG.md, "Measured": P1, P6).
  zigSet =
    {
      pname,
      root ? ./.,
      files ? [ ],
      steps ? "install",
      set ? null,
      flags ? "",
      optimizeFlag ? "$zigDefaultOptimizeFlag",
      deps ? null,
      buildInputs ? [ ],
      nativeBuildInputs ? [ ],
      extra ? "",
      version ? "0",
      passthru ? { },
    }:
    pkgs.stdenv.mkDerivation {
      inherit pname version buildInputs passthru;
      src = lib.fileset.toSource {
        inherit root;
        fileset = lib.fileset.unions ([ (root + "/build.zig") (root + "/build.zig.zon") ] ++ files);
      };
      nativeBuildInputs = [ zig ] ++ nativeBuildInputs;
      dontUseZigBuild = true;
      doCheck = false;
      disallowedReferences = [ zig ];
      # zigConfigurePhase has made an empty $ZIG_GLOBAL_CACHE_DIR
      # (setup-hook.sh:10); the lazy dependencies go where zig looks for a
      # fetched package, p/<hash>.
      postConfigure = lib.optionalString (deps != null) ''
        ln -s ${deps} "$ZIG_GLOBAL_CACHE_DIR/p"
      '';
      installPhase = ''
        runHook preInstall
        mkdir -p $out
        TERM=dumb zig build ${steps} -j$NIX_BUILD_CORES $zigDefaultCpuFlag ${optimizeFlag} \
          ${lib.optionalString (set != null) "-Dset=${set}"} --prefix $out ${flags}
        ${extra}
        runHook postInstall
      '';
    };

  # Every dependency in build.zig.zon, lazy ones included (fetchAll; its
  # default false fetches none, fetcher.nix:7-12, 37), as a fixed-output
  # derivation over build.zig and build.zig.zon alone. On a build.zig.zon
  # change: hash = lib.fakeHash, build .#checks.x86_64-linux.native-test,
  # copy `got:`, rebuild.
  zigDeps =
    {
      pname,
      root ? ./.,
      hash,
    }:
    zig.fetchDeps {
      inherit pname hash;
      version = "0";
      fetchAll = true;
      src = lib.fileset.toSource {
        inherit root;
        fileset = lib.fileset.unions [ (root + "/build.zig") (root + "/build.zig.zon") ];
      };
    };

  # minish and zwanzig, and zwanzig's own chilli: for native-test and
  # native-analyze only, which pass -Ddev=true.
  deps = zigDeps {
    pname = "flong";
    hash = "sha256-GicN77r9Oh9xPqlIP5CS0/y2hSenxlM6thAiv1bjBW8=";
  };

  # The modules every program imports (ZIG.md, "Per binary").
  shared = [
    ./src/sys.zig
    ./src/msg.zig
    ./src/errno.zig
    ./src/num.zig
    ./src/fd.zig
  ];

  # flong-seccomp and its subcommands. -Dself is its own $out, the compiler
  # path a project key is made of (quirk 36); zig finds libseccomp through NIX_LDFLAGS' -L,
  # which it turns into a library path and an rpath (NativePaths.zig:17-72).
  seccomp = zigSet {
    pname = "flong-seccomp";
    set = "seccomp";
    flags = "-Dself=$out";
    buildInputs = [ pkgs.libseccomp ];
    files = [ ./src/seccomp ] ++ shared;
  };

  # The C launcher's compiler flags (launcher/default.nix before phase 3),
  # a bash array's words: the store paths of the programs it runs are
  # compiled in, so the wrapper cannot hand it a different bwrap, pasta or
  # flong-init (tini is the Zig flong-init's -Dtini). newuidmap and
  # newgidmap are NixOS's setuid wrappers, which have no store path. -Werror
  # with the cc-wrapper's hardening.
  # FLONG_INIT names the Zig flong-init installed beside it, in the same
  # $out, so it is given as a shell word expanding $out.
  launcherCflags = ''
    -std=gnu11 -O2 -D_GNU_SOURCE -Wall -Wextra -Werror
    -DFLONG_BWRAP='"${pkgs.bubblewrap}/bin/bwrap"'
    -DFLONG_PASTA='"${pkgs.passt}/bin/pasta"'
    -DFLONG_NEWUIDMAP='"/run/wrappers/bin/newuidmap"'
    -DFLONG_NEWGIDMAP='"/run/wrappers/bin/newgidmap"'
    -DFLONG_INIT="\"$out/bin/flong-init\""
  '';

  # flong-launch, flong-sweeper and flong-init side by side in one $out
  # (tests/rootless.nix:636-641 finds the sweeper beside the launcher):
  # flong-init is Zig, -Dtini its compiled-in tini; the rest is still C,
  # built by $CC with launcherCflags (ZIG.md, "Phase 3"), and flong-launch
  # links the Zig mount helper, libflong-mount.a, never installed (ZIG.md,
  # "The mount-helper shim"), whose clash check fails this build. The fileset holds
  # src/ but for the seccomp set's and the fixtures' own sources, and
  # launcher/'s C, so neither set's edits move the other (ZIG.md, "The Nix
  # build").
  launcher = zigSet {
    pname = "flong-launcher";
    set = "launcher";
    flags = "-Dtini=${pkgs.tini}/bin/tini";
    files = [
      (lib.fileset.difference ./src (
        lib.fileset.unions [
          ./src/seccomp
          (lib.fileset.maybeMissing ./src/fixtures)
        ]
      ))
      (lib.fileset.fileFilter (f: f.hasExt "c" || f.hasExt "h") ./launcher)
    ];
    nativeBuildInputs = [
      pkgs.file
      pkgs.binutils
    ];
    extra = ''
      # flong-init: static, no INTERP, and no stack size in PT_GNU_STACK,
      # so the start code leaves RLIMIT_STACK alone (quirk 20; ZIG.md,
      # "Measured": P2).
      file -b $out/bin/flong-init | tee /dev/stderr | grep -q 'statically linked'
      readelf -lW $out/bin/flong-init > $TMPDIR/init.phdrs
      if grep -q INTERP $TMPDIR/init.phdrs; then echo "flong-init has an INTERP"; exit 1; fi
      [[ $(awk '$1 == "GNU_STACK" { print $6 }' $TMPDIR/init.phdrs) == 0x000000 ]]

      # The mount helper: the archive (src/hybrid/mount_c.zig), then the C
      # launcher linked with it.
      TERM=dumb zig build mountlib -j$NIX_BUILD_CORES $zigDefaultCpuFlag $zigDefaultOptimizeFlag --prefix $TMPDIR/mountlib
      mountlib=$TMPDIR/mountlib/lib/libflong-mount.a
      cd launcher
      cflags=(${launcherCflags})
      $CC "''${cflags[@]}" -o $out/bin/flong-launch flong-launch.c flong-spec.c flong-ns.c \
        flong-cgroup.c flong-record.c flong-tty.c flong-util.c $mountlib
      $CC "''${cflags[@]}" -o $out/bin/flong-sweeper \
        flong-sweeper.c flong-cgroup.c flong-record.c flong-util.c
      cd ..
      ${clashCheck}
      ${shimRun}
    '';
  };

  # The clash check (ZIG.md, "The mount-helper shim"; phase 0's P5 made it
  # on a proof's archive, this on the real link), in the launcher's build,
  # before Nix's fixup strips anything: the archive exports flong_mount_main
  # alone and needs nothing but what glibc supplies; the launcher defines
  # none of the names compiler-rt would have taken from glibc, and takes
  # memcpy, memset and __stack_chk_fail from it. The launcher's symbol
  # table is read once and must hold flong_mount_main and main, so a
  # stripped binary cannot pass by listing nothing.
  clashCheck = ''
    nm -g --defined-only $mountlib | awk 'NF == 3 { print $2, $3 }' > $TMPDIR/mount.globals
    echo "libflong-mount.a, $(stat -c %s $mountlib) bytes, defines: $(cat $TMPDIR/mount.globals)" >&2
    [[ "$(cat $TMPDIR/mount.globals)" == "T flong_mount_main" ]]
    nm --undefined-only $mountlib | awk 'NF == 2 { print $2 }' | sort -u > $TMPDIR/mount.undefined
    echo "libflong-mount.a needs: $(tr '\n' ' ' < $TMPDIR/mount.undefined)" >&2
    # The control: the list was read, so the refusal below is not vacuous.
    grep -qx memcpy $TMPDIR/mount.undefined
    if grep -Evx 'memcpy|memset|memmove|memcmp|bcmp' $TMPDIR/mount.undefined; then echo "the mount library needs more than glibc's mem* functions"; exit 1; fi
    nm --defined-only $out/bin/flong-launch | awk '{ print $NF }' > $TMPDIR/launch.defined
    grep -qx flong_mount_main $TMPDIR/launch.defined
    grep -qx main $TMPDIR/launch.defined
    if grep -Ex '(memcpy|memset|memmove|memcmp|bcmp|__stack_chk_fail|__stack_chk_guard)(@.*)?' $TMPDIR/launch.defined; then echo "flong-launch defines a glibc name"; exit 1; fi
    nm -D --undefined-only $out/bin/flong-launch > $TMPDIR/launch.dynamic
    grep -Eq ' U memcpy(@|$)' $TMPDIR/launch.dynamic
    grep -Eq ' U memset(@|$)' $TMPDIR/launch.dynamic
    grep -Eq ' U __stack_chk_fail(@|$)' $TMPDIR/launch.dynamic
  '';

  # The shim run where no namespace is needed, linked as the launcher links
  # it: a destination twice is said in the launcher's words, one line, 1;
  # a mount kind the shim does not know is its panic, one line, 125.
  shimRun = ''
    cat > $TMPDIR/shim-run.c <<'EOF'
    #include <string.h>
    #include "flong-mount.h"

    int main(int argc, char **argv)
    {
    	struct fl_mount twice[] = {
    		{ .kind = FL_TMPFS, .dest = "/srv/work", .mode = "0755" },
    		{ .kind = FL_BIND_RO, .dest = "/srv/work", .src = "/srv/lower" },
    	};
    	struct fl_mount unknown[] = { { .kind = (enum fl_mount_kind)99, .dest = "/x" } };
    	const char *protect[] = { "/run/user/1000/flong" };
    	struct fl_mount_job job = {
    		.u1 = -1, .leader_pidfd = -1, .ready = -1, .uid = 1000, .gid = 100,
    		.home = "/home/alice", .protect = protect, .nprotect = 1,
    	};
    	int panic = argc == 2 && strcmp(argv[1], "panic") == 0;
    	job.mounts = panic ? unknown : twice;
    	job.nmounts = panic ? 1 : 2;
    	flong_mount_main(&job, 0);
    }
    EOF
    $CC "''${cflags[@]}" -Ilauncher -o $TMPDIR/shim-run $TMPDIR/shim-run.c $mountlib
    rc=0; $TMPDIR/shim-run twice 2> $TMPDIR/shim.twice || rc=$?
    [[ $rc == 1 ]]
    [[ "$(cat $TMPDIR/shim.twice)" == "flong-launch: /srv/work is mounted twice" ]]
    rc=0; $TMPDIR/shim-run panic 2> $TMPDIR/shim.panic || rc=$?
    [[ $rc == 125 ]]
    [[ "$(cat $TMPDIR/shim.panic)" == "flong-launch: internal error: unknown mount kind" ]]
  '';

  # The unit and property tests, and test-libc against this nixpkgs' glibc,
  # in Debug and in ReleaseSafe.
  test =
    name: optimizeFlag:
    zigSet {
      pname = "native-test-${name}";
      files = [
        ./src
        ./tests/zig
        # flong-mount.h and the header it includes, for the shim's layout
        # check (tests/zig/libc_mount.zig).
        ./launcher/flong-mount.h
        ./launcher/flong-spec.h
      ];
      steps = "test test-libc";
      flags = "-Ddev=true";
      inherit deps optimizeFlag;
      buildInputs = [ pkgs.libseccomp ];
    };

  checks = {
    native-test = pkgs.linkFarm "native-test" {
      debug = test "debug" "";
      release = test "release" "-Drelease=true";
    };

    # fdlint over src/ and tests/zig/ and on its planted files, what must
    # not compile, and zig fmt: no dependency, no -Ddev.
    native-lint = zigSet {
      pname = "native-lint";
      files = [
        ./src
        ./tests/zig
        ./tools
      ];
      steps = "lint compile-fail fmt";
    };

    # zwanzig, built from source, over src/ and its planted bugs.
    native-analyze = zigSet {
      pname = "native-analyze";
      files = [
        ./src
        ./tests/zig/analyze
        ./.zwanzig.json
      ];
      steps = "analyze";
      flags = "-Ddev=true";
      inherit deps;
    };
  }
  // lib.optionalAttrs (pkgs.stdenv.hostPlatform.system == "x86_64-linux") {
    # aarch64 from x86_64 (P6's pieces, ZIG.md "Phase 2"): flong-seccomp
    # compiled and not linked, since the flake has no aarch64 libseccomp
    # here; tests/zig/abi.zig's aarch64 half, and its controls, each plant
    # failing the build naming what differs on both arches; flong-init for
    # aarch64 with a dummy tini, the launcher set's Zig; and the mount
    # library for aarch64, its symbols checked as the launcher's build
    # checks x86_64's (the aarch64 C link is unchecked, ZIG.md "The
    # mount-helper shim").
    cross-aarch64 = pkgs.linkFarm "cross-aarch64" {
      flong = zigSet {
        pname = "cross-aarch64";
        files = [
          ./src/seccomp
          ./src/init.zig
          ./src/mount.zig
          ./src/hybrid
          ./tests/zig/abi.zig
          ./tests/zig/abi.h
        ]
        ++ shared;
        steps = "cross";
        nativeBuildInputs = [
          pkgs.file
          pkgs.binutils
        ];
        extra = ''
          # flong-init for aarch64, with a dummy tini: static, no INTERP.
          file -b $out/cross/flong-init | tee /dev/stderr | grep -q 'ARM aarch64.*statically linked'
          if file -b $out/cross/flong-init | grep -q interpreter; then exit 1; fi
          # The mount library for aarch64: flong_mount_main its only global
          # definition, and nothing undefined that glibc does not define:
          # memcpy and memset as on x86_64, and getauxval, as its page size
          # is not comptime-known (ZIG.md, "Measured": P6). Never installed.
          lib=$TMPDIR/libflong-mount.a
          mv $out/cross/libflong-mount.a $lib
          readelf -h $lib | grep -q 'Machine: *AArch64'
          nm -g --defined-only $lib | awk 'NF == 3 { print $2, $3 }' > $TMPDIR/arm.globals
          [[ "$(cat $TMPDIR/arm.globals)" == "T flong_mount_main" ]]
          nm --undefined-only $lib | awk 'NF == 2 { print $2 }' | sort -u > $TMPDIR/arm.undefined
          echo "aarch64 libflong-mount.a, $(stat -c %s $lib) bytes, needs: $(tr '\n' ' ' < $TMPDIR/arm.undefined)" | tee $out/mountlib >&2
          grep -qx memcpy $TMPDIR/arm.undefined
          if grep -Evx 'memcpy|memset|memmove|memcmp|bcmp|getauxval' $TMPDIR/arm.undefined; then echo "the aarch64 mount library needs more than glibc gives"; exit 1; fi
          for plant in arch offset; do
            if zig build abi -Dabi-plant=$plant $zigDefaultCpuFlag $zigDefaultOptimizeFlag >plant-$plant.log 2>&1; then
              echo "cross-aarch64: abi passed with -Dabi-plant=$plant"; exit 1
            fi
          done
          grep -q 'abi: x86_64: __NR_openat is 257, expected 56' plant-arch.log
          grep -q 'abi: aarch64: __NR_openat is 56, expected 257' plant-arch.log
          grep -q 'abi: x86_64: open_how.flags: offset 0, header 1' plant-offset.log
          grep -q 'abi: aarch64: open_how.flags: offset 0, header 1' plant-offset.log
          grep -ho 'error: abi: .*' plant-*.log | sort -u | tee $out/plants >&2
        '';
      };
    };
  };
in
{
  inherit
    zigSet
    zigDeps
    deps
    seccomp
    launcher
    checks
    ;
}
