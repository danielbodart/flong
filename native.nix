# flong's native code as Nix builds it (DESIGN.md, "The build"): one
# builder, zigSet, and one derivation per install set, each over only the
# sources that set imports, so an edit elsewhere moves none of its store
# paths; the checks of the Zig package; the dependency fetch they share.
#
# Phase 1 has the seccomp set, which seccomp/default.nix imports; phase 3
# adds launcher, which launcher/default.nix imports (phase 5 adds
# flong-sweeper to it, phase 7's L4 the Zig flong-launch, and S1 makes the
# three one binary, flong); phase 6 fixtures, which tests/parity/default.nix and tests/probes.nix import.
# tests/integration.nix builds phase 0's proofs with the same zigSet.
#
# pkgs defaults to the flake's locked nixpkgs, as launcher/default.nix:10-19
# does, since zig_0_15 is that nixpkgs' (DESIGN.md, "Why Zig, and what it cost").
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
  # fixup strips only bin/, with -S, and no aarch64 ELF (DESIGN.md, "What the port measured").
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
  # change: hash = lib.fakeHash, build .#checks.x86_64-linux.native-test-debug,
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

  # minish and zwanzig, and zwanzig's own chilli: for native-test-debug,
  # native-test-release and native-analyze only, which pass -Ddev=true.
  deps = zigDeps {
    pname = "flong";
    hash = "sha256-GicN77r9Oh9xPqlIP5CS0/y2hSenxlM6thAiv1bjBW8=";
  };

  # The modules every program imports (DESIGN.md, "Files").
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

  # The tests' programs (src/fixtures/; DESIGN.md, "Files"): bpfdump, linked
  # with libc and libseccomp (its syscall names, scmp.zig), and
  # syscall-probe, swapper and ioctl-probe, static and without libc. The
  # fileset is what they import, so a launcher or seccomp edit moves it only
  # through a module they share. None has a stack size in PT_GNU_STACK, as
  # every installed artifact; the three static ones have no INTERP, and
  # bpfdump needs libseccomp.so.
  fixtures = zigSet {
    pname = "flong-fixtures";
    set = "fixtures";
    buildInputs = [ pkgs.libseccomp ];
    files = [
      ./src/fixtures
      ./src/seccomp/scmp.zig
      ./src/sys.zig
      ./src/msg.zig
      ./src/errno.zig
      ./src/fd.zig
    ];
    nativeBuildInputs = [
      pkgs.file
      pkgs.binutils
    ];
    extra = ''
      for prog in bpfdump syscall-probe swapper ioctl-probe; do
        readelf -lW $out/bin/$prog > $TMPDIR/$prog.phdrs
        [[ $(awk '$1 == "GNU_STACK" { print $6 }' $TMPDIR/$prog.phdrs) == 0x000000 ]]
      done
      for prog in syscall-probe swapper ioctl-probe; do
        file -b $out/bin/$prog | tee /dev/stderr | grep -q 'statically linked'
        if grep -q INTERP $TMPDIR/$prog.phdrs; then echo "$prog has an INTERP"; exit 1; fi
      done
      readelf -dW $out/bin/bpfdump | grep -q 'NEEDED.*libseccomp\.so'
    '';
  };

  # The programs flong launch runs, compiled in.
  bwrap = "${pkgs.bubblewrap}/bin/bwrap";
  pasta = "${pkgs.passt}/bin/pasta";
  newuidmap = "/run/wrappers/bin/newuidmap";
  newgidmap = "/run/wrappers/bin/newgidmap";

  # flong, one binary whose subcommands are launch, init and sweeper
  # (src/main.zig), static and without libc: -Dtini is
  # flong init's compiled-in tini, and flong launch's programs are -Dbwrap,
  # -Dpasta, -Dnewuidmap, -Dnewgidmap and -Dself, the flong in this $out,
  # which bwrap runs as `flong init`. The fileset holds src/ but for the
  # seccomp set's and the fixtures' own sources (DESIGN.md, "The build"), so
  # neither set's edits move it. Its size is printed, never gated (DESIGN.md,
  # "What the port measured": binaries).
  launcher = zigSet {
    pname = "flong-launcher";
    set = "launcher";
    flags = "-Dtini=${pkgs.tini}/bin/tini -Dbwrap=${bwrap} -Dpasta=${pasta} -Dnewuidmap=${newuidmap} -Dnewgidmap=${newgidmap} -Dself=$out/bin/flong";
    files = [
      (lib.fileset.difference ./src (
        lib.fileset.unions [
          ./src/seccomp
          (lib.fileset.maybeMissing ./src/fixtures)
        ]
      ))
    ];
    nativeBuildInputs = [
      pkgs.file
      pkgs.binutils
    ];
    extra = ''
      # One program, flong.
      [[ "$(ls $out/bin)" == flong ]]
      # Static, no INTERP, and no stack size in PT_GNU_STACK, so the start
      # code leaves RLIMIT_STACK alone (quirk 20; DESIGN.md, "What the port
      # measured": start code).
      file -b $out/bin/flong | tee /dev/stderr | grep -q 'statically linked'
      readelf -lW $out/bin/flong > $TMPDIR/flong.phdrs
      if grep -q INTERP $TMPDIR/flong.phdrs; then echo "flong has an INTERP"; exit 1; fi
      [[ $(awk '$1 == "GNU_STACK" { print $6 }' $TMPDIR/flong.phdrs) == 0x000000 ]]
      # Stripped, as build.zig makes every installed artifact: no symbol
      # table, so nothing names Zig's lib/std (disallowedReferences holds
      # the rest).
      readelf -SW $out/bin/flong > $TMPDIR/flong.sections
      grep -q '\.text' $TMPDIR/flong.sections
      if grep -q '\.symtab' $TMPDIR/flong.sections; then echo "flong has a symbol table"; exit 1; fi
      # flong launch runs its own binary as bwrap's payload, flong init.
      grep -qF "$out/bin/flong" $out/bin/flong
      echo "flong: $(stat -c %s $out/bin/flong) bytes" >&2
    '';
  };

  # The unit and property tests, and test-libc against this nixpkgs' glibc,
  # in Debug and in ReleaseSafe. build/ holds the doc harvest decl_docs.zig's
  # tests are compiled with.
  test =
    name: optimizeFlag:
    zigSet {
      pname = "native-test-${name}";
      files = [
        ./build
        ./src
        ./tests/zig
      ];
      steps = "test test-libc";
      flags = "-Ddev=true";
      inherit deps optimizeFlag;
      buildInputs = [ pkgs.libseccomp ];
    };

  checks = {
    # Two checks, not one, so each is a leg of CI's matrix
    # (.github/workflows/ci.yml) and a job of the local gate.
    native-test-debug = test "debug" "";
    native-test-release = test "release" "-Drelease=true";

    # fdlint over src/ and tests/zig/ and on its planted files, what must
    # not compile (the doc harvest's case among them), and zig fmt: no
    # dependency, no -Ddev.
    native-lint = zigSet {
      pname = "native-lint";
      files = [
        ./build
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
    # aarch64 from x86_64 (DESIGN.md, "The build": cross): flong-seccomp
    # and bpfdump compiled and not linked, since the flake has no aarch64
    # libseccomp here; syscall-probe, swapper and ioctl-probe built; tests/zig/abi.zig's aarch64 half, and its controls, each plant
    # failing the build naming what differs on both arches; flong (with
    # dummy paths) for aarch64, the launcher set.
    cross-aarch64 = pkgs.linkFarm "cross-aarch64" {
      flong = zigSet {
        pname = "cross-aarch64";
        files = [
          ./src/seccomp
          ./src/main.zig
          ./src/init.zig
          ./src/mount.zig
          ./src/sweeper.zig
          ./src/record.zig
          ./src/cgroup.zig
          ./src/names.zig
          ./src/proc.zig
          ./src/sig.zig
          ./src/launch.zig
          ./src/launch
          ./src/spec.zig
          ./src/ns.zig
          ./src/tty.zig
          ./src/passwd.zig
          ./src/fixtures
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
          # flong (with dummy paths) for aarch64: static, no INTERP.
          # And the fixtures but bpfdump, which needs libseccomp.
          for prog in flong syscall-probe swapper ioctl-probe; do
            file -b $out/cross/$prog | tee /dev/stderr | grep -q 'ARM aarch64.*statically linked'
            if file -b $out/cross/$prog | grep -q interpreter; then exit 1; fi
          done
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
    fixtures
    checks
    ;
}
