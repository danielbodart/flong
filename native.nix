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
  # built by $CC with launcherCflags (ZIG.md, "Phase 3"). The fileset holds
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
      cd launcher
      cflags=(${launcherCflags})
      $CC "''${cflags[@]}" -o $out/bin/flong-launch \
        flong-launch.c flong-spec.c flong-ns.c flong-cgroup.c flong-record.c \
        flong-mount.c flong-tty.c flong-util.c
      $CC "''${cflags[@]}" -o $out/bin/flong-sweeper \
        flong-sweeper.c flong-cgroup.c flong-record.c flong-util.c
      cd ..
    '';
  };

  # The unit and property tests, and test-libc against this nixpkgs' glibc,
  # in Debug and in ReleaseSafe.
  test =
    name: optimizeFlag:
    zigSet {
      pname = "native-test-${name}";
      files = [
        ./src
        ./tests/zig
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
    # failing the build naming what differs on both arches; and P5's archive
    # for aarch64 with its clash check (tests/proofs/p5); flong-init for
    # aarch64 with a dummy tini, the launcher set's Zig.
    cross-aarch64 = pkgs.linkFarm "cross-aarch64" {
      flong = zigSet {
        pname = "cross-aarch64";
        files = [
          ./src/seccomp
          ./src/init.zig
          ./tests/zig/abi.zig
          ./tests/zig/abi.h
        ]
        ++ shared;
        steps = "cross";
        nativeBuildInputs = [ pkgs.file ];
        extra = ''
          # flong-init for aarch64, with a dummy tini: static, no INTERP.
          file -b $out/cross/flong-init | tee /dev/stderr | grep -q 'ARM aarch64.*statically linked'
          if file -b $out/cross/flong-init | grep -q interpreter; then exit 1; fi
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
      p5 = (import ./tests/proofs/p5 { inherit pkgs lib zigSet; }).aarch64;
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
