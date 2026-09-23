# P1, the build (ZIG.md, "Phase 0: proofs"): the spike as a zigSet, each
# question answered by a derivation that fails if the answer is no.
#
#   dev      do the lazy dependencies, fetched by fetchDeps with fetchAll,
#            let `test` and `analyze` run with -Ddev=true offline?
#   offline  do install, lint, compile-fail and cross pass with an empty
#            cache, no network and no -Ddev, and do test and analyze then
#            refuse with "needs -Ddev=true" (spike/fd-zig/build.zig)?
#   outside  does a b.path outside the fileset break a build that does not
#            use it? The source holds build.zig, build.zig.zon and src/ only,
#            so lint's tools/fdlint.zig and probes/, compile-fail's probes/
#            and analyze's .zwanzig.json are all outside it.
#
# The fallback for `dev`, a fixed-output derivation running `zig fetch` per
# pinned URL, is not needed: `dev` builds.
{ pkgs, lib, zigSet, zigDeps, spikeRoot, ... }:
let
  src = spikeRoot + "/src";
  tools = spikeRoot + "/tools";
  probes = spikeRoot + "/probes";
  zwanzigConfig = spikeRoot + "/.zwanzig.json";

  deps = zigDeps {
    pname = "fd-spike";
    root = spikeRoot;
    hash = "sha256-GicN77r9Oh9xPqlIP5CS0/y2hSenxlM6thAiv1bjBW8=";
  };

  dev = zigSet {
    pname = "p1-dev";
    root = spikeRoot;
    files = [ src tools probes zwanzigConfig ];
    inherit deps;
    steps = "test analyze";
    flags = "-Ddev=true";
  };

  offline = zigSet {
    pname = "p1-offline";
    root = spikeRoot;
    files = [ src tools probes zwanzigConfig ];
    steps = "install lint compile-fail cross";
    nativeBuildInputs = [ pkgs.file ];
    extra = ''
      test -x $out/bin/fd-probe
      file -b $out/aarch64/fd-probe | tee /dev/stderr | grep -q 'ARM aarch64, .* statically linked'
      for step in test analyze; do
        if zig build $step $zigDefaultCpuFlag $zigDefaultOptimizeFlag >log 2>&1; then
          echo "p1: $step passed without -Ddev=true"; exit 1
        fi
        grep -q 'error: needs -Ddev=true' log || { cat log; echo "p1: $step failed for another reason"; exit 1; }
      done
    '';
  };

  outside = zigSet {
    pname = "p1-outside";
    root = spikeRoot;
    files = [ src ];
    extra = ''
      # One test per line: set -e ignores a failure before the last `&&`.
      test ! -e tools/fdlint.zig
      test ! -e probes
      test ! -e .zwanzig.json
      test -x $out/bin/fd-probe
      # The control: a step that does use those paths fails here, so the
      # install above succeeded because b.path is lazy, not because the
      # files were there.
      if zig build lint $zigDefaultCpuFlag $zigDefaultOptimizeFlag >log 2>&1; then
        echo "p1: lint passed without tools/"; exit 1
      fi
      grep -q 'fdlint.zig' log || { cat log; exit 1; }
    '';
  };
in
{
  build = pkgs.linkFarm "p1" { inherit dev offline outside; };

  # The spike's probe on the node, so the contract is exercised end to end:
  # run as alice through her user manager, it holds 0-2 and echoes argv.
  bins = outside;
  vmScript = ''
    with subtest("p1: the spike's fd-probe runs on the node"):
        out = machine.succeed(as_alice("fd-probe a b")).strip()
        assert out.endswith("| a b"), out
  '';
}
