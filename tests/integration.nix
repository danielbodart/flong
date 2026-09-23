# What checks.native and the build-sandbox proofs run: the spike, built as a
# zigSet, and every proof in spike/proofs/ (ZIG.md, "Phase 0: proofs"). Never
# a flake output or package: flake.nix reaches it only through
# checks.integration, which builds every derivation here, and checks.native,
# which puts `vm` on its node.
#
# Every value is a derivation:
#   spike        the spike's `install`, a plain zigSet
#   <pN>         a proof's `build`, whose own build runs its assertions
#   <pN>-bins    a proof's `bins`, a tree with bin/
#   vm           every proof's bins joined, for the VM node's PATH, with
#                passthru.vmScripts, the proofs' testScript fragments in order
#
# A proof is a directory spike/proofs/<pN>/ holding a default.nix; the
# contract is spike/proofs/README.md. Adding one needs no edit here or in
# tests/native.nix.
#
# pkgs defaults to the flake's locked nixpkgs, as launcher/default.nix:11-20
# does, since zig_0_15 is that nixpkgs' (ZIG.md, "Decided").
{
  pkgs ?
    let
      locked = (builtins.fromJSON (builtins.readFile ../flake.lock)).nodes.nixpkgs.locked;
    in
    import (fetchTarball {
      url = "https://github.com/${locked.owner}/${locked.repo}/archive/${locked.rev}.tar.gz";
      sha256 = locked.narHash;
    }) { },
}:
let
  inherit (pkgs) lib;
  zig = pkgs.zig_0_15;

  # One Zig package, one install set: ZIG.md "The Nix build", generalised
  # for phase 0, where each package has its own root (the spike, a proof).
  #
  #   root       the directory holding build.zig and build.zig.zon
  #   files      what else the build reads, as paths or filesets under root;
  #              nothing else is in src, so an edit elsewhere moves nothing
  #   steps      the `zig build` steps the installPhase runs ("install")
  #   set        when not null, -Dset=<set> (the production package's sets)
  #   flags      more `zig build` arguments, spliced into the shell line
  #   deps       a fetchDeps result (zigDeps below), linked into
  #              $ZIG_GLOBAL_CACHE_DIR/p, for -Ddev=true builds only
  #   extra      shell run after the build, in the unpacked source; it may
  #              write $out and fail the derivation
  #
  # The hook's buildPhase would be a second full build and its checkPhase
  # runs `zig build test`, which needs -Ddev (zig setup-hook.sh:16-41,
  # 108-110), so both are off and the one build is the installPhase. $out is
  # created first, so a set that installs nothing still has an output.
  zigSet =
    {
      pname,
      root,
      files ? [ ],
      steps ? "install",
      set ? null,
      flags ? "",
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
        TERM=dumb zig build ${steps} -j$NIX_BUILD_CORES $zigDefaultCpuFlag $zigDefaultOptimizeFlag \
          ${lib.optionalString (set != null) "-Dset=${set}"} --prefix $out ${flags}
        ${extra}
        runHook postInstall
      '';
    };

  # Every dependency in build.zig.zon, lazy ones included (fetchAll; its
  # default false fetches none, fetcher.nix:7-12, 37), as a fixed-output
  # derivation over build.zig and build.zig.zon alone. On a build.zig.zon
  # change: hash = lib.fakeHash, build, copy `got:`, rebuild.
  zigDeps =
    { pname, root, hash }:
    zig.fetchDeps {
      inherit pname hash;
      version = "0";
      fetchAll = true;
      src = lib.fileset.toSource {
        inherit root;
        fileset = lib.fileset.unions [ (root + "/build.zig") (root + "/build.zig.zon") ];
      };
    };

  spikeRoot = ../spike/fd-zig;

  # The spike's install needs src/ only.
  spike = zigSet {
    pname = "fd-spike";
    root = spikeRoot;
    files = [ (spikeRoot + "/src") ];
  };

  # Each spike/proofs/<pN>/default.nix, in name order.
  proofsDir = ../spike/proofs;
  proofNames =
    if builtins.pathExists proofsDir then
      lib.sort (a: b: a < b) (
        lib.attrNames (
          lib.filterAttrs (
            name: type: type == "directory" && builtins.pathExists (proofsDir + "/${name}/default.nix")
          ) (builtins.readDir proofsDir)
        )
      )
    else
      [ ];
  proofs = lib.genAttrs proofNames (
    name:
    import (proofsDir + "/${name}") {
      inherit pkgs lib zigSet zigDeps spikeRoot;
    }
  );

  builds = lib.concatMapAttrs (name: p: lib.optionalAttrs (p ? build) { ${name} = p.build; }) proofs;
  bins = lib.concatMapAttrs (
    name: p: lib.optionalAttrs (p ? bins) { "${name}-bins" = p.bins; }
  ) proofs;

  vm = pkgs.symlinkJoin {
    name = "flong-proofs-vm";
    paths = lib.attrValues bins;
    passthru.vmScripts = lib.concatMap (
      name:
      lib.optional (proofs.${name} ? vmScript) {
        inherit name;
        script = proofs.${name}.vmScript;
      }
    ) proofNames;
  };
in
{ inherit spike vm; } // builds // bins
