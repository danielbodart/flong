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

  # The one builder and the dependency fetch, native.nix's: see there for
  # their arguments. A proof passes its own root.
  inherit (import ../native.nix { inherit pkgs; }) zigSet zigDeps;

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
