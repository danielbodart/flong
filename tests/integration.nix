# What checks.native and the build-sandbox proofs run: every proof in
# tests/proofs/ (ZIG.md, "Phase 0: proofs" and "Phase 2"). Never a flake
# output or package: flake.nix reaches it only through checks.integration,
# which builds every derivation here, and checks.native, which puts `vm` on
# its node.
#
# Every value is a derivation:
#   <pN>         a proof's `build`, whose own build runs its assertions
#   <pN>-bins    a proof's `bins`, a tree with bin/
#   drivers      `zig build integration` over the package: bin/flong-walker
#                (tests/zig/walker.zig, phase 4), for checks.native
#   vm           every proof's bins and the drivers joined, for the VM
#                node's PATH, with passthru.vmScripts, the proofs' testScript
#                fragments in order
#
# A proof is a directory tests/proofs/<pN>/ holding a default.nix; the
# contract is tests/proofs/README.md. Adding one needs no edit here or in
# tests/native.nix. The spike and the retired proofs are in
# ~/Projects/flong-spikes-archive/zig.
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

  # Each tests/proofs/<pN>/default.nix, in name order.
  proofsDir = ./proofs;
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
      inherit pkgs lib zigSet zigDeps;
    }
  );

  builds = lib.concatMapAttrs (name: p: lib.optionalAttrs (p ? build) { ${name} = p.build; }) proofs;
  bins = lib.concatMapAttrs (
    name: p: lib.optionalAttrs (p ? bins) { "${name}-bins" = p.bins; }
  ) proofs;

  # The drivers checks.native runs against flong's own modules (ZIG.md,
  # "The Nix build": tests/integration.nix): static, no libc, stripped, as
  # an installed artifact is.
  drivers = zigSet {
    pname = "flong-drivers";
    steps = "integration";
    files = [
      ../src/sys.zig
      ../src/fd.zig
      ../src/msg.zig
      ../src/errno.zig
      ../src/mount.zig
      ../tests/zig/walker.zig
    ];
  };

  vm = pkgs.symlinkJoin {
    name = "flong-proofs-vm";
    paths = lib.attrValues bins ++ [ drivers ];
    passthru.vmScripts = lib.concatMap (
      name:
      lib.optional (proofs.${name} ? vmScript) {
        inherit name;
        script = proofs.${name}.vmScript;
      }
    ) proofNames;
  };
in
{ inherit vm drivers; } // builds // bins
