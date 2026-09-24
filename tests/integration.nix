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
#                (tests/zig/walker.zig, phase 4) and bin/flong-proc
#                (tests/zig/procdriver.zig, phase 5), for checks.native
#   spec-probe   `zig build spec-probe`: bin/spec-probe, src/launch.zig as
#                far as phase 7's L1 goes (root refused, the spec parsed,
#                the launcher's exit), for golden's spec set
#                (tests/golden.nix), until L4 builds the launcher itself
#   spec-paths   `zig build test-paths`: tests/golden/paths.txt against the
#                launcher's functions (tests/zig/paths.zig); module.nix
#                asserts its own side
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
      ../src/num.zig
      ../src/mount.zig
      ../src/sig.zig
      ../src/proc.zig
      ../src/names.zig
      ../src/cgroup.zig
      ../tests/zig/walker.zig
      ../tests/zig/procdriver.zig
    ];
  };

  # Phase 7's L1 (ZIG.md): the spec and what it imports.
  specFiles = [
    ../src/sys.zig
    ../src/fd.zig
    ../src/msg.zig
    ../src/errno.zig
    ../src/num.zig
    ../src/mount.zig
    ../src/sig.zig
    ../src/proc.zig
    ../src/names.zig
    ../src/spec.zig
  ];

  # Static, no libc, stripped, and no stack size in PT_GNU_STACK, as the
  # launcher's Zig will be.
  spec-probe = zigSet {
    pname = "flong-spec-probe";
    steps = "spec-probe";
    files = specFiles ++ [ ../src/launch.zig ];
    nativeBuildInputs = [
      pkgs.file
      pkgs.binutils
    ];
    extra = ''
      file -b $out/bin/spec-probe | tee /dev/stderr | grep -q 'statically linked'
      readelf -lW $out/bin/spec-probe > $TMPDIR/phdrs
      if grep -q INTERP $TMPDIR/phdrs; then echo "spec-probe has an INTERP"; exit 1; fi
      [[ $(awk '$1 == "GNU_STACK" { print $6 }' $TMPDIR/phdrs) == 0x000000 ]]
    '';
  };

  spec-paths = zigSet {
    pname = "flong-spec-paths";
    steps = "test-paths";
    files = specFiles ++ [
      ../tests/zig/paths.zig
      ../tests/golden/paths.txt
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
{ inherit vm drivers spec-probe spec-paths; } // builds // bins
