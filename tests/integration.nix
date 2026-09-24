# What checks.native and the build-sandbox proofs run: every proof in
# tests/proofs/ (the Zig port's phases 0 and 2;
# tests/proofs/README.md). Never a flake
# output or package: flake.nix reaches it only through checks.integration,
# which builds every derivation here, and checks.native, which puts `vm` on
# its node.
#
# Every value is a derivation:
#   <pN>         a proof's `build`, whose own build runs its assertions
#   <pN>-bins    a proof's `bins`, a tree with bin/
#   drivers      `zig build integration` over the package: bin/flong-walker
#                (tests/zig/walker.zig, phase 4), bin/flong-proc
#                (tests/zig/procdriver.zig, phase 5) and bin/flong-tty
#                (tests/zig/ttydriver.zig, phase 7's L3: src/tty.zig as the
#                launcher drives it), for checks.native
#   launch-driver
#                `zig build launch-driver`: bin/flong-launch-driver
#                (tests/zig/launchdriver.zig), phase 7's L2 (src/ns.zig,
#                src/passwd.zig, the launch's halves of src/cgroup.zig and
#                src/record.zig), for checks.native
#   launch-test  `zig build test-launch`: tests/zig/launch_test.zig, the
#                L2 record writer against tests/golden/records/ (outside
#                native-test's fileset), the name taken, the cache lock,
#                the session made and undone
#   vm           every proof's bins, the drivers and launch-driver joined,
#                for the VM node's PATH, with passthru.vmScripts, the
#                proofs' testScript fragments in order, then L2's
#                (tests/launch-native.nix)
#
# A proof is a directory tests/proofs/<pN>/ holding a default.nix; the
# contract is tests/proofs/README.md. Adding one needs no edit here or in
# tests/native.nix. The spike and the retired proofs are in
# ~/Projects/flong-spikes-archive/zig.
#
# pkgs defaults to the flake's locked nixpkgs, as launcher/default.nix:10-19
# does, since zig_0_15 is that nixpkgs' (DESIGN.md, "Why Zig, and what it cost").
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
  native = import ../native.nix { inherit pkgs; };
  inherit (native) zigSet zigDeps;

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

  # The drivers checks.native runs against flong's own modules (DESIGN.md,
  # "The build"): static, no libc, stripped, as
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
      # Phase 7's L3, the terminal.
      ../src/tty.zig
      ../tests/zig/ttydriver.zig
    ];
  };

  # The Zig port's L1: the spec and what it imports.
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

  # The Zig port's L2: the launch's halves, driven from checks.native.
  # Static, no libc, stripped, no stack size, as the launcher will be.
  launch-driver = zigSet {
    pname = "flong-launch-driver";
    steps = "launch-driver";
    files = specFiles ++ [
      ../src/cgroup.zig
      ../src/record.zig
      ../src/passwd.zig
      ../src/ns.zig
      ../tests/zig/launchdriver.zig
    ];
    nativeBuildInputs = [
      pkgs.file
      pkgs.binutils
    ];
    extra = ''
      file -b $out/bin/flong-launch-driver | tee /dev/stderr | grep -q 'statically linked'
      readelf -lW $out/bin/flong-launch-driver > $TMPDIR/phdrs
      if grep -q INTERP $TMPDIR/phdrs; then echo "flong-launch-driver has an INTERP"; exit 1; fi
      [[ $(awk '$1 == "GNU_STACK" { print $6 }' $TMPDIR/phdrs) == 0x000000 ]]
    '';
  };

  # L2's checks.native fragment: the driver above, and the launcher's Zig
  # flong sweeper sweeping a record the driver wrote.
  launchNative = import ./launch-native.nix {
    inherit pkgs;
    launcher = import ../launcher { inherit pkgs; };
  };

  # Phase 7's L2: the record writer against tests/golden/records/ and the
  # rest of tests/zig/launch_test.zig, in the build sandbox.
  launch-test = zigSet {
    pname = "flong-launch-test";
    steps = "test-launch";
    files = specFiles ++ [
      ../src/cgroup.zig
      ../src/record.zig
      ../src/passwd.zig
      ../src/ns.zig
      ../tests/zig/launch_test.zig
      ../tests/golden/records
    ];
  };

  vm = pkgs.symlinkJoin {
    name = "flong-proofs-vm";
    paths = lib.attrValues bins ++ [
      drivers
      launch-driver
    ];
    passthru.vmScripts =
      lib.concatMap (
        name:
        lib.optional (proofs.${name} ? vmScript) {
          inherit name;
          script = proofs.${name}.vmScript;
        }
      ) proofNames
      ++ [
        {
          name = "phase 7, L2";
          script = launchNative;
        }
      ];
  };
in
{
  inherit
    vm
    drivers
    launch-driver
    launch-test
    ;
}
// builds
// bins
