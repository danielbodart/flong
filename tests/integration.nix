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
#                (tests/zig/walker.zig, phase 4), bin/flong-proc
#                (tests/zig/procdriver.zig, phase 5) and bin/flong-tty
#                (tests/zig/ttydriver.zig, phase 7's L3: src/tty.zig as the
#                launcher drives it), for checks.native
#   spec-paths   `zig build test-paths`: tests/golden/paths.txt against the
#                launcher's functions (tests/zig/paths.zig); module.nix
#                asserts its own side
#   launch-driver
#                `zig build launch-driver`: bin/flong-launch-driver
#                (tests/zig/launchdriver.zig), phase 7's L2 (src/ns.zig,
#                src/passwd.zig, the launch's halves of src/cgroup.zig and
#                src/record.zig), for checks.native
#   launch-test  `zig build test-launch`: tests/zig/launch_test.zig, the
#                L2 record writer against tests/golden/records/ (outside
#                native-test's fileset), the name taken, the cache lock,
#                the session made and undone
#   flong-launch-c
#                the C flong-launch as native.nix's launcher set built it
#                until phase 7's L4, with the Zig mount library, for
#                rootless.nix's transition subtest (ZIG.md, phase 7's L4),
#                never an output; L5 deletes it
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
      # Phase 7's L3, the terminal.
      ../src/tty.zig
      ../tests/zig/ttydriver.zig
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

  # Phase 7's L2 (ZIG.md): the launch's halves, driven from checks.native.
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
  # flong-sweeper sweeping a record the driver wrote.
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

  spec-paths = zigSet {
    pname = "flong-spec-paths";
    steps = "test-paths";
    files = specFiles ++ [
      ../tests/zig/paths.zig
      ../tests/golden/paths.txt
    ];
  };

  # The C launcher beside the Zig one native.nix ships (ZIG.md, phase 7's
  # L4): the sources, flags, link, clash check and shim run the launcher set
  # had until L4 (native.nix's cLaunch), and the same compiled-in bwrap and
  # pasta; its FLONG_INIT names the shipped set's flong-init rather than one
  # of its own. So a session under either launcher runs the same flong-init,
  # and bwrap's argv names it by the same store path. Only
  # $out/bin/flong-launch: the mountlib step's install is the archive, which
  # the link has already used. rootless.nix points copies of the wrappers at
  # it, the Zig against the C.
  flong-launch-c = zigSet {
    pname = "flong-launch-c";
    steps = "mountlib";
    files = native.cLaunchFiles;
    nativeBuildInputs = [ pkgs.binutils ];
    extra = ''
      rm -r $out/lib
      mkdir $out/bin
    ''
    + native.cLaunch (native.launcherCflagsFor ''"\"${native.launcher}/bin/flong-init\""'')
    + ''
      # The control: the one path it runs that it does not own is the shipped
      # flong-init, and it runs no flong-init of its own.
      grep -qF '${native.launcher}/bin/flong-init' $out/bin/flong-launch
      [[ "$(ls $out/bin)" == flong-launch ]]
    '';
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
    spec-paths
    launch-driver
    launch-test
    flong-launch-c
    ;
}
// builds
// bins
