# The proofs that need a kernel the build sandbox does not give: one node, a
# lingering user with subordinate ids and a delegated user manager, the
# proofs' binaries on PATH (tests/integration.nix's `vm`), and each proof's
# testScript fragment after the common setup below, in tests/proofs/ name
# order (ZIG.md, "Tests", checks.native). A fourth VM beside basic, rootless
# and parity; nothing in it is about time.
#
# Fragments are Python run in this testScript's scope, so they may use
# `machine`, `shlex` and `as_alice`; each opens its own subtest.
{ hostPkgs, lib, ... }:

let
  integration = import ./integration.nix { pkgs = hostPkgs; };
in
{
  name = "flong-native";

  nodes.machine = { pkgs, ... }: {
    virtualisation.memorySize = 2048;
    virtualisation.cores = 2;

    # As on rootless.nix's node: nothing here runs through sudo.
    security.sudo.enable = false;

    users.users.alice = {
      isNormalUser = true;
      uid = 1000;
      group = "users";
      linger = true;
      autoSubUidGidRange = false;
      subUidRanges = [ { startUid = 100000; count = 65536; } ];
      subGidRanges = [ { startGid = 100000; count = 65536; } ];
    };

    environment.systemPackages = [
      pkgs.strace
      pkgs.util-linux
      pkgs.bubblewrap
      integration.vm
    ];
  };

  testScript = ''
    import shlex

    # SCRIPT as alice, through her own user manager, in a unit with
    # Delegate=yes (the unit's cgroup is hers to divide), with the wrappers
    # first on PATH so util-linux finds the newuidmap wrapper. PROPS are more
    # unit properties.
    def as_alice(script, props=""):
        inner = "export PATH=/run/wrappers/bin:/run/current-system/sw/bin; cd /tmp; " + script
        return (f"systemd-run -M alice@ --user --wait --pipe --quiet --collect "
                f"-p Delegate=yes {props} --expand-environment=no "
                f"-- /run/current-system/sw/bin/bash -c {shlex.quote(inner)} </dev/null")

    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("user@1000.service")

    with subtest("setup: a delegated unit of alice's, and her subordinate ids"):
        # The wrappers hold cap_setuid and cap_setgid, not the setuid bit
        # (nixos/modules/programs/shadow.nix:284).
        machine.succeed("test -x /run/wrappers/bin/newuidmap && test -x /run/wrappers/bin/newgidmap")
        # The unit's own cgroup takes a child: the leaf a proof creates.
        out = machine.succeed(as_alice(
            "cg=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup); "
            "mkdir $cg/leaf && rmdir $cg/leaf && "
            "systemctl --user show -p Delegate $(basename $cg)")).strip()
        assert out == "Delegate=yes", out
        # newuidmap maps her whole subordinate range.
        out = machine.succeed(as_alice(
            "unshare --user --map-auto --map-root-user cat /proc/self/uid_map")).split()
        assert out[:2] == ["0", "1000"] and "100000" in out and "65536" in out, out
  '' + lib.concatMapStrings (p: "\n# ${p.name}\n" + p.script) integration.vm.vmScripts;
}
