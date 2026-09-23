# The proofs that need a kernel the build sandbox does not give: one node, a
# lingering user with subordinate ids and a delegated user manager, the
# proofs' binaries on PATH (tests/integration.nix's `vm`), and each proof's
# testScript fragment after the common setup below, in tests/proofs/ name
# order (ZIG.md, "Tests", checks.native). Before them, flong-init past its
# argv. A fourth VM beside basic, rootless and parity; nothing in it is
# about time.
#
# Fragments are Python run in this testScript's scope, so they may use
# `machine`, `shlex` and `as_alice`; each opens its own subtest.
{ hostPkgs, lib, ... }:

let
  integration = import ./integration.nix { pkgs = hostPkgs; };
  # The launcher's output, for its flong-init (src/init.zig).
  launcher = import ../launcher { pkgs = hostPkgs; };
  # rootless.nix's ioctl-probe and swapper; the swapper races the walker
  # (ZIG.md phase 4).
  probes = import ./probes.nix;
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
      pkgs.util-linux
      integration.vm
      (probes pkgs)
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

    with subtest("flong-init past its argv: the gate's EOF, and a failing chdir printed whole"):
        # What golden's init set cannot reach (tests/golden.nix): as root of
        # a namespace newuidmap made, setgroups and the capability drop
        # succeed, as in the launcher's U1 (src/init.zig:210-213). GATE is 4,
        # reading GATE_FILE; READY is 5, writing to /dev/null; no groups,
        # terminal or trace. Prints stderr and the status as the last line.
        def init_run(gate_file, dir):
            return machine.succeed(as_alice(
                "unshare --user --map-auto --map-root-user -- "
                f"${launcher}/bin/flong-init 4 5 - - - {shlex.quote(dir)} -- true "
                f"4<{gate_file} 5>/dev/null 2>&1; echo rc=$?"))

        machine.succeed("printf g > /tmp/init-gate && chmod 644 /tmp/init-gate")
        # The gate closed without its byte (:230-233).
        out = init_run("/dev/null", "/")
        assert out == "flong-init: the gate closed without opening: not starting the payload\nrc=125\n", out
        # The gate open, DIR missing (:235-239): the message is over 1 KiB
        # and printed whole (ZIG.md quirk 22), then too long a DIR.
        for dir, text in (("/nonexistent/" + "/".join(["d" * 200] * 6), "No such file or directory"),
                          ("/" + "/".join(["d" * 200] * 21), "File name too long")):
            out = init_run("/tmp/init-gate", dir)
            assert len(dir) > 1024 and out == f"flong-init: changing to {dir}: {text}\nrc=125\n", out
        # The control: the gate open, DIR there, tini runs the payload.
        out = init_run("/tmp/init-gate", "/tmp")
        assert out.endswith("rc=0\n"), out
  '' + lib.concatMapStrings (p: "\n# ${p.name}\n" + p.script) integration.vm.vmScripts;
}
