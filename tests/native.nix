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

  # The walker's fixture and runs (ZIG.md, "Tests", checks.native; phase
  # 4): flong-walker (tests/zig/walker.zig) drives src/mount.zig's walk,
  # masks and source check as root of a user and mount namespace of its
  # own, over a tmpfs at /tmp/walk. Each run prints "$ ARGS", what it said
  # and "rc=N"; the race prints its counts. Run under `unshare --user
  # --map-root-user --mount`.
  walkerScript = hostPkgs.writeShellScript "walker-runs" ''
    set -u
    R=/tmp/walk
    mkdir -p $R
    mount -t tmpfs walk $R
    cd $R
    mkdir -p a d pre prot protx view/deep/x ws/sub/deep/x
    echo file > f
    ln -s /etc link
    ln -s $R/view a/sl
    ln -s $R/prot toprot
    ln -s $R/view ws/sublink
    ln -s d rel
    ln -s f relf
    run() { echo "\$ $*"; flong-walker "$@" 2>&1; echo "rc=$?"; }
    # A symlink on the way, and last; a file on the way, and last; a
    # directory where a file's clone would go; what the walk makes.
    run walk $R /a/new/deeper dir create
    run walk $R /link/x dir create
    run walk $R /a/sl dir create
    run walk $R /f/x dir create
    run walk $R /f dir exist
    run walk $R /d file exist
    # A symlink last that stays inside the root, to a directory and to a
    # file: RESOLVE_BENEATH alone would follow both, so only
    # RESOLVE_NO_SYMLINKS refuses them. A '..', out of the root and out of
    # a directory on the way: spec_parse never passes one, so only
    # RESOLVE_BENEATH refuses it here (fd.zig, walkOpen).
    run walk $R /rel dir exist
    run walk $R /relf file exist
    run walk $R /.. dir exist
    run walk $R /a/../f file exist
    run walk $R /a/newfile file create
    test -d a/new/deeper && test -f a/newfile && echo made-both
    # EEXIST: the name made by another before the walker's own make.
    run made $R pre
    run made $R fresh
    run walk $R /pre/sub dir create
    # Masks of a file and of a directory, and of nothing.
    run mask $R /f
    stat -c 'mode %a' f d
    echo x 2>&1 > f | sed 's/.*: //'
    awk -v f=$R/f '$5 == f { print "f", $6 }' /proc/self/mountinfo
    run mask $R /d
    stat -c 'mode %a' d
    touch d/x 2>&1 | sed 's/.*: //'
    awk -v d=$R/d '$5 == d { print "d", $6 }' /proc/self/mountinfo
    run mask $R /absent
    # The protected paths, by the kernel's resolved path: through a
    # symlink, refused; exact, the symlink refused; a name that only
    # starts with a protected one, taken.
    run source $R/toprot following $R/prot
    run source $R/toprot exact $R/prot
    run source $R/protx following $R/prot
    # The swap race: sub and a symlink to the view exchanged as fast as
    # the swapper can. The control first: opened by path, it escapes.
    swapper $R/ws &
    swapping=$!
    until [ -L $R/ws/sub ]; do :; done
    echo "naive $(flong-walker naive $R /ws/sub/deep/x 200 $R/view)"
    echo "exists $(flong-walker race $R /ws/sub/deep/x 200 $R/view exists 2>$R/race.err)"
    echo "missing $(flong-walker race $R /ws/sub/deep/y 200 $R/view missing 2>>$R/race.err)"
    kill $swapping
    echo "said $(sed 's/y[0-9]*$/yN/' $R/race.err | sort -u | tr '\n' '|')"
    echo "view $(ls $R/view/deep | tr '\n' ' ')"
  '';
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

    with subtest("the walker: symlinks, a file on the way, masks, EEXIST, protected paths, and the swap race"):
        # src/mount.zig through flong-walker (tests/zig/walker.zig), as root
        # of alice's own user and mount namespace, over a tmpfs at
        # /tmp/walk (the script: walkerScript, above).
        out = machine.succeed(as_alice("unshare --user --map-root-user --mount ${walkerScript}"))
        print(out)
        R = "/tmp/walk"
        want = f"""$ walk {R} /a/new/deeper dir create
    ok {R}/a/new/deeper
    rc=0
    $ walk {R} /link/x dir create
    flong-walker: a symlink is on the way to /link/x
    rc=1
    $ walk {R} /a/sl dir create
    flong-walker: a symlink is on the way to /a/sl
    rc=1
    $ walk {R} /f/x dir create
    flong-walker: /f, on the way to /f/x, is not a directory
    rc=1
    $ walk {R} /f dir exist
    flong-walker: /f is not a directory
    rc=1
    $ walk {R} /d file exist
    flong-walker: /d is a directory and its source is not
    rc=1
    $ walk {R} /rel dir exist
    flong-walker: a symlink is on the way to /rel
    rc=1
    $ walk {R} /relf file exist
    flong-walker: a symlink is on the way to /relf
    rc=1
    $ walk {R} /.. dir exist
    flong-walker: /..: Invalid cross-device link
    rc=1
    $ walk {R} /a/../f file exist
    flong-walker: /a/../f: Invalid cross-device link
    rc=1
    $ walk {R} /a/newfile file create
    ok {R}/a/newfile
    rc=0
    made-both
    $ made {R} pre
    existed
    rc=0
    $ made {R} fresh
    session
    rc=0
    $ walk {R} /pre/sub dir create
    ok {R}/pre/sub
    rc=0
    $ mask {R} /f
    masked {R}/f
    rc=0
    mode 0
    mode 755
    Read-only file system
    f ro,nosuid,nodev,noexec,relatime
    $ mask {R} /d
    masked {R}/d
    rc=0
    mode 0
    Read-only file system
    d ro,nosuid,nodev,noexec,relatime
    $ mask {R} /absent
    flong-walker: /absent: No such file or directory
    rc=1
    $ source {R}/toprot following {R}/prot
    flong-walker: the mount source {R}/toprot is, holds or lies inside {R}/prot, which no session may reach
    rc=1
    $ source {R}/toprot exact {R}/prot
    flong-walker: a symlink is on the way to {R}/toprot
    rc=1
    $ source {R}/protx following {R}/prot
    ok {R}/protx
    rc=0
    """
        assert out.startswith(want), out
        race = dict(l.split(" ", 1) for l in out[len(want):].splitlines())
        counts = {k: dict(kv.split("=") for kv in race[k].split()) for k in ("naive", "exists", "missing")}
        # The control: the race is live, and a walk by path escapes it.
        assert int(counts["naive"]["escaped"]) > 0, race
        for k in ("exists", "missing"):
            c = counts[k]
            assert c["escaped"] == "0" and c["odd"] == "0", race
            assert int(c["refused"]) + int(c["contained"]) == 200, race
        # Every refusal was the symlink's, and nothing was made in the view.
        said = set(l for l in race["said"].split("|") if l)
        assert said <= {"flong-walker: a symlink is on the way to /ws/sub/deep/x",
                        "flong-walker: a symlink is on the way to /ws/sub/deep/yN"}, race
        assert (len(said) > 0) == (int(counts["exists"]["refused"]) + int(counts["missing"]["refused"]) > 0), race
        assert race["view"] == "x ", race
  '' + lib.concatMapStrings (p: "\n# ${p.name}\n" + p.script) integration.vm.vmScripts;
}
