# The proofs that need a kernel the build sandbox does not give: one node, a
# lingering user with subordinate ids and a delegated user manager, the
# proofs' binaries on PATH (tests/integration.nix's `vm`), and each proof's
# testScript fragment after the common setup below, in tests/proofs/ name
# order (DESIGN.md, "Tests": checks.native). Before them, flong-init past its
# argv, the walker, and flong-proc: clone3 into a cgroup, a fork after
# setns(CLONE_NEWUSER), a session swept, and the sweeper over the records
# the C sweeper's output pins (phase 5); src/tty.zig through flong-tty and
# ptydrive (phase 7's L3). A fourth VM beside basic, rootless and parity;
# nothing in it is about time.
#
# Fragments are Python run in this testScript's scope, so they may use
# `machine`, `shlex` and `as_alice`; each opens its own subtest.
{ hostPkgs, lib, ... }:

let
  integration = import ./integration.nix { pkgs = hostPkgs; };
  # The launcher's output, for its flong-init (src/init.zig).
  launcher = import ../launcher { pkgs = hostPkgs; };
  # rootless.nix's ioctl-probe and swapper; the swapper races the walker
  # (the Zig port's phase 4).
  probes = import ./probes.nix;

  # The walker's fixture and runs (DESIGN.md, "Tests": checks.native;
  # the port's phase 4): flong-walker (tests/zig/walker.zig) drives src/mount.zig's walk,
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
    # race SWAPPER NAME: the race against SWAPPER, the missing walks making
    # NAME<i>; each run's lines follow "race SWAPPER PATH".
    race() {
      echo "race $1 $(readlink -f "$(command -v "$1")")"
      state() { if [ -L $R/ws/sub ]; then echo link; else echo dir; fi; }
      was=$(state)
      "$1" $R/ws &
      swapping=$!
      # Swapping once sub has changed from what the last run left.
      until [ "$(state)" != "$was" ]; do :; done
      echo "naive $(flong-walker naive $R /ws/sub/deep/x 200 $R/view)"
      echo "exists $(flong-walker race $R /ws/sub/deep/x 200 $R/view exists 2>$R/race.err)"
      echo "missing $(flong-walker race $R /ws/sub/deep/$2 200 $R/view missing 2>>$R/race.err)"
      kill $swapping
      # Killed while still swapping: SIGTERM's 143, not a swapper that
      # stopped after the first exchange.
      rc=0
      wait $swapping || rc=$?
      echo "killed $rc"
      echo "said $(sed "s/$2[0-9]*\$/yN/" $R/race.err | sort -u | tr '\n' '|')"
      echo "view $(ls $R/view/deep | tr '\n' ' ')"
    }
    race swapper y
  '';

  # The sweeper's differential fixture (the port's phase 5; DESIGN.md,
  # "Tests": the record contract): sweep-diff PROGRAM builds one state directory of records a
  # launcher writes and hostile ones, and the sessions they name under a
  # holder h of the calling unit's, runs PROGRAM as the holder's sweeper in
  # h/supervisor until it blocks in its inotify read, adds a record, lets it
  # sweep that, stops it, and prints what it said and left. Until phase 5
  # (b) deleted the C sweeper, the C and the Zig printed the same.
  # postStop programs (flong-record.c:436-484): one that logs its argv,
  # environment, stdin and directory, one exiting 3, one killed by SIGTERM,
  # a store symlink out of the store and one into it, a file that is not
  # executable, a directory.
  psLog = hostPkgs.writeShellScript "flong-ps-log" ''
    IFS= read -r line
    rc=$?
    echo "$0 argc=$# 1=$1 machine=$machine pwd=$PWD stdin-rc=$rc env="$(export -p) >>/tmp/ps.log
  '';
  psFail = hostPkgs.writeShellScript "flong-ps-fail" "exit 3";
  psSig = hostPkgs.writeShellScript "flong-ps-sig" "kill -TERM $$";
  psOut = hostPkgs.runCommand "flong-ps-out" { } "ln -s /tmp/ps-outside $out";
  psIn = hostPkgs.runCommand "flong-ps-in" { } "ln -s ${psLog} $out";
  psNoexec = hostPkgs.writeText "flong-ps-noexec" "#!/bin/sh\n";
  psDir = hostPkgs.runCommand "flong-ps-dir" { } "mkdir $out";
  # A program exiting 3 whose path is PATH_MAX - 1 bytes, which realpath
  # takes (flong-record.c:444). A build cannot make it, the daemon's own
  # path to it being too long, and the VM's store is read-only: root mounts
  # a tmpfs on the empty store directory `deep` and makes it there.
  deep = hostPkgs.runCommand "flong-ps-deep" { } "mkdir $out";
  mkDeep = hostPkgs.writeShellScript "mk-ps-deep" ''
    set -eu
    p=${deep}
    mount -t tmpfs -o mode=0755 flong-ps-deep $p
    while [ $((4095 - ''${#p} - 1)) -gt 255 ]; do
      p=$p/$(printf 'd%.0s' $(seq 200))
      mkdir -p $p
    done
    p=$p/$(printf 'f%.0s' $(seq $((4095 - ''${#p} - 1))))
    printf '#!${hostPkgs.runtimeShell}\nexit 3\n' >$p
    chmod 0555 $p
    test ''${#p} = 4095
  '';
  sweepDiff = hostPkgs.writeShellScript "sweep-diff" ''
    set -u
    prog=$1
    cg=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)
    # The unit's cgroup and the job's pids differ from run to run.
    main() {
    H=$cg/h
    S=/tmp/sweep-state
    D=$S/sessions
    rm -rf $S /tmp/ps.log /tmp/ps-outside
    printf '#!/bin/sh\necho outside >>/tmp/ps.log\n' >/tmp/ps-outside
    chmod +x /tmp/ps-outside
    mkdir -m 0700 $S $D
    mkdir -p $H/supervisor $H/c/s-full/sandbox $H/c/s-full/hooks $H/c/s-full/extra/inner \
      $H/c/s-noleader/sandbox
    sleep 600 & a=$!; echo $a >$H/c/s-full/sandbox/cgroup.procs
    sleep 600 & b=$!; echo $b >$H/c/s-full/hooks/cgroup.procs
    sleep 600 & c=$!; echo $c >$H/c/s-full/extra/inner/cgroup.procs
    rec() { printf '%b' "$2" >$D/$1; }
    long=$(printf 'a%.0s' $(seq 4000))
    # As a launcher writes them (flong-record.c:324-398), and blanked.
    rec s-full "poststop=${psLog}\ncgroup=$H/c/s-full\nleader=$a:$(cut -d' ' -f22 /proc/$a/stat)\n"
    rec s-noleader "poststop=${psFail}\ncgroup=$H/c/s-noleader\n"
    rec s-absent "poststop=${psSig}\ncgroup=$H/c/s-absent\nleader=$$:1\n"
    rec s-nocontainer "cgroup=$H/none/s-nocontainer\n"
    rec s-other "poststop=${psLog}\ncgroup=$cg/other/c/s-other\n"
    rec blanked "\n\n\ncgroup=$H/c/blanked\n"
    # cgroup= that is no session's (flong-cgroup.c:415-462).
    rec s-dotdot "cgroup=$H/../h/c/s-dotdot\n"
    rec s-machine "cgroup=$H/c/someone-else\n"
    rec s-short "cgroup=/sys/fs/cgroup/c/s-short\n"
    rec s-container "cgroup=$H/.c/s-container\n"
    rec s-outside "cgroup=/tmp/h/c/s-outside\n"
    rec s-longcg "cgroup=/sys/fs/cgroup/$long\n"
    # poststop= that is no program in the store (:436-449), and ones that are.
    rec ps-notstore "poststop=/tmp/ps-outside\ncgroup=$H/c/ps-notstore\n"
    rec ps-dotdot "poststop=/nix/store/../tmp/ps-outside\ncgroup=$H/c/ps-dotdot\n"
    rec ps-symout "poststop=${psOut}\ncgroup=$H/c/ps-symout\n"
    rec ps-symin "poststop=${psIn}\ncgroup=$H/c/ps-symin\n"
    rec ps-noexec "poststop=${psNoexec}\ncgroup=$H/c/ps-noexec\n"
    rec ps-dir "poststop=${psDir}\ncgroup=$H/c/ps-dir\n"
    rec ps-deep "poststop=$(find ${deep} -type f)\ncgroup=$H/c/ps-deep\n"
    rec ps-missing "poststop=/nix/store/nothing-here\ncgroup=$H/c/ps-missing\n"
    rec ps-long "poststop=/tmp/$long\ncgroup=$H/c/ps-long\n"
    # Not a record's form (:264-308).
    rec bad-nul "cgroup=/x\0\n"
    rec bad-nonl "cgroup=$H/c/bad-nonl"
    rec bad-unknown "x=1\ncgroup=$H/c/bad-unknown\n"
    rec bad-order "cgroup=$H/c/bad-order\npoststop=${psLog}\n"
    rec bad-twice "cgroup=$H/c/bad-twice\ncgroup=$H/c/bad-twice\n"
    rec bad-leader "cgroup=$H/c/bad-leader\nleader=01:1\n"
    rec bad-leader2 "cgroup=$H/c/bad-leader2\nleader=1:18446744073709551616\n"
    rec bad-empty ""
    rec bad-novalue "poststop=\ncgroup=$H/c/bad-novalue\n"
    rec bad-longpath "cgroup=/$long$long\n"
    head -c 8300 /dev/zero >$D/bad-big
    rec unreadable "cgroup=$H/c/unreadable\n"
    chmod 000 $D/unreadable
    # Not records, or not ours to open (:641-654, 712-715).
    rec .hidden "cgroup=$H/c/.hidden\n"
    rec '#123' "cgroup=$H/c/x\n"
    rec "$(printf 'n%.0s' $(seq 129))" "cgroup=$H/c/x\n"
    ln -s s-other $D/linkrec
    ln -s nowhere $D/dangling
    mkdir $D/dirrec
    mkfifo $D/fiforec
    # A record whose lock is held: tried once, left (:657-664).
    rec locked "cgroup=$H/c/locked\n"
    flock -s $D/locked sleep 600 </dev/null >/dev/null 2>&1 & l=$!
    for i in $(seq 3000); do grep -q ":$(stat -c %i $D/locked) " /proc/locks && break; sleep 0.05; done

    # The sweeper in the holder's supervisor leaf (flong-cgroup.c:279-298).
    (echo $BASHPID >$H/supervisor/cgroup.procs; exec "$prog" $S) 2>/tmp/sweeper.err &
    swp=$!
    blocked() {
      local s fd
      read -r s fd _ </proc/$swp/syscall 2>/dev/null || return 1
      [ "$s" = 0 ] && [ "$(readlink /proc/$swp/fd/$((fd)))" = "anon_inode:inotify" ]
    }
    waitblocked() {
      for i in $(seq 3000); do blocked && return 0; sleep 0.1; done
      echo "never blocked in its inotify read"
    }
    waitblocked
    # A record closed after the first sweeps: an event by its name, a sweep
    # with LOCK_NB (flong-record.c:736-753).
    rec late "cgroup=$H/c/late\n"
    for i in $(seq 3000); do [ -e $D/late ] || break; sleep 0.1; done
    waitblocked
    kill -TERM $swp
    wait $swp
    echo "== sweeper status $?"
    for p in $a $b $c; do wait $p; echo "== sleep status $?"; done
    echo "== said"
    cat /tmp/sweeper.err
    echo "== left"
    chmod 600 $D/unreadable
    (cd $D && for f in $(ls -A | LC_ALL=C sort); do
      if [ -f "$f" ] && [ ! -L "$f" ]; then
        echo "$f $(stat -c '%F %s %a' "$f") $(od -An -c "$f" | head -c 300 | tr -s ' \n' ' ')"
      else
        echo "$f $(stat -c '%F' "$f")"
      fi
    done)
    echo "== cgroups"
    find $H -mindepth 1 -type d | sed "s|^$H/||" | LC_ALL=C sort
    echo "== poststop"
    cat /tmp/ps.log 2>/dev/null
    pkill -P $l; kill $l; wait $l
    find $H -depth -type d -exec rmdir {} +
    rm -rf $S /tmp/ps.log /tmp/ps-outside /tmp/sweeper.err
    }
    main 2>&1 | sed -e "s|$cg|CG|g" -e '/ Killed  *sleep 600$/d'
  '';

  # postStop once, and the watch before the first sweep (the port's phase 5,
  # DESIGN.md's ordering checkpoint 11; flong-record.c:193-217, 755-825): sweep-order
  # PROGRAM runs PROGRAM as the holder's sweeper over three records, all
  # dead but one. `gated`'s postStop (psGate) holds the first sweep until
  # told. `late` comes before it in the directory's order and its lock is
  # held by a stand-in launcher, so the first sweep tries it once and leaves
  # it; the stand-in is SIGKILLed while that sweep is held, and only a watch
  # added before the sweep hears the close. `once` cannot be removed (its
  # sandbox leaf is mode 0500 around a nested cgroup), so its record
  # outlives its postStop: blanked, no later sweep runs postStop again,
  # and it goes once the leaf is writable.
  psGate = hostPkgs.writeShellScript "flong-ps-gate" ''
    echo "$machine" >>/tmp/order/ran
    if [ -e /tmp/order/gate-$machine ]; then
      : >/tmp/order/in-$machine
      while [ -e /tmp/order/gate-$machine ]; do ${hostPkgs.coreutils}/bin/sleep 0.05; done
    fi
  '';
  sweepOrder = hostPkgs.writeShellScript "sweep-order" ''
    set -u
    prog=$1
    cg=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)
    H=$cg/h
    S=/tmp/order/state
    D=$S/sessions
    rm -rf /tmp/order
    mkdir -p /tmp/order
    mkdir -m 0700 $S $D
    mkdir -p $H/supervisor $H/c/once/sandbox/inner
    chmod 0500 $H/c/once/sandbox
    ps=${psGate}
    printf 'poststop=%s\ncgroup=%s\n' $ps $H/c/once >$D/once
    # Of two names, the first in the order a sweep reads is `late`.
    : >$D/r1
    : >$D/r2
    read -r late gated < <(ls -f $D | grep -x 'r[12]' | tr '\n' ' ')
    printf 'cgroup=%s\n' $H/c/$late >$D/$late
    printf 'poststop=%s\ncgroup=%s\n' $ps $H/c/$gated >$D/$gated
    : >/tmp/order/gate-$gated
    # The stand-in launcher: late's lock, on a descriptor open for writing.
    (exec 9<>$D/$late; flock -x 9; exec sleep 600) &
    stand=$!
    for i in $(seq 600); do flock -n $D/$late true || break; sleep 0.05; done

    (echo $BASHPID >$H/supervisor/cgroup.procs; exec "$prog" $S) 2>/tmp/order/err &
    swp=$!
    blocked() {
      local s fd
      read -r s fd _ </proc/$swp/syscall 2>/dev/null || return 1
      [ "$s" = 0 ] && [ "$(readlink /proc/$swp/fd/$((fd)))" = "anon_inode:inotify" ]
    }
    waitblocked() {
      for i in $(seq 600); do blocked && return 0; sleep 0.05; done
      echo "never blocked in its inotify read"
    }
    for i in $(seq 600); do [ -e /tmp/order/in-$gated ] && break; sleep 0.05; done
    echo "gate entered: $([ -e /tmp/order/in-$gated ] && echo yes || echo no)"
    echo "late in the first sweep: $([ -e $D/$late ] && echo left || echo gone)"
    kill -KILL $stand
    wait $stand 2>/dev/null
    for i in $(seq 600); do flock -n $D/$late true && break; sleep 0.05; done
    rm /tmp/order/gate-$gated
    # Nothing but the stand-in's close wakes the sweeper now.
    for i in $(seq 100); do [ -e $D/$late ] || break; sleep 0.1; done
    echo "late: $([ -e $D/$late ] && echo left || echo released)"
    waitblocked
    { head -c $((10 + ''${#ps})) /dev/zero | tr '\0' '\n'; printf 'cgroup=%s\n' $H/c/once; } >/tmp/order/blanked
    echo "once: $(cmp -s /tmp/order/blanked $D/once && echo blanked || echo not blanked)"
    ran() { echo "ran: gated=$(grep -cx $gated /tmp/order/ran) once=$(grep -cx once /tmp/order/ran) late=$(grep -cx $late /tmp/order/ran)"; }
    ran
    chmod 0700 $H/c/once/sandbox
    # A close of something open for writing: a sweep.
    : >>$D/.nudge
    for i in $(seq 100); do [ -e $D/once ] || break; sleep 0.1; done
    waitblocked
    echo "once: $([ -e $D/once ] && echo left || echo released), cgroup $([ -e $H/c/once ] && echo left || echo gone)"
    ran
    kill -TERM $swp
    wait $swp
    echo "said:"
    sed -e "s|$H|H|g" /tmp/order/err | LC_ALL=C sort -u
    find $H -depth -type d -exec rmdir {} +
    rm -rf /tmp/order
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
      # The caller's terminal and shell for flong-tty, rootless.nix's L0
      # driver (the Zig port's L3).
      (pkgs.writers.writePython3Bin "ptydrive" { flakeIgnore = [ "E501" ]; } (builtins.readFile ./ptydrive.py))
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
        # and printed whole (quirk 22), then too long a DIR.
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
        # The race's runs, one per swapper.
        runs = {}
        for l in out[len(want):].splitlines():
            k, v = l.split(" ", 1)
            if k == "race":
                sw, path = v.split(" ", 1)
                race = runs[sw] = {"path": path}
            else:
                race[k] = v
        assert list(runs) == ["swapper"], runs
        for sw, race in runs.items():
            counts = {k: dict(kv.split("=") for kv in race[k].split()) for k in ("naive", "exists", "missing")}
            print(f"{sw}: " + ", ".join(f"{k} {race[k]}" for k in ("naive", "exists", "missing")))
            # The control: the race is live, and a walk by path escapes it.
            assert int(counts["naive"]["escaped"]) > 0, (sw, race)
            # And both states were seen: a swapper stalled on the symlink
            # lets every naive walk escape.
            assert int(counts["naive"]["contained"]) > 0, (sw, race)
            for k in ("exists", "missing"):
                c = counts[k]
                assert c["escaped"] == "0" and c["odd"] == "0", (sw, race)
                assert int(c["refused"]) + int(c["contained"]) == 200, (sw, race)
            # Every refusal was the symlink's, and nothing was made in the view.
            said = set(l for l in race["said"].split("|") if l)
            assert said <= {"flong-walker: a symlink is on the way to /ws/sub/deep/x",
                            "flong-walker: a symlink is on the way to /ws/sub/deep/yN"}, (sw, race)
            assert (len(said) > 0) == (int(counts["exists"]["refused"]) + int(counts["missing"]["refused"]) > 0), (sw, race)
            assert race["view"] == "x ", (sw, race)
            assert race["killed"] == "143", (sw, race)
        # The swapper that ran: the Zig's, static without glibc.
        zig = runs["swapper"]["path"]
        assert zig.endswith("/bin/swapper"), zig
        machine.fail(f"grep -q GLIBC_2 {zig}")

    # proc.zig, sig.zig and cgroup.zig's sweep half (phase 5), through
    # flong-proc (tests/zig/procdriver.zig): P3's questions (tests/proofs/p3,
    # retired in phase 5) asked of the real modules, and a session swept.
    with subtest("proc: the noreturn fork, as alice"):
        for mode, status in (("fork", "7"), ("fork-panic", "125")):
            out = machine.succeed(as_alice(f"flong-proc {mode} 2>&1")).splitlines()
            print("\n".join(out))
            assert len([l for l in out if l.startswith("child ran: ")]) == (1 if mode == "fork" else 0), out
            assert out[-2:-1] == [f"child exited {status}"], out
            assert out[-1].startswith("parent defer ran: "), out
            assert (mode == "fork") != ("flong-proc: internal error: planted" in out), out

    with subtest("proc: fork and Spawn with clone3(CLONE_INTO_CGROUP) into an O_PATH leaf of a delegated unit"):
        out = machine.succeed(as_alice(
            "cg=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup); mkdir $cg/leaf; "
            "flong-proc cgroup $cg/leaf; rc=$?; rmdir $cg/leaf; exit $rc")).splitlines()
        print("\n".join(out))
        child = [l for l in out if l.startswith("child cgroup: ")]
        parent = [l for l in out if l.startswith("parent cgroup: ")]
        spawned = [l for l in out if l.startswith("cgroup: ")]
        assert len(child) == 1 and len(parent) == 1 and len(spawned) == 1, out
        assert child[0] == parent[0].replace("parent", "child", 1) + "/leaf", out
        assert spawned[0] == parent[0].replace("parent ", "", 1) + "/leaf", out
        assert "/user@1000.service/" in child[0], out
        # The control: a cgroup that is not alice's refuses the child.
        out = machine.fail(as_alice("flong-proc cgroup /sys/fs/cgroup/system.slice 2>&1"))
        print(out)
        assert "flong-proc: clone3: Permission denied" in out, out

    with subtest("proc: a fork after setns(CLONE_NEWUSER), into the leaf"):
        out = machine.succeed(as_alice(
            "unshare --user --map-auto --map-root-user sleep 600 & h=$!; "
            "for i in $(seq 100); do grep -q 100000 /proc/$h/uid_map && break; sleep 0.1; done; "
            "cg=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup); mkdir $cg/leaf; "
            "flong-proc userns /proc/$h/ns/user $cg/leaf 2>&1; rc=$?; "
            "kill $h; wait $h; rmdir $cg/leaf; exit $rc")).splitlines()
        print("\n".join(out))
        assert "parent uid after setns: 0" in out, out
        assert "child uid: 0" in out, out
        assert "child uid_map: 0 1000 1 / 1 100000 65536" in out, out
        assert "child hostname: p3-userns" in out, out
        assert any(l.startswith("child cgroup: ") and l.endswith("/leaf") for l in out), out
        assert out[-1] == "child exited 0", out

    with subtest("cgroup: a session killed, waited for and removed, a cgroup nested in its leaf included"):
        # A holder h of alice's with a container c and a session m, as a
        # launch lays it out (flong-cgroup.h:1-17), but for pasta's leaf;
        # a process in each leaf and one in a cgroup the payload made in its
        # own. The sweep's half opens it by the record's path, kills it,
        # waits for cgroup.events and removes it; the container stays.
        out = machine.succeed(as_alice(
            "cg=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup); "
            "mkdir -p $cg/h/c/m/sandbox/inner $cg/h/c/m/hooks; "
            "sleep 600 & a=$!; echo $a > $cg/h/c/m/sandbox/cgroup.procs; "
            "sleep 600 & b=$!; echo $b > $cg/h/c/m/sandbox/inner/cgroup.procs; "
            "sleep 600 & c=$!; echo $c > $cg/h/c/m/hooks/cgroup.procs; "
            "flong-proc session $cg/h c m 2>&1; echo rc=$?; "
            "for p in $a $b $c; do wait $p; echo status=$?; done; "
            "test -e $cg/h/c/m && echo session remains; test -d $cg/h/c && echo container remains; "
            "flong-proc session $cg/h c m 2>&1; echo rc=$?; "
            "rmdir $cg/h/c $cg/h")).splitlines()
        print("\n".join(out))
        assert out == ["opened: session", "leaf sandbox: open", "leaf hooks: open", "leaf pasta: absent",
                       "killed", "empty", "removed: gone", "rc=0", "status=137", "status=137", "status=137",
                       "container remains", "opened: absent", "rc=0"], out

    with subtest("sweeper: the records swept as the C swept them"):
        # sweep-diff (above) as alice. Until phase 5 (b) it ran the C
        # sweeper too, and every line was the same; what the C said is kept
        # in tests/golden/sweep-diff.said (c9571be, store paths as @VAR@).
        # The first sweep's lines come in sessions/'s readdir order, and
        # the later sweeps' count in how inotify batches their events, so
        # the first sweep is compared as a multiset and the rest as a set,
        # each ending as the C's did. The controls below are against a
        # vacuous run, such as one stopping at the holder.
        machine.succeed("${mkDeep}")
        out = machine.succeed(as_alice("${sweepDiff} ${launcher}/bin/flong-sweeper 2>&1"))
        print(out)
        golden = ${builtins.toJSON (builtins.readFile ./golden/sweep-diff.said)}
        for var, path in (("@PSNOEXEC@", "${psNoexec}"), ("@PSOUT@", "${psOut}"), ("@PSDIR@", "${psDir}")):
            golden = golden.replace(var, path)
        def sweeps(said):
            first, rest = said.split("flong-sweeper: released 14 dead sessions\n")
            return sorted(first.splitlines()), set(rest.splitlines()), rest.splitlines()[-1]
        said = out.split("== said\n")[1].split("== left\n")[0]
        assert sweeps(said) == sweeps(golden), said
        assert "never blocked" not in out, out
        for want in ("== sweeper status 143", "== sleep status 137",
                     "flong-sweeper: released 1 dead session\n",
                     "flong-sweeper: postStop failed for s-noleader (status 3)",
                     "flong-sweeper: postStop failed for s-absent (status 143)",
                     "flong-sweeper: postStop failed for ps-dir (status 127)",
                     "flong-sweeper: postStop failed for ps-deep (status 3)",
                     "flong-sweeper: exec ${psDir}: Permission denied",
                     "flong-sweeper: postStop failed for ps-symout: ${psOut} is not a program in /nix/store",
                     "flong-sweeper: the record of bad-nul is removed: it is not lines of text",
                     "flong-sweeper: the record of bad-leader2 is removed: its leader= is not <pid>:<starttime>",
                     "flong-sweeper: the record s-dotdot does not name a session's cgroup:",
                     "flong-sweeper: read the record of bad-big: File too large",
                     "flong-sweeper: open the record of unreadable: Permission denied",
                     "${psLog} argc=1 1=s-full machine=s-full pwd=/ stdin-rc=1",
                     "${psLog} argc=1 1=ps-symin machine=ps-symin pwd=/ stdin-rc=1",
                     "\ns-other regular file", "\nlocked regular file", "\nlinkrec symbolic link",
                     "\n== cgroups\nc\nsupervisor\n== poststop"):
            assert want in out, want
        # Cut at 1023 bytes, newline included (quirk 22).
        assert max(len(l) for l in out.split("\n")) == 1022, out
        assert "outside" not in out.split("== poststop")[1], out

    with subtest("sweeper: postStop once across a failed removal, and the watch before the first sweep"):
        # sweep-order (above) as alice; the C sweeper, until phase 5 (b),
        # said the same. A sweep that skips the blank runs once's postStop
        # twice; a watch added after the first sweep leaves late
        # (checkpoint 11).
        out = machine.succeed(as_alice("${sweepOrder} ${launcher}/bin/flong-sweeper 2>&1"))
        print(out)
        assert out.splitlines() == [
            "gate entered: yes",
            "late in the first sweep: left",
            "late: released",
            "once: blanked",
            "ran: gated=1 once=1 late=0",
            "once: released, cgroup gone",
            "ran: gated=1 once=1 late=0",
            "said:",
            "flong-sweeper: released 1 dead session",
            "flong-sweeper: rmdir H/c/once/sandbox/inner: Permission denied",
        ], out

    with subtest("tty: the relay both ways, EIO, the drain, the window, the watchdog, a hang-up then SIGWINCH, and a terminal alice cannot reopen"):
        # The Zig port's L3: src/tty.zig through flong-tty
        # (tests/zig/ttydriver.zig), which drives it as the launcher does,
        # PROGRAM standing in for bwrap and the payload; ptydrive
        # (tests/ptydrive.py) plays the caller's terminal and shell, as for
        # rootless.nix's L0 subtest of the C, whose lines the first runs
        # repeat. Each run's lines are compared whole, after its pid= line.
        # CTTY runs the payload under `setsid -c`, the pty its controlling
        # terminal, as flong-init makes it, for a hang-up to reach it.
        SH = "/run/current-system/sw/bin/sh"
        def drive(scenario, payload, stderr=None, ctty=False, root=False):
            opt = f"--stderr {stderr} " if stderr else ""
            prog = f"/run/current-system/sw/bin/setsid -c {SH}" if ctty else SH
            launch = f"flong-tty --report {prog} -c {shlex.quote(payload)}"
            if root:
                out = machine.succeed(f"ptydrive {scenario} {opt}-- setpriv --reuid=alice --regid=users --init-groups {launch}")
            else:
                out = machine.succeed(as_alice(f"ptydrive {scenario} {opt}-- {launch}"))
            lines = out.splitlines()
            assert lines[0].startswith("pid="), (scenario, out)
            return lines[1:]

        READ = "echo ready; read -r l; exit 7"
        # The relay both ways: every input byte reaches the payload, the ^]
        # run another key broke included, and its output the terminal
        # (flong-tty.c:384-492); three ^] in a row are the escape's 137.
        lines = drive("keys", "echo ready; read -r l; [ \"$l\" = \"$(printf '\\035\\035x\\035')\" ] && exit 7; exit 8")
        assert lines == ["status=7"], lines
        lines = drive("escape", READ)
        assert lines == ["status=137"], lines
        OUT = "echo ready; read -r l; echo out; echo err >&2; [ -t 2 ] && echo err-tty || echo err-file"
        lines = drive("output", OUT)
        assert lines == ["line=out", "line=err", "line=err-tty", "status=0"], lines
        # A redirected stderr stays where the caller sent it (quirk 43);
        # the relay's output went through the terminal alice reopened.
        machine.succeed("rm -f /tmp/tty-err")
        lines = drive("output", OUT, "/tmp/tty-err")
        assert lines == ["line=out", "line=err-file", "status=0"], lines
        err = machine.succeed("cat /tmp/tty-err")
        assert err == "flong-tty: tty.out: reopened\nerr\n", err

        # A root-owned terminal, the launch run as alice through setpriv:
        # the /proc/self/fd/1 reopen is refused, and the output still
        # arrives, through fd 1 (quirk 42, flong-tty.c:196-203, 384).
        machine.succeed("rm -f /tmp/tty-err")
        lines = drive("output", OUT, "/tmp/tty-err", root=True)
        assert lines == ["line=out", "line=err-file", "status=0"], lines
        err = machine.succeed("cat /tmp/tty-err")
        assert err == "flong-tty: tty.out: fd 1\nerr\n", err
        machine.succeed("rm /tmp/tty-err")

        # The window size copied at the start, 30x100, and a resize of the
        # caller's terminal (:192-195, 276-282, 427-428).
        lines = drive("resize", "echo ready; stty size; read -r l; stty size; exit 7")
        assert lines == ["size=30 100", "size=40 120", "status=7"], lines

        # SIGKILLed while the terminal is raw, the relay leaves the watchdog
        # (checkpoint 8: 0-2, its pipe and the leader, nothing else), which
        # puts the caller's modes back (:243-259, 293-321). SIGCONT makes
        # the terminal raw again after the caller's shell restored it
        # (:429-433), and a clean end restores it (:515-521).
        lines = drive("watchdog", "echo ready; sleep infinity")
        assert lines == ["guard=0:tty 1:tty 2:tty pidfd pipe", "raw=yes", "status=137", "restored=yes"], lines
        lines = drive("sigcont", READ)
        assert lines == ["raw=yes", "stopped=yes", "raw=no", "raw=yes", "status=7", "restored=yes"], lines

        # EIO: the payload closes its terminal and lives on. The relay
        # stops reading the master, whose every slave is closed, and sleeps
        # in its poll instead of spinning on the master's POLLHUP; it still
        # forwards SIGTERM to the leader (:436-444, 425-426).
        lines = drive("eio", "echo ready; read -r l; echo bye; exec </dev/null >/dev/null 2>&1; touch \"$PTYDRIVE_DIR/closed\"; while :; do sleep 0.1; done")
        assert lines == ["closed=yes", "idle=yes", "status=143"], lines

        # The drain: the caller's terminal stopped (TCOOFF) while the
        # payload writes and exits, so the relay holds output when bwrap
        # is gone; restarted, every line arrives (:498-511). before=0 is
        # the control that the stop held the output back.
        lines = drive("drain", "echo ready; read -r l; seq 1 2000; echo $$ > \"$PTYDRIVE_DIR/done\"; exit 3")
        assert lines == ["before=0", "lines=2000 last=2000", "status=3"], lines

        # Hang-ups: the terminal gone, the payload's session sees SIGHUP
        # (:487-491). Then stdin at EOF on a terminal that is still there
        # (^D in canonical mode) closes the master, and a SIGWINCH after it
        # finds the master null (quirk 44): the payload's own status, 5,
        # not 125.
        lines = drive("hangup", "echo ready; sleep infinity", ctty=True)
        assert lines == ["status=129"], lines
        lines = drive("winch", "trap 'touch \"$PTYDRIVE_DIR/hup\"' HUP; echo ready; while [ ! -e \"$PTYDRIVE_DIR/go\" ]; do sleep 0.1; done; exit 5", ctty=True)
        assert lines == ["hup=yes", "status=5"], lines
  '' + lib.concatMapStrings (p: "\n# ${p.name}\n" + p.script) integration.vm.vmScripts;
}
