# P2, flong-init's start code as pid 1 (ZIG.md, "Phase 0: proofs"): a
# stand-in init built with "Per binary"'s settings, run as pid 1 under
# `bwrap --as-pid-1` and the strict stack with log = true, under strace -f,
# beside the C flong-init of launcher/ run the same way.
#
#   build   the build-sandbox checks: both binaries static with no INTERP;
#           p2-init's PT_GNU_STACK carries no size (stack_size = 0), the
#           control's carries Zig's 16 MiB; a planted panic prints one line
#           and exits 125; p2-init passes a soft RLIMIT_STACK of 4096 KiB to
#           its exec unchanged, the control raises it to 16384
#   bins    p2-init, p2-init-default (the control), p2-flong-init-c (the C
#           init, symlinked from launcher/'s output) and p2-pid1, which runs
#           its argv as pid 1 the way flong-launch.c:274-331 runs flong-init
#   vmScript
#           the pid-1 checks, which need a user namespace, a pid namespace
#           and the kernel's audit records
#
# The fallback, the smallest stack that works with its prlimit64 audited, is
# not needed: Zig 0.15.2 takes stack_size = 0 and p2-init makes no syscall
# before main.
{ pkgs, lib, zigSet, ... }:
let
  flong = ../../..;

  init = zigSet {
    pname = "p2-init";
    root = ./.;
    files = [ ./init.zig ];
    nativeBuildInputs = [ pkgs.binutils pkgs.file ];
    extra = ''
      cd $out/bin
      for b in p2-init p2-init-default; do
        file -b $b | tee /dev/stderr | grep -q 'statically linked'
        if readelf -lW $b | grep -q INTERP; then echo "p2: $b has an INTERP"; exit 1; fi
      done
      # PT_GNU_STACK's MemSiz is what the start code raises RLIMIT_STACK to
      # (start.zig:545-578): 0 for p2-init, 16 MiB for the control.
      stack() { readelf -lW $1 | awk '$1 == "GNU_STACK" { print $6 }'; }
      [[ $(stack p2-init) == 0x000000 ]] || { readelf -lW p2-init; echo "p2: p2-init has a stack size"; exit 1; }
      [[ $(stack p2-init-default) == 0x1000000 ]] || { readelf -lW p2-init-default; exit 1; }

      # The planted panic: exactly one line on stderr, nothing on stdout, 125.
      rc=0; ./p2-init panic >out 2>err || rc=$?
      [[ $rc == 125 && ! -s out && $(cat err) == "flong-init: internal error: planted" && $(wc -l <err) == 1 ]] ||
        { echo "p2: panic gave $rc"; cat out err; exit 1; }
      rm out err

      # A soft limit below 16 MiB: passed on by p2-init, raised by the
      # control. (The VM checks `ulimit -s 4096`, soft and hard, as pid 1.)
      out=$(ulimit -S -s 4096; ./p2-init stack ${pkgs.runtimeShell} -c 'ulimit -s')
      [[ $(echo "$out" | tail -1) == 4096 && $out == *"stack=4096"* ]] || { echo "p2: p2-init: $out"; exit 1; }
      out=$(ulimit -S -s 4096; ./p2-init-default stack ${pkgs.runtimeShell} -c 'ulimit -s')
      [[ $(echo "$out" | tail -1) == 16384 ]] || { echo "p2: the control: $out"; exit 1; }
      ls -l p2-init p2-init-default >&2
    '';
  };

  # The C flong-init as the launcher builds it (launcher/default.nix), so
  # its tini is compiled in.
  launcher = import (flong + "/launcher") { inherit pkgs; };

  # The strict tier with log = true, as module.nix:622 builds it (through
  # seccomp/policy.nix:111-121) for a declaration with no loosening, then
  # the fixed filters in the wrapper's order (rootless-wrapper.bash:381-385). systemd is pkgs.systemd, the VM's
  # config.systemd.package, so the tier's names are the node's own.
  seccomp = import (flong + "/seccomp/policy.nix") {
    inherit pkgs lib;
    systemd = pkgs.systemd;
    compiler = import (flong + "/seccomp") { inherit pkgs; };
  };
  strictLog = seccomp.filterFor {
    tier = "strict";
    debug = false;
    nestedSandbox = false;
    allow = [ ];
    deny = [ ];
    log = true;
    errno = "EPERM";
  };
  stack = [ strictLog seccomp.fixed.audit seccomp.fixed.tty seccomp.fixed.nsmask ];

  # p2-pid1 PROGRAM ARGS...: PROGRAM as pid 1 through bwrap, with
  # flong-launch.c's namespaces, --as-pid-1, the seccomp stack one
  # --add-seccomp-fd each, and CAP_SETGID and CAP_SETPCAP for flong-init.c's
  # setgroups and capability drop. It runs as root of a user namespace that
  # newuidmap made (`unshare --map-auto --map-root-user`), where setgroups is
  # allowed as in the launcher's U1; bwrap then needs no --unshare-user. The
  # root is the node's, read-only, so PROGRAM and its exec are found as on
  # the node. Descriptors 20-23 hold the filters; bwrap leaks them, as it does
  # the launcher's (flong-init.c:26-27).
  pid1 = pkgs.writeShellScript "p2-pid1" ''
    exec 20<${lib.elemAt stack 0} 21<${lib.elemAt stack 1} 22<${lib.elemAt stack 2} 23<${lib.elemAt stack 3}
    exec ${pkgs.bubblewrap}/bin/bwrap \
      --unshare-net --unshare-pid --unshare-ipc --unshare-uts --unshare-cgroup \
      --die-with-parent --as-pid-1 \
      --add-seccomp-fd 20 --add-seccomp-fd 21 --add-seccomp-fd 22 --add-seccomp-fd 23 \
      --cap-add CAP_SETGID --cap-add CAP_SETPCAP \
      --ro-bind / / --proc /proc --dev /dev --tmpfs /tmp \
      -- "$@"
  '';

  bins = pkgs.runCommand "p2-bins" { } ''
    mkdir -p $out/bin
    ln -s ${init}/bin/p2-init ${init}/bin/p2-init-default $out/bin/
    ln -s ${launcher}/bin/flong-init $out/bin/p2-flong-init-c
    ln -s ${pid1} $out/bin/p2-pid1
  '';
in
{
  build = init;
  inherit bins;

  vmScript = ''
    with subtest("p2: flong-init's start code as pid 1, under the strict stack with log"):
        # As alice, root of a user namespace newuidmap made, with RLIMIT_STACK
        # at 4096 KiB soft and hard: RUN under strace -f, one file per
        # process in /tmp/p2/NAME.PID. Prints RUN's stdout and stderr, and
        # its status as the last line.
        def p2(name, run):
            return machine.succeed(as_alice(
                "mkdir -p /tmp/p2 && ulimit -s 4096 && "
                "unshare --user --map-auto --map-root-user -- "
                f"strace -f -ff -qq -o /tmp/p2/{name} {run}; echo rc=$?")).strip().split("\n")

        # The first syscall after the successful execve of PROGRAM, in the
        # trace of the process that made it: pid 1 of the sandbox.
        def first_after_exec(name, program):
            line = machine.succeed(
                f"f=$(grep -l 'execve(\"[^\"]*/{program}\".* = 0$' /tmp/p2/{name}.*) && "
                "test $(echo \"$f\" | wc -l) = 1 && "
                f"sed -n '/execve(\"[^\"]*\\/{program}\".* = 0$/{{n;p;q}}' $f")
            # strace pads the result to a column.
            return " ".join(line.split())

        # The kernel's SECCOMP_RET_LOG records (type=1326), as the learning
        # path reads them (tests/rootless.nix:966-970), made by any process
        # of run NAME (the pids strace -ff named its files by): the set of
        # syscall numbers. kauditd prints them in order, after the call.
        def logged(name):
            pids = machine.succeed(f"ls /tmp/p2 | sed -n 's/^{name}\\.//p'").split()
            assert pids, name
            alt = "|".join(pids)
            out = machine.succeed(
                "journalctl -k -o cat --no-pager | grep -F type=1326"
                f" | grep -E ' pid=({alt}) ' | grep -o 'syscall=[0-9]*' | cut -d= -f2 | sort -un"
                " || true")  # none is an answer, and grep says it with 1
            return set(out.split())

        machine.succeed("printf g > /tmp/p2-gate && chmod 644 /tmp/p2-gate")

        # The C flong-init, the control: GATE reads the byte in /tmp/p2-gate,
        # READY writes to /dev/null, no groups, no terminal, no trace, DIR
        # /tmp, then tini -g -- sh.
        c_out = p2("c", "p2-pid1 p2-flong-init-c 4 5 - - - /tmp -- /bin/sh -c 'ulimit -s' "
                        "4</tmp/p2-gate 5>/dev/null")
        assert c_out[-2:] == ["4096", "rc=0"], c_out
        c_first = first_after_exec("c", "p2-flong-init-c")

        # p2-init: pid 1, getpid first (nothing before main), the stack limit
        # unchanged in itself and in its exec.
        z_out = p2("zig", "p2-pid1 p2-init stack /bin/sh -c 'ulimit -s'")
        assert z_out == ["pid=1 stack=4096", "4096", "rc=0"], z_out
        z_first = first_after_exec("zig", "p2-init")
        assert z_first == "getpid() = 1", z_first
        # No SET of RLIMIT_STACK anywhere in pid 1's trace, only main's GET.
        z_trace = "$(grep -l 'execve(\"[^\"]*/p2-init\".* = 0$' /tmp/p2/zig.*)"
        machine.succeed(f"grep -q 'prlimit64(0, RLIMIT_STACK, NULL, ' {z_trace}")
        machine.fail(f"grep 'prlimit64(0, RLIMIT_STACK, {{' {z_trace}")

        # The control's start code, in the same setting: the checks above see
        # what single_threaded and stack_size = 0 remove.
        d_out = p2("default", "p2-pid1 p2-init-default stack /bin/sh -c 'ulimit -s'")
        assert d_out == ["pid=1 stack=4096", "4096", "rc=0"], d_out
        d_first = first_after_exec("default", "p2-init-default")
        assert d_first.startswith("arch_prctl(ARCH_SET_FS, "), d_first

        # The planted panic, as pid 1: the one line, 125, through bwrap.
        out = machine.succeed(as_alice(
            "unshare --user --map-auto --map-root-user -- p2-pid1 p2-init panic 2>&1; echo rc=$?")).strip()
        assert out == "flong-init: internal error: planted\nrc=125", out

        # Last, the audit path's own check: a call the strict tier leaves
        # out, io_uring_setup (425), made by pid 1, is logged. kauditd
        # prints in order, so once this record is in the journal, any of
        # the runs above is too.
        out = p2("positive", "p2-pid1 p2-init logged")
        assert out[-1] == "rc=0", out
        machine.wait_until_succeeds("test -n \"$(journalctl -k -o cat --no-pager | grep -F type=1326 | grep -F syscall=425)\"")
        assert "425" in logged("positive"), logged("positive")
        c_rec, z_rec, d_rec = logged("c"), logged("zig"), logged("default")
        # No record the C init lacks.
        assert z_rec <= c_rec, (z_rec, c_rec)
        print(f"p2: C flong-init: records {sorted(c_rec)}, first call after exec: {c_first}")
        print(f"p2: p2-init: records {sorted(z_rec)}, first call after exec: {z_first}")
        print(f"p2: p2-init-default: records {sorted(d_rec)}, first call after exec: {d_first}")
  '';
}
