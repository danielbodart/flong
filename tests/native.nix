# The proofs that need a kernel the build sandbox does not give: one node, a
# lingering user with subordinate ids and a delegated user manager, the
# proofs' binaries on PATH (tests/integration.nix's `vm`), and each proof's
# testScript fragment after the common setup below, in tests/proofs/ name
# order (ZIG.md, "Tests", checks.native). Before them, flong-init past its
# argv, and phase 3 (a)'s transition: the C flong-init against the Zig, as
# pid 1 under strace. A fourth VM beside basic, rootless and parity;
# nothing in it is about time.
#
# Fragments are Python run in this testScript's scope, so they may use
# `machine`, `shlex` and `as_alice`; each opens its own subtest.
{ hostPkgs, lib, ... }:

let
  integration = import ./integration.nix { pkgs = hostPkgs; };
  native = import ../native.nix { pkgs = hostPkgs; };
  # The launcher's output, for its flong-init (src/init.zig).
  launcher = import ../launcher { pkgs = hostPkgs; };

  # Phase 3 (a)'s transition (ZIG.md, "Phase 3"): the C flong-init as the
  # launcher built it until now, with the same flags and so the same tini
  # (native.nix's launcherCflags; its FLONG_INIT names this $out, which
  # flong-init.c never reads). Built here, never an output.
  initC = hostPkgs.runCommandCC "flong-init-c" { } ''
    mkdir -p $out/bin
    cflags=(${native.launcherCflags})
    $CC "''${cflags[@]}" -o $out/bin/flong-init ${../launcher/flong-init.c}
  '';

  # The positive control of the audit compare: a payload making
  # io_uring_setup (425), which the strict tier leaves out, so log = true
  # writes a record of it (P2's `logged`).
  logProbe = hostPkgs.runCommandCC "io-uring-probe" { } ''
    mkdir -p $out/bin
    printf '%s\n' '#include <unistd.h>' '#include <sys/syscall.h>' \
      'int main(void) { syscall(425, 0, 0); return 0; }' > probe.c
    $CC -o $out/bin/io-uring-probe probe.c
  '';

  # The strict tier with log = true, as module.nix:622 builds it (through
  # seccomp/policy.nix's filterFor) for a declaration with no loosening, then
  # the fixed filters in the wrapper's order (rootless-wrapper.bash:381-385).
  # systemd is pkgs.systemd, the VM's config.systemd.package, so the tier's
  # names are the node's own.
  seccomp = import ../seccomp/policy.nix {
    inherit lib;
    pkgs = hostPkgs;
    systemd = hostPkgs.systemd;
    compiler = import ../seccomp { pkgs = hostPkgs; };
  };
  stack = [
    (seccomp.filterFor {
      tier = "strict";
      debug = false;
      nestedSandbox = false;
      allow = [ ];
      deny = [ ];
      log = true;
      errno = "EPERM";
    })
    seccomp.fixed.audit
    seccomp.fixed.tty
    seccomp.fixed.nsmask
  ];

  # pid1 PROGRAM ARGS...: PROGRAM as pid 1 through bwrap, with
  # flong-launch.c's namespaces, --as-pid-1, the seccomp stack one
  # --add-seccomp-fd each, and CAP_SETGID and CAP_SETPCAP for flong-init's
  # setgroups and capability drop (as P2 did; ZIG.md, "Measured").
  # It runs as root of a user namespace that newuidmap made (`unshare
  # --map-auto --map-root-user`), where setgroups is allowed as in the
  # launcher's U1; bwrap then needs no --unshare-user. The root is the
  # node's, read-only, with an empty /tmp. Descriptors 20-23 hold the
  # filters; bwrap leaks them, as it does the launcher's, for flong-init's
  # close_range.
  pid1 = hostPkgs.writeShellScript "flong-pid1" ''
    exec 20<${lib.elemAt stack 0} 21<${lib.elemAt stack 1} 22<${lib.elemAt stack 2} 23<${lib.elemAt stack 3}
    exec ${hostPkgs.bubblewrap}/bin/bwrap \
      --unshare-net --unshare-pid --unshare-ipc --unshare-uts --unshare-cgroup \
      --die-with-parent --as-pid-1 \
      --add-seccomp-fd 20 --add-seccomp-fd 21 --add-seccomp-fd 22 --add-seccomp-fd 23 \
      --cap-add CAP_SETGID --cap-add CAP_SETPCAP \
      --ro-bind / / --proc /proc --dev /dev --tmpfs /tmp \
      -- "$@"
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

    with subtest("flong-init past its argv: the gate's EOF, and a failing chdir printed whole"):
        # What golden's init set cannot reach (tests/golden.nix): as root of
        # a namespace newuidmap made, setgroups and the capability drop
        # succeed, as in the launcher's U1 (flong-init.c:195-201). GATE is 4,
        # reading GATE_FILE; READY is 5, writing to /dev/null; no groups,
        # terminal or trace. Prints stderr and the status as the last line.
        def init_run(gate_file, dir):
            return machine.succeed(as_alice(
                "unshare --user --map-auto --map-root-user -- "
                f"${launcher}/bin/flong-init 4 5 - - - {shlex.quote(dir)} -- true "
                f"4<{gate_file} 5>/dev/null 2>&1; echo rc=$?"))

        machine.succeed("printf g > /tmp/init-gate && chmod 644 /tmp/init-gate")
        # The gate closed without its byte (:214-215).
        out = init_run("/dev/null", "/")
        assert out == "flong-init: the gate closed without opening: not starting the payload\nrc=125\n", out
        # The gate open, DIR missing (:217-218): the message is over 1 KiB
        # and printed whole (ZIG.md quirk 22), then too long a DIR.
        for dir, text in (("/nonexistent/" + "/".join(["d" * 200] * 6), "No such file or directory"),
                          ("/" + "/".join(["d" * 200] * 21), "File name too long")):
            out = init_run("/tmp/init-gate", dir)
            assert len(dir) > 1024 and out == f"flong-init: changing to {dir}: {text}\nrc=125\n", out
        # The control: the gate open, DIR there, tini runs the payload.
        out = init_run("/tmp/init-gate", "/tmp")
        assert out.endswith("rc=0\n"), out

    with subtest("flong-init, C against Zig: the same calls in the same order as pid 1, under strict with log"):
        # ZIG.md phase 3 (a). Each init runs as pid 1 through bwrap under the
        # strict stack with log = true (${pid1}), under strace -f, one file
        # per process in /tmp/t3/NAME.PID. GATE is 4, READY 5.
        import re
        zig_init = "${launcher}/bin/flong-init"
        c_init = "${initC}/bin/flong-init"
        machine.succeed("printf g > /tmp/t3-gate && chmod 644 /tmp/t3-gate")

        # NAME's run, as alice, root of a user namespace newuidmap made:
        # stdout and stderr together, then the status as the last line.
        def traced(name, init, args, redirs):
            return machine.succeed(as_alice(
                "mkdir -p /tmp/t3 && unshare --user --map-auto --map-root-user -- "
                f"strace -f -ff -qq -o /tmp/t3/{name} ${pid1} {init} {args} {redirs} 2>&1; echo rc=$?"))

        # The calls of the process that exec'd INIT, after that execve, one
        # per line, normalised: blanks collapsed; addresses 0x_ (glibc's
        # and Zig's sa_restorer, the envp); the trace's time (the node's
        # clock has no vDSO fast path, so both make the call); each run of
        # writes to fd 2 one
        # `stderr`, since the C's stdio makes several where the Zig makes
        # one writev (quirk 22; the text is compared as the run's output).
        def calls(name, init):
            files = machine.succeed(f"grep -lF 'execve(\"{init}\"' /tmp/t3/{name}.*").split()
            assert len(files) == 1, (name, files)
            lines = machine.succeed(f"cat {files[0]}").splitlines()
            start = [i for i, l in enumerate(lines) if l.startswith(f'execve("{init}"') and l.endswith("= 0")]
            assert len(start) == 1, (name, lines)
            out = []
            for line in lines[start[0] + 1:]:
                line = re.sub(r"0x[0-9a-f]+", "0x_", " ".join(line.split()))
                line = re.sub(r"tv_sec=\d+, tv_nsec=\d+", "tv_sec=_, tv_nsec=_", line)
                if re.match(r"writev?\(2, ", line):
                    line = "stderr"
                    if out and out[-1] == line:
                        continue
                out.append(line)
            return out

        # The writes to fd 2 of the process that exec'd INIT, between that
        # execve and the next: `calls` counts a run of them as one entry, so
        # a message split in two would pass it. The Zig's is one writev
        # (quirk 22); the C's stdio makes several, the count's control.
        def stderr_writes(name, init):
            files = machine.succeed(f"grep -lF 'execve(\"{init}\"' /tmp/t3/{name}.*").split()
            lines = machine.succeed(f"cat {files[0]}").splitlines()
            start = [i for i, l in enumerate(lines) if l.startswith(f'execve("{init}"')][0]
            n = 0
            for line in lines[start + 1:]:
                if line.startswith("execve("):
                    break
                n += bool(re.match(r"writev?\(2, ", line))
            return n

        # The window ZIG.md names: from the first setgroups (or, for an
        # argv refusal, which calls nothing before it, the message) to the
        # exec of tini or the exit. The C's malloc (brk, mmap) is left out:
        # the Zig allocates nothing, which `allocates` checks.
        def window(seq):
            first = [i for i, l in enumerate(seq) if l.startswith("setgroups(") or l == "stderr"]
            assert first, seq
            out = []
            for line in seq[first[0]:]:
                if re.match(r"(brk|mmap|munmap)\(", line):
                    print(f"flong-init: left out: {line}")
                    continue
                if line == "stderr" and out and out[-1] == line:
                    continue
                out.append(line)
                if re.match(r"(execve|exit_group)\(", line):
                    return out
            raise AssertionError(("no exec or exit", seq))

        # The kernel's SECCOMP_RET_LOG records (type=1326), as the learning
        # path reads them (tests/rootless.nix:966-970), made by any process
        # of run NAME (the pids strace -ff named its files by): the set of
        # syscall numbers.
        def logged(name):
            pids = machine.succeed(f"ls /tmp/t3 | sed -n 's/^{name}\\.//p'").split()
            assert pids, name
            alt = "|".join(pids)
            out = machine.succeed(
                "journalctl -k -o cat --no-pager | grep -F type=1326"
                f" | grep -E ' pid=({alt}) ' | grep -o 'syscall=[0-9]*' | cut -d= -f2 | sort -un"
                " || true")  # none is an answer, and grep says it with 1
            return set(out.split())

        gate, eof = "4</tmp/t3-gate 5>/dev/null", "4</dev/null 5>/dev/null"
        paths = [
            # tini's exec, with groups and the trace: the payload runs.
            ("exec", "4 5 0,100 - trace /tmp -- /bin/sh -c 'echo payload-ran'", gate,
             re.compile(r"T \d+ payload-exec\npayload-ran\nrc=0\n")),
            # The gate's EOF (flong-init.c:214-215).
            ("eof", "4 5 - - - /tmp -- /bin/true", eof,
             "flong-init: the gate closed without opening: not starting the payload\nrc=125\n"),
            # A failing chdir (:217-218).
            ("chdir", "4 5 - - - /nonexistent -- /bin/true", gate,
             "flong-init: changing to /nonexistent: No such file or directory\nrc=125\n"),
            # TIOCSCTTY refused, fd 0 not a terminal (:199-200): the ioctl's
            # place between capset and the signals, which tini's path, with
            # no terminal, leaves out.
            ("ctty", "4 5 - ctty - /tmp -- /bin/true", "0</dev/null " + gate,
             "flong-init: taking the terminal (TIOCSCTTY): Inappropriate ioctl for device\nrc=125\n"),
            # An argv refusal (:103-109).
            ("argv", "2 5 - - - /tmp -- /bin/true", gate,
             "flong-init: gate descriptor is not a number above 2: 2\nrc=125\n"),
        ]
        for path, args, redirs, want in paths:
            outs, seqs = {}, {}
            for side, init in (("c", c_init), ("zig", zig_init)):
                name = f"{path}-{side}"
                outs[side] = traced(name, init, args, redirs)
                # The output exactly; the trace's time is the one pattern.
                ok = want.fullmatch(outs[side]) if isinstance(want, re.Pattern) else outs[side] == want
                assert ok, (name, outs[side])
                seqs[side] = calls(name, init)
            # One write per message, or for the trace's line, in the Zig.
            assert stderr_writes(f"{path}-zig", zig_init) == 1, (path, stderr_writes(f"{path}-zig", zig_init))
            if path != "exec":
                assert stderr_writes(f"{path}-c", c_init) > 1, (path, "the count's control")
            c, z = window(seqs["c"]), window(seqs["zig"])
            if c != z:
                import difflib
                raise AssertionError(f"flong-init {path}: C against Zig:\n" + "\n".join(difflib.unified_diff(c, z, "c", "zig", lineterm="", n=1)))
            # Nothing before the window in the Zig: no start code, no
            # allocation (P2's check: the audit compare cannot see it).
            assert seqs["zig"][:len(z)] == z, (path, "before the window", seqs["zig"][:3])
            print(f"flong-init {path}: {len(z)} calls equal: " + "; ".join(z))

        # The window's calls, as the checkpoint names them, on tini's path.
        z = window(calls("exec-zig", zig_init))
        names = [re.split(r"[^a-z_0-9]", l, maxsplit=1)[0] for l in z]
        order = ["setgroups", "prctl", "capset", "rt_sigaction", "rt_sigaction", "rt_sigprocmask",
                 "write", "close", "read", "chdir", "close_range", "clock_gettime", "stderr", "execve"]
        assert [n for i, n in enumerate(names) if n != "prctl" or names[i - 1] != "prctl"] == order, names
        assert z[0] == "setgroups(2, [0, 100]) = 0", z[0]
        assert z[-1].startswith('execve("${hostPkgs.tini}/bin/tini", ["tini", "-g", "--", "/bin/sh", "-c", "echo payload-ran"]'), z[-1]

        # Last, the audit path's own check: a call the strict tier leaves out,
        # made by the payload of the Zig init, is logged. kauditd prints in
        # order, so once this record is in the journal, any of the runs above
        # is too.
        out = traced("positive", zig_init, "4 5 - - - /tmp -- ${logProbe}/bin/io-uring-probe", gate)
        assert out == "rc=0\n", out
        machine.wait_until_succeeds("test -n \"$(journalctl -k -o cat --no-pager | grep -F type=1326 | grep -F syscall=425)\"")
        assert "425" in logged("positive"), logged("positive")
        for path, _, _, _ in paths:
            for side in ("c", "zig"):
                assert logged(f"{path}-{side}") == set(), (path, side, logged(f"{path}-{side}"))
  '' + lib.concatMapStrings (p: "\n# ${p.name}\n" + p.script) integration.vm.vmScripts;
}
