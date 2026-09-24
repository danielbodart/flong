# The seccomp stacks a session actually runs under, measured in one VM with one
# container declared twice: on seccomp.tier = "parity", and on the default,
# strict.
#
# The live filters of each session's payload are dumped with
# PTRACE_SECCOMP_GET_FILTER, as the driver's root, and evaluated over every
# syscall number of x86_64, x32 and i386 with the same argument sweep: every
# constant either stack compares an argument with. Each stack must be exactly
# the filters the build compiled, and strict may only refuse more than parity.
# The spike's syscall probe then runs as the payload of each session, and
# where strict answers differently from parity it is by refusing the call.
#
# The parity tier was proved against nspawn's own filter while both engines
# existed (commit d48ad97): with the audit mask it matched nspawn's stack
# except where the mask refuses more -- i386's socket and socketcall, and an
# x86_64 socket with a high bit set in a0, which nspawn's 64-bit compare let
# through -- and the whole stack differed further only by the tty filter's
# ioctl rows and the namespace mask's clone, unshare, setns and clone3 rows,
# all stricter. That VM held nspawn, which is gone, so the
# comparison is not repeated here; the byte-for-byte match with the build's
# filters is what keeps it true.
{ lib, ... }:

let
  # bpfdump and syscall-probe, Zig since phase 6 (src/fixtures/); `c` the C
  # they port, as bpfdump-c and syscall-probe-c, for phase 6 (a)'s
  # transition subtest below.
  tools = pkgs: import ./parity { inherit pkgs; };

  # One closure for every declaration, with the probe in it.
  boxConfig = { pkgs, ... }: {
    system.stateVersion = "24.05";
    users.users.alice = { isNormalUser = true; uid = 1000; group = "users"; };
    users.groups.users.gid = 100;
    environment.systemPackages = [ (tools pkgs) (tools pkgs).c ];
  };
in
{
  name = "flong-parity";

  nodes.machine = { config, pkgs, ... }:
    let
      # The build-time filters, from the same pipeline and systemd the
      # module compiles its own with, so that a live stack can be matched
      # against them byte for byte.
      seccomp = import ../seccomp/policy.nix {
        inherit pkgs lib;
        systemd = config.systemd.package;
        compiler = import ../seccomp { inherit pkgs; };
      };
      tier = t: seccomp.filterFor {
        tier = t;
        debug = false;
        nestedSandbox = false;
        allow = [ ];
        deny = [ ];
        errno = "EPERM";
        log = false;
      };
    in
    {
      imports = [ ../module.nix ];

      virtualisation.memorySize = 2048;

      users.users.alice = {
        isNormalUser = true;
        uid = 1000;
        group = "users";
        linger = true;
        autoSubUidGidRange = false;
        subUidRanges = [ { startUid = 100000; count = 65536; } ];
        subGidRanges = [ { startGid = 100000; count = 65536; } ];
      };

      systemd.tmpfiles.rules = [ "d /srv/work 0755 root root -" ];

      containers.box = {
        privateNetwork = true;
        config = boxConfig;
      };

      flong =
        let
          base = {
            container = "box";
            user = "alice";
            command = [ "bash" "-c" ];
          };
        in
        {
          parity = base // { seccomp.tier = "parity"; };
          strict = base;
        };

      environment.systemPackages =
        map (n: config.flong.${n}.launcher) [ "parity" "strict" ]
        ++ [ (tools pkgs) (tools pkgs).c ];

      environment.etc = lib.mapAttrs' (n: f: lib.nameValuePair "flong-parity/${n}.bpf" { source = f; }) {
        parity = tier "parity";
        strict = tier "strict";
        inherit (seccomp.fixed) audit tty nsmask;
      };
    };

  testScript = ''
    import re
    import shlex

    D = "/tmp/parity"
    F = "/etc/flong-parity"
    ARCHES = ["x86_64", "x32", "i386"]

    def as_user(script):
        inner = "export PATH=/run/wrappers/bin:/run/current-system/sw/bin; cd /srv/work; " + script
        return ("systemd-run -M alice@ --user --wait --pipe --quiet --collect "
                "--expand-environment=no -- /run/current-system/sw/bin/bash -c "
                + shlex.quote(inner) + " </dev/null")

    # A launch of SCRIPT through LAUNCHER, as alice.
    def launch(launcher, script):
        return as_user(f"{launcher} {shlex.quote(script)}")

    # The payload's live filters, dumped while it sleeps, as D/TAG.N.bpf.
    def dump(launcher, marker):
        # The driver's shell stops at the first failing command, and a
        # killed payload's launch fails, so its status is echoed from the
        # same list.
        rc = f"/tmp/rc-{launcher}"
        machine.succeed(f"rm -f {rc}; "
                        f"({launch(launcher, f'exec sleep {marker}')} && echo 0 > {rc} || echo $? > {rc}) "
                        f">/tmp/out-{launcher} 2>&1 &")
        pid = machine.wait_until_succeeds(f"pgrep -xf 'sleep {marker}'").split()[0]
        status = machine.succeed(
            f"grep -E '^(Uid|CapBnd|NoNewPrivs|Seccomp|Seccomp_filters):' /proc/{pid}/status")
        out = machine.succeed(f"bpfdump dump {pid} {D}/{launcher}")
        machine.succeed(f"kill {pid}")
        machine.wait_until_succeeds(f"test -s {rc}")
        n = int(out.split()[-1])
        print(f"{launcher}:\n{status}{out}")
        return [f"{D}/{launcher}.{i}.bpf" for i in range(n)]

    def sha(path):
        return machine.succeed(f"sha256sum {path}").split()[0]

    # An evaluation's lines, as the call's answer with all arguments 0 and
    # the answers a sweep found different from it.
    def rows(path):
        base, swept = {}, {}
        for line in machine.succeed(f"cat {path}").splitlines():
            t = line.split()
            arch, nr, name = t[0], int(t[1]), t[2]
            if len(t) == 4:
                base[(arch, nr)] = (name, t[3])
                continue
            args = [x for x in t[3:] if re.fullmatch(r"a[0-5]=0x[0-9a-f]+", x)]
            swept[(arch, nr, " ".join(args))] = t[3 + len(args)]
        return base, swept

    # Where two evaluations answer differently: (arch, nr, name, args, a, b).
    def differences(a, b):
        (base_a, swept_a), (base_b, swept_b) = a, b
        assert base_a.keys() == base_b.keys()
        keys = {(arch, nr, "") for arch, nr in base_a} | swept_a.keys() | swept_b.keys()
        out = []
        for arch, nr, args in sorted(keys, key=lambda k: (ARCHES.index(k[0]), k[1], k[2])):
            name, ra = base_a[(arch, nr)]
            rb = base_b[(arch, nr)][1]
            if args:
                ra = swept_a.get((arch, nr, args), ra)
                rb = swept_b.get((arch, nr, args), rb)
            if ra != rb:
                out.append((arch, nr, name, args, ra, rb))
        return out

    def show(d):
        arch, nr, name, args, ra, rb = d
        return f"{arch:6} {nr:4} {name:24} {args:28} {ra} -> {rb}"

    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("user@1000.service")
    machine.succeed(f"mkdir -p {D}")

    with subtest("each tier runs the container, warm"):
        for launcher in ("parity", "strict"):
            assert machine.succeed(launch(launcher, "id -u")).strip() == "1000", launcher

    with subtest("the live filters are dumped, and are the build's"):
        parity = dump("parity", "10012")
        strict = dump("strict", "10013")
        built = {name: sha(f"{F}/{name}.bpf") for name in ("parity", "strict", "audit", "tty", "nsmask")}
        by_sha = {v: k for k, v in built.items()}
        for tag, files, want in (("parity", parity, "parity"), ("strict", strict, "strict")):
            names = [by_sha.get(sha(f), "?") for f in files]
            print(f"{tag}: filters, most recently attached first: {names}")
            assert sorted(names) == sorted([want, "audit", "tty", "nsmask"]), (tag, names)

    # Every stack is swept with every stack's constants, so that their lines
    # compare one for one.
    k = " ".join(f"-k {f}" for f in parity + strict)
    def evaluate(tag, files):
        machine.succeed(f"bpfdump eval {k} {' '.join(files)} > {D}/{tag}.eval")
        machine.copy_from_machine(f"{D}/{tag}.eval", "")
        summary = machine.succeed(
            f"echo \"{tag}: x86_64 ALLOW $(grep -c '^x86_64 .* ALLOW$' {D}/{tag}.eval),"
            f" EPERM $(grep -c '^x86_64 .*ERRNO(EPERM)$' {D}/{tag}.eval),"
            f" ENOSYS $(grep -c '^x86_64 .*ERRNO(ENOSYS)$' {D}/{tag}.eval),"
            f" swept rows $(grep -c ' a[0-5]=' {D}/{tag}.eval)\"")
        print(summary.strip())
        return rows(f"{D}/{tag}.eval")

    with subtest("strict only refuses more than parity"):
        e_parity = evaluate("parity", parity)
        e_strict = evaluate("strict", strict)
        diffs = differences(e_parity, e_strict)
        print("parity -> strict:\n" + "\n".join(show(d) for d in diffs))
        for arch in ARCHES:
            names = sorted({d[2] for d in diffs if d[0] == arch})
            print(f"strict refuses on {arch} ({len(names)}): {' '.join(names)}")
        loosened = [d for d in diffs if d[5] == "ALLOW" or d[4] != "ALLOW"]
        assert not loosened, "\n".join(show(d) for d in loosened)

    with subtest("the syscall probe: strict differs from parity only by refusing"):
        out = {l: machine.succeed(launch(l, "syscall-probe 2>/dev/null")) for l in ("parity", "strict")}
        table = {l: [line.rsplit(None, 1) for line in o.strip().splitlines()] for l, o in out.items()}
        names = [n for n, _ in table["parity"]]
        assert [n for n, _ in table["strict"]] == names, out
        results = {l: dict(table[l]) for l in table}
        # A filter refuses with the tier's errno, EPERM, or with ENOSYS for
        # what it does not know; any other difference is not a refusal.
        report, loosened = [], []
        for n in names:
            a, b = results["parity"][n], results["strict"][n]
            note = ""
            if a != b:
                note = "refused" if b in ("EPERM", "ENOSYS") else "LOOSER"
                if note == "LOOSER":
                    loosened.append(n)
            report.append(f"{n:28} parity {a:14} strict {b:14} {note}")
        print("\n".join(report))
        assert not loosened, "\n".join(report)

    with subtest("the Zig fixtures against the C: the same dumps, evaluations and probe answers"):
        # ZIG.md phase 6 (a). The subtests above ran the Zig bpfdump and
        # syscall-probe; here the C they port (tests/parity/bpfdump.c,
        # probe.c) runs beside them and says the same. The controls first:
        # the two sides are different files, the C's importing glibc's
        # strerrorname_np, which the Zig's errno.zig replaces.
        for prog in ("bpfdump", "syscall-probe"):
            zig = machine.succeed(f"readlink -f \"$(command -v {prog})\"").strip()
            c = machine.succeed(f"readlink -f \"$(command -v {prog}-c)\"").strip()
            assert zig != c, (prog, zig, c)
            machine.succeed(f"grep -q strerrorname_np {c}")
            machine.fail(f"grep -q strerrorname_np {zig}")
            machine.fail(f"cmp -s {zig} {c}")

        # One payload's filters, dumped by each: the same files and lines.
        machine.succeed(f"mkdir -p {D}/zig {D}/c")
        rc = "/tmp/rc-dump"
        machine.succeed(f"rm -f {rc}; "
                        f"({launch('strict', 'exec sleep 10014')} && echo 0 > {rc} || echo $? > {rc}) "
                        f">/tmp/out-dump 2>&1 &")
        pid = machine.wait_until_succeeds("pgrep -xf 'sleep 10014'").split()[0]
        out = {side: machine.succeed(f"{prog} dump {pid} {D}/{side}/p")
               for side, prog in (("zig", "bpfdump"), ("c", "bpfdump-c"))}
        machine.succeed(f"kill {pid}")
        machine.wait_until_succeeds(f"test -s {rc}")
        assert out["zig"].replace(f"{D}/zig/", f"{D}/c/") == out["c"], out
        n = int(out["zig"].split()[-1])
        assert n == 4, out
        for i in range(n):
            machine.succeed(f"cmp {D}/zig/p.{i}.bpf {D}/c/p.{i}.bpf")
        print(f"dump: {n} filters, the same bytes from both")

        # The evaluations of both tiers' live stacks, as evaluate() ran them.
        for tag, files in (("parity", parity), ("strict", strict)):
            machine.succeed(f"bpfdump-c eval {k} {' '.join(files)} > {D}/{tag}.c.eval")
            machine.succeed(f"cmp {D}/{tag}.eval {D}/{tag}.c.eval")
            lines = machine.succeed(f"wc -l < {D}/{tag}.eval").strip()
            print(f"eval {tag}: {lines} lines, the same from both")

        # The probe under each tier, the C's run in the same session: its
        # stdout, then the byte count of its stderr, which the C never
        # writes and the Zig writes only in a panic.
        probe = lambda p: f"{{ {p} 2>&1 >&3 | wc -c; }} 3>&1"
        for l in ("parity", "strict"):
            out = machine.succeed(launch(l, f"{probe('syscall-probe')}; echo ==; {probe('syscall-probe-c')}"))
            zig, c = out.split("==\n")
            assert zig == c, (l, zig, c)
            # The control: the probe said its 39 lines, and nothing on stderr.
            lines = zig.splitlines()
            assert len(lines) == 40 and lines[-1].strip() == "0", (l, zig)
            print(f"syscall-probe under {l}: {len(lines) - 1} lines and an empty stderr, the same from both")
  '';
}
