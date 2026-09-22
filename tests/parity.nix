# The rootless engine's parity with nspawn, measured in one VM with both
# engines and one container declared three times: on nspawn with nspawn's own
# filter, on rootless with seccomp.tier = "parity", and on rootless with the
# default, strict.
#
# The live filters of each session's payload are dumped with
# PTRACE_SECCOMP_GET_FILTER, as the driver's root, and evaluated over every
# syscall number of x86_64, x32 and i386 with the same argument sweep: every
# constant any of the three stacks compares an argument with. The rootless
# stacks must be exactly the filters the build compiled. Then:
#
# - the parity tier and the audit mask against nspawn's stack must differ
#   only where ROOTLESS.md says they do: the audit mask refuses more (it
#   compares the low 32 bits, where nspawn's own is bypassed by setting a
#   high bit, and it also covers i386's socketcall), and rseq_slice_yield,
#   which systemd 261 lists in @known, so that the tier may refuse it with
#   EPERM where nspawn's filter leaves it ENOSYS (on this VM's systemd both
#   refuse it with EPERM, and the rows match);
# - the whole parity stack, with the tty filter and the namespace mask, may
#   differ further only by refusing ioctl's terminal requests and the
#   namespace calls;
# - strict against parity is printed for the record, and may only refuse
#   more.
#
# The spike's syscall probe then runs as the payload of each session, and
# nspawn's and parity's outputs may differ only on the calls those filters
# explain.
{ lib, ... }:

let
  tools = pkgs: import ./parity { inherit pkgs; };

  # One closure for every declaration, with the probe in it.
  boxConfig = { pkgs, ... }: {
    system.stateVersion = "24.05";
    users.users.alice = { isNormalUser = true; uid = 1000; group = "users"; };
    users.groups.users.gid = 100;
    environment.systemPackages = [ (tools pkgs) ];
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
          nspawned = base;
          parity = base // { engine = "rootless"; seccomp.tier = "parity"; };
          strict = base // { engine = "rootless"; };
        };

      environment.systemPackages =
        map (n: config.flong.${n}.launcher) [ "nspawned" "parity" "strict" ]
        ++ [ (tools pkgs) ];

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

    # A launch of SCRIPT through LAUNCHER: nspawn's from the driver's root
    # shell, the rootless ones as alice.
    def launch(launcher, script):
        if launcher == "nspawned":
            return f"cd /srv/work && nspawned {shlex.quote(script)}"
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

    # Why the rootless engine answers differently from nspawn, or None. The
    # fixed filters beyond the audit mask count only when WHOLE is set.
    def explain(d, whole):
        _, _, name, args, ns, rl = d
        if name in ("socket", "socketcall") and args and ns == "ALLOW" and rl == "ERRNO(EAFNOSUPPORT)":
            return "audit mask"
        if name == "rseq_slice_yield" and not args and ns == "ERRNO(ENOSYS)" and rl == "ERRNO(EPERM)":
            return "rseq_slice_yield in @known"
        if whole and ns == "ALLOW":
            if name == "ioctl" and args and rl == "ERRNO(EPERM)":
                return "tty filter"
            if name in ("clone", "unshare") and args and rl == "ERRNO(EPERM)":
                return "namespace mask"
            if name == "setns" and not args and rl == "ERRNO(EPERM)":
                return "namespace mask"
            if name == "clone3" and not args and rl == "ERRNO(ENOSYS)":
                return "namespace mask"
        return None

    def judge(what, diffs, whole):
        why = {}
        for d in diffs:
            why.setdefault(explain(d, whole), []).append(d)
        report = [f"{what}: {len(diffs)} rows differ"]
        for reason, ds in sorted(why.items(), key=lambda kv: str(kv[0])):
            report.append(f"  {reason or 'UNEXPLAINED'}: {len(ds)}")
            # The masks' sweeps run to hundreds of rows; the others are listed.
            listed = ds if reason in (None, "audit mask", "rseq_slice_yield in @known") else ds[:4]
            report += ["    " + show(d) for d in listed]
            if len(listed) < len(ds):
                report.append(f"    ... and {len(ds) - len(listed)} more")
        print("\n".join(report))
        assert None not in why, "\n".join(report)

    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("user@1000.service")
    machine.succeed(f"mkdir -p {D}")

    with subtest("each engine runs the container, warm"):
        for launcher in ("nspawned", "parity", "strict"):
            assert machine.succeed(launch(launcher, "id -u")).strip() == "1000", launcher

    with subtest("the live filters are dumped, and the rootless stacks are the build's"):
        nspawn = dump("nspawned", "10011")
        parity = dump("parity", "10012")
        strict = dump("strict", "10013")
        built = {name: sha(f"{F}/{name}.bpf") for name in ("parity", "strict", "audit", "tty", "nsmask")}
        by_sha = {v: k for k, v in built.items()}
        live = {}
        for tag, files, want in (("parity", parity, "parity"), ("strict", strict, "strict")):
            names = [by_sha.get(sha(f), "?") for f in files]
            print(f"{tag}: filters, most recently attached first: {names}")
            assert sorted(names) == sorted([want, "audit", "tty", "nsmask"]), (tag, names)
            live[tag] = dict(zip(names, files))
        assert not any(sha(f) in by_sha for f in nspawn), "nspawn's stack holds one of flong's filters"

    # Every stack is swept with every stack's constants, so that their lines
    # compare one for one.
    k = " ".join(f"-k {f}" for f in nspawn + parity + strict)
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

    with subtest("parity: the tier and the audit mask match nspawn, except where documented"):
        e_nspawn = evaluate("nspawn", nspawn)
        e_core = evaluate("parity-core", [live["parity"]["parity"], live["parity"]["audit"]])
        judge("nspawn -> rootless parity tier + audit mask", differences(e_nspawn, e_core), False)

    with subtest("parity: the whole stack only adds the tty filter and the namespace mask"):
        e_parity = evaluate("parity", parity)
        judge("nspawn -> rootless parity stack", differences(e_nspawn, e_parity), True)

    with subtest("strict against parity, for the record"):
        e_strict = evaluate("strict", strict)
        diffs = differences(e_parity, e_strict)
        print("parity -> strict:\n" + "\n".join(show(d) for d in diffs))
        for arch in ARCHES:
            names = sorted({d[2] for d in diffs if d[0] == arch})
            print(f"strict refuses on {arch} ({len(names)}): {' '.join(names)}")
        loosened = [d for d in diffs if d[5] == "ALLOW" or d[4] != "ALLOW"]
        assert not loosened, "\n".join(show(d) for d in loosened)

    with subtest("the syscall probe: nspawn and parity differ only where the filters say"):
        out = {l: machine.succeed(launch(l, "syscall-probe 2>/dev/null")) for l in ("nspawned", "parity", "strict")}
        table = {l: [line.rsplit(None, 1) for line in o.strip().splitlines()] for l, o in out.items()}
        names = [n for n, _ in table["nspawned"]]
        assert all([n for n, _ in table[l]] == names for l in table), out
        results = {l: dict(table[l]) for l in table}
        # What the rootless engine answers where it differs, and why.
        explained = {
            "unshare(NEWUSER)": ("EPERM", "namespace mask"),
            "unshare(NEWUSER|NEWNS)": ("EPERM", "namespace mask"),
            "clone3(plain)": ("ENOSYS", "namespace mask"),
            "setns(-1)": ("EPERM", "namespace mask"),
            "rseq_slice_yield (471)": ("EPERM", "rseq_slice_yield in @known"),
            "socket(NETLINK_AUDIT) hi": ("EAFNOSUPPORT", "audit mask"),
        }
        report, unexplained = [], []
        for n in names:
            a, b, c = (results[l][n] for l in ("nspawned", "parity", "strict"))
            note = ""
            if a != b:
                want = explained.get(n)
                note = want[1] if want and want[0] == b else "UNEXPLAINED"
                if note == "UNEXPLAINED":
                    unexplained.append(n)
            report.append(f"{n:28} nspawn {a:14} parity {b:14} strict {c:14} {note}")
        print("\n".join(report))
        assert not unexplained, "\n".join(report)
  '';
}
