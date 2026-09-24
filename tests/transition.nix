# TRANSITION ONLY (STANDALONE.md, S3, "Transition"), deleted with
# rootless-wrapper.bash, src/launch/argv_render.zig and `flong launch
# --dump-argv`: flong launch builds a declaration's spec as a value, where
# the wrapper built it as argv, and this diffs the two for every
# declaration of basic.nix and rootless.nix, on their own nodes, over the
# caller-side outcomes their commands can have.
#
# The old side is each declaration's transitionWrapper (module.nix), the
# wrapper as it was, run with FLONG_DUMP_SPEC set: it does everything it
# did, the commands and the prepared root included, then prints the words
# it would have exec'd flong launch with, and exits. The new side is
# `flong launch --dump-argv NAME -- ARGS`, which does the same and prints
# the value rendered in the old keywords (src/launch/argv_render.zig). Each
# run's status, its stderr (trace lines dropped) and, when it succeeded,
# its spec, each keyword's fields in order, must be the same. What cannot
# be is normalised: the session's name (the launcher's pid and a random
# number), the relaunch's own program (the wrapper's path, or flong's argv
# up to "--") and the resolver's descriptor number.
#
# Every launch is alice's, through her own user manager, from /srv/work
# unless an outcome says otherwise.
{ lib, ... }:

let
  basic = import ./basic.nix { config.part = "all"; inherit lib; };
  # Part a's node, which has no specialisation to evaluate.
  rootless = import ./rootless.nix { config.part = "a"; inherit lib; };

  # A test's node, with every declaration's old launcher and new command on
  # PATH.
  withBoth = node: { config, lib, ... }: {
    imports = [ node ];
    environment.systemPackages = lib.concatLists (lib.mapAttrsToList
      (_: d: [ d.launcher d.transitionWrapper ]) config.flong);
  };
in
{
  name = "flong-transition";

  nodes.basic = withBoth basic.nodes.machine;
  nodes.rootless = withBoth rootless.nodes.machine;

  testScript = ''
    import re
    import shlex

    # (tag, directory, environment, the launcher's arguments). The
    # FLONG_TEST_* ones are rootless.nix's mounts and project fixtures'
    # commands; every declaration gets every outcome.
    OUTCOMES = [
        ("plain", "/srv/work", {}, ["echo", "a  b", "", "--", "$(x)"]),
        ("trace", "/srv/work", {"FLONG_TRACE": "1", "TERM": "xterm-256color", "COLORTERM": "truecolor"}, []),
        ("no-term", "/tmp", {"TERM": ""}, ["true"]),
        ("the-root", "/", {}, ["true"]),
        ("a-bind", "/srv/work", {"FLONG_TEST_BIND": "/srv/companion"}, []),
        ("a-bind-rw", "/srv/work", {"FLONG_TEST_BIND": "/srv/rw:rw"}, []),
        ("a-deep-mask", "/srv/work", {"FLONG_TEST_BIND": "/srv:rw"}, []),
        ("no-bind", "/srv/work", {"FLONG_TEST_BIND": "/nonexistent"}, []),
        ("the-workspace-again", "/srv/work", {"FLONG_TEST_BIND": "/srv/work:rw"}, []),
        ("denied", "/srv/work", {"FLONG_TEST_DENY": "1"}, []),
        ("a-policy", "/srv/work", {"FLONG_TEST_POLICY": "allow userfaultfd\ndeny @swap"}, []),
        ("a-bad-policy", "/srv/work", {"FLONG_TEST_POLICY": "allow no_such_call"}, []),
        ("a-failing-policy", "/srv/work", {"FLONG_TEST_POLICY_FAIL": "1"}, []),
    ]

    KEYWORDS = {
        "machine": 1, "container": 1, "state": 1, "cache": 1, "relaunch": 1, "closure": 1,
        "uidmap": 3, "gidmap": 3, "user": 3, "group": 1, "chdir": 1, "protect": 1,
        "seccomp": 1, "nested-userns": 1, "holder": 1, "holder-start": 1, "limit": 2,
        "network": 0, "pasta-arg": 1, "pasta-wait": 0, "bwrap-arg": 1, "keep-fd": 1, "trace": 0,
    }
    MOUNTS = {"bind-ro": 2, "bind-rw": 2, "bind-ro-exact": 2, "bind-rw-exact": 2,
              "dev": 2, "tmpfs": 4, "overlay": 2, "mask": 1}

    def canon(side, data):
        # What a command printed on stdout comes first, as it is.
        at = data.find(b"resolv:")
        assert at >= 0, data[:200]
        before, data = data[:at], data[at:]
        words = data.split(b"\0")
        assert words[-1] == b"", data[-200:]
        words = [w.decode("utf-8", "surrogateescape") for w in words[:-1]]
        assert words[0].startswith("resolv:"), words[:3]
        spec = {}
        i = 1
        while words[i] != "--":
            k = words[i]
            if k == "mount":
                n = 1 + MOUNTS[words[i + 1]]
            elif k in ("post-start", "post-stop"):
                n = 1 + int(words[i + 1])
            else:
                n = KEYWORDS[k]
            spec.setdefault(k, []).append(tuple(words[i + 1:i + 1 + n]))
            i += 1 + n
        command = words[i + 1:]
        (machine,), = spec["machine"]
        assert re.fullmatch(r".+-[0-9]+-[0-9]+", machine), machine
        spec["machine"] = re.sub(r"-[0-9]+-[0-9]+$", "-PID-RANDOM", machine)
        relaunch = [w for (w,) in spec.pop("relaunch", [])]
        spec["relaunch"] = relaunch[1:] if side == "old" else relaunch[relaunch.index("--") + 1:]
        spec.pop("keep-fd", None)
        opts = [w for (w,) in spec.pop("bwrap-arg", [])]
        bw = {"clearenv": False, "setenv": [], "hostname": None, "data": []}
        j = 0
        while j < len(opts):
            o = opts[j]
            if o == "--clearenv":
                bw["clearenv"] = True
                j += 1
            elif o == "--setenv":
                bw["setenv"].append((opts[j + 1], opts[j + 2]))
                j += 3
            elif o == "--hostname":
                bw["hostname"] = opts[j + 1]
                j += 2
            elif o == "--perms" and opts[j + 2] == "--ro-bind-data":
                bw["data"].append((opts[j + 1], opts[j + 4]))
                j += 5
            else:
                raise Exception(f"{side}: bwrap-arg {o!r}")
        spec["bwrap-arg"] = bw
        return before, words[0], spec, command

    def stderr_of(data):
        text = data.decode("utf-8", "surrogateescape")
        return "\n".join(l for l in text.splitlines() if not re.match(r"T [0-9]+ ", l))

    def run(machine, node):
        machine.wait_for_unit("multi-user.target")
        machine.wait_for_unit("user@1000.service")
        names = sorted(machine.succeed("ls /etc/flong").split())
        names = [n[:-len(".zon")] for n in names if n.endswith(".zon")]
        assert len(names) > 5, names
        lines = ["set -u", "export PATH=/run/wrappers/bin:/run/current-system/sw/bin", "out=/tmp/transition", "rm -rf $out", "mkdir -p $out",
                 f"flong=$(readlink -f \"$(command -v {shlex.quote(names[0])})\")"]
        for name in names:
            for tag, cwd, env, args in OUTCOMES:
                pre = f"cd {shlex.quote(cwd)} && env " + " ".join(shlex.quote(f"{k}={v}") for k, v in env.items())
                a = " ".join(shlex.quote(x) for x in args)
                base = f"$out/{name}.{tag}"
                lines.append(f"({pre} FLONG_DUMP_SPEC=1 flong-wrapper-{name} {a} >{base}.old.out 2>{base}.old.err; echo $? >{base}.old.rc)")
                lines.append(f"({pre} \"$flong\" launch --dump-argv {shlex.quote(name)} -- {a} >{base}.new.out 2>{base}.new.err; echo $? >{base}.new.rc)")
        script = "\n".join(lines) + "\n"
        machine.succeed(f"printf %s {shlex.quote(script)} > /tmp/transition.sh && chmod 755 /tmp/transition.sh")
        machine.succeed("systemd-run -M alice@ --user --wait --pipe --quiet --collect --expand-environment=no "
                        "-- /run/current-system/sw/bin/bash /tmp/transition.sh </dev/null")
        machine.copy_from_vm("/tmp/transition", node)
        d = machine.out_dir / node / "transition"
        bad, ran, ok, refused = [], 0, 0, 0
        for name in names:
            for tag, _, _, _ in OUTCOMES:
                got = {}
                for side in ("old", "new"):
                    got[side] = {x: (d / f"{name}.{tag}.{side}.{x}").read_bytes() for x in ("out", "err", "rc")}
                ran += 1
                old, new = got["old"], got["new"]
                what = f"{node}: {name} {tag}"
                if old["rc"] != new["rc"]:
                    bad.append(f"{what}: status {old['rc'].strip()} and {new['rc'].strip()}; stderr {old['err']!r} and {new['err']!r}")
                    continue
                if stderr_of(old["err"]) != stderr_of(new["err"]):
                    bad.append(f"{what}: stderr {old['err']!r} and {new['err']!r}")
                    continue
                if old["rc"].strip() != b"0":
                    refused += 1
                    if old["out"] != new["out"]:
                        bad.append(f"{what}: stdout {old['out']!r} and {new['out']!r}")
                    continue
                ok += 1
                a, b = canon("old", old["out"]), canon("new", new["out"])
                if a != b:
                    bad.append(f"{what}: the specs differ:\n  old {a}\n  new {b}")
        print(f"{node}: {ran} pairs, {ok} specs the same, {refused} refusals the same, {len(bad)} different")
        for b in bad:
            print(b)
        assert not bad, f"{node}: {len(bad)} pairs differ"
        # The controls: specs were compared, and refusals too.
        assert ok > len(names) and refused > 0, (ok, refused)

    run(basic, "basic")
    run(rootless, "rootless")
  '';
}
