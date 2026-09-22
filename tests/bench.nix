# Like-for-like launch times of the two engines, in one VM, with the same
# container, the same payload (`true`) and the same features: no network; a
# pasta network with an nft postStart hook; the same with a fixed forwarded
# port, waiting for pasta to free it; and cold, with the prepared root made
# as part of the launch. The numbers ROOTLESS.md phase 5 asks for.
#
# Not a check: nothing here passes or fails on time. The build's result holds
# numbers.md, a table of medians of 20 over three runs, like ROOTLESS.md's.
# A launch that fails is counted and shown beside its row, and the warm-up
# launch before each set of 20 must succeed, so a row never times an error.
#
# nspawn launches as root from the test's shell, as it always has, and once
# more through sudo as alice. rootless launches as a lingering alice with no
# sudo rule. Every launch alice makes is timed by a loop that runs inside one
# `systemd-run -M alice@ --user` unit, so systemd-run's own cost is not in her
# numbers.
{ lib, ... }:

let
  # The same rule for both engines, as the hook of basic.nix installs it;
  # only the way into the session's namespace differs. Under rootless the
  # hook is the caller, and must enter the session's user namespace first to
  # hold any capability over its network.
  hookFor = enter: ''
    ${enter} nft \
      'add table inet flong
       add chain inet flong out { type filter hook output priority 0; policy accept; }
       add rule inet flong out tcp dport 19999 reject with tcp reset'
  '';

  # flong-bench RUNS PREP AFTER -- COMMAND...
  #
  # One warm-up launch, which must succeed, then RUNS timed launches of
  # COMMAND. PREP is evaluated before each, untimed; AFTER after each,
  # timed. Prints one line of microseconds -- median, p10, p90 -- then the
  # count of failed launches and the median fork+exec of `true` measured in
  # the same invocation; then the last failure's output, if any.
  bench = pkgs: pkgs.writeShellScriptBin "flong-bench" ''
    runs=$1 prep=$2 after=$3
    shift 4
    # Of a column of numbers: the median, the 10th and the 90th percentile.
    median() { sort -n | awk '{ a[NR] = $1 } END { print a[int((NR + 1) / 2)] }'; }
    p10() { sort -n | awk '{ a[NR] = $1 } END { print a[int(NR * 0.1) + 1] }'; }
    p90() { sort -n | awk '{ a[NR] = $1 } END { print a[int(NR * 0.9)] }'; }
    err=$(mktemp)

    t=$(type -P true) base=""
    for _ in $(seq "$runs"); do
      t0=''${EPOCHREALTIME/./}; "$t"; t1=''${EPOCHREALTIME/./}
      base+="$((t1 - t0))"$'\n'
    done

    eval "$prep"
    if ! "$@" >/dev/null 2>"$err"; then
      echo "flong-bench: the warm-up launch of $* failed:" >&2
      cat "$err" >&2
      exit 1
    fi
    eval "$after"

    s="" fails=0 last=""
    for _ in $(seq "$runs"); do
      eval "$prep"
      t0=''${EPOCHREALTIME/./}
      "$@" >/dev/null 2>"$err" || { fails=$((fails + 1)); last=$(head -c 2000 "$err"); }
      eval "$after"
      t1=''${EPOCHREALTIME/./}
      s+="$((t1 - t0))"$'\n'
    done
    rm -f "$err"

    printf '%s %s %s %s %s\n' \
      "$(printf %s "$s" | median)" "$(printf %s "$s" | p10)" "$(printf %s "$s" | p90)" \
      "$fails" "$(printf %s "$base" | median)"
    if [ -n "$last" ]; then printf '%s\n' "$last"; fi
  '';
in
{
  name = "flong-bench";

  nodes.machine = { config, pkgs, ... }: {
    imports = [ ../module.nix ];

    # As the VM the spikes measured in.
    virtualisation.memorySize = 3072;
    virtualisation.cores = 4;

    users.users.alice = {
      isNormalUser = true;
      uid = 1000;
      group = "users";
      linger = true;
      # Stated rather than allocated, so the maps a cold run collects its
      # cache with are known below.
      autoSubUidGidRange = false;
      subUidRanges = [ { startUid = 100000; count = 65536; } ];
      subGidRanges = [ { startGid = 100000; count = 65536; } ];
    };

    systemd.tmpfiles.rules = [ "d /srv/work 0755 alice users -" ];

    # One container for every declaration, with a network namespace of its
    # own, which the rootless engine requires and nspawn is given too.
    containers.box = {
      privateNetwork = true;
      config = {
        system.stateVersion = "24.05";
        users.users.alice = { isNormalUser = true; uid = 1000; group = "users"; };
        users.groups.users.gid = 100;
      };
    };

    flong =
      let
        plain = {
          container = "box";
          user = "alice";
          command = [ "true" ];
        };
        net = enter: plain // {
          path = [ pkgs.nftables ];
          network = { };
          postStart = hookFor enter;
        };
        # The rootless launcher waits for pasta to let a fixed port go
        # before it returns; the timing loop waits for the port to be free
        # after every launch of either engine.
        fwd = enter: port: net enter // {
          network.forwardPorts = [ { hostPort = port; containerPort = 18201; } ];
        };
        rootless = d: d // { engine = "rootless"; };
        nsEnter = ''nsenter --net="$netns"'';
        rlEnter = ''nsenter --user="$userns" --net="$netns"'';
      in
      {
        nsplain = plain;
        nsnet = net nsEnter;
        nsfwd = fwd nsEnter 18200;
        rlplain = rootless plain;
        rlnet = rootless (net rlEnter);
        rlfwd = rootless (fwd rlEnter 18300);
      };

    # The row ROOTLESS.md's table has for nspawn through sudo.
    security.sudo.extraRules = [{
      users = [ "alice" ];
      commands = [{ command = lib.getExe config.flong.nsplain.launcher; options = [ "NOPASSWD" ]; }];
    }];

    environment.systemPackages =
      map (n: config.flong.${n}.launcher) [ "nsplain" "nsnet" "nsfwd" "rlplain" "rlnet" "rlfwd" ]
      ++ [ (bench pkgs) pkgs.e2fsprogs pkgs.iproute2 ];
  };

  testScript = ''
    import shlex

    RUNS = 3
    N = 20

    # A command as alice, through her own user manager, with an explicit
    # PATH and the workspace as the current directory: one unit, inside
    # which the whole timing loop runs.
    def as_user(script):
        inner = "export PATH=/run/wrappers/bin:/run/current-system/sw/bin; cd /srv/work; " + script
        return ("systemd-run -M alice@ --user --wait --pipe --quiet --collect "
                "--expand-environment=no -- /run/current-system/sw/bin/bash -c "
                + shlex.quote(inner) + " </dev/null")

    def as_root(script):
        return "cd /srv/work; " + script

    # The port free again, from either engine's side: nothing listening.
    def port_free(port):
        return f"while ss -Hltn 'sport = :{port}' | grep -q .; do :; done"

    # Cold, untimed: the prepared root removed before each launch. nspawn's
    # is root's, with inode flags that refuse rm until cleared. rootless's
    # belongs to alice's subordinate ids, so it goes through her own cache
    # tool, as container root in a namespace with the maps her launcher
    # uses: container 1000 and 100 onto hers, the rest from her ranges.
    NS_COLD = "chattr -R -i /run/flong/box-* 2>/dev/null; rm -rf /run/flong/box-*"
    RL_MAPS = ("--map-users=0:100000:1000 --map-users=1000:1000:1 --map-users=1001:101000:64536 "
               "--map-groups=0:100000:100 --map-groups=100:100:1 --map-groups=101:100100:65436")
    RL_COLD = ("for c in /run/user/1000/flong/box-*; do [ -d \"$c\" ] || continue; "
               f"\"$CT\" gc {RL_MAPS} -- \"$c\" || exit 1; done")
    RL_CT = ("CT=$(sed -n \"s/^cache_tool=//p\" \"$(readlink -f \"$(command -v rlplain)\")\" | tr -d \"'\"); "
             "export CT; ")

    def bench(prep, after, command):
        return f"flong-bench {N} {shlex.quote(prep)} {shlex.quote(after)} -- {command}"

    # Row, engine, and the command that times it.
    rows = [
        ("no network", "nspawn", as_root(bench("", "", "nsplain"))),
        ("no network", "rootless", as_user(bench("", "", "rlplain"))),
        ("no network, via sudo as a user", "nspawn",
         as_user(bench("", "", "/run/wrappers/bin/sudo -n \"$(readlink -f \"$(command -v nsplain)\")\""))),
        ("pasta network + nft hook", "nspawn", as_root(bench("", "", "nsnet"))),
        ("pasta network + nft hook", "rootless", as_user(bench("", "", "rlnet"))),
        ("network + nft hook + fixed forwardPort, waiting for pasta to free it", "nspawn",
         as_root(bench("", port_free(18200), "nsfwd"))),
        ("network + nft hook + fixed forwardPort, waiting for pasta to free it", "rootless",
         as_user(bench("", port_free(18300), "rlfwd"))),
        ("cold (prepare included), no network", "nspawn", as_root(bench(NS_COLD, "", "nsplain"))),
        ("cold (prepare included), no network", "rootless", as_user(RL_CT + bench(RL_COLD, "", "rlplain"))),
    ]

    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("user@1000.service")

    # Every result, by row and engine: one (median, p10, p90, fails, true)
    # per run, in microseconds, and the last failure's output of any run.
    results = {}
    notes = {}
    for run in range(RUNS):
        # Runs interleave the rows, so that a slow stretch of the host
        # spreads over all of them rather than landing on one.
        for row, engine, command in rows:
            with subtest(f"run {run + 1}: {engine}, {row}"):
                out = machine.succeed(command)
                first, _, rest = out.partition("\n")
                median, p10, p90, fails, true = (int(x) for x in first.split())
                results.setdefault((row, engine), []).append((median, p10, p90, fails, true))
                if rest.strip():
                    notes[(row, engine)] = rest.strip()

    def ms(us):
        return f"{us / 1000:.1f}"

    def span(values):
        lo, hi = min(values), max(values)
        return f"{ms(lo)} ms" if ms(lo) == ms(hi) else f"{ms(lo)}–{ms(hi)} ms"

    def cell(row, engine):
        runs = results.get((row, engine))
        if not runs:
            return "—"
        text = span([r[0] for r in runs])
        fails = sum(r[3] for r in runs)
        return text + (f" ({fails} of {N * len(runs)} failed)" if fails else "")

    kernel = machine.succeed("uname -r").strip()
    systemd = machine.succeed("systemctl --version | head -n 1").strip()
    cores = machine.succeed("nproc").strip()

    order = []
    for row, _, _ in rows:
        if row not in order:
            order.append(row)

    md = []
    md.append("# flong launch times, nspawn against rootless")
    md.append("")
    md.append(f"Same NixOS VM ({cores} cores; kernel {kernel}; {systemd}), same container, "
              f"same payload (`true`), medians of {N} over {RUNS} runs, each after one warm-up "
              "launch; a range is the lowest to the highest of the runs' medians.")
    md.append("")
    md.append("| | nspawn, root | rootless, lingering user |")
    md.append("|---|---|---|")
    for row in order:
        md.append(f"| {row} | {cell(row, 'nspawn')} | {cell(row, 'rootless')} |")
    md.append("")
    md.append("- nspawn launches from the test's root shell, and through `sudo -n` as alice "
              "for its own row. rootless launches as alice, lingering, with no sudo rule, "
              "on its default seccomp tier (`strict`).")
    md.append("- Every launch alice makes is timed by a loop inside one "
              "`systemd-run -M alice@ --user` unit, so systemd-run's own cost is in none of "
              "her numbers. The root loop runs in the test's shell.")
    md.append("- The nft hook is the same rule for both engines: a table, an output chain and "
              "one reject rule, entered as root under nspawn and as the session's user "
              "namespace's root under rootless.")
    md.append("- The forwarded-port rows time each launch together with a poll, `ss` in a "
              "loop, until nothing listens on the port: the rootless launcher waits for pasta "
              "itself before it returns, nspawn's does not, so the poll puts both on the same "
              "footing; both rows include at least one fork of `ss`, not measured apart.")
    md.append("- Cold removes the prepared root before each launch, untimed: nspawn's as root, "
              "rootless's through alice's own cache tool.")
    md.append("")
    md.append("## Every run")
    md.append("")
    md.append("Milliseconds: median (p10–p90), failed launches, and the median fork+exec of "
              "`true` in the same invocation.")
    md.append("")
    md.append("| | engine | " + " | ".join(f"run {i + 1}" for i in range(RUNS)) + " |")
    md.append("|---|---|" + "---|" * RUNS)
    for row, engine, _ in rows:
        cells = [f"{ms(m)} ({ms(a)}–{ms(b)}), {f} failed, true {ms(t)}"
                 for m, a, b, f, t in results[(row, engine)]]
        md.append(f"| {row} | {engine} | " + " | ".join(cells) + " |")
    if notes:
        md.append("")
        md.append("## The last failure of each row that had one")
        for (row, engine), text in notes.items():
            md.append("")
            md.append(f"{engine}, {row}:")
            md.append("")
            md.append("```")
            md.append(text)
            md.append("```")
    md.append("")

    text = "\n".join(md)
    print(text)
    (machine.out_dir / "numbers.md").write_text(text)
  '';
}
