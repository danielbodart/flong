# Launch times, in one VM, with one container, one payload (`true`) and each
# feature in turn: no network; a pasta network with an nft postStart hook;
# the same with a fixed forwarded port, waiting for pasta to free it; and
# cold, with the prepared root made as part of the launch.
#
# Not a check: nothing here passes or fails on time. The build's result holds
# numbers.md, a table of medians of 20 over three runs. A launch that fails
# is counted and shown beside its row, and the warm-up launch before each set
# of 20 must succeed, so a row never times an error.
#
# Every launch is alice's, lingering, with no sudo rule, timed by a loop that
# runs inside one `systemd-run -M alice@ --user` unit, so systemd-run's own
# cost is not in the numbers.
{ ... }:

let
  # The rule the hook of basic.nix installs. The hook is the caller, and
  # enters the session's user namespace first to hold any capability over
  # its network.
  hook = ''
    nsenter --user="$userns" --net="$netns" nft \
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
    # own, which flong requires.
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
        net = plain // {
          path = [ pkgs.nftables ];
          network = { };
          postStart = hook;
        };
      in
      {
        inherit plain net;
        # The launcher waits for pasta to let a fixed port go before it
        # returns, and the timing loop waits for the port to be free after
        # every launch.
        fwd = net // {
          network.forwardPorts = [ { hostPort = 18300; containerPort = 18201; } ];
        };
      };

    environment.systemPackages =
      map (n: config.flong.${n}.launcher) [ "plain" "net" "fwd" ]
      ++ [ (bench pkgs) pkgs.iproute2 ];
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

    # The port free again: nothing listening.
    def port_free(port):
        return f"while ss -Hltn 'sport = :{port}' | grep -q .; do :; done"

    # Cold, untimed: the prepared root removed before each launch. It
    # belongs to alice's subordinate ids, so it goes through her own cache
    # tool, as container root in a namespace with the maps her launcher
    # uses: container 1000 and 100 onto hers, the rest from her ranges.
    MAPS = ("--map-users=0:100000:1000 --map-users=1000:1000:1 --map-users=1001:101000:64536 "
            "--map-groups=0:100000:100 --map-groups=100:100:1 --map-groups=101:100100:65436")
    COLD = ("for c in /run/user/1000/flong/box-*; do [ -d \"$c\" ] || continue; "
            f"\"$CT\" gc {MAPS} -- \"$c\" || exit 1; done")
    CT = ("CT=$(sed -n \"s/^cache_tool=//p\" \"$(readlink -f \"$(command -v plain)\")\" | tr -d \"'\"); "
          "export CT; ")

    def bench(prep, after, command):
        return f"flong-bench {N} {shlex.quote(prep)} {shlex.quote(after)} -- {command}"

    # Row, and the command that times it.
    rows = [
        ("no network", as_user(bench("", "", "plain"))),
        ("pasta network + nft hook", as_user(bench("", "", "net"))),
        ("network + nft hook + fixed forwardPort, waiting for pasta to free it",
         as_user(bench("", port_free(18300), "fwd"))),
        ("cold (prepare included), no network", as_user(CT + bench(COLD, "", "plain"))),
    ]

    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("user@1000.service")

    # Every result, by row: one (median, p10, p90, fails, true) per run, in
    # microseconds, and the last failure's output of any run.
    results = {}
    notes = {}
    for run in range(RUNS):
        # Runs interleave the rows, so that a slow stretch of the host
        # spreads over all of them rather than landing on one.
        for row, command in rows:
            with subtest(f"run {run + 1}: {row}"):
                out = machine.succeed(command)
                first, _, rest = out.partition("\n")
                median, p10, p90, fails, true = (int(x) for x in first.split())
                results.setdefault(row, []).append((median, p10, p90, fails, true))
                if rest.strip():
                    notes[row] = rest.strip()

    def ms(us):
        return f"{us / 1000:.1f}"

    def span(values):
        lo, hi = min(values), max(values)
        return f"{ms(lo)} ms" if ms(lo) == ms(hi) else f"{ms(lo)}–{ms(hi)} ms"

    def cell(row):
        runs = results[row]
        text = span([r[0] for r in runs])
        fails = sum(r[3] for r in runs)
        return text + (f" ({fails} of {N * len(runs)} failed)" if fails else "")

    kernel = machine.succeed("uname -r").strip()
    systemd = machine.succeed("systemctl --version | head -n 1").strip()
    cores = machine.succeed("nproc").strip()

    md = []
    md.append("# flong launch times")
    md.append("")
    md.append(f"One NixOS VM ({cores} cores; kernel {kernel}; {systemd}), one container, "
              f"one payload (`true`), medians of {N} over {RUNS} runs, each after one warm-up "
              "launch; a range is the lowest to the highest of the runs' medians.")
    md.append("")
    md.append("| | lingering user |")
    md.append("|---|---|")
    for row, _ in rows:
        md.append(f"| {row} | {cell(row)} |")
    md.append("")
    md.append("- Every launch is alice's, lingering, with no sudo rule, on the default "
              "seccomp tier (`strict`), timed by a loop inside one "
              "`systemd-run -M alice@ --user` unit, so systemd-run's own cost is in none of "
              "the numbers.")
    md.append("- The nft hook is a table, an output chain and one reject rule, entered as "
              "the session's user namespace's root.")
    md.append("- The forwarded-port row times each launch together with a poll, `ss` in a "
              "loop, until nothing listens on the port, and so includes at least one fork of "
              "`ss`, not measured apart.")
    md.append("- Cold removes the prepared root before each launch, untimed, through alice's "
              "own cache tool.")
    md.append("")
    md.append("## Every run")
    md.append("")
    md.append("Milliseconds: median (p10–p90), failed launches, and the median fork+exec of "
              "`true` in the same invocation.")
    md.append("")
    md.append("| | " + " | ".join(f"run {i + 1}" for i in range(RUNS)) + " |")
    md.append("|---|" + "---|" * RUNS)
    for row, _ in rows:
        cells = [f"{ms(m)} ({ms(a)}–{ms(b)}), {f} failed, true {ms(t)}"
                 for m, a, b, f, t in results[row]]
        md.append(f"| {row} | " + " | ".join(cells) + " |")
    if notes:
        md.append("")
        md.append("## The last failure of each row that had one")
        for row, text in notes.items():
            md.append("")
            md.append(f"{row}:")
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
