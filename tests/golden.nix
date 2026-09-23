# golden: black-box cases for flong's programs, each recorded once from the
# C and never regenerated (ZIG.md, "Tests"). A case is an argv, a stdin and
# redirections; what it pins is stdout, stderr and the exit status, byte for
# byte. The check runs in the build sandbox against the programs being tested,
# so a port meets the same cases its C met.
#
# A set is a directory tests/golden/<set>/ run against one program (`sets`
# below). A case NAME there is these files, NAME.status the only required one:
#
#   NAME.status    the exit status, in decimal, then a newline
#   NAME.args      the arguments, one per line (none if absent)
#   NAME.stdin     stdin (/dev/null if absent)
#   NAME.redirect  more redirections, applied after the others, in bash
#                  syntax: `<&-` closes stdin, `>&-` stdout, `<.` makes stdin
#                  the (empty) working directory
#   NAME.setup     bash, sourced with `set -e` in the case's working
#                  directory before the program runs, in the shell that then
#                  execs it: it makes what the arguments name, and a umask it
#                  sets is the program's
#   NAME.stdout    stdout (empty if absent and there is no NAME.bpf)
#   NAME.bpf       a filter libseccomp wrote: stdout, or, when NAME.stdout
#                  exists too, the file its first line names, relative to
#                  the case's working directory
#   NAME.stderr    stderr (empty if absent)
#   NAME.tree      the working directory afterwards, one `MODE PATH` line
#                  per entry (find's %M %P), bytewise sorted by path (empty
#                  if absent)
#
# Each case runs with an empty environment in a working directory of its
# own, empty but for what NAME.setup makes. A value only the check can know, such as a store path or a project
# key, is a set's `vars` entry, or one its `caseVars` prints for the case:
# @NAME@ in NAME.args, NAME.stdout, NAME.stderr and NAME.tree is replaced by
# it before the run and the compare. `.bpf` and `.stdin` files are compared
# and fed as they are. A set's other files (inputs its cases name, and
# `caseVars`'s) are not cases.
#
# A .bpf file depends on libseccomp as well as on flong, so a set holding
# them has a LIBSECCOMP file, libseccomp's version and a newline, and the
# check compares it with pkgs.libseccomp's first, failing with `libseccomp
# changed: run golden-update` before any case runs. The .bpf files are
# x86_64's filters, which cover i386 and x32 too
# (src/seccomp/compile.zig:159-164); on another system a .bpf case checks
# its stderr and status only.
#
# golden-update (`nix run .#golden-update`, from the repo root) is this
# file's passthru.update. It rewrites the .bpf files and LIBSECCOMP and
# nothing else, and only when libseccomp's version differs from LIBSECCOMP
# (at one version, a changed byte is a bug in flong, not an update). It
# refuses, writing nothing, when a case's stderr or status changed, or when
# `bpfdump eval` of the old and new bytes differ, which would mean libseccomp
# changed what a policy means (ZIG.md, stop condition 9). Its commit is its
# own and shows both eval texts equal.
#
# pkgs defaults to the flake's locked nixpkgs, as launcher/default.nix:11-20
# does; seccomp is the program the seccomp sets run against, launcher the
# output whose bin/flong-init the init set does.
{
  pkgs ?
    let
      locked = (builtins.fromJSON (builtins.readFile ../flake.lock)).nodes.nixpkgs.locked;
    in
    import (fetchTarball {
      url = "https://github.com/${locked.owner}/${locked.repo}/archive/${locked.rev}.tar.gz";
      sha256 = locked.narHash;
    }) { },
  seccomp ? import ../seccomp { inherit pkgs; },
  launcher ? import ../launcher { inherit pkgs; },
}:
let
  inherit (pkgs) lib;

  # golden/dump.txt in place of the live `systemd-analyze syscall-filter`,
  # so a systemd bump changes no case. dump.txt is that dump as
  # seccomp/policy.nix's `dump` makes it (comment lines dropped) from systemd
  # 261.2, so `dump` here has the same bytes; the tooling cases name it as
  # @DUMP@.
  analyze = pkgs.writeShellScriptBin "systemd-analyze" ''
    [ "$*" = syscall-filter ] || exit 99
    exec ${pkgs.coreutils}/bin/cat ${./golden/dump.txt}
  '';
  policy = import ../seccomp/policy.nix {
    inherit pkgs lib;
    systemd = analyze;
    compiler = seccomp;
  };

  # Each set's program and derived values. A set whose directory does not
  # exist is an evaluation error: skipped, it would pass having compared
  # nothing.
  sets = {
    # Recorded from the C of 2026-09-23 (seccomp/flong-seccomp.c, deleted
    # in phase 1 b): every message it prints but three no input reaches,
    # libseccomp failing to add the i386 or x32 arch or to set the
    # optimisation (src/seccomp/compile.zig:159-167). The
    # repo's audit, tty and nsmask policies are copies, so a policy edit
    # moves nothing here; no case comes from the live systemd dump.
    seccomp = {
      program = "${seccomp}/bin/flong-seccomp";
      vars = { };
    };

    # Recorded from the awk and bash of 2026-09-23 (seccomp/expand.awk,
    # seccomp/policy.nix:81-209, deleted in phase 2 b) over golden/dump.txt,
    # through a `tooling SUB DUMP ARG...` that ran them in the argv of the
    # subcommands that replaced them (ZIG.md quirks 16 and 38): expand-* the
    # names of every tier variant and the expander's refusals, render-* the
    # rendered policies, project-* a project corpus. parity.groups and
    # strict.groups are copies of seccomp/'s. A project case that compiles
    # has NAME.policy, the policy it renders, from which the check derives
    # its key, KEY, as the compiler does: the sha256 of its own store path,
    # a newline, and the policy without its trailing newline (quirk 36).
    tooling = {
      program = "${seccomp}/bin/flong-seccomp";
      vars = {
        DUMP = "${policy.dump}";
        GOLDEN = "${cases}";
      };
      caseVars = ''
        if [[ -e $dir/$name.policy ]]; then
          key=$(printf '%s\n%s' ${seccomp} "$(<"$dir/$name.policy")" | sha256sum)
          echo "KEY=''${key%% *}"
        fi
      '';
    };

    # Recorded from the C of 2026-09-23 (launcher/flong-init.c, deleted in
    # phase 3 b): every refusal of its argv (:86-148, 179-193) in the order
    # it checks them, each field's edge (0-2, INT_MAX, (gid_t)-1, ULONG_MAX
    # and past it, signs, blanks, empty fields), GROUPS counted against
    # NGROUPS_MAX before any gid is parsed, and a refused word over 1 KiB,
    # printed whole (ZIG.md quirk 22). accepted-* pass every argv check and
    # stop at the first call, setgroups, with EPERM: a Nix builder never
    # holds CAP_SETGID. What follows it needs CAP_SETGID and CAP_SETPCAP in
    # a user namespace, which CI's build sandbox refuses, or pid 1: the
    # gate's EOF and a failing chdir to a DIR over 1 KiB are checks.native's
    # (tests/native.nix), the rest is the gate and the launches of rootless
    # and basic.
    init = {
      program = "${launcher}/bin/flong-init";
      vars = { };
    };

    # Recorded from the C of 2026-09-24 (launcher/flong-sweeper.c and
    # flong-record.c:46-89's state_open, deleted in phase 5 b): the usage
    # line, then every refusal of the state directory and its sessions/
    # (the open, the owner and the mode, sessions/ made under the umask or
    # found as it is), in the order it makes them, and a message over 1 KiB
    # cut to 1023 bytes (ZIG.md quirk 22). holder-* pass the state
    # directory and stop at the next refusal, cg_holder_self's
    # (flong-cgroup.c:279-296), since a builder is never in a holder unit's
    # supervisor leaf; OWN is the cgroup that message names, as
    # own_cgroup (:95-119) spells it. Not reached here: root (uid 0, which
    # rootless.nix:629-642 has), fstat or mkdir failing on a directory the
    # caller owns, and the holder's other refusals, which need a cgroup the
    # sandbox does not give. CALLER is the builder's uid, OWNER that of the
    # store directory GOLDEN.
    sweeper = {
      program = "${launcher}/bin/flong-sweeper";
      vars = {
        GOLDEN = "${cases}";
      };
      caseVars = ''
        echo "CALLER=$(id -u)"
        echo "OWNER=$(stat -c %u ${cases})"
        own=$(sed -n 's/^0:://p' /proc/self/cgroup)
        if [[ $own == / ]]; then
          own=
        fi
        echo "OWN=/sys/fs/cgroup$own"
      '';
    };

    # The subcommands' usage errors, the one text phase 2 (a) changed
    # (quirk 38): rewritten from the bash's then, and expand's added.
    tooling-usage = {
      program = "${seccomp}/bin/flong-seccomp";
      vars = {
        DUMP = "${policy.dump}";
      };
    };
  };

  cases = lib.fileset.toSource {
    root = ./golden;
    fileset = ./golden;
  };

  x86_64 = pkgs.stdenv.hostPlatform.system == "x86_64-linux";

  # The shell both the check and golden-update source: run_case and expect.
  lib-sh = pkgs.writeText "golden-lib.sh" ''
    # run_case PROGRAM DIR NAME OUT [VAR=VALUE]...: runs case NAME of DIR,
    # leaving its stdout, stderr and status in OUT, its working directory in
    # OUT/work, and that directory's listing in OUT/tree.
    run_case() {
      local program=$1 dir=$2 name=$3 out=$4 stdin=/dev/null redirect= setup=/dev/null work kv i
      shift 4
      local -a args=()
      if [[ -e $dir/$name.args ]]; then
        mapfile -t args <"$dir/$name.args"
      fi
      for kv in "$@"; do
        for i in "''${!args[@]}"; do
          args[i]=''${args[i]//@''${kv%%=*}@/''${kv#*=}}
        done
      done
      if [[ -e $dir/$name.stdin ]]; then
        stdin=$dir/$name.stdin
      fi
      if [[ -e $dir/$name.redirect ]]; then
        redirect=$(<"$dir/$name.redirect")
      fi
      if [[ -e $dir/$name.setup ]]; then
        setup=$dir/$name.setup
      fi
      work=$out/work
      mkdir "$work"
      set +e
      (
        cd "$work" || exit 1
        set -e
        # shellcheck source=/dev/null
        source "$setup"
        set +e
        # shellcheck disable=SC2016
        eval 'exec env -i "$program" "''${args[@]}" <"$stdin" >"$out/stdout" 2>"$out/stderr"' "$redirect"
      )
      echo $? >"$out/status"
      set -e
      (cd "$work" && find . -mindepth 1 -printf '%M %P\n' | LC_ALL=C sort -k 2) >"$out/tree"
    }

    # written DIR NAME OUT: the file case NAME's .bpf is compared with, from
    # its run in OUT: stdout, or the file stdout names when NAME.stdout
    # exists too.
    written() {
      local dir=$1 name=$2 out=$3 path
      if [[ -e $dir/$name.stdout ]]; then
        IFS= read -r path <"$out/stdout" || true
        printf '%s\n' "$out/work/$path"
      else
        printf '%s\n' "$out/stdout"
      fi
    }

    # expect FILE OUT [VAR=VALUE]...: writes FILE to OUT with every @VAR@
    # replaced, or an empty OUT if FILE does not exist.
    expect() {
      local file=$1 out=$2 content kv
      shift 2
      if [[ ! -e $file ]]; then
        : >"$out"
      elif (($# == 0)); then
        cp "$file" "$out"
      else
        IFS= read -rd "" content <"$file" || true
        for kv in "$@"; do
          content=''${content//@''${kv%%=*}@/''${kv#*=}}
        done
        printf '%s' "$content" >"$out"
      fi
    }
  '';

  # A call of FN (run_set or prepare) for set NAME: its case_vars, then FN
  # NAME PROGRAM VAR=VALUE... with the set's vars. case_vars DIR NAME prints
  # the case's own VAR=VALUE lines.
  setCall =
    fn: name: s:
    ''
      case_vars() {
        local dir=$1 name=$2
        :
        ${s.caseVars or ""}
      }
      ${fn} ${name} ${
        lib.escapeShellArgs ([ s.program ] ++ lib.mapAttrsToList (k: v: "${k}=${v}") s.vars)
      }
    '';

  libseccompVersion = pkgs.libseccomp.version;

  check =
    pkgs.runCommand "golden"
      {
        nativeBuildInputs = [ pkgs.diffutils ];
        passthru = {
          inherit update;
          libSh = lib-sh;
        };
      }
      ''
        set -euo pipefail
        source ${lib-sh}

        # libseccomp first: a .bpf difference means nothing until it holds.
        for lock in ${cases}/*/LIBSECCOMP; do
          [[ -e $lock ]] || continue
          if ! printf '%s\n' ${lib.escapeShellArg libseccompVersion} | cmp -s - "$lock"; then
            echo "libseccomp changed: run golden-update" >&2
            exit 1
          fi
        done

        failed=0
        mkdir -p $out
        run_set() {
          local set=$1 program=$2 dir=${cases}/$1 status name got bpf n=0
          local -a vars
          shift 2
          for status in "$dir"/*.status; do
            name=$(basename "$status" .status)
            mapfile -t vars < <(case_vars "$dir" "$name")
            got=$(mktemp -d)
            run_case "$program" "$dir" "$name" "$got" "$@" "''${vars[@]}"
            expect "$status" "$got/status.want"
            expect "$dir/$name.stderr" "$got/stderr.want" "$@" "''${vars[@]}"
            expect "$dir/$name.tree" "$got/tree.want" "$@" "''${vars[@]}"
            expect "$dir/$name.stdout" "$got/stdout.want" "$@" "''${vars[@]}"
            if [[ -e $dir/$name.bpf ]]; then
              bpf=$dir/$name.bpf
              ${lib.optionalString (!x86_64) ''bpf=$(written "$dir" "$name" "$got") # x86_64's bytes; see above''}
              if ! cmp -s "$bpf" "$(written "$dir" "$name" "$got")"; then
                echo "golden: $set/$name: filter differs:" >&2
                cmp -l "$bpf" "$(written "$dir" "$name" "$got")" 2>&1 | head -n 20 >&2 || true
                failed=1
              fi
            fi
            if [[ -e $dir/$name.bpf && ! -e $dir/$name.stdout ]]; then
              : # stdout is the filter, compared above
            elif ! cmp -s "$got/stdout.want" "$got/stdout"; then
              echo "golden: $set/$name: stdout differs:" >&2
              diff -a "$got/stdout.want" "$got/stdout" | head -c 4096 >&2 || true
              echo >&2
              failed=1
            fi
            if ! cmp -s "$got/status.want" "$got/status"; then
              echo "golden: $set/$name: status $(<"$got/status"), not $(<"$got/status.want")" >&2
              failed=1
            fi
            if ! cmp -s "$got/stderr.want" "$got/stderr"; then
              echo "golden: $set/$name: stderr differs:" >&2
              diff -a "$got/stderr.want" "$got/stderr" | head -c 4096 >&2 || true
              echo >&2
              failed=1
            fi
            if ! cmp -s "$got/tree.want" "$got/tree"; then
              echo "golden: $set/$name: working directory differs:" >&2
              diff -a "$got/tree.want" "$got/tree" | head -c 4096 >&2 || true
              failed=1
            fi
            rm -rf "$got"
            n=$((n + 1))
          done
          echo "golden: $set: $n cases" | tee -a $out/cases
        }
        ${lib.concatStrings (
          lib.mapAttrsToList (
            name: s:
            if builtins.pathExists (./golden + "/${name}") then
              setCall "run_set" name s
            else
              throw "golden: tests/golden/${name} does not exist"
          ) sets
        )}
        if ((failed)); then
          exit 1
        fi
      '';

  # The sets golden-update rewrites: those with a LIBSECCOMP.
  bpfSets = lib.filterAttrs (
    name: _: builtins.pathExists (./golden + "/${name}/LIBSECCOMP")
  ) sets;

  update = pkgs.writeShellApplication {
    name = "golden-update";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.diffutils
      pkgs.findutils
      (import ./parity { inherit pkgs; })
    ];
    text = ''
      # shellcheck source=/dev/null
      source ${lib-sh}
      want=${lib.escapeShellArg libseccompVersion}
      if [[ ! -d tests/golden ]]; then
        echo "golden-update: run it from the repository's root" >&2
        exit 2
      fi
      new=$(mktemp -d)
      trap 'rm -rf "$new"' EXIT

      # Every new byte is made and judged before any file is written.
      prepare() {
        local set=$1 program=$2 dir=tests/golden/$1 bpf name got filter
        local -a vars
        shift 2
        if [[ $(<"$dir/LIBSECCOMP") == "$want" ]]; then
          echo "golden-update: $dir/LIBSECCOMP already says $want; at one version a changed byte is a bug" >&2
          exit 1
        fi
        mkdir -p "$new/$set"
        for bpf in "$dir"/*.bpf; do
          name=$(basename "$bpf" .bpf)
          mapfile -t vars < <(case_vars "$dir" "$name")
          got=$(mktemp -d)
          run_case "$program" "$PWD/$dir" "$name" "$got" "$@" "''${vars[@]}"
          expect "$dir/$name.status" "$got/status.want"
          expect "$dir/$name.stderr" "$got/stderr.want" "$@" "''${vars[@]}"
          expect "$dir/$name.tree" "$got/tree.want" "$@" "''${vars[@]}"
          if [[ -e $dir/$name.stdout ]]; then
            expect "$dir/$name.stdout" "$got/stdout.want" "$@" "''${vars[@]}"
          else
            cp "$got/stdout" "$got/stdout.want"
          fi
          if ! cmp -s "$got/status.want" "$got/status" || ! cmp -s "$got/stderr.want" "$got/stderr" ||
            ! cmp -s "$got/tree.want" "$got/tree" || ! cmp -s "$got/stdout.want" "$got/stdout"; then
            echo "golden-update: $set/$name: its stderr, status, stdout or working directory changed, which golden-update does not record:" >&2
            cat "$got/stderr" >&2
            exit 1
          fi
          filter=$(written "$dir" "$name" "$got")
          bpfdump eval -k "$bpf" -k "$filter" "$bpf" >"$got/old.eval"
          bpfdump eval -k "$bpf" -k "$filter" "$filter" >"$got/new.eval"
          if ! diff -u "$got/old.eval" "$got/new.eval" >&2; then
            echo "golden-update: $set/$name: bpfdump eval differs: libseccomp changed what the policy means" >&2
            exit 1
          fi
          cp "$filter" "$new/$set/$name.bpf"
          rm -rf "$got"
        done
      }
      write() {
        local set=$1 bpf
        for bpf in "$new/$set"/*.bpf; do
          if ! cmp -s "$bpf" "tests/golden/$set/$(basename "$bpf")"; then
            echo "golden-update: $set/$(basename "$bpf") rewritten"
          fi
          cp "$bpf" "tests/golden/$set/"
        done
        printf '%s\n' "$want" >"tests/golden/$set/LIBSECCOMP"
        echo "golden-update: tests/golden/$set/LIBSECCOMP is $want"
      }
      ${lib.concatStrings (lib.mapAttrsToList (setCall "prepare") bpfSets)}
      ${lib.concatMapStrings (name: "write ${name}\n") (lib.attrNames bpfSets)}
    '';
  };
in
check
