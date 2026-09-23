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
#   NAME.stdout    stdout (empty if absent and there is no NAME.bpf)
#   NAME.bpf       stdout, when it is a filter libseccomp wrote
#   NAME.stderr    stderr (empty if absent)
#
# Each case runs with an empty environment in an empty working directory of
# its own. A value only the check can know, such as a store path or a project
# key, is a set's `vars` entry: @NAME@ in NAME.args, NAME.stdout and
# NAME.stderr is replaced by it before the run and the compare. `.bpf` and
# `.stdin` files are compared and fed as they are.
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
# does; seccomp is the program the seccomp set runs against.
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
}:
let
  inherit (pkgs) lib;

  # Each set's program and derived values. A set whose directory does not
  # exist is skipped.
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
  };

  cases = lib.fileset.toSource {
    root = ./golden;
    fileset = ./golden;
  };

  x86_64 = pkgs.stdenv.hostPlatform.system == "x86_64-linux";

  # The shell both the check and golden-update source: run_case and expect.
  lib-sh = pkgs.writeText "golden-lib.sh" ''
    # run_case PROGRAM DIR NAME OUT [VAR=VALUE]...: runs case NAME of DIR,
    # leaving its stdout, stderr and status in OUT.
    run_case() {
      local program=$1 dir=$2 name=$3 out=$4 stdin=/dev/null redirect= work kv i
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
      work=$(mktemp -d)
      set +e
      (
        cd "$work" || exit 1
        # shellcheck disable=SC2016
        eval 'exec env -i "$program" "''${args[@]}" <"$stdin" >"$out/stdout" 2>"$out/stderr"' "$redirect"
      )
      echo $? >"$out/status"
      set -e
      rm -rf "$work"
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

  # A set's program and vars as bash words: PROGRAM VAR=VALUE...
  setWords =
    s:
    lib.escapeShellArgs (
      [ s.program ] ++ lib.mapAttrsToList (k: v: "${k}=${v}") s.vars
    );

  libseccompVersion = pkgs.libseccomp.version;

  check =
    pkgs.runCommand "golden"
      {
        nativeBuildInputs = [ pkgs.diffutils ];
        passthru = {
          inherit update;
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
          local set=$1 program=$2 dir=${cases}/$1 status name got stdout n=0
          shift 2
          for status in "$dir"/*.status; do
            name=$(basename "$status" .status)
            got=$(mktemp -d)
            run_case "$program" "$dir" "$name" "$got" "$@"
            expect "$status" "$got/status.want"
            expect "$dir/$name.stderr" "$got/stderr.want" "$@"
            if [[ -e $dir/$name.bpf ]]; then
              stdout=$dir/$name.bpf
              ${lib.optionalString (!x86_64) ''stdout=$got/stdout # x86_64's bytes; see above''}
            else
              expect "$dir/$name.stdout" "$got/stdout.want" "$@"
              stdout=$got/stdout.want
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
            if ! cmp -s "$stdout" "$got/stdout"; then
              echo "golden: $set/$name: stdout differs:" >&2
              cmp -l "$stdout" "$got/stdout" 2>&1 | head -n 20 >&2 || true
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
            lib.optionalString (builtins.pathExists (./golden + "/${name}")) ''
              run_set ${name} ${setWords s}
            ''
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
        local set=$1 program=$2 dir=tests/golden/$1 bpf name got
        shift 2
        if [[ $(<"$dir/LIBSECCOMP") == "$want" ]]; then
          echo "golden-update: $dir/LIBSECCOMP already says $want; at one version a changed byte is a bug" >&2
          exit 1
        fi
        mkdir -p "$new/$set"
        for bpf in "$dir"/*.bpf; do
          name=$(basename "$bpf" .bpf)
          got=$(mktemp -d)
          run_case "$program" "$PWD/$dir" "$name" "$got" "$@"
          expect "$dir/$name.status" "$got/status.want"
          expect "$dir/$name.stderr" "$got/stderr.want" "$@"
          if ! cmp -s "$got/status.want" "$got/status" || ! cmp -s "$got/stderr.want" "$got/stderr"; then
            echo "golden-update: $set/$name: its stderr or status changed, which golden-update does not record:" >&2
            cat "$got/stderr" >&2
            exit 1
          fi
          bpfdump eval -k "$bpf" -k "$got/stdout" "$bpf" >"$got/old.eval"
          bpfdump eval -k "$bpf" -k "$got/stdout" "$got/stdout" >"$got/new.eval"
          if ! diff -u "$got/old.eval" "$got/new.eval" >&2; then
            echo "golden-update: $set/$name: bpfdump eval differs: libseccomp changed what the policy means" >&2
            exit 1
          fi
          cp "$got/stdout" "$new/$set/$name.bpf"
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
      ${lib.concatStrings (lib.mapAttrsToList (name: s: "prepare ${name} ${setWords s}\n") bpfSets)}
      ${lib.concatMapStrings (name: "write ${name}\n") (lib.attrNames bpfSets)}
    '';
  };
in
check
