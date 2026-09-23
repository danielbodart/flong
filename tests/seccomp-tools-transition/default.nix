# seccomp-tools-transition: phase 2's check that `flong-seccomp expand`,
# `render` and `project` are the awk and bash they replace (ZIG.md,
# "Phase 2"). The old tools are built here from old.nix and expand.awk,
# copies of seccomp/policy.nix's and seccomp/expand.awk as they were before
# the port, and never leave this derivation. Both run over the LIVE dump,
# pkgs.systemd's (module.nix's default, config.systemd.package), and
# compare:
#
#   names     every phase-1 tier variant, parity and strict, each plain, with
#             debug, nestedSandbox, both, and allow/deny entries, and @known:
#             the names files, by cmp
#   rendered  each tier's policy denying with 1, 13, 38 and log, by cmp
#   corpus    every expand-, render- and project- case of
#             tests/golden/tooling, the expander's and render's refusals and
#             a project corpus (groups, comments, blank lines, CR, no final
#             newline, unknown groups and names, a deny of everything, each
#             refusal, directories it cannot make), run by both sides as
#             `SUB DUMP ARG...` over the live dump, a project's NAMES the
#             live strict tier's: stdout, stderr, status and the working
#             directory, and the .bpf file a project names, by cmp
#   extra     a bad DENY to project (its message and 2; the bash may add a
#             "Broken pipe" from the printf feeding render, so its stderr
#             need only hold the line), a warm cache, a DIR the caller can
#             write and search but not read (mktemp and mv need no read),
#             an unsorted NAMES to render, where comm's merge and warnings
#             are the answer, a DIR it cannot write (mktemp's own line), a
#             umask without the owner's write bit (the shell's `>` refused
#             mktemp's file), and a directory for each file awk and mapfile
#             read (skipped, or no names); the bash's and gawk's own
#             prefixes, which name their scripts, are made the Zig's first
#
# Each project that compiles has its key checked against `printf '%s\n%s'
# $seccomp "$policy" | sha256sum` (quirk 36), its policy derived by the old
# tools alone. Controls: the two sides are different programs; `same` sees a
# planted difference in each thing it compares; the comparison count is
# exact; and the corpus has projects that compile and ones that are refused.
# A difference is a Zig bug. Deleted with the bash in phase 2 (b).
{
  pkgs ?
    let
      locked = (builtins.fromJSON (builtins.readFile ../../flake.lock)).nodes.nixpkgs.locked;
    in
    import (fetchTarball {
      url = "https://github.com/${locked.owner}/${locked.repo}/archive/${locked.rev}.tar.gz";
      sha256 = locked.narHash;
    }) { },
  seccomp ? import ../../seccomp { inherit pkgs; },
}:
let
  inherit (pkgs) lib;

  policy = import ../../seccomp/policy.nix {
    inherit pkgs lib;
    systemd = pkgs.systemd;
    compiler = seccomp;
  };
  inherit (policy) dump;

  old = import ./old.nix {
    inherit pkgs lib dump;
    compiler = seccomp;
  };

  # policy.nix's tierNames and namesFor, with the old expander.
  oldTierNames = rec {
    parity = old.expand [ ../../seccomp/parity.groups ];
    strict = old.expand [
      parity
      ../../seccomp/strict.groups
    ];
  };
  oldNamesFor =
    s:
    let
      extras =
        lib.optional s.debug "ptrace"
        ++ lib.optional s.nestedSandbox "@mount"
        ++ s.allow
        ++ map (x: "-${x}") s.deny;
    in
    if extras == [ ] then
      oldTierNames.${s.tier}
    else
      old.expand [
        oldTierNames.${s.tier}
        (pkgs.writeText "flong-seccomp-extra" (lib.concatLines extras))
      ];

  base = {
    debug = false;
    nestedSandbox = false;
    allow = [ ];
    deny = [ ];
    errno = "EPERM";
    log = false;
  };
  variants = {
    plain = { };
    debug = {
      debug = true;
    };
    nestedSandbox = {
      nestedSandbox = true;
    };
    debug-nestedSandbox = {
      debug = true;
      nestedSandbox = true;
    };
    allow-deny = {
      allow = [
        "@keyring"
        "userfaultfd"
      ];
      deny = [
        "ptrace"
        "@swap"
      ];
    };
  };
  tiers = [
    "parity"
    "strict"
  ];

  # "WHAT OLD NEW" per names file.
  names =
    lib.concatMap (
      tier:
      lib.mapAttrsToList (
        v: extra:
        let
          s = base // { inherit tier; } // extra;
        in
        "${tier}-${v} ${oldNamesFor s} ${policy.namesFor s}"
      ) variants
    ) tiers
    ++ [
      "known ${old.known} ${policy.expand [ (pkgs.writeText "known" "@known") ]}"
    ];

  # "WHAT NAMES DENY" per rendered policy, the old tier names for both.
  rendered = lib.concatMap (
    tier: map (d: "${tier}-${d} ${oldTierNames.${tier}} ${d}") [ "1" "13" "38" "log" ]
  ) tiers;

  # The old tools in the argv of the subcommands, as golden.nix's
  # `tooling` ran them when the cases were recorded (0dc291c): expand is
  # policy.nix:29-30's command line, DUMP its first operand whatever it is;
  # render and project, which had it built in, drop DUMP.
  tooling = pkgs.writeShellApplication {
    name = "tooling";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.gawk
    ];
    text = ''
      sub=$1
      shift
      if [[ $sub == expand ]]; then
        awk -f ${./expand.awk} "$@" | LC_ALL=C sort
        exit
      fi
      if (($# > 0)); then
        if [[ $1 != "${dump}" ]]; then
          echo "tooling: DUMP is not ${dump}: $1" >&2
          exit 99
        fi
        shift
      fi
      case $sub in
        render) exec ${old.render}/bin/flong-seccomp-render "$@" ;;
        project) exec ${old.project}/bin/flong-seccomp-project "$@" ;;
        *)
          echo "tooling: no subcommand $sub" >&2
          exit 99
          ;;
      esac
    '';
  };

  corpus = lib.fileset.toSource {
    root = ../golden/tooling;
    fileset = lib.fileset.fileFilter (
      f: lib.hasPrefix "expand-" f.name || lib.hasPrefix "render-" f.name || lib.hasPrefix "project-" f.name
    ) ../golden/tooling;
  };
  goldenCases = lib.fileset.toSource {
    root = ../golden;
    fileset = ../golden;
  };
in
pkgs.runCommand "seccomp-tools-transition"
  {
    nativeBuildInputs = [
      pkgs.diffutils
      pkgs.findutils
    ];
  }
  ''
    set -euo pipefail
    old=${tooling}/bin/tooling
    zig=${seccomp}/bin/flong-seccomp
    seccomp=${seccomp}
    dump=${dump}
    strict=${oldTierNames.strict}

    failed=0
    n=0
    mkdir -p $out
    # same WHAT OLD-DIR ZIG-DIR [FILE...]: each FILE (stdout, stderr, status,
    # tree, bpf by default) equal. The directories must be run's of the old
    # tools and of the Zig, in that order, as each says in its `side`: a
    # compare of one side with itself would pass.
    same() {
      local what=$1 a=$2 b=$3 f
      shift 3
      (($# > 0)) || set -- stdout stderr status tree bpf
      if [[ $(<"$a/side") != old || $(<"$b/side") != zig ]]; then
        echo "seccomp-tools-transition: $what: not the old tools against the Zig: $(<"$a/side") against $(<"$b/side")" >&2
        failed=1
      fi
      for f in "$@"; do
        if ! cmp -s "$a/$f" "$b/$f"; then
          echo "seccomp-tools-transition: $what: $f differs:" >&2
          diff -a "$a/$f" "$b/$f" | head -c 4096 >&2 || true
          echo >&2
          failed=1
        fi
      done
      n=$((n + 1))
    }

    # The controls, since a compare that cannot fail passes: the two sides
    # are different programs, and same sees a difference in each file and
    # a side that is not the one it should be.
    if cmp -s ${tooling}/bin/tooling "$zig"; then
      echo "seccomp-tools-transition: the two sides are one program" >&2
      exit 1
    fi
    ctl=$(mktemp -d)
    for f in stdout stderr status tree bpf side; do
      rm -rf "$ctl/a" "$ctl/b"
      mkdir "$ctl/a" "$ctl/b"
      for g in stdout stderr status tree bpf; do
        echo "$g" >"$ctl/a/$g"
        echo "$g" >"$ctl/b/$g"
      done
      echo old >"$ctl/a/side"
      echo zig >"$ctl/b/side"
      echo other >"$ctl/b/$f"
      same "control/$f" "$ctl/a" "$ctl/b" 2>/dev/null
      if ((!failed)); then
        echo "seccomp-tools-transition: same misses a $f difference" >&2
        exit 1
      fi
      failed=0
    done
    rm -rf "$ctl"
    n=0

    # ---- names ----
    while read -r what a b; do
      [[ -n $what ]] || continue
      if [[ $a == "$b" ]]; then
        echo "seccomp-tools-transition: names/$what: one file for both sides: $a" >&2
        failed=1
      fi
      if [[ ! -s $a ]]; then
        echo "seccomp-tools-transition: names/$what: empty" >&2
        failed=1
      fi
      n=$((n + 1))
      if ! cmp -s "$a" "$b"; then
        echo "seccomp-tools-transition: names/$what differs:" >&2
        diff "$a" "$b" | head -n 20 >&2 || true
        failed=1
      fi
      echo "names/$what: $(wc -l <"$b") names" >>$out/names
    done <<'EOF'
    ${lib.concatLines names}
    EOF

    # run SIDE OUT STDIN ARG...: SIDE's program in OUT/work, as golden runs
    # a case, under $run_umask if set; the .bpf a project names copied to
    # OUT/bpf; SIDE in OUT/side.
    run() {
      local side=$1 out=$2 stdin=$3 path
      shift 3
      mkdir -p "$out/work"
      echo "$side" >"$out/side"
      set +e
      (cd "$out/work" && umask "''${run_umask:-$(umask)}" && exec env -i "''${!side}" "$@" <"$stdin" >"$out/stdout" 2>"$out/stderr")
      echo $? >"$out/status"
      set -e
      # A directory a case made unreadable, readable again for find.
      if [[ -n ''${unreadable:-} ]]; then chmod u+r "$out/work/$unreadable"; fi
      (cd "$out/work" && find . -mindepth 1 -printf '%M %P\n' | LC_ALL=C sort -k 2) >"$out/tree"
      : >"$out/bpf"
      if [[ $1 == project && $(<"$out/status") == 0 ]]; then
        IFS= read -r path <"$out/stdout"
        cp "$out/work/$path" "$out/bpf"
      fi
    }

    # ---- rendered ----
    while read -r what names deny; do
      [[ -n $what ]] || continue
      got=$(mktemp -d)
      run old "$got/old" /dev/null render "$dump" "$names" "$deny"
      run zig "$got/zig" /dev/null render "$dump" "$names" "$deny"
      same "rendered/$what" "$got/old" "$got/zig" stdout stderr status
      echo "rendered/$what: $(wc -l <"$got/zig/stdout") lines, status $(<"$got/zig/status")" >>$out/rendered
      rm -rf "$got"
    done <<'EOF'
    ${lib.concatLines rendered}
    EOF

    # ---- the corpus ----

    # key POLICY-STDIN NAMES DENY: the key the old tools' policy makes,
    # parsing the project's lines as policy.nix:145-167 do for accepted
    # input.
    key() {
      local stdin=$1 names=$2 deny=$3 text list p k
      local -a words spec=()
      while IFS= read -r text || [[ -n $text ]]; do
        read -r -a words <<<"$text"
        if ((''${#words[@]} == 0)) || [[ ''${words[0]} == \#* ]]; then continue; fi
        for x in "''${words[@]:1}"; do
          if [[ ''${words[0]} == deny ]]; then spec+=("-$x"); else spec+=("$x"); fi
        done
      done <"$stdin"
      list=$(printf '%s\n' "''${spec[@]}" | "$old" expand "$dump" "$names" -)
      p=$("$old" render "$dump" <(printf '%s\n' "$list") "$deny")
      k=$(printf '%s\n%s' "$seccomp" "$p" | sha256sum)
      printf '%s\n' "''${k%% *}"
    }

    cases=0 compiled=0 refused=0
    for status in ${corpus}/*.status; do
      name=$(basename "$status" .status)
      dir=${corpus}
      stdin=/dev/null
      [[ -e $dir/$name.stdin ]] && stdin=$dir/$name.stdin
      mapfile -t args <"$dir/$name.args"
      for i in "''${!args[@]}"; do
        args[i]=''${args[i]//@DUMP@/$dump}
        args[i]=''${args[i]//@GOLDEN@/${goldenCases}}
      done
      # A project's NAMES is the live strict tier's.
      if [[ ''${args[0]} == project ]]; then
        args[2]=$strict
      fi
      got=$(mktemp -d)
      run old "$got/old" "$stdin" "''${args[@]}"
      run zig "$got/zig" "$stdin" "''${args[@]}"
      same "corpus/$name" "$got/old" "$got/zig"
      cases=$((cases + 1))
      if [[ ''${args[0]} == project ]]; then
        if [[ $(<"$got/zig/status") == 0 ]]; then
          compiled=$((compiled + 1))
          want=$(key "$stdin" "''${args[2]}" "''${args[3]}")
          have=$(basename "$(<"$got/zig/stdout")" .bpf)
          if [[ $want != "$have" ]]; then
            echo "seccomp-tools-transition: corpus/$name: key $have, not $want" >&2
            failed=1
          fi
          if [[ ! -s $got/zig/bpf ]]; then
            echo "seccomp-tools-transition: corpus/$name: an empty filter" >&2
            failed=1
          fi
          echo "corpus/$name: key $have, $(($(stat -c %s "$got/zig/bpf") / 8)) instructions" >>$out/corpus
        else
          refused=$((refused + 1))
          echo "corpus/$name: status $(<"$got/zig/status"): $(head -n 1 "$got/zig/stderr")" >>$out/corpus
        fi
      fi
      rm -rf "$got"
    done

    # ---- extra ----
    # A bad DENY reaches render after the policy is expanded: its message,
    # exit 2.
    for deny in 2 01 LOG ""; do
      got=$(mktemp -d)
      printf 'allow ptrace\n' >"$got/stdin"
      run old "$got/old" "$got/stdin" project "$dump" "$strict" "$deny" cache/seccomp
      run zig "$got/zig" "$got/stdin" project "$dump" "$strict" "$deny" cache/seccomp
      same "extra/bad-deny-$deny" "$got/old" "$got/zig" stdout status tree
      if [[ $(<"$got/zig/stderr") != "flong-seccomp-render: not 1, 13, 38 or log: $deny" ]] ||
        ! grep -qxF "flong-seccomp-render: not 1, 13, 38 or log: $deny" "$got/old/stderr"; then
        echo "seccomp-tools-transition: extra/bad-deny-$deny: stderr:" >&2
        cat "$got/old/stderr" "$got/zig/stderr" >&2
        failed=1
      fi
      rm -rf "$got"
    done

    # A warm cache: the second run prints the same path and compiles
    # nothing, its file untouched.
    got=$(mktemp -d)
    printf 'allow ptrace\ndeny @swap\n' >"$got/stdin"
    for side in old zig; do
      run $side "$got/$side" "$got/stdin" project "$dump" "$strict" 13 cache/seccomp
      touch -d @1 "$got/$side/work/cache/seccomp/"*.bpf
      mv "$got/$side/stdout" "$got/$side/stdout.cold"
      run $side "$got/$side" "$got/stdin" project "$dump" "$strict" 13 cache/seccomp
      cmp -s "$got/$side/stdout" "$got/$side/stdout.cold" || { echo "seccomp-tools-transition: extra/warm: $side's path moved" >&2; failed=1; }
      [[ $(stat -c %Y "$got/$side/work/cache/seccomp/"*.bpf) == 1 ]] || { echo "seccomp-tools-transition: extra/warm: $side recompiled" >&2; failed=1; }
    done
    same "extra/warm" "$got/old" "$got/zig"
    rm -rf "$got"

    # A DIR the caller can write and search but not read: mktemp and mv
    # need no read, so the old tools compile into it, and the Zig must too.
    got=$(mktemp -d)
    printf 'allow ptrace\n' >"$got/stdin"
    unreadable=cache/seccomp
    for side in old zig; do
      mkdir -p "$got/$side/work/cache/seccomp"
      chmod 0300 "$got/$side/work/cache/seccomp"
      if ls "$got/$side/work/cache/seccomp" >/dev/null 2>&1; then
        echo "seccomp-tools-transition: extra/unreadable-dir: $side's DIR is readable" >&2
        failed=1
      fi
      run $side "$got/$side" "$got/stdin" project "$dump" "$strict" 1 cache/seccomp
    done
    unreadable=
    if [[ $(<"$got/old/status") != 0 ]]; then
      echo "seccomp-tools-transition: extra/unreadable-dir: the old tools refused it" >&2
      failed=1
    fi
    same "extra/unreadable-dir" "$got/old" "$got/zig"
    rm -rf "$got"

    # An unsorted NAMES to render: comm's merge, its warnings, exit 1.
    for deny in 1 38; do
      got=$(mktemp -d)
      printf 'write\nread\nclose\nzzz\naaa\n' >"$got/stdin"
      run old "$got/old" "$got/stdin" render "$dump" /dev/stdin "$deny"
      run zig "$got/zig" "$got/stdin" render "$dump" /dev/stdin "$deny"
      same "extra/unsorted-$deny" "$got/old" "$got/zig"
      rm -rf "$got"
    done

    # norm DIR: DIR/stderr with what only the bash could print made the
    # Zig's, into DIR/stderr.norm: the script's store path and line before a
    # shell error become its name, as quirk 38's prefixes are; gawk's own
    # "awk: SCRIPT:LINE:" before its warnings becomes the expander's name;
    # a temp file's six random letters are XXXXXX.
    norm() {
      sed -E \
        -e 's|^.*/bin/flong-seccomp-project: line [0-9]+: |flong-seccomp-project: |' \
        -e 's|^awk: (/[^ ]*: )?warning: |flong-seccomp: warning: |' \
        -e 's|(\.[0-9a-f]{64}\.)[A-Za-z0-9]{6}:|\1XXXXXX:|' \
        "$1/stderr" >"$1/stderr.norm"
    }

    # A DIR the caller can search but not write: mktemp's refusal, its own
    # line in the C locale, exit 1, nothing left.
    got=$(mktemp -d)
    printf 'allow ptrace\n' >"$got/stdin"
    for side in old zig; do
      mkdir -p "$got/$side/work/cache/seccomp"
      chmod 0500 "$got/$side/work/cache/seccomp"
      run $side "$got/$side" "$got/stdin" project "$dump" "$strict" 1 cache/seccomp
    done
    if [[ $(<"$got/old/status") != 1 ]] || ! grep -q '^mktemp: failed to create file via template' "$got/old/stderr"; then
      echo "seccomp-tools-transition: extra/unwritable-dir: mktemp did not refuse" >&2
      failed=1
    fi
    same "extra/unwritable-dir" "$got/old" "$got/zig"
    rm -rf "$got"

    # A umask that takes the owner's write bit: mktemp makes the temp file,
    # the shell's `>` cannot open it again, and the file goes, exit 1.
    got=$(mktemp -d)
    printf 'allow ptrace\n' >"$got/stdin"
    for side in old zig; do
      mkdir -p "$got/$side/work/cache/seccomp"
      run_umask=0277 run $side "$got/$side" "$got/stdin" project "$dump" "$strict" 1 cache/seccomp
      norm "$got/$side"
    done
    if [[ $(<"$got/old/status") != 1 ]] || ! grep -q 'Permission denied$' "$got/old/stderr"; then
      echo "seccomp-tools-transition: extra/umask-0277: the bash did not refuse" >&2
      failed=1
    fi
    same "extra/umask-0277" "$got/old" "$got/zig" stdout stderr.norm status tree
    rm -rf "$got"

    # A directory where awk or mapfile reads a file: awk skips it with a
    # warning, mapfile reads no names; "." is each run's empty working
    # directory.
    got=$(mktemp -d)
    printf 'read\n' >"$got/spec"
    printf 'allow ptrace\n' >"$got/stdin"
    for side in old zig; do
      run $side "$got/$side-expand" /dev/null expand "$dump" . "$got/spec"
      run $side "$got/$side-project" "$got/stdin" project "$dump" . 1 cache/seccomp
      run $side "$got/$side-render" /dev/null render "$dump" . 13
      for sub in expand project render; do norm "$got/$side-$sub"; done
    done
    if ! grep -q 'is a directory: skipped' "$got/old-expand/stderr"; then
      echo "seccomp-tools-transition: extra/directory: awk did not skip it" >&2
      failed=1
    fi
    for sub in expand project render; do
      same "extra/directory-$sub" "$got/old-$sub" "$got/zig-$sub" stdout stderr.norm status tree bpf
    done
    rm -rf "$got"

    echo "seccomp-tools-transition: $n comparisons; corpus $cases cases, projects $compiled compiled, $refused refused" |
      tee $out/count
    # Every comparison made: the names and rendered lines (a lost heredoc
    # line would pass), each corpus case, and the extras (4 bad denies,
    # the warm cache, the unreadable DIR, 2 unsorted, the unwritable DIR,
    # the umask, 3 directories).
    want=$((${
      toString (builtins.length names + builtins.length rendered)
    } + $(find ${corpus} -name '*.status' | wc -l) + 13))
    if ((n != want)); then
      echo "seccomp-tools-transition: $n comparisons, not $want" >&2
      exit 1
    fi
    if ((compiled < 10 || refused < 10)); then
      echo "seccomp-tools-transition: the corpus compiled $compiled projects and refused $refused" >&2
      exit 1
    fi
    if ((failed)); then
      exit 1
    fi
  ''
