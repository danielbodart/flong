# seccomp-transition: phase 1's check that the Zig flong-seccomp is the C
# one (ZIG.md, "Phase 1"). The C is built here, from
# seccomp/flong-seccomp.c as seccomp/default.nix built it before the port,
# and never leaves this derivation. Both compile the same inputs and their
# stdout, stderr and status are compared with cmp:
#
#   - the tier policies of seccomp/policy.nix, rendered from the live
#     systemd dump by policy.nix's own derivations: parity and strict, each
#     denying with 1, 13, 38 and log; debug; nestedSandbox; allow and deny
#     entries on each tier
#   - the fixed filters' policies, seccomp/{audit,tty,nsmask}.policy
#   - every case of tests/golden/seccomp, the refusal corpus, run as the
#     golden check runs it (golden.nix's run_case)
#
# A difference is a Zig bug when the Zig makes other libseccomp calls or in
# another order; otherwise it is stop condition 2. Deleted with the C in
# phase 1 (b).
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

  policy = import ../seccomp/policy.nix {
    inherit pkgs lib;
    # module.nix's default, config.systemd.package.
    systemd = pkgs.systemd;
    compiler = seccomp;
  };

  base = {
    debug = false;
    nestedSandbox = false;
    allow = [ ];
    deny = [ ];
    errno = "EPERM";
    log = false;
  };

  denials = {
    "1" = { };
    "13" = {
      errno = "EACCES";
    };
    "38" = {
      errno = "ENOSYS";
    };
    log = {
      log = true;
    };
  };

  tiers = lib.listToAttrs (
    lib.concatMap (
      tier:
      lib.mapAttrsToList (d: extra: {
        name = "${tier}-${d}";
        value = base // { inherit tier; } // extra;
      }) denials
      ++ [
        {
          name = "${tier}-debug";
          value = base // {
            inherit tier;
            debug = true;
          };
        }
        {
          name = "${tier}-nestedSandbox";
          value = base // {
            inherit tier;
            nestedSandbox = true;
          };
        }
        {
          name = "${tier}-allow-deny";
          value = base // {
            inherit tier;
            allow = [
              "@keyring"
              "userfaultfd"
            ];
            deny = [
              "ptrace"
              "@swap"
            ];
            errno = "ENOSYS";
          };
        }
      ]
    ) [ "parity" "strict" ]
  );

  # Each tier variant's policy text, rendered as policy.nix's filterFor does.
  rendered = lib.mapAttrsToList (
    name: s: "${name} ${policy.render}/bin/flong-seccomp-render ${policy.namesFor s} ${policy.deny s}"
  ) tiers;

  golden = import ./golden.nix { inherit pkgs seccomp; };
in
pkgs.runCommandCC "seccomp-transition"
  {
    buildInputs = [ pkgs.libseccomp ];
    nativeBuildInputs = [ pkgs.diffutils ];
  }
  ''
    set -euo pipefail
    source ${golden.libSh}

    # The C, as seccomp/default.nix built it before phase 1.
    mkdir -p c
    $CC -std=gnu11 -O2 -D_GNU_SOURCE -Wall -Wextra -Werror \
      -o c/flong-seccomp ${../seccomp/flong-seccomp.c} -lseccomp
    c=$PWD/c/flong-seccomp
    zig=${seccomp}/bin/flong-seccomp

    failed=0
    n=0
    mkdir -p $out
    # same WHAT C-DIR ZIG-DIR: stdout, stderr and status equal.
    same() {
      local what=$1 f
      for f in stdout stderr status; do
        if ! cmp -s "$2/$f" "$3/$f"; then
          echo "seccomp-transition: $what: $f differs:" >&2
          if [[ $f == stdout ]]; then
            cmp -l "$2/$f" "$3/$f" 2>&1 | head -n 20 >&2 || true
          else
            diff -a "$2/$f" "$3/$f" | head -c 4096 >&2 || true
          fi
          failed=1
        fi
      done
      n=$((n + 1))
    }

    # The comparison's own controls, since a compare that cannot fail
    # passes: the two programs are different files, and same sees a
    # difference in each of stdout, stderr and status.
    if cmp -s "$c" "$zig"; then
      echo "seccomp-transition: the C and the Zig are the same file" >&2
      exit 1
    fi
    ctl=$(mktemp -d)
    for f in stdout stderr status; do
      rm -rf "$ctl/a" "$ctl/b"
      mkdir "$ctl/a" "$ctl/b"
      for g in stdout stderr status; do
        echo "$g" >"$ctl/a/$g"
        echo "$g" >"$ctl/b/$g"
      done
      echo other >"$ctl/b/$f"
      same "control/$f" "$ctl/a" "$ctl/b" 2>/dev/null
      if ((!failed)); then
        echo "seccomp-transition: same misses a $f difference" >&2
        exit 1
      fi
      failed=0
    done
    rm -rf "$ctl"
    n=0

    # compile WHAT POLICY: both compilers over one policy file, which each
    # must accept.
    compile() {
      local what=$1 policy=$2 got side
      got=$(mktemp -d)
      for side in c zig; do
        mkdir "$got/$side"
        set +e
        env -i "''${!side}" <"$policy" >"$got/$side/stdout" 2>"$got/$side/stderr"
        echo $? >"$got/$side/status"
        set -e
      done
      same "$what" "$got/c" "$got/zig"
      if [[ $(<"$got/zig/status") != 0 ]]; then
        echo "seccomp-transition: $what: refused: $(<"$got/zig/stderr")" >&2
        failed=1
      fi
      printf '%s: %d instructions, %s\n' "$what" $(($(stat -c %s "$got/zig/stdout") / 8)) \
        "$(<"$got/zig/stderr")" >>$out/filters
      rm -rf "$got"
    }

    while read -r name render names deny; do
      [[ -n $name ]] || continue
      "$render" "$names" "$deny" >"$name.policy"
      compile "$name" "$name.policy"
    done <<'EOF'
    ${lib.concatLines rendered}
    EOF

    ${lib.concatMapStrings (f: ''
      compile ${f} ${../seccomp + "/${f}.policy"}
    '') [ "audit" "tty" "nsmask" ]}

    # The refusal corpus: every golden case, each side in its own run.
    dir=${./golden/seccomp}
    for status in "$dir"/*.status; do
      name=$(basename "$status" .status)
      got=$(mktemp -d)
      mkdir "$got/c" "$got/zig"
      run_case "$c" "$dir" "$name" "$got/c"
      run_case "$zig" "$dir" "$name" "$got/zig"
      same "golden/$name" "$got/c" "$got/zig"
      rm -rf "$got"
    done

    echo "seccomp-transition: $n comparisons" | tee $out/count
    cat $out/filters
    # Every policy compared: the tier variants, the fixed three and each
    # golden case (a lost heredoc line or an empty glob would pass).
    want=$((${toString (builtins.length rendered + 3)} + $(find "$dir" -name '*.status' | wc -l)))
    if ((n != want)); then
      echo "seccomp-transition: $n comparisons, not $want" >&2
      exit 1
    fi
    if ((failed)); then
      exit 1
    fi
  ''
