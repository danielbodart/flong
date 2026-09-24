# fixtures-transition: phase 6 (a)'s check that the Zig fixtures are the C
# ones where the build sandbox can run them (ZIG.md, "Phase 6"). The C is
# built here, from tests/parity/bpfdump.c and probe.c and tests/probes.nix's
# inline C, by those files' own `c` derivations, as they built it before
# phase 6, and never leaves the check. Each side runs the same arguments,
# stdin and working directory, and stdout (by cmp), stderr and status must
# be equal:
#
#   - bpfdump eval over the build's filters: every tier variant of
#     seccomp/policy.nix (parity and strict, each denying with 1, 13, 38 and
#     log, debug, nestedSandbox, allow and deny entries), alone and stacked
#     with audit, tty and nsmask as a session runs them, swept with both
#     tiers' constants as tests/parity.nix sweeps; audit, tty and nsmask
#     alone; and every .bpf file of tests/golden/seccomp. That text is what
#     golden-update trusts (ZIG.md, "Tests"; stop condition 9)
#   - bpfdump's refusals: usage, missing and malformed files, -k without a
#     file, too many programs, too many constants, an opcode it does not
#     know (before and after output began), and dump of no process
#   - an evaluation of every opcode the interpreter knows
#   - syscall-probe in the sandbox, whose answers are the sandbox's
#   - ioctl-probe's usage and requests in the spellings strtoul reads, on
#     stdin /dev/null and closed, and one that returns a positive value
#   - swapper's usage and failures, and a live run of each
#
# A dump of a live process's filters, the probe under each tier, the
# requests under the tty filter and the swap races run where they can: the
# parity VM, rootless.nix and tests/native.nix. Deleted with the C in phase
# 6 (b).
{
  pkgs ?
    let
      locked = (builtins.fromJSON (builtins.readFile ../flake.lock)).nodes.nixpkgs.locked;
    in
    import (fetchTarball {
      url = "https://github.com/${locked.owner}/${locked.repo}/archive/${locked.rev}.tar.gz";
      sha256 = locked.narHash;
    }) { },
}:
let
  inherit (pkgs) lib;

  parity = import ./parity { inherit pkgs; };
  probes = import ./probes.nix pkgs;
  zig = parity;
  c = pkgs.symlinkJoin {
    name = "flong-fixtures-c";
    paths = [
      parity.c
      probes.c
    ];
  };

  policy = import ../seccomp/policy.nix {
    inherit pkgs lib;
    # module.nix's default, config.systemd.package.
    systemd = pkgs.systemd;
    compiler = import ../seccomp { inherit pkgs; };
  };

  base = {
    debug = false;
    nestedSandbox = false;
    allow = [ ];
    deny = [ ];
    errno = "EPERM";
    log = false;
  };

  # The tier variants phase 1's transition compiled (d8d4eed,
  # tests/seccomp-transition.nix).
  tiers = lib.listToAttrs (
    lib.concatMap (
      tier:
      lib.mapAttrsToList
        (d: extra: {
          name = "${tier}-${d}";
          value = policy.filterFor (base // { inherit tier; } // extra);
        })
        {
          "1" = { };
          "13".errno = "EACCES";
          "38".errno = "ENOSYS";
          log.log = true;
          debug.debug = true;
          nestedSandbox.nestedSandbox = true;
          allow-deny = {
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
    ) [ "parity" "strict" ]
  );

  fixed = policy.fixed;

  # Programs bpfdump must refuse or run through every opcode it knows:
  # badop, an opcode it does not know first; laterbad, one reached only for
  # nr 5, after nr 0-4's lines; manyk, 5000 constants past its 4096;
  # allops, every opcode of bpfdump.c:102-141, a shift of 33 among them,
  # each in its own block, which syscall nr i runs: the block loads a0, then
  # compares it with no-op jumps, whose constants the sweep tries; it ends
  # with its answer where the output shows it, A's low half under action
  # 0x0001, which action() prints in hex, or a jump's two ends returning
  # 0x00010001 and 0x00010002. A single program whose actions all print as
  # KILL_THREAD hid 29 of the 30 one-opcode plants of bpfdump.zig's run().
  programs = pkgs.writeText "fixtures-bpf.py" ''
    import struct

    def prog(name, insns):
        with open(name, "wb") as f:
            f.write(b"".join(struct.pack("<HBBI", *i) for i in insns))

    prog("badop", [(0x99, 0, 0, 0)])
    prog("laterbad", [(0x20, 0, 0, 0), (0x15, 0, 1, 5), (0x27, 0, 0, 0), (0x06, 0, 0, 0x7FFF0000)])
    prog("manyk", [(0x20, 0, 0, 16)] + [(0x15, 0, 0, k) for k in range(5000)] + [(0x06, 0, 0, 0x7FFF0000)])
    a0 = [(0x20, 0, 0, 16)] + [(0x15, 0, 0, c) for c in (1, 9, 0x80000001, 0xFFFFFFFF)]
    show = [(0x54, 0, 0, 0xFFFF), (0x44, 0, 0, 0x10000), (0x16, 0, 0, 0)]
    ret12 = [(0x06, 0, 0, 0x10001), (0x06, 0, 0, 0x10002)]
    blocks = [a0 + body + show for body in (
        [(0x80, 0, 0, 0)],
        [(0x81, 0, 0, 0), (0x87, 0, 0, 0)],
        [(0x00, 0, 0, 0x1234)],
        [(0x01, 0, 0, 0x4321), (0x87, 0, 0, 0)],
        [(0x02, 0, 0, 3), (0x00, 0, 0, 0), (0x60, 0, 0, 3)],
        [(0x02, 0, 0, 5), (0x00, 0, 0, 0), (0x61, 0, 0, 5), (0x87, 0, 0, 0)],
        [(0x07, 0, 0, 0), (0x03, 0, 0, 7), (0x00, 0, 0, 0), (0x60, 0, 0, 7)],
        [(0x07, 0, 0, 0), (0x00, 0, 0, 0), (0x87, 0, 0, 0)],
        [(0x04, 0, 0, 3)],
        [(0x14, 0, 0, 3)],
        [(0x54, 0, 0, 0x0FF0)],
        [(0x44, 0, 0, 0x0300)],
        [(0x64, 0, 0, 4)],
        [(0x64, 0, 0, 33)],
        [(0x74, 0, 0, 2)],
        [(0x01, 0, 0, 0x0FF0), (0x5C, 0, 0, 0)],
        [(0x01, 0, 0, 0x0300), (0x4C, 0, 0, 0)],
        [(0x84, 0, 0, 0)],
    )]
    blocks.append(a0 + [(0x06, 0, 0, 0x15678)])
    blocks.append(a0 + [(0x05, 0, 0, 1)] + ret12)
    for code, k in ((0x15, 9), (0x25, 9), (0x35, 9), (0x45, 0x80000001)):
        blocks.append(a0 + [(code, 1, 0, k)] + ret12)
        blocks.append(a0 + [(0x01, 0, 0, k), (code | 0x08, 1, 0, 0)] + ret12)
    # Load nr; for each block a jeq and a ja to it; then ALLOW; the blocks.
    insns = [(0x20, 0, 0, 0)]
    at = 1 + 2 * len(blocks) + 1
    for i, b in enumerate(blocks):
        insns += [(0x15, 0, 1, i), (0x05, 0, 0, at - (len(insns) + 2))]
        at += len(b)
    insns.append((0x06, 0, 0, 0x7FFF0000))
    for b in blocks:
        insns += b
    prog("allops", insns)
  '';
in
pkgs.runCommand "fixtures-transition"
  {
    nativeBuildInputs = [
      pkgs.diffutils
      pkgs.binutils
      pkgs.python3
      pkgs.strace
    ];
  }
  ''
    set -euo pipefail
    zig=${zig}/bin
    c=${c}/bin
    failed=0
    n=0
    mkdir -p $out work
    cd work

    # same WHAT C-DIR ZIG-DIR: stdout, stderr and status equal.
    same() {
      local what=$1 f
      for f in stdout stderr status; do
        if ! cmp -s "$2/$f" "$3/$f"; then
          echo "fixtures-transition: $what: $f differs:" >&2
          diff -a "$2/$f" "$3/$f" | head -c 4096 >&2 || true
          failed=1
        fi
      done
      n=$((n + 1))
    }

    # pair WHAT PROGRAM ARGS...: the C (PROGRAM-c) and the Zig over the same
    # arguments, stdin /dev/null unless $stdin names another, in this
    # directory; the Zig's status is echoed to $out/runs. $keep, when set,
    # is where the Zig's output stays.
    pair() {
      local what=$1 prog=$2 got side bin ran=()
      shift 2
      got=$(mktemp -d)
      for side in c zig; do
        mkdir "$got/$side"
        if [[ $side == c ]]; then bin=$c/$prog-c; else bin=$zig/$prog; fi
        ran+=("$(readlink -f "$bin")")
        set +e
        if [[ ''${stdin:-} == closed ]]; then
          "$bin" "$@" >"$got/$side/stdout" 2>"$got/$side/stderr" <&-
        else
          "$bin" "$@" >"$got/$side/stdout" 2>"$got/$side/stderr" <"''${stdin:-/dev/null}"
        fi
        echo $? >"$got/$side/status"
        set -e
      done
      # The control: the two runs were the two files the controls below
      # tell apart.
      if [[ ''${ran[0]} == "''${ran[1]}" || ''${ran[1]} != "$(readlink -f "$zig/$prog")" ]]; then
        echo "fixtures-transition: $what: ran ''${ran[*]}" >&2
        exit 1
      fi
      same "$what" "$got/c" "$got/zig"
      printf '%s: status %s, %s lines (%s), %s\n' "$what" "$(<"$got/zig/status")" \
        "$(wc -l <"$got/zig/stdout")" "$(head -n 1 "$got/zig/stdout" | head -c 60)" \
        "$(head -c 200 "$got/zig/stderr" | tr '\n' '|')" >>$out/runs
      if [[ -n ''${keep:-} ]]; then cp "$got/zig/stdout" "$keep"; fi
      rm -rf "$got"
    }

    # The controls, since a compare that cannot fail passes. Each pair is
    # two files; the C's link glibc and the Zig's but bpfdump do not, and
    # bpfdump's links libseccomp on both sides.
    for prog in bpfdump syscall-probe ioctl-probe swapper; do
      if cmp -s "$c/$prog-c" "$zig/$prog"; then
        echo "fixtures-transition: $prog: the C and the Zig are one file" >&2
        exit 1
      fi
      readelf -dW "$(readlink -f "$c/$prog-c")" >$prog-c.dyn
      readelf -dW "$(readlink -f "$zig/$prog")" >$prog.dyn
      grep -q 'NEEDED.*libc\.so' $prog-c.dyn
    done
    for prog in syscall-probe ioctl-probe swapper; do
      if grep -q NEEDED $prog.dyn; then echo "$prog: the Zig is dynamic" >&2; exit 1; fi
    done
    grep -q 'NEEDED.*libseccomp\.so' bpfdump-c.dyn
    grep -q 'NEEDED.*libseccomp\.so' bpfdump.dyn
    # Both bpfdumps link glibc, so the C's is told apart by what it imports:
    # strerrorname_np, which the Zig's errno.zig replaces.
    readelf -W --dyn-syms "$(readlink -f "$c/bpfdump-c")" >bpfdump-c.syms
    readelf -W --dyn-syms "$(readlink -f "$zig/bpfdump")" >bpfdump.syms
    grep -q strerrorname_np bpfdump-c.syms
    if grep -q strerrorname_np bpfdump.syms; then echo "fixtures-transition: the Zig bpfdump imports strerrorname_np" >&2; exit 1; fi
    # And same sees a difference in each of stdout, stderr and status.
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
        echo "fixtures-transition: same misses a $f difference" >&2
        exit 1
      fi
      failed=0
    done
    rm -rf "$ctl"
    n=0
    want=0

    # ---- bpfdump eval over the build's filters ----
    ${lib.concatStrings (
      lib.mapAttrsToList (name: f: ''
        cp ${f} ${name}.bpf
      '') (tiers // fixed)
    )}
    k="-k parity-1.bpf -k strict-1.bpf"
    for f in ${lib.concatStringsSep " " (lib.attrNames tiers)}; do
      keep=$f.eval pair "eval $f" bpfdump eval $k $f.bpf
      keep=$f.stacked.eval pair "eval $f, stacked" bpfdump eval $k $f.bpf audit.bpf tty.bpf nsmask.bpf
      want=$((want + 2))
    done
    for f in audit tty nsmask; do
      pair "eval $f" bpfdump eval $f.bpf
      want=$((want + 1))
    done
    golden=${./golden/seccomp}
    for f in "$golden"/*.bpf; do
      pair "eval golden/$(basename "$f")" bpfdump eval "$f"
      want=$((want + 1))
    done
    # golden-update's own call: two -k files, one program.
    pair "eval golden-update's" bpfdump eval -k "$golden/tier-errno.bpf" -k parity-1.bpf "$golden/tier-errno.bpf"
    want=$((want + 1))
    # The control: the tiers' evaluations say something, a stack's sweeps
    # included, and differ.
    grep -q '^x86_64    0 read                     ALLOW$' parity-1.eval
    grep -q '^x86_64   16 ioctl .* a1=0x5412 ERRNO(EPERM) (base ALLOW)$' parity-1.stacked.eval
    if cmp -s parity-1.eval strict-1.eval; then echo "fixtures-transition: parity and strict evaluate the same" >&2; exit 1; fi

    # ---- bpfdump's refusals, and every opcode it knows ----
    : >empty
    printf 'abcdefg' >seven
    mkdir adir
    python3 ${programs}
    many=$(for i in $(seq 17); do printf '%s ' audit.bpf; done)
    for args in "" "eval" "dump 1" "foo a b" "eval nope" "eval empty" "eval seven" "eval adir" \
      "eval -k" "eval -k nope audit.bpf" "eval -k audit.bpf" "eval badop" "eval manyk" \
      "eval laterbad" "eval $many" "eval ''${many% audit.bpf }" \
      "dump 999999999 p" "dump abc p" "dump 99999999999999999999 p" "dump -5 p"; do
      # shellcheck disable=SC2086
      pair "bpfdump $args" bpfdump $args
      want=$((want + 1))
    done
    # perror("") prints the text alone; a procfs file's st_size, 0, is its
    # size to fseek (glibc's SEEK_END), where lseek would refuse it.
    pair "bpfdump eval (empty path)" bpfdump eval ""
    pair "bpfdump eval /proc/self/status" bpfdump eval /proc/self/status
    keep=allops.eval pair "bpfdump eval allops" bpfdump eval allops
    want=$((want + 3))
    grep -q '^bpfdump eval laterbad: status 3, 5 lines (.*), bpfdump: unsupported opcode 0x27 at 2|$' $out/runs
    grep -q '^bpfdump eval manyk: status 3, 0 lines (), bpfdump: too many constants|$' $out/runs
    grep -q '^bpfdump eval (empty path): status 2, 0 lines (), No such file or directory|$' $out/runs
    grep -q '^bpfdump eval /proc/self/status: status 2, 0 lines (), bpfdump: /proc/self/status is not a BPF program|$' $out/runs
    grep -q '^bpfdump eval allops: status 0, 8784 lines' $out/runs
    # The control: the blocks' answers show (nr 2, ld imm 0x1234; nr 9, a0 - 3).
    grep -q '^i386    2 fork                     0x00011234$' allops.eval
    grep -q '^x86_64    9 mmap                     0x0001fffd$' allops.eval

    # ---- syscall-probe, in the sandbox ----
    pair "syscall-probe" syscall-probe
    want=$((want + 1))
    grep -q '^syscall-probe: status 0, 39 lines' $out/runs
    # The arguments filters see, which its output does not show: each
    # side's calls under strace, raw, pointers masked. The C passes a
    # negative int through syscall(2) as 0xffffffff, and forks with glibc's
    # clone flags.
    probecalls() {
      strace -f -qq -e signal=none -e raw=all -o "$2" \
        -e trace=clone,perf_event_open,keyctl,setns,open_by_handle_at,add_key,socket \
        "$1" >/dev/null
      sed -E -i 's/^[0-9]+ +//; s/ += .*//; s/^(clone\([^,]*),.*/\1)/;
        s/^(keyctl\([^,]*, [^,]*, [^,]*),.*/\1)/; s/^perf_event_open\(0x[0-9a-f]+,/perf_event_open(P,/;
        s/^add_key\([^,]*, [^,]*, [^,]*,/add_key(P, P, P,/' "$2"
    }
    probecalls $c/syscall-probe-c probe-c.calls
    probecalls $zig/syscall-probe probe-zig.calls
    diff probe-c.calls probe-zig.calls
    grep -q '^setns(0xffffffff, 0)$' probe-zig.calls
    grep -q '^clone(0x1200011)$' probe-zig.calls

    # ---- ioctl-probe: FIOCLEX (0x5451) takes any descriptor, TIOCSTI
    # (0x5412) and TCGETS (0x5401) a terminal's, so a spelling read wrong
    # answers differently ----
    for req in 0x5451 0X5451 21585 052121 0b101010001010001 " 0x5451" "+21585" "-0x5451" \
      0x100005451 0x5451z 0x 0xg 0b 0b2 "" abc 0x10000000000000000 18446744073709551615 \
      0x5412 0x100005412 0x10000541c 0x100005401; do
      pair "ioctl-probe '$req'" ioctl-probe "$req"
      want=$((want + 1))
    done
    stdin=closed pair "ioctl-probe 0x5451 <&-" ioctl-probe 0x5451
    # NS_GET_NSTYPE returns CLONE_NEWNET, not 0: the C prints errno's name,
    # "0", not ok.
    stdin=/proc/self/ns/net pair "ioctl-probe 0xb703 <ns/net" ioctl-probe 0xb703
    pair "ioctl-probe" ioctl-probe
    pair "ioctl-probe a b" ioctl-probe a b
    want=$((want + 4))
    grep -q "^ioctl-probe '0x5451': status 0, 1 lines (ok)" $out/runs
    [[ $($zig/ioctl-probe 0x5451 </dev/null) == ok ]]
    [[ $($zig/ioctl-probe 0x5412 </dev/null) == ENOTTY ]]
    [[ $($zig/ioctl-probe 0x5451 <&-) == EBADF ]]
    [[ $($zig/ioctl-probe 0xb703 </proc/self/ns/net) == 0 ]]

    # ---- swapper: its refusals, then each side swapping until killed ----
    mkdir ws noswap
    pair "swapper" swapper
    pair "swapper a b" swapper a b
    pair "swapper nowhere" swapper nowhere
    pair "swapper noswap" swapper noswap
    pair "swapper (empty path)" swapper ""
    want=$((want + 5))
    mkdir ws/sub
    ln -s /nonexistent ws/sublink
    for bin in "$c/swapper-c" "$zig/swapper"; do
      "$bin" ws &
      pid=$!
      # Swapping, and still swapping: the directory under the symlink's
      # name and back, three times. One that stops fails here in 60 s
      # rather than hanging the build.
      end=$((SECONDS + 60))
      for _ in 1 2 3; do
        until [[ -d ws/sublink && ! -L ws/sublink ]] || ((SECONDS > end)); do :; done
        until [[ -L ws/sublink ]] || ((SECONDS > end)); do :; done
      done
      if ((SECONDS > end)); then
        echo "fixtures-transition: $bin did not keep swapping" >&2
        kill -KILL $pid
        exit 1
      fi
      kill -TERM $pid
      rc=0
      wait $pid || rc=$?
      echo "swapper $bin: swapped, rc=$rc" >>$out/runs
      [[ $rc == 143 ]]
    done

    echo "fixtures-transition: $n comparisons" | tee $out/count >&2
    if ((n != want)); then
      echo "fixtures-transition: $n comparisons, not $want" >&2
      exit 1
    fi
    if ((failed)); then
      exit 1
    fi
  ''
