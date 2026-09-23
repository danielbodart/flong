# P5, the hybrid link (ZIG.md, "Phase 0: proofs" and "The mount-helper
# shim"): a Zig static library with the shim's settings (build.zig), linked
# by $CC with the launcher's cflags into a C program (c/main.c) that forks as
# fl_fork does and calls the library's one symbol in the child. One
# derivation answers every question and fails if an answer is no:
#
#   link     does the archive, with no compiler-rt, resolve against glibc and
#            libgcc under the launcher's -Werror and hardening?
#   run      does the child adopt its three descriptors, read, fstat, sort,
#            allocate with page_allocator, use a 256 KiB frame and print one
#            line in one write, exiting 0; does a planted panic exit 125 with
#            its one line; is the parent's heap intact after each?
#   clash    nm -g --defined-only of the archive lists proof_main alone;
#            the program defines none of memcpy, memset, memmove, memcmp,
#            bcmp, __stack_chk_fail, __stack_chk_guard; nm -D --undefined-only
#            lists memcpy, memset and __stack_chk_fail, so glibc supplies them.
#
# The fallback (compiler-rt bundled, `ld -r --whole-archive` into one object,
# `objcopy --keep-global-symbol=proof_main`) is not needed: the link resolves.
{ pkgs, lib, zigSet, ... }:
let
  hybrid = zigSet {
    pname = "p5-hybrid";
    root = ./.;
    files = [ ./src ./c ];
    nativeBuildInputs = [ pkgs.strace ];
    extra = ''
      # The archive is never installed (ZIG.md, "The mount-helper shim").
      mountlib=$TMPDIR/p5lib
      mv $out/lib $mountlib

      # launcher/default.nix:31-47's cflags, as they are; the -DFLONG_*
      # paths are unused here. The cc-wrapper adds the same hardening
      # (stack protector, fortify, pie) as the launcher's runCommandCC.
      cflags=(
        -std=gnu11 -O2 -D_GNU_SOURCE -Wall -Wextra -Werror
        -DFLONG_BWRAP='"${pkgs.bubblewrap}/bin/bwrap"'
        -DFLONG_PASTA='"${pkgs.passt}/bin/pasta"'
        -DFLONG_TINI='"${pkgs.tini}/bin/tini"'
        -DFLONG_NEWUIDMAP='"/run/wrappers/bin/newuidmap"'
        -DFLONG_NEWGIDMAP='"/run/wrappers/bin/newgidmap"'
        -DFLONG_INIT="\"$out/bin/flong-init\""
      )
      mkdir -p $out/bin
      $CC "''${cflags[@]}" -o $out/bin/p5-hybrid c/main.c $mountlib/libp5.a

      fail() { echo "p5: $*" >&2; exit 1; }
      echo "p5: libp5.a $(stat -c %s $mountlib/libp5.a) bytes; p5-hybrid, before fixup, $(stat -c %s $out/bin/p5-hybrid) bytes, $(od -An -tx2 -j16 -N2 $out/bin/p5-hybrid | tr -d ' ') e_type (3: PIE)"

      [ "$(od -An -tx2 -j16 -N2 $out/bin/p5-hybrid | tr -d ' ')" = 0003 ] || fail "the program is not a PIE"

      # The clash check.
      echo "p5: the archive's undefined symbols, for glibc and libgcc:"
      nm --undefined-only $mountlib/libp5.a | awk 'NF == 2 { print "  " $2 }' | sort -u
      globals=$(nm -g --defined-only $mountlib/libp5.a | awk 'NF == 3 { print $2, $3 }')
      echo "p5: the archive's global definitions: $globals"
      [ "$globals" = "T proof_main" ] || fail "the archive defines more than proof_main"
      clash='(memcpy|memset|memmove|memcmp|bcmp|__stack_chk_fail|__stack_chk_guard)(@.*)?'
      # Read once, and proof_main must be in it: a stripped program lists no
      # symbols and would pass the grep below without checking anything.
      nm --defined-only $out/bin/p5-hybrid | awk '{ print $NF }' > defined
      grep -qx proof_main defined || fail "the program's symbol table is empty or lacks proof_main"
      if grep -Ex "$clash" defined; then
        fail "the program defines a glibc name"
      fi
      nm -D --undefined-only $out/bin/p5-hybrid > dynamic
      for s in memcpy memset __stack_chk_fail; do
        grep -Eq " U $s(@|\$)" dynamic || { cat dynamic; fail "$s is not taken from glibc"; }
      done

      # The run.
      $out/bin/p5-hybrid ok > ok.out 2> ok.err || { cat ok.out ok.err; fail "ok mode failed"; }
      cat ok.out
      [ ! -s ok.err ] || { cat ok.err; fail "ok mode wrote to stderr"; }
      grep -q "^p5: child read 'zigflong', sorted 'fggilnoz', heap sum 8589869056, frame sum 520, .*, tracing 0\$" ok.out \
        || fail "the child's line is wrong"
      grep -qx 'p5: parent: child exited 0 as wanted, heap intact' ok.out || fail "the parent's line is wrong"
      P5_TRACE=1 $out/bin/p5-hybrid ok | grep -q 'tracing 1$' || fail "tracing did not cross"

      $out/bin/p5-hybrid panic > panic.out 2> panic.err || { cat panic.out panic.err; fail "panic mode failed"; }
      cat panic.err panic.out
      [ "$(wc -l < panic.err)" = 1 ] || fail "the panic wrote more than one line"
      grep -qx 'p5: internal error: index out of bounds: index 9, len 4' panic.err || fail "the panic's line is wrong"
      grep -qx 'p5: parent: child exited 125 as wanted, heap intact' panic.out || fail "the parent's line is wrong"

      # One write: the child's syscalls, from clone3's return to exit_group.
      strace -f -qq -o trace $out/bin/p5-hybrid ok > /dev/null
      child=$(awk '/write\(1, "p5: child/ { print $1; exit }' trace)
      [ -n "$child" ] || { cat trace; fail "no child write in the trace"; }
      echo "p5: the child's syscalls (pid $child):"
      awk -v p="$child" '$1 == p' trace | tee child.trace
      [ "$(grep -Ec '^[0-9]+ +write\(' child.trace)" = 1 ] || fail "the child wrote more than once"
    '';
  };
in
{
  build = hybrid;
  bins = hybrid;
  vmScript = ''
    with subtest("p5: the hybrid link forks and panics on the node"):
        out = machine.succeed(as_alice("p5-hybrid ok"))
        assert "p5: parent: child exited 0 as wanted, heap intact" in out, out
        out = machine.succeed(as_alice("p5-hybrid panic 2>&1"))
        assert "p5: internal error: index out of bounds: index 9, len 4" in out, out
        assert "p5: parent: child exited 125 as wanted, heap intact" in out, out
  '';
}
