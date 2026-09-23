# P6, aarch64 (ZIG.md, "Phase 0: proofs"): the spike, P4 and P5 built for
# aarch64-linux by Zig on x86_64, in the build sandbox, from those proofs'
# own sources. The VM tests stay x86_64 (ZIG.md, "Decided"); each derivation
# fails if its answer is no.
#
#   spike  does the spike's `install` build fd-probe for aarch64, static,
#          and does it run (under qemu-aarch64, "0 1 2 | a b")?
#   p4     do p4-mount and the abi step build for aarch64: abi-aarch64's
#          comptime asserts against Zig's aarch64 headers, and the arch
#          assert still firing on a planted x86_64 number? Under qemu-aarch64
#          in `unshare -Urm`, do fsopen, fsconfig, fsmount and move_mount
#          round-trip by their aarch64 numbers? That run is in the VM
#          (vmScript): CI's build sandbox refuses the uid_map write.
#   p5     does the shim-settings archive build for aarch64-linux-none, with
#          proof_main its only global definition and nothing undefined that
#          glibc does not define? The aarch64 C link is out of scope: the
#          flake has no cross C toolchain (ZIG.md, "The mount-helper shim").
#
# Each writes what it found to $out/facts. The fallback, -fno-emit-bin, is
# not needed: every binary is emitted.
#
# Nothing unstripped for aarch64 may stay in $out: it names Zig's lib/std,
# which trips disallowedReferences, and Nix's fixup cannot strip it, since
# the builder's binutils reads aarch64 ELF only as elf64-little ("Unable to
# recognise the architecture"; `zig objcopy --strip-all` is "unimplemented").
# So `.strip = true` in build.zig is the only way an aarch64 artifact ships.
{ pkgs, lib, zigSet, spikeRoot, ... }:
let
  qemu = "${pkgs.qemu-user}/bin/qemu-aarch64";

  # readelf's e_machine, and "static" when there is no PT_INTERP.
  checkElf = ''
    elf() {
      readelf -h "$1" | grep -q 'Machine: *AArch64' || { readelf -h "$1"; echo "p6: $1 is not aarch64"; exit 1; }
      if readelf -l "$1" | grep -q INTERP; then echo "p6: $1 is dynamic"; exit 1; fi
      echo "$(basename $1): aarch64, static, $(stat -c %s "$1") bytes" | tee -a $out/facts
    }
  '';

  spike = zigSet {
    pname = "p6-spike";
    root = spikeRoot;
    files = [ (spikeRoot + "/src") ];
    flags = "-Dtarget=aarch64-linux --prefix-exe-dir aarch64";
    extra = ''
      ${checkElf}
      elf $out/aarch64/fd-probe
      # The spike's install does not strip fd-probe (spike/fd-zig/build.zig,
      # `probe`), so it names Zig's store path and is not kept in $out.
      if grep -q ${pkgs.zig_0_15} $out/aarch64/fd-probe; then
        echo "fd-probe: unstripped, names zig's store path, not kept" | tee -a $out/facts
      fi
      mv $out/aarch64 $TMPDIR/spike-aarch64
      out1=$(${qemu} $TMPDIR/spike-aarch64/fd-probe a b </dev/null)
      echo "qemu-aarch64 fd-probe a b: $out1" | tee -a $out/facts
      [ "$out1" = "0 1 2 | a b" ]
    '';
  };

  p4 = zigSet {
    pname = "p6-p4";
    root = ../p4;
    files = [ ../p4/src ];
    steps = "install abi";
    flags = "-Dtarget=aarch64-linux --prefix-exe-dir aarch64";
    nativeBuildInputs = [ pkgs.util-linux ];
    extra = ''
      ${checkElf}
      elf $out/aarch64/p4-mount

      # abi compiles abi-aarch64 whatever -Dtarget says (p4/build.zig);
      # the summary shows it did (the install's run left it cached).
      zig build abi --summary all $zigDefaultCpuFlag $zigDefaultOptimizeFlag > abi.log 2>&1
      grep -Eo 'compile test abi-aarch64 [A-Za-z]+ aarch64-linux-musl (success|cached)' abi.log > abi.line \
        || { cat abi.log; echo "p6: abi did not compile abi-aarch64"; exit 1; }
      tee -a $out/facts < abi.line
      if zig build abi -Dplant=arch $zigDefaultCpuFlag $zigDefaultOptimizeFlag > plant.log 2>&1; then
        echo "p6: abi passed with -Dplant=arch"; exit 1
      fi
      grep -q 'p4: aarch64: __NR_openat is 56, expected 257' plant.log || { cat plant.log; exit 1; }
      echo "abi -Dplant=arch: p4: aarch64: __NR_openat is 56, expected 257" | tee -a $out/facts

    '';
  };

  p5 = zigSet {
    pname = "p6-p5";
    root = ../p5;
    files = [ ../p5/src ];
    flags = "-Dtarget=aarch64-linux-none";
    extra = ''
      # The archive is never installed (ZIG.md, "The mount-helper shim").
      a=$TMPDIR/libp5.a
      mv $out/lib/libp5.a $a
      rmdir $out/lib
      readelf -h $a | grep -q 'Machine: *AArch64' || { readelf -h $a; echo "p6: libp5.a is not aarch64"; exit 1; }
      echo "libp5.a: aarch64, $(stat -c %s $a) bytes" | tee -a $out/facts

      # The clash check's archive half, as P5 runs it for x86_64.
      globals=$(nm -g --defined-only $a | awk 'NF == 3 { print $2, $3 }')
      echo "libp5.a global definitions: $globals" | tee -a $out/facts
      [ "$globals" = "T proof_main" ] || { echo "p6: the archive defines more than proof_main"; exit 1; }

      # What the archive leaves to the C link. x86_64's is memcpy and memset;
      # aarch64 adds getauxval, since its page size is not comptime-known
      # and std.heap.defaultQueryPageSize asks AT_PAGESZ (heap.zig:82), and
      # a library without main leaves getauxval undefined (os/linux.zig:
      # 515-525). glibc defines all three.
      undef=$(nm --undefined-only $a | awk 'NF == 2 { print $2 }' | sort -u | tr '\n' ' ')
      echo "libp5.a undefined: $undef" | tee -a $out/facts
      for s in $undef; do
        case $s in
          memcpy | memset | memmove | memcmp | bcmp | getauxval) ;;
          *) echo "p6: libp5.a needs $s, which the aarch64 C link may not resolve"; exit 1 ;;
        esac
      done
    '';
  };
in
{
  build = pkgs.linkFarm "p6" {
    inherit spike p4 p5;
  };

  bins = pkgs.runCommand "p6-bins" { } ''
    mkdir -p $out/bin
    ln -s ${p4}/aarch64/p4-mount $out/bin/p6-p4-mount-aarch64
  '';

  # qemu-user 11.1 has no statmount (457): the run gets through the new
  # mount API and stops there with NOSYS, from qemu, not the kernel
  # (p4-mount built for x86_64 passes the same call natively).
  vmScript = ''
    with subtest("p6: the aarch64 mount calls under qemu-aarch64 and unshare -Urm"):
        out = machine.succeed(as_alice(
            "d=$(mktemp -d); "
            "unshare -Urm ${qemu} $(command -v p6-p4-mount-aarch64) $d > /tmp/p6.log 2>&1; "
            "cat /tmp/p6.log"))
        print(out)
        lines = out.splitlines()
        assert "p4: all ok" in lines or "p4: FAIL: statmount a: NOSYS" in lines, "p6: p4-mount failed before statmount"
        assert any(l.startswith("p4: ok: fsopen tmpfs, fsconfig mode size create, fsmount") for l in lines)
        assert any(l.startswith("p4: ok: move_mount: DIR/a is mount") for l in lines)
  '';
}
