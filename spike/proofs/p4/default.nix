# P4, the mount ABI (ZIG.md, "Phase 0: proofs"): the structs flong's Zig
# passes to the mount calls, src/abi.zig, written by hand, checked against
# Zig's bundled uapi headers on both arches, then used on a kernel.
#
#   abi    (build) does every field of open_how, mount_attr, mnt_id_req
#          (VER0), statmount, clone_args and std's Statx (stx_mnt_id at
#          0x90, __pad2[0]) sit at the header's offset with the header's
#          size, and does every constant and syscall number agree, for
#          x86_64 and aarch64, each from its own asm/ (__NR_openat 257 and
#          56) and from Zig's lib/libc/include (LINUX_VERSION_CODE 6.13.4)?
#          The checks are comptime, so compiling for an arch is checking
#          it; the two planted mismatches must fail, naming what differs.
#   mount  (bins, vmScript) do open_tree(OPEN_TREE_CLONE), move_mount,
#          fsopen/fsconfig/fsmount, mount_setattr, openat2's RESOLVE_ flags
#          and statmount by statx's unique id round-trip under
#          `unshare -Urm` as alice, each checked (src/mount.zig)?
#
# The fallback, a C program printing sizeof and offsetof, is not needed:
# translate-c reads the bundled headers for either target.
{ pkgs, lib, zigSet, ... }:
let
  abi = zigSet {
    pname = "p4-abi";
    root = ./.;
    files = [ ./src ];
    steps = "abi --summary all";
    extra = ''
      # The controls: a mismatch planted in the expectations fails both
      # arches' compiles, naming it. The logs name zig's store path, so
      # only the p4 lines are kept, as $out/plants.
      for plant in arch offset; do
        if zig build abi -Dplant=$plant $zigDefaultCpuFlag $zigDefaultOptimizeFlag >plant-$plant.log 2>&1; then
          echo "p4: abi passed with -Dplant=$plant"; exit 1
        fi
      done
      grep -q 'p4: x86_64: __NR_openat is 257, expected 56' plant-arch.log
      grep -q 'p4: aarch64: __NR_openat is 56, expected 257' plant-arch.log
      grep -q 'p4: x86_64: open_how.flags: offset 0, header 1' plant-offset.log
      grep -q 'p4: aarch64: open_how.flags: offset 0, header 1' plant-offset.log
      grep -ho 'error: p4: .*' plant-*.log | sort -u | tee $out/plants >&2
    '';
  };

  mount = zigSet {
    pname = "p4-mount";
    root = ./.;
    files = [ ./src ];
  };
in
{
  build = abi;
  bins = mount;

  # As alice, root only of her own user and mount namespace. After it, DIR/a
  # and DIR/b are plain empty directories again: the mounts lived and died
  # with that namespace.
  vmScript = ''
    with subtest("p4: the mount calls round-trip under unshare -Urm"):
        out = machine.succeed(as_alice(
            "d=$(mktemp -d) && unshare -Urm p4-mount $d && "
            "test -z \"$(ls -A $d/a)$(ls -A $d/b)\" && echo p4: host side empty"))
        print(out)
        assert "p4: all ok" in out and "p4: host side empty" in out, out
  '';
}
