# Phase 0 proofs

Each proof answers one question of ZIG.md's "Phase 0: proofs" by a build that
fails when the answer is no. A proof is a directory `spike/proofs/<pN>/`
holding a `default.nix`; `tests/integration.nix` finds it with
`builtins.readDir`, so adding one needs no edit there, in `tests/native.nix`
or in `flake.nix`. As a flake only sees tracked files, `git add` the
directory.

## The contract

`default.nix` is a function of one attrset, called as

```nix
import ./spike/proofs/<pN> { inherit pkgs lib zigSet zigDeps spikeRoot; }
```

so it should take `{ pkgs, lib, zigSet, ... }` (the `...` lets arguments be
added later). It returns an attrset with any of:

| attribute | what | where it goes |
|---|---|---|
| `build` | a derivation whose own build runs the proof's build-sandbox assertions and fails if one fails | `integration.<pN>`, so `checks.integration` |
| `bins` | a derivation with `bin/` | `integration.<pN>-bins`, joined into `integration.vm`, which is on the `checks.native` node's PATH |
| `vmScript` | a Python testScript fragment | appended to `checks.native`'s testScript after the common setup, in name order (`p1` < `p10` < `p2`) |

The arguments:

- `zigSet { pname, root, files ? [], steps ? "install", set ? null, flags ?
  "", optimizeFlag ? "$zigDefaultOptimizeFlag", deps ? null, buildInputs ?
  [], nativeBuildInputs ? [], extra ? "", version ? "0", passthru ? {} }`,
  `native.nix`'s builder (the one flong's own sets use, whose `root`
  defaults to the repo's): a `stdenv.mkDerivation` with the
  `zig_0_15` hook, `src` the fileset of `root/build.zig`,
  `root/build.zig.zon` and `files`, `dontUseZigBuild`, `doCheck = false`,
  `disallowedReferences = [ zig_0_15 ]`. Its installPhase is `mkdir -p $out`,
  then `zig build <steps> -j$NIX_BUILD_CORES $zigDefaultCpuFlag
  $zigDefaultOptimizeFlag [-Dset=<set>] --prefix $out <flags>` (so ReleaseSafe,
  `-Dcpu=baseline`), then `extra`, run in the unpacked source with `zig` on
  PATH. `extra` may write `$out` and fails the build on a nonzero status
  (`set -e`), but `set -e` ignores every command of an `a && b` list but
  the last, so put one assertion on each line. `deps` is linked into `$ZIG_GLOBAL_CACHE_DIR/p`.
- `zigDeps { pname, root, hash }`: `zig_0_15.fetchDeps` with `fetchAll = true`
  over `root/build.zig*`: every dependency, lazy ones included. Hash
  bootstrap: `lib.fakeHash`, build, copy `got:`.
- `spikeRoot`: `spike/fd-zig`, for a proof that builds against the spike's
  `src/fd.zig`.
- `pkgs`, `lib`: the flake's locked nixpkgs.

A proof with its own Zig package puts `build.zig` and `build.zig.zon` in its
directory and passes `root = ./.`. A build-sandbox proof has no user
namespaces beyond what Nix's sandbox allows and no KVM; anything needing a
delegated cgroup, `newuidmap` or a real pid 1 goes in `vmScript`.

## The VM

`checks.native`'s node (`tests/native.nix`): alice, uid 1000, lingering, with
subordinate ids 100000-165535 for both uid and gid; the
`/run/wrappers/bin/new{u,g}idmap` wrappers (file capabilities, not setuid);
no sudo; `strace`, `util-linux`, `bubblewrap` and every proof's `bins` on the
system PATH. A `vmScript` runs after the common setup, which has
waited for `user@1000.service` and checked that a `Delegate=yes` unit's cgroup
takes a child and that `unshare --user --map-auto` maps the range. In scope:

- `machine`, `shlex`;
- `as_alice(script, props="")` returns a shell command running `script` in
  bash as alice, through her user manager (`systemd-run -M alice@ --user
  --wait --pipe --quiet --collect -p Delegate=yes <props>`), with PATH
  `/run/wrappers/bin:/run/current-system/sw/bin` and `/tmp` as the working
  directory; pass it to `machine.succeed` or `machine.fail`. The unit's own
  cgroup is `/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)`.

A fragment opens its own `with subtest("<pN>: ..."):` and is indented from
column 0, like the rest of the testScript.

## The proofs

- `p1`: the build. The spike as a zigSet: lazy dependencies offline under
  `-Ddev=true` (`dev`), `install lint compile-fail cross` with none
  (`offline`), a `b.path` outside the fileset (`outside`).
- `p2`: flong-init's start code as pid 1. `p2-init` (flong-init's no-libc,
  `stack_size = 0` settings), the `p2-init-default` control, the C
  flong-init, and `p2-pid1` (bwrap `--as-pid-1` with the strict/log stack):
  the first syscall after `execve`, audit records, a planted panic, `ulimit -s`.
- `p3`: processes. `clone3` into a delegated `O_PATH` leaf, the `noreturn`
  fork (`compile-fail` and at run time), a fork after `setns(CLONE_NEWUSER)`.
- `p4`: the mount ABI. `abi-*`: the structs, constants and syscall numbers
  against translate-c of Zig's bundled headers, x86_64 and aarch64, with
  the arch and offset plants; `p4-mount`: the mount calls under `unshare -Urm`.
- `p5`: the hybrid link. A Zig archive with the shim's settings linked by
  `$CC` with the launcher's flags; its fork child, a planted panic, the
  clash check.
- `p6`: aarch64 builds of the spike, p4 and p5, run under qemu-aarch64
  where they can be (`p4-mount` stops at `statmount`, which qemu lacks).
