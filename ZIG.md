# Plan: flong's native code in Zig

flong's native code moves from C to Zig, one program at a time, on trunk. That
covers four programs (`flong-seccomp`, `flong-init`, `flong-sweeper` and
`flong-launch`), the C test fixtures, and the seccomp tooling that is bash and
awk today. Goals, in order:

1. **Descriptor and process bugs become hard to write.** Every descriptor is a
   typed handle in one table. A forked child cannot return into its parent's
   cleanup. Raw syscalls live in one layer, and a linter enforces it.
2. **Nothing observable changes.** Every string a test greps, every exit code,
   the bwrap and pasta argv (up to pids and descriptor numbers), record bytes
   and BPF bytes stay identical. Each known quirk has a keep or fix line below.
3. **Ship early.** Zig reaches trunk in phase 1. Every phase replaces one
   program and deletes its C. The shared layers grow only as far as the
   program being ported needs them.
4. **Build cost is mitigated, not avoided.** It is reported at every phase and
   never gated on.

This file is deleted when the port lands (phase 8), and what it establishes
moves into DESIGN.md. *Measured* means a number or a run exists and its source
is named; *inferred* means nothing has checked it yet, and the phase that
checks it is named.

## Decided

By the user (final; not revisited):

- **Zig, locked.** Build time is a cost to mitigate and report, never a reason
  to reconsider.
- **Zig 0.15.2, from nixpkgs `zig_0_15`**
  (`pkgs/top-level/all-packages.nix:6745` in the locked nixpkgs `eaad0894`,
  whose unqualified `zig` is 0.16, `:6756`). minish (property tests) and
  zwanzig (static analysis) are lazy dependencies pinned to tags (minish
  v0.1.0, zwanzig v0.15.1, `build.zig.zon:8-16`).
- **Scope.** Into Zig: the four programs; the C fixtures
  (`tests/parity/bpfdump.c`, `tests/parity/probe.c`, and the inline `swapper`
  and `ioctl-probe`, `tests/probes.nix` since phase 4); the seccomp tooling
  (`seccomp/expand.awk`, and `flong-seccomp-render` and
  `flong-seccomp-project` at `seccomp/policy.nix:81-209`). Staying bash:
  `rootless-wrapper.bash` and module.nix's scripts (`flong-cache`, prepare,
  the hooks).
- **flong-seccomp keeps libseccomp.** Filters stay byte-identical, proven by
  an explicit C-against-Zig transition check.
- **Binary by binary on trunk.** The C of a program is deleted in the phase
  that replaces it.
- **No libc** for `flong-launch`, `flong-sweeper` and `flong-init`: static,
  with an errno text table for `strerror` and an `/etc/passwd` parse for
  `getpwuid`. `flong-seccomp` links libc, through libseccomp.
- **Asserted behaviour is byte-identical.** Test-asserted strings and exit
  codes do not change. Each quirk gets keep or fix; fixes wait until after the
  port unless the port requires them.
- **This plan is `ZIG.md`** at the repo root, deleted when the port lands; its
  conclusions go into DESIGN.md.
- **aarch64** gets a cross-build check; the VM tests stay x86_64.
- **Working style.** Commit per phase, push when green, keep going unless a
  design decision is needed. Timing is reported, never gated.
- **The launcher is hybrid for the mount helper only.** A Zig mount helper,
  built as a static library and called from the C launcher's fork child,
  reaches trunk early and meets the full VM suite (phase 4). ns and tty are
  ported on the launcher branch, each milestone gated by the `checks.native`
  VM; the rest of the launcher lands when green (phase 7).

By this plan (each detailed below):

- **Proofs first** (phase 0), each question with a named fallback. **Every
  transition phase is two commits:** (a) Zig beside the C with a transition
  check; (b) the C and the check deleted. Each is a release.
- **One Zig package at the repo root; one derivation per install set**
  (`seccomp`, `launcher`, `fixtures`), each over only the sources it imports,
  so a launcher edit moves neither the seccomp store path, nor the project
  cache key, nor any filter derivation. The cost, a build runner and
  compiler-rt per derivation (each Nix build starts with an empty
  `ZIG_GLOBAL_CACHE_DIR`, `setup-hook.sh:10`), is reported in phases 3 and 6.
- **Build mode:** ReleaseSafe, stripped, `single_threaded`, `stack_size = 0`,
  `disallowedReferences = [ zig_0_15 ]`. **No `std.posix`**, anywhere. **Two
  errors:** `error.Reported` (printed) and `error.Aborted` (a signal). **Lazy
  dependencies only under `-Ddev=true`.** **The mount library links without
  compiler-rt**, exporting one symbol. **The seccomp tooling becomes
  subcommands of `flong-seccomp`.**
- **The launcher branch gets CI through a draft pull request** (`ci.yml:6`;
  release runs only on trunk pushes, `ci.yml:42`). **DESIGN.md** is corrected
  by each phase that makes a line false; phase 8 rewrites its native chapter.

## Measured

| what | value | source |
|---|---|---|
| Zig start code, `--stack 0 -fsingle-threaded` | no syscall before `main`; `--stack 65536` adds one `prlimit64` GET; the default stack GET then SET to 16 MiB (`start.zig:545-578`); without `-fsingle-threaded`, `arch_prctl(ARCH_SET_FS)` (`:504-519`) | this host, 2026-09-23: Zig 0.15.2, x86_64, ReleaseSafe, stripped, `strace` |
| a normal return from a single-threaded `main` | `exit`, not `exit_group` (`posix.zig:777-789`); the binary 21,920 bytes, static | same |
| a Zig static library (`-OReleaseSafe -fPIC -fsingle-threaded -target x86_64-linux-none`) in a glibc C program, nixpkgs `gcc-wrapper-15.3.0` | without compiler-rt, 5 undefined `__zig_probe_stack` (stack probing). With `-fcompiler-rt` it links, a fork child running Zig (page_allocator, sort, fmt, a 256 KiB frame) works, a panic exits 125, the parent's heap is intact; but compiler_rt.o defines `memcpy`, `memset`, `memmove`, `memcmp`, `bcmp`, `__stack_chk_fail` (W) and `__stack_chk_guard` (V), which then take the C's calls from glibc | this host, 2026-09-23, `nm` |
| an unguarded `lazyDependency`, offline, empty cache | `zig build install` fails fetching minish and zwanzig (`build_runner.zig:370`) | this host, spike |
| Zig's bundled headers | `any-linux-any` is kernel 6.13.4 (`mnt_id_req`, `PIDFD_GET_MNT_NAMESPACE`); per-arch `aarch64-linux-*` beside x86_64's | this host |
| `nix flake check` in CI | 5 min 55 s: about 3 min evaluation and fetching; basic 118.6 s, rootless 133.9 s, parity 40.75 s, in parallel | run 35821381759, bafc20a |
| `zig_0_15` | 231.6 MiB download, 926 MiB unpacked, substituted | port inventory |
| the spike's handle table | catches double close, use after close, a closed alias, stale copies in structs and fork children, kind confusion; a child ignoring the keep list, `retainOnly` without its final `close_range`, `close` without the generation bump each caught, minish shrinking each to 2-3 operations | spike |
| zwanzig v0.15.1 | the CLI reports no leak, even on its own fixture; struct-stored resources count as escaped; with no config it catches B1-B3, B6, B8 | spike |
| spike `fd-probe`, ReleaseSafe | unstripped 2.3 MB, 3 references to Zig's `lib/std`; stripped 51 KB, static, no libc; PT_GNU_STACK 16 MiB by default | spike |
| libseccomp | 2.6.1; `seccomp_export_bpf` is one `write` (`api.c:760`) | port inventory (the locked tarball is inferred) |
| `zig_0_15.fetchDeps { fetchAll = true; }` over the spike (P1) | one FOD, 2.2 MiB: minish 0.1.0, zwanzig 0.15.1 and zwanzig's own chilli 0.2.2; a symlink to `$ZIG_GLOBAL_CACHE_DIR/p` is enough; `test analyze -Ddev=true` then runs in the sandbox, zwanzig built from source; fallback not needed | this host, 2026-09-23, phase 0, `checks.integration` (p1-dev) |
| the spike gated (P1) | `install lint compile-fail cross` pass with an empty cache, no deps and no `-Ddev`; `test` and `analyze` fail `needs -Ddev=true`; with `test` ungated, `install` fails `unable to connect to server` | same (p1-offline; the ungated plant in a scratch copy) |
| a `b.path` outside the fileset (P1) | lazy: `install` passes from `build.zig`, `build.zig.zon` and `src/` alone; `lint` then fails naming `fdlint.zig` | same (p1-outside) |
| Nix's fixup and Zig outputs (P1, P6) | strips `bin/` only, with `strip -S` (`fd-probe` 294,208 bytes), and no aarch64 ELF (binutils 2.46: "Unable to recognise the architecture"; `zig objcopy --strip-all`: "unimplemented"); any unstripped artifact names zig and trips `disallowedReferences`; with `.strip = true` the aarch64 `fd-probe` is 43,592 bytes | same (p1-offline, p6-spike) |
| a no-libc root as pid 1 (P2): static, ReleaseSafe, stripped, `single_threaded`, `stack_size = 0` (17,768 bytes, PT_GNU_STACK MemSiz 0), under bwrap 0.12 `--as-pid-1` with the strict/log, audit, tty and nsmask filters | first syscall after `execve` is main's `getpid() = 1`; the control (Zig's default stack and threading) starts with `arch_prctl(ARCH_SET_FS)`, the C flong-init with `brk(NULL)`; Zig 0.15.2 accepts `stack_size = 0`, fallback not needed | this host, 2026-09-23, phase 0, `checks.native` (p2), `strace -f` |
| audit records of the start code (P2) | none from p2-init, the control or the C flong-init (the strict tier allows `arch_prctl` and `prlimit64`, so the audit compare cannot tell them apart; the strace does); a positive control's `io_uring_setup` is logged, syscall=425 | same |
| the pid-1 panic and RLIMIT_STACK (P2) | `flong-init: internal error: planted`, one line, 125 through bwrap; `ulimit -s 4096` reaches the exec'd `sh`; with only the soft limit at 4096 the control's child sees 16384, p2-init's 4096. bwrap ran in an `unshare --map-auto --map-root-user` namespace over `--ro-bind / /`, not the launcher's U1 and mounts | same, and `checks.integration` (p2) |
| `std.os.linux` in 0.15.2 (P3) | no `clone3` or `setns` wrapper (raw `syscall2`, numbers 435 and 308 on x86_64); `CLONE.INTO_CGROUP` and `CLONE.PIDFD` correct | `std/os/linux.zig:5315-5348`, grep |
| `clone3(CLONE_INTO_CGROUP\|CLONE_PIDFD)`, 88-byte args, no stack (P3) | into an `O_PATH\|O_DIRECTORY\|O_NOFOLLOW` leaf of a `Delegate=yes` unit: the child reads the leaf from `/proc/self/cgroup`, the parent stays, `waitid(P_PIDFD)` reaps; into `system.slice`: EACCES. After `setns(CLONE_NEWUSER)`: uid 0, map `0 1000 1 / 1 100000 65536`, the namespace's capabilities (`sethostname`), and `INTO_CGROUP` still lands | this host, 2026-09-23, phase 0, `checks.native` (p3) |
| the `noreturn` fork (P3) | a `fn (u8) void` body: `expected type 'fn (u8) noreturn', found 'fn (u8) void'` (the `compile-fail` step; a `noreturn` body makes the step fail); a working body runs once and the parent's `defer` once, in the parent; a panicking body: 125, one line | same, and `checks.integration` (p3) |
| translate-c of Zig's bundled headers (P4) | with `-target <arch>-linux-musl` it reads only Zig's `lib/libc/include`, never `pkgs.linuxHeaders` or `NIX_CFLAGS_COMPILE`; `LINUX_VERSION_CODE` 396548 (6.13.4), no `STATMOUNT_MNT_UIDMAP` | this host, 2026-09-23, phase 0, `checks.integration` (p4-abi) |
| hand-written `extern struct`s against it (P4) | `open_how` 24, `mount_attr` 32, `mnt_id_req` VER0 24, `statmount`'s fixed part 512, `clone_args` 88, `stx_mnt_id` at 0x90 (`linux.Statx.__pad2[0]`): every field's offset and size, 28 constants and 12 syscall numbers equal on x86_64 and aarch64; the arch plant (`__NR_openat` 257 or 56) and an offset plant each fail the compile, naming the field; fallback not needed | same |
| the mount calls under `unshare -Urm` as alice, kernel 6.18.51 (P4) | `fsopen`/`fsconfig`/`fsmount`, `move_mount`; the statx unique id stable across the move; `statmount` by it returns the id, `TMPFS_MAGIC`, `tmpfs`, the point, the parent's id, `mnt_id_old`; `mount_setattr` RDONLY then EROFS; `open_tree(OPEN_TREE_CLONE)` inherits RDONLY; `openat2` BENEATH refusals EXDEV, NO_SYMLINKS and NO_MAGICLINKS ELOOP, IN_ROOT, a 16-byte `how` EINVAL; nothing left on the host | this host, 2026-09-23, phase 0, `checks.native` (p4) |
| the shim's library settings, linked by `$CC` with `launcher/default.nix:31-47`'s cflags and the wrapper's hardening (P5) | links: the archive's undefined symbols are `memcpy` and `memset` only, no `__zig_probe_stack`; a PIE with BIND_NOW and fortify; the clash check holds (`T proof_main` alone; the program defines no glibc name; it imports `memcpy`, `memset`, `__stack_chk_fail`). `stack_check = true` gives 3 undefined `__zig_probe_stack`; `bundle_compiler_rt = true` fails the clash check. libp5.a 70,708 bytes; fallback not needed | this host, 2026-09-23, phase 0, `checks.integration` (p5), `nm`, `readelf`; plants in a scratch copy |
| the hybrid fork child (P5) | after `clone3(CLONE_PIDFD)` and the C's `close_range(3, keep)`: reads the pipe to EOF, fstats the kept descriptors, finds the rest EBADF, sorts, 1 MiB through `page_allocator`, a 256 KiB frame, exactly one `write`, `exit_group(0)`, no start code; a planted panic: one line, 125; the parent's heap and `malloc` intact (CoW: this shows the allocator, not isolation) | same, `strace -f`, and `checks.native` (p5) |
| aarch64 (P6) | the spike's `install` (unstripped 2,286,120 bytes, runs under qemu-aarch64 11.1.0), P4's `p4-mount` (48,112 bytes, stripped) and ABI asserts, P5's archive (59,500 bytes, `T proof_main` alone) all build; the archive also needs `getauxval` (the page size is not comptime-known, `std/heap.zig:82`; a library leaves it extern, `std/os/linux.zig:515-525`), which glibc defines (the aarch64 C link is inferred). Under qemu `p4-mount` stops at `statmount`, NOSYS from qemu (no 457), so `statmount`, `mount_setattr`, `open_tree` and `openat2` have run on x86_64 only. `-fno-emit-bin` not needed | this host, 2026-09-23, phase 0, `checks.integration` (p6) |
| derivation times, `nix build --rebuild` (32 cores, empty `ZIG_GLOBAL_CACHE_DIR`, each bit-identical) | a small no-libc set 6.9-9.7 s (p2-init 9.0, p3-proc 8.8-9.7, p4-mount 9.3, p5 6.9-8.8); the spike's `install` 19.6-20.4 s; p4-abi 22.8-23.1 s (the x86_64 translate-c compile 16 s); p1-dev 81.1 s (zwanzig from source); p6: 19.4, 21.6, 6.6 s | this host, 2026-09-23, phase 0 |
| `checks.native` (one node, KVM) | 20.9-32 s wall; boot 8.2 s, multi-user.target 15.7 s; test script 16.5-19.6 s, each proof's subtest 0.2-1.7 s. Local `nix flake check`, 9 checks, partly cached: 197.9 s | this host, 2026-09-23, phase 0 |
| `nix flake check` in CI, before phase 1 | 8 min 5 s (the step; the run 8 min 31 s) | run 35872849343, a2016b9 |
| the Zig `flong-seccomp` against the C (phase 1 a) | `checks.seccomp-transition`: 123 comparisons (17 rendered policies, audit, tty, nsmask, 106 golden cases), stdout by `cmp`, stderr and status all equal; tier filters 1550 (parity and strict, each of 1, 13, log, debug, nestedSandbox), 1324 and 1242 (38), 1321 and 1257 (allow/deny), audit 26, tty 19, nsmask 49; parity's live filters 1550, 26, 19, 49 for both tiers. A planted `ctl_optimize` 1: 32 stdout differences, golden red. Fuzzing both binaries, 87,000 policies (about 1,500 accepted) and 39 edge cases: 0 differences | this host, 2026-09-23, phase 1 (a) and its reviews |
| the Zig `flong-seccomp` (phase 1 a) | 41,096 bytes stripped (the C 17,256), PT_GNU_STACK size 0, needs `libseccomp.so.2` and `libc.so.6`; no zig in the closure; closure 37,953,832 bytes (the C 48,454,728: it also held gcc-lib and the source) | same, `readelf -lW`, `nix path-info -rS` |
| phase 1's derivations, `nix build --rebuild` | `seccomp` 8-10.9 s, bit-identical; `native-test` Debug 14.7 s, release 23.9 s; `native-analyze` 81-88 s; `native-lint` 8 s; `cross-aarch64` 7 s. Local `nix flake check`, partly cached: 6 min 8 s; test scripts parity 22.1 s, basic 88.7 s, rootless 113.2 s, native 19.0 s | same |
| `nix flake check` in CI, before phase 2 | 9 min 37 s (the step; the run 10 min 4 s) | run 35888978900, 0dc291c |
| the Zig tooling against the awk and bash (phase 2 a) | `checks.seccomp-tools-transition`, over the live dump: 109 comparisons (11 names files: parity and strict, each plain, debug, nestedSandbox, both, allow/deny, and `@known`; 8 rendered policies; the 77 tooling golden cases, 12 projects compiling, 18 refused; a bad DENY 4 ways, a warm cache, an unsorted NAMES, an unwritable DIR, umask 0277, a directory as each operand), all equal, each compiled project's key equal to `printf '%s\n%s' $seccomp "$policy" \| sha256sum`; each comparison records which side ran and must be old against Zig. Fuzzing both sides (about 4,000 expand, 5,000 render, 2,700 project runs; 13 DIR states, 11 spellings, 10 umasks): after four fixes (the reopen under a umask without owner write, mktemp's line, a directory operand skipped, an empty DUMP) no difference but quirk 46. Plants in a scratch copy, each caught: by golden and the check, the stats line printed, the temp file left, a newline added to the key, the sort reversed, the directories 0755, a changed key byte, a rule dropped; by the check, comm's warnings dropped, each of the four fixes reverted, the old tools on both sides; by golden, a changed usage line, a missing set; by native-test, `close` without the generation bump, opens without `O_CLOEXEC`; by rootless, the project's stderr dropped or a stray line on it | this host, 2026-09-23, phase 2 (a) and its reviews |
| the project compile, cold and warm (phase 2 a; reported, not gated) | `flong-seccomp project` on the host, a groups policy, strict names, median of 21 (p10-p90): cold 31.6 ms (28.1-33.1), warm 3.4 ms (2.8-3.5); an earlier run 37.7 ms (34.4-47.3) and 6.4 ms; the bash it replaces, cold 85.8 ms (80.9-89.0), warm 42.4 ms (38.1-45.8). A launch in `checks.rootless`, one sample each, three runs: cold 0.221, 0.181, 0.205 s, warm 0.153, 0.179, 0.182 s; on the parent 0dc291c, cold 0.277 s, warm 1.145 s | same, `rootless.nix`'s stderr subtest timed by the driver |
| the gate subtest's one red run (phase 2 a; `rootless.nix:732-740`) | the output ended `…not starting the payloadrc=125`: the C flong-init's refusal is three `stderr` writes (`flong-init.c:60-64`) and teardown kills the sandbox right after closing the gate (`flong-launch.c:792-797`), so a kill between them drops the newline; not the Zig's (the `hooked` box has no project policy). The assertion now takes `rc=125` at the end of the output, on its own line or not; phase 3's one `writev` removes the race | this host, 2026-09-23, the failing log and a green re-run of the same derivation |
| phase 2's derivations, `nix build --rebuild` | `seccomp` 10.9-11.6 s, bit-identical; flong-seccomp 139,360 bytes stripped (phase 1: 41,096: the subcommands, sha256, hash maps, sort), PT_GNU_STACK size 0, closure 38,052,096 bytes, no zig; `native-test` Debug 15.7 s, release 26.9 s; `native-analyze` 76.8 s; `native-lint` 4.5 s; `cross-aarch64` 13.1 s and P5's aarch64 archive 5.8 s; golden 5.7 s; the transition check 5.8 s. Local `nix flake check`, partly cached: 4 min 43 s and 5 min 11 s; the final one 35 min 23 s, beside a `--no-build --all-systems` evaluation that itself took 35 min 13 s (cause not investigated); test scripts native 18.3 s, parity 21.4 s, basic 83.6 s, rootless 113.0 s. The launcher's store path is unchanged (`rr1aja5r…-flong-launcher`) | same |
| `nix flake check` in CI, before phase 3 | 8 min 10 s (the step; the run 8 min 33 s) | run 35907715248, 3cb27fb |
| the Zig flong-init against the C (phase 3 a) | `checks.native`'s transition subtest, both as pid 1 through bwrap under strict/log, audit, tty and nsmask, `strace -f -ff`: the window from the first `setgroups` (or the message) to `execve` or `exit_group` equal call for call on five paths, tini's exec 97 calls, gate EOF 94, chdir 95, TIOCSCTTY refused 89, an argv refusal 2; the outputs byte-equal; the Zig makes no call before the window; no audit record from any of the 10 runs, an `io_uring_setup` control logged (syscall=425). The compare needs two normalisations: the C's malloc (`brk`, `mmap`) left out, the Zig allocating nothing; each run of stderr writes one entry, the C's stdio writing a message in pieces, so the Zig's one `writev` per message is counted apart (exactly 1 per path, the C's more than 1 as the control). Plants in a scratch copy, each caught: chdir and `close_range` swapped, `close_range` gone (native, and basic's payload descriptors), a message in pieces, a refusal's byte (golden), TIOCSCTTY after the signal reset, the mask emptied before the reset, a 64 KiB and the default stack (a `prlimit64` before `setgroups`; rootless's `ulimit -s` saw 16384). Differential outside the VM: 4,000 random argvs and 9 large ones (60,000 groups, 131,000-byte words), and 21 paths under `unshare --map-root-user --map-auto`, 0 differences. Two differences no caller can see: GROUPS' commas are not overwritten (strtok_r), and a one-byte READY write returning 0 prints `Success` where the C printed a stale errno. The pid-1 panic is no longer run (P2 gone; the same `msg.onPanic` as flong-seccomp's) | this host, 2026-09-23, phase 3 (a) and its reviews |
| the Zig flong-init (phase 3 a) | 40,312 bytes, static, stripped, no INTERP, PT_GNU_STACK size 0 (the C 17,408, dynamic, glibc); aarch64: static, no interpreter. The launcher set is `flong-launcher-0` (zigSet's version); Nix's fixup now strips the `$CC` binaries with `-S` (flong-launch 107,648 to 107,224 bytes, flong-sweeper 50,088 to 49,808); closure 43,825,072 bytes (54,318,016 before). `sys.zig` is a seccomp source, so seccomp's path moved once (quirk 36); a scratch edit of `src/init.zig`, `launcher/*.c` or `launcher/*.h` leaves seccomp's drv path unchanged, the launcher's moving (the control) | same, `readelf -lW`, `file`, `nix path-info -S` |
| phase 3's derivations, `nix build --rebuild` | `launcher` 11.7-12.1 s, `seccomp` 10.8-11.4 s, each bit-identical; the transition subtest 2.4 s. Local `nix flake check -L`, alone, partly cached: 161.7 s and 291.8 s; `--no-build --all-systems` after it 276.8-278.9 s; test scripts native 33.7 s, parity 21.2 s, basic 83.8 s, rootless 110.1 s | same |
| `nix build .#bench`, C flong-init (57e2de0) against Zig (phase 3 a; reported, not gated) | medians of 20, three runs, ms, median (p10-p90) per run. No network: C 31.8 (26.8-35.4), 31.0 (26.4-34.0), 31.8 (30.0-34.9); Zig 32.9 (28.5-35.8), 29.5 (27.3-33.5), 33.5 (30.4-34.5). Pasta + nft hook: C 60.1, 56.1, 57.0; Zig 58.3, 52.8, 49.0. Forwarded port: C 78.2, 72.9, 73.4; Zig 75.2, 78.1, 70.1. Cold: C 376.9, 365.9, 367.9; Zig 370.8, 379.5, 367.9. Within the runs' spread | same, `numbers.md` of each |
| the Zig mount helper in the C launcher (phase 4 a) | `libflong-mount.a` (ReleaseSafe, stripped, pic, no libc, no compiler-rt): 185,626 bytes, `T flong_mount_main` its only global, needing `memcpy` and `memset` only (`sys.clockRealtime` makes the syscall in a library, as std's vDSO lookup would add `getauxval`); aarch64 183,778 bytes, needing `getauxval`, `memcpy`, `memset`. `flong-launch` 234,976 bytes after `strip -S` (107,224 before), the launcher closure 43,952,824 bytes (43,825,072); the clash check holds on the real link (no glibc name defined; `memcpy`, `memset`, `__stack_chk_fail` from glibc). `rootless.nix` passes unchanged with the Zig helper; its transition subtest runs the refusals and their controls, the declaration's mounts (each mount's `/proc/self/mountinfo` options included), the protected paths, the prepared-root symlink and the trace under both helpers, output and status equal; the swap race 20+20 under each, 0 escapes (Zig 15-20 refused, the rest contained; C 17-23), and 16 extra-mount cases (symlinks on the way, protected paths through a link, tmpfs and overlay under a caller's directory with host owner and mode, masks, sysfs, home) equal under both. The walker (`checks.native`): a path open following symlinks escapes 11-67 of 200 under the swapper (29 in the commit's run), the walk 0 of 400. Plants a review found missed, now caught: `walkOpen` without `RESOLVE_BENEATH` (`/..` walks out), a last-component file following a symlink (relative links), `/run` left writable, the transition running one launcher twice. Plants in a scratch copy, each caught: compiler-rt bundled (the clash check: more globals), `flong-launch` linked `-s` (the clash check: no symbols), a mirror field of the wrong size (test-libc's layout check), a walk without `RESOLVE_NO_SYMLINKS` (the walker's transcript and race), masks without `noexec` (only the transition subtest) | this host, 2026-09-23, phase 4 (a), `nm`, `nix path-info -S` |
| phase 4 (a)'s derivations and runs | `launcher` 14.5 s (`nix build --rebuild`, bit-identical); test scripts rootless 109.2-115.7 s, native 16.0-25.4 s (the walker's subtest 0.2 s), basic 80.2 s, parity 20.2 s; the transition subtest 7.2 s. Local `nix flake check -L`, alone: green, 5 min 0.7 s, then 321.1 s for the commit; `--no-build --all-systems` 280.3 s; `launcher` again 15.5 s, bit-identical. CI before it (e07049a, run 35918252132): `nix flake check` 7 min 49 s. `sys.zig` moved seccomp's store path once more (quirk 36) | same |
| the Zig flong-sweeper against the C (phase 5 a) | `golden`'s 30 sweeper cases green against both, the C built in the check (`native.nix`'s `sweeperC`), each side told by whether it names a glibc symbol; `test-libc`'s differential of `record.parse`, `cgroup.sessionForm` and `record.closedInode` against `parse_record`, `session_form` and `closed_inode` compiled from `launcher/` (`tests/zig/record_c.c`), 10,000 token-built inputs under a fixed and a random seed each (parse also cut at a random length), 0 differences; `num.strtoull10` against glibc's base-10 `strtoull` (every string of up to 4 over 21 characters, 20,000 random): equal. Fuzzing (minish, Debug and ReleaseSafe): 7 targets, each its corpus (`tests/zig/corpus/`, 79 files) then 10,000 token lists and 10,000 byte strings under a fixed and a random seed: no panic; token runs accept per 10,000 record-parse 1,317, session-form 752, closed-inode 2,006, proc-stat 1,210, own 205, populated 4,753, inotify 2,050 (before structured builders: 15, 17, 39, 0), each run needing 1%. A review's scratch fuzz, about 24.3M structured mutations over 9 seeds: 0 panics; end to end, 9,000 fuzzed records, 22,000 churn rounds, 1,100-deep nested cgroups: the sweeper alive, 7 descriptors idle. Mutations in a scratch copy, each caught by `native-test`: a child ignoring the keep list, `retainOnly` without its final `close_range`, `retainOnly` skipping `close_range` (the keep-list test, the property); `close` without the generation bump (fd's stale tests, fd_props, the property); Spawn skipping the signal reset (the reset test); `dup2` without staging (the permutation test); a fork child keeping a stale signalfd (the signalfd test); `awaitFd` ignoring POLLHUP, and POLLERR (the awaitFd test, `error.Hung` after its 10 s bound). Plants, each red: a changed record byte (basic's record-bytes); postStop run twice, the blank skipped, the watch after the first sweep (checkpoint 11), a 4095-byte realpath refused (`checks.native`'s two sweeper subtests); golden running the Zig on both sides; a fuzz target that never parses; the lockWait helper not taking the lock; four models (B20-B23, 22 findings). `checks.native`'s differential runs both sweepers over one state directory of launcher-written and hostile records: byte-identical output, records, cgroups and postStop log, 1.1 s. The VM suite unchanged: rootless, basic, parity, native green with the Zig sweeper | this host, 2026-09-24, phase 5 (a) |
| the Zig flong-sweeper (phase 5 a) | 142,208 bytes, static, stripped, no INTERP, PT_GNU_STACK size 0 (the C 49,808, dynamic); the launcher closure 44,045,224 bytes (43,952,824); `launcher` `nix build --rebuild` 9.3-16.6 s, bit-identical. `cgroup.removeTree`'s frame 2,576 bytes (6,720 before its shared path buffer; the C about 4.2 KB): 1,100 nested cgroups peak at 2,672 kB of stack, stopping at the descriptor table as the C does. `waitEmpty` can wait forever when another process of the user removes the cgroup inside the kernel's 10 ms `cgroup.events` notification delay, as `flong-cgroup.c:495-529` does; kept. Local `nix flake check -L`, alone: 285.1 s (native and basic cached; test scripts native 17.9 s, parity 22.2 s, basic 87.3 s, rootless 110.0 s); `--no-build --all-systems` 280.2 s. CI before it (d698a44, run 35932499136): `nix flake check` 7 min 52 s. `sys.zig`, `fd.zig` and `msg.zig` moved seccomp's store path (quirk 36). P3 retired: its questions run on `src/proc.zig` (`checks.native`'s `proc:` subtests, `native-test`, `fork_body_returns.zig`) | same |

**Reporting.** CI runs after a push and trunk commits are never amended, so
each phase's first commit reports the previous push's CI flake-check time (run
ID, SHA) and its own derivations' build times; phase 8 reports L5's. Phases 3
and 7 add `nix build .#bench` on parent and phase commit (median, p10, p90).

## The target

### Layout

At the root, `build.zig`, `build.zig.zon`, `.zwanzig.json`, `native.nix`,
`tools/fdlint.zig`; `src/` holds the modules of [Per binary](#per-binary),
`fixtures/` and `hybrid/` (phases 4-7); `tests/` holds `zig/`, `golden/`,
`native.nix`, `integration.nix`, `probes.nix`. `launcher/` and `seccomp/` keep
`default.nix` (thin imports of `native.nix`), `policy.nix`, `*.policy`,
`*.groups`; each `.c` and `.h` stays until its phase. `spike/` is archived in phase 2.

### build.zig

- `standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe })`
  accepts the hook's `--release=safe -Dcpu=baseline` (`generic.nix:158-160`);
  a plain `-Doptimize=ReleaseSafe` was rejected (observed).
- `-Dset=launcher|seccomp|fixtures` picks what `install` installs.
  Compiled-in paths are options with no default, read by the roots only:
  `-Dbwrap -Dpasta -Dtini -Dinit -Dnewuidmap -Dnewgidmap`, and `-Dself` (the
  seccomp derivation's `$out`, the key's compiler path); a missing one makes
  that install depend on `b.addFail` (`flong-init.c:52-54`'s `#error`).
- `-Ddev=true` guards every `b.lazyDependency`; without it `test` and
  `analyze` depend on `b.addFail("needs -Ddev=true")`. Installed artifacts:
  `strip` (every one, cross included: Nix's fixup strips only `bin/`, with
  `-S`, and no aarch64 ELF, measured), `single_threaded`, `stack_size = 0`;
  `link_libc` only for `flong-seccomp` and `bpfdump`.
- Steps: `install`; `test` (`-Drelease=true` for ReleaseSafe); `test-libc`;
  `compile-fail`; `lint`; `fmt` as `b.addFmt(.{ .check = true, .paths = &.{
  "build.zig", "build.zig.zon", "src", "tests/zig", "tools" } })` (with no
  paths it runs a bare `zig fmt --check`, which exits 1,
  `Build/Step/Fmt.zig:16`); `analyze`; `cross`; `integration`; `mountlib`
  (phases 4-7). `minimum_zig_version = "0.15.2"`.

### The syscall layer: `sys.zig`

- **On `std.os.linux` only**, importing none of flong's modules: `std.posix`
  makes real errnos `unreachable` (`posix.zig:5478-5481, 6949, 5894-5913,
  6772-6784, 4470-4476, 293-297`), and `linux.sigaction` asserts on SIGKILL
  and SIGSTOP (`linux.zig:1857-1861`), so Spawn's reset uses raw
  `rt_sigaction`. Each wrapper returns `Result(T) = union(enum) { ok: T,
  err: linux.E }`. EINTR is retried where the C retries it.
- **Re-exports** what the lint bans elsewhere (`argv()`, `environ()`,
  `argvSlots()`, the kernel's writable slots flong-init execs from,
  `path_max`) and `exitGroup(u8) noreturn`.
- **Adds**, each `extern struct` or constant with a comptime assert:
  `clone3`, `CloneArgs` (88 bytes); `close_range`; `setns` (std wraps
  neither `clone3` nor `setns`, measured); `openat2`,
  `OpenHow` (24), `RESOLVE_*`; `open_tree`, `move_mount`, `fsopen`,
  `fsconfig`, `fsmount`, `mount_setattr`, `MountAttr` (32); `statmount`,
  `MntIdReq` (VER0, 24), `StatMount`, `STATX_MNT_ID_UNIQUE` read at 0x90
  (`linux.Statx.__pad2[0]`); `PIDFD_GET_{CGROUP,MNT,NET}_NAMESPACE`;
  `setfsuid`/`setfsgid` per arch, `fchownat`, `umask`, `getpgrp`;
  `O_TMPFILE` as the kernel's full `__O_TMPFILE|O_DIRECTORY` (std's
  `O.TMPFILE` is one bit, `linux.zig:333, 474`); `cfmakeraw` with glibc's
  bits. Terminal ioctls are std's, `TIOC*` from `T`'s generic branch
  (`linux.zig:5090-5139`; `:4790` is MIPS); `isatty` is `TCGETS` succeeding.
- **Kernel floor,** unchanged (`statmount` 6.8, `PIDFD_GET_*_NAMESPACE`
  6.11, fd-valued overlay layers about 6.13, inferred); phase 8 documents it.

### The descriptor layer: `fd.zig`

The spike's table (`spike/fd-zig/src/fd.zig`, archived in phase 2), moved onto `sys.zig`. A handle
is `{slot: u16, gen: u32}`; `close` bumps the generation; `raw()` on a stale
handle panics; the kind is in the type. Every open is `O_CLOEXEC`.

- **Changed from the spike:** 1024 slots, not 64 (`fd.zig:22`): `TableFull`
  ("too many open descriptors") where the C gets EMFILE; `fork` and
  `Spawn.start` reserve the pidfd's slot before `clone3` (`:280, 326`);
  `retainOnly` closes up to `~0U` (`flong-util.c:159`), not `maxInt(i32)`.
- **`Held(k)`** (`h.holdUntilExit()`) has no `close`; a fork child that does
  not keep it drops it. Held, as the C never closes them: the state and
  sessions directories, the cache (locked shared), the holder's cgroup, the
  info read end, U1, the netns, the leader's pidfd, the pasta memfd
  (`flong-launch.c:52-78, 785-845`).
- **`Inherited`** (kind `inherited`, L4; `adoptInherited(n)` after the spec
  validated `n`): `keepInherited` and `close` (`flong-launch.c:407-408`).
  The wrapper's `--ro-bind-data N` strings go to bwrap verbatim, the spec
  having matched them to keep-fds (`flong-spec.c:396-406, 696-706`).
- **`Stdio`**: fds 0-2, outside the table; read, write, poll; no `close`,
  never non-blocking. **`selfPath`**/**`pidPath`** give `/proc/self/fd/N`
  and `/proc/<pid>/fd/N`. **`closeUntracked()`** is `flong-launch.c:907-925`.
  **`adoptForeign`** is for the mount-helper shim only.
- **openat2:** `walkOpen` is the only `RESOLVE_BENEATH` caller
  (`flong-mount.c:318-335`); `openExact` is `openat2` from `AT_FDCWD` with
  `NO_SYMLINKS|NO_MAGICLINKS` (`:120`); `openFollowing` is `open` (`:121`).

### Descriptor kinds

| kind | minted by | operations | phase |
|---|---|---|---|
| `file` | `openFile`, `memfd` | read, write, pread, pwrite, flock, fstat, poll with POLLPRI (`cgroup.events`) | 2 |
| `dir` | `openDir`; `openExact`/`openFollowing(.dir)` (`O_RDONLY\|O_DIRECTORY`: overlay lowers, `flong-mount.c:221`); `upper<i>`/`work<i>` from the scratch tree (`:223-225`) | openat-relative, mkdirat, unlinkat, renameat, getdents64 with `d_ino`, flock, `FsCtx.setFd` | 2 |
| `path` | `openPath`, `walkOpen`, `openExact`/`openFollowing(.path)` (`O_PATH`: bind sources, `:145`) | fstat, statx, `fchownat(AT_EMPTY_PATH)`, open_tree, move_mount target, mount_setattr, openat2 dirfd | 4 |
| `tree` | `open_tree`, `fsmount` | move_mount source, mount_setattr, dirfd for the scratch tmpfs and masks | 4 |
| `fsctx` | `fsopen` | fsconfig; `setFd` takes `dir` only (`FSCONFIG_SET_FD`'s `fget` refuses `O_PATH`); fsmount into a `tree` | 4 |
| `userns`, `mntns`, `netns`, `cgroupns` | `/proc/<pid>/ns/*`, the pidfd ioctls | setns with the matching `CLONE_NEW*`; `pidPath` | 4 |
| `pipe_r`, `pipe_w` | `pipe` | read or write | 4, 5 |
| `pidfd` | `fork`, `Spawn.start`, `pidfd_open` (ESRCH is an answer) | poll, waitid, pidfd_send_signal, the namespace ioctls | 4 (adopted), 5 |
| `cgroup` | `openCgroup` (`O_PATH\|O_DIRECTORY\|O_NOFOLLOW`, `flong-cgroup.c:123-126`) | openat, mkdirat, unlinkat, file I/O relative to it; the only kind `fork` and `Spawn` take as `cgroup` | 5 |
| `inotify` | `inotifyInit` | add_watch by `selfPath`, an event iterator over an aligned buffer | 5 |
| `signalfd` | `sig.openSignalfd` | read of `signalfd_siginfo` | 5 |
| `record` | `record.create` (`sys.O_TMPFILE\|O_RDWR`, then `LOCK_EX`) | write at the offset (never `O_APPEND`), pread and pwrite at 0, link by `selfPath`, unlink then close | L2 |
| `pty_master` | `/dev/ptmx`, `O_NONBLOCK` | read, write, `TIOCSPTLCK`, `TIOCGPTN`, `TIOCSWINSZ`, early close (hang-up) | L3 |
| `pty_slave` | open of `/dev/pts/N` | termios, winsize, a stdio source for `Spawn` | L3 |
| `tty_out` | reopen of `/proc/self/fd/1`, `O_WRONLY\|O_NOCTTY\|O_NONBLOCK`; may fail (quirk 42) | write | L3 |

### Signals and processes: `sig.zig`, `proc.zig`

- **`sig`:** `block()` (TERM, HUP, INT, QUIT, WINCH, CONT), `ignorePipe()`,
  `defaultChld()` (`flong-launch.c:861-877`, `flong-sweeper.c:26-29`);
  `sig.fd: ?Fd(.signalfd)`; `take(want)` (`flong-util.c:258-282`);
  `abort_signal` (`flong-launch.c:842, 905`). `awaitFd` is `fl_await`
  (`flong-util.c:284-322`). `awaitFdOrExit(h, child)` (L4) is
  `await_or_bwrap`'s epoll as one `poll` over `{h, pidfd, sig.fd}`, `h`
  winning a tie (`flong-launch.c:421-448`). Waits test `sig.fd.isLive()`,
  never `raw()`, so a fork child that dropped it is fine
  (`flong-util.c:476-479`).
- **`fork(opts, ctx, comptime body: fn (@TypeOf(ctx)) noreturn)
  error{Reported}!Child`**, `opts = { cgroup: ?Fd(.cgroup) = null, keep }`:
  the child runs `retainOnly(keep)` (on failure `close_range N: text`, 125,
  `flong-util.c:154-165, 474-475`), then `body`; no parent `defer` runs in it,
  and a body that is not `noreturn` does not compile. Mask and dispositions
  are inherited (`flong-util.h:187`).
- **`Spawn`**: argv in a caller-given allocator (bwrap's exceeds 100);
  `passFd(h)` (number into argv, `h` kept), `keepInherited`, `stdio:
  [3]?AnyFd`, `envp` (null is `sys.environ()`), `dir`, `cgroup`, all built
  before `clone3`. The child is `spawn_child` step for step
  (`flong-util.c:406-452`), its failures printed, then 127.
- **`Child { pidfd, pid }`** ends once: `await()` (`flong-util.c:336-346`;
  after `Aborted` the child is still the caller's), `reapNow(.kill | .wait)`
  (`:348-358`) or `release()`, closed unreaped (`flong-launch.c:771-778`).
  `peek()` is `WNOWAIT`, not an ending (`flong-tty.c:351-358`). Status:
  `si_status` for `CLD_EXITED`, else `128 + si_status`. No implicit kill.
- **`lockWait(h, op)`** is `fl_lock_wait` (`flong-util.c:484-513`);
  **`starttime(pid)`** is `:360-385`. **Exit:** a returning single-threaded
  `main` ends in `exit`, not `exit_group` (measured), so every root is `pub fn
  main() noreturn` ending in `sys.exitGroup` (`proc.exit` re-exports it), as
  every fork body. Nothing with a side effect is deferred across a fork.

### Messages, errors and panics: `msg.zig`, `errno.zig`

- **`prog`** is set first in each root. `msg` imports `sys` for its write;
  `check(r, fmt, args)` unwraps a `sys.Result` or prints and returns
  `error.Reported`; `fail`, `refuse`, `die` (125, for fork bodies),
  `trace(stage)`, `traceAt(t, stage)` (`flong-util.c:112-130`).
- **Unbuffered, one write per message**, EINTR retried, failures dropped; no
  `std.debug.print`, `std.log` or buffered stderr. As the C: **cut** for
  `flong-launch`, its children, the mount library and `flong-sweeper` (body
  at 1022 bytes, then `\n`, `flong-util.c:51-79`); **whole** for
  `flong-init`, `flong-seccomp` and its subcommands, one `writev`
  (`flong-init.c:59-67`; `flong-seccomp.c:75` prints a word of up to 4095
  bytes; `policy.nix:157-167`).
- **`errno.zig`**: glibc's text and name for 1..133, "Unknown error N"
  beyond. `error.Reported` is printed once, at the failure; `error.Aborted`
  prints nothing and sets `sig.abort_signal`. Tagged unions replace
  multi-valued ints; outside integers go through `num.zig`'s checked
  arithmetic.
- **Panics.** The default calls `abort`; in pid 1 a self-sent SIGABRT is
  dropped and it ends in SIGSEGV (`posix.zig:680-727`). Every root sets
  `pub const panic = std.debug.FullPanic(onPanic)`: one line, `exitGroup`.

### Per binary

All four set `enable_segfault_handler = false`, `keep_sigpipe = true`
(`start.zig:687-719`), `single_threaded` and `stack_size = 0`, so
RLIMIT_STACK reaches bwrap, tini, the payload and hooks unchanged (if a later
Zig rejects 0: the smallest size that works, its `prlimit64` recorded).

| binary | root | modules | libc | on panic |
|---|---|---|---|---|
| `flong-seccomp` | `seccomp/main.zig` | compile, expand, render, project, scmp, fd, sys, msg, errno, num; `std.crypto.hash.sha2.Sha256` | yes | `flong-seccomp: internal error: <msg>` (under `render` and `project`, their own prefix, as their messages), exit 1, the refusal callers handle; nothing on stdout |
| `flong-init` | `init.zig` | sys, msg, errno, num; no table, proc or allocator (DESIGN.md:1379-1383) | no | `flong-init: internal error: <msg>`, 125: the payload never ran |
| `flong-sweeper` | `sweeper.zig` | record, cgroup, names, proc, sig, fd, sys, msg, errno, num | no | `flong-sweeper: …`, 125; its exit stops the holder and every session (`module.nix:936-941`), so it must be panic-free on hostile records |
| `flong-launch` | `launch.zig` | spec, ns, cgroup, record, mount, tty, passwd, names, proc, sig, fd, sys, msg, errno, num | no | `flong-launch: …`, 125: a helper's 125 means "said why" (`flong-util.c:507-509`, `flong-ns.c:28-40`); the main process skips teardown, the sweeper releases, the watchdog restores the terminal, `--die-with-parent` ends the payload |
| `libflong-mount.a` | `hybrid/mount_c.zig` | mount, fd, sys, msg, errno (`flong-mount.c` uses only `fl_close`, `fl_err`, `fl_errx`, `fl_trace`) | the C's | `flong-launch: …`, 125, read as a failed mount (`flong-launch.c:570-575`) |

Dependencies point one way: `sys`; then `msg`, `errno`, `num`, `fd`; then
`sig`, `proc`; `record` uses `cgroup`; `mount` uses no `proc`.

**Allocation.** flong-init: none; both callocs go, the groups into a static
`[65536]u32` (`flong-init.c:113-138`), tini's argv reusing the kernel's
(`:222-237`: slots 5-7 become `"tini"`, `"-g"`, `"--"`, `&argv[5]` is
exec'd, DIR read first). flong-sweeper: none, fixed buffers (`REC_MAX`,
`flong-record.c:38-39`; 256 waits, `:758-762`). flong-launch: one arena over
`page_allocator`, never freed (`flong-launch.c:97-99`), fork bodies' inputs
built before the fork. The mount helper's source array: `page_allocator` in
the child (`flong-mount.c:524`). flong-seccomp: an arena over `c_allocator`.

### The mount-helper shim (phases 4-7)

- **The call.** `flong-launch.c:553`'s `_exit(mount_run(&job))`, in the
  `fl_fork` child, becomes `flong_mount_main(&job, fl_tracing);`, and
  `flong-mount.h` gains `_Noreturn void flong_mount_main(const struct
  fl_mount_job *job, int tracing);` (`fl_tracing` is an `int`,
  `flong-util.h:43`); `mount_run`'s prototype stays until (b). Nothing else
  in the shipped C changes.
- **What crosses:** `struct fl_mount_job` (`flong-mount.h:67-81`) in the
  child's copy of memory, protect paths canonicalised before the fork
  (`flong-launch.c:234-248`), and the trace flag (`flong-mount.c:592`). Back:
  0, 1 after printing why, 125 on a panic. The child holds 0-2, U1, the ready
  read end and the leader's pidfd (`flong-util.c:467-482`), adopted as
  `.userns`, `.pipe_r`, `.pidfd`; exit owns everything (`flong-mount.c:3-5`).
- **`src/hybrid/mount_c.zig`**, the only `adoptForeign` user: `export fn
  flong_mount_main`; `extern struct` mirrors checked against `addTranslateC`
  of `flong-mount.h`; sets `msg.prog = "flong-launch"` and the trace flag,
  calls `mount.run(job)`, exits 0 or 1. No Zig start code runs; `mount.zig`
  reads no argv or environ and knows nothing of C.
- **The library:** no libc, `pic`, `single_threaded`, stripped, ReleaseSafe,
  its own panic, `bundle_compiler_rt = false`, `stack_check = false`,
  `stack_protector = false`. Stack probing is what needed
  `__zig_probe_stack` (measured); without it the remaining references are
  `memcpy` and `memset`, plus `getauxval` on aarch64 (and on x86_64 but
  for `sys.clockRealtime` making the raw syscall in the library, std's vDSO
  lookup needing it; measured phase 4), all glibc's, and
  nothing of Zig's takes a glibc name (measured, P5, P6). **The link,** in the launcher
  derivation with today's `cflags` (`launcher/default.nix:31-47`); the
  archive is never installed:
  ```
  zig build mountlib $zigDefaultCpuFlag $zigDefaultOptimizeFlag --prefix $TMPDIR/mountlib
  $CC "${cflags[@]}" -o $out/bin/flong-launch flong-launch.c flong-spec.c flong-ns.c \
    flong-cgroup.c flong-record.c flong-tty.c flong-util.c $TMPDIR/mountlib/lib/libflong-mount.a
  ```
- **The clash check,** failing the same build: `nm -g --defined-only` of the
  archive lists `flong_mount_main` alone; `nm --defined-only flong-launch`
  defines none of `memcpy`, `memset`, `memmove`, `memcmp`, `bcmp`,
  `__stack_chk_fail`, `__stack_chk_guard`; `nm -D --undefined-only` lists
  `memcpy`, `memset` and `__stack_chk_fail`.
  **Fallback** if P5 finds a reference glibc and libgcc do not resolve:
  bundle compiler-rt, `$LD -r --whole-archive` the archive into one object,
  `objcopy --keep-global-symbol=flong_mount_main`; the same check holds.
- **The C-only variant** `flong-launch-cmount` (phase 4 (a), check-only)
  links the C with `flong-mount.c` and `tests/cmount-shim.c`, whose body is
  `fl_tracing = tracing; _exit(mount_run(job));`. **aarch64:**
  `cross-aarch64` checks the archive's global symbols, and that it needs
  nothing outside `memcpy`, `memset`, `memmove`, `memcmp`, `bcmp`,
  `getauxval`; the aarch64 C link is
  unchecked in phases 4-7 (no cross C toolchain in the flake), so a failure
  there is a loud build error for that user. **L5 deletes** `src/hybrid/`,
  `adoptForeign`, `mountlib`, the layout check, `launcher/*.h`.

### Lint and analysis

- **fdlint** (the spike's, over `std.zig.Tokenizer`, so comments and strings
  never match, and an alias is caught where made). Rules, with allow-lists:
  - `raw-namespace`: `os`, `fs`, `c`, `posix`, `process` after `std.`
    (`std.process.exit` would skip the teardown), so `callconv(.c)` and
    `builtin.os` pass (the spike matched `c` after any period,
    `fdlint.zig:21`). Allowed: `sys`, `fd`, `proc`, `sig`, `src/fixtures/*`,
    tests.
  - `posix`: `.posix` anywhere outside tests.
  - `extern`: `extern fn`/`var`/`const`, `extern "lib"`, `@extern`, `export`,
    `@cImport`; `extern struct`/`union`/`enum` pass everywhere. Allowed:
    `scmp.zig`, `mount_c.zig`, `tests/zig/abi.zig`, `tests/zig/libc_*.zig`.
  - `raw-number`: `.raw` outside `sys`, `fd`, `proc`, `sig`,
    `seccomp/scmp.zig`; the ways out are `passFd`, `selfPath`, `pidPath`,
    `FsCtx.setFd`, `scmp.exportBpf(ctx, Fd(.file))`.
  - `argv`: `sys.argv`/`sys.argvSlots`/`sys.environ` outside the roots and
    `proc.zig` (Spawn's default envp).
  - `handle-guts` (`.slot`, `.gen`) outside `fd.zig`; `adopt-foreign`
    outside `hybrid/mount_c.zig`; `debug-output` (`debug.print`, `std.log`);
    `catch-unreachable` without `// proven: <why>` on the line; `alloc`
    (`GeneralPurposeAllocator`, `DebugAllocator` in `src/`).

  `lint` runs fdlint on `tests/zig/lint/bad.zig` (every planted line
  reported, as the spike's `build.zig:71-87` did) and `good.zig` (nothing
  reported: `extern struct`, `callconv(.c)`, `builtin.os.tag`, an allowed
  `export fn`).
- **zwanzig** on `src/`, method-name models (`receiver_type` and `fqn` do not
  resolve imported types) matched exactly, no wildcard (zwanzig
  `src/config.zig:128-131`): one open model per minting function (`openFile`,
  `openDir`, `openPath`, `walkOpen`, `openExact`, `openFollowing`,
  `openCgroup`, `memfd`, `inotifyInit`, `openSignalfd`, `pipe`, `fork`,
  `start`, `create`, `openTree`, `fsopen`, `fsmount`, `openNs`, `pidfdOpen`,
  `openPtmx`, `openSlave`, `reopenOut`, and `adoptForeign`), added with the
  function; closes `close`, `await`, `reapNow`, `release` (a close model for
  `fd.closeChecked` is not honoured, measured phase 4: its double close is
  the table's to catch at run time; nor are `reapNow(.kill)`, a close with an
  argument, and `try c.await()` as an ending, measured phase 5: a `release`
  after either is not reported, one after `release` is, so they only miss
  findings). It must still report
  `tests/zig/analyze/bugs.zig` (spike B1-B3, B6-B8; B9-B11 on `fd.zig` from
  phase 2); leaks come from
  `liveCount` and the `/proc/self/fd` property.
- **compile-fail:** read on `pipe_w`; `pidfd` for `dir`; `dir` as
  `Spawn.cgroup`; `netns` to an `mntns` setns; `close` on `Held` or `Stdio`;
  `passFd` of `Stdio`; `FsCtx.setFd` of a `path`; a fork body that returns.

## The Nix build

- **`native.nix`** builds one derivation per set through one builder;
  `launcher/default.nix`, `seccomp/default.nix` and `tests/parity/default.nix`
  import it and keep their `pkgs ? locked nixpkgs` default
  (`launcher/default.nix:11-20`), so `module.nix:126, 478`, `flake.nix:37-40`
  and `tests/parity.nix:46` are untouched.

  `zigSet { pname, set, files, flags, buildInputs, extra }` is a
  `stdenv.mkDerivation` with the `zig_0_15` hook, `src` a fileset of
  `build.zig`, `build.zig.zon` and `files`, `dontUseZigBuild` (the hook's
  buildPhase is a second full build, `setup-hook.sh:16-41, 108-110`),
  `doCheck = false` (its checkPhase runs `zig build test`, which needs
  `-Ddev`), `disallowedReferences = [ zig_0_15 ]`, and an installPhase of
  `zig build install -j$NIX_BUILD_CORES $zigDefaultCpuFlag
  $zigDefaultOptimizeFlag -Dset=${set} --prefix $out ${flags}`, then `extra`:

  ```nix
  seccomp = zigSet { set = "seccomp"; flags = "-Dself=$out"; buildInputs = [ pkgs.libseccomp ];
    files = [ ./src/seccomp ./src/sys.zig ./src/fd.zig ./src/msg.zig ./src/errno.zig ./src/num.zig ]; … };
  launcher = zigSet { set = "launcher"; flags = "-Dbwrap=… -Dinit=$out/bin/flong-init …";
    files = [ (lib.fileset.difference ./src (lib.fileset.unions [ ./src/seccomp ./src/fixtures ]))
              (lib.fileset.fileFilter (f: f.hasExt "c" || f.hasExt "h") ./launcher) ];
    extra = "…"; … };  # phases 3-7: the remaining C by $CC; phases 4-7 the mountlib link and clash check
  ```

  A `build.zig` or `build.zig.zon` edit moves every set. Phase 1 has
  `seccomp`, phase 3 adds `launcher`, phase 6 `fixtures`. Until phase 7 the
  remaining C is built by `$CC` with today's flags into the launcher's `$out`,
  keeping `bin/flong-launch`, `flong-sweeper`, `flong-init` side by side
  (`tests/rootless.nix:636-641`, `flake.nix:314-321`). Zig turns each `-L` of
  `NIX_LDFLAGS` into a lib dir and rpath (`NativePaths.zig:17-72`), which is
  how `flong-seccomp` and `bpfdump` find libseccomp.
- **`tests/integration.nix`**, from phase 0, never an output: `zig build
  integration` over the whole package (the proofs, then the spawn probe,
  walker, ns and pty drivers, on the branch `spec-probe`) for `checks.native`
  and `golden`. Phase 0's is per-proof derivations instead: it finds each
  `tests/proofs/<pN>/default.nix` by `readDir` (`tests/proofs/README.md`;
  `spike/proofs/` until phase 2), for `checks.integration` and `checks.native`.
- **`deps = pkgs.zig_0_15.fetchDeps { pname; version; src = <build.zig*>;
  fetchAll = true; hash; }`** (`fetchAll` defaults to false, fetching no lazy
  dependency, `fetcher.nix:7-12, 37`), linked into `$ZIG_GLOBAL_CACHE_DIR/p`
  by `native-test` and `native-analyze` only, with `-Ddev=true`. On a
  `build.zig.zon` change, the hash bootstrap: `lib.fakeHash`, build
  `.#checks.x86_64-linux.native-test`, copy `got:`, rebuild.
- **Checks**, beside the existing five: `launcher`, `seccomp` (a clean build
  with every guard on replaces `-Werror`); `native-test` (`test test-libc
  -Ddev=true`, Debug and `-Drelease=true`; glibc, `libseccomp.dev`, uapi and
  `asm/` headers from Zig's bundled per-arch set, since `pkgs.linuxHeaders`'
  `asm/` is the builder's); `native-lint` (`lint compile-fail fmt`);
  `native-analyze`; `golden`; `cross-aarch64` (x86_64 only: the launcher set
  with dummy paths, a `-fno-emit-bin` seccomp set, `abi.zig`, the archive
  check in phases 4-7; `flong-seccomp.c:191-198` adds x86 and x32 on x86_64
  only); `native` (`tests/native.nix`, phase 0 on); the transition checks. A
  devShell (both systems) carries `zig_0_15`, `libseccomp`, `strace`.
- **CI** has no KVM or binary cache (`ci.yml:22-28`); only the outputs and
  `tests/integration.nix` sit on the VM tests' path; `checks.native` is a
  fourth VM in parallel. Cachix or FlakeHub is the user's call if the total
  grows too long. `workflow_dispatch` (`ci.yml:7`) serves one-off runs.

## Tests

**The gate** is basic, rootless and parity at every commit, plus
`checks.native` and `golden`. Their strings stay byte-identical: `refusing to
run as root` (`rootless.nix:633-641`, `basic.nix:1331`), `postStart failed`
(`rootless.nix:733`), `launcher-start` (`:655`), `no user manager for dave`
(`:838`), `which no session may reach` (`:891-894`), `a symlink is on the way`
(`:486, 898`), `seccomp policy was refused` (`:1005`); statuses 125, 143, 137,
130, 1 and the payload's own; pasta's `--pid /proc/<pid>/fd/`
(`basic.nix:680-684`); `leader=` in records (`:659-667`); empty stderr on a
clean launch (`:728-732`).

**Characterization, landed on C before its program is ported**, each its own
commit. Root refusals need uid 0, which the build sandbox lacks, so they stay
with `rootless.nix:629-642`.

| test | where | before |
|---|---|---|
| the seccomp golden set (fixed cases, `.bpf` files), from the C | `golden` | 1 |
| the tooling golden set over `tests/golden/dump.txt`, from the awk and bash | `golden` | 2 |
| a project-policy launch writes nothing to stderr | rootless | 2 |
| `ulimit -s 4096; <launcher> sh -c 'ulimit -s'` prints 4096 | rootless | 3 |
| flong-init's argv refusals; a failing chdir to a >1 KiB DIR, printed whole | `golden` | 3 |
| the payload's `/proc/self/fd` holds only 0-2 | basic | 3 |
| mount refusals: `is mounted twice`, `is a directory and its source is not`, `X, on the way to Y, is not a directory` | rootless | 4 |
| the record during a sleeping hook equals `tests/golden/records/` (from `flong-record.c:337-341, 391-398`'s formats) with pid, start and paths substituted: `poststop=…\ncgroup=…\n`, then `leader=<pid>:<start>\n` after child-pid, nothing else | basic | 5 |
| flong-sweeper's usage and state-directory refusals | `golden` | 5 |
| tty (python pty driver): `^]^]^]` gives 137; a resize reaches the payload; after a SIGKILL of the launcher in relay the outer `stty -g` is as it was; SIGCONT makes it raw again; stdin EOF hangs up; relay with `2>file` leaves stderr in the file | rootless | L0 |
| postStart's and postStop's `/proc/self/fd` hold only 0-2 and the lister's own | basic | L0 |
| the spec refusal corpus, one case per refusal in `flong-spec.c` but root; a >1 KiB keyword cut to 1023 bytes | `golden` | L0 |

**`golden`**, permanent and black-box: argv, stdin and inherited descriptors
against stdout, stderr and status, in the build sandbox, against the outputs
and `tests/integration.nix`. It records only what flong's code determines:

- **Fixed cases** (`tests/golden/<set>/`), recorded from the C, never
  regenerated: seccomp (every refusal in `flong-seccomp.c`, the stats line,
  an empty policy, a 4096-byte line, a ~4000-byte comparison word printed
  whole, a repeated default, `010`, `0b1`, `1_0`, `+1`, one run with an
  argument); the tooling over `tests/golden/dump.txt`, a checked-in copy of
  today's `systemd-analyze syscall-filter` dump, so a systemd bump changes
  nothing; flong-init; flong-sweeper; the spec. After the C is gone a fixed
  case changes only as a Change quirk lists (quirk 16, phase 2).
- **Derived values**, computed when the check runs: the project key (`printf
  '%s\n%s' $seccomp "$policy" | sha256sum`) and every path with a store path
  or key in it.
- **BPF bytes** (`tests/golden/seccomp/*.bpf`) of a dozen checked-in policies
  and `audit`, `tty`, `nsmask`, none from the dump. They depend on
  libseccomp, so `golden` first compares `tests/golden/seccomp/LIBSECCOMP`
  with its version and fails with `libseccomp changed: run golden-update`.
  **`golden-update`** (a flake app) rewrites the `.bpf` files and
  `LIBSECCOMP` only, and is used only when the version differs and `bpfdump
  eval`'s text over old and new bytes is identical; the commit shows both. A
  byte change at the same version is a Zig bug. Filters built from the live
  dump are held by phase 1's transition and by parity.

**Unit and property** (minish, `native-test`):

- `fd.zig`: the spike's model property (`/proc/self/fd` equals the table),
  stale handles, fork, each kind. `num.zig` accepts exactly what the C did.
  `spec.parse` asserts `fd.liveCount() == 0` on entry; valid specs from a
  model parse back; each single-rule mutation is refused with its message;
  `bwrapArgv(spec)` has golden argv per branch (relay, nestedSandbox, a
  project filter, keep-fds, trace).
- **Fuzzing**, never a panic or `unreachable`: properties in ReleaseSafe,
  10,000 cases each, a fixed seed plus a random one printed on failure, a
  checked-in crash corpus (`tests/zig/corpus/`) replayed first; over
  `record.parse`, `session_form`, the mountinfo reader (with the launch
  half, phase 7), `cgroup.events`, `/proc/<pid>/stat` field 22,
  `closed_inode`, inotify events; each token run must accept at least 1% of
  its inputs and refuse one (measured phase 5: token lists alone reached
  stat's field 22 in 0 of 10,000).
- The child-pid parser over split reads and the 4096-byte bound
  (`flong-launch.c:455-531`); the `^]` detector as a pure state machine, 137
  iff three 0x1d within 1 s with nothing between, over any chunking
  (`flong-tty.c:33-36, 360-372, 479-486`); `overlaps()`
  (`flong-mount.c:84-92`); the mount sort and duplicate refusal.
- **Mutations** planted in a scratch copy in phase 5, each caught, the result
  in the commit message: a child ignoring the keep list; `retainOnly` without
  its final `close_range`; `close` without the generation bump; `Spawn`
  skipping the signal reset; `dup2` without staging; a fork child keeping a
  stale signalfd; `awaitFd` ignoring POLLHUP or POLLERR (the harness's kill
  bounds the hang); `retainOnly` skipping `close_range`.

**`test-libc`:** `errno.zig`, `cfmakeraw` and strtoull-base-0 against glibc
(`tests/zig/libc_*.zig`); `scmp.zig` against `seccomp.h`; `sys.O_TMPFILE`
against `fcntl.h`; in `tests/zig/abi.zig`, every `sys.zig` struct and
constant against `addTranslateC` of `linux/{mount,openat2,sched,pidfd,stat,
uio,capability,prctl,limits}.h`, `asm/{ioctls,signal,unistd}.h` (L3 adds
`asm/termbits.h`) from Zig's bundled headers,
for x86_64 and (in `cross-aarch64`) aarch64, each with `-target
<arch>-linux-musl` so only Zig's headers are read, asserting each took its
arch's headers (`__NR_openat` 257 or 56; P4's `abi_test.zig` is the model); phases 4-7, `flong-mount.h`'s layout
(`tests/zig/libc_mount.zig`: the header includes glibc's `sys/types.h`, so
x86_64 only, offsets and sizes; translate-c reads `_Noreturn` as `void`).

**`checks.native`** (one node, lingering alice with subordinate ranges,
`systemd-run --user -p Delegate=yes`, `unshare -Urm` where needed), binaries
from `tests/integration.nix`: `clone3(CLONE_INTO_CGROUP)` into an `O_PATH`
leaf, read back; the spawn probe (held descriptors equal the keep list and
argv numbers; `SigBlk`, `SigIgn`, dispositions default; stdio remap over every
permutation); the walker (phase 4: a symlink on the way and last, absolute
and relative, `..` refused, EEXIST
from a concurrent make, file and directory masks, ENOTDIR on the way, a
directory at a file destination, overlaps, and 2×200 walks against
`tests/probes.nix`'s swapper, 0 escapes); cgroup create, limits, undo, kill,
wait, remove (phase 5, L2); U1 and U2 through `/run/wrappers/bin/newuidmap`,
maps read back, and SIGTERM during the U2 wait giving `Aborted` with no helper
or pipe left (L2); pty (L3: relay both ways; EIO after the last slave
closes; the drain; the window copy; the watchdog restoring modes after a
SIGKILL of the relayer; a root-owned pty with the launch run as alice through
`setpriv`, so the `/proc/self/fd/1` reopen fails and output still arrives
through fd 1; stdin closed, then SIGWINCH to the launcher, and the payload's
own status, not 125).

**The record contract.** From phase 5 to L4 the C launcher writes records the
Zig sweeper sweeps. `tests/golden/records/` pins the writer's bytes (phase 5's
basic subtest on the C, L2's writer test, the same subtest at L4), so an old C
sweeper reads Zig records after an upgrade (`module.nix:941-945`). The parser
also meets no `cgroup=`, repeats, a NUL, oversize, `leader=` with a leading 0
or a sign.

**Mirrors of the spec in Nix:** `clean` (`module.nix:136-143` against
`flong-spec.c:208-229`), duplicate destinations (`:201-206, 683` against
`flong-mount.c:537-541`), `overlaps` (`:145-146` against
`flong-mount.c:84-92`). `tests/golden/paths.txt` holds (path, verdict) cases
for the Zig tests and for `assertions`, one declaration each, marking those
meant to differ (lexical module, canonical launcher, `module.nix:128-130`).
The mask depth rule (`module.nix:210-249`) has no launcher counterpart.

## Ordering checkpoints

Types cannot hold these. Each is one linear function with numbered comments,
never a helper, and a review item on every commit that touches it.

| # | order | held by |
|---|---|---|
| 1 | **The prologue** (`flong-launch.c:847-925`): the time taken as main's first statement (`:853`); block signals, SIGPIPE ignored, SIGCHLD default; `spec.parse`, refusing root first (`flong-spec.c:423`), `liveCount() == 0` on entry; adopt the keep-fds; the signalfd, so its number is never a keep-fd's; `traceAt(start, "launcher-start")`, stamped at entry and printed now (`:887-889`); `state_open`; `cache_lock` (swept: relaunch with SIGPIPE default and the old mask, or 75); `closeUntracked`. Nothing chdirs before step 4 | the keep-fd launches, the spec golden cases, the payload-descriptor subtest, bench's stage rows |
| 2 | **The child's ends go at once** after bwrap's spawn, whether or not it succeeded: info_w, ready_w, gate_r, the seccomp files, U2, the keep-fds (`flong-launch.c:396-409`) | the gate subtests (`rootless.nix:731-751`) |
| 3 | **`ready_r` closes right after the helper's fork** (`flong-launch.c:553-556`), so the helper alone sees the byte or EOF | the mount subtests |
| 4 | **ns.** U2 is strictly sequential: the grandchild unshares and writes `u`; the helper writes `uid_map`, `gid_map`, then `m`; only then the grandchild writes `/proc/sys/user/max_user_namespaces` and `n`; only after `n` the helper sends the pid and waits for the grandchild (`flong-ns.c:249-255, 289-305`). The namespace is opened before the hold or release pipe closes; on failure every pipe closes before any reap, then the map programs get `reapNow(.kill)` and the helpers `reapNow(.wait)` (`:199-219, 345-369`); an `errdefer` chain would reap first and hang | the U2 tests in `checks.native` |
| 5 | **The gate:** `tty.start` (the watchdog before raw), `take(0)`, resize, one byte, then `gate_opened` (`flong-launch.c:686-703`) | the ^C, gate and L0 tty subtests |
| 6 | **Teardown** in `flong-launch.c:785-845`'s order: finish the terminal, close the gate, kill, reap (short-circuiting), wait the sandbox and hooks leaves, postStop, pasta only with `pasta-wait`, remove or close | `basic.nix:1128-1146, 901-953` |
| 7 | **The mount helper** (`flong-mount.c:521-615`): umask, sort, duplicates; the pidfd namespace ioctls as the caller; `setns(U1)`, then `setresgid`/`setresuid(0)`; `unshare(CLONE_NEWNS)` and the sources; the ready byte; `setns(mnt)`, the root `O_PATH`, `setns(net)` and `setns(cgns)` before the sysfs and cgroup2 `fsopen`, `/.hostsys` detached; attach in sorted order; `/run` read-only last | `rootless.nix:846-917`, `basic.nix:787-872, 1252-1411`, the walker |
| 8 | **The watchdog** forks before raw mode, only when `isatty(0)`, keeping `{pipe_r, leader}` and 0-2 (`flong-tty.c:284-323`) | the L0 watchdog subtest |
| 9 | **flong-init** (`flong-init.c:195-238`): setgroups, the bounding set, the ambient set, capset, `TIOCSCTTY`, INT and QUIT default and an empty mask, `r` then close, the gate byte, chdir, `close_range(3, ~0U, 0)`, the trace, exec | phase 3's strace subtest, `basic.nix:742-744, 874-893` |
| 10 | **Records:** `O_TMPFILE`, `LOCK_EX\|LOCK_NB`, one write, `linkat` through `selfPath` with the uncounted EEXIST loop; `leader=` at the offset; unlink before close (`flong-record.c:343-386, 391-398, 408-417`) | the record-bytes subtest, `basic.nix:1186-1212` |
| 11 | **The sweeper** adds its inotify watch before the first sweep (`flong-record.c:769-777`) | `checks.native`'s "postStop once across a failed removal, and the watch before the first sweep" (a record released only by a close during a held first sweep; measured phase 5, no `rootless.nix` subtest reaches that window) |

## Behaviour: keep or fix

Keep: reproduced. Mechanism: done another way, no visible effect. Change: a
visible difference the port requires. Fixes wait for Open decisions.

| # | behaviour | verdict |
|---|---|---|
| 1 | writing the ready byte after the helper died, flong-init gets EPIPE, not SIGPIPE's death: it is its namespace's pid 1, which a default-action signal never kills; it prints `telling the launcher the root is built: Broken pipe`, or not, by timing (`flong-init.c:206`; CI run 35931207199) | Keep, `keep_sigpipe` (SIGPIPE stays default for the payload) |
| 2 | relaunch execs the wrapper before inherited descriptors are closed, restoring SIGPIPE and the mask first (`flong-launch.c:163-175` against `:907-925`) | Keep |
| 3 | pasta inherits `leader`, `userns`, `netns`, `machine` only when a hook ran (the `setenv` is in `run_hook` after its early return, `flong-launch.c:586-599`) | Keep: the envp is built only when a hook runs; pasta gets it then, `environ` otherwise |
| 4 | pasta's `--netns` names the leader by pid, the hook's `$netns` the launcher's descriptor (`flong-launch.c:594` against `:643`) | Keep |
| 5 | a malformed record under the wanted name is dropped, `release` returns 0, and the launch refuses `has ended but cannot be released yet` though the name is free (`flong-record.c:376-378, 543-546, 596-600`) | Keep; open decision 1 |
| 6 | postStop counts any reap error but an abort as run (`flong-record.c:471-478`) | Keep |
| 7 | teardown's reaps short-circuit on the first failure, the rest zombies until exit (`flong-launch.c:798-799`) | Keep |
| 8 | holder-start's pidfd is closed unreaped on an abort (`flong-cgroup.c:195-198`) | Keep, `Child.release()` |
| 9 | the watchdog's pidfd is closed at once, the watchdog reaped by pid (`flong-tty.c:309-313, 528`) | Mechanism: keep the pidfd, `reapNow(.wait)` in `finish`, same order |
| 10 | `^]^]^]` stalls while the payload reads no input: stdin is polled only when `in_len == 0` (`flong-tty.c:403`) | Keep; phase 8 documents it |
| 11 | the U2 handshake bytes' values are never checked (`flong-ns.c:173, 289, 301`) | Keep |
| 12 | `limit io.weight` is accepted and never emitted (`flong-spec.c:97-100` against `module.nix:530-547`) | Keep; open decision 1 |
| 13 | duplicate detection ignores negative (pseudo) syscall numbers (`flong-seccomp.c:253-259`) | Keep; open decision 1 |
| 14 | a `masked_eq` with mask 0 passes the int-argument check (`flong-seccomp.c:240-242`) | Keep |
| 15 | policy numbers are `strtoull` base 0 behind a leading-digit check (`flong-seccomp.c:112-121`) | Keep exactly what the phase-1 C binary accepts, pinned by the corpus |
| 16 | any argument to `flong-seccomp` is a usage error (`flong-seccomp.c:333-336`) | Change: no argument compiles; `expand`, `render`, `project` are subcommands; anything else prints `usage: flong-seccomp [expand DUMP SPEC... \| render DUMP NAMES 1\|13\|38\|log \| project DUMP NAMES 1\|13\|38\|log DIR] < POLICY`, exit 2. Phase 2 (a) rewrites that golden case |
| 17 | libseccomp exports with one `write` (`api.c:760`) | Keep: the same call, to stdout or the project's temp file |
| 18 | strerror texts | Keep glibc's, `errno.zig` |
| 19 | `getpwuid` (`flong-cgroup.c:160-168`) | Change, forced by no libc: `/etc/passwd`; an NSS-only user gets the `uid N` form; the tested text is unchanged |
| 20 | RLIMIT_STACK passes through to children | Keep, `stack_size = 0` and the `ulimit -s` subtest |
| 21 | `realpath` for postStop and the protected paths (`flong-record.c:442-446`, `flong-launch.c:185-229`) | Mechanism: `O_PATH` open, readlink of `selfPath` (as `flong-mount.c:97-110`); `canonical()`'s longest-existing-prefix rule unchanged; `access(X_OK)` is `faccessat` |
| 22 | message lengths: the launcher's, the mount helper's and the sweeper's cut at 1023 bytes; flong-init's (several stdio writes, `flong-init.c:59-67`), flong-seccomp's and the tooling's unbounded | Keep the lengths; Mechanism: one write or `writev` per message |
| 23 | `await_or_bwrap` uses epoll | Mechanism: one `poll`, the descriptor winning a tie |
| 24 | the spike's fork child exits 125 silently when `retainOnly` fails (`fd.zig:277`), its spawned child 127 silently (`:331-341`) | Fix (spike bugs): print first, as `flong-util.c:449-451, 474-475` |
| 25 | the spike's `Child.deinit` kills an unreaped child (`fd.zig:259-268`) | Change: no implicit kill; each site states `.kill` or `.wait`, as the C does |
| 26 | the spike leaks a child when adopting the pidfd fails (`fd.zig:280, 326`) | Fix: the slot is reserved before `clone3` |
| 27 | `remove_tree` recursion is unbounded (`flong-cgroup.c:539-575`) | Keep |
| 28 | uid map extents are uncapped; above 340 the kernel says EINVAL (`flong-spec.c:271-287`) | Keep |
| 29 | a deleted source reads back with ` (deleted)` and misses the protected-path compare (`flong-mount.c:97-110`) | Keep |
| 30 | `relaunch` has no absolute-path check, because it is exec'd from the wrapper's own working directory and its `$0` may be relative (`flong-spec.c:687-688`) | Keep, with no chdir before step 4; the comment moves into `spec.zig` |
| 31 | the info pipe's read end is never closed (`flong-launch.c:475-484`) | Keep: `Held` |
| 32 | exit 125 collides with a payload's own 125 | Keep |
| 33 | the sweeper's waits cap at 256 inodes (`flong-record.c:758-762`) | Keep |
| 34 | the project tool never shows the compiler's stats line on success (`policy.nix:201-205`) | Keep: the in-process compile suppresses it |
| 35 | a project that denies every name renders `allow ` with no name (`policy.nix:179`, `mapfile` at `:98`), refused ("missing syscall name") | Keep (inferred; the phase-2 corpus pins it) |
| 36 | the project key is sha256 of the compiler's store path, `\n`, and the rendered policy without its trailing newline (`policy.nix:179-184`); the compiler reads the policy plus one newline (`<<<`, `:201`) | Keep both. The path is the seccomp derivation's, which moves only with its own sources, `build.zig*`, libseccomp or Zig, not with launcher edits; caches are orphaned when it moves |
| 37 | the project's temp file is `mktemp`'s `.KEY.XXXXXX`, then `mv -T` (`policy.nix:200-206`) | Mechanism: `.KEY.<6 random>`, `O_CREAT\|O_EXCL\|O_WRONLY` 0600, then opened again by name as the shell's `>` did (a umask without the owner's write bit refuses it, as before), `renameat`; mktemp's refusal keeps its own line; a panic leaves the name, the next compile uses another |
| 38 | the tooling's messages: `flong-seccomp-project:` and `flong-seccomp-render:` prefixes (`policy.nix:86-94, 142-195`); in `project`, the compiler's captured lines keep their `flong-seccomp: line N:` prefix (`:201-205`), and an expand failure prints the expander's unprefixed line and exits 1 (`:173-176`) | Keep; only the usage lines change: `usage: flong-seccomp render DUMP NAMES 1\|13\|38\|log`, `usage: flong-seccomp project DUMP NAMES 1\|13\|38\|log DIR < POLICY`, and a new `usage: flong-seccomp expand DUMP SPEC...` |
| 39 | `tty_finish` is safe on the zero struct, whose fds are 0 (`flong-tty.h`) | Moot: optionals |
| 40 | a stale or wrong-kind handle reaches the wrong file in C silently | New: Zig panics, 125; fails closed |
| 41 | `TableFull` at 1024 | Matches EMFILE at the default soft limit |
| 42 | a terminal the caller cannot reopen (after su): the `/proc/self/fd/1` reopen fails silently and the relay writes through fd 1 only when poll reports POLLOUT (`flong-tty.c:196-203, 384`) | Keep: `tty.out: ?Fd(.tty_out)`, falling back to `Stdio(1)` |
| 43 | a redirected stderr stays where the caller sent it: in relay `stdio[2]` is the slave iff `isatty(2)` (`flong-tty.c:205-206`) | Keep |
| 44 | after a hang-up the master is closed, and resize and the drain check for it (`flong-tty.c:281-282, 386-389`) | Keep: `tty.master = null` after `close`; resize and drain branch on null |
| 45 | `launcher-start` is stamped when main begins and printed after the signalfd (`flong-launch.c:853, 887-889`) | Keep, `traceAt` |
| 46 | the tooling on inputs no caller gives (phase 2's fuzz): `project` with an unreadable stdin printed bash's read error and compiled the tier without the project's lines, exit 0 (fails open); texts that named the old tools' store paths (`awk: /nix/store/…-expand.awk:N:`, `<script>: line N:`) or followed the locale (the word check `^@?[a-z0-9_-]+$`, gawk's multibyte warning, mktemp's quotes) | Change: `project` refuses (`reading the policy: <strerror>`), exit 1; flong's prefixes and the C locale's text, ASCII words; each exit status as before. None is test-asserted |

## Phases

**Every phase:** land its characterization tests on the C first. **(a)** Zig
beside the C with the transition check, whose artifacts live in the check's
derivation, never in an output. **(b)** Delete the C and the check (`golden`
stays), fix the DESIGN.md lines the phase made false. Each is pushed green and
released (`ci.yml:32-43`) with its subject as the note, so each is complete
and says what changed for a user. Report as in [Measured](#measured); go on
unless a [stop condition](#stop-conditions-and-rollback) holds.

### Phase 0: proofs

**Goal:** answer the unknowns that would change the architecture, before any
production code. Proofs live in `spike/proofs/`, built by a first
`tests/integration.nix`, run by a first `tests/native.nix`.

- **P1, the build**, the spike as a `zigSet`: does `fetchAll = true` supply
  the lazy dependencies to `test -Ddev=true` offline; do `install`, `lint`
  and `cross` pass with an empty cache, no network and no `-Ddev` once
  `spike/fd-zig/build.zig:21, 93` are gated; does a `b.path` outside the
  fileset break a build that does not use it (the seccomp set needs no)?
  *Fallback:* a fixed-output derivation running `zig fetch` per pinned URL.
- **P2, flong-init's start code as pid 1** under `bwrap --as-pid-1`, the
  strict tier, `log = true`: no syscall before `main`, no audit record the C
  init lacks, a planted panic exits 125, `ulimit -s` passes through.
  *Fallback:* the smallest stack that works, its `prlimit64` audited.
- **P3, processes:** `clone3(CLONE_INTO_CGROUP)` into an `O_PATH` leaf of a
  delegated unit; the `noreturn` fork; a fork after `setns(CLONE_NEWUSER)`.
  *Fallback:* none; a failure is a Zig ABI bug.
- **P4, the mount ABI:** translate-c asserts from Zig's bundled headers for
  `open_how`, `mount_attr`, `mnt_id_req`, `statmount`, `clone_args`,
  `stx_mnt_id`, both arches with the arch assert; the mount calls
  round-tripped under `unshare -Urm`. *Fallback:* a C program printing
  `sizeof` and `offsetof`.
- **P5, the hybrid link:** a library with the shim's settings, linked by
  `$CC` with the launcher's flags (`-Werror`, hardening) into a C program
  that forks like `fl_fork`; the child adopts three descriptors, prints,
  sorts, allocates, uses a 256 KiB frame; a planted panic exits 125; the
  parent is intact; the clash check passes. *Fallback:* the `ld -r`/`objcopy`
  shim; if that fails too, stop condition 1.
- **P6, aarch64:** aarch64 builds of the spike, P4 and P5. *Fallback:*
  `-fno-emit-bin`.

**Result (2026-09-23, this host):** P1-P6 pass, no fallback used; the
answers and numbers are in Measured, the proofs in `spike/proofs/` (README
there; archived or moved to `tests/proofs/` in phase 2), the launcher and seccomp store paths unchanged. Still open for
Accept: the `workflow_dispatch` run.

**Accept:** every proof green in a `workflow_dispatch` run of the proof commit
on a branch; the answers and that run's numbers in Measured, in the commit
pushed to trunk; the outputs' store paths unchanged.

### Phase 1: the seccomp compiler

**Goal:** the first Zig on trunk; every filter byte-identical;
`flong-seccomp.c` gone. **Before:** the seccomp golden set.

- **Contents:** the package and every step but `integration` and
  `mountlib`; `seccomp/compile.zig`, a whole port of `flong-seccomp.c`
  (values through `num.strtoullBase0`, messages whole and byte-identical);
  `scmp.zig` (8 externs, `exportBpf`, `SCMP_ACT_ERRNO(x)` is `0x00050000 |
  (x & 0xffff)`); `sys`, `msg`, `errno`, `num`; `native.nix` with `seccomp`;
  the `native-*` and `cross-aarch64` checks (`golden` came with the
  characterization commit, run against the C); the devShell.
- **(a)** `checks.seccomp-transition`: the C (built in the check) and the Zig,
  `cmp`, stderr and status, over parity and strict with deny 1, 13, 38 and
  log, debug, nestedSandbox, an allow/deny variant, audit, tty, nsmask, and
  the refusal corpus. **(b)** Delete `flong-seccomp.c` and the check;
  DESIGN.md:1049, 1057.
- **Accept:** the transition check; parity (live equals built, counts 1550,
  26, 19, 49, DESIGN.md:1147-1150); rootless, basic; no Zig reference;
  `readelf -lW` shows no stack size in PT_GNU_STACK.

### Phase 2: the seccomp tooling

**Goal:** the awk and bash become subcommands producing the same text at build
and launch time; the cache behaves as before. **Before:** the tooling golden
set; the project-launch stderr subtest.

- **Contents:** `expand DUMP SPEC...`, `expand.awk` exactly (`:7-30`), sorted
  bytewise in place of `| LC_ALL=C sort` (`policy.nix:29-30`); `render DUMP
  NAMES DENY` (`policy.nix:81-108`, `@known` from DUMP, so `known` goes);
  `project DUMP NAMES DENY DIR < POLICY`, `policy.nix:141-206` in process
  (quirks 34-38; `mkdirat` 0700 for DIR's parent and DIR; the compile under
  `msg.prog = "flong-seccomp"`; on failure the temp file unlinked, exit 1).
  `policy.nix` calls `expand` and `render`; `module.nix:624-625` becomes `[
  "${compiler}/bin/flong-seccomp" "project" "${dump}" names deny ]`. `fd.zig`
  with `file` and `dir`, its tests, property, probes and planted bugs.
- **`spike/` moves to `~/Projects/flong-spikes-archive`** (as the rootless
  spikes did): P1 retires (the derivations subsume it), P6 too
  (`cross-aarch64`); P3 stays
  in `checks.native` (until phase 5, whose `proc:` subtests ask its
  questions of `src/proc.zig` and retire it); P2 and P5 move to `tests/proofs/` until phase 3's strace
  subtest and phase 4's clash check replace them; P4 becomes `abi.zig`, with
  its own struct copies until phase 4.
- **(a)** `checks.seccomp-tools-transition`, awk and bash against Zig over the
  live dump: names for every phase-1 tier variant; rendered text for 1, 13,
  38, log; a project corpus (groups, comments, blank lines, CR, no final
  newline, an unknown group, a deny of everything, each refusal) compared on
  the key (equal to `printf '%s\n%s' $seccomp "$policy" | sha256sum`), the
  `.bpf` bytes, stderr, status. The one-argument golden case is rewritten
  (quirk 16). **(b)** Delete `expand.awk`, the bash, `known`, the check;
  DESIGN.md:1060-1064.
- **Accept:** the transition check; `rootless.nix:976-1007`; the new
  subtest; parity; `analyze` clean, planted bugs caught. **Report:** the cold
  project compile time.

### Phase 3: flong-init

**Goal:** the first Zig in the launch path: static, no libc, the same bytes,
also under the filter stack. **Before:** the `ulimit -s` subtest, the init
golden cases, the payload-descriptor subtest.

- **Contents:** `init.zig` ports `flong-init.c` (argv checks `:86-148,
  179-193`, GROUPS counted against NGROUPS_MAX before parsing; checkpoint 9;
  argv reused; failures whole, 125); the panic, `std_options` and `noreturn
  main` pattern; `native.nix` gains `launcher` (Zig flong-init, `$CC` for the
  rest with `-DFLONG_INIT="$out/bin/flong-init"`).
- **(a)** A `checks.native` subtest, the C init built in the check: `strace
  -f` of both as pid 1 through bwrap under the strict stack with `log =
  true`, over tini's exec, a gate EOF (125), a failing chdir and an argv
  refusal (and TIOCSCTTY refused, which alone places the ioctl); per path
  the ordered syscalls from the first `setgroups` to `execve` or exit,
  arguments normalised, the C's `brk`/`mmap` left out and a message's
  writes one entry, are equal; the Zig writes each message once; neither
  leaves an audit record; the Zig makes no syscall between its `execve` and that
  `setgroups` (P2's check: the audit compare alone cannot see start code,
  measured). P2 goes. **(b)** Delete `flong-init.c`, the subtest;
  DESIGN.md:1379's row.
- **Accept:** rootless (the gate 731-751, no timeouts 622 and 1011, ^C 130
  under a pty and a pipe 957-961, TIOCSTI 944-955, log learning 963-976,
  `ulimit -s`); basic (groups 742-744, caps 874-893, chdir 689-693,
  1303-1308, clean stderr 728-732); `file`: static, no INTERP; a
  launcher-only edit leaves `seccomp`'s drv path unchanged. **Report:**
  bench, C against Zig; the two derivations' times.

### Phase 4: the mount helper, inside the C launcher

**Goal:** the riskiest module on trunk early, meeting the full VM suite inside
the working C launcher; `flong-mount.c` gone. **Before:** the mount-refusal
subtests; `probes` moves from rootless.nix to `tests/probes.nix`, imported by
rootless.nix and `tests/native.nix`, so the walker test has the swapper.

- **Contents:** `mount.zig`, one linear function in checkpoint 7's order:
  `openExact`/`openFollowing` with `.path` for binds and `.dir` for overlay
  lowers and `upper<i>`/`work<i>`; `walkOpen`, make, then reopen;
  `asPayload(job, f)` sets fsgid then fsuid, reads both back, runs `f`,
  restores 0:0, and reports a failed restore ahead of `f`'s error; sort by
  `std.mem.orderZ`. The shim, `mountlib`, the link and the clash check; the
  mount API in `sys.zig` (abi.zig drops its copies); the phase-4 kinds.
- **(a)** The shipped `flong-launch` links the library;
  `flong-launch-cmount` is built in the check. No module option: the subtest
  copies each generated wrapper it uses (`plain`, `mounts`, `esc`, `race`;
  the race runs the swapper through `plain`) and `sed`s its `launcher=` line
  (`module.nix:612`) to the check-only binary. Mount refusals, the declaration's mounts, the protect and symlink
  refusals and the swap race run under both: stderr and status equal, 0
  escapes. `checks.native` gains the walker. **(b)** Delete `flong-mount.c`,
  `mount_run`'s prototype, the C-only variant, P5, the subtest; DESIGN.md's
  `flong-mount` row.
- **Accept:** the full VM suite, in particular `rootless.nix:846-917` and
  `basic.nix:787-872, 1252-1411` (the overlays prove `dir` lowers); the
  walker; the layout check; the clash check on the real link.

### Phase 5: flong-sweeper, and the process layer complete

**Goal:** the holder's process is Zig, panic-free on any record, sweeping the
C launcher's records; `proc.zig` and `sig.zig` complete, so the branch does
not redesign shipped code. **Before:** the record-bytes subtest with
`tests/golden/records/`; the sweeper golden cases.

- **Contents:** `sweeper.zig` (`flong-sweeper.c:18-42`: no signalfd, so
  SIGTERM kills it); `record.zig`'s sweep half (`flong-record.c:46-89,
  268-320, 436-484, 527-604, 641-685, 755-825`: ELOOP skipped silently,
  blanking through a `selfPath` writable reopen, postStop's argv, envp,
  stdin, dir and cgroup as the C's); `cgroup.zig`'s sweep half
  (`flong-cgroup.c:419-488, 539-595`); `proc.zig` and `sig.zig` complete, the
  signalfd tested though the sweeper opens none; the mutation list;
  `names.zig`; the `cgroup`, `inotify`, `pidfd`, `pipe_w`, `signalfd` kinds.
- **(a)** The Zig sweeper installed; `golden` runs its cases against it and a
  C sweeper built in the check. **(b)** Delete `flong-sweeper.c` only.
- **Accept:** rootless (root refused 629-642, the sweeper after a SIGKILLed
  launcher 718-729, a launcher killed in its hook 731-751, ten concurrent cold
  launches with the sweeper stopped 781-810, a switch 1017-1025); basic
  (postStop 901-953, pasta released by the next sweep 1100-1126, SIGKILL
  1177-1184, a held lock never released 1186-1212); every mutation caught;
  the fuzz properties pass.

### Phase 6: the test fixtures

**Goal:** no C in `tests/`, proven equal before the branch relies on them.

- **Contents:** `bpfdump.zig` links libc and `scmp.zig`, which gains
  `seccomp_syscall_resolve_num_arch` (a malloc'd string, `bpfdump.c:293`) and
  `free` with their translate-c check; its own classic-BPF interpreter (std's
  mixes eBPF names); `ERRNO(NAME)` from `errno.zig` (`bpfdump.c:185-194`).
  `probe.zig` (no libc), `swapper.zig`, `ioctl_probe.zig`. `native.nix`
  gains `fixtures`, used by `tests/parity/default.nix` and `tests/probes.nix`.
- **(a)** Both versions: `bpfdump eval` text over the build's filters,
  `bpfdump dump` files on one payload, `syscall-probe` under both tiers,
  `ioctl-probe` for the rootless requests; identical. **(b)** Delete
  `bpfdump.c`, `probe.c`, the inline C, the subtests.
- **Accept:** parity and rootless green, the swap race included (901-917).
  **Report:** the fixtures derivation's time.

### Phase 7: the launcher, on the branch `zig-launch`

**Goal:** `flong-launch` is Zig and every suite is green; the C launcher, its
modules, the headers and the shim are deleted.

**How it runs.** L0 lands on trunk; the branch then opens with a draft PR.
L1-L3 are branch commits, each green in the PR's CI; the branch is rebased
after every trunk push, trunk changes to `launcher/*.c` ported before the next
milestone. Trunk owns `native.nix` and `build.zig`; the branch edits only a
delimited `// launcher (branch)` block of `build.zig` and
`tests/integration.nix`, and only L4 touches `native.nix`. L4 and L5, (a) and
(b), are fast-forwarded onto trunk when green; L1-L3 ride in L4's push, their
subjects saying the code is not yet built in.

- **L0 (trunk):** the tty, hook-descriptor and spec characterization tests.
- **L1, the spec.** `spec.zig` (`flong-spec.c:417-708`: two passes, then the
  cross checks; `refuseRoot` first; keep-fds by `F_GETFD` in the parse,
  `:656-667`). `launch.zig` passes `sys.argv()` to `spec.parse`, whose
  strings are slices of it, the command argv's tail (`:447-450`); arrays in
  the arena, sized by pass 1; `bwrapArgv`; the `paths.txt` tie. Spec golden
  cases run through `spec-probe` (refuseRoot, parse, exit as the launcher),
  built only by `tests/integration.nix`. **Accept:** `native-test`, `golden`.
- **L2, namespaces, cgroups, records, passwd.** `ns.zig`: U1 a fork, then
  newuidmap and newgidmap in parallel, both reaped before either is judged;
  U2 as checkpoint 4, the maps split along U1's extents; 125 and 127 silent
  (`flong-ns.c:28-40, 134-140`). `cgroup.zig`'s launch half (the last
  `/sys/fs/cgroup` mountinfo line wins; quirk 8; undo in reverse);
  `passwd.zig`; `record.zig`'s launch half (`create` with `sys.O_TMPFILE`
  only) and its writer test against `tests/golden/records/`. **Accept:**
  `checks.native` (maps, the U2 abort, an EINVAL limit leaving nothing, a
  created-then-closed record swept by the Zig sweeper, passwd against
  `getent` and the uid fallback), `native-test`.
- **L3, the terminal.** `tty.zig` ports `flong-tty.c` with the C's pty path
  (`/dev/ptmx`, `TIOCSPTLCK`, `TIOCGPTN`, the slave by path, `:174-186`),
  quirks 42-44, checkpoint 8, and `finish` infallible and idempotent in
  `:515-545`'s order; SIGTTOU scopes restore in a `defer`, `make_raw`
  deliberately does not ignore SIGTTOU (`:315-321`), restore paths ignore
  every errno. **Accept:** the pty tests, `cfmakeraw` against glibc, L0
  green, and a line-by-line review of `prepare` against `:59-80` (no test
  reaches the orphan refusal or SIGTTOU discarding).
- **L4 = (a), the launch.** `Launch` is a struct of optional handles, `Held`
  fields, `?Child`s and `gate_opened`; `main` is `proc.exit(teardown(&l,
  run(&l)))`; `run()` follows DESIGN.md's steps 1-19
  (`flong-launch.c:709-767, 847-928`) with checkpoints 1-6, `passFd` for U1,
  U2, info, the seccomp files, ready and gate, the mount helper as a fork
  body in the sandbox leaf keeping `{u1, ready_r, leader}`, quirk 3's envp,
  pasta with a memfd (`:637-644`). `native.nix` builds the Zig launcher;
  `flong-launch-c` (the C with the Zig mount library) is built in the check.
  The spec golden cases switch to `flong-launch`; `spec-probe` is deleted.
  The rootless transition subtest, with phase 4's wrapper copies, runs warm
  launches with a sleeping hook under each launcher (plain; relay through
  `script`; nestedSandbox; a project `seccompPolicy`; hostPorts and
  forwardPorts with the resolv.conf keep-fd; trace; `pasta-wait`) and diffs
  bwrap's and pasta's `/proc/<pid>/cmdline`, flong-init's argv tail and each
  child's `/proc/<pid>/environ`, pids and descriptors normalised.
  **Accept:** every suite (L0 included); a clean launch's stderr empty;
  outputs static and stripped, `disallowedReferences` holding,
  `cross-aarch64` building. **Report:** bench, the trunk parent against Zig.
- **L5 = (b).** Delete `launcher/*.c`, `launcher/*.h`, `src/hybrid/`,
  `adoptForeign`, `mountlib`, `flong-launch-c`, the subtest. **Accept:** every
  check green.

### Phase 8: documentation and baggage

- **DESIGN.md:** rewrite "The native launcher" (1351-1414): the build, the
  module table, the conventions (errors as values, one cleanup path, handles
  and `Held`, `noreturn` fork bodies, signals, panics, the lint), the kernel
  floor, 1359-1361's "C, not Zig" replaced by what the port measured; the
  launch table's call column (1496-1516); 21, 55, 479; 1147-1150; quirk 10's
  stall; `golden-update`'s rule. **README:** 379; 161-164 gains the kernel
  floor, checked against the kernel source (which makes `module.nix:973-974`
  true). **module.nix** comments 124-126, 136-137; `ci.yml:25` gets the
  measured time. **Delete this file.**
- **Accept:** `grep -rn 'runCommandCC\|gnu11\|expand\.awk\|\.c\b'` over
  DESIGN.md, README.md, flake.nix, module.nix, `seccomp/`, `launcher/`,
  `tests/` finds nothing stale; `nix flake check` green.

## Stop conditions and rollback

**Stop, report and wait for the user** when:

1. A Phase 0 proof fails and its fallback would change a user decision (P5
   and its fallback failing: the recommendation would be to move the mount
   helper to the branch as a milestone gated by `checks.native`).
2. The seccomp transition finds a byte difference that is not a Zig bug (the
   same libseccomp calls in the same order), or the fix would change which
   policies are accepted.
3. Any swap-race escape, or a symlink or protected-path refusal the C makes
   and the Zig does not after one fix attempt.
4. A test-asserted string, an exit code or a VM assertion would have to
   change, other than as a Change quirk lists.
5. A kept quirk turns out impossible to keep.
6. A red VM run whose cause is not found, or that fails the same way on the
   parent. Nothing is re-run blind or retried away.
7. The shim needs shipped C changes beyond the call line and its declaration.
8. A released phase misbehaves for the user.
9. After a `flake.lock` bump, `bpfdump eval`'s text over the golden filters
   differs between old and new bytes: libseccomp changed what a policy means.

**Fix and continue** otherwise: compile, lint, fmt and analyze findings; a
transition or golden diff traced to the Zig; unit, property and ABI failures;
a fetchDeps hash mismatch; a `flake.lock` bump that changes only libseccomp's
`.bpf` bytes with `eval` text equal (`golden-update`, its own commit); a flaky
run whose cause is found and fixed; CI time growth (reported only).

**Rollback.** Users pin their flake input to the previous release (every
green trunk push is tagged, `ci.yml:63-70`). Before (b) lands, `git revert`
of (a) restores the C. After (b), before the next phase touches the same
files: revert (b), then (a). After a later phase has built on it: fix
forward; a revert chain, one phase at a time and each pushed green, only for
a security fault (seccomp bytes, a mount escape, the gate). Record bytes are
the same on both sides, so any rollback leaves every session sweepable.

## Open decisions

1. **Fixes after the port**, each its own commit with a test, once L5 is on
   trunk: the malformed-record refusal (quirk 5; recommended: treat a dropped
   record as released so `rec_create` retries); `limit io.weight` (quirk 12;
   recommended: keep until module.nix emits it or drops it with
   DESIGN.md:1450's row); pseudo-number duplicates (quirk 13; recommended:
   keep, since no repo policy has one); the `^]` stall (quirk 10;
   recommended: poll stdin while input is buffered).
2. **Sweeper resilience.** A sweeper failure stops the holder and every
   session (`module.nix:936-941`); the port relies on panic-freedom.
   Alternative: sweep in a forked child. Recommended: keep.
3. **When nixpkgs drops `zig_0_15`:** port to the next Zig in one commit, or
   add a second nixpkgs input. Recommended: port forward, alongside capsper
   and zerocast.
