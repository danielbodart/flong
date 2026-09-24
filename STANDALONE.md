# Plan: one `flong` binary, ZON declarations, no bash wrapper

This plan starts after [ZIG.md](ZIG.md) lands, meaning its L5 and phase 8
are done. Its goals, in order:

1. **One binary for the libc-free programs.** `flong-launch`, `flong-init`
   and `flong-sweeper` become subcommands of one static binary, `flong`,
   which has no libc. The seccomp compiler stays a separate binary,
   `flong-seccomp`.
2. **Declarations in ZON.** A declaration is a typed Zig struct, and each
   field carries its description as a doc comment. The NixOS module
   renders each declaration to a `.zon` file, the way capsper's module
   does (`../capsper/nix/to-zon.nix`). flong validates that file with the
   same parser at build time and at launch.
3. **No bash wrapper.** `flong launch DECL.zon -- ARGS` works out what only
   the launch can know. That is the work `rootless-wrapper.bash` does
   today, and the file is deleted.
4. **Usable outside Nix, eventually.** When the configuration is in ZON and
   the logic is in Zig, flong can ship as a native binary with a
   documented config file. Nix stays the first-class way to use flong, and
   nothing here may make the Nix path worse.

This file is deleted when the plan lands, and what it establishes moves
into DESIGN.md and the README. *Inferred* means nothing has checked it
yet; the phase that checks it is named.

## Decided

The user decided these on 2026-09-24:

- **The libc-free programs merge; the compiler stays separate.**
  `flong-seccomp` links glibc for libseccomp (ZIG.md, "Decided": keep
  libseccomp, byte-identical BPF). Merging it would put libc start code
  into every sandbox's pid 1, which undoes P2's "no syscall before `main`"
  (ZIG.md, Measured). It would also move the project cache key on every
  launcher edit: that key hashes the compiler's store path (ZIG.md, quirk
  36).
- **ZON is the declaration format**, following capsper. The schema lives in
  the type; an unknown field or a wrong type is a parse error with a line
  number. Each field's doc comment is its only description.
- **Removing the bash wrapper is the goal**, not an option.
- **A native release outside Nix is a later goal**, and it shapes the
  choices made now: the config file is documented, and `--help`, messages
  and paths assume no Nix store.

## Why

- **Two validators today.** Nix `assertions` (`module.nix:676`,
  `assertionsFor`) and the launcher's spec checks (`src/spec.zig`) judge
  many of the same things. `tests/golden/paths.txt` exists to keep them in
  step (ZIG.md, "Mirrors of the spec in Nix"). One parser, run at build
  time by `flong check`, replaces the Nix mirror.
- **Three languages on the launch path.** Nix renders a header,
  `rootless-wrapper.bash` (457 lines) computes the runtime facts, and Zig
  checks the spec as argv. The argv spec, keywords such as `mount`,
  `uidmap`, `post-start` and `keep-fd` (`rootless-wrapper.bash:376-455`),
  is an interface that exists only because the wrapper is bash.
- **Descriptions in one place.** capsper writes each setting's prose once,
  as a doc comment (`../capsper/src/shared/config_docs.zig`). The same text
  then feeds `--help`, `--write-config` and the docs. flong's 34 module
  options carry their prose in `module.nix`, which a native release could
  not reuse.

## The target

### The binary

- **`flong`** is static, has no libc and is stripped, with the settings
  every root has today (ZIG.md, "Per binary").
  - Subcommands: `launch`, `init`, `sweeper`, `check`, `version`, `help`.
  - The test fixtures that need no libc (`syscall-probe`, `swapper`,
    `ioctl-probe`) become hidden subcommands only if that simplifies
    `tests/probes.nix`.
  - Dispatch works on both `argv[0]`'s basename and the first argument.
  - The old names (`flong-launch`, `flong-init`, `flong-sweeper`) stay as
    symlinks to `flong`, so nothing that calls them changes in phase S1.
  - Dispatch is the first thing in `main` and makes no syscall, so P2's
    property holds; the strace check in `tests/native.nix` confirms it.
- **`flong init`** keeps reusing the kernel's argv slots for tini's argv
  (ZIG.md, "Allocation"). Invoked as `flong-init`, the slot indices are
  unchanged. Invoked as `flong init`, every index shifts by one, and a unit
  test pins both forms.
- **Message prefixes** (`flong-launch: …`, `flong-init: …`,
  `flong-sweeper: …`) are asserted by the VM and golden tests. S1 keeps
  them; renaming them to `flong launch: …` is open decision 1.
- **`flong-seccomp`** stays as it is: glibc, libseccomp, subcommands
  `expand`, `render` and `project`. Its store path moves only with its own
  sources, so project caches survive flong updates.

### The declaration

- **The schema.** `src/decl.zig` defines `Declaration`, one struct whose
  fields mirror the static half of a declaration. Every field carries a
  doc comment, and a missing one is a compile error, as in capsper. The
  static half is what `module.nix` renders into the wrapper's header today
  (`rootless-wrapper.bash:1-9`):
  - identity: name, container, user;
  - the closure: closure, cuid, cgid, closure8, steps8, static;
  - declared destinations and binds, masks and mask hosts;
  - network and DNS forwarding;
  - hooks, snippets, seccomp tier and filters, limits.
- **Rendering.** `module.nix` renders each declaration with a
  `to-zon.nix` like capsper's (`../capsper/nix/to-zon.nix`). Enums are
  named by path, and a build-time check catches drift between the two
  schemas.
- **`flong check DECL.zon`** runs in the declaration's derivation, so a bad
  declaration fails `nixos-rebuild` with a line number.
  - It covers everything the launcher can judge without the caller: paths,
    overlaps, duplicate destinations and modes.
  - The module assertions that duplicate it, and `tests/golden/paths.txt`,
    go.
  - Assertions about NixOS itself (a container exists, a user exists)
    stay in Nix.
- **Descriptions.** The option descriptions in `module.nix` are generated
  from the doc comments where the option maps one-to-one to a field; this
  is open decision 3.
- **The trust boundary does not move.** Any caller can run `flong launch`
  with any file, just as it can run `flong-launch` with any spec today
  (`module.nix:958`). The parser is therefore a boundary:
  - its allocation is bounded;
  - every parse error is a refusal, never a panic;
  - it is fuzzed with a checked-in corpus, as the record parser is.

### `flong launch DECL.zon -- ARGS`

It does what each section of `rootless-wrapper.bash` does, in the same
order, and then calls the spec builder in-process. There is no argv spec
and no exec.

| wrapper section | what moves into Zig |
|---|---|
| the caller (`:52`) | uid, gids, the passwd name for newuidmap (`passwd.zig` exists) |
| the runtime directory (`:72`) | `/run/user/$UID`, ownership refusal |
| the workspace (`:84`) | `canon` without a fork, `refuse_path`, the `pwd` snippet |
| the caller's binds (`:138`) | the binds snippet, merge and mode rules |
| the guard (`:182`) | runs the guard snippet as the caller |
| the project's seccomp policy (`:190`) | runs the snippet, hashes the policy, runs `flong-seccomp project` on a cache miss |
| the depth rule (`:210`) | the mask depth check for writable binds |
| the maps (`:234`) | `/etc/subuid` and `/etc/subgid`, U1 and U2 extents |
| the prepared root (`:277`) | the cache lock, and calling the prepare tool (see open decision 4) |
| the payload's identity (`:330`) | reading the prepared root's passwd and group |
| `$home/tmp` (`:362`) | the tmpfs mount |
| the spec (`:376`) | built as a value and handed to the launch, never rendered as argv |

- **Snippets.** The guard, `pwd`, binds and project-policy snippets are
  shell text the user writes, and they stay shell. `flong launch` runs
  each one through a shell named in the declaration: the store's bash
  under Nix, `/bin/sh` or a configured path outside Nix. Only the glue
  goes, not the user's shell code.
- **The warm path.** Today it runs bash builtins only, which is the reason
  for the wrapper's style (`rootless-wrapper.bash:11-14`). The Zig warm
  path must fork nothing a declaration did not ask for. Phase S3 reports
  its time against the wrapper's with `nix build .#bench`; the figure is
  reported, never gated.
- **The relaunch** (quirk 2) re-execs `flong launch` with the same
  arguments, and no longer the wrapper.

### Outside Nix (S5, later)

What a native release needs that Nix supplies today:

- **Paths compiled in.** `-Dbwrap`, `-Dpasta`, `-Dtini`, `-Dnewuidmap` and
  `-Dnewgidmap` (ZIG.md, "build.zig") become optional fields in the
  config. A missing one is looked up on `PATH` at `check` time, never
  silently at launch.
- **The root.** Today a session's root is a NixOS container closure plus
  a prepared root (`module.nix:301-401`: `prepareInner`, `cacheTool`).
  Outside Nix, a root must come from somewhere else: a directory, an
  image, or the host read-only. This is open decision 5, and it is the
  real work of S5.
- **The sweeper's unit.** A documented systemd user unit
  (`flong sweeper %t/flong`), as `module.nix:1002` declares one.
- **Seccomp.** `flong-seccomp` could ship static against musl and a
  static libseccomp. It is not pid 1, so libc start code is acceptable
  there. The BPF golden files (`tests/golden/seccomp/*.bpf`) prove the
  bytes are unchanged.
- **Release artifacts.** CI builds `flong` and `flong-seccomp` for x86_64
  and aarch64 (ZIG.md already cross-builds them) and attaches them to the
  release that each trunk push publishes (`.github/workflows/ci.yml`).

## Phases

The same pattern as ZIG.md, on trunk only:
- characterization tests land first;
- each phase is one or more commits, each through `nix run .#gate`, each
  pushed as a fast-forward;
- where behaviour could change, a transition check compares old and new;
- a later commit deletes the old side;
- no branch and no force push, ever.

- **S1, one binary.** `flong` with subcommands and the old names as
  symlinks. module.nix, the wrapper and the tests are unchanged.
  - Accept: every check green; the strace check shows dispatch adds no
    syscall before the first one `main` makes; the size of `flong`
    against the three binaries' sum (reported).
- **S2, the declaration.** `src/decl.zig`, `to-zon.nix`, and
  `flong check` in each declaration's derivation. The duplicated module
  assertions and `tests/golden/paths.txt` go.
  - Characterization first: every refusal the Nix assertions make today
    gets a golden case, so the move can be checked refusal by refusal.
- **S3, no wrapper.** `flong launch DECL.zon`.
  - Transition: the Zig builds the spec as a value; for the transition
    only, it also renders that spec as argv. The check diffs it against
    the argv the bash wrapper builds, over every declaration in the tests
    and every caller-side snippet outcome, with pids and paths
    normalised.
  - Then delete `rootless-wrapper.bash`, the argv spec keywords and the
    spec's argv parser (`src/spec.zig` keeps its checks, run over the
    value).
- **S4, descriptions in one place.** `flong help`, `flong help decl`, and
  generated option descriptions (open decision 3).
- **S5, outside Nix.** Open decisions 4 and 5 first; then the release
  artifacts and a README section on using flong without Nix.

## Constraints kept from ZIG.md

- **Every ordering checkpoint** (ZIG.md, "Ordering checkpoints") still
  holds in the linear functions it names. `flong launch` adds its own
  linear prologue ahead of checkpoint 1, for the wrapper's order above.
- **Asserted strings and exit codes stay as they are** unless an open
  decision below changes them in its own commit with its tests.
- **The project cache key stays sha256 of `flong-seccomp`'s store path**
  plus the policy (quirk 36).
- **Every test the wrapper passes today passes against `flong launch`.**
  That includes the rootless and basic VM subtests, which call the
  generated wrappers by name. Those names become small launchers (open
  decision 2).

## Open decisions

1. **Message prefixes.** Keep `flong-launch: …` and the others forever, or
   rename them to `flong launch: …` in one commit that updates every
   asserted string. Recommended: rename in S1's last commit, since nothing
   outside the tests parses them.
2. **What a declaration's command is.** Today each declaration is a
   generated bash script on `PATH`. After S3 it could be:
   - (a) a symlink to `flong`, finding its `.zon` from `argv[0]`;
   - (b) a two-line script, `exec flong launch /nix/store/…-NAME.zon -- "$@"`;
   - (c) a tiny generated ELF.

   Recommended: (b) for its transparency. The declaration stays readable
   with `cat`, and the exec adds almost nothing (inferred; S3 measures
   it).
3. **Generated NixOS option descriptions.** Generate them from the doc
   comments, or keep module.nix's prose and check the two agree in a
   test. Recommended: generate them where an option maps one-to-one to a
   field, and write by hand the Nix-only options (`containers`, `users`).
4. **The prepared root and the cache tool** (`prepareInner`, `cacheTool`,
   `module.nix:311-401`) are bash and stay bash under ZIG.md. Should
   `flong launch` call them as it does today, or should they move into Zig
   with S3 or later? Recommended: call them unchanged in S3, and decide
   again in S5, where a non-Nix root changes what "prepare" means.
5. **A session's root outside Nix:** a directory, an OCI or plain image,
   or the host read-only. It decides S5's scope; spike it first.
