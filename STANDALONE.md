# Plan: one `flong` binary, ZON declarations, no bash wrapper

This plan starts where the Zig port ended: every native program is Zig, and
what the port established is DESIGN.md's [The native
launcher](DESIGN.md#the-native-launcher). Its goals, in order:

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
  `flong-seccomp` links glibc for libseccomp (DESIGN.md, "Why Zig, and what
  it cost": keep libseccomp, byte-identical BPF). Merging it would put libc start code
  into every sandbox's pid 1, which undoes "no syscall before `main`"
  (DESIGN.md, "What the port measured": start code). It would also move the project cache key on every
  launcher edit: that key hashes the compiler's store path (DESIGN.md, "Kept
  behaviour", quirk 36).
- **ZON is the declaration format**, following capsper. The schema lives in
  the type; an unknown field or a wrong type is a parse error with a line
  number. Each field's doc comment is its only description.
- **Removing the bash wrapper is the goal**, not an option.
- **A native release outside Nix is a later goal**, and it shapes the
  choices made now: the config file is documented, and `--help`, messages
  and paths assume no Nix store.
- **No compatibility layer.** flong's only consumers are ours: chase,
  frisket and nix-config. Every change here updates module.nix, the tests
  and those consumers together. There are no old-name symlinks, no shim
  scripts and no translated fields. Anything left on an old interface
  should fail loudly, so that it gets fixed rather than carried.
- **Snippets become commands.** The guard, `pwd`, binds and project-policy
  snippets, and the hooks, are shell text that flong runs today. In ZON
  each one is a command: a program path and its argv. flong runs no shell
  of its own, and a consumer that wants shell writes
  `pkgs.writeShellScript`.
  - chase uses guard, binds, seccompPolicy, postStart and postStop.
  - frisket uses guard, postStart and postStop.
  - Both migrate in the same change.
- **One source for every description: the Zig doc comment.** A build step
  walks `Declaration`'s fields, the way capsper's `config_docs.zig` does.
  For each one it emits the type, the default, the doc comment and the
  merge kind into a checked-in file. module.nix builds its typed options
  from that file. Only the Nix-only options (containers, users, enable)
  keep hand-written prose. Details are under "The declaration".

## Why

- **Two validators today.** Nix `assertions` (`module.nix:676`,
  `assertionsFor`) and the launcher's spec checks (`src/spec.zig`) judge
  many of the same things. `tests/golden/paths.txt` exists to keep them in
  step (DESIGN.md, "Tests": mirrors of the spec in Nix). One parser, run at build
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
  every root has today (DESIGN.md, "Conventions").
  - Subcommands: `launch`, `init`, `sweeper`, `check`, `version`, `help`.
  - The test fixtures that need no libc (`syscall-probe`, `swapper`,
    `ioctl-probe`) become hidden subcommands only if that simplifies
    `tests/probes.nix`.
  - Dispatch uses `argv[0]`'s basename first, then the first argument,
    as busybox does. A basename that is not a subcommand is a declaration
    name (see "The declaration's command").
  - The old names (`flong-launch`, `flong-init`, `flong-sweeper`) are
    gone in S1, and module.nix, the wrapper, the tests and the consumers
    call `flong <sub>` in the same change.
  - Dispatch is the first thing in `main` and makes no syscall, so P2's
    property holds; the strace check in `tests/native.nix` confirms it.
- **`flong init`** keeps reusing the kernel's argv slots for tini's argv
  (DESIGN.md, "Conventions": allocation). The slot indices shift by one for the
  subcommand word, and a unit test pins them.
- **Message prefixes** become `flong launch: …`, `flong init: …` and
  `flong sweeper: …` in S1. The same commit updates every asserted string
  in the VM and golden tests.
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
- **Generated options.** `flong schema` walks `Declaration` at comptime
  and prints one entry per field.
  - Each entry holds: its path, its type (and its enum tags), its default,
    its doc comment, and its merge kind. Hooks and other ordered
    sequences merge as ordered lists, so chase's `lib.mkOrder` and
    frisket's `lib.mkMerge` and `lib.mkAfter` keep working. Everything
    else is a single value.
  - The output is checked in as `decl-options.json`.
  - module.nix builds its typed options from that file with
    `builtins.fromJSON`: no import from a derivation, and the NixOS
    manual, `nixos-option` and type errors keep working.
  - A check fails when the file is stale, and `nix run .#update-options`
    regenerates it.
  - A field without a doc comment is a compile error, as in capsper.
  - The same walk produces `flong help decl` and the reference page for
    non-Nix users.
- **The trust boundary does not move.** Any caller can run `flong launch`
  with any file, just as it can run `flong-launch` with any spec today
  (`module.nix:958`). The parser is therefore a boundary:
  - its allocation is bounded;
  - every parse error is a refusal, never a panic;
  - it is fuzzed with a checked-in corpus, as the record parser is.

### The declaration's command

The user decided this on 2026-09-24: each declaration is a symlink
`NAME -> flong` on `PATH`, with no script.
- **The lookup.** flong reads `argv[0]`'s basename, which is the name the
  caller typed, because the shell passes it through exec. That name is not
  a subcommand, so flong loads `/etc/flong/NAME.zon`. The module writes
  that file through `environment.etc`; outside Nix it would be
  `$XDG_CONFIG_HOME/flong/NAME.zon`.
  - The lookup order (decided in S3): `/etc/flong` first, then
    `$XDG_CONFIG_HOME/flong` (`$HOME/.config/flong` when it is unset or
    not absolute). The system's first, so a declaration the system
    installs is the one its name runs, whatever the caller's
    configuration holds; `flong list` shows each name once, as it runs.
    A missing one names every path looked for.
  - The fixed directory, rather than a file beside the symlink in the same
    store path, keeps the lookup obvious: `ls /etc/flong` lists every
    declaration, and no chain of symlinks has to be followed.
  - Resolving by name moves no trust boundary. A caller can run
    `flong launch` with any file anyway.
- **Making it obvious:**
  - `flong launch NAME -- ARGS` is exactly what the symlink does, and the
    docs describe the symlink in those terms.
  - `flong list` prints each declaration and its config path.
  - A missing declaration says so and names the path it looked in:
    `flong: no declaration "agent" (looked for /etc/flong/agent.zon)`.
  - `ls -l $(command -v agent)` shows `agent -> …/flong`.

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
| the prepared root (`:277`) | the cache lock, and calling the prepare tool (see "Direction") |
| the payload's identity (`:330`) | reading the prepared root's passwd and group |
| `$home/tmp` (`:362`) | the tmpfs mount |
| the spec (`:376`) | built as a value and handed to the launch, never rendered as argv |

- **Commands, not snippets.** `flong launch` runs the guard, `pwd`,
  binds and project-policy commands as the caller, with argv and a
  documented environment. Their output formats are the ones the snippets
  print today (`rootless-wrapper.bash:118-209`). flong runs no shell of
  its own.
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
  `-Dnewgidmap` (DESIGN.md, "The native launcher") become optional fields in the
  config. A missing one is looked up on `PATH` at `check` time, never
  silently at launch.
- **The root.** Today a session's root is a NixOS container closure plus
  a prepared root (`module.nix:301-401`: `prepareInner`, `cacheTool`).
  Outside Nix, a root must come from somewhere else: a directory, an
  image, or the host read-only. It is decided only if a release outside
  Nix is actually pursued, by whoever that release is for. The user's
  current lean is a directory.
- **The sweeper's unit.** A documented systemd user unit
  (`flong sweeper %t/flong`), as `module.nix:1002` declares one.
- **Seccomp.** `flong-seccomp` could ship static against musl and a
  static libseccomp. It is not pid 1, so libc start code is acceptable
  there. The BPF golden files (`tests/golden/seccomp/*.bpf`) prove the
  bytes are unchanged.
- **Release artifacts.** CI builds `flong` and `flong-seccomp` for x86_64
  and aarch64 (`cross-aarch64` already cross-builds them) and attaches them to the
  release that each trunk push publishes (`.github/workflows/ci.yml`).

## Phases

The same pattern as the Zig port (its plan, ZIG.md, is in git at
e717355), on trunk only:
- characterization tests land first;
- each phase is one or more commits, each through `nix run .#gate`, each
  pushed as a fast-forward;
- where behaviour could change, a transition check compares old and new;
- a later commit deletes the old side;
- no branch and no force push, ever.

- **S1, one binary.** `flong` with subcommands and the new message
  prefixes. module.nix, the wrapper, the tests, chase and frisket switch
  to `flong <sub>` in the same change.
  - Accept: every check green, plus the consumers' own checks; the strace
    check shows dispatch adds no syscall before the first one `main`
    makes; the size of `flong` against the three binaries' sum
    (reported).
- **S2, the declaration.** `src/decl.zig`, `flong schema` and
  `decl-options.json`, and the module's options built from it.
  `to-zon.nix`, and `flong check` in each declaration's derivation. The
  snippets become commands, and chase and frisket migrate in the same
  change. The duplicated module assertions and `tests/golden/paths.txt`
  go.
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
  - Landed first: `flong launch DECL.zon|NAME`, the links, `flong list`,
    `src/launch/assemble.zig` (the wrapper's order, one function),
    `spec.validate`, the typed environment, hostname and resolver; the
    transition's `--dump-argv`, the wrapper's `FLONG_DUMP_SPEC` and
    `tests/transition.nix`. `path` reaches the caller's commands as the
    declaration's computed `commandPath`, and the hooks through
    module.nix's hook programs, `postStartProgram` and `postStopProgram`,
    which stay until the sweeper can put `path` on `PATH` itself. The
    deletion commit takes the wrapper, `transitionWrapper`,
    `argv_render.zig`, `--dump-argv`, `tests/transition.nix`, the argv
    spec (parse, its keywords, `bwrap_args`, `keep_fds`, `relaunch`, and
    `launch.zig`'s guess between the two) and the spec's golden cases.
- **S4, the reference.** `flong help`, `flong help decl`, and a generated
  reference page for the declaration, from the same walk as
  `decl-options.json`.
- **S5, outside Nix.** Only if pursued: decide the root first; then the release
  artifacts and a README section on using flong without Nix.

## Constraints kept from the Zig port

- **Every ordering checkpoint** (DESIGN.md, "The ordering checkpoints") still
  holds in the linear functions it names. `flong launch` adds its own
  linear prologue ahead of checkpoint 1, for the wrapper's order above.
- **Asserted strings and exit codes stay as they are**, except the
  message prefixes S1 renames, in a commit that updates their tests.
- **The project cache key stays sha256 of `flong-seccomp`'s store path**
  plus the policy (quirk 36).
- **Every test the wrapper passes today passes against `flong launch`.**
  That includes the rootless and basic VM subtests, which call the
  generated wrappers by name. Those names become the per-declaration
  commands (see "The declaration's command").

## Direction, not yet a decision

- **More of the tooling moves into Zig over time.** The prepared root and
  the cache tool (`prepareInner`, `cacheTool`, `module.nix:311-401`) are
  bash, and S3 calls them unchanged. The direction is that the fiddly
  parts, the ones that are easy to get wrong and nobody should need to
  edit, move into the binary as typed code. Each move is its own
  decision, made when it is due; nothing here makes one.
- **A session's root outside Nix** is parked with S5 (see "Outside Nix").
