# The integrated launcher: contract for phase 1

A working document for [ROOTLESS.md](../ROOTLESS.md)'s phase 1. It fixes the
file layout, each module's interface and the launcher's input, so the modules
can be written in parallel. It is folded into DESIGN.md later. ROOTLESS.md
stays the authority on *what* the engine does; this file says *where* each
part of it lives and *how* the parts meet. Where the two disagree, the
difference is listed under "Choices this contract makes", with its reason.

The headers in this directory are part of the contract. Each declaration's
comment is its specification: what it does, when it is called and how it
fails. This file does not repeat them; it covers what sits between them.

## 1. File layout

| file | owns |
|---|---|
| `flong-util.h` / `.c` | messages, trace, descriptors, `fl_await`, `fl_spawn` (clone3), `fl_fork`, pidfds, starttime, small file I/O |
| `flong-spec.h` / `.c` | the input contract: argv tokens into `struct fl_spec`, and every check that needs nothing but the spec |
| `flong-ns.h` / `.c` | U1 (newuidmap and newgidmap in parallel) and U2 (split maps, `max_user_namespaces`) |
| `flong-cgroup.h` / `.c` | nsdelegate check, finding or starting the holder, the session cgroup and its leaves, limits, kill, wait, remove |
| `flong-record.h` / `.c` | the state directory, the cache lock, records, liveness, the sweep, postStop, the sweeper's loop |
| `flong-mount.h` / `.c` | the mount helper: sources, the fd walker, masks, overlays, `/sys`, `/run` read-only |
| `flong-tty.h` / `.c` | the foreground wait, pty relay or passthrough, raw mode, the watchdog, `^]^]^]`, the wait for bwrap |
| `flong-launch.c` | `main`: the order of a launch, bwrap's argv, the hook, pasta, the gate, the one teardown path, exit codes |
| `flong-sweeper.c` | `main` of the holder unit's process: `state_open`, `cg_holder_self`, `rec_watch` |
| `flong-init.c` | pid 1 in the session: groups, capabilities, controlling tty, ready byte, the gate, chdir, exec tini. Self-contained: it links nothing else |
| `default.nix` | `runCommandCC` building the three programs; the store paths they run are compiled in |
| `test/` | the hand-written test wrapper and its helpers (section 10) |

Dependencies point one way, so a module can be written against the headers
below it and nothing above:

```
flong-util ← flong-spec (types only) ← flong-ns
                                     ← flong-cgroup ← flong-record
                                     ← flong-mount
                                     ← flong-tty (util only)
flong-launch.c   uses all of them
flong-sweeper.c  uses util, cgroup, record
flong-init.c     uses none
```

The headers are frozen for the parallel phase. A module that needs something
another module does not declare says so to whoever coordinates; it does not
add a private copy.

**Building.** `nix-build launcher` builds `flong-launch`, `flong-sweeper` and
`flong-init` with `-std=gnu11 -O2 -D_GNU_SOURCE -Wall -Wextra -Werror` and
these compiled-in strings: `FLONG_BWRAP`, `FLONG_PASTA`, `FLONG_TINI`,
`FLONG_INIT` (store paths) and `FLONG_NEWUIDMAP`, `FLONG_NEWGIDMAP`
(`/run/wrappers/bin/...`). A module is checked on its own with

```
cc -std=gnu11 -O2 -D_GNU_SOURCE -Wall -Wextra -Werror \
   -DFLONG_BWRAP='"x"' -DFLONG_PASTA='"x"' -DFLONG_TINI='"x"' -DFLONG_INIT='"x"' \
   -DFLONG_NEWUIDMAP='"x"' -DFLONG_NEWGIDMAP='"x"' -c flong-mount.c -o /dev/null
```

The nix build compiles with fortify: an unchecked `write`, `read` or
`fscanf` is a warning, so an error.

## 2. Conventions

- **Errors.** A function that can fail prints why, once, where it failed,
  and returns -1. Its caller unwinds without printing again. Messages are
  `flong-launch: <what>: <strerror>` (`fl_err`) or a refusal in plain words
  (`fl_errx`), in the user's terms: "a symlink is on the way to /srv/x",
  "no user manager for alice: set users.users.alice.linger = true".
- **One cleanup path.** `flong-launch.c` keeps every resource in one
  `struct launch`, each descriptor initialised to -1 and each pid to 0.
  `main` is `rc = run(&l); return teardown(&l, rc);`. `run` returns at the
  first failure; `teardown` looks at what exists and undoes it, whatever stage
  was reached. Modules undo their own partial work before returning -1, so the
  launcher never sees half a resource.
- **Forked helpers exit, never return.** `fl_die` exists for them only.
- **No timeouts, no retry caps.** Every wait is `fl_await` on a pipe, a pidfd
  or `cgroup.events` (POLLPRI), a held `flock` (the cache's shared one and a
  record's exclusive one, both through `fl_lock_wait`, whose helper takes the
  lock so the wait is a pidfd and a terminating signal ends it), or
  `poll(-1)` in `tty_wait` and the sweeper. No `nanosleep`, no poll count, no
  `poll` timeout other than -1, no `WNOHANG` loop. Grep for them before handing a module
  over. The one clock read is the `^]^]^]` check, which waits for nothing.
- **Descriptors.** Everything is opened `O_CLOEXEC`. Every program is started
  with `fl_spawn`, which closes everything not named in `keep`. Every helper is
  forked with `fl_fork`, which closes everything not named in `keep` at once,
  because a fork keeps descriptors whatever their flags: a helper holding the
  record's lock keeps a dead session alive for the sweep, and a watchdog
  holding the pty master keeps the session's terminal from hanging up.
- **Signals.** `main` blocks SIGTERM, SIGHUP, SIGINT, SIGQUIT, SIGWINCH and
  SIGCONT first thing and reads them from `fl_sigfd`; SIGPIPE is ignored.
  SIGCHLD is reset to its default, in `flong-sweeper` too: an ignored SIGCHLD
  survives `execve`, the kernel then reaps children itself, and `waitid` says
  ECHILD. `fl_reap` treats ECHILD as the error it is, so a helper's, a hook's
  or pasta's lost status fails the launch instead of opening the gate.
  Before the gate a terminating signal aborts the launch (`fl_abort_signal`);
  after it, `tty_wait` forwards it to the leader. `tty_wait` never blocks in
  a write: the relay's output goes to the caller's terminal through a
  descriptor of its own, opened again non-blocking (fd 1 itself when the
  terminal cannot be opened), and only when poll reports it writable, so a
  terminal that stops draining never holds a signal or `^]^]^]` back.
- **No root.** Nothing runs as host root, nothing asks for it, and the
  launcher and the sweeper refuse a caller of uid 0 (`fl_refuse_root`),
  and the launcher refuses a map that reaches host id 0.
- **Style.** C as the repo writes prose: comments are plain declarative
  sentences that say why. No dead code: no test-only knob, no variant kept
  for comparison, no fallback that nothing reaches.

## 3. The input contract

The wrapper runs `flong-launch` with the whole spec as its arguments: a
sequence of keywords, each followed by a fixed number of fields, then `--`
and the payload's command. Arguments are NUL-terminated strings, so a path
may hold a tab or a newline; bash builds the list with builtins alone (an
array and `exec`). Keywords come in any order; repeatable ones accumulate in
the order given.

`R` required, `1` at most once, `*` repeatable.

| keyword and fields | | meaning |
|---|---|---|
| `machine NAME` | R | the session's name: record, leaf cgroup, `$machine`. `[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}` |
| `container NAME` | R | the cgroup level between the holder and its sessions; same charset |
| `state DIR` | R | `$XDG_RUNTIME_DIR/flong`: the caller's, mode 0700 (checked) |
| `cache DIR` | R | the cache; the root is `DIR/prepared`; locked shared for the launch |
| `relaunch ARG` | * | the wrapper's own argv, exec'd when the cache was swept before it was locked |
| `closure PATH` | R | the container's toplevel, bound at `/run/current-system`; under `/nix/store/`, no empty, `.` or `..` component, and its target under `/nix/store/` too (bwrap binds it by path, outside the walker's protected-path check) |
| `uidmap IN OUT COUNT` | R* | an extent of U1's uid map, for newuidmap |
| `gidmap IN OUT COUNT` | R* | the same for gids |
| `user UID GID HOME` | R | the payload's container uid, gid and home |
| `group GID` | * | a supplementary group, from the container's `/etc/group` |
| `chdir DIR` | 1 | where the payload starts (the workspace); `/` when absent |
| `mount bind-ro DEST SRC` | * | declared bind; the source follows symlinks |
| `mount bind-rw DEST SRC` | * | the same, writable |
| `mount bind-ro-exact DEST SRC` | * | caller bind or workspace: `SRC` is canonical; a symlink on it refuses |
| `mount bind-rw-exact DEST SRC` | * | the same, writable |
| `mount dev DEST SRC` | * | an `allowedDevices` node: a read-write bind that is not nodev |
| `mount tmpfs DEST MODE SIZE OWNER` | * | `MODE` octal; `SIZE` tmpfs's `size=` or empty for none; `OWNER` `root` or `user` |
| `mount overlay DEST LOWER` | * | reads `LOWER`, writes are thrown away with the session |
| `mount mask DEST` | * | a mode-0 read-only node over an existing `DEST` |
| `protect PATH` | * | no mount source may equal, lie inside or contain `PATH` (frisket's socket directory); the launcher adds `state` and the holder's cgroup itself. Absolute, with no empty, `.` or `..` component. The launcher compares it canonicalised: a part that does not exist yet is appended, as spelled, to the canonical path of its longest prefix that does |
| `seccomp PATH` | * | a compiled BPF program; each becomes one `--add-seccomp-fd`, in order |
| `nested-userns N` | 1 | `nestedSandbox`: U2's `max_user_namespaces` is `N` and `--assert-userns-disabled` goes |
| `holder REL` | R | the holder unit's cgroup below `user@UID.service`, e.g. `app.slice/flong-sessions.service` |
| `holder-start ARG` | * | argv run when the holder is absent (`/run/current-system/sw/bin/systemctl --user start flong-sessions.service`); the first `ARG` is an absolute path, since nothing searches PATH |
| `limit FILE VALUE` | * | an opt-in limit; `FILE` one of `memory.max memory.high memory.swap.max memory.oom.group pids.max cpu.max cpu.weight io.weight` |
| `post-start ARG` | * | the postStart hook's argv; none, no hook |
| `post-stop PATH` | 1 | the postStop program, under `/nix/store/`, recorded for the sweep |
| `network` | 1 | start pasta |
| `pasta-arg ARG` | * | pasta's port and DNS flags (`-t`, `-u`, `-T`, `-U`, `--no-map-gw`, `--dns-forward`, `--host-lo-to-ns-lo`) |
| `pasta-wait` | 1 | fixed `forwardPorts` bind host ports: teardown waits for pasta's exit |
| `bwrap-arg ARG` | * | one argument for bwrap, from the allowed options below |
| `keep-fd N` | * | an open descriptor a `bwrap-arg` names; passed to bwrap only |
| `trace` | 1 | stage timestamps on stderr (section 4) |
| `-- COMMAND...` | R | the payload, run as `tini -g -- COMMAND...` |

**Allowed `bwrap-arg` options.** `--clearenv`, `--setenv VAR VALUE`,
`--unsetenv VAR`, `--hostname NAME`, `--perms OCTAL` immediately before
`--ro-bind-data`, and `--ro-bind-data FD DEST` with `FD` a `keep-fd`. The
parser walks them with their arities and refuses anything else: every
flong-level mount goes through the walker (condition 1), so a path mount
here is a wrapper bug the launcher catches. `--ro-bind-data` is for
`/etc/resolv.conf`, a fixed file in the fresh root, written before the
payload runs.

What a spec never carries: the programs (compiled in), U2's maps (derived
from U1's), the fixed mounts, `/sys`, `/run` read-only and the nsdelegate
check (always), and anything about seccomp policy (phase 3 compiles the files
this receives).

**The environment.** The launcher's own environment is the wrapper's, which
exports what hooks see on trunk (`workspace`, `workspace_mode`, `binds`,
`uid`, `gid`, `home` and the rest). `post-start` inherits it plus:

| variable | value |
|---|---|
| `leader` | bwrap's child, the session's pid 1 as the host sees it (from `--info-fd`) |
| `userns` | `/proc/<launcher>/fd/<U1>`: U1, held by the launcher |
| `netns` | `/proc/<launcher>/fd/<M>`: the session's network namespace, held by the launcher |
| `machine` | the machine name |

A hook enters with `nsenter --user="$userns" --net="$netns"`, without
`--preserve-credentials`, and runs there as U1 root with every capability
over the session. A hook that enters the mount namespace also enters the pid
namespace (`/proc/$leader/ns/...`). The hook runs in the hooks leaf, as the
caller, with the launcher's stdin, stdout and stderr and its working
directory. postStop runs with exactly `machine=<name>` and nothing else
(`fl_poststop`).

**What the launcher gives bwrap**, in this order, so the fixed part cannot be
undone by the wrapper's part and flong-init's protocol follows everything:

```
FLONG_BWRAP
  --userns <U1> --userns2 <U2> [--assert-userns-disabled]      (absent with nested-userns)
  --unshare-net --unshare-pid --unshare-ipc --unshare-uts --unshare-cgroup
  --die-with-parent --as-pid-1 --info-fd <info>
  [--new-session]                                               (relay only)
  --add-seccomp-fd <fd> ...                                     (one per seccomp, in order)
  --cap-add CAP_SETGID --cap-add CAP_SETPCAP                    (for flong-init, which drops them)
  --uid <UID> --gid <GID>
  --overlay-src <cache>/prepared --tmp-overlay /
  --ro-bind /nix/store /nix/store --ro-bind /nix/var/nix/db /nix/var/nix/db
  --proc /proc --dev /dev
  --perms 0755 --tmpfs /run
  --ro-bind <closure> /run/current-system
  --perms 0755 --dir /run/user --perms 0700 --tmpfs /run/user/<UID>
  --perms 1777 --tmpfs /tmp
  --ro-bind /sys /.hostsys                                      (the mount helper detaches it)
  <bwrap-arg ...>
  -- FLONG_INIT <gate-fd> <ready-fd> <groups> <tty> <trace> <dir> -- <COMMAND...>
```

bwrap is spawned in the sandbox leaf with `keep` = U1, U2, the info, gate and
ready pipe ends, the seccomp descriptors and the `keep-fd`s, and stdio from
`tty_stdio`.

**flong-init's arguments** are positional: `<gate-fd>` and `<ready-fd>`
(decimal), `<groups>` (comma-separated gids, or `-` for none), `<tty>`
(`ctty` to take fd 0 as controlling terminal, or `-`), `<trace>` (`trace` or
`-`), `<dir>` (absolute), then `--` and the command. flong-init runs, in
order: `setgroups`; drop the bounding set, clear ambient, zero every set with
`capset`; `TIOCSCTTY` on fd 0 with `ctty`; SIGINT and SIGQUIT to default and
an empty signal mask (a bash `&` hands them over ignored); one byte on
`<ready-fd>`, then close it; read one byte from `<gate-fd>`, **EOF exits
125**; `chdir(<dir>)`; `close_range(3, ~0)`; with `trace`, print
`T <us> payload-exec`; `execv(FLONG_TINI, {"tini", "-g", "--", COMMAND...})`.
Any failure before the exec exits 125. `oom_score_adj` is not touched (open
decision 4: only if someone asks).

## 4. The launch, in order

Each step names the call that does it and the trace stage printed after it.

| # | step | call | stage |
|---|---|---|---|
| 1 | name, block signals, ignore SIGPIPE, SIGCHLD to its default | `main` | `launcher-start` |
| 2 | parse; refuse uid 0; then `fl_sigfd`, so its number is never one a `keep-fd` names | `spec_parse`, `main` | |
| 3 | open and check the state directory | `state_open` | |
| 4 | lock the cache; swept: exec `relaunch`, or exit 75 | `cache_lock` | `cache-locked` |
| 5 | close inherited descriptors except `keep-fd`s and our own | `fl_close_from` | |
| 6 | wait for the foreground (an orphaned background group is refused), choose relay or passthrough, open the pty | `tty_prepare` | |
| 7 | nsdelegate; find or start the holder | `cg_check_nsdelegate`, `cg_holder_find` | |
| 8 | the inline sweep | `rec_sweep` | `swept` |
| 9 | the record, locked, with poststop= and cgroup=; a name held by an ended session waits for its release | `cg_session_path`, `rec_create` | `recorded` |
| 10 | U1, then U2 | `ns_create` | `U1-mapped`, `U2-made` |
| 11 | the session cgroup, limits, leaves | `cg_session_create` | `cgroup-made` |
| 12 | open the seccomp files; pipes for info, ready, gate; bwrap in the sandbox leaf | `fl_spawn` | |
| 13 | read `--info-fd` until `child-pid` (EOF first: bwrap failed), and keep its read end open until exit; open the leader's pidfd and netns; append leader= | `rec_set_leader` | `bwrap-child` |
| 14 | fork the mount helper into the sandbox leaf with the leader's pidfd (it prepares sources while bwrap builds, then waits for the ready byte; then `/sys`, before the declared mounts so one under `/sys` lands on the session's sysfs or fails instead of being covered, then the declared mounts, then `/run` read-only) | `fl_fork`, `mount_run` | `sandbox-ready`, then `mounts-done` when reaped with 0 |
| 15 | the postStart hook in the hooks leaf, waited for | `fl_spawn`, `fl_reap` | `hook-done` |
| 16 | pasta in the pasta leaf; ready when the spawned pasta exits 0 | `fl_spawn`, `fl_reap` | `pasta-up` |
| 17 | save modes, the watchdog, then raw (relay), so the terminal is never raw without one; take queued signals; copy the window size again (relay); write the gate byte, close it | `tty_start`, `fl_take_signal`, `tty_resize` | `gate-open` |
| 18 | wait for bwrap | `tty_wait` | `bwrap-exited` |
| 19 | teardown (section 5) | `teardown` | |

Who prints a stage: `ns_create` prints `U1-mapped` and `U2-made`, the
mount helper prints `sandbox-ready` (it alone reads the ready byte), and
`launcher-start` goes out after `spec_parse`, since `trace` is known only
then, with the time taken first thing in `main`. The waits of steps 13 and
14 also end when bwrap exits: bwrap's child was seen to outlive bwrap before
it had execed flong-init, still holding the info and ready pipes' write
ends, so neither pipe reported EOF.

The info pipe's read end is never closed while bwrap may write to it.
bwrap 0.12 writes its JSON in several writes (the `child-pid`, each
namespace id, the closing brace), and a launcher that closed the pipe once it
had the pid killed bwrap with SIGPIPE, silently, in about 1 launch of 100
under load: the launch failed closed with 125. The rest of the JSON is never
read; it fits in the pipe.

**A name already taken** (step 9). `linkat` refusing the name is a refusal
while that session runs: its record has no leader= yet (it is starting), or
its leader is the recorded process. When the leader has exited, the session
is ending and whoever holds its record's lock is releasing it: its launcher's
teardown (postStop, pasta with fixed forwardPorts), or a sweep, which holds
the lock while it waits for pasta's 20-40 ms and which the inline sweep of
step 8 therefore took for a live launcher. `rec_create` then waits for that
lock (`fl_lock_wait`), releases what is still there itself (as the sweep
does), and links the name. Running the same machine again right after it
exits, networked without fixed forwardPorts, failed 9 of 20 times with "a
session named ... is already running" before this, and 0 of 60 after. There
is no count: each turn follows the release of the session that held the name.

A SIGWINCH during any wait before the gate is taken and dropped, having no
payload to tell, so the gate copies the caller's window size to the pty once
more after it has taken the queued signals (`tty_resize`); one after that is
`tty_wait`'s.

A terminating signal that arrives after the last wait and before the gate is
taken off the signalfd at the gate (`fl_take_signal`), which aborts the
launch. Taking it, not only seeing it pending, is what lets the teardown's
own waits run: a signal left queued would end the first of them at once, and
the teardown would skip postStop and the cgroup's removal.

The order is ROOTLESS.md's: sweep, record, U1 and U2, cgroup, bwrap
(clone3), child-pid, ready byte, mount helper and `/sys`, hooks, pasta
ready, gate, wait, teardown. The helper is forked at child-pid, not at the
ready byte, so its source work overlaps bwrap's setup; it does nothing in the
session's mount namespace before the byte, which is the property the plan
needs (a hook ran before bwrap had finished the root in 179 of 200 launches
without it). Pasta starts after the hook, sequentially (open decision 8), so
the hook still sees no route.

pasta's argv is `FLONG_PASTA --quiet --config-net --userns
/proc/<launcher>/fd/<U1> --netns /proc/<leader>/ns/net --pid
/proc/<launcher>/fd/<memfd> <pasta-arg...>`, stdin `/dev/null`. `--userns`
names U1, the network namespace's owner (U2 is EPERM). The pid file is a
memfd the launcher holds: nothing on disk, and a unique path in pasta's
cmdline that tests identify it by. The launcher never signals pasta by pid:
`cgroup.kill` ends it.

A failure or a terminating signal at any step before the gate goes straight
to the teardown. The gate is never written, so flong-init, if it exists, reads
EOF and exits 125: the payload never runs.

## 5. Teardown

One function, run whatever stage was reached, in this order:

1. `tty_finish`: modes restored, watchdog released, foreground handed back.
   Hooks and postStop then print to a cooked terminal.
2. Close the gate's write end if it is still open.
3. `cg_kill`: every process in the session, bwrap and the helper included.
4. Reap what is ours: bwrap, the mount helper, the hook, the spawned pasta.
5. `cg_wait_empty` on the sandbox leaf, then the hooks leaf.
6. `fl_poststop` when the record has poststop=, then `rec_poststop_done`.
   Stage `poststop-done`.
7. With `pasta-wait`: `cg_wait_empty` on the pasta leaf. Stage `pasta-gone`.
8. `cg_remove`. When it returns 0, `rec_remove`; when it returns 1 (pasta
   still exiting), `rec_close`: the record stays, without poststop=, and the
   sweeper or the next launch removes the cgroup and the record. A launch of
   the same machine meanwhile waits for that (section 4, "A name already
   taken"). Stage `released`.
9. The cache lock is released by exit.

Steps 3 to 8 happen only for what exists: no record, no postStop; no
cgroup, nothing to kill or wait for.

A terminating signal during a teardown wait, or a failing `cg_kill`,
`rec_poststop_done` or `cg_remove`, leaves the session possibly not empty.
The teardown then runs no postStop and removes nothing: it closes the
record (`rec_close`), and the sweeper, woken by that close, kills, waits,
runs postStop and removes.

A terminating signal while postStop runs is one of those waits. `fl_poststop`
then kills and reaps postStop and returns -1; the teardown keeps poststop=
(no `rec_poststop_done`), removes nothing and closes the record, so the
sweeper runs postStop again (it is idempotent), and the machine's name stays
taken until it has. A sweep that is ended the same way leaves the record as
it found it. A postStop that merely fails is reported and counts as run.

## 6. Exit codes

| status | when |
|---|---|
| payload's | the gate opened: bwrap's exit code, which is pid 1's, which is tini's, which is the payload's; 128+n when a signal killed it |
| 125 | the payload never ran: a refusal, a failed step, a hook that exited non-zero, pasta failing (a host port in use or below 1024), bwrap failing, flong-init's gate EOF. stderr says which |
| 75 | the cache was swept before it was locked and there is no `relaunch` |
| 128+n | a terminating signal n reached the launcher before the gate: the launch was aborted and torn down |

After the gate, a signal is forwarded, not acted on, so the payload's status
tells what happened: `^C` is 130 under a pty and in a pipeline, `^]^]^]` is
137. A failing postStop is reported and does not change the status. 125
collides with a payload's own 125, as it does for `env` and `chroot`.

`flong-sweeper STATE-DIR` runs until killed; it exits 125 when it cannot
start (no state directory, no holder).

## 7. Who calls what, when

| function | caller | when |
|---|---|---|
| `spec_parse` | launch | step 2 |
| `state_open` | launch, sweeper | step 3; sweeper start |
| `cache_lock` | launch | step 4, before `fl_close_from` |
| `fl_close_from` | launch; `fl_fork`'s child | step 5; every helper |
| `tty_prepare`, `tty_stdio`, `tty_spawned` | launch | step 6; step 12 |
| `cg_check_nsdelegate`, `cg_holder_find` | launch | step 7 |
| `cg_holder_self` | sweeper | start |
| `rec_sweep` | launch; `rec_watch` | step 8; every inotify batch |
| `cg_session_path`, `rec_create` | launch | step 9; `rec_create` releases an ended session holding the name as the sweep does |
| `ns_create` | launch | step 10 |
| `cg_session_create` | launch | step 11 |
| `rec_set_leader` | launch | step 13 |
| `mount_run` | the helper | step 14 |
| `tty_start`, `tty_resize`, `tty_wait` | launch | steps 17, 18 |
| `tty_finish`, `cg_kill`, `cg_wait_empty`, `fl_poststop`, `rec_poststop_done`, `cg_remove`, `rec_remove`, `rec_close`, `cg_close` | teardown | section 5 |
| `cg_session_open`, `cg_kill`, `cg_wait_empty`, `fl_poststop`, `cg_remove` | `rec_sweep`, `rec_watch`, `rec_create` | per dead record |
| `fl_lock_wait` | `cache_lock`; `rec_watch`, `rec_create` | a cache being swept; a record that is being let go |
| `rec_watch` | sweeper | forever |

## 8. Layouts on disk and in cgroupfs

```
$XDG_RUNTIME_DIR/flong/                    0700, the caller's (state)
  sessions/<machine>                       the record; its lock is the launcher's
  <container>-<closure hash>-<steps hash>/ a cache (the wrapper's)
    prepared/                              the root, subuid-owned
    .prepare.lock

<user@UID.service>/<holder>/               the holder unit (Delegate=yes)
  supervisor/                              its own process: flong-sweeper
  <container>/                             shared; never removed by a launcher
    <machine>/                             the session; no process of its own
      sandbox/                             bwrap, the session, the mount helper for a moment; the limits
      hooks/  pasta/                       leaves
```

## 9. flong-sweeper

The holder unit's process, `flong-sweeper $XDG_RUNTIME_DIR/flong`, in the
unit's `DelegateSubgroup=supervisor` leaf. It holds the holder open and sweeps
when a record is closed, so a SIGKILLed launcher's postStop and hook daemons
go within milliseconds, not at the next launch.

The kernel queues IN_CLOSE_WRITE in `__fput` (`fsnotify_close`) before it
drops the descriptor's flock (`locks_remove_file`), so a sweep that answers
the event with LOCK_NB can find the lock still held, skip the record, and
never hear of it again. The sweep that follows a batch therefore waits for
the lock (`fl_lock_wait`) of each record a launcher's close names; every
other record is tried with LOCK_NB. A launcher's record was made with
O_TMPFILE, and its close is reported under the name the kernel gave the
unnamed file, `#<inode>`, whatever it was linked as since: that close is
its last descriptor of the record, so its lock is being let go, and the
sweep matches records by that inode. A close reported under a machine's
name is a sweep's writable open (the sweeper's, or a launcher's inline
sweep) closed after blanking `poststop=`. It is never resolved to an inode
and never waited on: by the time the event is read the dead record may be
unlinked and a relaunch's live record linked under the name, and waiting on
that lock would stall every sweep for that session's whole life. The event
still wakes a sweep, which tries every record with LOCK_NB. When the queue
overflows (IN_Q_OVERFLOW), a launcher's `#<inode>` close may be among the
events dropped, so the next sweep waits for the lock of every record whose
`leader=` has exited (only a holder that is letting go keeps such a lock)
and tries the rest with LOCK_NB: still a wait on an event, with no timeout.

`release` drops a record only when its `cgroup=` is refused
(`FL_CG_REFUSED`: not a session's cgroup, or too long). A cgroup that could
not be opened (EMFILE, ENOMEM) keeps the record for the next sweep: it is
the only trace of the session's hook daemons, pasta and postStop. The module ships the unit in
phase 2; in phase 1 the test wrapper's `holder-start` runs it with
`systemd-run --user`.

## 10. The test wrapper

`launcher/test/launch.sh WORKSPACE RO_DIR COMMAND...`, the spikes'
`launch.sh` shape, so their repros change only where they name it. It is a
stand-in for phase 2's wrapper and does the same jobs by hand, with bash
builtins on the warm path so the numbers stay comparable:

1. **Programs.** `FLONG_BUILD` (default `launcher/test/result`, from
   `nix-build launcher/test -o launcher/test/result`, where
   `test/default.nix` joins the launcher with util-linux for `unshare`,
   `nsenter` and `flock`). `FLONG_CLOSURE` (default
   `launcher/test/result-closure`, from
   `nix-build spikes/rootless/shared/container.nix -o launcher/test/result-closure`;
   the same store path the spikes' repros name, `.../nixos-system-demo-...`).
   Both names are covered by the repo's `.gitignore`.
2. **Runtime directory.** `XDG_RUNTIME_DIR`, else `/run/user/$UID` when it
   exists and is the caller's, else fail naming `users.users.<name>.linger`.
   State is `$runtime/flong-p1`, made 0700, so it never meets a real flong's.
3. **Identity.** The first `/etc/subuid` and `/etc/subgid` entry at least
   65536 wide (none: fail naming `subUidRanges`). The container user's uid
   onto the caller's, its gid onto the caller's primary gid, the rest from
   the range (`FLONG_CUID`, `FLONG_CGID`, default 1000 and 100), as `r2-vm`'s
   `mkmap`.
4. **The cache.** `$state/demo-<tag>` (`FLONG_CACHE_TAG`, default the first 8
   characters of the closure's hash, plus the map key). Cold: hold a shared
   `flock` on it, take `.prepare.lock` exclusively, remove any stale
   `.prepare.*`, prepare in a keep-id namespace with `prepare-inner.sh`
   (r2-lifecycle's, which never recreates a vanished staging directory), `mv
   -T` into place or discard the loser's through the namespace. Superseded
   caches of the container go through `gc-cache.sh` (r2-lifecycle's).
   `test/asroot.sh` runs a command as container root in the keep-id
   namespace, for fixtures in a prepared root and for cleanup.
5. **The payload's identity** from `prepared/etc/passwd` and `etc/group`.
6. **The spec**, then `exec flong-launch`:
   `machine ${FLONG_MACHINE:-demo-$$-$RANDOM}`, `container demo`, `state`,
   `cache`, `relaunch "$0" "$@"`, `closure`, the maps, `user`, `group`s,
   `chdir WORKSPACE`, `mount bind-rw-exact WORKSPACE WORKSPACE` (or
   `bind-ro-exact` with `FLONG_WS_MODE=ro`), `mount bind-ro-exact RO RO`,
   `mount tmpfs $home/tmp 0700 '' user`, `holder
   flong.slice/flong-p1.slice/flong-p1-sessions.service` (systemd nests a
   dashed slice name under the slices its prefixes spell), `holder-start
   /abs/path/systemd-run --user --quiet --collect --unit=flong-p1-sessions
   --slice=flong-p1.slice -p Type=exec -p Delegate=yes -p
   DelegateSubgroup=supervisor -p OOMPolicy=continue
   $FLONG_BUILD/bin/flong-sweeper $state` (argv[0] absolute: `fl_spawn` does
   no PATH search; `Type=exec`, or the sweeper may not have moved to
   `supervisor/` when `systemd-run` returns, and enabling a controller in the
   holder fails with EBUSY; phase 2's unit is `Type=exec` too), the environment as `bwrap-arg`s
   (`--clearenv`, `PATH` `$closure/sw/bin` plus `FLONG_EXTRA_PATH`, `HOME`,
   `USER`, `XDG_RUNTIME_DIR /run/user/$uid`, `TERM`, `TMPDIR $home/tmp`;
   `--hostname demo`), then the knobs below, then `--` and the command.
   WORKSPACE and RO_DIR are made canonical with `cd -P` and `$PWD`, not a
   `realpath` fork.

| knob | spec it produces | replaces in the spikes |
|---|---|---|
| `FLONG_SPEC_EXTRA=FILE` | the file's NUL-separated tokens, before `--` | `FLONG_MOUNTS_EXTRA` (tab lines), `FLONG_EXTRA` |
| `FLONG_POLICY=P` | `seccomp` per file: `strict` (default) is `strict.bpf audit.bpf nsmask.bpf tty.bpf`, and `none parity parity-ns strict-nons plus-* nons-plus-* learn` as `r2-compat/proto/launch.sh` maps them, each plus `tty.bpf`; files from the old scratchpad's `r2-compat/filters` and `r2-terminal/sc` | `FL_FILTER`, `FL_FILTERS` |
| `FLONG_FILTERS=a:b` | `seccomp` per file, overriding the policy | the same |
| `FLONG_NESTED=N` | `nested-userns N` | `FL_U2_MAXNS` |
| `FLONG_LIMITS="f=v ..."` | `limit f v` each | `FL_CG_LIMITS`, `FL_CG_SET`, `FLONG_MEM` |
| `FLONG_NET=1` | `network`, `pasta-arg`s for DNS (`--dns-forward 169.254.1.1`, `--no-map-gw`, `-U none`), `resolv.conf` through `--ro-bind-data 9` and `keep-fd 9` | the same |
| `FLONG_PORTS`, `FLONG_HOSTPORT`, `FLONG_PASTA_EXTRA` | `pasta-arg`s (default `-t none -u none`, `-T none`); `pasta-wait` when `-t` or `-u` names a fixed port | `FL_PASTA_ARGS`, `FL_PASTA_NOWAIT` |
| `FLONG_HOOK=1`, `FLONG_HOOK_FILE=F` | `post-start /bin/sh F` (default `spikes/rootless/prototype/hook.sh`), `HOOK_SW=$closure/sw` exported | `FL_HOOK` |
| `FLONG_POSTSTOP=P` | `post-stop P`; fixtures go into the store with `nix-store --add` | `FL_POSTSTOP`, `FL_POSTSTOP_PREFIX` |
| `FLONG_DEVS="d ..."` | `mount dev d d` each | the same (was `--dev-bind`) |
| `FLONG_TRACE=1` | `trace` | `FL_TRACE`, `FLONG_TRACE` |
| `FLONG_MACHINE`, `FLONG_CACHE_TAG`, `FLONG_CUID`, `FLONG_CGID`, `FLONG_WS_MODE`, `FLONG_EXTRA_PATH` | as above | the same |

Knobs that go, because the behaviour is no longer optional or the variant was
a comparison: `FLONG_SAFE`, `FM_EARLY`, `FM_SRC` (the walker, early, always),
`FL_WAIT_READY` (the ready byte, always), `FLONG_BWRAP_EXTRA` and
`hook-sysc.sh` (`/sys`, always), `FLONG_SCOPE`, `FL_SUBCG`, `FL_CGPARENT`,
`FL_CGROUP`, `FL_CG_NAME`, `FL_CG_NOWAIT` (the holder, always),
`FL_PASTA_KILL`, `FL_PASTA_NOWAIT` (the wait follows `pasta-wait`),
`FLONG_PTY`, `FL_PTY`, `FL_TTY_GUARD`, `FL_TTY_RESTORE`, `FL_FG_WAIT`,
`FL_NO_FG_RETURN` (the terminal follows stdin and stdout, the watchdog and
restore always run), `FL_LOCK_BWRAP`, `FL_TEST_PAUSE_MS`, `FL_TEST_NOVERIFY`,
`FL_REEXEC`, `FLONG_PREP_NOLOCK`, `FLONG_PREP_SERIAL` (serialised, always),
`FLONG_OOM_ADJ`, `FLONG_ROOT_SIZE`, `FLONG_BWRAP`, `FLONG_EXTRA_LOWER`,
`FLONG_PIDDIR_ON_DISK`, `FLONG_NOLIFE`, and the `pin` mount kind.

## 11. Acceptance: each spike's repro against this launcher

Each spike directory is copied to
`/tmp/claude-1000/-home-dan-Projects-flong/979e8b64-ed0c-4f53-ba42-64cda2e55c8a/scratchpad/phase1/repro/<spike>`,
its `proto/launch.sh` (or `prototype/launch.sh`) calls replaced by
`launcher/test/launch.sh`, the old scratchpad prefix kept only for fixtures
and tools that live there (filters, `lockwatch`, the tools env), and the
knobs rewritten per section 10. What each must show:

- **r2-mounts.** `escape.sh`, safe mode only (bwrap-by-path was round one's
  comparison): every PASS. Spec lines become tokens: `bind D S` is `mount
  bind-rw D S`, `robind` is `bind-ro`, `tmpfs D mode=0755,uid=1000,gid=100`
  is `mount tmpfs D 0755 '' user`, `mask D` is `mount mask D`, `overlay D L`
  is `mount overlay D L`; `readonly /run` is the launcher's own. E4 plants
  its symlink with `asroot.sh` in a prepared root of its own
  (`FLONG_CACHE_TAG=e4`). The odd-path case gains a tab and a newline.
  `race.sh`: one mode, N=200, both fixtures, 0 escaped, 0 host directories
  made. `maskbypass.sh`, plain only: depth 1 held, depth 2 bypassed (refused
  at evaluation in phase 2, open decision 1). Candidates (a) to (c) were
  design probes and are not rerun.
- **r2-lifecycle.** `e1-kill.sh 20` for `launcher`, `bwrap`, `pid1` with
  `LW_LEADER=1`: no session process alive when the sweep may call it dead,
  20 of 20. `e2-hooks.sh`, holder mode only: a clean exit leaves no daemon,
  file, record or cgroup and runs postStop once; after SIGKILL the sweeper
  releases it (postStop once, daemon gone, record and cgroup gone) without a
  launch; ten concurrent launches run no second postStop. SIGTERM: postStop
  saw the daemon dead. Limits via `FLONG_LIMITS`. `e3a` unchanged. `e3b`
  steps 1 and 4 unchanged; step 3's window is made from outside: the test
  holds `flock -x` on A's cache while A launches, renames the cache and
  releases, and A relaunches and runs its payload. Step 2 and every
  `NOLOCK`/`NOVERIFY` control go. `e3c` with the lock only; `e4` serialised
  only: 50 of 50 payloads ran, no staging left. No user manager: `env -u
  XDG_RUNTIME_DIR` still launches (derived `/run/user/$UID`); a runtime
  directory that is not the caller's fails naming linger.
- **r2-containment.** Session placement and limits (`systemd-cgls --user-unit
  flong-p1-sessions.service`), cpu and pids limits, SIGKILL then the sweeper
  (no manual `cgroup.kill`), OOM with and without `memory.oom.group`, the
  tmp-overlay charge, stopping the holder ends every session. The
  `oom_score_adj` row runs once, without it. Root size (open decision 3) and
  the scope comparisons go. `interleave.sh` compares the exec baseline with a
  launch; containment cannot be turned off, so its cost is judged against
  the table.
- **r2-terminal.** `interactive.py` in two modes: relay (the default under
  its pty: every test, ^C 130, SIGWINCH, job control, TUIs, /dev/tty) and
  passthrough (stdout piped through `cat`: ^C 130, termios restored,
  foreground handed back). The tiocsti rows with `tty.bpf` in the stack
  (the default). `bgdebug.py`, `fgcheck.py` (without its `FL_NO_FG_RETURN`
  control), `hookcr.py`, `bench.py`. The `legacy_tiocsti=1` VM is phase 4's.
- **r2-compat.** `matrix.sh none parity strict`, `learn.sh`, `chrome.sh`
  with `FLONG_NESTED=16` for the nested rows, `nested-in.sh`, `sys-in.sh`
  with `/sys` as it now always is (row (a) goes), `sysleak-in.sh` (no
  `/.hostsys` left), the hook race with every hook after the ready byte.
- **Network and frisket.** `spike-network`'s experiments and
  `r2-consumers` sections 1 to 5 with `FLONG_NET`, `FLONG_PORTS`,
  `FLONG_PASTA_EXTRA`: `auto` and `hostLoopbackToSession`, 20 back-to-back
  relaunches on a fixed port with 0 failures, the pasta teardown from the
  trace (`pasta-gone` minus `bwrap-exited`), ports below 1024 exit 125,
  `hook-lowport.sh`, `hook-gons.sh`, `hook-frisket.sh` with the rootless
  frisket. `prototype/ro/checks.sh` with `FLONG_NET=1 FLONG_HOOK=1
  FLONG_HOSTPORT`.
- **Numbers**, from `trace` over 30 runs, within 10% of ROOTLESS.md's
  host table: warm with no network 16.1 ms (9.5 to payload exec); network,
  nft hook and hostPort 29.9 ms (22.6); waiting for pasta to free a fixed
  forwarded port 70.7 ms (20.5); cold 176-198 ms.

Every repro also greps the build's sources for `nanosleep`, a non-negative
`poll` timeout and `WNOHANG`, and finds none.

## 12. Choices this contract makes

ROOTLESS.md left these to phase 1, or the prototypes disagreed. Each is
settled here and is to be carried into DESIGN.md.

1. **The spec is argv.** An argument is already NUL-terminated, and bash can
   build and pass it without a fork; bash cannot hold a NUL in a string, so a
   spec file or pipe would cost a fork or a temporary file per launch.
2. **flong-init's protocol is its argv, not `--setenv`.** The prototypes'
   invariant (the launcher's variables after the wrapper's options, so a
   `--clearenv` cannot drop them) now holds by construction, and nothing has
   to be unset before the payload sees its environment. flong-init's argv is
   gone at the exec of tini.
3. **Records are made with `O_TMPFILE` and `linkat`**, not as `.<machine>`
   renamed into place. The record appears locked and whole, a concurrent
   sweeper can never find and unlink a half-made one, a killed launcher
   leaves no dot file, and `linkat` refusing an existing name is the O_EXCL.
4. **A record outlives its launcher when the cgroup cannot be removed yet**:
   without `pasta-wait`, pasta is still exiting when the launcher is done.
   poststop= is dropped from the record first, so postStop runs once; the
   sweeper (woken by the record's close) or the next launch removes the
   cgroup and the record. The sweep looks only at records, never at
   cgroupfs.
5. **The `/sys/fs/cgroup` view is the payload's own cgroup namespace**,
   rooted at the sandbox leaf by bwrap's `--unshare-cgroup` (bwrap is created
   in the leaf). The mount helper joins that namespace
   (`PIDFD_GET_CGROUP_NAMESPACE`) before it mounts cgroup2, so the mount's
   root is the cgroup `/proc/self/cgroup` names, `/`. A view rooted at the
   session cgroup instead, with the payload's namespace at the leaf, showed a
   mount root of `/..`, and Go uses a cgroup2 mount only when its root is a
   prefix of the process's cgroup path: GOMAXPROCS ignored `cpu.max`. The
   payload's namespace cannot be rooted at the session either: it is made
   where bwrap is, in the leaf, and flong-init has no capability over U1 to
   join one the helper made. The view also no longer shows the session's
   `hooks/` and `pasta/`.
6. **Limits are written on the sandbox leaf**, with their controllers
   enabled in the holder's, the container level's and the session's
   `cgroup.subtree_control`. A program reads its limits from its own cgroup,
   and Go reads `cpu.max` there and nowhere above, so the plan's "`nproc`,
   Go, Node and Java honour declared limits" needs them on the payload's
   cgroup. They bound the payload and bwrap, not the hooks or pasta; pasta
   can no longer be the OOM victim of the payload's memory, and
   `memory.oom.group` kills the payload's group. The mount helper lives in
   the sandbox leaf for the moment it runs, so the session cgroup holds no
   process and can enable controllers.
7. **`allowedDevices` goes through the walker** (`mount dev`), not bwrap's
   `--dev-bind`: condition 1 says every flong-level mount does. It is the
   same operation (a clone without nodev). Acceptance re-measures `/dev/snd`
   and `/dev/kvm`.
8. **The programs are compiled in**, and `bwrap-arg` is an allow-list. The
   wrapper cannot point the launcher at another bwrap, and cannot add a path
   mount that bypasses the walker.
9. **The cache recheck loops through the wrapper.** A swept cache execs
   `relaunch` (the wrapper, which prepares afresh), with no count: each turn
   follows a sweep's rename, an event. A cache whose path was taken by a
   sweep and made again by another wrapper passes the inode recheck while
   that wrapper is still preparing it, since both hold it shared, so the
   recheck also asks for `prepared/`: without it there is no
   `--overlay-src`, and the relaunched wrapper waits for the preparer's
   `.prepare.lock` and finds the root made.
10. **Signals.** Before the gate, TERM, HUP, INT and QUIT abort the launch
    (128+n after the teardown); after it they go to the leader, through its
    pidfd, never its pid, which bwrap may have reaped and the kernel reused.
11. **The holder's process is `flong-sweeper`**, a small program of its own
    sharing the record and cgroup code.
12. **An orphaned background launcher is refused.** The plan says a
    launcher in the background "gives up if its group is orphaned": the
    kernel discards the SIGTTOU that would stop it, no shell will continue
    it, and it could neither make the terminal raw nor read from it. It is
    refused in `tty_prepare`, before any session state exists, rather than
    failing at the gate.
13. **The sweep leaves another holder's sessions alone.** Two units of the
    caller's, or a launch with and one without a user manager, share the
    state directory but not the holder. A record whose `cgroup=` spells a
    session under another holder is left, unreported, for that holder's
    sweep: its cgroup is not this sweep's to kill, and its postStop must
    still run. Only a record that is not well formed, or does not spell a
    session's cgroup, is unlinked.
14. **Always on:** `/sys`, `/run` read-only by the helper, the watchdog,
    termios restore and the foreground hand-back. **Dropped:** the pin
    (open decision 1), `oom_score_adj` (4), the root size (3), the scope
    fallback.
