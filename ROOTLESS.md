# Plan: the rootless engine

flong replaces its engine. systemd-nspawn, run as root through sudo, gives way
to bubblewrap in user namespaces the caller owns. Three goals, in order:

1. **No root anywhere.** Not in the launcher, the hooks, pasta, the sweep or
   the session. No sudo rule grants the launcher.
2. **Fast.** A warm session in well under nspawn's 124–153 ms.
3. **Seccomp policy as a feature.** A syscall filter per chase tier,
   loosenable per project through chase's approver.

This is a rewrite of the engine, not a feature: most of `module.nix`'s
launcher changes, and DESIGN.md's account of the engine is replaced. The
option interface mostly survives.

Every design decision below was spiked on this machine and, where it
mattered, in a NixOS VM, in two rounds with an adversarial review after each.
The evidence is in [`spikes/rootless/`](spikes/rootless/README.md): sources,
repro scripts and their output (not yet committed; for now it lives in the
working tree where the spikes ran). Where this plan says *measured*, a repro
there shows it. This file and that directory are deleted once the rewrite lands
(phase 8); what they establish moves into DESIGN.md.

## Decided

By the user:

- **`guard` stays**, as a veto the caller runs. Without root it cannot refuse
  the caller anything, so it is a consistency check (chase's trusted-tier
  check), not an entitlement gate.
- **The default seccomp tier is tighter than nspawn's.** It is `strict`
  (below), not parity.
- **A project may loosen its tier's seccomp**, through chase's approver like
  any other envelope change.
- **chase's trusted tier has `debug` on by default** (`strict` plus `ptrace`),
  so strace and gdb work on our own code. The strict tier does not.
- **Keep-id first.** The session runs as the caller's own uid on the host. A
  separate uid range per session (today's PLAN.md §1) is a later layer.
- **C, not Zig**, for flong's native code. Measured: identical BPF and runtime,
  but a clean Zig build is 78–93 s against C's 1.6 s and needs a 1.8 GiB
  compiler, and a typed config format repeats checks the Nix module types
  already make. Nix renders a line format; nothing parses JSON or ZON.

By the spikes (each with its reason further down):

- bubblewrap, not nspawn. Unprivileged nspawn only supports its managed uid
  range mode, and stops at `Failed to reset audit login UID` in a keep-id
  namespace.
- Two user namespaces: the outer one owns the network and mount namespaces,
  the payload lives in an inner one with nested user namespaces off.
- A compiled launcher (`flong-launch`) and first-exec shim (`flong-init`). A
  bash launcher measured 61 ms, python 106 ms, C 19 ms.
- The session root is an overlay on the prepared root. No per-session copy.
- Every flong-level mount goes through an fd-based walker in `flong-launch`,
  not through bwrap's path arguments.
- Every session gets its own cgroup in a delegated user unit, entered with
  `clone3(CLONE_INTO_CGROUP)`, so its hook daemons and pasta die with it.
  Resource limits are opt-in; none is set by default.
- No timeouts anywhere: every wait is on an event.
- Sessions no longer outlive their launcher (`--die-with-parent`).

## Numbers

Quote each with its harness; do not mix them.

**Same NixOS VM, same payload (`true`)**, flong's locked nixpkgs (kernel
6.18.51, systemd 261.2), medians of 20 over three runs:

| | today (nspawn, root) | prototype (rootless) |
|---|---|---|
| no network | 124–141 ms | 20–21 ms |
| no network, via sudo as a user | 141–155 ms | — |
| pasta network + nft hook | 141–198 ms | 67–74 ms with a `systemd-run --user` scope; 43–68 ms without |
| cold (prepare included) | — | 313–317 ms |

**This host, the final shape** (a session cgroup, `strict` seccomp stack,
fail-closed gate, overlay root; the runs also wrote memory, pids and cpu
limits, which cost nothing measurable; fork+exec of `true` 1.4–1.7 ms in the same
runs; medians of 30):

| | total | to payload exec |
|---|---|---|
| warm, no network | 16.1 ms | 9.5 ms |
| warm, network + nft hook + hostPort | 29.9 ms | 22.6 ms |
| same, waiting for pasta to free a forwarded host port | 70.7 ms | 20.5 ms |
| cold, no network | 176–198 ms | |

The session cgroup costs +0.14 ms (interleaved, n=40); `systemd-run --user --scope`
would cost +23 ms. The seccomp filters cost nothing measurable at launch and
18–35 ns per syscall. frisket's steer + connect add about 38 ms per steered
launch, more than the rest of the launch (see phase 6).

## The design

### Process shape

```
launcher (bash, the caller)          workspace, binds, guard as today; reads
│                                    passwd/group/subuid; builds argv
└─ exec flong-launch (C, the caller)
   ├─ unshare U1 + newuidmap/newgidmap in parallel     (keep-id, owned by caller)
   ├─ U2 = child of U1, identity map split along U1's extents,
   │       user.max_user_namespaces = 0
   ├─ mkdir session cgroup under the holder; write declared limits, if any
   ├─ clone3(CLONE_INTO_CGROUP) → bwrap --userns U1 --userns2 U2 --assert-userns-disabled
   │     --info-fd → child pid     --overlay-src PREPARED --tmp-overlay /
   │     fixed mounts only         --add-seccomp-fd × N   --as-pid-1
   │     └─ flong-init (pid 1): setgroups, cap drop, TIOCSCTTY,
   │           ready byte, BLOCK ON GATE (EOF → exit 125), chdir, close_range
   │           └─ tini -g -- payload
   ├─ mount helper (forked; U1; fd walker)        after the ready byte
   ├─ postStart hook (clone3 into the session cgroup, as the caller)
   ├─ pasta (clone3 into the session cgroup, as the caller)
   ├─ open the gate
   └─ wait; teardown
```

### Identity

- Read `/etc/subuid` and `/etc/subgid` at run time. NixOS allocates automatic
  ranges in user-name order (a VM gave alice 165536 because dave had 100000),
  so nothing assumes 100000. Use the first entry at least 65536 wide. A caller
  with no range is refused with a message naming `subUidRanges`.
- **Map the container user's uid onto the caller's uid, and its primary gid
  onto the caller's primary gid, whatever the numbers.** Container 1001:1001
  onto caller 1000:100 was measured. This removes today's limitation that
  `user` must have the caller's uid.
- Everything else in the container's 0–65535 fills from the subordinate range.
  Container root is a subuid on the host, never host root.
- U2's map is the identity split along U1's extents (`0 0 1000 / 1000 1000 1 /
  1001 1001 64536`, and the same for gids). A single `0 0 65536` extent is
  refused with EPERM. With the split, container-root files read as root inside.
- The maps go into the prepared-root cache key: the root's on-disk owners
  depend on them.
- **Supplementary groups** come from the container's `/etc/group`. flong-init
  calls `setgroups` (bwrap is given `CAP_SETGID` for it, and the shim drops it
  again). bwrap never calls setgroups itself, so without this the caller's
  host groups (wheel, docker, kvm) leak into the payload: measured.
- **Host group pass-through** (a container gid that means the host gid):
  newgidmap refuses mere membership. It needs an explicit one-gid subgid entry
  (`subGidRanges = [{ startGid = 17; count = 1; }]`). A `hostGroups` option
  would declare the entry and map the gid to itself; measured to work for
  `audio` and `kvm`. Not needed by any consumer today (see open decisions).
- A caller of uid 0 is refused. Root has no subuid range and "no root
  anywhere" includes the caller.

### The prepared root

- Built rootless, once per cache key:
  `unshare --user <keep-id maps> --setuid 0 --setgid 0 --mount --pid --fork`
  around today's prepare steps, with nspawn's mounts replaced by explicit ones
  (proc, a tmpfs `/dev` with the usual nodes bound in, tmpfs `/run` and
  `/tmp`, read-only `/nix/store` and `/nix/var/nix/db`). Measured 160–350 ms,
  identical tree, owners and modes to a bwrap-built root.
- `chown 0:0` the staging directory first, and make every mount-point
  directory as container root. A caller-made skeleton fails tmpfiles with exit
  73 ("unsafe path transition").
- `/run/wrappers/bin` first on `PATH`: util-linux `unshare` execs `newuidmap`
  from `PATH`, and the closure's non-setuid copy fails.
- `chattr +i` on `/var/empty` cannot be set in a user namespace; tmpfiles
  ignores the failure. So `chattr -R -i` before deletion goes.
- Cache: `$XDG_RUNTIME_DIR/flong/<container>-<closure hash>-<steps hash>/prepared`,
  state directory mode 0700. A prepared root is 52 K and 183 entries; the
  runtime directory is 10% of RAM.
- The caller cannot `rm` subuid-owned trees. Deletion goes through the keep-id
  namespace (12–17 ms).
- Cold prepares are serialised on `.prepare.lock`; the atomic `mv -T` stays as
  the second line, the loser discarding its copy through the namespace. Ten
  concurrent cold launches: 188–211 ms serialised, 256–300 ms racing.
- `prepare-inner` never recreates a vanished staging directory (a sweep that
  landed mid-prepare otherwise left a cache owned by container root that
  locked every later launch out: found and fixed in the spike).
- Integrity: none beyond a microsecond sanity check. Anything running as the
  caller can edit the cache, and nothing stored in caller-writable space can
  beat that. Document that the prepared root's integrity equals the caller's,
  like `~/.bashrc`.

### The session root and mounts

- **Root:** `bwrap --overlay-src $prepared --tmp-overlay /` in U1. Copy-up
  keeps ownership; a SIGKILL leaves nothing on disk; it costs nothing over a
  plain bind (`cp -a` plus `rm -rf` cost about 45 ms). Single-uid bwrap cannot
  do this: every write through a subuid-owned lower fails EOVERFLOW.
- **bwrap mounts only fixed destinations** in fresh filesystems: the overlay
  root, `/nix/store`, `/nix/var/nix/db`, `/proc`, `/dev`, the `/run` tmpfs,
  `/run/current-system`, `/run/user/$uid`, a fresh 1777 `/tmp`.
- **Everything else goes through the fd walker**: declared `bindMounts`,
  `tmpfs`, `overlays`, masks, the workspace, caller binds, `~/tmp`, `/sys`.
  A child of flong-launch joins U1, clones each source in a private mount
  namespace it owns (`open_tree(OPEN_TREE_CLONE|AT_RECURSIVE)`), joins the
  session's mount namespace, walks each destination one component at a time
  with `openat2(RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_BENEATH)`
  and `mkdirat` on the parent fd, and attaches with
  `move_mount(MOVE_MOUNT_T_EMPTY_PATH)` onto the final O_PATH fd. Nothing is
  resolved by name twice. About 1 ms for 3 mounts, 1.5 ms for 12.
- **Why:** bwrap resolves nested destinations by path and follows symlinks the
  payload planted. Under a concurrent session swapping a directory for a
  symlink, bwrap escaped 60–65 of 200 launches, a launcher pre-check plus bwrap
  18–20 of 200, the walker 0 of 400. bwrap refuses an fd as a destination.
  Today's nspawn engine follows the same planted symlink as root (measured in
  a VM): this closes a hole trunk already has, beyond trunk's home-only rule.
- **Walk rule:** a symlink anywhere on the way, the last component included,
  ends the launch ("a symlink is on the way"). Trunk's subtest for home ports
  unchanged. A concurrent session can therefore deny a launch by planting one
  (about half of launches under a tight swap loop): a denial of service on its
  own workspace, as on trunk.
- **Directories made on the way:** on the session's own mounts, as container
  root, chowned to the payload inside home; on a host bind, with
  `setfsuid`/`setfsgid` set to the payload's ids, so the kernel checks the
  write as the caller's and the directory is the caller's on the host.
- **Caller and workspace sources** are opened with
  `openat2(RESOLVE_NO_SYMLINKS)` from `/` after `realpath`. The path is
  canonical, so any symlink met now is a race, and the launch is refused.
  Declared `bindMounts` sources keep following symlinks, as their author
  intended.
- **Masks** are a mode-0 read-only node of the target's kind, owned by U1's
  mount namespace, so the payload in U2 gets EPERM on `umount`. The target
  must exist. A mask two or more levels below a payload-writable bind root can
  be bypassed by renaming a parent directory (on trunk too); see open
  decisions.
- Mounts are sorted by destination, parents first, as nspawn did. `/run` is
  made read-only last, by the helper, because declarations bind under `/run`.
- The spec reaches flong-launch NUL-separated: paths may hold tabs and
  newlines.
- `nspawnPath` and `nspawn_path` escaping go: bwrap and the walker take paths
  as whole arguments.

### Namespace topology and lockdown

- **U1** (keep-id, owned by the caller) owns the network, mount, ipc, uts and
  pid namespaces. **U2** (child of U1) holds the payload, with no capabilities,
  no_new_privs and `user.max_user_namespaces=0`, plus bwrap's
  `--assert-userns-disabled`.
- The payload holds no capability over its own network namespace, even in
  principle. Measured: `nft list/flush`, `ip link add`, route changes and
  `/proc/sys/net` writes get EPERM; `unshare -U`, `-Ur` and `-Urn` get ENOSPC;
  a hook's rules are intact afterwards.
- Today, `unshare -U` works in a session (DESIGN.md measured it). Blocking it
  removes the user-namespace kernel attack surface from the default. The
  default tiers also stack a namespace mask filter, so the refusal is EPERM,
  not ENOSPC, and there are two locks, not one.
- `/proc/1` in the session is tini, not bwrap: bwrap's argv does not leak.
- `/run/wrappers` is not mounted: no setuid binary is reachable, and
  no_new_privs would defeat one anyway.

### flong-init, the gate and readiness

bwrap's own `--block-fd` gate is **fail-open**: the payload runs when the
launcher dies. So flong-init, which bwrap execs as pid 1, is the gate. In
order:

1. `setgroups` from the container's groups; drop the bounding, ambient and
   effective sets (bwrap is given `CAP_SETGID` and `CAP_SETPCAP` for this and
   nothing else).
2. With a relay pty, `TIOCSCTTY`.
3. Reset SIGINT and SIGQUIT to default (a bash `&` hands them over ignored).
4. Write one byte on the ready fd: bwrap has finished building the sandbox.
5. Block on the gate pipe. **EOF exits 125.** The payload never runs if the
   hook fails or the launcher is killed first (measured both).
6. `chdir` to the workspace (it is a helper mount, so bwrap's `--chdir` would
   point at the covered directory), `close_range(3, ~0)`, exec
   `tini -g -- payload`.

The launcher waits for the ready byte before the mount helper and any hook
that enters the mount namespace: without it, a hook ran before bwrap had
finished the root in 179 of 200 concurrent launches. Pasta and hooks that
touch only the network namespace may start at child-pid. The gate opens only
when the helper, the hooks and pasta have all succeeded. The order hook →
pasta → gate is kept, so the hook still sees no route (measured 0, then 2
after pasta).

### Hooks

All hooks run as the caller: `workspace`, `binds`, `guard`, `postStart`,
`postStop`. `SUDO_UID`/`PKEXEC_UID`, `run_as_caller`'s `setpriv` and the root
fallback go.

`postStart` gets:

- `$leader`: the bwrap child pid, from `--info-fd`. This replaces
  `machinectl` and the cgroup walk.
- `$userns`: `/proc/<launcher>/fd/N`, U1, held by the launcher.
- `$netns`: `/proc/<launcher>/fd/M`.

A hook enters with `nsenter --user="$userns" --net="$netns"`, without
`--preserve-credentials`: tools then run as U1 root (a subuid on the host) with
full capabilities in the session. `--preserve-credentials` runs them as uid
1000 with none. nft tables with tproxy, socket, fib and reject, a dummy link,
routes, fwmark rules and `IP_TRANSPARENT` listeners all work, measured. A hook
that enters the mount namespace also enters the pid namespace, or `/proc/self`
does not resolve.

On a fresh VM boot, every nft expression module autoloaded on demand from a
non-init user namespace. No `boot.kernelModules` preload is needed on this
kernel; document an optional preload list for hosts that disable autoload.

Hooks, and anything they start, run in the session cgroup (clone3), so the
teardown kills a hook's daemon. Without a session cgroup, a hook daemon leaks
on every exit: measured.

### Network

- pasta runs as the caller:
  `pasta --config-net --userns /proc/<launcher>/fd/N --netns /proc/<leader>/ns/net --pid /proc/<launcher>/fd/<memfd>`
  plus trunk's `pastaPorts` flags, `--no-map-gw`, `--dns-forward` constants and
  resolv.conf writer, unchanged. The namespace pin, its bind mount, `--runas 0`
  and `umount -l` go.
- `--userns` must name U1, the owner of the network namespace, not
  `/proc/<leader>/ns/user` (which is U2): EPERM otherwise.
- The pid file is a memfd the launcher holds: nothing on disk, and pasta's
  cmdline carries a unique path for identifying it.
- Every trunk feature works, measured: egress, DNS through a loopback resolver
  in either or both families, `hostPorts` with unnamed ports blocked,
  `forwardPorts`, `forwardPorts = "auto"` (including a listener opened after
  start), `hostLoopbackToSession`, and nft rules a hook installed beforehand,
  which pasta leaves alone.
- **Teardown:** pasta takes 20–40 ms to exit, and that is the kernel removing
  its tap device, so SIGKILL does not shorten it. The launcher waits for it
  only when fixed `forwardPorts` bind host ports (11–12 of 20 back-to-back
  relaunches hit `EADDRINUSE` without the wait). `auto`,
  `hostLoopbackToSession` and `hostPorts` bind nothing on the host, so they do
  not wait.
- **Host ports below `ip_unprivileged_port_start`** (1024) cannot be bound by
  the caller: pasta fails at once and the launch fails closed. Refuse them at
  evaluation against `boot.kernel.sysctl."net.ipv4.ip_unprivileged_port_start"`.

### The session cgroup, and opt-in limits

Every session gets its own cgroup, as every session gets its own scope today.
That is mechanism, not policy: it is how a hook's daemon and pasta die with
the session, and how the sweep finds everything a dead session left. **No
limit is set unless the declaration sets one.**

- The module ships a user unit, `systemd.user.services.flong-sessions`
  (`Delegate=yes`, `DelegateSubgroup=supervisor`, a pause program). It is the
  only delegation systemd gives a user: `mkdir` under `user@UID.service` works
  but is not delegated, and the caller's own cgroup cannot enable controllers
  (EBUSY). `OOMPolicy=continue` on it, because systemd's default (`stop`)
  would stop the holder, and so every session, when one session's process
  is OOM-killed.
- The launcher finds the holder's cgroup by path (from `/proc/self/cgroup`),
  not `systemctl show` (7 ms), and starts it on demand if absent (about 7 ms,
  once).
- Each session is `<holder>/<container>/<session>`, with leaf children for the
  sandbox, hooks and pasta. bwrap, hooks and pasta are created in it with
  `clone3(CLONE_INTO_CGROUP)`, never migrated (migration costs 15–30 ms on this
  kernel). 0.2 ms to create, 0.06 ms to kill and remove.
- **Limits are opt-in**, a typed option rendered into cgroup files when set:
  MemoryMax → `memory.max`, MemoryHigh → `memory.high`, MemorySwapMax →
  `memory.swap.max`, TasksMax → `pids.max`, CPUQuota → `cpu.max`, CPUWeight →
  `cpu.weight`, IOWeight → `io.weight`, OOM group → `memory.oom.group`. A
  controller is enabled only when a declared limit needs it. Unset, a session
  is bounded by whatever bounds the caller, as a process the caller runs
  directly would be.
- Worth documenting for whoever sets a memory limit: the overlay upper,
  `TMPDIR`, `/tmp` and the other tmpfs mounts are charged to the session's
  memory, not to disk (measured); and pasta and bwrap's monitor share the
  cgroup with the payload, so the kernel's OOM killer may pick pasta (measured:
  a tmpfs fill killed DNS). Neither is acted on by default.
- **The payload cannot escape or rewrite its cgroup:** the cgroup files are
  the caller's, and the payload is the caller's uid. It holds because cgroup2
  is mounted `nsdelegate` (systemd's default), the cgroup namespace is unshared
  after the process is in the session cgroup, and the cgroup2 view is
  read-only. Measured: a nested user and cgroup namespace mounting cgroup2 at
  the session cgroup gets EPERM on `memory.max`, `pids.max` and
  `cgroup.kill`. The launcher checks `nsdelegate` in `/proc/self/mountinfo`
  and refuses to start without it, since without it a payload could move out
  of the cgroup that reaps it.
- Refused at evaluation, because a user cgroup silently ignores them
  (measured): `AllowedCPUs`, `DevicePolicy`, `DeviceAllow`, `IPAddressAllow`
  and `IPAddressDeny`, `SocketBind*`, `RestrictNetworkInterfaces`.
- `scopeConfig` becomes the typed, opt-in `limits` option.
- Sessions show in `systemd-cgls` and `systemctl --user status
  flong-sessions.service`, not in `machinectl`. `systemctl --user stop
  flong-sessions.service` kills every session.

### No timeouts

Nothing in the engine gives up on a clock, as trunk's hook wait no longer does
(`ffbb78f`). Every wait is on an event, with no timeout: the gate pipe, the
ready byte, a pidfd (`poll` with `-1`), `cgroup.events` (`POLLPRI`), pasta's
exit, the foreground wait (which ends when the kernel reports the group
orphaned, not after a delay). No retry has a cap: the cache's
lock-and-recheck loops until the inode is stable.

The spike prototypes did not keep to this, and their code must not be copied
as it is: `r2-lifecycle`'s launcher caps the cgroup-empty wait at 25,000 polls,
`poll`s the pidfd for 5 s and caps the cache re-exec at 3 tries; `r2-containment`'s
rmdir wait has a 10 s cap.

### Lifecycle

- **Records:** `$XDG_RUNTIME_DIR/flong/sessions/<machine>`, one per session and
  per user, so any launch sweeps any dead session. Created as `.<machine>` with
  `O_EXCL`, locked with `flock`, filled with `poststop=<store path>` and
  `cgroup=<path>`, renamed into place. `leader=<pid>:<starttime>` is appended
  once bwrap reports its child. The record exists before the cgroup and before
  the hook, so `postStop` runs even for a launcher killed mid-hook, and must
  stay idempotent.
- The lock lives only in the launcher. bwrap's monitor closes inherited fds,
  and a lock inside the sandbox would be in the payload's reach.
- **Liveness:** a session is dead only when its lock is free *and* its
  recorded pid 1 has exited (pidfd, starttime checked). A lock alone is
  granted 1–1.5 ms before the session's last process is gone (20 of 20 runs);
  lock plus pidfd gave 0 of 20.
- **Teardown order:** bwrap exits → `cgroup.kill` → wait for the non-pasta
  leaves to empty → `postStop` → wait for the pasta leaf only for fixed
  `forwardPorts` → `rmdir` → unlink the record.
- **The sweep** runs inline at launch start (20 µs when there is nothing to
  do) and in the holder unit's process (inotify on `sessions/` plus a lock
  attempt), so a killed launcher's `postStop` and hook daemons do not wait days
  for the next launch. For each dead record: kill the cgroup, wait, run
  `postStop`, unlink. Ten concurrent sweepers ran a dead session's `postStop`
  exactly once.
- **The sweep is defensive, because records are now the caller's files:**
  it `chdir`s to `/`, gives `postStop` `/dev/null` for stdin and a fixed
  environment, runs only an executable `/nix/store` path, requires `cgroup=`
  to sit under the holder's prefix and `leader=` to match its starttime.
- **Sessions do not outlive their launcher.** `--die-with-parent` ends the
  payload about 1.5 ms after a launcher SIGKILL. Today a session survives its
  launcher in its scope; that state no longer exists, and the sweep never
  needs to decide about a live session with a dead launcher.
- **Cache liveness:** every launcher holds a shared `flock` on its cache
  directory for its life, re-checking after locking that the path still names
  the inode it locked and that the inode holds the prepared root: a cache the
  sweep took away may have been made afresh at the same path by a wrapper that
  is still preparing it, whose shared lock is granted beside the launcher's.
  Either answer sends the launch back through the wrapper. The sweep of a
  superseded cache takes it exclusively, renames the cache to `.trash.*` and
  deletes it through the namespace. Deleting a live overlay lower breaks the
  session; renaming it does not (measured).
- **No user manager** (no `XDG_RUNTIME_DIR`, no linger): if `/run/user/$UID`
  exists and is the caller's, use it; otherwise fail loudly, naming
  `users.users.<name>.linger`. A system unit with `User=` uses its own cgroup
  when it has `Delegate=yes` (and `DelegateSubgroup=` for declared limits). No
  `~/.cache` fallback: records must reset at boot, and there would be no
  session cgroup to reap hook daemons.

### Terminal

- **Relay a pty when stdin and stdout are both terminals**, which is
  `--console=autopipe`'s condition on trunk today. flong-launch allocates the
  pty on the host devpts before bwrap, copies termios and window size, and
  relays; bwrap gets `--new-session` and flong-init does `TIOCSCTTY`. The
  caller's terminal is raw only between gate-open and payload exit. SIGWINCH,
  SIGTERM, SIGHUP, SIGINT and SIGCONT are handled; EINTR is retried. A
  launcher started in the background waits for the foreground first, and
  gives up if its group is orphaned. A watchdog child restores the terminal
  after a SIGKILL. nspawn's `^]^]^]` escape stays.
- Measured: launch cost within noise (15.5 against 15.4 ms), about 10 µs per
  keystroke round trip, throughput within noise. Passthrough, by contrast,
  kills an interactive caller's bash when started with `&`, leaves a caller
  without job control in the background of its own terminal, and leaks terminal
  modes the payload set.
- **Otherwise fds 0–2 pass straight through**, so `echo prompt | launcher`
  keeps working, and afterwards the launcher hands the foreground back and
  restores termios. No `--new-session` in that mode: it breaks ^C, SIGWINCH
  and job control.
- **A fixed tty filter in every tier**, which no tier or project can remove:
  `ioctl` with request `TIOCSTI`, `TIOCLINUX`, `TIOCSETD` or `TIOCCONS` →
  EPERM, compared with `masked_eq` on the low 32 bits. A plain `eq` rule is
  bypassed by setting bit 32: in a VM with `dev.tty.legacy_tiocsti=1`, that
  bypass injected `echo INJECTED` into the caller's shell, and `masked_eq`
  stopped it. The payload holds the caller's real terminal whenever stdin is a
  tty and stdout is not, and flong does not control that sysctl.
- Trunk's carriage-return wrapper (`dbc7ee9`, `sed -u 's/$/\r/'`) goes: hooks
  now always print to a cooked terminal.

### Seccomp

**The compiler** is C against libseccomp, about 75 lines, reading a line
format Nix renders (`default ERRNO|allow`, `allow NAME [aN:op:value[:mask]]`,
`errno N NAME…`, `log NAME`). It refuses a syscall named twice, an
unconditional rule combined with any other rule for the same number, and `eq`
on an int-typed argument (it requires `masked_eq`). libseccomp silently keeps
the first of two rules and lets an unconditional rule cancel conditional ones.
It reports the count of names libseccomp does not know, so version skew shows
in the build log.

**Groups** are expanded at build time from one
`${config.systemd.package}/bin/systemd-analyze syscall-filter` call and an awk
expander. That works in the Nix build sandbox and matches the host's own
groups. An unknown group fails the build.

**The filter stack**, each passed with a repeated `--add-seccomp-fd` (bwrap
refuses it together with `--seccomp`):

1. The tier's allow-list: ALLOW the names, ERRNO(EPERM) for the rest of
   `@known`, ERRNO(ENOSYS) by default, on x86_64, i386 and x32.
2. The audit mask: `socket(AF_NETLINK, …, NETLINK_AUDIT)` → EAFNOSUPPORT, with
   `masked_eq` (nspawn's own is bypassable with high bits; flong deliberately
   exceeds parity here).
3. The tty filter (above).
4. The namespace mask (clone and unshare with `CLONE_NEW*` → EPERM, `clone3`
   → ENOSYS, setns → EPERM), except under `nestedSandbox`.

**Tiers:**

- `parity`: exactly what nspawn installs for flong today, 409 names on systemd
  260.2. Proven exact in a VM: the live filters of an nspawn session and of
  the new engine, dumped with `PTRACE_SECCOMP_GET_FILTER` and evaluated over
  every syscall on all three arches with argument sweeps, match except four
  i386 rows where the new filter is stricter.
- `strict` (**the default**): parity minus `@keyring`, `userfaultfd`, `@mount`,
  `io_uring_*`, `ptrace` and `process_vm_*`: 387 names. Measured under the real
  chain: node, python (venv, pip, multiprocessing), git, go (including
  `-race`), cargo, gcc, make, java, tmux and the claude and codex CLIs behave as
  under parity. strace and gdb break. node tries io_uring and falls back
  silently.
- Loosenings, combinable: `debug` adds `ptrace` (enough for strace and gdb,
  reach limited to the session's pid namespace). `nestedSandbox` raises U2's
  `max_user_namespaces`, drops the namespace mask and allows `@mount`, which
  Chromium's own sandbox, `codex sandbox` and nested bwrap need; all three are
  needed together. With it, the payload still cannot touch the session's
  network namespace: measured.
- Headless Chromium works under `strict` with `--no-sandbox`, Playwright's
  default. The nixpkgs chromium wrapper looks for a setuid sandbox in
  `/run/wrappers`, which is absent: a consumer running it sets
  `CHROME_DEVEL_SANDBOX` empty. flong sets nothing for it.

**The option** (shape to settle in phase 3):

```nix
flong.<name>.seccomp = {
  tier = "strict";              # or "parity", or null for no allow-list
  debug = false;                # + ptrace
  nestedSandbox = false;        # nested userns, no namespace mask, @mount
  allow = [ ];                  # names or @groups, added
  deny = [ ];                   # names or @groups, removed; a set difference in Nix
  errno = "EPERM";              # for known calls not allowed
  log = false;                  # denied calls allowed but logged, for learning a policy
};
```

The audit and tty filters are not options. The namespace mask follows
`nestedSandbox`.

**Per project:** a filter is loaded by bwrap before the payload execs, so a
project's policy must be known before bwrap starts. Today chase evaluates a
project's envelope in `postStart`, which is too late. So flong gains a
pre-launch snippet, `seccompPolicy`, run as the caller after `guard`, that
prints extra `allow`/`deny` lines. chase evaluates the envelope there, sends
any loosening through its approver, and prints the result. flong compiles it
at launch, cached by content hash at
`$XDG_RUNTIME_DIR/flong/seccomp/<hash>.bpf`: measured 37 ms cold, a hash when
warm. A launch with no project policy compiles nothing. The compiler, the group
dump and the expander ship as store paths; `systemd-analyze` is never called
at launch.

### `/sys`, `/tmp`, `/dev`

- **`/sys`:** a fresh read-only sysfs (U1 owns the network namespace, so it
  shows only the session's interfaces) and a read-only cgroup2 view of the
  session cgroup. The kernel refuses a fresh sysfs unless one is already
  visible, so bwrap binds the host's at a scratch path, and the mount helper
  mounts the fresh one and detaches the scratch before the gate. 0.1 ms in C
  (9 ms through nsenter and sh). With it, `nproc`, Go, Node and Java honour
  declared limits; without it `lscpu` fails.
- **`/tmp`:** a fresh 1777 tmpfs, charged to the session. `TMPDIR` stays
  `$home/tmp`.
- **`/dev`:** bwrap's minimal set. `/dev/mqueue` can be mounted from U1 if
  wanted (`mq_*` works without it). Device nodes need `--dev-bind`: a plain bind
  is nodev (EACCES on `/dev/snd`, measured). `allowedDevices` becomes a list of
  `--dev-bind` nodes; access is the caller's own host permission (the logind
  ACL on `/dev/snd`, `/dev/kvm` being 0666 on NixOS). The `r`/`rw` modifier
  cannot be enforced and `m` is meaningless: accept `rw` only.

### Options and declaration fields

| | becomes |
|---|---|
| `container`, `user`, `command`, `path` | unchanged; `user` no longer needs the caller's uid |
| `workspace`, `binds` | unchanged contract; a plain `bash -c` as the caller |
| `guard` | kept; runs as the caller; documented as a consistency check |
| `postStart` | as the caller; gains `$userns`; `$leader` is bwrap's child |
| `postStop` | as the caller; run from the record by the sweep after a SIGKILL |
| `network` and its ports | unchanged; ports below 1024 refused |
| `overlays`, `masks` | unchanged interface; through the fd walker |
| `scopeConfig` | replaced by typed `limits` |
| `seccomp`, `seccompPolicy` | new |
| `bindMounts` | through the fd walker; the source must be reachable by the caller |
| `tmpfs` | through the walker; only `mode=` and `size=` (or uid/gid equal to the user) |
| `allowedDevices` | `--dev-bind` of each node, `rw` only |
| `extraFlags` | refused, all of it (no nspawn) |
| `networkNamespace` | refused: a caller cannot join a namespace the initial user namespace owns |
| `privateUsers`, `additionalCapabilities`, `enableTun`, `hostBridge`, addresses, `interfaces`, `macvlans`, `extraVeths`, `flake` | still refused |
| `launcher` | run directly, no sudo |

### The security boundary

For the threat model *the payload is an untrusted coding agent*, the review
after round two judged the boundary at least as strong as today's, and
stronger in places, **only with every condition below adopted**.

**Stronger than trunk:**

- No root anywhere, and no sudo grant.
- Nested user namespaces are off by default. Today `unshare -U` works in a
  session.
- The payload holds no capability over its network namespace.
- The tty and audit filters use `masked_eq`; nspawn's audit mask is
  bypassable.
- Mount destinations refuse symlinks everywhere; trunk refused only in home,
  and nspawn follows them inside binds.
- Sources resolve with the caller's reach, not root's.
- The ready-marker symlink class (DESIGN §"The payload waits for the hook")
  is gone with the marker.

**Equal:** seccomp parity (exact), the payload's host identity and its bind
set, the interactive terminal (its own pty).

**Conditions:**

1. Every flong-level mount goes through the fd walker.
2. Caller and workspace sources are opened with `RESOLVE_NO_SYMLINKS`.
3. Every session has its own cgroup, with `nsdelegate` checked and the
   cgroup2 view read-only.
4. **No session can reach flong's state or frisket's control socket.** Both
   are now the caller's files: a payload that could write a record would get
   the sweep to run a store program of its choice as the caller, in its
   working directory, or `cgroup.kill` any of the caller's cgroups. Refuse,
   at evaluation and at launch, any bind equal to, inside or containing
   `$XDG_RUNTIME_DIR/flong`, the holder's state or frisket's socket directory.
   The sweep's defences above are the second line.
5. The tty filter is in every tier, including a project-loosened one.

**Weaker, accepted and documented:**

- The prepared root's and the records' integrity falls from root to the
  caller: anything running as the caller outside a session can poison later
  sessions.
- After a launcher SIGKILL, hook daemons and frisket's listeners last until a
  sweep; the holder unit's sweeper keeps that short.
- Hook daemons of different sessions share one subuid, so they can signal each
  other. Hooks are trusted code.
- `nestedSandbox` reopens user-namespace kernel surface for the containers
  that opt in.

**Known behaviour differences:**

- Host-root-owned files (`/nix/store`, `/nix/var/nix/db`) read as
  `nobody:nogroup` inside. ssh refuses NixOS's store-owned `Include` of
  `20-systemd-ssh-proxy.conf`: containers set
  `programs.ssh.systemd-ssh-proxy.enable = false`, or bind an alice-owned copy
  of a store-symlinked config with `--ro-bind-data`. Idmapped mounts are EPERM
  rootless.
- `nix` inside a session stays unsupported (it is today). A read-only local
  store misses paths registered after the database's last checkpoint.
- `journal-nocow` tmpfiles rule is skipped at prepare (uninitialised
  `/etc/machine-id`); running machine-id setup first would fix it, cosmetic.
- The session's `/` is owned by the payload's user (the overlay upper's root):
  it can create top-level entries in its own session only.

## Phases

Each phase ends with its acceptance tests passing. The old engine stays
working until phase 7, so the two can be compared.

### Phase 1: one integrated launcher

The spikes each changed their own copy of `flong-launch.c` and `flong-init.c`.
Compose them into one, with one cleanup path for early errors, in the repo
(`launcher/flong-launch.c`, `launcher/flong-init.c`, `launcher/flong-mount.h`,
built with `runCommandCC`), driven by a hand-written test wrapper.

Order inside a launch: sweep → record → U1, U2 → cgroup → bwrap (clone3) →
child-pid → pasta may start → ready byte → mount helper, `/sys` → hooks →
pasta ready → gate → wait → teardown.

Also: `close_range` before every spawn (the prototype leaked bash's fd 9 into
hooks and pasta); state directory 0700 checked; the pty relay and watchdog;
the no-user-manager path; the holder unit started on demand.

**Accept:** every spike's repro reruns green against the integrated launcher:
`race.sh` and `escape.sh` (mounts, 0 escapes), the lifecycle suite e1–e4,
containment's interleave and cgroup tests (with the caps noted under
No timeouts removed), `interactive.py` across modes,
compat's `matrix.sh`, the network and frisket hooks. Numbers within 10% of the
table above.

### Phase 2: the module

Rewrite `mkLauncher`: the bash wrapper keeps `workspace`, `binds` and `guard`,
reads passwd, group and the subordinate ranges, builds the NUL-separated mount
spec and argv, and execs flong-launch. Rootless prepare, the cache and its
locks. The holder unit. `limits`. Evaluation refusals (`extraFlags`,
`networkNamespace`, the ignored cgroup properties, tmpfs options, ports below
1024, binds covering flong's state, masks two levels deep if so decided).
Assertions that the host has `security.allowUserNamespaces` and newuidmap.
The OSC 666 `vte.container.runtime` value changes from `systemd-nspawn`.

**Accept:** a launch as a lingering user with no sudo rule runs the sample
container, with and without network and hook.

### Phase 3: seccomp as policy

The compiler, the build-time tier pipeline, the `seccomp` option, the fixed
filters, `seccompPolicy` and its cache. Chase sets a tier per chase tier
(trusted: `strict` with `debug`; strict: `strict`).

**Accept:** per-tier and per-project subtests; a strict session runs the
tools matrix; `log = true` produces a usable learned policy.

### Phase 4: the test suite

Rewrite `tests/basic.nix` to launch as a lingering alice:
`systemd-run -M alice@ --user --wait --pipe --quiet --collect --expand-environment=no -- bash -c …`
with an explicit `PATH`, `users.users.alice.linger = true`, explicit
`subUidRanges`/`subGidRanges`, `wait_for_unit("user@1000.service")`, no
`security.sudo` rules, hook fixtures writing under `/tmp`. The driver stays
root and can still read a session's ruleset from outside.

The 74 trunk subtests, classified in
[`spikes/rootless/spike-migration/map.md`](spikes/rootless/spike-migration/map.md)
(with the lifecycle spike's corrections):

- **45 keep**, unchanged or with new paths.
- **23 adapt**, the property holds but the assertion is root- or
  nspawn-shaped: `machinectl`, `machine.slice`, `/run/flong`, the pin, hooks
  as root.
- **6 retire**: extraFlags reaching nspawn, a SIGKILLed session's machine name
  (unix-export), the sudo grant, the root fallback, the two ready-marker tests.
- One **inverts**: "the sweep leaves a session whose launcher was killed but
  whose container is alive" becomes "a SIGKILLed launcher takes its payload
  with it" and "the sweep never releases a session whose lock is held".

New subtests:

- launched with no sudo rule; no session process, hook or pasta has host uid
  0; the uid map never maps host 0; a caller without a subuid range is
  refused, and so is uid 0;
- nested user namespaces refused; seccomp applied; two tiers differ on one
  syscall (`strace true` works with `debug` and gets EPERM under plain
  `strict`); a project policy compiles and applies;
- the hook runs as the caller and the payload cannot undo it, with and without
  `nestedSandbox`;
- the gate: a failing hook and a hook-time launcher SIGKILL both mean the
  payload never runs; routes at hook time 0, at payload start 2;
- mounts: the swap race (0 escapes), the symlink-in-the-root case, mask
  bypass at depth 1 held;
- lifecycle: a hook daemon dies with the session on clean exit, SIGTERM and
  SIGKILL + sweep; ten concurrent sweepers run `postStop` once; ten concurrent
  cold launches; a superseded cache a live session uses is kept; no user
  manager fails loudly; a system unit with `Delegate=yes` gets its declared
  limits;
- the session cgroup: with no `limits` declared, no limit file is written
  and no controller enabled; declared limits are applied; the payload cannot
  write its cgroup files or move out of it (`nsdelegate`), including under
  `nestedSandbox`;
- no timeouts: a `postStart` that sleeps for longer than any plausible
  timeout still gates the payload, and the payload then runs;
- a bind covering `$XDG_RUNTIME_DIR/flong` is refused;
- terminal: TIOCSTI with bit 32 set refused, in a VM with
  `legacy_tiocsti=1`; ^C returns 130 under a pty and in a pipeline;
- `forwardPorts` below 1024 refused at evaluation.

Keep the suite affordable. The launch cost falls about sevenfold; the new
fixed cost is waiting for the user manager.

**Accept:** the suite passes on the new engine, and the kept and adapted
subtests still pass on the old one where they apply.

### Phase 5: parity and numbers, before anything is deleted

In one VM, with both engines: the syscall probe and the live filter dump,
diffed (the spike's `probe.c` and `bpfdump.c`); and like-for-like timings with
the same payload and features. These numbers replace this file's tables in
the README and DESIGN.md.

### Phase 6: consumers

- **frisket** carries the rootless patch
  ([`spikes/rootless/r2-consumers/frisket-rootless.patch`](spikes/rootless/r2-consumers/frisket-rootless.patch),
  186 lines, measured end to end in both the `all` and `service` sets): every
  step that enters the sandbox re-executes under an absolute-path
  `nsenter --user=$userns --net=$netns` (Go cannot `setns(CLONE_NEWUSER)`,
  EINVAL even in `init()`, and frisket builds without cgo); the CA tmpfs is
  made after entering the mount namespace; the control socket is owned by the
  daemon's user with `-control-uid`. Its VM test runs the launcher as a user.
  Later, collapse steer and connect into one nsenter'd process to cut the
  38 ms.
- **chase:** `selector.nix` drops sudo in both branches and
  `security.sudo.extraRules`, and rewrites the guard comment.
  `project/default.nix` drops `setpriv --init-groups` from `postStart` (it
  fails unprivileged). Its envelope's seccomp section is evaluated and
  approved in `seccompPolicy`, before bwrap starts; the rest of the envelope
  stays in `postStart`.
  Tiers set `seccomp`: trusted gets `debug = true`, strict stays plain
  `strict`. Chase's PLAN decision 2 is rewritten: a launcher now
  has exactly the caller's privilege, and the approver is the gate.
- **nix-config:** `audio.nix` drops the `/dev/snd` bind and keeps
  `allowedDevices` (now `--dev-bind`); comments in `gnome.nix`, `dragoman.nix`.
  Containers set `programs.ssh.systemd-ssh-proxy.enable = false`.

The full file:line list is in the migration map and the consumers spike.

### Phase 7: delete the old engine

Only when phases 1–6 pass. From `module.nix`: `uidFlag`, `nspawnPath` and
`nspawn_path`, `extraFlagWords` and the privileged-flag refusal list,
`deviceProps`, `capabilityFlags`, `networkFlags`, `resolvConfFlag`, `pinDir`
and the pin, the nspawn and machinectl paths, `is_leader`/`find_leader`, the
gate marker, `session_live`'s machinectl branch, the unix-export and
propagate sweep, `chattr`, `SUDO_UID`/`PKEXEC_UID` and `run_as_caller`, the
carriage-return wrapper. Check whether `boot.enableContainers` is still
needed for `containers.<name>` to exist.

### Phase 8: documentation and baggage

- **README:** the introduction and Terms (no nspawn, no root, the new
  numbers); `sudo <launcher>` becomes `<launcher>`; "A session with a root
  hook" becomes a caller hook with `nsenter --user --net`; "Running the
  launcher" is rewritten (a subuid range, newuidmap, a user manager or linger;
  `guard` as a check); the options and hooks tables; Inside a session (user
  namespaces off, seccomp, the uid map); the declaration table; Limitations
  (the user namespace is now the rule; `machinectl shell` and `terminate`
  become `systemctl --user` and `nsenter --user`; ports below 1024;
  ownership inside). `flake.nix`'s description.
- **DESIGN.md:** rewrite the engine's account from this file's design section,
  keeping DESIGN's voice: launch sequence, the prepared root, identity, hooks,
  mounts and the walker, topology and lockdown, the gate, the network,
  containment, the lifecycle, the terminal, seccomp. Delete "nspawn
  invocation", "The namespace pin", "Finding the leader", the marker section,
  and every "as root".
- **PLAN.md:** its tests list loses the root-hook and `unshare -Ur` wording.
  §1 becomes phase 9 below.
- Delete this file and `spikes/rootless/`.

### Phase 9 (later): a uid range per session

What PLAN.md §1 was reaching for, now one layer up: each session maps to its
own slice of the subordinate range (nspawn's managed mode, or a flong-managed
allocation), so an escape lands on a uid that owns nothing of the caller's.
The workspace then reaches the caller's uid through an idmapped mount, which
is EPERM rootless today, so this needs `systemd-mountfsd`/`nsresourced` or a
kernel that allows it. Spike it then.

## Open decisions

Each has a recommendation; none blocks phase 1.

1. **Masks two or more levels below a writable bind root:** refuse at
   evaluation (recommended), or offer a "pin" that binds every directory on
   the way onto itself, which makes them un-renamable in every session.
2. **A symlink on the way outside home, on the session's own mounts** (an
   `/etc/static`-style path): refuse everywhere (recommended; simpler and no
   consumer declares one) or follow with `RESOLVE_IN_ROOT` there.
3. **An opt-in size for the session root:** unbounded unless declared, like
   the rest. If wanted, a `rootSize` option needs the 69-line bwrap patch that
   honours `--size` for `--tmp-overlay` (ENOSPC instead of an OOM kill under
   a memory limit), carried or upstreamed.
4. **An opt-in `oomScoreAdj`**, for whoever sets a memory limit and wants the
   payload, not pasta, to be the victim. Only if someone asks.
5. **`hostGroups`:** only if a consumer needs a group-gated device without a
   logind ACL. Audio works through the ACL while the caller holds the seat
   (unverified over SSH).
6. **frisket's daemon:** keep it a system unit with `User=` and change the
   socket owner (recommended; keeps its hardening and fd store), or move it to
   a user unit.
7. **frisket's control socket peers:** file ownership alone, or also check
   the peer is in the initial user namespace (recommended, cheap, defence in
   depth for condition 4).
8. **Pasta in parallel with the hook:** saves about 10 ms but gives up the
   "no route at hook time" assertion. Recommended: keep it sequential.
9. **32-bit syscalls:** filter i386 and x32 (parity, recommended) or refuse
   foreign architectures outright (compile 4× faster, no i686 binaries).
