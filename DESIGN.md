# Design

Why flong works the way it does, for anyone changing it. Terms (prepared root,
session, launcher, workspace, payload, hook) are as defined in
[README.md](README.md). Work not yet built is in [PLAN.md](PLAN.md).

Measurements were taken in NixOS VM tests against this flake's nixpkgs
(systemd 261.2, nftables 1.1.7, passt 2026_07_16, kernel 6.18.51), in flong's
invocation shape: `systemd-run --scope` around `systemd-nspawn
--private-network --uid=…` with a prepared root. Startup timings were taken
warm on one machine.

## Launch sequence

1. `workspace`, then `extraBinds` and `extraBindsRo`, as the invoking user.
2. `guard`, as root.
3. Prepare the root if this closure has none yet.
4. Read `user`'s uid, gid and home from the prepared root's `/etc/passwd`.
5. Sweep: release what dead sessions of this container left behind.
6. `cp -a` the prepared root to `/run/flong/<cache>/s-<machine>`. The machine
   name is `<container>-<launcher pid>-<random>`.
7. Write the session's `resolv.conf` (with `network`), create mount points,
   arm the exit trap.
8. `attachBinds`, then `attachWrap`, as root.
9. Start `systemd-run --scope … systemd-nspawn …` in the background.
10. Find the session's leader, run `postStart`, then start pasta (with `network`),
    then create the readiness marker.
11. Wait for the session. The exit trap runs `postStop` and releases the rest.

## Sessions are copies of a prepared root

| approach | time to first output |
|---|---|
| [`extra-container`](https://github.com/erikarvstedt/extra-container), evaluating a config per launch | 4943 ms |
| a declared container, its `.conf` rewritten per launch | 2213 ms |
| flong: nspawn against a prepared root | 117 ms |

**Nothing is evaluated at launch.** About 2.5 s of the slower cases is Nix
evaluation. `nixos-rebuild` builds the closure once, and the launcher is
generated at the same time with the declaration's mounts and flags already in
it. Everything else a session gets is computed at launch by the hooks.

**The declaration is read as data.** `bindMounts`, `tmpfs` and `extraFlags`
are read as the option values they are, at evaluation, and each path is passed
to nspawn as one argument. The container module's own rendering of the same
options is a string its unit splices into a shell command unquoted, where a
path with whitespace splits into two valid, wrong flags. nspawn itself
expresses any path: `--bind`, `--tmpfs` and `--overlay` split on `:` and treat
a backslash as an escape for the next character, so flong writes `\:` and `\\`
and every other character as itself. Nothing in a declared path is refused.
`extraFlags` entries are split on whitespace, as the container module's unit
splits them, so one entry can still carry several flags.

A `tmpfs` entry is already in nspawn's `PATH[:OPTIONS]` syntax, and flong reads
the path out of it the way nspawn does. A colon in a tmpfs path would need
`\:` in the declaration, which nixpkgs cannot build: its `container@` unit
splices the list into a script, and shellcheck refuses the escape.

**Nothing boots.** Booting the container's systemd costs 1.23 s across about
thirty units, to run one process. What boot provides that a session needs is
the `/etc` the activation script writes: `passwd`, `group` and `shadow` are not
in the closure, so a rootfs assembled from the store cannot resolve a username.
flong runs `activate` once into a prepared root under `/run`, and each session
copies it in about 3 ms.

**The store is shared.** `/nix/store` is bind-mounted read-only, so a package
set costs nothing to ship. Every session can read every store path on the host.

### Preparing the root

Preparation runs as root, which a session never has, and once per prepared
root:

- `activate`, then `systemd-tmpfiles --create --exclude-prefix=/dev`. No unit
  ever starts in a session, so without this a container's tmpfiles rules do
  nothing (for example, `programs.nix-ld`'s `/lib64/ld-linux-x86-64.so.2` would
  be missing). `/dev` is excluded because `allowedDevices` decides device
  access. `--boot` is omitted because boot-only rules assume a boot sequence
  that later undoes them, such as `/run/nologin`.
- `/etc/resolv.conf` is removed, so the root does not carry the host's DNS
  from the moment it was prepared.
- `systemd-machine-id-setup` writes `/etc/machine-id`, which a container's init
  would otherwise write. Failure is tolerated.
- The user's home is created, for accounts declared with `createHome = false`.

The cache directory is named for both the closure hash and a hash of the
prepare steps and identity reader. Keying on the closure alone would keep
using a warm cache after the prepare steps change. Preparation happens in a
`mktemp` directory and is published with an atomic `mv -T`; a launch that loses
the race discards its copy. NixOS declares `h /var/empty - - - - +i`, so the
immutable attribute is cleared with `chattr -R -i` before a prepared root is
deleted. `cp -a` does not copy inode flags, so session roots need no such step.

## Identity is read, not declared

`user` is the only identity option. The uid, gid and home are read at launch
from the prepared root's `/etc/passwd`, which is the file nspawn resolves
`--uid` against. There is no second copy to drift: the launcher creates
`TMPDIR`, tmpfs mounts and overlay upper layers with the same numbers nspawn
uses. Reading also covers what evaluation cannot see: a container declared by
`path` has no configuration, and an unset `users.users.<name>.uid` is allocated
during activation.

The uid is shared with the host, because sessions have no user namespace. A
bind mount carries host uids, so `user` must have the invoking user's uid to
write the workspace. flong cannot check this, because nothing in the container
knows who will invoke the launcher.

`privateUsers` is refused because a bind-mounted file owned by a host uid maps
to an unmapped uid inside, so reads fail with `Permission denied`.
`--private-users-ownership=map` does not change this on kernel 6.18. nspawn's
per-bind-mount idmapped mounts are the likely route; see PLAN.md §1.

## `workspace` runs as the caller, `guard` as root

`workspace` runs first, as `SUDO_UID` or `PKEXEC_UID`, and as root only when
no unprivileged caller exists (a launcher started by a unit). It runs `git` in
a directory the caller chose, and git reads configuration from the repository
it is pointed at. The answer is the caller's to give, so running it with the
caller's privilege loses nothing and avoids git-in-a-hostile-checkout
privilege escalation. sudo sets `SUDO_UID` itself, so a caller cannot unset it
to get root. The gid comes from the passwd database, since pkexec does not set
`SUDO_GID`.

The printed path is resolved with `realpath` before it is validated, so what
is checked is what is mounted. `:` and newlines are refused because `--bind`
has no escaping.

`guard` runs second, as root, with `$workspace` set. It judges the directory
that will be mounted, rather than re-deriving one from `$PWD` and agreeing with
the mount only by coincidence. It stays root because a gate the caller can
`ptrace` or `LD_PRELOAD` is not a gate. `$extra_binds` and `$extra_binds_ro`
are in scope because they are mounts the caller chose; a guard that reads only
`$workspace` admits them unexamined. The cost of this order is that a refused
caller has already run `workspace`, as themselves, which gains them nothing.

`guard` runs in a subshell, as the other root hooks do. Its exit status is its
verdict and nothing more: `exit 0` allows the launch rather than ending the
launcher with nothing launched, and an assignment to `$workspace` cannot change
what is mounted after it was judged.

## Mounts

- **tmpfs ownership.** A bare `--tmpfs` is root-owned 0755. An unprivileged
  payload cannot write it and most programs treat an unwritable cache as an
  absent one, so the failure is silent. Each entry defaults to
  `mode=0755,uid=<uid>,gid=<gid>`.
- **`XDG_RUNTIME_DIR`.** `/run` is nspawn's tmpfs, created at every start, and
  nothing in the session can create a directory in it. The launcher mounts
  `/run/user/<uid>` at 0700, owned by the user, unless the declaration's
  `tmpfs` names it,
  because tools reject a root-owned 0755 runtime directory without saying why.
- **Overlay upper layers** live inside the session root, not in nspawn's
  default location under the host's `/var/tmp`, which a SIGKILL would leak.
  The upper layer is owned by the user; the merged directory takes its owner
  from the lower one.
- **Static mounts are the declaration's.** Every mount known at evaluation,
  bind or tmpfs, is declared on `containers.<name>`, in the vocabulary NixOS
  already has for it. flong adds only what is known at launch (the workspace,
  the caller's `binds`, a root hook's binds) or has no declaration form
  (`overlays`, whose upper layer flong places and owns).
- **Mount order.** nspawn sorts custom mounts by destination, so a tmpfs can
  mask part of a bind mount and a bind mount can reach through a tmpfs. A
  single socket can be exposed from an otherwise masked directory this way.
- **Read-only binds** stop writes, not execution. They are for reference
  material, not for making untrusted directories safe.

## What flong honours from the declaration

A refused option is never dropped silently. Each refused option declares less
privilege than the default (a user namespace, fewer capabilities, a network of
its own), and a container that silently differs from its declaration is worse
than one that fails to build.

- `flake`: such a container's path is a per-container profile that only the
  `container@` start script creates, so there is nothing to prepare.
- `privateUsers`: see above.
- `additionalCapabilities`, `enableTun`: nothing in a session holds a
  capability. nspawn switches to `user` before starting pid 1, so no process
  exists for a capability to belong to. A tun device a session needs has to be
  created on the host and moved in.
- `--capability`, `--ambient-capability`, `--private-users`, `-U` in
  `extraFlags`: each returns something flong withholds. A user namespace of the
  container's own would make it the owner of the session's network namespace,
  which is the property that stops the payload undoing a `postStart` hook.
- `hostBridge`, addresses, `forwardPorts`, `interfaces`, `macvlans`,
  `extraVeths`: each is fixed per container, and one declaration runs many
  concurrent sessions. Two sessions would claim one address or one host port.
  `network` configures networking per session.

## nspawn invocation

- **Absolute paths** to `systemd-nspawn`, `systemd-run`, `machinectl` and
  `systemctl` under `/run/current-system/sw/bin`. sudo resets `PATH` to
  `secure_path`, and a copy from `pkgs` could differ from the systemd running as
  pid 1.
- **`--keep-unit`** inside `systemd-run --scope --unit=<machine>
  --slice=machine.slice`. Without it nspawn creates its own scope and the
  `--property` flags apply to nothing. `--slice` on nspawn is ignored under
  `--keep-unit`, so it goes on the scope. `machine.slice` is where `container@`
  would put it, so slice limits and `systemd-cgls` cover sessions.
- **tini as pid 1**, not `--as-pid2`: nspawn's stub init reaps orphans but does
  not forward SIGTERM.
- **`--uid`**, so nspawn switches user before pid 1 and nothing in the session
  is root. It initialises supplementary groups from the container's
  `/etc/group`. `--user` is deprecated in systemd 261. nspawn resolves the name
  by running `getent` inside the container root, which works only because the
  closure is bind-mounted at `/run/current-system` and `PATH` names
  `/run/current-system/sw/bin`. `/run` is nspawn's tmpfs, so the symlink
  `activate` wrote is gone by then.
- **`--console=autopipe`.** The default is `read-only` without a terminal,
  which never reads stdin, so `echo prompt | launcher` would get an empty
  stdin. autopipe keeps a pty when there is a terminal and otherwise passes the
  file descriptors through. The payload then holds the caller's own stdout and
  stderr and can write escape sequences to a shared terminal, as any program
  the caller runs can.
- **`--hostname=<container>`**, because the machine name changes per session.
- **OSC 666 `vte.container.*` termprops** tell a VTE terminal it is attached to
  a container, as toolbox and distrobox do. ST-terminated, since VTE rejects
  the BEL form. Written only when stdout is a terminal, and reset on exit.

## The launcher owns its session

nspawn starts in the background, so the launcher can act between namespace
creation and the payload starting. stdin is passed explicitly on fd 3, because
bash gives an asynchronous command `/dev/null` otherwise. A script has no job
control, so nspawn stays in the terminal's foreground process group and an
interactive session still reads the keyboard.

On SIGHUP, SIGINT or SIGTERM the launcher stops the session, waits for it, and
only then releases what it depends on. Releasing first would run `postStop`,
remove the namespace pin and delete the root under a running session. The
launcher runs `systemctl stop <machine>.scope` and also signals its
`systemd-run` child, because until that child has registered the scope and
exec'd nspawn there is no scope to stop. The signals are trapped explicitly
(`exit 129`, `130`, `143`), so the EXIT trap runs as ordinary code after `wait`
is interrupted, not from inside bash's fatal-signal handler. After a normal
`wait` the child's pid is cleared, since a reaped pid may belong to another
process.

SIGKILL runs no trap. `systemd-run --scope` makes the payload a child of the
scope, not of the launcher, so the session keeps running. The sweep releases it
once it stops.

## Liveness and the sweep

What a session leaves outside itself (its root, nspawn's
`/run/systemd/nspawn/<machine>/unix-export` mount and
`/run/systemd/nspawn/propagate/<machine>` directory, the namespace pin, pasta,
and whatever `postStop` releases) is released by one function, called from two
places: the exit trap, and the next launch's sweep. A leftover `unix-export`
mount is not reusable: nspawn refuses to start a machine whose mount point
already exists.

**The sweep leaves live sessions alone.** It runs inside an unrelated launch.
Terminating a neighbour's running session to tidy up would destroy work, and
that session's own trap will release it. So liveness decides everything. A
session is live if any of these holds:

1. `/proc/<launcher pid>` exists (from the machine name). Only this covers the
   window between `cp -a` and `systemd-run`, when a root exists with no scope
   behind it. A reused pid can only make a dead session look live, which
   delays its release.
2. `systemctl is-active <machine>.scope`.
3. machined knows the machine, which covers an nspawn that outlived its scope.

The launcher pid alone is not enough: after a SIGKILL the scope, nspawn and
the payload are still running. Measured: a pid-only test deleted a running
session's root.

**The sweep covers every cache the container has had**, globbed as
`/run/flong/<container>-????????-????????`. After a rebuild the previous
closure's sessions are in a directory the new launcher does not use, and a
leaked pin or pasta process would otherwise persist until reboot. The explicit
`?` width stops `demo` matching `demo-two`'s caches. A superseded cache with no
live session is deleted whole.

**No lock.** A launcher from a superseded generation can lose its prepared root
to a concurrent sweep between checking for it and copying it. The copy then
fails and that launch exits with an error. A `flock` across prepare-and-copy
in every launch would cost every launch to avoid a rare, visible failure.

**Each session records its own `postStop`.** Several launchers can drive one
container, and a rebuild changes the snippet. The launcher writes the store
path of the session's own `postStop` script to `poststop-<machine>` beside the
root, and the sweep runs that one. Only a `/nix/store` path is executed. Only
`$machine` is passed, because on the sweep's path nothing else survives. A
failing `postStop` is reported and does not stop the rest of the release.

## `postStart`

`guard` runs before the session exists: before prepare, before the machine
name and before the exit trap. Anything it creates leaks if a later step
fails, and the network namespace it would configure does not exist yet.
`postStart` runs after nspawn has created the namespace.

The root hooks take the names of a systemd service's stages, `postStart` and
`postStop`, because they run at the same moments and fail the same way: a
failed `ExecStartPost` stops the unit, and `ExecStopPost` runs however the unit
ended. One difference is deliberate and stronger than systemd's: during
`ExecStartPost` the main process is already running, while a session's payload
is held until `postStart` has returned.

### Finding the leader

`systemd-run` returns before nspawn has unshared anything. Measured: the
leader appears 26–30 ms after it returns, and the payload starts at 58–65 ms.
So the leader is polled for, every 5 ms for up to 5 s: `machinectl show
--property=Leader` first, then the scope's cgroups. The cgroup walk recurses,
because under `--keep-unit` the scope's own `cgroup.procs` is empty; nspawn
puts itself in `supervisor/` and pid 1 in `payload/`. If the scope appears and
then disappears, the session failed to start and polling stops.

A candidate is accepted only if `NSpid` in `/proc/<pid>/status` shows it is pid
1 of the pid namespace exactly one level below the launcher's. "A pid whose
network namespace differs from the host's" would find nothing without
`privateNetwork`. "Any pid in a namespace of its own" would also match a payload
that ran `unshare -Upf`, handing the hook a namespace the payload built.

### The ordering is the security property

Whatever `postStart` installs is in place before anything gives the namespace
egress. A `--private-network` namespace starts with `lo` up and an empty
routing table, so until egress exists the payload has nowhere to send packets.
There is no window to race. flong starts pasta only after `postStart` returns. A
hook that provisions egress before installing its rules (from `guard`, or at
the top of the hook) loses the property without any error. Measured: 12 of 12
connections bypassed the rules.

The hook runs in a subshell, so `exit` ends the hook, not the launcher. A
non-zero exit, a leader that never appears, or a launcher killed before
attaching all leave a session with nothing installed; the trap kills its scope
with SIGKILL. A session whose `network` failed to attach is killed the same
way.

### What stops the payload undoing it

The session's network namespace is owned by the initial user namespace, which
the payload is not in. Every write it attempts gets `EPERM`, whatever
capabilities it appears to hold: listing or flushing the nftables ruleset,
changing a route, address or link, writing `/proc/sys/net/*`, or moving an
interface into a namespace it created. Measured, all of these.

A session with `postStart` or `network` also runs with `CAP_NET_ADMIN` dropped
from its capability bounding set and `--no-new-privileges=yes`, so no
file-capability or setuid binary can regain it. This is defence in depth only:
`unshare -U` inside the session creates a user namespace with a full capability
set again. Measured. The writes above still fail, because that user namespace
owns nothing of the session's.

### The payload waits for the hook

nspawn would start the payload while `postStart` and pasta are still running. A
short payload could then finish before the hook ran, turning a successful
payload into a failed launch. Measured: a payload ran to completion against an
empty routing table, and the launcher then failed to pin a namespace that no
longer existed; separately, a hook failed with `nsenter: cannot open
/proc/<pid>/ns/net`.

So in a session with `postStart` or `network`, a wait between tini and everything
else (`attachWrap`, `command`, the payload) polls for the directory
`/run/flong-ready`, every 5 ms for up to 10 s. The launcher creates it
through `/proc/<leader>/root` once `postStart` and pasta are done. This is a
readiness marker, not a security boundary; the ordering above is the boundary.

The marker is created with `mkdir`, not `touch`. Paths walked beneath
`/proc/<pid>/root` belong to the session, and an absolute symlink met on that
walk resolves against the caller's root: the same class of bug as runc's
`/proc/self/exe` escape. Measured: `touch` through a planted
`/run/flong-ready -> /tmp/escaped` creates `/tmp/escaped` on the host.
Today nothing in a session can write `/run`, which is nspawn's root-owned
tmpfs; `mkdir` does not depend on that. It never follows its final component
and fails with `EEXIST` on anything already there, including a dangling
symlink. Failure fails the launch.

### `attachBinds` and `attachWrap`

`attachBinds` exists because `extraBinds` takes directories only, binds each at
its own path, runs as the caller, and is reported to the payload. A hook needs
a socket or a single file, from a path of its choosing, at a fixed path inside,
and the payload has no need to be told. It runs before nspawn because a bind
mount is an nspawn argument: by the time the namespace exists the mount table
is built. It runs after the machine name exists and the trap is armed, so a
per-session source is released on every path. Bind the specific path, never a
shared parent: with a directory bound, the payload can list and write other
sessions' entries.

`attachWrap` places a command between the session's pid 1 and the payload.
That is the only place a wrapper can go: `command` already runs inside as
`user`, so a gate expressed there is one the payload's own shell could skip.

## `network`

### pasta, not a veth

flong runs many concurrent sessions from one declaration. A veth pair needs an
address per session, IP forwarding, NAT, and firewall rules to keep sessions
off services the host binds on `0.0.0.0`, and it gives the session raw packets
to spoof. [pasta](https://passt.top), Podman's default rootless network mode,
needs no host interface and no host configuration, and gives the session
sockets rather than packets.

Flags that are not options:

- **Every port class spelt out.** `-t`, `-u`, `-T` and `-U` default to `auto`,
  which forwards every port bound on the other side; for `-T` that is
  everything listening on the host's loopback. Each is `none` unless listed.
- **`hostPorts` go out as TCP and UDP.** A resolver on the host's loopback is
  as likely a reason to name a port as a database.
- **`--no-map-gw`.** Without it the gateway address maps to the host's
  loopback. Measured: a listener on `127.0.0.1:18123` answered from inside with
  every port list set to `none`.
- **`--config-net`**, so pasta assigns addresses and routes. Nothing inside the
  session has the privilege to.

### The namespace pin

pasta cannot join a namespace by pid when run as root: it drops to `nobody` in
`isolate_user()` before `pasta_open_ns()` calls `setns()`, and never sets
`PR_SET_KEEPCAPS`. Measured: every by-pid form fails with `Permission denied`.
So the launcher bind-mounts `/proc/<leader>/ns/net` onto
`/run/flong/netns/<machine>` (a namespace pin, as `ip netns` makes) and runs
`pasta --netns <pin> --runas 0`. pasta watches the pin and exits when it is
removed. It forks once ready and writes its pid, so the launcher continues only
when the network is up. pasta runs outside the session's scope.

The pin is released with `umount -l`, then `rm`. A plain `umount` fails with
"target is busy" for as long as pasta lives, measured with the container alive
and after it exited. A leaked pin keeps a dead session's namespace alive until
reboot. pasta exits about 60 ms after the file is removed. It is also sent
SIGTERM, but only after `/proc/<pid>/cmdline` shows it holds that exact pin
path, because on the sweep's path the pid file may be older than the process
now holding that pid. The release does not depend on the releasing launcher
having `network`, because the session may be another launcher's.

`/run/flong/netns` sits beside the caches, not inside one, because a cache is
deleted whole and the pin is a mount.

### DNS

A networked session's `/etc/resolv.conf` is written into its copy of the root
before nspawn starts. It names an address pasta intercepts with
`--dns-forward`: UDP and TCP to ports 53 and 853 there are re-sent from the
host to the host's first nameserver. Because the query originates on the host,
a stub resolver on the host's loopback (systemd-resolved's `127.0.0.53`,
dnsmasq on `127.0.0.1`) answers. Copying the host's file in would not work:
`127.0.0.53` would name the session's own loopback. The host's `search`,
`domain` and `options` lines are copied unchanged, so short names resolve the
same way. The host's file is never written.

- **`169.254.1.1`** for IPv4, the address Podman uses for the same purpose
  (`dnsForwardIpv4`). It is link-local, so no router forwards it, and it is
  clear of cloud metadata and resolver addresses (`169.254.169.254`,
  `169.254.169.253`, `169.254.170.2`), so no rule written for those matches it.
  A hook's own service address on `lo` in the same namespace (frisket's, for
  example) must be a different address, or it would receive these queries
  before pasta does.
- **`100::1`** for IPv6, in RFC 6666's discard-only prefix: globally
  unreachable and used by no LAN. An `fe80::` nameserver would need a zone
  index, and the interface inside is named after whichever host interface
  pasta copied. Podman does not forward IPv6 DNS.

**A family is forwarded only if the host names a nameserver in it.** For a
family with none, pasta's only target is the unspecified address, which Linux
treats as the host's own loopback. Measured, with the host naming `127.0.0.1`
alone and `100::1` forwarded anyway: a TCP query to `100::1` was answered by the
resolver on the host's `::1`, a port no `hostPorts` entry named. The reverse
held with `::1` alone. UDP timed out both ways.

nspawn gets `--resolv-conf=off`. Under `--private-network` the default `auto`
already leaves the file alone, but a copy mode would write after the custom
bind mounts, with `O_TRUNC`, through whatever a bind (an `attachBinds` line, for
example) had placed at that path. A private session without `network` has no
`resolv.conf`, because it has nowhere to send a query. A session on the host's
network gets nspawn's own.

pasta reads the host's nameserver once, at start, and flong reads the host's
`resolv.conf` at the same moment. A host that changes network keeps a running
session on the old resolver. A stub on the host's loopback keeps its address
and follows the network itself, so only `search` domains go stale. A hook that
redirects port 53 in the session's namespace answers every query itself,
whatever `resolv.conf` names.

A published port can be bound by one process at a time, so a second concurrent
session with the same `forwardPorts` entry fails in pasta ("Address already in
use") and is killed rather than run without its network.

## Why some NixOS features are absent

- **Setuid wrappers.** `security.wrappers` is a unit plus a mount under `/run`,
  so `/run/wrappers/bin` is empty. This is intended: a setuid-root binary in a
  container without a user namespace is root over the host's uids, holding
  `CAP_SYS_ADMIN` from nspawn's default capability set.
- **Nix daemon.** The daemon socket is not bound. Through it a session could
  build arbitrary derivations, and a fixed-output derivation is fetched by the
  host's daemon outside the session's network namespace, where no `postStart`
  rule sees it. A `trusted-users` member could also set sandbox options, which is
  root-equivalent. See PLAN.md §3.
- **Resource limits.** The session root, `TMPDIR` and overlay upper layers are
  under `/run`, which is RAM. `scopeConfig` exists so `MemoryMax` makes a
  payload that fills them the session's problem, not the host's. It takes the
  value type `serviceConfig` takes, rendered the same way, so a setting means
  what it would in a unit file.
- **A payload `PATH` option.** `/etc/set-environment` sets `PATH` before the
  payload is exec'd, so packages added only to `command`'s script would reach
  `command` and not the program it runs. The workload's tools belong in the
  container's `environment.systemPackages`; `path` is for the host-side hooks
  only.
