# Design

Why flong works the way it does, for anyone changing it. Terms (prepared root,
session, launcher, workspace, payload, hook) are as defined in
[README.md](README.md). Work not yet built is in [PLAN.md](PLAN.md).

Measurements were taken in NixOS VM tests against this flake's nixpkgs
(kernel 6.18.51, systemd 261.2, bubblewrap 0.12.0, passt 2026_07_16,
nftables 1.1.7, libseccomp 2.6.1), launching as a lingering user with no sudo
rule. Component costs quoted in a section (a few milliseconds or less, a
count of escapes or failures) were measured while the engine was designed, on
a development machine or in a VM, and are there for their size. Where a
number compares flong with systemd-nspawn, nspawn was run as root in the same
VM with the same container and payload. Startup times are warm
unless they say otherwise, and each is quoted with its harness; they are
reported, never used as a pass mark.

## Launch sequence

The launcher is a bash wrapper, run as the caller, that execs `flong-launch`,
a C program. Nothing in either runs as host root, and nothing asks for it.

The wrapper works out what only the launch can know:

1. Refuse a caller of uid 0 or of primary group 0. Use `/run/user/$UID`,
   which must exist and be the caller's.
2. `workspace`, then `binds`, then `guard`, each as the caller.
3. Name the session `<container>-<wrapper pid>-<random>`, then run
   `seccompPolicy`, as the caller, and compile what it prints.
4. Check the depth rule against the caller's writable binds.
5. Build the id maps from `/etc/subuid` and `/etc/subgid`.
6. Prepare the root if this closure, prepare program and map have none yet.
7. Read `user`'s uid, gid, home and groups from the prepared root.
8. Build the spec and exec `flong-launch` with it as its arguments.

`flong-launch` then runs the session, in this order (the full table is in
[The launch, in order](#the-launch-in-order)):

1. Lock the cache shared, for the launcher's life.
2. Sweep: release what dead sessions of this caller left behind.
3. Write the session's record.
4. Make U1 and U2, the two user namespaces.
5. Make the session's cgroup, with any declared limits.
6. Start bwrap in the session's cgroup; learn its child's pid.
7. Fork the mount helper at bwrap's child pid; it mounts once flong-init
   reports the root built.
8. `postStart`, then pasta (with `network`).
9. Open the gate: flong-init execs tini and the payload.
10. Wait for the session. Then kill its cgroup, run `postStop` and release
    the rest.

On the warm path the wrapper forks nothing but the snippets the declaration
chose: every test is a builtin, and there is no command substitution outside
a snippet. A bash launcher measured 61 ms and a python one 106 ms, against
C's 19 ms, which is why everything after the spec is C.

## Data is data; shell is for what only launch knows

flong follows NixOS's own pattern. A service exposes typed options and its
module generates the shell that acts on them; a raw `lines` hook is plumbing
that modules generate into, and an escape hatch. In nixpkgs,
`systemd.services.<name>.postStart` is `types.lines` (systemd-unit-options),
and the nixos-containers module generates its `container@` unit's `postStart`
from typed options such as `hostAddress`, `localAddress` and `extraVeths`,
rather than asking its user for shell.

So nothing is declared by running a command:

- **`command` is an argument list**, `nonEmptyListOf str`: a program and its
  fixed arguments, to which the launcher's arguments are appended. Anything
  that needs a script is a package of its own, named by `lib.getExe`.
- **Every mount known at evaluation is the declaration's**: `bindMounts`,
  `tmpfs` and `allowedDevices` on `containers.<name>`, read as the typed
  records they are. There is no hook before the session starts, because
  nothing a session is given at start is unknown at evaluation except the
  caller's directories, which `workspace` and `binds` compute.
- **`postStart` and `postStop` are `types.lines`**, exactly as systemd's are.
  They are what a module such as frisket's adapter generates into, and several
  modules' snippets merge, ordered with `mkBefore` and `mkAfter`.
- **`workspace`, `binds`, `guard` and `seccompPolicy` are shell** because what
  they answer is known only at launch (the repository around the caller's
  working directory, what travels with it, a project's own syscall policy) or
  is a judgement on this launch.

The wrapper itself is the same text for every declaration. `module.nix`
generates a header of quoted assignments in front of `rootless-wrapper.bash`,
and the header is the only place a declaration reaches bash: a name, a path or
a snippet is data there, and the body decides what runs. Every name the
header assigns is un-exported, since an assignment to a name the caller's
environment exports keeps it exported, into the launcher and the hooks.

## `command` is exec'd through the container's environment

The payload script `cd`s into the workspace and runs
`bash -c '. /etc/set-environment; exec "$@"'` with `command` and the launcher's
arguments as that bash's positional parameters. None of them is ever the text
of a script, so a space, `;`, `$` or glob in any argument arrives as that
character. The spec reaches `flong-launch` as argv and bwrap takes each path
as a whole argument, so nothing on the way splits or expands a word either.

It goes through `/etc/set-environment` because that file is where the
container's `PATH` comes from: its system profile,
`/etc/profiles/per-user/$USER` for the user's `packages`, and every variable
the declaration exports. An absolute path, such as `lib.getExe` of a package,
runs as it is: the store is shared.

The payload's environment is otherwise built from nothing (`--clearenv`), so
the caller's tokens and agent sockets never reach it. It gets `PATH` (the
closure's `sw/bin`, until `set-environment` replaces it), `HOME`, `USER`,
`LOGNAME`, `SHELL`, `XDG_RUNTIME_DIR`, `TMPDIR`, `FLONG_BINDS`,
`container=flong`, `TERM` and, when the caller has it, `COLORTERM`, and its
hostname is the container's name.

## Sessions are overlays on a prepared root

**Nothing is evaluated at launch.** Evaluating a config per launch (the
approach of [`extra-container`](https://github.com/erikarvstedt/extra-container))
took 4943 ms to first output, and rewriting a declared container's `.conf`
per launch 2213 ms; about 2.5 s of each is Nix evaluation. `nixos-rebuild`
builds the closure once, and the launcher is generated at the same time with
the declaration's mounts already in it. Everything else a session gets is
computed at launch by the hooks.

**Nothing boots.** Booting the container's systemd costs 1.23 s across about
thirty units, to run one process. What boot provides that a session needs is
the `/etc` the activation script writes: `passwd`, `group` and `shadow` are not
in the closure, so a rootfs assembled from the store cannot resolve a username.
flong runs `activate` once into a prepared root, and each session sees it
through an overlay.

**The session root is an overlay, not a copy.** bwrap mounts
`--overlay-src <prepared> --tmp-overlay /`: the prepared root is the lower
layer and every write goes to an upper layer on a tmpfs that dies with the
session. Copy-up keeps ownership, a SIGKILL leaves nothing on disk, and it
costs nothing measurable over a plain bind, where `cp -a` of the root plus its
`rm -rf` cost about 45 ms. It needs the maps described
under [Identity](#identity-is-mapped-not-shared): a single-uid namespace fails
every write through a subuid-owned lower with `EOVERFLOW`.

**The store is shared.** `/nix/store` and `/nix/var/nix/db` are bound
read-only, so a package set costs nothing to ship. Every session can read
every store path on the host.

### Preparing the root

Preparation runs once per cache, as container root in a user namespace of the
caller's with the same maps a session gets (`unshare --user --map-users=…
--map-groups=… --setuid 0 --setgid 0 --mount --pid --fork`), so the root's
files are owned by exactly the ids a session later sees them as. It measured
160–350 ms, with a tree, owners and modes identical to a root built by bwrap.

- Container root owns the staging directory and makes every mount point in
  it. A skeleton the caller made fails tmpfiles with exit 73 ("unsafe path
  transition").
- The mounts a container's boot would have are made explicitly: proc, a
  tmpfs `/dev` with `null`, `zero`, `full`, `random`, `urandom` and `tty`
  bound in, tmpfs `/run` and `/tmp`, read-only `/nix/store` and
  `/nix/var/nix/db`. `activate` and tmpfiles then run chrooted, with only the
  closure on `PATH`.
- `activate`, then `systemd-tmpfiles --create --exclude-prefix=/dev`. No unit
  ever starts in a session, so without this a container's tmpfiles rules do
  nothing (for example, `programs.nix-ld`'s `/lib64/ld-linux-x86-64.so.2` would
  be missing). `/dev` is excluded because `allowedDevices` decides device
  access. `--boot` is omitted because boot-only rules assume a boot sequence
  that later undoes them, such as `/run/nologin`. tmpfiles cannot set the
  immutable bit on `/var/empty` from a user namespace; it logs that and exits
  0, and nothing then needs clearing before a root is deleted.
- `/etc/resolv.conf` is removed, so the root does not carry the host's DNS
  from the moment it was prepared.
- `systemd-machine-id-setup` writes `/etc/machine-id`, which a container's init
  would otherwise write. Failure is tolerated.
- The user's home is made inside the root and given to the user, for accounts
  declared with `createHome = false`.
- util-linux's `unshare` execs `newuidmap` from `PATH`, and the closure's copy
  is not setuid, so `/run/wrappers/bin` comes first.

activate and tmpfiles are gated: a root without them is quietly broken. Each
step's status goes to a log in the cache: `prepare.log`, or
`.prepare.XXXXXX.log` beside a failed staging directory.

### The cache

A cache is `$XDG_RUNTIME_DIR/flong/<container>-<closure>-<steps>-<map>`, where
`<closure>` is eight characters of the closure's hash, `<steps>` eight of the
hash of the cache tool (which references the prepare program), and `<map>`
the container user's uid and gid, the starts of the caller's subordinate uid
and gid ranges, and the caller's primary gid. Keying on the closure alone
would keep using a warm cache after the prepare steps change, and the maps
decide the root's on-disk owners. The state directory is mode 0700 and the
caller's. A prepared root is about 52 K in 183 entries; the runtime
directory is a tmpfs of 10% of RAM.

- **Cold prepares are serialised** on `.prepare.lock`, taken while holding a
  shared lock on the cache. A prepare happens in a `mktemp` staging directory
  and is published with an atomic `mv -T`; a loser's copy is deleted. Ten
  concurrent cold launches took 188–211 ms serialised, against 256–300 ms
  racing. A staging directory left by a killed
  preparer is removed by the next one, and the prepare program never
  recreates a vanished staging directory: a sweep that landed mid-prepare
  otherwise left a cache owned by container root that locked every later
  launch out.
- **Deletion goes through the namespace.** The caller cannot `rm` a tree
  owned by subordinate ids, so the cache tool deletes as container root in
  the same maps (12–17 ms).
- **A cache in use is never deleted.** Every launcher holds a shared `flock`
  on its cache for its whole life. A cold launch collects the superseded
  generations of its container with the same maps, and any `.trash.*`: each
  is taken with an exclusive lock that is tried, not waited for, renamed to
  `.trash.*` and deleted. A cache in use is kept for a later launch, or goes
  with the runtime directory at logout. Deleting a live overlay's lower layer
  breaks the session; renaming it does not (measured).
- **The recheck loops through the wrapper.** A launcher that opened its cache
  before a sweep renamed it, and locked it after, finds that the path no
  longer names the inode it locked. A sweep may also have taken the cache
  and another wrapper made one afresh at the same path, which that wrapper
  still holds shared while it prepares: so the launcher also requires
  `prepared/` to be there. Either answer execs the wrapper again (`relaunch`
  in the spec), which prepares afresh or waits on the preparer's lock. There
  is no count: each turn follows a sweep's rename, an event. A relaunch runs
  `guard` and `seccompPolicy` again.

**Integrity is the caller's.** Anything running as the caller can edit the
cache, and nothing stored in space the caller can write could stop that.
There is a sanity check and nothing more: the prepared root is as
trustworthy as the caller's `~/.bashrc`.

## Identity is mapped, not shared

A session runs in U1, a user namespace the caller owns, whose maps
`newuidmap` and `newgidmap` write from the caller's subordinate ranges:

- **The container user's uid is mapped onto the caller's uid, and its primary
  gid onto the caller's primary gid, whatever the numbers.** Container
  1001:1001 onto caller 1000:100 was measured. So the workspace is the
  caller's on the host and the user's inside, and `user` need not have the
  caller's uid.
- **Everything else in the container's 0–65536, 65536 ids, comes from the
  subordinate range**, in order around that one id. Container root is a subuid on the
  host, never host root, and the launcher refuses any map that reaches host
  id 0.
- **The range is read, not assumed.** The first `/etc/subuid` and
  `/etc/subgid` entry for the caller, by name or uid, at least 65536 wide.
  NixOS allocates automatic ranges in user-name order (a VM gave alice 165536
  because dave had 100000). A caller with none is refused with a message
  naming `subUidRanges`. `newuidmap` and `newgidmap` run in parallel.
- **The ids are declared.** `users.users.<user>.uid` and its group's gid must
  be set in the container's `config`: they name the cache and build the maps
  before anything is prepared, so a container declared by `path` is refused.
  The home is read at launch from the prepared root's `/etc/passwd`, and a
  launch refuses a root whose ids disagree with the declaration.
- **Supplementary groups** are the primary group and every group in the
  prepared root's `/etc/group` that names the user. flong-init sets exactly
  these with `setgroups`. bwrap never calls `setgroups` itself, so without it
  the caller's host groups (wheel, docker, kvm) stay effective in the payload:
  measured.

Host ids outside the map read as `nobody:nogroup` inside, which is how the
host root's `/nix/store` and `/nix/var/nix/db` appear. ssh refuses NixOS's
store-owned `Include` of `20-systemd-ssh-proxy.conf` for that reason; a
container that runs ssh sets `programs.ssh.systemd-ssh-proxy.enable = false`.
Idmapped mounts, which would fix ownership per mount, are `EPERM` in a user
namespace the caller owns.

A container gid that means a host gid (a group-gated device, say) is not
offered. `newgidmap` refuses mere membership of the group; it needs an
explicit one-gid `subGidRanges` entry, which was measured to work for `audio`
and `kvm`. Devices reach a session through the caller's own access instead
(see [Mounts](#mounts)).

`privateUsers` is refused: a session always has flong's own user namespace,
so there is no other to choose.

## Every hook runs as the caller

`workspace`, `binds`, `guard`, `seccompPolicy`, `postStart` and `postStop` all
run as the caller, with the caller's privilege and no more. A hook that
configures the session enters its namespaces (see
[postStart](#poststart-the-gate-and-readiness)); nothing is done as host root.

`workspace` runs first, in the directory the caller chose. A consumer's
snippet commonly runs `git` there, which reads configuration from the
repository it is pointed at; as the caller, that grants nothing the caller
lacked. The default, `pwd`, is taken without a fork. The printed path is
resolved to its physical path before it is checked, so what is checked is
what is mounted. `binds` runs next, the same way, with `$workspace` exported
so it can name what travels with that directory.

A caller's path travels as `PATH:MODE`, one per line: in what the hooks print,
in `$binds` for the guard, and in `FLONG_BINDS` for the payload. So `:` and
newlines are refused in a caller's path, which keeps those lists unambiguous
to anything that splits them naively. A trailing `:ro` or `:rw` is always a
mode. `/` is refused, and so is a path the declaration already mounts
something at. A path named twice is bound once, writable if either line says
so, and a bind of the workspace itself changes only the workspace's mode.

**Read-only is the default** for a caller's bind, as `isReadOnly` defaults to
`true` in the declaration: a directory is writable because a line says `:rw`.
The workspace is the exception, read-write unless it says `:ro`, because it is
what the session was started to work on. `$binds` and `FLONG_BINDS` spell the
mode out on every entry, so neither the guard nor the payload has to know the
default.

**`guard` is a consistency check, not a gate.** It runs third, with
`$workspace`, `$workspace_mode` and `$binds` as they will be mounted, and
judges those rather than re-deriving a directory from `$PWD`. A non-zero exit
refuses the launch. Without root it cannot refuse the caller anything: the
caller can run `flong-launch` directly with any spec. So it catches a launch
the declaration does not mean to make (chase's trusted-tier check is one),
and setting it warns, to say so. It runs in a shell of its own, so `exit 0`
allows the launch rather than ending the launcher, and nothing it assigns
reaches the launcher.

**`seccompPolicy` runs after the guard**, with what the guard sees and with
`$machine`, the name `postStart` and `postStop` will see: what it approves
for them can be staged per launch rather than per checkout, where two
launches of one checkout at once would each apply the other's approval. See
[Seccomp](#seccomp).

Every hook runs under `set -euo pipefail` with `path` on `PATH`, and every
one but `postStop` sees the launcher's arguments in `"$@"`. `postStop` runs
from `/` with `$machine` and nothing else, since on the sweeper's path that is
all that survives. `postStart` and `postStop` are programs of their own in the
store, because the launcher and the sweeper run them with the
environment they give them, and the sweeper may run a superseded
generation's `postStop`.

## Every bind is one record, filled in by two parties

Every bind flong makes has the shape of the declaration's `bindMounts` entry: a
mount point, a host path that defaults to it, and read-only unless it says
otherwise. What differs is who fills the record in, and when:

| source | filled in by | when | shape |
|---|---|---|---|
| `containers.<name>.bindMounts` | the admin, in Nix | evaluation | any file, at any mount point |
| `workspace`, `binds` | the caller | launch, before `guard` | a directory, at its own path |

The rest follows from who fills it in:

- **Advertised or not.** The caller's binds are the session's working set, and
  the payload is told about them in `FLONG_BINDS` so an agent can be given
  `--add-dir`. The declaration's binds are at fixed paths the container's own
  configuration already knows, and are not reported.
- **Same path or not.** The caller's binds are mounted at their own paths, so a
  caller cannot choose where inside the session a directory lands: not over
  `/etc`, and not over `/run/current-system`. A path in an error message also
  means the same thing on both sides. The admin chooses the mount point.
- **Directories or any file.** The caller's are directories, because that is
  what `--add-dir` takes. The declaration binds a socket or a single file as
  readily.
- **Exact or followed.** The caller's paths are canonical when the launcher
  gets them, so a symlink met on the way now is a race, and the launch is
  refused. A declared source follows symlinks, as its author intended.

A read-only bind costs a socket nothing: `connect()` is not a write to the
filesystem, so a socket bound read-only still connects, which is why Docker's
`docker.sock:ro` works. A file bound read-only refuses writes, `chmod` and
`chown` with `EROFS` even when the payload owns it. Bind the specific path,
never a shared parent: with a directory bound, the payload can list and write
everything in it.

Read-only binds stop writes, not execution. They are for reference material,
not for making untrusted directories safe.

## Mounts

bwrap mounts only fixed destinations, in fresh filesystems: the overlay root,
`/nix/store`, `/nix/var/nix/db`, `/proc`, a minimal `/dev`, a 0755 tmpfs
`/run`, the closure at `/run/current-system`, a 0700 tmpfs at
`/run/user/<uid>`, a fresh 1777 `/tmp`, and the session's `/etc/resolv.conf`
as data. Everything else goes through flong's own mount helper: the
declaration's `bindMounts`, `tmpfs`, `allowedDevices`, `overlays` and
`masks`, the workspace, the caller's binds, `$HOME/tmp` and `/sys`.

### The walker

bwrap resolves a nested destination by path and follows a symlink the
payload planted there. Under a concurrent session swapping a directory for a
symlink, bwrap escaped 60–65 of 200 launches; a launcher pre-check in front of
bwrap still escaped 18–20 of 200; the walker escaped 0 of 400 (development
machine), and the VM test's swap race holds it at 0. bwrap refuses a
descriptor as a destination, so the helper does the mounting itself:

1. It is forked at child-pid into the sandbox leaf, joins U1 as its root, and
   unshares a mount namespace of its own. There it opens each source and
   clones it (`open_tree(OPEN_TREE_CLONE|AT_RECURSIVE)`), makes each tmpfs
   and overlay (`fsopen`, `fsmount`), and sets their flags, while bwrap is
   still building the root.
2. It waits for flong-init's ready byte: bwrap has finished the root.
3. It joins the session's mount namespace, through the leader's pidfd
   (`PIDFD_GET_MNT_NAMESPACE`), and walks each destination one component at
   a time with `openat2(RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_BENEATH)`,
   making a missing component with `mkdirat` on the parent's descriptor, and
   attaches with `move_mount` onto the final `O_PATH` descriptor. Nothing is
   resolved by name twice.

It costs about 1 ms for 3 mounts and 1.5 ms for 12.

- **A symlink anywhere on the way ends the launch**, the last component
  included ("a symlink is on the way to …"). A concurrent session can
  therefore deny a launch by planting one: a denial of service on its own
  workspace. Following it with `RESOLVE_IN_ROOT` instead would add a second
  rule for no consumer that needs it.
- **Sources are opened with the caller's reach.** The helper takes the
  payload's file ids (`setfsuid`, `setfsgid`) to open a bind's or an overlay's
  source, so it reaches exactly what the caller can, not what container root
  could over every subordinate id. A caller's source is opened with
  `RESOLVE_NO_SYMLINKS` from `/`.
- **The way to a mount point is the user's, inside home.** A directory made
  on the session's own mounts is made as container root, and given to the
  user when it lies inside the user's home, so a bind at
  `~/.cache/tool/data` leaves `~/.cache/tool` writable to every program
  keeping state beside it. A directory made on a host bind is made with the
  payload's file ids, so the kernel checks the write as the caller's and the
  directory is the caller's on the host. Directories are made 0755 whatever
  the caller's umask.
- **Protected sources.** No source may equal, lie inside or contain a
  protected path, compared on the path the kernel resolved the opened
  descriptor to, so neither a symlink nor a bind hides where a source is. The
  spec protects `/proc`, `/sys/fs/cgroup`, the user manager's `bus` and
  `systemd` sockets and the declaration's `protect` list (frisket's control
  socket directory, for one); the launcher adds its own state directory and
  the holder's cgroup. The same check runs lexically at evaluation. See
  condition 4 of [the security boundary](#the-security-boundary).
- **Mount order.** Mounts are sorted by destination, parents first, and one
  destination twice is refused. A bind can therefore land inside a declared
  tmpfs, and a single file or socket can be exposed inside an otherwise
  private directory this way.

### What each kind mounts

- **Binds** are recursive clones, `nosuid` and `nodev`, read-only when asked.
- **Devices.** `allowedDevices` entries are binds without `nodev`: a plain
  bind is `nodev`, and `/dev/snd` opened through one gave `EACCES`. They go
  through the walker like every other flong-level mount. Access is the
  caller's own host permission (the logind ACL on `/dev/snd`, `/dev/kvm`
  being 0666 on NixOS), so `rw` and `rwm` are accepted (the `m` means nothing
  for a bound node); `r` cannot be enforced, and is refused. A declared bind of a `/dev` path is
  refused, since it would mount and then refuse every open.
- **tmpfs ownership.** A bare tmpfs is root-owned 0755. An unprivileged
  payload cannot write it and most programs treat an unwritable cache as an
  absent one, so the failure is silent. A declared entry with no options is
  the user's, 0755. An entry may give `mode=`, `size=`, and `uid=` with `gid=`
  of either the user or root, and nothing else, which is refused.
- **`XDG_RUNTIME_DIR`** is `/run/user/<uid>`, a 0700 tmpfs of the user's,
  because tools reject a root-owned 0755 runtime directory without saying why.
- **`TMPDIR`** is `$HOME/tmp`, a 0700 tmpfs of the user's, unless a bind or a
  declared mount already covers that path; then it is `/tmp`.
- **Overlays** read their lower directory with the payload's reach. The upper
  and work directories sit on one detached tmpfs that nothing names, and the
  upper is the user's. Every layer is passed to overlayfs as a descriptor.
  overlayfs reports changing device and inode numbers as a file is written,
  so an overlay must not cover a sqlite database.
- **Masks are a last resort.** `masks` over-mounts a path with a mode-0,
  read-only, `noexec` node of its own kind: an empty tmpfs for a directory, a
  mode-0 file for anything else. The mask belongs to U1's mount namespace, so
  the payload in U2 cannot unmount it. It is a denylist, so it fails open for
  anything it does not name; the path must exist at launch or the launch
  fails; and it masks the file, not the name -- a host program that renames a
  new file over the masked one detaches the mask in the session (measured).
  Binding the parts wanted is always preferred.
- **The depth rule.** A mask two or more levels below the root of a writable
  bind can be moved from under it: a session that can write the host
  directory renames the masked name's parent and leaves a decoy, and the file
  is readable at the new name. One level down, the parent is the bind's root,
  which a session cannot rename. So such a mask is refused: against the
  declaration's writable binds at evaluation, and against the workspace and
  the caller's writable binds at launch. A mask below a read-only bind, and a
  tmpfs or an overlay at any depth, is not checked: moving the parent of
  either only moves where the session's own writes land.
- **`/sys`** is a fresh read-only sysfs, made in the session's network
  namespace so it shows only the session's interfaces, with a read-only
  cgroup2 at `/sys/fs/cgroup`. The kernel refuses a fresh sysfs unless one is
  fully visible already, so bwrap binds the host's at `/.hostsys` and the
  helper detaches and removes it before the gate. It is mounted before the
  declared mounts, so a declaration under `/sys` lands on the session's own
  sysfs, or fails, rather than being covered without a word. With it,
  `nproc`, Go, Node and Java honour declared limits; without it `lscpu`
  fails. It costs 0.1 ms in C, against 9 ms through `nsenter` and `sh`.
- **The cgroup view is the payload's own cgroup namespace**, rooted at the
  sandbox leaf by bwrap's `--unshare-cgroup` (bwrap is created in the leaf).
  The helper joins that namespace before it mounts cgroup2, so the mount's
  root is the cgroup `/proc/self/cgroup` names, `/`. A view rooted at the
  session cgroup instead, with the payload's namespace at the leaf, showed a
  mount root of `/..`, and Go uses a cgroup2 mount only when its root is a
  prefix of the process's cgroup path: `GOMAXPROCS` ignored `cpu.max`.
- **`/run` is made read-only last**, the tmpfs alone, because declarations
  bind under `/run`. The mounts under it keep their own flags, and
  `/run/user/<uid>` stays writable.
- **`/dev`** is bwrap's minimal set. `mq_*` works without `/dev/mqueue`.

## Namespace topology and lockdown

- **U1**, the keep-id user namespace the caller owns, owns the session's
  network, mount, ipc, uts, pid and cgroup namespaces.
- **U2**, a child of U1, holds the payload, which has no capabilities,
  `no_new_privs`, and `user.max_user_namespaces = 0` in U2, and bwrap asserts
  that with `--assert-userns-disabled`.
- U2's map is U1's identity, split along U1's extents (`0 0 1000`,
  `1000 1000 1`, `1001 1001 64536` for a user of uid 1000): the kernel wants each
  U2 extent inside one U1 extent, and a single `0 0 65536` is `EPERM`. With
  the split, container-root files read as root inside.

So the payload holds no capability over its own network namespace, even in
principle. Measured: `nft list` and `nft flush`, `ip link add`, route changes
and `/proc/sys/net` writes all get `EPERM`, and a hook's rules are intact
afterwards. A nested user namespace, the kernel attack surface nested
sandboxes open, is refused twice: by U2's `max_user_namespaces` (`ENOSPC` for
`unshare -U`, `-Ur` and `-Urn`) and first by the namespace mask filter
(`EPERM`).

`nestedSandbox` lifts both locks for a payload that sandboxes its own
children. Even then it cannot reach the session's network namespace, which
belongs to U1, not to anything the payload makes: measured.

`/proc/1` in the session is tini, not bwrap (`--as-pid-1`), so bwrap's argv
does not leak. `/run/wrappers` is not mounted, so no setuid binary is
reachable, and `no_new_privs` would defeat one anyway.

## postStart, the gate and readiness

### The hook

`postStart` runs as the caller in the session's hooks cgroup, with the
launcher's stdio, working directory and environment, plus:

| variable | value |
|---|---|
| `leader` | bwrap's child, the session's pid 1 as the host sees it, from `--info-fd` |
| `userns` | `/proc/<launcher>/fd/<n>`: U1, held by the launcher |
| `netns` | `/proc/<launcher>/fd/<m>`: the session's network namespace, held by the launcher |
| `machine` | the session's name |

`$uid`, `$gid`, `$home`, `$workspace`, `$workspace_mode` and `$binds` are
exported by the wrapper. The namespaces are named by descriptors the
launcher holds, so nothing is pinned on disk and a pid is never looked up
again.

A hook enters with `nsenter --user="$userns" --net="$netns"`, without
`--preserve-credentials`. Its tools then run as U1's root, a subuid on the
host, with every capability over the session and none over the host. With
`--preserve-credentials` they would run as the caller's uid with none. nft
tables with tproxy, socket, fib and reject, a dummy link, routes, fwmark
rules and `IP_TRANSPARENT` listeners all work, measured. A hook that enters
the mount namespace also enters the pid namespace (`/proc/$leader/ns/…`), or
`/proc/self` does not resolve. Go cannot `setns(CLONE_NEWUSER)` (`EINVAL`,
even in `init()`), so a Go hook re-executes itself under an absolute-path
`nsenter`, as frisket does.

On a freshly booted VM, every nft expression module autoloaded on demand from
a non-initial user namespace, so no `boot.kernelModules` preload is needed on
this kernel. A host that disables module autoloading must preload the ones
its hooks use.

The hook, and anything it starts, lives in the session's cgroup, so the
teardown kills a daemon a hook leaves behind. Without a session cgroup, a hook
daemon leaked on every exit: measured.

`postStart` and `postStop` take the names, and the type, of a systemd
service's: they run at the same moments and fail the same way. A failed
`ExecStartPost` stops the unit, and `ExecStopPost` runs however the unit ended.
One difference is deliberate and stronger than systemd's: during
`ExecStartPost` the main process is already running, while a session's payload
is held until `postStart` has returned.

### The ordering is the security property

Whatever `postStart` installs is in place before anything gives the namespace
egress. A new network namespace starts with `lo` up and an empty routing
table, so until egress exists the payload has nowhere to send packets, and
there is no window to race. flong starts pasta only after `postStart` returns:
a hook sees 0 routes, and the payload 2. A hook that provisions egress before
installing its rules (from `guard`, or at the top of the hook) loses the
property without any error. Measured: 12 of 12 connections bypassed the rules.

Starting pasta beside the hook would save about 10 ms and give up "no route
at hook time", so it stays sequential.

### The gate

bwrap's own `--block-fd` gate is fail-open: the payload runs when the launcher
dies. So flong-init, which bwrap execs as the session's pid 1, is the gate.
Its protocol is its argv, not the environment, so the wrapper's `--clearenv`
cannot drop it and nothing has to be unset before the payload sees its
environment; the argv is gone at the exec of tini. In order, it:

1. calls `setgroups` with the container's groups, then drops the bounding
   set, clears the ambient set and zeroes the rest (bwrap gives it
   `CAP_SETGID` and `CAP_SETPCAP` for this and nothing else);
2. with a relayed pty, takes it as its controlling terminal (`TIOCSCTTY`);
3. resets SIGINT and SIGQUIT to their default and empties its signal mask,
   because a bash `&` hands them over ignored;
4. writes one byte on the ready pipe: bwrap has finished the root;
5. reads one byte from the gate pipe, and **on EOF exits 125**: the payload
   never runs if the launcher fails, is killed or is signalled first (a
   failing hook and a SIGKILL mid-hook were both measured);
6. changes to the workspace, which is a helper mount made after bwrap built
   the root, so bwrap's `--chdir` would name the directory underneath it;
7. closes every descriptor above stderr (bwrap leaks its namespace
   descriptors), and execs `tini -g -- payload`.

Any failure before the exec exits 125. tini then stays pid 1, reaping
orphans and forwarding signals to the payload's group (`-g`).

The mount helper waits for the ready byte before it touches the session's
mount namespace, and the launcher runs no hook until the helper has finished: without it, a hook ran
before bwrap had finished the root in 179 of 200 concurrent launches. The
gate opens only when the helper, the hook and pasta have all succeeded.

This replaces a readiness marker created through `/proc/<pid>/root`, and with
it that marker's class of bug: a path walked beneath a session's root that
meets an absolute symlink resolves it against the caller's root (runc's
`/proc/self/exe` class). The gate is a pipe, which no session can plant
anything in.

### No timeouts

Nothing in the engine gives up on a clock. A hook can take as long as it
needs, a person answering a question in it included. Every wait is on an
event, with no timeout: the gate pipe, the ready byte, a pidfd polled with
`-1`, `cgroup.events` (`POLLPRI`), a held `flock` (waited for by a helper whose
pidfd is the event), pasta's exit, the foreground wait. No retry has a cap:
the cache's recheck loops through the wrapper, and a taken session name waits
on its holder's release. A failing hook, and a launcher asked to stop, end the
session through the teardown; a launcher killed mid-hook takes the session
with it (below). The one clock read is the `^]^]^]` check, which waits for
nothing.

## `network`

### pasta, not a veth

flong runs many concurrent sessions from one declaration. A veth pair needs an
address per session, IP forwarding, NAT, and firewall rules to keep sessions
off services the host binds on `0.0.0.0`, and it gives the session raw packets
to spoof. [pasta](https://passt.top), Podman's default rootless network mode,
needs no host interface and no host configuration, and gives the session
sockets rather than packets. It runs as the caller:

```
pasta --quiet --config-net --userns /proc/<launcher>/fd/<U1>
      --netns /proc/<leader>/ns/net --pid /proc/<launcher>/fd/<memfd> <ports and DNS>
```

- **`--userns` names U1**, the network namespace's owner. U2, which
  `/proc/<leader>/ns/user` names, gives `EPERM`.
- **The pid file is a memfd** the launcher holds: nothing on disk, and a path
  in pasta's cmdline unique to the session. The launcher never signals pasta
  by pid; `cgroup.kill` ends it with the session.
- pasta runs in the session's pasta leaf. The spawned pasta exits 0 once the
  namespace is configured and its daemon runs; a host port it cannot bind
  fails it at once, and the launch fails closed.

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

Measured working: egress, DNS through a loopback resolver in either family
or both, `hostPorts` with unnamed ports blocked, fixed `forwardPorts`,
`forwardPorts = "auto"` (a listener opened after start included),
`hostLoopbackToSession`, and nft rules a hook installed beforehand, which
pasta leaves alone.

**Host ports below `net.ipv4.ip_unprivileged_port_start`** cannot be bound by
the caller, so a fixed `forwardPorts` entry below it is refused at evaluation.

**The teardown waits for pasta only when it must.** pasta takes 20–40 ms to
exit after the session, and that is the kernel removing its tap device, so
SIGKILL does not shorten it. Fixed `forwardPorts` bind host ports, and 11–12
of 20 back-to-back relaunches hit `EADDRINUSE` without the wait, so the
launcher waits for the pasta leaf to empty when it has any.
`hostLoopbackToSession` and `hostPorts` bind nothing on the host. `auto` binds
the ports the session listens on, but only while it listens and never at a
number a launch asks for, so it does not wait either.

A fixed host port is one session's at a time, so a second concurrent session
with the same `forwardPorts` entry fails in pasta ("Address already in use")
and is ended rather than run without its network.

### DNS

A networked session's `/etc/resolv.conf` is written at launch and given to
bwrap as data (`--ro-bind-data`), a fixed file in the fresh root that no bind
can redirect. It names an address pasta intercepts with `--dns-forward`: UDP
and TCP to ports 53 and 853 there are re-sent from the host to the host's
first nameserver. Because the query originates on the host, a stub resolver on
the host's loopback (systemd-resolved's `127.0.0.53`, dnsmasq on `127.0.0.1`)
answers. Copying the host's file in would not work: `127.0.0.53` would name
the session's own loopback. The host's `search`, `domain` and `options` lines
are copied unchanged, so short names resolve the same way. The host's file is
never written.

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

A session without `network` has no `resolv.conf`, because it has nowhere to
send a query.

pasta reads the host's nameserver once, at start, and flong reads the host's
`resolv.conf` at the same moment. A host that changes network keeps a running
session on the old resolver. A stub on the host's loopback keeps its address
and follows the network itself, so only `search` domains go stale. A hook that
redirects port 53 in the session's namespace answers every query itself,
whatever `resolv.conf` names.

## Containment: the session cgroup

Every session gets its own cgroup. That is mechanism, not policy: it is how a
hook's daemon and pasta die with the session, and how the sweep finds
everything a dead session left. **No limit is set unless the declaration sets
one.**

### The holder

The module declares a user unit, `flong-sessions.service`, in every user's
manager: `Type=exec`, `Slice=app.slice`, `Delegate=yes`,
`DelegateSubgroup=supervisor`, `OOMPolicy=continue`, and one process, the
sweeper. It is the only delegation systemd gives a user: `mkdir` under
`user@UID.service` works but is not delegated, and the caller's own cgroup
cannot enable controllers (`EBUSY`).

- **Started on demand.** Nothing wants the unit. The launcher finds its
  cgroup by path, from `/proc/self/cgroup` (one `open` on the warm path,
  against 7 ms for `systemctl show`), and starts it with
  `systemctl --user start` when it is absent (about 7 ms, once).
- **`Type=exec`**, so start returns once the sweeper has moved itself into
  `supervisor/`; before that, enabling a limit's controller in the holder
  fails with `EBUSY`.
- **`OOMPolicy=continue`**, because systemd's default, `stop`, would stop the
  holder, and so every session, when one session's process is OOM-killed.
- **Stopping it stops every session.** With `KillMode=control-group`, anything
  that deactivates the unit kills its whole cgroup: `systemctl --user stop`,
  and the sweeper exiting. So there is no `Restart=` (a restart is a stop
  first), and `restartIfChanged` and `stopIfChanged` are off: a switch leaves
  running sessions alone. After an upgrade the old sweeper sweeps the new
  launchers' records until the unit next starts, so the record format is a
  contract between versions.
- **No `RuntimeDirectory=`**: stopping the unit would delete the records
  `postStop` needs.

Sessions show in `systemd-cgls` and `systemctl --user status
flong-sessions.service`, not in `machinectl`.

A caller with no user manager is refused, naming `users.users.<name>.linger`.
There is no fallback outside the runtime directory: records must reset at
boot, and there would be no session cgroup to reap hook daemons. A system
unit with `User=`, a `/run/user/<uid>` of the caller's and `Delegate=yes` runs
its sessions under its own cgroup instead (`DelegateSubgroup=` too, for
declared limits, since a cgroup with a process in it cannot enable
controllers for its children).

### The layout

```
<user@UID.service>/app.slice/flong-sessions.service/   the holder (Delegate=yes)
  supervisor/                                         flong-sweeper
  <container>/                                        shared; never removed by a launcher
    <machine>/                                        the session; no process of its own
      sandbox/                                        bwrap, the payload, the mount helper briefly; the limits
      hooks/                                          postStart and what it leaves running
      pasta/                                          pasta
```

bwrap, the hook and pasta are created in their leaves with
`clone3(CLONE_INTO_CGROUP)`, never migrated: migration costs 15–30 ms on this
kernel, and creating the cgroup costs 0.2 ms and killing and removing it 0.06
ms. The session cgroup costs 0.14 ms a launch
(interleaved, n=40), where a `systemd-run --user --scope` would cost 23 ms.
Every level below the holder is opened with one path component under its
parent's descriptor, with `O_NOFOLLOW`, and removed the same way.

### Opt-in limits

`limits` names systemd's properties and writes the cgroup files they stand
for: `MemoryMax` (`memory.max`), `MemoryHigh` (`memory.high`),
`MemorySwapMax` (`memory.swap.max`), `TasksMax` (`pids.max`), `CPUQuota`
(`cpu.max`), `CPUWeight` (`cpu.weight`) and `oomGroup`
(`memory.oom.group`). Unset, a session is bounded by whatever bounds the
caller, as a process the caller runs directly would be.

- **On the sandbox leaf.** A program reads its limits from its own cgroup,
  and Go reads `cpu.max` there and nowhere above, so `nproc`, Go, Node and
  Java honour a declared limit only when it is on the payload's cgroup. The
  limits bound the payload and bwrap, not the hook or pasta: pasta cannot be
  the OOM victim of the payload's memory, and `memory.oom.group` kills the
  payload's group. A controller is enabled in the holder's, the container
  level's and the session's `cgroup.subtree_control` only when a declared
  limit needs it. The mount helper sits in the sandbox leaf for the moment
  it runs, so the session cgroup holds no process and can enable
  controllers.
- **Only delegated controllers.** A user manager is delegated memory, pids
  and cpu, so there is no `IOWeight`.
- **Refused properties.** `AllowedCPUs`, `DevicePolicy`, `DeviceAllow`,
  `IPAddressAllow`, `IPAddressDeny`, `SocketBind*` and
  `RestrictNetworkInterfaces` are silently ignored by a user cgroup
  (measured), so the old `scopeConfig`, which could carry them, is refused.
- **Memory is where the files are.** The overlay's upper layer, `TMPDIR`,
  `/tmp` and every other tmpfs are charged to the session's memory, not to
  disk (measured). `MemoryMax` makes a payload that fills them the
  session's problem rather than the host's. The session root has no size of
  its own; bounding it would need bubblewrap to honour `--size` for
  `--tmp-overlay`.

### The payload cannot leave its cgroup

The cgroup files are the caller's, and the payload is the caller's uid. It
still cannot write them or move out, because cgroup2 is mounted `nsdelegate`
(systemd's default), the payload's cgroup namespace is made after it is in
the sandbox leaf, and its cgroup2 view is read-only. Measured: a nested user
and cgroup namespace mounting cgroup2 at the session cgroup gets `EPERM` on
`memory.max`, `pids.max` and `cgroup.kill`, with and without
`nestedSandbox`. The launcher checks `nsdelegate` in `/proc/self/mountinfo`
and refuses to start without it, since without it a payload could move out of
the cgroup that reaps it.

## Lifecycle

### Records

A session's record is `$XDG_RUNTIME_DIR/flong/sessions/<machine>`, one per
session, in one directory per caller, so any launch can sweep any dead
session of the caller's:

```
poststop=<store path>       the session's own postStop program, if any
cgroup=<path>               its session cgroup
leader=<pid>:<starttime>    appended once bwrap reports its child
```

- **It is made unnamed and locked.** The launcher opens it with `O_TMPFILE`,
  takes an exclusive `flock`, fills it, and only then links it into place
  with `linkat`, which refuses an existing name: the `O_EXCL`. So the record
  appears locked and whole, a concurrent sweep never finds a half-made one,
  and a killed launcher leaves no dot file behind.
- **The lock is the launcher's life**, and lives only in the launcher: bwrap's
  monitor closes inherited descriptors, and a lock inside the sandbox would
  be in the payload's reach. Every helper is forked with its descriptors
  closed, since a helper holding the record's lock would keep a dead session
  alive for the sweep.
- **The record exists before the cgroup and before the hook**, so `postStop`
  runs even for a launcher killed mid-hook, and must be idempotent.
- **Each session records its own `postStop`.** Several launchers can drive one
  container, and a rebuild changes the snippet, so the sweep runs the store
  path in the record, not the current one.

### Liveness

A session is dead only when its record's lock is free **and** its recorded
pid 1 has exited, checked through a pidfd whose starttime matches. A lock
alone was granted 1–1.5 ms before the session's last process was gone (20 of
20 runs); lock and pidfd together, 0 of 20. A record with no `leader=` yet is
a session starting, and an error in asking counts as running, so the answer
never ends a live session.

**Sessions do not outlive their launcher.** bwrap's `--die-with-parent` ends
the payload about 1.5 ms after the launcher is SIGKILLed. So the sweep never
has to decide about a running session whose launcher is dead.

**A name already taken.** Running the same machine name again right after it
exits can find the old record still linked: its launcher's teardown, or a
sweep, still holds it while it runs `postStop` or waits for pasta. `linkat`'s
refusal is a refusal while that session runs (no `leader=` yet, or the
leader alive). When its leader has exited, the new launch waits for the
lock, releases what is left as the sweep does, and links the name. Running
the same session again at once, networked without fixed forwardPorts, failed
9 of 20 times with "a session named … is already running" before this, and 0
of 60 after. There is no count: each turn follows a release.

### The sweep

The sweep runs inline at launch start, costing about 20 µs when there is
nothing to do, and in the holder's sweeper, so a killed launcher's `postStop`
and hook daemons do not wait for the next launch. For each record whose lock
it can take, whose name still names the inode it locked, and whose pid 1 has
exited, it kills the cgroup, waits for it to empty, runs `postStop`, removes
the cgroup and unlinks the record. Ten concurrent sweepers ran a dead
session's `postStop` exactly once. `postStop` runs once even if the sweep dies
before the unlink: the sweep first blanks `poststop=` through a writable
descriptor of its own, in one write, so a kill at any moment leaves the old
record or the new one.

**The sweep is defensive, because records are the caller's files.** A payload
that could write one would get the sweep to run a program of its choice, or
kill any of the caller's cgroups; no session can reach the state directory
(condition 4), and the sweep is the second line. It `chdir`s to `/`, gives
`postStop` `/dev/null` for stdin and exactly `machine=<name>` for its
environment, runs only an executable `/nix/store` path whose target is also in
the store, requires `cgroup=` to spell exactly
`<holder>/<container>/<machine>` for the record's own machine before anything
is killed, and requires `leader=` to match its starttime. A record that is not
well formed, or does not name a session's cgroup, is unlinked and nothing it
says is acted on. A record whose cgroup lies under another holder (another
unit of the caller's, or a launch with and one without a user manager) is
left for that holder's sweep: its cgroup is not this sweep's to kill, and its
`postStop` must still run. A cgroup that cannot be opened for a transient
reason (`EMFILE`, `ENOMEM`) keeps the record, the only trace of what is left.

A failing `postStop` is reported and counts as run. A signal while it runs
kills it and leaves `poststop=` in place, so the next sweep runs it again.

### The sweeper

`flong-sweeper $XDG_RUNTIME_DIR/flong` is the holder unit's one process. It
keeps the holder's cgroup up while no session is, sweeps at start, and sweeps
again whenever a record is closed (inotify `IN_CLOSE_WRITE` on `sessions/`),
so a SIGKILLed launcher's session is released within milliseconds.

- **The event comes before the lock is dropped.** The kernel queues
  `IN_CLOSE_WRITE` in `__fput` before it drops the descriptor's `flock`, so a
  sweep that answers the event with `LOCK_NB` can find the lock still held,
  skip the record, and never hear of it again. A launcher's record was made
  with `O_TMPFILE`, and its close is reported under the name the kernel gave
  the unnamed file, `#<inode>`, whatever it was linked as since: that close is
  its last descriptor, so the sweep waits for that inode's lock, an event
  with no timeout.
- **A sweep's own close is not waited on.** A close reported under a
  machine's name is a sweep's writable open, closed after blanking
  `poststop=`. By the time the event is read the record may be unlinked and a
  relaunch's live record linked under the name, so it is never resolved to an
  inode: waiting on that lock would stall every sweep for that session's whole
  life. The event still wakes a sweep, which tries every record with
  `LOCK_NB`.
- **On overflow** (`IN_Q_OVERFLOW`) a launcher's close may have been dropped,
  so the next sweep waits for the lock of every record whose `leader=` has
  exited (only a holder that is letting go keeps such a lock) and tries the
  rest with `LOCK_NB`.

It refuses to run anywhere but a `supervisor` leaf, because it releases only
the sessions under its own holder and must not guess one. It exits 125 when
it cannot start.

### Teardown

One function, run whatever stage the launch reached, in this order:

1. Restore the terminal, release the watchdog and hand back the foreground.
   Hooks and `postStop` then print to a cooked terminal.
2. Close the gate's write end if it is still open: flong-init, if it exists,
   reads EOF and exits 125.
3. `cgroup.kill`: every process in the session, bwrap and the helper
   included.
4. Reap what is ours: bwrap, the mount helper, the hook, the spawned pasta.
5. Wait for the sandbox leaf, then the hooks leaf, to empty.
6. Run `postStop`, if the record has one, then blank it in the record.
7. With fixed `forwardPorts`, wait for the pasta leaf to empty.
8. Remove the session cgroup, then unlink the record. When pasta is still
   exiting and the cgroup cannot go yet, the record is closed, not removed,
   without `poststop=`, and the sweeper (woken by that close) or the next
   launch removes the cgroup and the record. The sweep looks only at records,
   never at cgroupfs.
9. The cache lock goes with the process.

Each step happens only for what exists: no record, no `postStop`; no cgroup,
nothing to kill or wait for. A terminating signal during one of the
teardown's waits, or a failed kill, blank or removal, leaves the session
possibly not empty: the teardown then runs no `postStop`, removes nothing,
and closes the record for the sweeper.

## The terminal

**A pty is relayed when stdin and stdout are both terminals.** The launcher
opens the pty on the host's devpts before bwrap, copies the caller's modes
and window size to it, and relays bytes both ways; bwrap gets
`--new-session` and flong-init takes the pty as its controlling terminal. The
caller's terminal is raw only between the gate and the payload's exit.
SIGWINCH, SIGTERM, SIGHUP, SIGINT and SIGCONT are handled, and `^]^]^]` within
a second ends the session (exit 137), as nspawn's escape does. Measured:
launch cost within noise (15.5 against 15.4 ms), about
10 µs per keystroke round trip, and throughput within noise.

**Otherwise descriptors 0–2 pass straight through**, so `echo prompt |
launcher` keeps working; `tini -g` gives the payload's group the foreground,
and afterwards the launcher takes it back and restores the modes. There is
no `--new-session` in this mode: it breaks ^C, SIGWINCH and job control.
Passthrough everywhere would have been simpler, and was measured to kill an
interactive caller's bash when started with `&`, to leave a caller without job
control in the background of its own terminal, and to leak terminal modes the
payload set.

- **The relay never blocks in a write.** Its output goes to the caller's
  terminal through a descriptor of its own, opened again non-blocking (so the
  caller's shell's `fd 1` is untouched), and only when poll says it takes
  output; a terminal that stops draining never holds a signal or the escape
  back.
- **A watchdog restores the terminal after a SIGKILL.** It is started before
  the terminal goes raw, holds the caller's terminal, and restores the modes
  when its pipe from the launcher reaches EOF without a "done" byte; in
  passthrough it also takes the foreground back once the payload's group is
  gone. It keeps the caller's stdout while it lives, so a killed launcher in a
  pipeline does not let the caller's shell resume and save the still-raw
  modes before they are restored.
- **A launcher started in the background** waits for the foreground first, as
  any job that needs its terminal does. An orphaned background group is
  refused before any session state exists: the kernel discards the SIGTTOU
  that would stop it, no shell will continue it, and it could neither make
  the terminal raw nor read from it.
- **Signals.** Before the gate, TERM, HUP, INT and QUIT abort the launch
  (128+n after the teardown). After it they are forwarded to the leader,
  through its pidfd, never its pid, which bwrap may have reaped and the kernel
  reused; ^C is 130 under a pty and in a pipeline. A SIGWINCH before the gate
  has no payload to tell, so the gate copies the window size once more.
- **OSC 666 `vte.container.*` termprops** tell a VTE terminal it is attached to
  a container, as toolbox and distrobox do: `name` is the container, `runtime`
  is `flong` and `uid` is the container user's uid. ST-terminated, since VTE
  rejects the BEL form, and written only when stdout is a terminal. The
  launcher writes them, not the wrapper, which execs it: the launcher clears
  them in its teardown, whatever stage the launch reached, and the watchdog
  clears them after a SIGKILL.

**A fixed tty filter in every tier**, which no tier or project can remove:
`ioctl` with request `TIOCSTI`, `TIOCLINUX`, `TIOCSETD` or `TIOCCONS` gets
`EPERM`. The payload holds the caller's real terminal whenever stdin is a tty
and stdout is not, and flong does not control `dev.tty.legacy_tiocsti`. The
kernel reads the request as 32 bits, so the filter compares only the low 32
(`masked_eq`): a plain `eq` rule is bypassed by setting bit 32. In a VM with
`legacy_tiocsti=1`, that bypass injected `echo INJECTED` into the caller's
shell, and `masked_eq` stopped it.

## Seccomp

A session's filter is a policy, compiled at build time from its declaration
and, per project, at launch.

**The compiler** is Zig against libseccomp, reading a line format Nix renders:
`default N|allow`, `allow NAME [CMP…]`, `errno N NAME [CMP…]`,
`log NAME [CMP…]`, where a comparison is `aI:OP:VALUE` or
`aI:masked_eq:VALUE:MASK`. libseccomp silently keeps the first of two
unconditional rules for one call and lets an unconditional rule swallow
conditional ones; the compiler refuses both, so the filter says what the
policy says. It refuses `eq` on an int-typed argument, which needs
`masked_eq`, and it reports how many names libseccomp does not know, so
version skew shows in the build log. It is built ReleaseSafe and checked by
`native-test`, `native-lint` and `native-analyze`, and nothing reaches its
output unless the whole policy is accepted.

**Groups** are expanded at build time from one
`systemd-analyze syscall-filter` dump of `config.systemd.package`, by the
compiler's `expand`, and `render` turns the names into the tier's policy.
That works in the Nix build sandbox and matches the host's own groups. An
unknown group or name fails the build. Nothing at launch calls
`systemd-analyze`: a project's policy is expanded against the same dump.

**The stack**, each filter passed with its own `--add-seccomp-fd` (bwrap
refuses that together with `--seccomp`), in this order:

1. **The tier**: ALLOW its names, the declaration's `errno` (EPERM by
   default) for the rest of systemd's `@known`, ENOSYS for everything else, so
   a call newer than the policy makes a program fall back as it would on an
   older kernel.
2. **The audit mask**: `socket(AF_NETLINK, …, NETLINK_AUDIT)` gets
   `EAFNOSUPPORT`, compared on the low 32 bits of each argument.
3. **The tty filter** (above).
4. **The namespace mask**: `clone` and `unshare` with any `CLONE_NEW*` flag
   and `setns` get `EPERM`, and `clone3` gets `ENOSYS`, because its flags are
   in memory the filter cannot read, and glibc falls back to `clone` on ENOSYS.
   Absent under `nestedSandbox`.

The order decides only which errno a call two of them refuse gets: the most
recently installed filter's. The audit, tty and namespace filters are not
options.

All apply on x86_64, i386 and x32; refusing foreign architectures outright
would compile faster and lose i686 binaries.

### Tiers

- **`parity`** is the allow-list systemd-nspawn installs for a container, with
  the capability-gated rows resolved against the capabilities nspawn keeps by
  default.
- **`strict`**, the default, is parity without `@keyring`, `userfaultfd`,
  `@mount`, `io_uring_*`, `ptrace` and `process_vm_*`. Under the whole stack,
  node, python (venv, pip, multiprocessing), git, go (including `-race`),
  cargo, gcc, make, java, tmux and the claude and codex CLIs behave as under
  parity. strace and gdb break; node tries io_uring
  and falls back without a word.
- **`null`** installs no allow-list, only the fixed filters, and warns.

Loosenings, combinable:

- **`debug`** adds `ptrace`, enough for strace and gdb, whose reach is the
  session's own pid namespace.
- **`nestedSandbox`** raises U2's `max_user_namespaces` (to 128), drops the
  namespace mask and bwrap's assertion, and allows `@mount`. Chromium's own
  sandbox, `codex sandbox` and a nested bwrap need all three together, and ran
  with 16.
- **`allow`** adds names or groups; **`deny`** removes them, after everything
  else, which it overrides.
- **`log`** allows the calls `errno` would refuse and has the kernel log each
  (audit `type=1326`), to learn a policy. It warns.

Headless Chromium works under `strict` with `--no-sandbox`, Playwright's
default. The nixpkgs chromium wrapper looks for a setuid sandbox in
`/run/wrappers`, which is absent, so a consumer running it sets
`CHROME_DEVEL_SANDBOX` empty. flong sets nothing for it.

### Per project

A filter is loaded by bwrap before the payload execs, so a project's policy
must be known before bwrap starts: too early for `postStart`. `seccompPolicy`
runs as the caller after `guard` and prints `allow X…` and `deny X…` lines,
applied to the declaration's names (its allows added, then its denies
removed). chase evaluates a project's envelope there, sends any loosening
through its approver, and prints the result. The fixed filters stay, the tty
filter included.

The result is compiled at launch by `flong-seccomp project`, in one process,
and cached under `$XDG_RUNTIME_DIR/flong/seccomp/<hash>.bpf`, keyed by exactly
what is compiled and by which compiler, so a new compiler makes new filters.
It measured 32 ms cold and 3 ms warm. A policy that prints nothing
compiles nothing, so the warm path stays builtins-only. It needs a tier to act
on, and it is a consistency check in the way `guard` is: the caller can run
`flong-launch` with any filter.

### What the stack costs and what it matches

The filters cost nothing measurable at launch, and 18–35 ns per syscall.

`parity` was compared with nspawn's own filters in one VM (kernel 6.18.51,
systemd 261.2), one container declared under nspawn as root, on `parity` and
on `strict`. Each session's live filters were dumped with
`PTRACE_SECCOMP_GET_FILTER` and evaluated over every syscall on x86_64, x32
and i386, sweeping every argument with the union of every stack's constants
so rows line up. nspawn stacked 5 filters (587, 479, 492, 11 and 16
instructions). flong's were byte-identical to the build's, most recently
attached first: tier (1550 instructions), audit mask (26), tty filter (19),
namespace mask (49). nspawn is no longer in the tree, so `checks.parity` now
keeps this true by checking the byte-for-byte match and that `strict` only
ever refuses more than `parity`.

**The tier and audit mask against nspawn** agree on every x86_64 syscall's
count (328 allowed, 56 EPERM, 640 ENOSYS) and differ on five rows, all
stricter, all the audit mask:

| arch | syscall | arguments | nspawn | flong |
|---|---|---|---|---|
| x86_64 | socket (41) | a0=0x100000010 a2=0x9 | ALLOW | EAFNOSUPPORT |
| i386 | socketcall (102) | a0=0x1 a2=0x9 | ALLOW | EAFNOSUPPORT |
| i386 | socketcall (102) | a0=0x100000001 a2=0x9 | ALLOW | EAFNOSUPPORT |
| i386 | socket (359) | a0=0x10 a2=0x9 | ALLOW | EAFNOSUPPORT |
| i386 | socket (359) | a0=0x100000010 a2=0x9 | ALLOW | EAFNOSUPPORT |

nspawn's `NETLINK_AUDIT` rule compares all 64 bits of `a0`, so `AF_NETLINK`
with a high bit set passes it; `masked_eq` compares the 32 bits the kernel
uses and refuses it.

**The whole parity stack against nspawn** differs further only by 9834
namespace-mask rows (`clone`, `unshare`, `setns`, `clone3`: ALLOW to EPERM or
ENOSYS) and 2184 tty-filter rows (`ioctl`: ALLOW to EPERM). Nothing is looser
and nothing is unexplained; x86_64 counts 326 allowed, 57 EPERM, 641 ENOSYS.
A syscall probe run as the payload differed between nspawn and parity on
exactly five calls, each explained by a filter: `unshare(CLONE_NEWUSER)`,
`unshare(CLONE_NEWUSER|CLONE_NEWNS)` and `setns` get EPERM, a plain `clone3`
gets ENOSYS, and `socket(NETLINK_AUDIT)` with a high bit gets EAFNOSUPPORT.

**Strict against parity** only ever refuses more, every row ALLOW to EPERM:
on x86_64 and x32 `ptrace`, `process_vm_readv`, `process_vm_writev`,
`add_key`, `request_key`, `keyctl`, `userfaultfd`, `io_uring_setup`,
`io_uring_enter`, `io_uring_register`, `mount`, `umount2`, `pivot_root`,
`chroot`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`, `fspick`,
`mount_setattr` and `open_tree_attr`, and on i386 those and `umount`. x86_64
counts 305 allowed, 78 EPERM, 641 ENOSYS.

`rseq_slice_yield` got EPERM under nspawn, parity and strict alike on systemd
261.2; earlier 261.x builds answered ENOSYS under one and EPERM under the
other. It is version-dependent, and nothing relies on either answer.

## What flong honours from the declaration

A refused option is never dropped silently. Most refused options declare less
privilege than the default (a user namespace, fewer capabilities, a network of
its own), and a container that silently differs from its declaration is worse
than one that fails to build.

- `flake`: such a container's path is a per-container profile that only the
  `container@` start script creates, so there is nothing to prepare. A
  container declared by `path` is refused too, since `user`'s ids are read
  from its `config`.
- `privateUsers`: see [Identity](#identity-is-mapped-not-shared).
- `additionalCapabilities`, `enableTun`: nothing in a session holds a
  capability. The payload's bounding set is empty, and there is no
  `CAP_NET_ADMIN` to make a tun device useful.
- `extraFlags`: they are nspawn flags, and flong runs no nspawn.
- `privateNetwork` must be true: every session has a network namespace of its
  own, and `network` gives it a real network.
- `networkNamespace`: a namespace something else built is owned by the
  initial user namespace, and a caller cannot join it from one of their own.
- `hostBridge`, addresses, `forwardPorts`, `interfaces`, `macvlans`,
  `extraVeths`: each is fixed per container, and one declaration runs many
  concurrent sessions. Two sessions would claim one address or one host port.
  `network` configures networking per session.
- `autoStart`: it would boot the container at every host boot as an nspawn
  machine run as root.
- `tmpfs` options other than `mode=`, `size=` and a `uid=`/`gid=` of the user or
  root; `allowedDevices` outside `/dev/` or with a modifier other than `rw`
  or `rwm`; a bind of a `/dev` path.
- Any path the launcher would refuse at launch: not clean (`/`, an empty,
  `.` or `..` component, a component over 255 bytes), two mounts at one
  destination, a source that reaches a protected path, a mask below the depth
  rule.
- The container's name, which names a cgroup and a record: letters, digits,
  `_`, `-` and `.`, not starting with `.`, at most 100 characters.

## Why some NixOS features are absent

- **Setuid wrappers.** `/run/wrappers` is not mounted, and `no_new_privs`
  would defeat a setuid binary anyway.
- **Nix daemon.** The daemon socket is not bound. Through it a session could
  build arbitrary derivations, and a fixed-output derivation is fetched by the
  host's daemon outside the session's network namespace, where no `postStart`
  rule sees it. A `trusted-users` member could also set sandbox options, which is
  root-equivalent. A read-only local store would also miss paths registered
  after the database's last checkpoint. See PLAN.md's `nix` inside a session.
- **A payload `PATH` option.** The payload's `PATH` is the one
  `/etc/set-environment` sets, so the workload's tools belong in the
  container's `environment.systemPackages` or the user's `packages`, and a
  program outside them is named by absolute path, with `lib.getExe`. `path` is
  for the hooks only.
- **`machinectl`.** Sessions are not machines: `systemctl --user` shows and
  stops them, and `nsenter --user --net` (or `--mount --pid`) enters one.

## The security boundary

The threat model is *the payload is an untrusted coding agent*. Against it,
the boundary is at least as strong as running the same container under
systemd-nspawn as root, and stronger in places, **only while every condition
below holds**.

**Who holds what.** A launcher has exactly the caller's privilege, and the
caller holds full capability over every session of theirs from the host: U1
is the caller's, so the caller (or anything running as the caller) can enter
a session's user, mount, network and pid namespaces as U1's root, change its
mounts, rules and cgroup, and read or write anything in it. That is the same
reach the caller has over any process they run. The boundary is between the
payload and everything else, not between the caller and the payload.
`guard`, `seccompPolicy` and the wrapper's checks are consistency checks for
the same reason: the caller can run `flong-launch` with any spec.

**Stronger:**

- No root anywhere, and no sudo grant: a bug in the launcher or a hook is the
  caller's privilege, not root's.
- Nested user namespaces are off by default, twice (U2's limit and the
  namespace mask), which removes the user-namespace kernel attack surface.
  Under nspawn, `unshare -U` in a session gave a full capability set.
- The payload holds no capability over its network namespace, even in
  principle.
- The tty and audit filters compare with `masked_eq`; nspawn's audit rule is
  bypassed with a high bit.
- Mount destinations refuse symlinks everywhere. nspawn follows a planted
  symlink inside a bind, as root.
- Sources are opened with the caller's reach, not root's.
- The gate is a pipe, so the readiness marker's symlink class is gone.

**Equal:** the parity tier's syscall filter (the five rows above are
stricter), the payload's host identity (the caller's uid) and its bind set,
the interactive terminal (a pty of its own).

**Conditions:**

1. Every flong-level mount goes through the walker. The spec's `bwrap-arg` is
   an allow-list with no path mount in it, and the programs are compiled in.
2. Caller and workspace sources are opened with `RESOLVE_NO_SYMLINKS`.
3. Every session has its own cgroup, `nsdelegate` is checked, and the cgroup2
   view is read-only.
4. **No session can reach flong's state, the holder's cgroup, the user
   manager's sockets or a `protect` path** (frisket's control socket, for
   one). All are the caller's: a payload that could write a record would get
   the sweep to run a store program of its choice as the caller, or
   `cgroup.kill` any of the caller's cgroups, and one that could reach the
   manager's bus could start a unit outside the sandbox. Refused at
   evaluation and at launch; the sweep's defences are the second line.
5. The tty filter is in every tier, including a project-loosened one.

**Weaker, accepted:**

- The prepared root's and the records' integrity falls from root's to the
  caller's: anything running as the caller outside a session can poison
  later sessions.
- After a launcher SIGKILL, hook daemons and frisket's listeners last until
  the sweeper runs, within milliseconds.
- Hook daemons of different sessions that entered as U1's root run as the
  same subuid, so they can signal each other. Hooks are trusted code.
- `nestedSandbox` reopens user-namespace kernel surface for the containers
  that opt in.

**Inside a session**, beyond ownership (see
[Identity](#identity-is-mapped-not-shared)): the session's `/` is the
overlay's upper root, owned by the payload's user, so the payload can create
top-level entries in its own session only.

A separate uid range per session, so an escape lands on a uid that owns
nothing of the caller's, is the next layer; see PLAN.md.

## Numbers

Same NixOS VM (4 cores), same container, payload `true`. Medians of 20 over 3
runs, each run after one warm-up launch; a range is the lowest to the highest
of the runs' medians. flong launches as a lingering user with no sudo rule, on
its default seccomp tier (`strict`), timed by a loop inside one
`systemd-run --user` unit, so `systemd-run`'s own cost is in none of its
numbers. nspawn (the root engine flong replaced, for comparison) launches from
the test's root shell, and through `sudo -n` for its own row. The flong column
is reproduced by `packages.bench`; the nspawn column is from the same bench at
d48ad97, while both engines existed.

| | flong | nspawn, root |
|---|---|---|
| no network | 14.6–14.9 ms | 97.0–97.2 ms |
| no network, via sudo as a user | — | 101.8–107.5 ms |
| pasta network + nft hook | 25.1–25.4 ms | 106.0–110.2 ms |
| network + nft hook + fixed `forwardPorts`, waiting for pasta to free it | 45.8–46.1 ms | 107.4–108.4 ms |
| cold (prepare included), no network | 160.3–163.6 ms | 308.7–316.2 ms |

- The nft hook is the same rule for both: a table, an output chain and one
  reject rule, entered as U1's root for flong and as root for nspawn.
- The forwarded-port row times each launch together with a poll, `ss` in a
  loop, until nothing listens on the port: flong waits for pasta itself
  before it returns, and nspawn's launcher did not, so the poll puts both on
  the same footing. It includes at least one fork of `ss`, not measured
  apart.
- Cold removes the prepared root before each launch, untimed.
- p10–p90 for flong: no network 14.4–17.1 ms, network 24.5–28.4 ms, forwarded
  port 39.9–55.0 ms, cold 157.2–170.6 ms. No launch failed. A fork and exec of
  `true` took 1.2–1.4 ms in the same invocations.

Component costs are quoted in their sections, with their harness.

## The native launcher

Three programs, installed side by side by `native.nix`'s `launcher` set:
`flong-launch` and `flong-sweeper`, C in `launcher/`, built by `$CC` with
`-std=gnu11 -O2 -D_GNU_SOURCE -Wall -Wextra -Werror` and fortify (an unchecked
`write`, `read` or `fscanf` is an error), `flong-launch` linking the mount
helper, Zig (`src/mount.zig`, through `src/hybrid/mount_c.zig`), as a static
library with no libc and no compiler-rt; and `flong-init`, Zig
(`src/init.zig`, static, no libc), which `ZIG.md` is porting the rest to. The
store paths they run (bwrap, pasta, tini, flong-init) and
`/run/wrappers/bin/newuidmap` and `newgidmap` are compiled in, so the wrapper
cannot point the launcher at another bwrap.

The launcher began as C, not Zig: the BPF and the runtime were identical, but
a clean Zig build took 78–93 s against C's 1.6 s and needs a 1.8 GiB
compiler, and a typed config format would repeat checks the Nix module's types
already make. `ZIG.md` is the decision to port it anyway, and what the port
has measured since.

### Files

Each header's comments are the specification of what it declares: what it
does, when it is called and how it fails.

| file | owns |
|---|---|
| `flong-util` | messages, trace, descriptors, `fl_await`, `fl_spawn` (clone3), `fl_fork`, pidfds, starttime, small file I/O |
| `flong-spec` | the input contract: argv into `struct fl_spec`, and every check that needs nothing but the spec |
| `flong-ns` | U1 (newuidmap and newgidmap in parallel) and U2 (the split maps, `max_user_namespaces`) |
| `flong-cgroup` | the nsdelegate check, finding or starting the holder, the session cgroup and its leaves, limits, kill, wait, remove |
| `flong-record` | the state directory, the cache lock, records, liveness, the sweep, `postStop`, the sweeper's loop |
| `flong-mount.h` | the mount helper's job and its one call, `flong_mount_main`, which `flong-launch` makes in the forked child |
| `flong-tty` | the foreground wait, the pty relay or passthrough, raw mode, the watchdog, `^]^]^]`, the wait for bwrap |
| `flong-launch.c` | `main`: the order of a launch, bwrap's argv, the hook, pasta, the gate, the one teardown path, exit codes |
| `flong-sweeper.c` | `main` of the holder unit's process |
| `src/mount.zig` | the mount helper, linked into `flong-launch` through `src/hybrid/mount_c.zig`: sources, the walker, masks, overlays, `/sys`, `/run` read-only; no libc |
| `src/init.zig` | `flong-init`, pid 1 in the session: groups, capabilities, controlling tty, ready byte, the gate, chdir, exec tini; static, no libc, no allocator |

Dependencies point one way: util, then spec, then ns, cgroup (then record)
and tty; `flong-launch` uses all of them and the mount helper, `flong-sweeper`
util, cgroup and record. The Zig uses none of them: the mount helper reads
`flong-mount.h`'s job through mirrors checked against the header, and imports
the Zig package's `sys`, `fd` and `msg`, as `flong-init` imports `sys` and
`msg`.

### Conventions

- **Errors.** A function that can fail prints why, once, where it failed,
  and returns -1; its caller unwinds without printing again. Messages are
  `flong-launch: <what>: <strerror>`, or a refusal in plain words in the
  user's terms ("a symlink is on the way to /srv/x").
- **One cleanup path.** `flong-launch` keeps every resource in one struct,
  each descriptor -1 and each pid 0 until it exists. `main` is
  `rc = run(&l); return teardown(&l, rc);`: `run` returns at the first
  failure, and `teardown` undoes whatever exists. A module undoes its own
  partial work before returning -1, so the launcher never sees half a
  resource.
- **Descriptors.** Everything is opened `O_CLOEXEC`. Every program starts
  through `fl_spawn` and every helper through `fl_fork`, each of which closes
  everything not named in `keep`, since a fork keeps descriptors whatever
  their flags: a helper holding the record's lock keeps a dead session alive
  for the sweep, and a watchdog holding the pty master keeps the session's
  terminal from hanging up.
- **Signals.** `main` blocks TERM, HUP, INT, QUIT, WINCH and CONT first and
  reads them from a signalfd, so every wait ends on one as an event and none
  interrupts a step half done. SIGPIPE is ignored. SIGCHLD is reset to its
  default, in the sweeper too: an ignored SIGCHLD survives `execve`, the
  kernel then reaps children itself, and `waitid` says `ECHILD`, which would
  lose a helper's, a hook's or pasta's failure. A terminating signal still
  queued at the gate is taken off the signalfd there, which aborts the
  launch, so the teardown's own waits end only on a signal that comes later.
- **No root.** The launcher and the sweeper refuse a caller of uid 0, and the
  launcher a map that reaches host id 0.
- **No dead code**: no test-only knob, no variant kept for comparison, no
  fallback that nothing reaches.

### The input contract

The wrapper runs `flong-launch` with the whole spec as its arguments: keywords,
each followed by a fixed number of fields, then `--` and the payload's
command. An argument is already NUL-terminated, so a path may hold a tab or a
newline, and bash builds and passes the list with builtins alone; bash cannot
hold a NUL in a string, so a spec file or a pipe would cost a fork or a
temporary file per launch. Keywords come in any order; repeatable ones
accumulate in order. `R` required, `1` at most once, `*` repeatable.

| keyword and fields | | meaning |
|---|---|---|
| `machine NAME` | R | the session's name: record, cgroup, `$machine`. `[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}` |
| `container NAME` | R | the cgroup level between the holder and its sessions; the same charset |
| `state DIR` | R | `$XDG_RUNTIME_DIR/flong`: the caller's, mode 0700 (checked) |
| `cache DIR` | R | the cache; the root is `DIR/prepared`; locked shared for the launch |
| `relaunch ARG` | * | the wrapper's own argv, exec'd when the cache was swept before it was locked |
| `closure PATH` | R | the container's toplevel, bound at `/run/current-system`; it and its target under `/nix/store/`, with no empty, `.` or `..` component |
| `uidmap IN OUT COUNT` | R* | an extent of U1's uid map |
| `gidmap IN OUT COUNT` | R* | the same for gids |
| `user UID GID HOME` | R | the payload's container uid, gid and home |
| `group GID` | * | a supplementary group |
| `chdir DIR` | 1 | where the payload starts (the workspace); `/` when absent |
| `mount bind-ro DEST SRC`, `bind-rw` | * | a declared bind; the source follows symlinks |
| `mount bind-ro-exact DEST SRC`, `bind-rw-exact` | * | a caller's bind or the workspace: `SRC` is canonical, and a symlink on it refuses |
| `mount dev DEST SRC` | * | an `allowedDevices` node: a read-write bind that is not `nodev` |
| `mount tmpfs DEST MODE SIZE OWNER` | * | `MODE` octal; `SIZE` tmpfs's `size=`, or empty; `OWNER` `root` or `user` |
| `mount overlay DEST LOWER` | * | reads `LOWER`; writes go with the session |
| `mount mask DEST` | * | a mode-0 read-only node over an existing `DEST` |
| `protect PATH` | * | no mount source may equal, lie inside or contain `PATH`, compared canonicalised (a part that does not exist yet is appended, as spelt, to the canonical path of its longest existing prefix) |
| `seccomp PATH` | * | a compiled BPF program; each becomes one `--add-seccomp-fd`, in order |
| `nested-userns N` | 1 | `nestedSandbox`: U2's `max_user_namespaces` is `N`, and `--assert-userns-disabled` goes |
| `holder REL` | R | the holder's cgroup below `user@UID.service`: `app.slice/flong-sessions.service` |
| `holder-start ARG` | * | argv run when the holder is absent; the first an absolute path, since nothing searches `PATH` |
| `limit FILE VALUE` | * | an opt-in limit, `FILE` one of `memory.max`, `memory.high`, `memory.swap.max`, `memory.oom.group`, `pids.max`, `cpu.max`, `cpu.weight`, `io.weight` |
| `post-start ARG` | * | the `postStart` program and its arguments; none, no hook |
| `post-stop PATH` | 1 | the `postStop` program, under `/nix/store/`, recorded for the sweep |
| `network` | 1 | start pasta |
| `pasta-arg ARG` | * | pasta's port and DNS flags |
| `pasta-wait` | 1 | fixed `forwardPorts`: the teardown waits for pasta's exit |
| `bwrap-arg ARG` | * | one argument for bwrap, from the allow-list below |
| `keep-fd N` | * | an open descriptor a `bwrap-arg` names, passed to bwrap only |
| `trace` | 1 | stage timestamps on stderr, `T <µs> <stage>` |
| `-- COMMAND…` | R | the payload, run as `tini -g -- COMMAND…` |

**`bwrap-arg` is an allow-list**: `--clearenv`, `--setenv VAR VALUE`,
`--unsetenv VAR`, `--hostname NAME`, `--perms OCTAL` immediately before
`--ro-bind-data`, and `--ro-bind-data FD DEST` with `FD` a `keep-fd`. The
parser walks them with their arities and refuses anything else, so a path
mount here is a wrapper bug the launcher catches (condition 1).

A spec never carries the programs, U2's maps (derived from U1's), the fixed
mounts, `/sys`, `/run` read-only, the nsdelegate check, or anything about
seccomp policy beyond the compiled files.

**bwrap's argv** is, in this order, so the fixed part cannot be undone by the
wrapper's part, and flong-init's protocol follows everything:

```
bwrap --userns <U1> --userns2 <U2> [--assert-userns-disabled]
  --unshare-net --unshare-pid --unshare-ipc --unshare-uts --unshare-cgroup
  --die-with-parent --as-pid-1 --info-fd <info>
  [--new-session]                                    (relay only)
  --add-seccomp-fd <fd> ...                          (one per seccomp, in order)
  --cap-add CAP_SETGID --cap-add CAP_SETPCAP         (for flong-init, which drops them)
  --uid <UID> --gid <GID>
  --overlay-src <cache>/prepared --tmp-overlay /
  --ro-bind /nix/store /nix/store --ro-bind /nix/var/nix/db /nix/var/nix/db
  --proc /proc --dev /dev
  --perms 0755 --tmpfs /run
  --ro-bind <closure> /run/current-system
  --perms 0755 --dir /run/user --perms 0700 --tmpfs /run/user/<UID>
  --perms 1777 --tmpfs /tmp
  --ro-bind /sys /.hostsys                           (the mount helper detaches it)
  <bwrap-arg ...>
  -- flong-init <gate-fd> <ready-fd> <groups> <ctty|-> <trace|-> <dir> -- <COMMAND...>
```

### The launch, in order

| # | step | call | trace stage |
|---|---|---|---|
| 1 | block signals, ignore SIGPIPE, SIGCHLD to its default | `main` | `launcher-start` |
| 2 | parse; refuse uid 0; then the signalfd, so its number is never one a `keep-fd` names | `spec_parse` | |
| 3 | open and check the state directory | `state_open` | |
| 4 | lock the cache shared; swept: exec `relaunch`, or exit 75 | `cache_lock` | `cache-locked` |
| 5 | close inherited descriptors except `keep-fd`s and our own | `fl_close_from` | |
| 6 | wait for the foreground, choose relay or passthrough, open the pty | `tty_prepare` | |
| 7 | nsdelegate; find or start the holder | `cg_check_nsdelegate`, `cg_holder_find` | |
| 8 | the inline sweep | `rec_sweep` | `swept` |
| 9 | the record, locked, with `poststop=` and `cgroup=` | `rec_create` | `recorded` |
| 10 | U1, then U2 | `ns_create` | `U1-mapped`, `U2-made` |
| 11 | the session cgroup, limits, leaves | `cg_session_create` | `cgroup-made` |
| 12 | open the seccomp files; the info, ready and gate pipes; bwrap in the sandbox leaf | `fl_spawn` | |
| 13 | read `--info-fd` until `child-pid`; hold the leader's pidfd and network namespace; append `leader=` | `rec_set_leader` | `bwrap-child` |
| 14 | fork the mount helper, which prepares sources, waits for the ready byte, then mounts `/sys`, the declared mounts and `/run` read-only | `fl_fork`, `flong_mount_main` (`src/mount.zig`) | `sandbox-ready`, `mounts-done` |
| 15 | `postStart` in the hooks leaf, waited for | `fl_spawn`, `fl_reap` | `hook-done` |
| 16 | pasta in the pasta leaf, ready when the spawned pasta exits 0 | `fl_spawn`, `fl_reap` | `pasta-up` |
| 17 | save modes, start the watchdog, then raw (relay); take queued signals; copy the window size; write the gate byte | `tty_start`, `fl_take_signal` | `gate-open` |
| 18 | wait for bwrap | `tty_wait` | `bwrap-exited` |
| 19 | teardown | `teardown` | `poststop-done`, `pasta-gone`, `released` |

A failure or a terminating signal at any step before the gate goes straight
to the teardown, and the gate is never written.

- **The helper is forked at child-pid, not at the ready byte**, so its source
  work overlaps bwrap's setup; it does nothing in the session's mount
  namespace before the byte.
- **bwrap's death also ends the waits of steps 13 and 14.** bwrap's child was
  seen to outlive bwrap before it had execed flong-init, still holding the
  info and ready pipes' write ends, so neither pipe reported EOF.
- **The info pipe's read end stays open until exit.** bwrap 0.12 writes its
  JSON in several writes (the child pid, each namespace id, the closing
  brace), and a launcher that closed the pipe once it had the pid killed
  bwrap with SIGPIPE, silently, in about 1 launch of 100 under load. The rest
  of the JSON is never read; it fits in the pipe.

### Exit codes

| status | when |
|---|---|
| the payload's | the gate opened: bwrap's status, which is pid 1's, which is tini's, which is the payload's; 128+n when a signal killed it |
| 125 | the payload never ran: a refusal, a failed step, a failing hook, pasta failing (a host port in use), bwrap failing, flong-init's gate EOF. stderr says which |
| 75 | the cache was swept before it was locked, and there is no `relaunch` |
| 128+n | a terminating signal n reached the launcher before the gate: the launch was aborted and torn down |

After the gate a signal is forwarded, not acted on, so the payload's status
tells what happened: `^C` is 130 under a pty and in a pipeline, `^]^]^]` is
137. A failing `postStop` is reported and does not change the status. 125
collides with a payload's own 125, as it does for `env` and `chroot`. The
wrapper's own refusals exit 1.

### Layouts on disk

```
$XDG_RUNTIME_DIR/flong/                     0700, the caller's
  sessions/<machine>                        a record; its lock is the launcher's
  seccomp/<hash>.bpf                        a project's compiled filter
  <container>-<closure>-<steps>-<map>/      a cache
    prepared/                               the root, owned by subordinate ids
    .prepare.lock
    prepare.log
  .trash.*                                  a cache being deleted
```

The cgroup layout is under [The layout](#the-layout).
