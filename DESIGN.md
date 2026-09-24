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

The launcher is `flong launch`, a Zig program, static and without libc, run
as the caller: each declaration's command is a link `NAME -> flong`, which
loads `/etc/flong/NAME.zon` (then `$XDG_CONFIG_HOME/flong/NAME.zon`) as
`flong launch NAME -- ARGS` does, and judges it as `flong check` does.
Nothing in it runs as host root, and nothing asks for it.

Its prologue works out what only the launch can know, in the order the bash
wrapper it replaced did (`src/launch/assemble.zig`):

1. Refuse a caller of uid 0 or of primary group 0. Use `/run/user/$UID`,
   which must exist and be the caller's.
2. `workspace`, then `binds`, then `guard`, each as the caller.
3. Name the session `<container>-<launcher pid>-<random>`, then run
   `seccompPolicy`, as the caller, and compile what it prints.
4. Check the depth rule against the caller's writable binds.
5. Build the id maps from `/etc/subuid` and `/etc/subgid`.
6. Prepare the root if this closure, prepare program and map have none yet.
7. Read `user`'s uid, gid, home and groups from the prepared root.
8. Build the spec, as a value, and hand it to the launch.

The launch then runs the session, in this order (the full table is in
[The launch, in order](#the-launch-in-order)):

1. Lock the cache shared, for the launcher's life.
2. Sweep: release what dead sessions of this caller left behind.
3. Write the session's record.
4. Make U1 and U2, the two user namespaces.
5. Make the session's cgroup, with any declared limits.
6. Start bwrap in the session's cgroup; learn its child's pid.
7. Fork the mount helper at bwrap's child pid; it mounts once flong init
   reports the root built.
8. `postStart`, then pasta (with `network`).
9. Open the gate: flong init execs tini and the payload.
10. Wait for the session. Then kill its cgroup, run `postStop` and release
    the rest.

On the warm path the prologue forks nothing but the commands the
declaration chose, as the bash wrapper, whose every test was a builtin, did
before it. A bash launcher measured 61 ms and a python one 106 ms, against
the C launcher's 19 ms, which is why everything after the spec was native
code, and why the prologue is now too. The Zig launcher that replaced the C
is within the runs' spread of it, and moving the wrapper's work into it took
a warm launch from 14.3–15.3 ms to 11.2–11.9 ms (`packages.bench`, [What the
port measured](#what-the-port-measured)).

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
- **The hooks are commands, never shell.** `workspace`, `binds`, `guard` and
  `seccompPolicy` run at launch because what they answer is known only then
  (the repository around the caller's working directory, what travels with
  it, a project's own syscall policy) or is a judgement on this launch;
  `postStart` and `postStop` because they act on the session. Each is an
  argument list run as it is, with the launcher's arguments after its own
  (they were shell snippets until the declaration became data; see [The
  declaration](#the-declaration)), and all but
  `workspace` are lists of them, which a module such as frisket's adapter
  adds to: several modules' lists merge, ordered with `mkBefore` and
  `mkAfter`. flong runs no shell of its own; a hook that wants one names a
  script.

A declaration reaches flong as data and nothing else. `module.nix` renders
each one to `/etc/flong/<name>.zon` (`nix/to-zon.nix`), and `flong launch`
reads it with the typed parser `flong check` judges it with, so a name, a
path or a command's word is a value there, never code. The spec holds each
`postStart` and `postStop` command as one entry, and runs them in order,
stopping at the first that fails; module.nix puts each command behind its
declaration's hook program, `flong-poststart-<name>` or
`flong-poststop-<name>` (the declaration's `postStartProgram` and
`postStopProgram`), which puts `path` on `PATH`, drops the machine name the
record appends to a `postStop` command, and execs the command. The caller's
own commands (`workspace`, `binds`, `guard`, `seccompPolicy`) get `path` as
the declaration's `commandPath`, in front of `PATH`. The prologue exports
nothing of its own but what the commands are documented to see, so a
variable of the caller's reaches them and the launch as it came.

## `command` is exec'd through the container's environment

The payload script `cd`s into the workspace and runs
`bash -c '. /etc/set-environment; exec "$@"'` with `command` and the launcher's
arguments as that bash's positional parameters. None of them is ever the text
of a script, so a space, `;`, `$` or glob in any argument arrives as that
character. The spec is a value inside `flong launch` and bwrap takes each
path as a whole argument, so nothing on the way splits or expands a word
either.

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
- **The recheck relaunches flong.** A launcher that opened its cache
  before a sweep renamed it, and locked it after, finds that the path no
  longer names the inode it locked. A sweep may also have taken the cache
  and another launch made one afresh at the same path, which that launch
  still holds shared while it prepares: so the launcher also requires
  `prepared/` to be there. Either answer execs flong again,
  `/proc/self/exe` with the launch's own argv (so a link's name is looked
  up again), which prepares afresh or waits on the preparer's lock; so do
  the three points of the prologue that find the cache swept before they
  hold it. There is no count: each turn follows a sweep's rename, an event.
  A relaunch runs `guard` and `seccompPolicy` again.

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
  prepared root's `/etc/group` that names the user. flong init sets exactly
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
command commonly runs `git` there, which reads configuration from the
repository it is pointed at; as the caller, that grants nothing the caller
lacked. The default, `null`, is taken without a fork. The printed path is
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
caller can run `flong launch` directly with any spec. So it catches a launch
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
all that survives. `postStart` and `postStop` commands are run through
programs of their own in the store, which give them `path` and exec them,
because the launcher and the sweeper run them with the environment they give
them, and the sweeper may run a superseded generation's `postStop`.

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
2. It waits for flong init's ready byte: bwrap has finished the root.
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
  the holder's cgroup. `flong check` makes the same check lexically when
  the declaration's file is built. See
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
  declaration's writable binds by `flong check` at build, and against the workspace and
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
  fails. It costs 0.1 ms in the mount helper (measured when it was C),
  against 9 ms through `nsenter` and `sh`.
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
exported by the prologue (`src/launch/assemble.zig`). The namespaces are named by descriptors the
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
dies. So flong init, which bwrap execs as the session's pid 1, is the gate.
Its protocol is its argv, not the environment, so the spec's `--clearenv`
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
the cache's recheck relaunches flong, and a taken session name waits
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
  supervisor/                                         flong sweeper
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
poststop=<commands>         the session's own postStop commands, if any
cgroup=<path>               its session cgroup
leader=<pid>:<starttime>    appended once bwrap reports its child
```

- **`poststop=` is a list of commands**, run in order: the commands
  separated by 0x1E, each command's words by 0x1F, its program first. A
  record is lines with no escaping, a value its bytes up to the newline,
  and neither separator is a byte a store path or the module's words hold,
  so the launcher refuses a word holding either (or a newline) rather than
  escaping it, and the value, at most `PATH_MAX - 1` bytes like every
  other, reads one way only. There is no compatibility layer: a record
  written before the list, one store path, reads as one command of one
  word, which is how it ran.

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
  container, and a rebuild changes the commands, so the sweep runs the store
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
environment, runs a command only when its program is an executable
`/nix/store` path whose target is also in the store, requires `cgroup=` to spell exactly
`<holder>/<container>/<machine>` for the record's own machine before anything
is killed, and requires `leader=` to match its starttime. A record that is not
well formed, or does not name a session's cgroup, is unlinked and nothing it
says is acted on. A record whose cgroup lies under another holder (another
unit of the caller's, or a launch with and one without a user manager) is
left for that holder's sweep: its cgroup is not this sweep's to kill, and its
`postStop` must still run. A cgroup that cannot be opened for a transient
reason (`EMFILE`, `ENOMEM`) keeps the record, the only trace of what is left.

`postStop`'s commands run in order, each with its own words, then
`$machine` as its last argument. A failing command (a non-zero status, or a
program the checks refuse) is reported, ends the list, and the list counts
as run. A signal while one runs kills it and leaves `poststop=` in place, so
the next sweep runs the whole list again.

### The sweeper

`flong sweeper $XDG_RUNTIME_DIR/flong` is the holder unit's one process. It
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
2. Close the gate's write end if it is still open: flong init, if it exists,
   reads EOF and exits 125.
3. `cgroup.kill`: every process in the session, bwrap and the helper
   included.
4. Reap what is ours: bwrap, the mount helper, the hook, the spawned pasta.
5. Wait for the sandbox leaf, then the hooks leaf, to empty.
6. Run `postStop`'s commands in order, if the record has any, stopping at
   the first failure, then blank `poststop=` in the record.
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
`--new-session` and flong init takes the pty as its controlling terminal. The
caller's terminal is raw only between the gate and the payload's exit.
SIGWINCH, SIGTERM, SIGHUP, SIGINT and SIGCONT are handled, and `^]^]^]` within
a second ends the session (exit 137), as nspawn's escape does. The escape is
read with the rest of stdin, which the relay reads only once the payload has
taken what was read before, so while the payload reads no input `^]^]^]`
waits (quirk 10, `src/tty.zig:594`). Measured:
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
  launcher writes them, so it clears them in its teardown, whatever stage
  the launch reached, and the watchdog clears them after a SIGKILL.

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
`flong launch` with any filter.

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
namespace mask (49). These counts were first measured with the C compiler;
the Zig compiler's filters are the C's byte for byte (123 comparisons over
every tier and variant, and `golden`'s `.bpf` files, recorded from the C),
so they stand. nspawn is no longer in the tree, so `checks.parity` now
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
`guard`, `seccompPolicy` and the prologue's checks are consistency checks
for the same reason: the caller can run `flong launch` with any declaration
file.

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

1. Every flong-level mount goes through the walker. The spec's only bwrap
   options are typed (the resolver's file, the environment, the hostname),
   with no path mount among them, and the programs are compiled in.
2. Caller and workspace sources are opened with `RESOLVE_NO_SYMLINKS`.
3. Every session has its own cgroup, `nsdelegate` is checked, and the cgroup2
   view is read-only.
4. **No session can reach flong's state, the holder's cgroup, the user
   manager's sockets or a `protect` path** (frisket's control socket, for
   one). All are the caller's: a payload that could write a record would get
   the sweep to run a store program of its choice as the caller, or
   `cgroup.kill` any of the caller's cgroups, and one that could reach the
   manager's bus could start a unit outside the sandbox. Refused at
   build, by `flong check`, and at launch; the sweep's defences are the
   second line.
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
is reproduced by `packages.bench`, and is its run at b197e54, the first
without the bash wrapper; the nspawn column is from the same bench at
d48ad97, while both engines existed.

| | flong | nspawn, root |
|---|---|---|
| no network | 11.2–11.9 ms | 97.0–97.2 ms |
| no network, via sudo as a user | — | 101.8–107.5 ms |
| pasta network + nft hook | 23.9–24.6 ms | 106.0–110.2 ms |
| network + nft hook + fixed `forwardPorts`, waiting for pasta to free it | 42.1–45.0 ms | 107.4–108.4 ms |
| cold (prepare included), no network | 156.9–162.9 ms | 308.7–316.2 ms |

- The nft hook is the same rule for both: a table, an output chain and one
  reject rule, entered as U1's root for flong and as root for nspawn.
- The forwarded-port row times each launch together with a poll, `ss` in a
  loop, until nothing listens on the port: flong waits for pasta itself
  before it returns, and nspawn's launcher did not, so the poll puts both on
  the same footing. It includes at least one fork of `ss`, not measured
  apart.
- Cold removes the prepared root before each launch, untimed.
- p10–p90 for flong: no network 11.1–13.5 ms, network 23.2–28.6 ms, forwarded
  port 37.8–53.0 ms, cold 154.7–167.6 ms. No launch failed. A fork and exec of
  `true` took 1.3–1.4 ms in the same invocations.
- With the bash wrapper in front (c83dcde), the same bench gave 14.3–15.3,
  27.1–27.5, 47.0 and 167.3–170.3 ms ([What the port
  measured](#what-the-port-measured)).

Component costs are quoted in their sections, with their harness.

## The native launcher

Two programs and the tests' fixtures, all Zig 0.15.2: `flong-seccomp`, the
policy compiler, with its `expand`, `render` and `project` subcommands, which
links libc through libseccomp; and `flong`, static, stripped and without
libc, whose subcommands are `launch`, `init` (pid 1 in the session),
`sweeper` (the holder unit's process), `check`, `schema`, `list`, `version`
and `help`. `src/main.zig` picks the subcommand from `argv[0]`'s basename,
then from `argv[1]`, as busybox does, and makes no syscall doing it; a
basename that is no subcommand is a declaration's name ([The declaration's
command](#the-declarations-command)). Until the one binary ([One
binary](#one-binary)), `flong launch`, `flong init` and `flong sweeper` were
three, `flong-launch`, `flong-init` and `flong-sweeper`, and the
measurements below that name those are of the three. The programs `flong
launch` runs (bwrap, pasta, its own binary as
`flong init`, `/run/wrappers/bin/newuidmap` and `newgidmap`) and the tini
`flong init` execs are compiled in, as build options with no default
(`-Dbwrap`, `-Dpasta`, `-Dself`, `-Dnewuidmap`, `-Dnewgidmap`, `-Dtini`;
`build.zig`'s `LaunchPaths`), so no caller can point the launcher at
another bwrap, and a build that forgets one fails. So are the two its
prologue runs: `-Dcache`, the cache tool
(`cache.nix`), and `-Dseccomp`, `flong-seccomp`;
`flong version` prints every one, `NAME=PATH` a line.

Line numbers that cite the deleted C (`launcher/flong-*.c` and `*.h`,
`seccomp/flong-seccomp.c`, `tests/parity/*.c`) are those of the C as it last
stood, `launcher/` at a103e76 (unchanged since a7919be), unless the citing
file names another commit. Every Zig module's `//!` comment names the C it
ports. The port's phases (0 to 8) and the launcher's milestones (L0 to L5),
which some comments name, are those of its plan, `ZIG.md`, deleted when the
port was done and in git at e717355. `build.zig` and the modules the seccomp
set is built from (`src/seccomp/`, `sys`, `fd`, `msg`, `errno`, `num`) still
cite `ZIG.md` by section: editing them, even a comment, moves the seccomp
set's store path and with it every project cache key (quirk 36), so they
change with the next edit that moves it anyway. Likewise the phases S1 to
S4, and the chunks of S2 (0, A to E) and S3, are those of the plan that made
the three one binary, the declaration data and the bash wrapper Zig,
`STANDALONE.md`, deleted when it landed and in git at bed8750; `build.zig`
still cites it by section, for the same reason. `rootless-wrapper.bash`,
which `src/launch/`'s comments cite by line, is in git until b197e54
deleted it.

### Why Zig, and what it cost

The launcher began as C: a clean Zig build took 78–93 s against C's 1.6 s
and needed a 1.8 GiB compiler, for identical BPF and runtime. It moved to
Zig anyway, one program at a time on trunk (2026-09-23 to 24), so that
descriptor and process bugs are hard to write: every descriptor is a typed
handle in one table, a forked child cannot return into its parent's
cleanup, and raw syscalls live in one layer that a linter enforces. Each
program ran beside the C it replaced, with a check comparing the two,
before the C was deleted. The decisions that stand:

- **Zig 0.15.2, from nixpkgs' `zig_0_15`** (the locked nixpkgs' unqualified
  `zig` is 0.16). Build time is a cost to report and mitigate, never a
  reason to reconsider the language. minish (property tests) and zwanzig
  (static analysis) are lazy dependencies pinned to tags (minish v0.1.0,
  zwanzig v0.15.1, `build.zig.zon:8-16`).
- **flong-seccomp keeps libseccomp**, so its filters are libseccomp's bytes;
  flong has no libc, with glibc's errno texts in `errno.zig`
  and an `/etc/passwd` reader in `passwd.zig` for the one `getpwuid`.
- **Nothing observable changed.** Every string a test asserts, every exit
  status, bwrap's and pasta's argv, the record bytes and the BPF bytes
  are the C's, but flong-seccomp's usage line, which names the
  subcommands (quirk 16), and the texts [Kept behaviour](#kept-behaviour)
  lists as changed. What a test cannot see is recorded there too, as kept,
  done another way, or changed.
- **aarch64 is cross-built**, not run: `cross-aarch64` builds the static
  programs for it and compiles flong-seccomp and bpfdump unlinked; the VM
  tests are x86_64's.
- **Timing is reported, never gated.**

What it cost and what it bought, from [What the port
measured](#what-the-port-measured):

- **Behaviour is the C's.** flong-seccomp's filters were the C's byte for
  byte over 123 comparisons (every tier and variant, the fixed filters, the
  refusal corpus), and 87,000 fuzzed policies differed in nothing. The
  seccomp tooling's text, keys and filters equalled the awk and bash's over
  109 comparisons. flong-init as pid 1 made the C's syscalls call for call
  on five paths under `strace -f`, the C's allocations aside, with no
  syscall of start code before them. The mount helper gave the C's output
  and status under every mount, refusal and protected-path case, and the
  swap race escaped 0 of 40 under each. The sweeper's readers equalled the
  C's over 10,000 inputs each, and both sweepers left byte-identical
  records, cgroups and `postStop` logs. The fixtures' 111 comparisons were
  equal. flong-launch gave the C's bwrap, pasta and flong-init argv, every
  child's environment and descriptors, its own descriptors, stdout, stderr
  and status over six launch variants, and an `strace -f` of both over 40
  launches the same calls in the same order in each process, the kept
  mechanisms aside. `golden` pins what the C printed, recorded from it once
  and never regenerated.
- **Build cost.** Each Nix build starts with an empty Zig cache, so every
  derivation compiles its build runner and compiler-rt again. Rebuilt from
  nothing, each bit-identical: the seccomp set 10.9–11.6 s, the launcher
  set 19.6 s (the C launcher's set 16.8 s), the fixtures 8.5–9.3 s;
  `native-test` 15.7 s in Debug and 26.9 s in ReleaseSafe; `native-lint`
  4.5 s; `native-analyze` 76–88 s, most of it building zwanzig. `zig_0_15`
  is a 231.6 MiB download, 926 MiB unpacked, and a build input only: no
  output may refer to it.
- **Size.** Zig binaries are larger and closures smaller: flong-launch
  446,448 bytes static against the C's 234,976 dynamic (which linked the Zig
  mount helper), flong-init 40,312 against 17,408, flong-sweeper 142,272
  against 49,808, flong-seccomp 144,784 with its subcommands (the C compiler
  alone was 17,256). Over the port the launcher set's closure fell from
  54,318,016 bytes to 44,256,760, and flong-seccomp's from 48,454,728 to
  38,057,520 (the C compiler's held gcc's runtime library and its source).
- **Speed.** `packages.bench` put each Zig program within the runs' spread
  of the C's on every row (no network, pasta with a hook, a forwarded port,
  cold); the cold row's order between C and Zig flipped between two pairs
  of runs. A project's policy compiles in one process in 31.6 ms cold and
  3.4 ms warm, where the bash it replaced took 85.8 and 42.4 ms.
- **What the types and checks caught.** The handle table catches double
  closes, use after close, a closed alias, stale copies in structs and in
  fork children, and one kind used as another; each of the port's planted
  mutations (a child ignoring its keep list, a close without the generation
  bump, a spawn skipping the signal reset, `dup2` without staging, a stale
  signalfd in a child, a wait ignoring POLLHUP) was caught by `native-test`.
  The prototype's table itself had three bugs the port fixed: a fork child
  and a spawned child that failed silently, and a child leaked when its
  pidfd found no slot. Differential fuzzing of the seccomp tooling found
  four differences from the bash, each fixed.
- **CI.** One `nix flake check` took 7 min 49 s to 14 min 53 s while the
  port ran. As a matrix of one job per check with the Cachix cache, a push
  that changes the native code takes about 5–6 min (5 min 38 s for a103e76,
  run 35995141108; 5 min 54 s for e717355, run 35996579837, its longest leg
  `native-test-release` at 4 min 34 s) and one that changes only docs about
  3–4 min (3 min 18 s and 3 min 39 s, runs 35991513067 and 35992523422).

### What the port measured

Measured on the development host (32 cores, kernel 6.18.51, Zig 0.15.2,
x86_64, ReleaseSafe) unless named; the code cites these rows. The
binary sizes and closures are the tree's after L5 and the timings L4's,
unless a row names its phase or commit.

| what | value |
|---|---|
| start code, `stack_size = 0` and `single_threaded` | no syscall before `main`; as pid 1 under bwrap the first call after `execve` is `main`'s. With Zig's default stack the start code reads and then sets `RLIMIT_STACK` to 16 MiB (`start.zig:545-578`), which the payload's `ulimit -s` then shows; without `single_threaded`, an `arch_prctl(ARCH_SET_FS)` (`:504-519`) |
| a returning single-threaded `main` | ends in `exit`, not `exit_group` (`posix.zig:777-789`) |
| panics | Zig's default ends in `abort`; pid 1 drops its own SIGABRT and dies of SIGSEGV (`posix.zig:680-727`). `std.debug.FullPanic(msg.onPanic)` prints one line and exits 125 through bwrap |
| `std.os.linux` | wraps neither `clone3` nor `setns` (raw calls, numbers 435 and 308 on x86_64); `std.posix` turns errnos a caller must see into `unreachable` (`posix.zig:5478-5481` and others); `linux.sigaction` asserts on SIGKILL and SIGSTOP (`linux.zig:1857-1861`); `O.TMPFILE` is one bit, where the kernel's `O_TMPFILE` is `__O_TMPFILE\|O_DIRECTORY` |
| `clone3(CLONE_INTO_CGROUP\|CLONE_PIDFD)` | into an `O_PATH` leaf of a `Delegate=yes` unit the child starts in the leaf and `waitid(P_PIDFD)` reaps it; into `system.slice`, EACCES; after `setns(CLONE_NEWUSER)` it still lands (`checks.native`'s `proc:` subtests) |
| a `noreturn` fork body | a body that returns does not compile (`tests/zig/compile_fail/fork_body_returns.zig`); a working body runs once and the parent's `defer` once, in the parent; a panicking body exits 125 with one line |
| Zig's bundled headers | `any-linux-any` is kernel 6.13.4 (`LINUX_VERSION_CODE` 396548; no `STATMOUNT_MNT_UIDMAP`); translate-c with `-target <arch>-linux-musl` reads only them, never `pkgs.linuxHeaders`. Every struct and constant of `sys.zig` equals them on x86_64 and aarch64 (`abi`) |
| lazy dependencies | an unguarded `lazyDependency` makes an offline `zig build install` fail fetching it (`build_runner.zig:370`); `zig_0_15.fetchDeps { fetchAll = true; }` is one fixed-output derivation of 2.2 MiB (minish 0.1.0, zwanzig 0.15.1, zwanzig's chilli 0.2.2), linked at `$ZIG_GLOBAL_CACHE_DIR/p` |
| a `b.path` outside a set's fileset | lazy: a set configures and installs from `build.zig`, `build.zig.zon` and its own sources; a step that reads the missing path fails naming it |
| Nix's fixup and Zig outputs | strips `bin/` only, with `strip -S`, and no aarch64 ELF; an unstripped artifact names Zig's `lib/std` and trips `disallowedReferences`, so `build.zig` strips every installed artifact |
| aarch64 | every static program builds; under qemu-aarch64 `statmount` is ENOSYS (qemu's), so the mount calls have run on x86_64 only; a library leaves the page size to `getauxval` (`std/heap.zig:82`) |
| the mount calls under `unshare -Urm` | `fsopen`/`fsconfig`/`fsmount`, `move_mount`, `statmount` by the statx unique id (stable across the move), `mount_setattr` read-only then EROFS, `open_tree(OPEN_TREE_CLONE)` inheriting it, `openat2`'s `RESOLVE_BENEATH` (EXDEV) and `NO_SYMLINKS`/`NO_MAGICLINKS` (ELOOP) |
| the walker against the symlink swapper (`checks.native`) | a path open that follows symlinks escaped 11–108 of 200; the walk 0 of 400, with each swapper |
| zwanzig v0.15.1 | its CLI reports no leak, and a handle stored in a struct counts as escaped, so leaks are the table's; models match on the method name alone (`receiver_type` and `fqn` do not resolve imported types); a close model for `fd.closeChecked`, `reapNow(.kill)` and `try c.await()` as an ending are not honoured, which only loses findings |
| terminal, kernel 6.18 | a write to the pty master after the last slave closed succeeds, so no test asserts the C's EIO for input writes |
| a sweeper's `waitEmpty` | can wait forever when another process of the user removes the cgroup inside the kernel's 10 ms `cgroup.events` delay, as the C could; kept |
| derivations, `nix build --rebuild`, empty Zig cache | seccomp 10.9–11.6 s, launcher 19.6 s, fixtures 8.5–9.3 s, each bit-identical; `native-test` 15.7 s Debug, 26.9 s ReleaseSafe; `native-analyze` 76–88 s; `native-lint` 4.5–8 s; `cross-aarch64` 7–19 s |
| `flong`, S1 | 513,200 bytes, stripped and static as the three were, against their sum of 629,032: the shared modules, std and the start code are in it once |
| `flong`, S2 to S4 | 521,976 bytes before `flong check` and `flong schema`, 1,254,968 with them (the ZON parser, the schema's walk and its doc comments); 1,474,040 with the prologue beside the argv spec (41e2607), 1,398,936 once the argv spec went (b197e54); 1,417,640 with `flong help` (bed8750). Its closure, which holds the cache tool and flong-seccomp it runs, is 112,295,408 bytes |
| `packages.bench`, before and after S3, medians of 20 over three runs, ms | the bash wrapper (c83dcde): no network 14.3–15.3, pasta and an nft hook 27.1–27.5, a forwarded port 47.0, cold 167.3–170.3; `flong launch NAME` (41e2607): 11.0–11.4, 23.4–24.9, 41.9–43.0, 156.7–158.7; with the wrapper gone (b197e54): 11.2–11.9, 23.9–24.6, 42.1–45.0, 156.9–162.9 |
| `flong check` | a megabyte of masks and binds in about a second, every lookup a search of a sorted list; before `decl.notZon`, a file of 100,000 `.{` or `-` overflowed `std.zon.parse`'s stack and ended it with SIGSEGV |
| binaries, stripped | flong-launch 446,448 bytes, flong-init 40,312, flong-sweeper 142,272, static, no INTERP, `PT_GNU_STACK` size 0; flong-seccomp 144,784 (libc, libseccomp); fixtures bpfdump 43,872, syscall-probe 22,104, swapper 20,584, ioctl-probe 19,080 |
| closures | the launcher set 44,256,760 bytes (54,318,016 with the C, before phase 3); flong-seccomp 38,057,520 (48,454,728 with the C); the fixtures 38,019,032 |
| `packages.bench`, C against Zig, medians of 20 over three runs, ms | flong-init: no network C 31.0–31.8, Zig 29.5–33.5; flong-launch (6acfa9b against a103e76's tree): no network 32.5–33.6 against 30.8–34.0, pasta and an nft hook 53.1–60.1 against 52.5–59.3, a forwarded port 72.0–79.0 against 71.4–73.9, cold 355.7–358.2 against 374.7–382.0, and in an earlier pair cold 368.2–379.4 against 352.9–374.0 |
| a project's policy compiled at launch | cold 31.6 ms, warm 3.4 ms (the bash: 85.8 and 42.4 ms), medians of 21 on the host |
| CI | one `nix flake check` job: 5 min 55 s before the port, 7 min 49 s to 14 min 53 s during it; a matrix of one job per check: see [Why Zig](#why-zig-and-what-it-cost) |

### One binary

The libc-free programs became one (2026-09-24), so that flong is one static
file with no libc, which a release outside Nix can ship as it is, and the
shared modules, std and the start code are in it once. The seccomp
compiler stays a program of its own, `flong-seccomp`, for two reasons:

- **It links glibc**, for libseccomp and its byte-identical filters ([Why
  Zig](#why-zig-and-what-it-cost)). In `flong` it would put libc's start
  code into every session's pid 1, which undoes "no syscall before `main`"
  ([What the port measured](#what-the-port-measured): start code).
- **The project cache key hashes its store path** (quirk 36). Apart, that
  path moves only with the seccomp set's own sources and the files every
  set shares ([The build](#the-build)), so a launcher edit orphans no
  project's cache.

`flong init` reads its words after `init`, so each of the kernel's argv
slots it reuses for tini's argv moved by one; `init.words` and
`init.tiniArgv` are pure, and `tests/zig/init_test.zig` pins the slots.
Messages say `flong launch:`, `flong init:` and `flong sweeper:`.

**No compatibility layer.** flong's only consumers are its own: chase,
frisket and nix-config. A change of interface updates module.nix, the tests
and those consumers together, and leaves no old-name link, no shim script
and no translated field behind: anything left on an old interface fails
loudly, so that it is fixed rather than carried. `flong-launch` and its
siblings left no link behind, and a declaration that spells a field the
old way is refused (`tests/golden/decl/an-unknown-field.zon`).

### The declaration

A declaration is a value of `src/decl.zig`'s `Declaration`, and its file is
ZON, as capsper's configuration is. The static half of a session, what
module.nix rendered into the bash wrapper's header, is one typed value
with one parser:

- **The type is the schema.** Each field is named as its Nix option,
  camelCase and `MemoryMax` alike, with no translation. Its type is what
  `std.zon.parse` can hold a file to: enums, `u16` ports, optionals, and a
  tagged union where Nix has an either (`forwardPorts` is `.auto` or
  `.{ .ports = ... }`, a memory size `.infinity`, `.{ .bytes = N }` or
  `.{ .size = "8G" }`). What the parse cannot check, a type's `patterns`
  and `ranges` say. An unknown field or a wrong type is a parse error at
  its line and column. The computed fields (`Declaration.computed`: the
  closure, the ids, the filters, `commandPath`, the hook programs) are
  worked out by module.nix from `containers.<name>`; a configuration made
  without Nix writes them itself.
- **One description, the doc comment.** Each field's doc comment is its
  only description, and a field without one does not compile
  (`tests/zig/compile_fail/decl_undocumented.zig`).
  `build/gen_decl_docs.zig` harvests them with `std.zig.Ast`, as capsper's
  `gen_config_docs.zig` does, and `src/decl_docs.zig` walks the type into
  three things: `decl-options.json` (`flong schema`: each field's path,
  type, default, doc comment and merge kind), from which module.nix builds
  every typed option with `builtins.fromJSON` (`nix/decl-options.nix`), so
  there is no import from a derivation and the NixOS manual and
  `nixos-option` read the same text; `flong help decl`; and
  `docs/declaration.md`, its `--markdown`. The ordered sequences, the hooks
  and the caller's commands, merge as ordered lists, so a module's
  `mkBefore` and `mkAfter` still order them. `decl-options-fresh` and
  `reference-fresh` fail on a stale file, and `nix run .#update-options`
  rewrites both. Only the options Nix alone has (`container`, `path`,
  `scopeConfig`, `launcher`) keep prose in module.nix.
- **Rendered, not interpreted.** module.nix renders each declaration with
  `nix/to-zon.nix`, adapted from capsper's, to `/etc/flong/<name>.zon`.
  `flong launch` reads that file with the parser `flong check` judges it
  with at build time, so the two cannot read it differently.
- **One validator.** `flong check` (`src/check.zig`) runs in each
  declaration file's derivation and replaced module.nix's assertions of
  what the file says and `tests/golden/paths.txt`, the mirror that kept
  them in step with the launcher's; a refused declaration fails
  `nixos-rebuild` in its words ([Tests](#tests)). Assertions of NixOS
  itself, a container or a user that exists, stay in Nix.
- **The trust boundary does not move.** Any caller can run `flong launch`
  with any file, as it could run the old launcher with any spec, so the
  parser is a boundary: `decl.load` reads at most 1 MiB into one arena,
  `decl.notZon` refuses a `{` past 32 deep, two `-` in a row and any token
  no declaration holds before `std.zon.parse`'s recursion sees them, every
  parse error is a refusal and never a panic, and `decl.parse` and
  `check.validate` are fuzzed over a checked-in corpus
  (`tests/zig/corpus/decl-parse/`).
- **Commands, not snippets.** The hooks and the caller's commands were
  shell text flong ran; each is now an argument list, and flong runs no
  shell of its own ([Data is data](#data-is-data-shell-is-for-what-only-launch-knows)).
- **The spec is a value.** `flong launch` does the wrapper's work in its
  order (`src/launch/assemble.zig`) and hands the launch a `spec.Spec`
  ([The input contract](#the-input-contract)). The argv spec, keywords such
  as `mount`, `uidmap` and `keep-fd`, was an interface that existed only
  because the wrapper was bash, and it went with the wrapper. Each step was
  ported beside the bash, and a transition check (`tests/transition.nix`,
  deleted with it) found the value spec, rendered as argv, the wrapper's for
  every declaration of the basic and rootless tests over 13 caller-side
  outcomes.

`--help`, messages and paths assume no Nix store, for a release outside
Nix, which is [PLAN.md](PLAN.md)'s.

### The declaration's command

Each declaration's command is a link, `NAME -> flong`, with no script
(module.nix's `mkLauncher`). flong reads `argv[0]`'s basename, the name the
caller typed, finds no subcommand by it, and does what `flong launch NAME
-- ARGS` does, which is how the docs describe the link. A name is looked up
(`src/launch/lookup.zig`) in `/etc/flong`, which module.nix fills through
`environment.etc`, then in `$XDG_CONFIG_HOME/flong` (`$HOME/.config/flong`
when that is unset or not absolute):

- **The system's first**, so a declaration the system installs is the one
  its name runs, whatever the caller's configuration holds.
- **A fixed directory**, rather than a file beside the link in its store
  path, so the lookup is obvious: `ls /etc/flong` lists every declaration,
  `flong list` prints each name once as it runs and its file, `ls -l
  $(command -v NAME)` shows the link, and no chain of links is followed.
- **A missing one names every path looked for**, `flong: no declaration
  "NAME" (looked for ...)`, and exits 2.
- **Resolving by name moves no trust boundary**: a caller can run `flong
  launch` with any file anyway.

A relaunch execs `/proc/self/exe` with the launch's own argv, argv[0] as it
came, so the lookup repeats (quirk 30).

### The build

**`native.nix`** holds one builder, `zigSet`, and one derivation per install
set, each over only the sources that set imports, so an edit elsewhere moves
none of its store paths. `launcher/default.nix` and `seccomp/default.nix`
import it (so `module.nix`, `flake.nix` and the tests import them as
before), and `tests/parity/default.nix` and `tests/probes.nix` import the
fixtures.

| set | installs | its sources |
|---|---|---|
| `seccomp` | `flong-seccomp`; `-Dself=$out`, the project key's compiler path | `src/seccomp/` and the shared modules (`sys`, `msg`, `errno`, `num`, `fd`) |
| `launcher` | `flong`; the compiled-in programs as `-D` options, `-Dself` the `flong` in the same `$out` | `src/` but `seccomp/` and `fixtures/` |
| `fixtures` | `bpfdump` (libc, libseccomp), `syscall-probe`, `swapper`, `ioctl-probe` | `src/fixtures/`, `scmp.zig`, `sys`, `msg`, `errno` and `fd` |

A set is `stdenv.mkDerivation` with the `zig_0_15` hook, whose own build and
check phases are off: its build would be a second full build, and its check
runs `zig build test`, which needs the dependencies. The one build is the
install phase, `zig build install -Dset=<set>` with the hook's
`--release=safe -Dcpu=baseline`, then the set's assertions
(`native.nix:167-177, 210-229`): the static programs static with no
interpreter, no stack size in any `PT_GNU_STACK`, `flong` the launcher's
one program, with no symbol table and naming its own path, `bpfdump` needing
libseccomp. `disallowedReferences = [ zig_0_15 ]` holds for every set. A
`build.zig` or `build.zig.zon` edit moves every set; only its own sources,
the shared modules, those two files, libseccomp or Zig move `seccomp`'s
store path, which is part of every project key (quirk 36), so a launcher
edit orphans no cache. An edit to a shared module, even to a comment, moves
it.

The lazy dependencies, minish and zwanzig, come from one fixed-output
derivation, `zig_0_15.fetchDeps` with `fetchAll = true`, linked into the
Zig cache by the checks that pass `-Ddev=true` alone. Without `-Ddev` no
step touches them, since an unguarded lazy dependency makes an offline
build fail fetching it. After a `build.zig.zon` change, the hash is set to
`lib.fakeHash`, `native-test-debug` built, and the `got:` hash copied in.

**`build.zig`** steps:

| step | what |
|---|---|
| `install` | the set `-Dset` names; a missing compiled-in path fails it |
| `test` | unit and property tests (minish), Debug or ReleaseSafe with `-Drelease=true`; the fuzz targets with their corpus replayed first; the launch's pieces against stand-ins (`flong-fake-bwrap`, the spawn probe); needs `-Ddev=true` |
| `test-libc` | Zig against what it ports: `errno.zig` against glibc, `num.zig` against `strtoull`, `scmp.zig` against `seccomp.h`, `cfmakeraw` against glibc's, the fixtures' number readers, `sys.O_TMPFILE` against `fcntl.h`, the hook's environment against `setenv`, and `abi` for the host |
| `abi` | every kernel struct and constant of `sys.zig` against Zig's bundled headers through translate-c, x86_64 and aarch64, each asserting it read its own arch's; `-Dabi-plant` must fail it |
| `compile-fail` | 15 files in `tests/zig/compile_fail/` that must fail, each with its message, one of them over a planted `decl.zig` missing a doc comment |
| `lint` | `tools/fdlint.zig` over `src/` and `tests/zig/`, and over its planted files |
| `fmt` | `zig fmt --check` |
| `schema` | writes `decl-options.json` and `docs/declaration.md` from `src/decl.zig`, as `nix run .#update-options` does |
| `analyze` | zwanzig over `src/`, and the 27 planted bugs of `tests/zig/analyze/bugs.zig` it must report, and no more; needs `-Ddev=true` |
| `cross` | aarch64: flong (dummy paths) and the three static fixtures built, flong-seccomp and bpfdump compiled unlinked, `abi`'s half |
| `integration`, `launch-driver`, `test-launch` | the drivers `checks.native` runs (`flong-walker`, `flong-proc`, `flong-tty`, `flong-launch-driver`) and the record writer against `tests/golden/records/`, built only by `tests/integration.nix` |

Every installed artifact is ReleaseSafe, stripped by the build,
`single_threaded`, and `stack_size = 0`.

**The checks** are `nix flake check`'s: `native-test-debug` and
`native-test-release` (`test test-libc`), `native-lint` (`lint compile-fail
fmt`), `native-analyze`, `cross-aarch64` (on x86_64), `launcher`, `seccomp`,
`golden`, `integration`, the VM tests `native`, `basic-a`, `basic-b`,
`rootless-a`, `rootless-b` and `parity`, the six `assertions-N` shards,
`assertions-decl`, `decl-options-fresh`, `reference-fresh` and `shellcheck`. `native` boots one node with a lingering user, subordinate
ranges and a delegated user manager, for what the build sandbox cannot do:
`clone3` into a cgroup, U1 and U2 through the real `newuidmap`, the walker
against a symlink swapper, the spawn probe, the terminal through a pty, the
sweepers over hostile records. `golden` runs flong's programs in the build
sandbox against cases recorded from the C (`tests/golden/`): argv, stdin
and redirections against stdout, stderr, status and the working directory
afterwards, byte for byte, with store paths and project keys filled in as
the check runs. A fixed case changes only as [Kept
behaviour](#kept-behaviour) lists.

**golden's filters and libseccomp.** A `.bpf` case depends on libseccomp as
well as on flong, so `tests/golden/seccomp/LIBSECCOMP` holds the version it
was recorded with, and `golden` fails `libseccomp changed: run
golden-update` when the build's differs. `nix run .#golden-update` rewrites
the `.bpf` files and `LIBSECCOMP` and nothing else, and is used only when
the version differs and `bpfdump eval`'s text over the old and the new
bytes is identical, so what a policy means has not changed; its commit is
its own and shows both. A byte change at the same version is a bug in
flong. When `eval`'s text differs, libseccomp changed what a policy means:
stop and decide, never update.

**Running them.** `nix run .#gate` builds every x86_64 check through
nix-fast-build (parallel evaluators, each check built as soon as it
evaluates, those a binary cache has skipped), one evaluator per 10 GiB of
the host's memory, each restarted past 6 GiB, so one gate at a time on a
machine. `nix run
.#gate-aarch64` evaluates aarch64's checks without building them. The dev
shell has `zig_0_15`, libseccomp and strace, for `zig build test -Ddev=true`
and the like. **CI** (`.github/workflows/ci.yml`) lists the checks, builds
each in its own job with KVM, and evaluates the other outputs; a push to
trunk green on every job is released. Every job reads the `danielbodart`
Cachix cache; a job that is not a VM test pushes flong's own outputs, by an
allow-list of names, and a fork's pull request pushes nothing.

### Tests

The native code is tested at four levels, each a check.

- **`golden`**, black-box: flong's programs run in the build sandbox, argv,
  stdin and inherited descriptors against stdout, stderr and status
  (`tests/golden.nix`). Fixed cases (`tests/golden/<set>/`) were recorded
  from the C, or from the awk and bash for the seccomp tooling, and are
  never regenerated: every seccomp refusal and edge, the tooling over a
  checked-in copy of `systemd-analyze syscall-filter`'s dump (so a systemd
  bump changes nothing), flong init's argv refusals, flong sweeper's usage
  and state-directory refusals; `flong launch`'s entry (its usage, a name
  with no declaration, a declaration that does not parse or that `flong
  check` refuses, and one that reaches the prologue); `flong check`
  over `tests/golden/decl/`, one declaration a case, each refusal of a
  declaration with its accepted counterpart (below); and `flong help`'s
  text and flong's usage errors (`tests/golden/help/`). The spec's own
  cases, recorded from the C's argv parser, went with it in S3: each
  refusal a value can still reach is a case of `tests/zig/spec_test.zig`
  under its old name. What
  a case derives (store paths, project keys) is filled in as the check
  runs. The `.bpf` files follow golden-update's rule above.
- **Unit and property tests** (minish, `native-test`): the descriptor
  table's model property (the table always equals `/proc/self/fd`), stale
  handles, fork and each kind; `num.zig` accepts exactly what the C did;
  valid spec values drawn from a model pass `spec.validate`, each
  single-rule mutation is refused with its message, and `bwrapArgv` has
  golden argv per branch; the
  child-pid reader over any chunking and its 4096-byte bound; the `^]`
  detector as a state machine against a model; the launch's pieces against
  stand-ins (`flong-fake-bwrap`, the spawn probe). **Fuzzing**: the sweep's
  readers (records, session forms, `cgroup.events`, the own-cgroup and
  mountinfo readers, `/proc/<pid>/stat`'s field 22, closed inodes, inotify
  events) and the child-pid reader never panic, in ReleaseSafe, 10,000
  cases each under a fixed seed and a random one printed on failure, after
  replaying `tests/zig/corpus/`; each token run must accept at least 1% of
  its inputs. **Mutations** were planted once in a scratch copy, each
  caught by `native-test`: a child ignoring its keep list, `retainOnly`
  without its final `close_range`, `close` without the generation bump,
  `Spawn` skipping the signal reset, `dup2` without staging, a fork child
  keeping a stale signalfd, `awaitFd` ignoring POLLHUP or POLLERR (the
  harness's kill bounds the hang).
- **`test-libc`**: what the no-libc code reimplements, against glibc and
  the headers (see the `build.zig` table), and `abi`'s structs and
  constants against Zig's bundled headers on both arches.
- **`checks.native`** (one node, a lingering user with subordinate ranges, a
  delegated user manager): the first syscall after `execve` under strace,
  the subcommand's and never the dispatch's; `clone3(CLONE_INTO_CGROUP)`
  into an `O_PATH` leaf; the spawn probe (held descriptors equal the keep list, the signal
  mask and dispositions default, stdio remapped over every permutation);
  the walker against the symlink swapper, 0 escapes in 400; a session's
  cgroup killed, waited for and removed; U1 and U2 through the real
  `newuidmap`, and SIGTERM during U2's wait leaving no helper or pipe; the
  holder, limits and passwd; both sweepers over one state directory of
  launcher-written and hostile records, and the watch before the first
  sweep; the terminal through a pty (the relay, EIO, the drain, the window,
  the watchdog after a SIGKILL, a root-owned pty the caller cannot reopen).

The VM tests (`basic-*`, `rootless-*`, `parity`) run the shipped launcher
end to end. **The record contract**: the bytes the launcher writes are
pinned by `tests/golden/records/`, against which both the writer test and
basic's record subtest compare, so a sweeper of an older release reads a
newer launcher's records. **One validator of a declaration**: `flong
check` (`src/check.zig`) judges each `/etc/flong/<name>.zon` in its own
derivation (`module.nix`'s `declFileOf`), with the parse `flong launch`
reads it with, so a refused declaration fails the system's build with its
line and column or the refusal's own words. It refuses before a launch
what `spec.clean` and the mount helper refuse at launch -- unclean paths,
a destination twice, a source reaching a protected path -- lexically on
the declaration's spelling, where the launcher's checks are canonical and
stay the authority; and what only a declaration can say: the mask depth
rule against its own writable binds, devices, seccomp settings with no
tier, the container's ids, the patterns and ranges `src/decl.zig`
declares, an empty command, and a NUL in any string, which ZON can write
and an argv or a path would cut short. `tests/golden/decl/` is its cases,
each refusal and its accepted counterpart. `module.nix`'s assertions keep
only what NixOS alone can say, of `containers.<name>`, the host and the
option types (`tests/assertions.nix`, evaluated in shards), and
`assertions-decl` builds a refused declaration's file to hold that the
refusal surfaces there, in `flong check`'s words.

### Files

Each module's `//!` comment is the specification of what it declares: what it
does, when it is called and how it fails, with the file and lines of the C it
ports.

| file | owns |
|---|---|
| `src/sys.zig` | the syscall layer: every raw call, on `std.os.linux` alone, each returning the value or the errno; the kernel structs std lacks, each size and offset asserted |
| `src/fd.zig` | the descriptor table: handles, kinds, `Held`, `Stdio`, `inherited`, `retainOnly`, `closeUntracked`, `selfPath` and `pidPath` |
| `src/msg.zig`, `src/errno.zig`, `src/num.zig` | messages, the trace and the panic handler; glibc's errno texts and names; numbers from outside read exactly as the C read them |
| `src/sig.zig`, `src/proc.zig` | the signal mask, the signalfd, `awaitFd`, `awaitFdOrExit`, `take`; `fork` (a `noreturn` body, the keep list), `Spawn`, `Child`, `lockWait`, starttime |
| `src/names.zig`, `src/passwd.zig` | machine and container names; a user's name from `/etc/passwd`, without libc (quirk 19) |
| `src/spec.zig` | the input contract: the `Spec` value, `validate` (every check that needs nothing but the spec) and bwrap's argv |
| `src/ns.zig` | U1 (newuidmap and newgidmap in parallel) and U2 (the split maps, `max_user_namespaces`); checkpoint 4 |
| `src/cgroup.zig` | the nsdelegate check, finding or starting the holder, the session cgroup, its limits and leaves; kill, wait, remove |
| `src/record.zig` | the state directory, records and `leader=`, liveness, the sweep, `postStop`, the watch |
| `src/tty.zig` | the foreground wait, the pty relay or passthrough, raw mode, the watchdog, `^]^]^]`, the wait for bwrap |
| `src/main.zig` | `flong`'s root: the dispatch, the start settings and the one panic handler; each subcommand's `main` is handed argv from its word on; `flong help`'s text |
| `src/decl.zig`, `src/check.zig` | the declaration's type, its parse and `load`, and `notZon`; `flong check`, every refusal of a declaration |
| `src/decl_docs.zig` | the walk of the declaration's type and doc comments: `flong schema` (`decl-options.json`) and `flong help decl` (`docs/declaration.md`, with `--markdown`) |
| `src/mount.zig` | the mount helper, a fork body of `flong launch`'s: sources, the walker, masks, overlays, `/sys`, `/run` read-only; checkpoint 7 |
| `src/launch.zig` | `flong launch`: `main` (its words), the declaration loaded and judged, `launch` (the prologue), `run` and `teardown`, the order of a launch; checkpoints 1, 2, 3, 5 and 6 |
| `src/launch/` | the launch's pieces, each tested alone: `assemble.zig` (the prologue's work in the wrapper's order, building the spec) and its pieces `caller.zig`, `workspace.zig`, `cmd.zig`, `binds.zig`, `refuse.zig`, `depth.zig`, `subid.zig`, `prepare.zig`, `identity.zig`, `groups.zig`, `hometmp.zig` and `resolv.zig`; `lookup.zig` (a name's declaration); `prologue.zig` (the cache lock, the relaunch, the close of what was inherited, the protected paths), `bwrap.zig` (its spawn), `childpid.zig` (`--info-fd`), `hook.zig` (`postStart`), `pasta.zig` |
| `src/init.zig` | `flong init`: groups, capabilities, the controlling tty, the ready byte, the gate, chdir, exec tini; no allocator; checkpoint 9 |
| `src/sweeper.zig` | `flong sweeper`: the state directory, its holder, then the watch; no allocator |
| `src/seccomp/` | `flong-seccomp`: `main.zig` the root, `compile.zig` the policy compiler, `expand.zig`, `render.zig`, `project.zig` the subcommands, `scmp.zig` libseccomp's externs |
| `src/fixtures/` | the tests' programs: `bpfdump`, `syscall-probe`, `swapper`, `ioctl-probe` |
| `tools/fdlint.zig` | the lint |

Dependencies point one way: `sys`; then `msg`, `errno`, `num` and `fd`; then
`sig` and `proc`; `record` uses `cgroup`; `mount` uses no `proc`. `sys`
imports none of flong's modules. `src/main.zig` imports the three
subcommands' modules, all over one graph of the others, so they share fd's
table and msg's prefix. `flong launch` imports spec, ns, cgroup, record,
mount, tty, passwd, names, proc, sig, fd, sys, msg, errno and num, and
`src/launch/`; `flong sweeper` record, cgroup, names, proc, sig and the
shared modules; `flong init` sys, msg and errno only. The records the
launcher writes are the C's, byte for byte as `tests/golden/records/` pins
them (`launch_test.zig`'s writer test, basic's record subtest), so an old
sweeper reads a new launcher's records.

### Conventions

- **Errors are values.** `sys.zig` returns `Result(T)`, the value or the
  kernel's errno, and ignoring one is a compile error. A function that fails
  says why, once, where it failed, and returns `error.Reported`; its callers
  pass that up without printing again. The one other error is
  `error.Aborted`: a terminating signal ended a wait, which prints nothing
  and leaves the signal for the exit status. Messages are `<prog>: <what>:
  <strerror>`, or a refusal in plain words in the user's terms ("a symlink
  is on the way to /srv/x"). Each is one unbuffered write, cut at 1022 bytes
  and a newline in the launcher, its children and the sweeper, and whole, as
  one `writev`, in flong init and flong-seccomp, as the C printed them
  (quirk 22). `errno.zig` holds glibc's texts, so the programs without libc
  say what glibc would. `std.posix` is banned: it turns errnos a caller must
  see into `unreachable`. Numbers from outside go through `num.zig`'s
  checked arithmetic.
- **One cleanup path.** A program's resources are values that end once, and
  a failure unwinds through its caller to the one place that undoes what
  exists. The launcher keeps every resource in one struct, `Launch`
  (`src/launch.zig:96-142`): a handle that may not exist yet is optional,
  one kept until exit is `Held`, each child a `?proc.Child`, null once
  reaped, and `gate_opened`. `launch` ends `proc.exit(teardown(&l, run(&l)))`:
  `run` returns at the first failure, and `teardown` undoes whatever
  exists. A module undoes its own partial work before returning, so the
  launcher never sees half a resource. The mount helper and the other fork
  bodies own nothing past their exit.
- **Handles, not numbers.** Every descriptor is a handle, a slot and a
  generation in one table of 1024 (`fd.zig:119`), opened `O_CLOEXEC`.
  Closing bumps the generation, so every copy (in a struct, a keep list, a
  forked child) is stale and panics if used, instead of reaching whatever
  file reused the number (quirk 40). The kind is in the type, so a read on
  a directory, a `dir` where a cgroup is wanted, or a network namespace
  handed to a mount-namespace `setns` does not compile. `Held(k)` is a
  handle with no `close`, for what lives until exit: the state and sessions
  directories, the cache (locked shared), the holder's cgroup, U1, the info
  pipe's read end (quirk 31), the leader's pidfd, the network namespace and
  pasta's memfd. `Stdio` is 0–2, outside the table, never closed;
  `inherited` is a descriptor adopted from outside the table, which
  `Spawn.keepInherited` passes on (a launch held one per keep-fd until S3,
  and holds none now). A number
  leaves the table only as a child's argument (`passFd`), `/proc/self/fd/N`
  (`selfPath`), `/proc/<pid>/fd/N` (`pidPath`), a filesystem context's
  `setFd` or `scmp.exportBpf`. A full table is "too many open descriptors",
  where the C got `EMFILE` (quirk 41).
- **Children.** `proc.fork` runs a body that is `noreturn`, so a child
  never returns into its parent's frames and no parent `defer` runs in it;
  a body that can return does not compile. It keeps only its keep list
  (`retainOnly`), since a fork keeps descriptors whatever their flags: a
  helper holding the record's lock keeps a dead session alive for the
  sweep, and a watchdog holding the pty master keeps the session's terminal
  from hanging up. `Spawn` builds a program's argv, environment, stdio and
  kept descriptors before `clone3`, and resets the signal mask and
  dispositions in the child. Every child is made by `clone3` with a pidfd,
  into its cgroup when it has one, and its pidfd's slot is taken first. A
  `Child` ends once: awaited, reaped now (`.kill` or `.wait`, said at each
  site), or released unreaped; nothing kills implicitly. Every root is `pub
  fn main() noreturn` and every body ends in `exit_group`, since a
  returning single-threaded `main` ends in `exit`. Nothing with a side
  effect is deferred across a fork.
- **Signals.** The launcher blocks TERM, HUP, INT, QUIT, WINCH and CONT
  first and reads them from a signalfd, so every wait ends on one as an
  event and none interrupts a step half done. SIGPIPE is ignored. SIGCHLD is
  reset to its default, in the sweeper too: an ignored SIGCHLD survives
  `execve`, the kernel then reaps children itself, and `waitid` says
  `ECHILD`, which would lose a helper's, a hook's or pasta's failure. A
  terminating signal still queued at the gate is taken off the signalfd
  there, which aborts the launch, so the teardown's own waits end only on a
  signal that comes later. A child that did not keep the signalfd holds a
  stale handle, which every wait tests before use. The sweeper has no
  signalfd: SIGTERM kills it.
- **Panics.** Every root installs one handler: `<prog>: internal error:
  <msg>`, one line, then `exit_group` with the program's failure status
  (125 but for flong-seccomp's 1). Zig's default ends in `abort`, whose
  SIGABRT pid 1 would drop. A handle used stale is a panic, so it fails
  closed. When `flong launch` panics it skips the teardown: the sweeper
  releases the session, the watchdog restores the terminal and
  `--die-with-parent` ends the payload; in the mount helper a panic's 125
  reads as a failed mount. flong sweeper must not panic on any record a
  caller can write, since its exit stops the holder and every session: its
  readers are fuzzed.
- **Start code.** Every program is single-threaded with `stack_size = 0`,
  so Zig's start code makes no syscall before `main` and `RLIMIT_STACK`
  reaches bwrap, tini, the payload and the hooks as the caller set it
  (quirk 20). flong's dispatch reads argv and makes no syscall either, so
  the first call after `execve` is the subcommand's (`checks.native`'s
  strace subtest). No segfault handler; SIGPIPE is left as it came, for
  each subcommand's `main` to set (`keep_sigpipe`).
- **Allocation.** flong init and flong sweeper allocate nothing: fixed
  buffers, and flong init execs tini from the kernel's own argv.
  flong launch has one arena over `page_allocator`, never freed, and builds
  a fork body's inputs before the fork; the mount helper uses `page_allocator` in
  its child. flong-seccomp has an arena over libc's allocator. No
  general-purpose allocator.
- **Lint and analysis.** `tools/fdlint.zig` checks, over Zig's tokens, what
  the compiler cannot: `std.os`, `std.fs`, `std.c`, `std.posix` and
  `std.process` outside the syscall layer (`sys`, `fd`, `proc`, `sig`, the
  fixtures and tests); `.posix` anywhere; a C symbol (`extern`, `export`,
  `@cImport`) outside `scmp.zig` and the tests that compare with C; a descriptor's `.raw`
  number outside the syscall layer; argv and environ outside the roots and
  `Spawn`; a handle's fields outside `fd.zig`; `debug.print` and `std.log`;
  `catch unreachable` without `// proven: <why>` on its line; a
  general-purpose allocator. zwanzig reports a double close or a use after
  close through one open model per function that makes a handle and closes
  for `close`, `await`, `reapNow` and `release`; each minting function gets
  its model when it is written, and the planted bugs keep the models
  honest. Leaks are the table's `liveCount` and a property that the table
  always equals `/proc/self/fd`.
- **Ordering.** What types cannot hold is each one linear function with
  numbered comments, never split into helpers, listed below.
- **No root.** The launcher and the sweeper refuse a caller of uid 0, and
  the launcher a map that reaches host id 0.
- **No dead code**: no test-only knob, no variant kept for comparison, no
  fallback that nothing reaches. What a test needs of the C it ports is
  built in the test.

**The ordering checkpoints**, each cited by number where it is written:

| # | order | where | held by |
|---|---|---|---|
| 1 | the prologue: the time as `main`'s first statement; SIGCHLD default; the wrapper's work, in its order, ahead of the launch's own (`assemble.run`, itself one linear function, its refusals under the declaration's name, 1); then block signals, SIGPIPE ignored; the spec's checks over the value, refusing root first (`spec.validate`); the signalfd; `launcher-start`; the state directory; the cache lock (swept: relaunch this binary with its argv); the prologue's own shared lock on a cold cache closed; close what was inherited. Nothing chdirs before step 4 | `launch.zig`'s `launch`, `launch/assemble.zig`'s `run` | spec_test's validate cases, wrapper_test, golden's launch set, the payload-descriptor subtest |
| 2 | the child's ends close at once after bwrap's spawn, whether or not it succeeded: info, ready and gate write ends, the seccomp files, U2, the resolver's memfd | `run` | the gate subtests |
| 3 | the ready pipe's read end closes right after the helper's fork, so the helper alone sees the byte or EOF | `run` | the mount subtests |
| 4 | U2 is strictly sequential: the grandchild unshares and writes `u`; the helper writes the maps, then `m`; the grandchild then writes `max_user_namespaces` and `n`; only then the helper sends the pid and waits. On failure every pipe closes before any reap, then the map programs are killed and the helpers waited for | `ns.zig` | the U2 tests in `checks.native` |
| 5 | the gate: the terminal started (the watchdog before raw), queued signals taken, the window size, one byte, then the gate is open | `run` | the ^C, gate and terminal subtests |
| 6 | teardown: finish the terminal, close the gate, kill, reap (short-circuiting), wait the sandbox and hooks leaves, `postStop`, pasta only with `pasta-wait`, remove or close | `teardown` | basic's teardown subtests |
| 7 | the mount helper: umask, sort, duplicates; the namespaces through the leader's pidfd, as the caller; `setns(U1)`, then root; its own mount namespace and the sources; the ready byte; the session's mount namespace, its root, then its network and cgroup namespaces before sysfs and cgroup2; `/.hostsys` detached; the mounts in sorted order; `/run` read-only last | `mount.run` | the mount subtests, the walker |
| 8 | the watchdog forks before raw mode, only when stdin is a terminal, keeping its pipe, the leader and 0–2 | `tty.zig` | the watchdog subtest |
| 9 | flong init: groups, the bounding set, the ambient set, capabilities, the controlling tty, INT and QUIT default and an empty mask, the ready byte then close, the gate byte, chdir, close all but 0–2, the trace, exec | `init.zig` | the init golden cases, basic's groups and capabilities |
| 10 | records: `O_TMPFILE`, `LOCK_EX\|LOCK_NB`, one write, linked through `/proc/self/fd` with the uncounted EEXIST loop; `leader=` at the offset; unlink before close | `record.zig` | the record-bytes subtest, the writer test |
| 11 | the sweeper adds its inotify watch before the first sweep | `record.watch` | `checks.native`'s watch subtest |

### The kernel floor

flong needs Linux 6.13 or later. Nothing asserts it (`module.nix`'s host
assertions leave it to this section and the README): on an older kernel a
launch fails loudly at the first call the kernel lacks. Each row was checked
against the kernel source at the release named and the one before it (the
syscall table, `include/uapi/linux/`, or the code that parses the
parameter):

| since | what | used for |
|---|---|---|
| 5.2 | `fsopen`, `fsconfig`, `fsmount`, `move_mount`, `open_tree` | every mount the helper makes |
| 5.3, 5.4 | `clone3`, `pidfd_open`; `waitid(P_PIDFD)` | every child, and waiting on it |
| 5.6 | `openat2` with `RESOLVE_*` | the walker, exact binds |
| 5.7 | `CLONE_INTO_CGROUP` | a child created in its leaf, never migrated |
| 5.9 | `close_range` | a child's keep list; flong init; the prologue |
| 5.11 | overlayfs mountable in a user namespace; `CLOSE_RANGE_CLOEXEC` | overlay mounts; `Spawn`'s child marking all but its keep list close-on-exec (`proc.zig:300`) |
| 5.12 | `mount_setattr` | read-only and the other flags after attaching |
| 5.14 | `cgroup.kill` | ending a session |
| 6.8 | `statmount` with `STATMOUNT_MNT_BASIC`, `STATX_MNT_ID_UNIQUE` | the walker telling a host bind's mounts from the session's (`mount.zig:345-358`) |
| 6.11 | `PIDFD_GET_{CGROUP,MNT,NET}_NAMESPACE` | the helper entering the session's namespaces through the leader's pidfd (`fd.zig:701-710`) |
| 6.13 | overlay layers by descriptor: `lowerdir+` through `FSCONFIG_SET_FD` (`fsparam_file_or_string` in `fs/overlayfs/params.c`; 6.8 to 6.12 take `lowerdir+` as a string only) | overlay mounts (`mount.zig:299-306`) |

The VM tests run 6.18.51. The ABI is Zig's bundled uapi headers (6.13.4),
not the host's: `abi` holds every struct and constant `sys.zig` declares
equal to them on x86_64 and aarch64.

### Kept behaviour

What the port kept of the C that a user might call a bug, what it does
another way, and what it changed. The code cites these by number. **Keep**:
reproduced. **Mechanism**: done another way, no visible effect. **Change**:
a visible difference. **Fix**: a prototype's bug, fixed. Fixes of kept
behaviour wait for [Open decisions](#open-decisions).

| # | behaviour | where | verdict |
|---|---|---|---|
| 1 | the ready byte written after the helper died gives flong init EPIPE, not SIGPIPE's death: it is its namespace's pid 1, which a default-action signal never kills; it says `telling the launcher the root is built: Broken pipe`, or not, by timing | `init.zig` | Keep; SIGPIPE stays default for the payload |
| 2 | a relaunch execs flong again (`/proc/self/exe`, with the launch's own argv) before inherited descriptors are closed, restoring SIGPIPE and the mask first | `launch/prologue.zig` | Keep; it execed the wrapper until S3 |
| 3 | pasta gets `$leader`, `$userns`, `$netns`, `$machine` only when a hook ran | `launch/hook.zig`, `pasta.zig` | Keep: the environment is built once, only when `postStart` has a command, every command gets it, and pasta gets it then |
| 4 | pasta's `--netns` names the leader by pid, the hook's `$netns` the launcher's descriptor | `launch/pasta.zig` | Keep |
| 5 | a malformed record under the wanted name is dropped, release returns 0, and the launch refuses `has ended but cannot be released yet` though the name is free | `record.zig` | Keep; open decision 1 |
| 6 | `postStop` counts any reap error but an abort as run | `record.zig` | Keep, for the list as a whole: a failing command ends it, and it counts as run |
| 7 | teardown's reaps short-circuit on the first failure, the rest zombies until exit | `launch.zig` | Keep |
| 8 | holder-start's pidfd is closed unreaped on an abort | `cgroup.zig` | Keep, `Child.release()` |
| 9 | the C closed the watchdog's pidfd at once and reaped it by pid | `tty.zig` | Mechanism: the pidfd is kept, `reapNow(.wait)` in `finish`, same order |
| 10 | `^]^]^]` stalls while the payload reads no input: stdin is polled only when nothing read is still waiting for the payload | `tty.zig:594` | Keep; open decision 1 |
| 11 | the U2 handshake bytes' values are never checked | `ns.zig` | Keep |
| 12 | `limit io.weight` is accepted and never emitted by the module | `spec.zig` | Keep; open decision 1 |
| 13 | the seccomp compiler's duplicate check ignores negative (pseudo) syscall numbers | `seccomp/compile.zig` | Keep; open decision 1 |
| 14 | a `masked_eq` with mask 0 passes the int-argument check | `seccomp/compile.zig` | Keep |
| 15 | policy numbers are `strtoull` base 0 behind a leading-digit check | `num.zig`, `seccomp/compile.zig` | Keep exactly what the C accepted, pinned by `test-libc` and the golden corpus |
| 16 | an argument to `flong-seccomp` was a usage error | `seccomp/main.zig` | Change: `expand`, `render` and `project` are subcommands; anything else prints the new usage line, exit 2 |
| 17 | libseccomp exports with one `write` | `seccomp/scmp.zig` | Keep, to stdout or the project's temp file |
| 18 | strerror texts | `errno.zig` | Keep glibc's |
| 19 | `getpwuid` | `passwd.zig` | Change, forced by no libc: `/etc/passwd` only; an NSS-only user gets the `uid N` form; the tested text is unchanged |
| 20 | `RLIMIT_STACK` passes through to children | `init.zig`, `build.zig` | Keep, `stack_size = 0` and rootless's `ulimit -s` subtest |
| 21 | `realpath` for `postStop`, the closure and the protected paths | `launch/prologue.zig`, `record.zig`, `spec.zig` | Mechanism: an `O_PATH` open and the readlink of its `selfPath`, which needs a free descriptor and `/proc` where glibc's needs neither; the longest-existing-prefix rule unchanged; `access(X_OK)` is `faccessat` |
| 22 | message lengths: the launcher's, the mount helper's and the sweeper's cut at 1023 bytes; flong init's, flong-seccomp's and the tooling's whole | `msg.zig` | Keep the lengths; Mechanism: one write or `writev` per message, where the C's stdio wrote some in pieces |
| 23 | the C waited for the info pipe or bwrap with epoll | `sig.zig` | Mechanism: one `poll`, the descriptor winning a tie |
| 24 | the prototype's fork child exited 125 silently when `retainOnly` failed, its spawned child 127 | `proc.zig` | Fix: printed first, as the C did |
| 25 | the prototype's `Child.deinit` killed an unreaped child | `proc.zig` | Change: no implicit kill; each site says `.kill` or `.wait`, as the C did |
| 26 | the prototype leaked a child when adopting its pidfd failed | `fd.zig`, `proc.zig` | Fix: the slot is reserved before `clone3` |
| 27 | removing a cgroup tree recurses without a bound | `cgroup.zig` | Keep; 1,100 nested cgroups peak at 2,672 kB of stack and stop at the descriptor table, as the C did |
| 28 | uid map extents are uncapped; above 340 the kernel says EINVAL | `spec.zig` | Keep |
| 29 | a deleted source reads back with ` (deleted)` and misses the protected-path compare | `mount.zig` | Keep |
| 30 | a relaunch's argv[0] is passed on as it came, relative or not: the exec is of `/proc/self/exe`, and argv[0] is only the name a link's lookup reads | `launch/prologue.zig` | Keep, with no chdir before step 4; until S3 the spec's `relaunch`, the wrapper's own `$0`, was exec'd from the wrapper's working directory |
| 31 | the info pipe's read end is never closed | `launch.zig` | Keep: `Held` |
| 32 | exit 125 collides with a payload's own 125 | `launch.zig` | Keep |
| 33 | the sweeper's waits cap at 256 inodes | `record.zig` | Keep |
| 34 | the project compile never shows the compiler's stats line on success | `seccomp/project.zig` | Keep |
| 35 | a project that denies every name renders `allow ` with no name, refused (`missing syscall name`) | `seccomp/project.zig` | Keep |
| 36 | the project key is sha256 of the compiler's store path, `\n`, and the rendered policy without its trailing newline; the compiler reads the policy plus one newline | `seccomp/project.zig`, `native.nix` | Keep both. The path moves only with the seccomp set's sources, `build.zig*`, libseccomp or Zig; caches are orphaned when it moves |
| 37 | the project's temp file was `mktemp`'s, then `mv -T` | `seccomp/project.zig` | Mechanism: `.KEY.<6 random>`, `O_CREAT\|O_EXCL`, 0600, opened again by name as the shell's `>` did (a umask without the owner's write bit refuses it, as before), `renameat` |
| 38 | the tooling's prefixes (`flong-seccomp-project:`, `flong-seccomp-render:`), the compiler's captured `flong-seccomp: line N:` lines, an expand failure's unprefixed line and exit 1 | `seccomp/` | Keep; only the usage lines changed |
| 39 | the C's terminal teardown was safe on the zero struct, whose fds are 0 | `tty.zig` | Moot: optionals |
| 40 | a stale or wrong-kind descriptor reached the wrong file in C silently | `fd.zig` | New: a panic, 125; fails closed |
| 41 | the table is full at 1024 | `fd.zig` | Matches `EMFILE` at the default soft limit |
| 42 | a terminal the caller cannot reopen (after `su`): the `/proc/self/fd/1` reopen fails silently and the relay writes through fd 1 only when poll reports POLLOUT | `tty.zig` | Keep |
| 43 | a redirected stderr stays where the caller sent it: in relay the payload's stderr is the pty's slave only if the launcher's is a terminal | `tty.zig` | Keep |
| 44 | after a hang-up the master is closed, and resize and the drain check for it | `tty.zig` | Keep |
| 45 | `prologue-start` is stamped when `main` begins and printed once `FLONG_TRACE` is read; `launcher-start` when the launch proper begins, after the signalfd | `launch.zig` | Change (S3): `launcher-start` was `main`'s stamp, printed after the signalfd |
| 46 | the tooling on inputs no caller gives: an unreadable stdin to `project` compiled the tier without the project's lines, exit 0 (failing open); texts that named the old tools' store paths or followed the locale | `seccomp/` | Change: `project` refuses (`reading the policy: <strerror>`), exit 1; flong's prefixes and the C locale's text; each exit status as before. None is test-asserted |

### Open decisions

1. **Fixes of kept behaviour**, each its own commit with a test: the
   malformed-record refusal (quirk 5; recommended: treat a dropped record as
   released, so the create retries); `limit io.weight` (quirk 12;
   recommended: keep until module.nix emits it or drops it); pseudo-number
   duplicates (quirk 13; recommended: keep, since no policy of the repo has
   one); the `^]` stall (quirk 10; recommended: poll stdin while input is
   buffered).
2. **Sweeper resilience.** A sweeper failure stops the holder and every
   session (`module.nix`'s holder unit); flong relies on its readers being
   panic-free. The alternative, sweeping in a forked child. Recommended:
   keep.
3. **When nixpkgs drops `zig_0_15`:** port to the next Zig in one commit, or
   add a second nixpkgs input. Recommended: port forward.

### The input contract

`flong launch` builds the spec, `spec.Spec`, as a value
(`src/launch/assemble.zig`), from the declaration and what only the launch
knows, and `spec.validate` checks it before anything is in the descriptor
table. Until S3 the spec was the bash wrapper's argv, a keyword and its
fields each; `validate` runs that parser's checks over the value, and each
refusal still names its field in the keyword's words (`uidmap`, `user's
home`, `mount bind-ro source`, `post-stop`, `bwrap-arg --hostname`), which
is how the tests quote them. A list is empty when the launch has none.

| field (its refusals' word) | meaning |
|---|---|
| `machine` | the session's name: record, cgroup, `$machine`. `[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}` |
| `container` | the cgroup level between the holder and its sessions; the same charset |
| `state` | `$XDG_RUNTIME_DIR/flong`: the caller's, mode 0700 (checked) |
| `cache` | the cache; the root is `cache/prepared`; locked shared for the launch |
| `closure` | the container's toplevel, bound at `/run/current-system`; it and its target under `/nix/store/`, with no empty, `.` or `..` component |
| `uidmap`, `gidmap` | U1's extents, at least one each, disjoint, none reaching host id 0 |
| `uid`, `gid`, `home` (`user's uid`, ...) | the payload's container uid, gid and home, each id in its map |
| `groups` (`group`) | supplementary groups, each in the gid map |
| `chdir` | where the payload starts (the workspace); `/` by default |
| `mounts` (`mount KIND destination`, `source`) | `bind-ro`, `bind-rw`: a declared bind, the source following symlinks; `bind-ro-exact`, `bind-rw-exact`: a caller's bind or the workspace, the source canonical, a symlink on it refused; `dev`: an `allowedDevices` node, a read-write bind that is not `nodev`; `tmpfs`: an octal mode, tmpfs's `size=` or none, owned by root or the user; `overlay`: reads the lower, writes go with the session; `mask`: a mode-0 read-only node over an existing destination |
| `protect` | no mount source may equal, lie inside or contain it, compared canonicalised (a part that does not exist yet is appended, as spelt, to the canonical path of its longest existing prefix) |
| `seccomp` | compiled BPF programs; each becomes one `--add-seccomp-fd`, in order |
| `nested_userns` (`nested-userns`) | `nestedSandbox`: U2's `max_user_namespaces`, and `--assert-userns-disabled` goes; 0 is off |
| `holder` | the holder's cgroup below `user@UID.service`: `app.slice/flong-sessions.service` |
| `holder_start` (`holder-start`) | argv run when the holder is absent; its program an absolute path, since nothing searches `PATH` |
| `limits` (`limit`) | opt-in limits, each file once, one of `memory.max`, `memory.high`, `memory.swap.max`, `memory.oom.group`, `pids.max`, `cpu.max`, `cpu.weight`, `io.weight`, with a value |
| `post_start` (`post-start`) | `postStart`'s commands, each at least its program, an absolute path; in order, the first failure ending the launch; none, no hook |
| `post_stop` (`post-stop`) | `postStop`'s commands, the same way, each program under `/nix/store/`; in order, recorded for the sweep |
| `network` | start pasta |
| `pasta_args` (`pasta-arg`) | pasta's port and DNS flags; only with `network` |
| `pasta_wait` (`pasta-wait`) | fixed `forwardPorts`: the teardown waits for pasta's exit; only with `network` |
| `resolv_conf` | a networked session's `/etc/resolv.conf`, whole, which bwrap binds read-only from a memfd |
| `env` (`bwrap-arg`) | the payload's environment, built from nothing: `--clearenv`, then a `--setenv` for each, its name non-empty and without `=` |
| `hostname` (`bwrap-arg --hostname`) | bwrap's `--hostname`, not empty |
| `trace` | stage timestamps on stderr, `T <µs> <stage>` |
| `command` | the payload, run as `tini -g -- COMMAND…`; not empty |

bwrap is given no option but the fixed part and the three typed ones (the
resolver's file, the environment, the hostname), so a path mount can only
be a mount the walker makes (condition 1).

A spec never carries the programs, U2's maps (derived from U1's), the fixed
mounts, `/sys`, `/run` read-only, the nsdelegate check, or anything about
seccomp policy beyond the compiled files.

**bwrap's argv** is, in this order, so the fixed part cannot be undone by the
typed options, and flong init's protocol follows everything:

```
bwrap --userns <U1> --userns2 <U2> [--assert-userns-disabled]
  --unshare-net --unshare-pid --unshare-ipc --unshare-uts --unshare-cgroup
  --die-with-parent --as-pid-1 --info-fd <info>
  [--new-session]                                    (relay only)
  --add-seccomp-fd <fd> ...                          (one per seccomp, in order)
  --cap-add CAP_SETGID --cap-add CAP_SETPCAP         (for flong init, which drops them)
  --uid <UID> --gid <GID>
  --overlay-src <cache>/prepared --tmp-overlay /
  --ro-bind /nix/store /nix/store --ro-bind /nix/var/nix/db /nix/var/nix/db
  --proc /proc --dev /dev
  --perms 0755 --tmpfs /run
  --ro-bind <closure> /run/current-system
  --perms 0755 --dir /run/user --perms 0700 --tmpfs /run/user/<UID>
  --perms 1777 --tmpfs /tmp
  --ro-bind /sys /.hostsys                           (the mount helper detaches it)
  --perms 0644 --ro-bind-data <memfd> /etc/resolv.conf  (resolv_conf only)
  --clearenv --setenv VAR VALUE ...                  (env)
  --hostname NAME                                    (hostname)
  -- flong init <gate-fd> <ready-fd> <groups> <ctty|-> <trace|-> <dir> -- <COMMAND...>
```

### The launch, in order

Steps 6 to 18 are numbered so in `run`'s comments in `src/launch.zig`;
`launch`'s comments number its own statements and name steps 3 to 5 where
they are made. Before step 1, SIGCHLD goes to its default and the
prologue does the wrapper's work, building the spec (`assemble.run`; see
[Launch sequence](#launch-sequence)). The call is what that step calls.

| # | step | call | trace stage |
|---|---|---|---|
| 0 | SIGCHLD to its default; the prologue, which builds the spec | `sig.defaultChld`, `assemble.run` | `prologue-start` |
| 1 | block signals, ignore SIGPIPE | `sig.block`, `sig.ignorePipe` | |
| 2 | the spec's checks, refusing uid 0 first; then the signalfd | `spec.validate`, `sig.openSignalfd` | `launcher-start` |
| 3 | open and check the state directory | `prologue.stateOpen` (`record.stateOpen`) | |
| 4 | lock the cache shared; swept: exec flong again with the launch's argv | `prologue.cacheLock`, `prologue.relaunchSwept` | `cache-locked` |
| 5 | close the prologue's own shared lock on a cold cache, then every inherited descriptor but our own | `prologue.closeUntracked` | |
| 6 | wait for the foreground, choose relay or passthrough, open the pty | `tty.prepare` | |
| 7 | nsdelegate; find or start the holder | `cgroup.checkNsdelegate`, `cgroup.holderFind` | |
| 8 | the inline sweep | `record.sweep` | `swept` |
| 9 | the record, locked, with `poststop=` and `cgroup=` | `cgroup.sessionPath`, `record.create` | `recorded` |
| 10 | U1, then U2 | `ns.create` | `U1-mapped`, `U2-made` |
| 11 | the session cgroup, limits, leaves | `cgroup.sessionCreate` | `cgroup-made` |
| 12 | the protected paths made canonical; open the seccomp files; the info, ready and gate pipes; bwrap in the sandbox leaf | `prologue.protectPaths`, `bwrap.spawn` | |
| 13 | read `--info-fd` until `child-pid`; hold the leader's pidfd and network namespace; append `leader=` | `childpid.wait`, `fd.pidfdOpen`, `fd.openNetns`, `Record.setLeader` | `bwrap-child` |
| 14 | fork the mount helper, which prepares sources, waits for the ready byte, then mounts `/sys`, the declared mounts and `/run` read-only; wait for it or bwrap | `proc.fork` with `mount.run`, `sig.awaitFdOrExit`, `Child.await` | `sandbox-ready`, `mounts-done` |
| 15 | `postStart`'s commands in the hooks leaf, in order, each waited for, the first failure ending the launch; one environment, built once | `hook.build`, `Spawn.start`, `Child.await`, `hook.done` | `hook-done`, per command |
| 16 | pasta in the pasta leaf, ready when the spawned pasta exits 0 | `pasta.build`, `Pasta.start`, `Child.await`, `pasta.done` | `pasta-up` |
| 17 | save modes, start the watchdog, then raw (relay); take queued signals; copy the window size; write the gate byte | `tty.start`, `sig.take`, `tty.resize` | `gate-open` |
| 18 | wait for bwrap | `tty.wait` | `bwrap-exited` |
| 19 | teardown | `teardown` | `poststop-done`, `pasta-gone`, `released` |

A failure or a terminating signal at any step before the gate goes straight
to the teardown, and the gate is never written.

- **The helper is forked at child-pid, not at the ready byte**, so its source
  work overlaps bwrap's setup; it does nothing in the session's mount
  namespace before the byte.
- **bwrap's death also ends the waits of steps 13 and 14.** bwrap's child was
  seen to outlive bwrap before it had execed flong init, still holding the
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
| 125 | the payload never ran: a refusal of the spec, a failed step, a failing hook, pasta failing (a host port in use), bwrap failing, flong init's gate EOF, a relaunch that could not exec. stderr says which |
| 1 | the prologue refused, before the spec: the declaration, the caller, the workspace, a command, the maps, the prepared root |
| 2 | a usage error, or a name with no declaration |
| 128+n | a terminating signal n reached the launcher before the gate: the launch was aborted and torn down |

After the gate a signal is forwarded, not acted on, so the payload's status
tells what happened: `^C` is 130 under a pty and in a pipeline, `^]^]^]` is
137. A failing `postStop` is reported and does not change the status. 125
collides with a payload's own 125, as it does for `env` and `chroot`. The
prologue's own refusals, the wrapper's before it, exit 1 under the
declaration's name (`agent: ...`), and so does a declaration file that
cannot be read or that `flong check` refuses, under `flong launch`; a name
no directory has a declaration for is 2, `flong: no declaration "NAME"
(looked for ...)`, as is `usage: flong launch DECL.zon|NAME [-- ARGS...]`.
A cache swept before it was locked is no status: flong runs itself again.
Until S3 the argv spec's launch exited 75 when it had no `relaunch` to
run.

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
