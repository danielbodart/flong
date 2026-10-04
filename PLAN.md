# Plan

What is not built yet, in order. What is built, and why, is in
[DESIGN.md](DESIGN.md).

## 1. A uid range per container

Every container maps the entrypoint to your own uid, so an escape lands on
a uid that owns everything you own. Each container could instead map to
its own slice of your subordinate range, so an escape lands on a uid
that owns nothing of yours. The working directory would then reach your
uid through an idmapped mount, and an idmapped mount is `EPERM` rootless.
This needs `systemd-mountfsd` and `systemd-nsresourced`, or a kernel that
allows it. Spike it then.

## 2. Persistence, and a discardable working directory

Two options that answer the same question in opposite directions. Each needs a
sentence in the README saying when to choose it.

- `state = [ paths ]`, each bound from a directory you own,
  `$XDG_STATE_HOME/flong/<container><path>` (by default under
  `~/.local/state`), created on first use with the entrypoint's ownership. A
  package index, a compiler cache or a language server's database wants state
  that persists across containers and stays out of the host's own layout.
- A discardable working directory: the working directory as the lower layer
  of an overlay whose upper layer is discarded at the end, so the container
  can write and nothing reaches the host. `workspace` binds read-write or,
  with `:ro`, read-only, and `overlays` takes static paths fixed at
  evaluation, so a per-container overlay of the working directory cannot be
  expressed.

## 3. `nix` inside a container

A container's tools belong in its `containers.<name>` declaration, which is
already a Nix closure. The one repository that does want `nix` against the
host, a machine's own configuration, cannot run in a sandbox at all:
`nixos-rebuild switch` needs a real `sudo`, and `no_new_privs` refuses it.

The case it serves is a container used as a development environment for a
checkout whose own flake defines the toolchain, where `nix develop`,
`nix build` and `nix-shell` are how the project is worked on. chase has asked
for that. Its first step needs nothing of flong: the launcher realises the
checkout's devShell on the host and the session loads the result from the
store it can already read (chase's PLAN, decision 21). What it leaves out is
an agent changing the flake and entering it again, which needs `nix` in the
container, by one of two routes. The second is to be spiked first: it is the
one whose fetches the container's own network sees.

### The host's daemon

The cost is why it stays off. Using it means binding
`/nix/var/nix/daemon-socket`, and per-container `profiles` and `gcroots` for a
warm toolchain. Through that socket a container can build arbitrary
derivations, use unbounded CPU and disk, and reach the network from a
fixed-output derivation. The host's daemon fetches that derivation outside
the container's network namespace, where no rule a `postStart` hook installed
can see or log it, so a container whose egress is filtered must refuse the
socket. A user in `trusted-users` could also set
sandbox options through it, which is root-equivalent; on a default NixOS that
list is `root` alone, so this is the weaker reason, but the option description
must state it.

If built: off by default, opt-in per launcher, refused in a container with a
`postStart` hook. A read-only bind of `/nix/var/nix/daemon-socket` (a
`bind-ro` mount in the spec), and a read-write bind of a profile
directory you own, kept per container, such as
`$XDG_STATE_HOME/flong/<container>/profiles`, at `/nix/var/nix/profiles`,
plus the matching `gcroots`, created by the launcher as you so a warm
toolchain survives.

### A store of the container's own, over the host's

Nix's `local-overlay` store (experimental feature `local-overlay-store`)
reads a lower store it never writes and keeps what it adds in an overlayfs
upper layer. The host's `/nix/store` is the lower, as it is already bound;
the upper and the store's own database are the container's, in a directory
the launcher keeps per container or per cache. `nix` in the container then
runs single-user against that store, with no daemon: a build or a fetch is
the container's own process, in its own network namespace, under its
filter, its limits and its seccomp, and frisket sees every name it looks up.
Nothing it does reaches the host's store or database.

Spiked (Determinate Nix 2.35.2, Linux 6.18), outside flong: `unshare -Urm`
for the mount, then a nested namespace mapping 1000 back, since the
entrypoint is never root. What was found:

- **It works.** An overlay with `userxattr`, the host's `/nix/store` as its
  lower, mounted at `/nix/store`, and
  `local-overlay://?real=/nix/store&state=<state>&lower-store=local%3Froot%3D<host>%26read-only%3Dtrue&upper-layer=<upper>`,
  with the experimental features `local-overlay-store` and
  `read-only-local-store`. `nix path-info` reads the host's paths from its
  database; `nix build nixpkgs#hello` fetched hello alone into the upper,
  its glibc read from the lower; a local build ran; `nix develop` of
  chase's flake put its Go on `PATH`. The upper and its database, kept,
  served the next mount as they were.
- **Nix must not think it is root.** As namespace root it is multi-user,
  and fails chowning the store to `nixbld`. As your uid, as the entrypoint
  is, it is single-user and trusted on its own store. `NIX_LOG_DIR` must
  move into the state: the host's `/nix/var/log` is not writable.
- **The build sandbox is off.** `sandbox = false`: a build is a process of
  the container, confined by the container. With the sandbox on it needs a
  namespace of its own, which flong's filter refuses.
- **The host adding paths is fine, read as `mode=ro`.** A path built on the
  host while the overlay was mounted was readable inside at once, known to
  the lower's database, and an upper build depending on it succeeded.
  overlayfs calls a changing lower undefined; adding to it was not seen to
  matter. But `read-only-local-store` opens the host's database
  `immutable=1`, and an immutable read misses what the host's WAL holds
  (the design's experiment 5a) and fails while the host checkpoints it
  (5b); opened `mode=ro` over the same read-only bind it did neither, 0
  errors. A copy of the database instead goes stale: a path the host adds
  after the copy cannot be realised inside (`fchmodat2 … EPERM`, the
  critique's C2). So the container's nix carries a patch opening the lower
  `mode=ro`, until upstream takes it. The read-only store also wants its
  state's `gcroots/per-user`, `profiles/per-user` and `temproots` to exist
  (5c): a state directory of empty ones with `db` a symlink to the bound
  host database serves.
- **The host collecting paths is not.** Nix requires the lower only grow.
  Collect a lower path an upper path refers to, and the upper's database
  still lists it valid, and `nix build` reuses the dependent path whose
  dependency is gone: only `nix store verify` sees it. `nix store repair`
  fetched it back into the upper from the cache, and verify passed after.
  The fix is to keep the host from collecting it: the launcher, as you,
  holds an indirect GC root on the host for every lower path the upper's
  database lists, refreshed at each launch and kept while the store is.
  Nothing the container's own `nix store gc` does reaches the lower.
- **Warmth is the host's.** chase's devShell, not built on the host, fetched
  53 MB into the upper; one the host has costs nothing.

- **One upper, one mount.** The same upper behind two mounts at once gave a
  path nix called valid that `cat` could not open (experiment 6); overlayfs
  only warns of it, since `userxattr` forces `index=off`. So one container
  holds an upper at a time.
- **Rooting is cheap.** waydriver's devShell had 8,521 lower paths for the
  host to root; a `nix build` of one `builtins.toFile` of their names,
  each through `builtins.storePath`, realised and rooted them in about
  0.2 s (experiment 7). The names go to Nix as JSON, never as its source.
- **The payload must not own the upper's root** (the critique's C1). With a
  root of the caller's, the payload unlinked a store file of the lower's
  root and planted its own at the name, which a kept upper would keep. A
  root of the container's root, the payload's group and the lower root's
  `1775` refuses the unlink (`EPERM`), and single-user nix still adds,
  deletes and builds.
- **Made as container root, layers are not yours.** Directories namespace
  root makes are its subordinate id's, which you cannot remove (experiment
  4): the overlay is mounted as you, so overlayfs makes its upper files as
  you.

Built in flong: `binds`' `PATH:overlay:LAYERS`, a kept overlay (DESIGN.md,
"What each kind mounts"), allowed over `/nix/store`, one holder per
`LAYERS` for the cgroup's life, `$machine` seen from `workspace` on so a
consumer keys a store per launch by it, and the `kept-overlay` VM test,
where single-user nix builds into such a store under the strict tier and
the three fixed filters. The store's state is bound beside it with an
ordinary `:rw` line, and its lower's read-only; the settings above go in
the container's `nix.conf`. Whether a store is kept per session or shared
is the consumer's: a store shared by a tier's checkouts is one each can
write paths into that the next one trusts, so a tier for other people's
code keeps it per session, as it keeps its other caches.

Left to the consumer (chase's PLAN): the patched nix and its schema check,
the indirect GC roots on the host for the lower paths the store's database
lists, a bound on the upper's bytes and inodes, and removing the layers in
`postStop`. Untested here: the host collecting a path mid-session with and
without those roots, and fetches through a filtering proxy.

## 4. Loose ends

- **frisket's steer and connect as one process.** Each re-executes under
  `nsenter --user --net`, and frisket's hook costs about 38 ms of each
  launch. One nsenter'd process doing both cuts into that.
- **The seccomp set's own build file.** flong-seccomp's store path is part
  of every project cache key (quirk 36), and its fileset includes
  `build.zig`, so an edit to `build.zig` for the launcher alone moves every
  project's key and orphans its cache. Give
  the seccomp set a build file of its own, so its path moves only with its
  own sources.
- **The hook programs.** `flong-poststart-<name>` and
  `flong-poststop-<name>` (the declaration's `postStartProgram` and
  `postStopProgram`) exist only to put `path` on `PATH` and to drop the
  machine name the record appends to a `postStop` command. They can go once
  the launch and the sweeper put the declaration's `commandPath` on `PATH`
  themselves.
- **A SIGKILL before the record.** From the moment the prologue names the
  container, `postStop` runs for it however the launcher ends the launch,
  but a SIGKILL, the OOM killer or a crash before the record exists leaves
  nothing that knows the name: the sweep
  finds records only. What `seccompPolicy` or `exec` staged for that
  `$machine` stays until something else releases it. A record written as
  the container is named, before the hooks, would close it, at the cost of a
  record for every launch the prologue refuses.
- **NIX_PATH's channels.** module.nix reads nix-channel's lines in
  `/etc/set-environment`, which put `$HOME/.nix-defexpr/channels` in front
  of `NIX_PATH` when it exists, as doing nothing: a container's home is the
  rootfs's, and no container has a daemon. A declaration that binds a
  home holding channels loses that prefix, which no container could use.
- **flong's size.** flong is 1,417,640 bytes with the ZON parser, the
  schema's walk and the doc comments' text, and it is every container's
  pid 1, as `flong init`.

Only if someone asks:

- **`rootSize`**, an opt-in size for the container's root. The root is
  unbounded unless declared, like the rest. A size needs bubblewrap to honour
  `--size` for `--tmp-overlay`, a 69-line patch carried or upstreamed, so a
  full root gives `ENOSPC` rather than an OOM kill under a memory limit.
- **`oomScoreAdj`**, for whoever sets a memory limit and wants the entrypoint,
  not pasta, to be the one killed.
- **`hostGroups`**, for a consumer that needs a group-gated device without a
  logind ACL. Audio works through the ACL while you hold the seat.

## 5. Outside Nix, only if pursued

Nix stays the first-class way to use flong, and nothing here may make the
Nix path worse. `--help`, messages and paths assume no Nix store,
and the declaration is documented (`docs/declaration.md`). What a native
release needs that Nix supplies today:

- **Paths compiled in.** `-Dbwrap`, `-Dpasta`, `-Dtini`, `-Dnewuidmap`,
  `-Dnewgidmap`, `-Dcache` and `-Dseccomp` (DESIGN.md, [The native
  launcher](DESIGN.md#the-native-launcher)) become optional fields of the
  configuration. A missing one is looked up on `PATH` at `flong check`'s
  time, never silently at launch.
- **The rootfs.** A container's rootfs is built from a NixOS container
  closure (`cache.nix`: `prepareInner`, `cacheTool`). Outside Nix a
  rootfs must come from somewhere else: a directory, an image, or the host
  read-only. It is decided first, and only if a release outside Nix is
  pursued, by whoever that release is for; the current lean is a
  directory.
- **The sweeper's unit.** A documented systemd user unit running `flong
  sweeper %t/flong`, as module.nix's `flong-sessions` unit does.
- **Seccomp.** `flong-seccomp` could ship static against musl and a static
  libseccomp: it is not pid 1, so libc's start code is acceptable there.
  The BPF golden files (`tests/golden/seccomp/*.bpf`) prove the bytes
  unchanged.
- **Release artifacts.** CI builds `flong` and `flong-seccomp` for x86_64
  and aarch64 (`cross-aarch64` cross-builds them) and attaches them
  to the release each trunk push publishes (`.github/workflows/ci.yml`),
  with a README section on using flong without Nix.

More of the tooling may move into Zig over time: building the rootfs and the
cache tool are bash, which `flong launch` calls unchanged. The direction is
that the fiddly parts, the ones easy to get wrong that nobody should need to
edit, become typed code in the binary; each move is its own decision, made
when it is due.

## Tests

New work is tested to the standard the network tests set, each property
asserted rather than assumed:

- A container with no `network` has only `lo`, and no route in either family.
- A `postStart` hook runs as the invoking user, is handed a namespace that is not the
  host's, and finds no route in it.
- `command` is an argument list: the launcher's arguments are appended, and a
  double space, `;`, `$(…)`, `$HOME`, quotes, a glob, an empty argument and a
  trailing backslash each arrive as that argument, past `systemd-run` as well
  as any shell. A bare name is found on the `PATH` the container's
  `/etc/set-environment` sets, computed at evaluation, and a program in the
  user's `packages` alone proves it.
- The entrypoint's environment, exec'd with no shell, equals what a bash in the
  same container makes of the container's `/etc/set-environment` from the same
  launch variables, but for the three bash sets for itself. What only a
  shell could compute is refused at evaluation, naming its line.
- `exec`'s variables and argument list reach the entrypoint, an empty word
  among them, and each malformed output, a name set twice or already set, and
  a failing `exec` refuse the launch. Its files are in the home before the
  entrypoint starts, the user's, in a nested new directory, with their modes, one
  already there replaced; a path outside the home is refused, and one through
  a symlink in the rootfs or into a bind ends the launch, writing
  nothing on the host. `postStop` runs once for every `$machine` `seccompPolicy` and
  `exec` saw: after a refusal, a signal during `exec`, and a failure before
  the record.
- The declaration binds single files and a socket at paths of its choosing,
  absent from `FLONG_BINDS`; a file bound read-only refuses a write and a
  `chmod` with `EROFS` though the entrypoint owns it, and a socket bound read-only
  still connects.
- Every bind is read-only unless it says otherwise, proved by `EROFS` rather
  than `EACCES`. A guard's `exit 0` allows the launch, and its assignments do
  not reach the launcher.
- The entrypoint cannot list or flush a hook's ruleset, add a link or add a route.
  It cannot make a user namespace in which to hold `CAP_NET_ADMIN` again, and
  with `nestedSandbox`, where it can, the rule still holds. The rule is intact
  from outside afterwards.
- Rules land before any egress: the hook sees no route, pasta adds some after,
  and the hook's rule then refuses a port the container was given.
- `hostPorts` reaches the named host port on the loopback, and not an unnamed
  one; through the gateway address it reaches neither.
- A `forwardPorts` entry reaches the container from the host; a port the
  container starts listening on after pasta's one-second `auto` scan does not;
  a second concurrent container asking for the same host port is refused.
- A networked container resolves a name, and a short one through the host's
  search domain, from a resolver bound only to the host's loopback, in both
  families; its `resolv.conf` names pasta's addresses and carries the host's
  `search` and `options`. A private container without `network` has none. A
  host with a nameserver in one family only gives the container that family
  alone:
  the other is not forwarded, not listed, and reaches no port 53 on the host's
  loopback through its forward address or the unspecified one.
- A clean exit and a SIGKILLed launcher both release the container and pasta,
  the second through the holder's sweeper, or through the inline sweep of any
  later launch. A SIGKILLed launcher takes its entrypoint with it, and no
  sweep releases a container whose lock is held.
- `postStop` runs on both paths, the sweep running the dead container's own.
- `extraFlags`, `networkNamespace` and a forwarded port below the host's
  `net.ipv4.ip_unprivileged_port_start` (1024 by default) are refused, checked
  by the evaluation-only `assertions` check along with the network
  assertions, and a `command` that is a string or empty does not evaluate.

Keep the suite affordable. A launch is cheap; waiting for the user manager is
the fixed cost.
