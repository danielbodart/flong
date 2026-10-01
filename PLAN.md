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

## 3. `nix` inside a container, only if asked for

Nothing flong is built for needs this. A container's tools belong in its
`containers.<name>` declaration, which is already a Nix closure. The one
repository that does want `nix` against the host, a machine's own configuration, cannot
run in a sandbox at all: `nixos-rebuild switch` needs a real `sudo`, and
`no_new_privs` refuses it.

The case it would serve is a container used as a development environment for a
checkout whose own flake defines the toolchain, where `nix develop`,
`nix build` and `nix-shell` are how the project is worked on. That is a
reasonable request, and not one to build before someone makes it.

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
