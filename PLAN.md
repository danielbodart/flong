# Plan

What is not built yet, in order. What is built, and why, is in
[DESIGN.md](DESIGN.md).

The native code is Zig, the libc-free programs are one `flong` binary,
declarations are ZON checked by the same parser at build time and at
launch, and the bash wrapper is gone. What the port and that plan
established is in DESIGN.md's [The native
launcher](DESIGN.md#the-native-launcher), [One
binary](DESIGN.md#one-binary) and [The
declaration](DESIGN.md#the-declaration); the plan itself, `STANDALONE.md`,
is in git at bed8750. What it left, a release outside Nix, is §5.

## 1. A uid range per session

Every session maps the payload to the caller's own uid, so an escape lands on
a uid that owns everything the caller owns. Each session could instead map to
its own slice of the caller's subordinate range, so an escape lands on a uid
that owns nothing of the caller's. The workspace would then reach the caller's
uid through an idmapped mount, and an idmapped mount is `EPERM` rootless
today. This needs `systemd-mountfsd` and `systemd-nsresourced`, or a kernel
that allows it. Spike it then.

## 2. Persistence, and a discardable workspace

Two options that answer the same question in opposite directions. Each needs a
sentence in the README saying when to choose it.

- `state = [ paths ]`, each bound from a directory the caller owns,
  `$XDG_STATE_HOME/flong/<container><path>` (by default under
  `~/.local/state`), created on first use with the payload's ownership. A
  package index, a compiler cache or a language server's database wants state
  that persists across sessions and stays out of the host's own layout.
- A discardable workspace: the workspace as the lower layer of an overlay whose
  upper layer is discarded at the end, so the session can write and nothing
  reaches the host. `workspace` binds read-write or, with `:ro`, read-only, and
  `overlays` takes static paths fixed at evaluation, so a per-session
  workspace overlay cannot be expressed.

## 3. `nix` inside a session, only if asked for

Nothing flong is built for needs this. A session's tools belong in its
container's declaration, which is already a Nix closure. The one repository
that does want `nix` against the host, a machine's own configuration, cannot
run in a sandbox at all: `nixos-rebuild switch` needs a real `sudo`, and
`no_new_privs` refuses it.

The case it would serve is a session used as a development environment for a
checkout whose own flake defines the toolchain, where `nix develop`,
`nix build` and `nix-shell` are how the project is worked on. That is a
reasonable request, and not one to build before someone makes it.

The cost is why it stays off. Using it means binding
`/nix/var/nix/daemon-socket`, and per-container `profiles` and `gcroots` for a
warm toolchain. Through that socket a session can build arbitrary derivations,
use unbounded CPU and disk, and reach the network from a fixed-output
derivation. The host's
daemon fetches that derivation outside the session's network namespace, where
no rule a `postStart` hook installed can see or log it, so a session whose egress
is filtered must refuse the socket. A user in `trusted-users` could also set
sandbox options through it, which is root-equivalent; on a default NixOS that
list is `root` alone, so this is the weaker reason, but the option description
must state it.

If built: off by default, opt-in per launcher, refused in a session with a
`postStart` hook. A read-only bind of `/nix/var/nix/daemon-socket` (a
`bind-ro` mount in the spec), and a read-write bind of a caller-owned profile
directory kept per container, such as
`$XDG_STATE_HOME/flong/<container>/profiles`, at `/nix/var/nix/profiles`,
plus the matching `gcroots`, created by the launcher as the caller so a warm
toolchain survives.

## 4. Loose ends

- **frisket's steer and connect as one process.** Each re-executes under
  `nsenter --user --net`, and frisket's hook costs about 38 ms of each
  launch. One nsenter'd process doing both cuts into that.
- **The seccomp set's own build file.** flong-seccomp's store path is part
  of every project cache key (quirk 36), and its fileset includes
  `build.zig`, so an edit to `build.zig` for the launcher alone moves every
  project's key and orphans its cache, as S1's and S3's edits did. Give
  the seccomp set a build file of its own, so its path moves only with its
  own sources.
- **The hook programs.** `flong-poststart-<name>` and
  `flong-poststop-<name>` (the declaration's `postStartProgram` and
  `postStopProgram`) exist only to put `path` on `PATH` and to drop the
  machine name the record appends to a `postStop` command. They can go once
  the launch and the sweeper put the declaration's `commandPath` on `PATH`
  themselves.
- **flong's size.** flong grew from 513,200 bytes as one binary (S1) to
  1,417,640 with the ZON parser, the schema's walk and the doc comments'
  text, and it is every session's pid 1, as `flong init`.

Only if someone asks:

- **`rootSize`**, an opt-in size for the session's root. The root is
  unbounded unless declared, like the rest. A size needs bubblewrap to honour
  `--size` for `--tmp-overlay`, a 69-line patch carried or upstreamed, so a
  full root gives `ENOSPC` rather than an OOM kill under a memory limit.
- **`oomScoreAdj`**, for whoever sets a memory limit and wants the payload,
  not pasta, to be the one killed.
- **`hostGroups`**, for a consumer that needs a group-gated device without a
  logind ACL. Audio works through the ACL while the caller holds the seat.

## 5. Outside Nix, only if pursued

Nix stays the first-class way to use flong, and nothing here may make the
Nix path worse. `--help`, messages and paths already assume no Nix store,
and the declaration is documented (`docs/declaration.md`). What a native
release needs that Nix supplies today:

- **Paths compiled in.** `-Dbwrap`, `-Dpasta`, `-Dtini`, `-Dnewuidmap`,
  `-Dnewgidmap`, `-Dcache` and `-Dseccomp` (DESIGN.md, [The native
  launcher](DESIGN.md#the-native-launcher)) become optional fields of the
  configuration. A missing one is looked up on `PATH` at `flong check`'s
  time, never silently at launch.
- **The root.** A session's root is a NixOS container closure and a
  prepared root (`cache.nix`: `prepareInner`, `cacheTool`). Outside Nix a
  root must come from somewhere else: a directory, an image, or the host
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
  and aarch64 (`cross-aarch64` already cross-builds them) and attaches them
  to the release each trunk push publishes (`.github/workflows/ci.yml`),
  with a README section on using flong without Nix.

More of the tooling may move into Zig over time: the prepared root and the
cache tool are bash, which `flong launch` calls unchanged. The direction is
that the fiddly parts, the ones easy to get wrong that nobody should need to
edit, become typed code in the binary; each move is its own decision, made
when it is due.

## Tests

New work is tested to the standard the network tests set, each property
asserted rather than assumed:

- A session with no `network` has only `lo`, and no route in either family.
- A `postStart` hook runs as the caller, is handed a namespace that is not the
  host's, and finds no route in it.
- `command` is an argument list: the launcher's arguments are appended, and a
  double space, `;`, `$(…)`, `$HOME`, quotes, a glob, an empty argument and a
  trailing backslash each arrive as that argument, past `systemd-run` as well
  as any shell. A bare name is found on the container's `/etc/set-environment`
  `PATH`, and a program in the user's `packages` alone proves it.
- The declaration binds single files and a socket at paths of its choosing,
  absent from `FLONG_BINDS`; a file bound read-only refuses a write and a
  `chmod` with `EROFS` though the payload owns it, and a socket bound read-only
  still connects.
- Every bind is read-only unless it says otherwise, proved by `EROFS` rather
  than `EACCES`. A guard's `exit 0` allows the launch, and its assignments do
  not reach the launcher.
- The payload cannot list or flush a hook's ruleset, add a link or add a route.
  It cannot make a user namespace in which to hold `CAP_NET_ADMIN` again, and
  with `nestedSandbox`, where it can, the rule still holds. The rule is intact
  from outside afterwards.
- Rules land before any egress: the hook sees no route, pasta adds some after,
  and the hook's rule then refuses a port the session was given.
- `hostPorts` reaches the named host port on the loopback, and not an unnamed
  one; through the gateway address it reaches neither.
- A `forwardPorts` entry reaches the session from the host; a port the session
  starts listening on after pasta's one-second `auto` scan does not; a second
  concurrent session asking for the same host port is refused.
- A networked session resolves a name, and a short one through the host's
  search domain, from a resolver bound only to the host's loopback, in both
  families; its `resolv.conf` names pasta's addresses and carries the host's
  `search` and `options`. A private session without `network` has none. A host
  with a nameserver in one family only gives the session that family alone:
  the other is not forwarded, not listed, and reaches no port 53 on the host's
  loopback through its forward address or the unspecified one.
- A clean exit and a SIGKILLed launcher both release the session and pasta,
  the second through the holder's sweeper, or through the inline sweep of any
  later launch. A SIGKILLed launcher takes its payload with it, and no sweep
  releases a session whose lock is held.
- `postStop` runs on both paths, the sweep running the dead session's own.
- `extraFlags`, `networkNamespace` and a forwarded port below the host's
  `net.ipv4.ip_unprivileged_port_start` (1024 by default) are refused, checked
  by the evaluation-only `assertions` check along with the network
  assertions, and a `command` that is a string or empty does not evaluate.

Keep the suite affordable. A launch is cheap; waiting for the user manager is
the fixed cost.
