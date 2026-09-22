# Plan

What is not built yet, in order. What is built, and why, is in
[DESIGN.md](DESIGN.md).

## 1. The rootless engine

Replace root systemd-nspawn with bubblewrap in user namespaces the caller
owns: no root anywhere, a warm session in about 16 ms, and seccomp policy per
tier. Spiked and planned in [ROOTLESS.md](ROOTLESS.md), which supersedes what
was here: a keep-id user namespace comes first, and a uid range per session
is that plan's last phase.

## 2. Persistence, and a discardable workspace

Two options that answer the same question in opposite directions. Each needs a
sentence in the README saying when to choose it.

- `state = [ paths ]`, each bound from `/var/lib/flong/<container><path>`,
  created on first use with the payload's ownership. A package index, a
  compiler cache or a language server's database wants state that persists
  across sessions and stays out of the host's own layout.
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

The cost is why it stays off. A declared container binds
`/nix/var/nix/daemon-socket` plus per-container `profiles` and `gcroots`.
Through that socket a session can build arbitrary derivations, use unbounded
CPU and disk, and reach the network from a fixed-output derivation. The host's
daemon fetches that derivation outside the session's network namespace, where
no rule a `postStart` hook installed can see or log it, so a session whose egress
is filtered must refuse the socket. A user in `trusted-users` could also set
sandbox options through it, which is root-equivalent; on a default NixOS that
list is `root` alone, so this is the weaker reason, but the option description
must state it.

If built: off by default, opt-in per launcher, refused in a session with an
`postStart` hook, `--bind-ro=/nix/var/nix/daemon-socket`, and
`--bind=/nix/var/nix/profiles/per-container/<container>:/nix/var/nix/profiles`
plus the matching `gcroots`, created by the launcher and kept per container so
a warm toolchain survives.

## Tests

New work is tested to the standard the network tests set, each property
asserted rather than assumed:

- A session with no `network` has only `lo`, and no route in either family.
- A `postStart` hook runs as root, is handed a namespace that is not the host's,
  and finds no route in it.
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
- The payload cannot list or flush a hook's ruleset, add a link or add a route,
  including inside `unshare -Ur`, where it holds `CAP_NET_ADMIN` again; the
  rule is intact from outside afterwards.
- Rules land before any egress: the hook sees no route, pasta adds some after,
  and the hook's rule then refuses a port the session was given.
- `hostPorts` reaches the named host port, and not an unnamed one, directly or
  through the gateway address.
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
- A clean exit and a SIGKILLed launcher both release the pin and pasta, the
  second through a sweep by a different launcher over the same container.
- `postStop` runs on both paths, the sweep running the dead session's own.
- The capability and privilege flags are refused in `extraFlags`, checked by
  the evaluation-only `assertions` check along with the network assertions,
  and a `command` that is a string or empty does not evaluate.

The suite runs in about 65 s of test script with KVM. Keep it affordable.
