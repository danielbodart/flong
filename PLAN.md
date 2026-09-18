# Plan

What is not built yet, in order. What is built, and why, is in
[DESIGN.md](DESIGN.md).

## 1. Reopen `privateUsers`

flong refuses `privateUsers != "no"` because a bind-mounted file owned by a
host uid is unreadable inside, so the session cannot read its workspace. That
describes `noidmap`, which is the default.

nspawn takes an ID-mapping option per bind mount: `idmap`, `rootidmap` and
`owneridmap`. With `owneridmap`, the owner of the bind source on the host maps
to the user inside, which is the workspace case, and
`--private-users-ownership=map` maps the image with idmapped mounts instead of
chowning it.

The benefit is worth the work. A session runs as the caller's own uid, so
anything it reaches outside its bind mounts (a leaked file descriptor, a path
through `/proc`, a bug in nspawn) it acts on as that user. nspawn's manual says
of `--private-users=no`: *"This option is not secure and must not be used to
run untrusted code."*

It needs testing: idmapped mounts need support from each source filesystem,
and the prepared root, the tmpfs mounts and the overlays each need their own
answer. A wrong mapping shows up as `nobody` and a read failure, which is the
safe direction to fail in.

## 2. Persistence, and a read-only workspace

Two options that answer the same question in opposite directions. Each needs a
sentence in the README saying when to choose it.

- `state = [ paths ]`, each bound from `/var/lib/flong/<container><path>`,
  created on first use with the payload's ownership. A package index, a
  compiler cache or a language server's database wants state that persists
  across sessions and stays out of the host's own layout.
- A read-only workspace: the workspace as the lower layer of an overlay whose
  upper layer is discarded at the end. `workspace` is always bound read-write,
  and `overlays` takes static paths fixed at evaluation, so a per-session
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
  and finds no route in it; its `attachBinds` are inside and absent from
  `FLONG_EXTRA_BINDS`.
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
  the evaluation-only `assertions` check along with the network assertions.

The suite runs in about 50 s of test script with KVM. Keep it affordable.
