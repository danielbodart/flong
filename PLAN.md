# Plan

What is left, in order. The struck-out sections have shipped and are kept for
their numbering; the rest is the network work and the hooks a launcher needs
around a session's lifetime.

Everything marked *measured* was run in a NixOS VM test against this flake's own
nixpkgs (systemd 261.2, nftables 1.1.7, passt 2026_07_16, kernel 6.18.51), in
flong's real invocation shape: `systemd-run --scope` around `systemd-nspawn
--private-network --user=…` with a prepared root.

Done already: the container's own `tmpfs` list, `privateNetwork` (as a
loopback-only namespace), `networkNamespace`, `--console=autopipe` so stdin
survives a pipeline, `--hostname`, `/run/user/<uid>`, `/etc/machine-id`,
`machine.slice` and `properties`, a launch-time identity check against the
prepared root's passwd, an assertion for each declaration flong does not honour,
and the README section on what a session is not.

---

## ~~1. The unix-export path is wrong~~

Done. `cleanup` and the sweep unmount `/run/systemd/nspawn/<machine>/unix-export`
and remove the mount tunnel beside it, which is where nspawn leaves both.

## ~~2. The sweep's liveness test is wrong, and it deletes live sessions~~

Done. A session is live while its launcher pid, its scope unit or its
registration with machined says so — the launcher pid first, because between
`cp -a` and `systemd-run` it is the only one of the three that exists. Live
sessions are left alone rather than stopped: the sweep runs inside an unrelated
launch, and a session's own trap is what ends it. Tasks 6 and 7 are unblocked.

## ~~3. Sweep past the current closure~~

Done. The sweep globs `/run/flong/<container>-????????-????????`, skips the
current cache and anything live, and `chattr -R -i`s a superseded cache before
removing it whole.

No lock. The prepare/copy race costs the launch that loses it, loudly — `cp -a`
fails and `set -e` ends that launch — where a `flock` across prepare-and-copy
would cost every launch of a tool that advertises 117 ms.

## ~~4. A root hook, after the namespace exists~~

Done, as `attach`. nspawn is started in the background — stdin handed over
explicitly, since bash gives an asynchronous command `/dev/null` otherwise — and
the launcher polls for the leader: `machinectl show --property=Leader` first,
then a recursive walk of the scope's cgroups, both judged by the same test.

That test is not "a pid whose `ns/net` differs from the host's". A container
without `privateNetwork` shares the host's, so that finds no leader there; and
"any pid in a namespace of its own" also matches a workload that ran
`unshare -Upf`, whose pid 1 a hook must never be handed. The leader is pid 1 of
the pid namespace exactly one level below the launcher's, which `NSpid` in
`/proc/<pid>/status` spells out.

The hook runs in a subshell, so its `exit` is its verdict. A non-zero one — or
a leader that never appears — kills the scope: a session whose hook did not
finish has nothing installed and nobody left to install it. The ordering
contract is in the option description, the README and the comment beside the
call. The test asserts the hook runs as root, is handed a namespace that is not
the host's, and finds it with an empty route table.

**Since changed: the payload waits for the hook.** nspawn starts the payload
while the hook is still running, and a short payload finished first — measured
as a hook failing with `nsenter: cannot open /proc/<pid>/ns/net`, a payload that
succeeded reported as a launch that failed, at random. So for a session with a
hook or a `network`, a gate between `tini` and everything else waits for
`/run/flong-attached`, which the launcher creates through `/proc/<leader>/root`
once the hook has run and pasta is up. It is
not a boundary — the ordering still is, and "no handshake" still holds for
safety — but it contradicts "no readiness protocol", and a hooked session's
payload now starts after the hook rather than beside it.

## ~~5. Let the hook wrap the payload~~

Done, as `attachWrap`: shell run as root before nspawn, printing a command one
word per line, spliced between `tini` and the payload.

## ~~6. A teardown hook~~

Done, as `detach`. The trap and the sweep now release a session through one
function, so the clean path and the killed path cannot drift apart again.

The sweep runs inside whichever launch of the container comes next, and
several launchers can drive one container — so running the *sweeping*
launcher's teardown would release the wrong state, or none. Each session
records the store path of its own teardown beside its root, and the sweep runs
that one, which also covers a superseded generation's. Only `$machine` is in
scope, because on the sweep's path it is all that is left.

## ~~7. `network` — a real network for a private session~~

Done, as planned: pasta through a bind-mounted pin with `--runas 0`,
`--config-net`, `--no-map-gw` and an explicit `none` for every port class not
listed; `forwardPorts` shaped like the declaration's, `hostPorts` going out as
TCP and UDP both. It is attached after `attach` returns. The pin is released
with `umount -l` and `rm` and pasta is signalled too — only once its command
line shows it is that session's pasta, because on the sweep's path the pid file
can be older than the process now holding its number. The release is not
conditional on the *sweeping* launcher having a network, since the session it
releases may be another launcher's. The veth, bridge and port refusal now says
why: static per container, many sessions per declaration.

The payload gate under task 4 covers a network too, and needs to: before it, a
whole payload ran against an empty route table and exited, and the launcher
then failed to pin a namespace that had already gone. Besides that, three things
turned up that the plan did not have:

- **`iproute2` is not needed.** The pin is `mount --bind` and `umount -l`, both
  util-linux, which the launcher already carries; only `passt` joined
  `runtimeInputs`.
- **A host port in `forwardPorts` is one session's at a time.** The second
  concurrent session's pasta cannot bind it (*"Listen failed for HOST TCP port
  \*/18200: Address already in use"*), so that launch fails and is ended rather
  than run without it — asserted. Loud rather than wrong, but the same
  concurrency limit the declaration's own `forwardPorts` is refused for.
- **Nothing arranges DNS.** With `--private-network`, nspawn's
  `--resolv-conf=auto` leaves the root's file alone, and prepare deletes it. A
  resolver is a service on the host's loopback — reaching it is a channel out
  that a steering hook would want a say in — so how a networked session
  resolves names (pasta's `--dns-forward`, a `hostPorts` entry, or the hook's
  business) is left as a decision rather than defaulted.

## ~~8. Per-session binds, source ≠ destination~~

Done, as `attachBinds`: `SOURCE:DESTINATION` lines, any kind of source, bound
read-write and kept out of `FLONG_EXTRA_BINDS`. Run as root before nspawn rather
than from `attach` — a bind mount is an argument to nspawn, so by the time the
namespace exists the mount table is made — but after the trap is armed, so a
per-session source is released on every path. Refuses `:` and newlines on
either side, after resolving the source as well as before.

## ~~9. Capabilities~~

Done. A session with a root hook runs with `--drop-capability=CAP_NET_ADMIN
--no-new-privileges=yes`, documented as defence in depth only: the test shows
the workload holding `CAP_NET_ADMIN` again inside `unshare -Ur` and *still*
failing to flush the ruleset, add a link or add a route, with the hook's rule
intact from outside afterwards. `--capability`, `--ambient-capability`,
`--private-users` and `-U` are refused in `extraFlags`, and the old assertion
message that recommended the first of them is rewritten. A new `assertions`
check evaluates each refusal, since nothing tested flong's assertions before.

## ~~10. `--uid`, and `getent`~~

Done. The flag is `--uid=`, so systemd 261 no longer prints a deprecation
warning over every launch, and the test asserts the absence of one. Recorded
beside it: nspawn resolves either spelling by exec'ing `getent` *inside the
container root*, which flong satisfies only through
`--bind-ro=$closure:/run/current-system` and a PATH naming
`/run/current-system/sw/bin` — accidental, and a hard failure the day a closure
stops carrying one.

## 11. Reopen `privateUsers`

flong refuses `privateUsers != "no"` on the ground that a bind-mounted file
owned by a host uid is unreadable inside, so the session cannot read the
workspace it was started for. That describes `noidmap`, which is the default.

nspawn now takes an ID-mapping option per bind mount: `idmap`, `rootidmap` and
`owneridmap`. With `owneridmap`, the owner of the bind source on the host maps
to the user inside, which is exactly the workspace case, and
`--private-users-ownership=map` maps the image with ID-mapped mounts rather than
chowning it.

The prize is worth the work: today a session runs as the caller's own uid, so
anything it reaches outside its deliberate binds — a leaked descriptor, a path
through `/proc`, a bug in nspawn — it acts on *as that user*. nspawn's own
manual says of `--private-users=no`: *"This option is not secure and must not be
used to run untrusted code."*

It needs checking rather than assuming: ID-mapped mounts need support from each
source filesystem, and the prepared root, the tmpfs mounts and the overlays each
need their own answer. A wrong mapping shows up as `nobody` and a read failure,
which is the right direction to fail in.

## 12. `nix` inside a session

A declared container binds `/nix/var/nix/daemon-socket` plus per-container
`profiles` and `gcroots`. flong binds `store` and `db` only, so `nix build`,
`nix develop`, `nix-shell` and `nix profile` all fail inside a session.

The daemon socket is a privilege: through it a session can build arbitrary
derivations, reach the network from a fixed-output derivation, spend unbounded
CPU and disk, and — if the invoking user is a `trusted-user` — set sandbox
options, which is host-equivalent. It is also a way out of the network namespace
that no in-namespace rule can see, which matters to anything steering a
session's traffic. So: off by default, opt-in per launcher, with the caveat in
the option description and not only here.

When on: `--bind-ro=/nix/var/nix/daemon-socket`, and
`--bind=/nix/var/nix/profiles/per-container/<container>:/nix/var/nix/profiles`
plus the matching `gcroots`, created by the launcher. Per container rather than
per session, so a warm toolchain survives.

## 13. Persistence, and a read-only workspace

Two options that are the same question answered in opposite directions, and both
want a sentence each in the README or nobody will pick correctly.

- `state = [ paths ]`, each bound from `/var/lib/flong/<container><path>`,
  created on first use with the payload's ownership. "Persists across sessions,
  invisible to the host's own layout" is what a package index, a compiler cache
  or a language server's database wants.
- A read-only workspace: the workspace bound as the lower layer of an overlay
  whose upper layer is discarded at the end. Today `workspace` is always bound
  read-write and `overlays` takes static paths fixed at evaluation, so a
  per-session workspace overlay cannot be expressed at all.

## Tests

The network section is in, each property asserted rather than assumed:

- A session with no `network` has only `lo`, and no route in either family.
- A hook runs as root, is handed a namespace that is not the host's, and finds
  no route in it; its binds are inside and absent from `FLONG_EXTRA_BINDS`.
- The workload cannot list or flush a hook's ruleset, add a link or add a route
  — including inside `unshare -Ur`, where it holds `CAP_NET_ADMIN` again — and
  the rule is intact from outside afterwards.
- Rules land before any egress: the hook sees no route, pasta adds some after,
  and the hook's rule then refuses a port the session was given.
- `hostPorts` reaches the named host port, and not an unnamed one, directly or
  through the gateway address.
- A `forwardPorts` entry reaches the session from the host; a port the session
  listens on past pasta's one-second `auto` scan does not; a second concurrent
  session asking for the same host port is refused.
- A clean exit and a SIGKILLed launcher both release the pin and pasta — the
  second through a sweep by a different launcher over the same container.
- `detach` runs on both paths, the sweep running the dead session's own.
- The capability and privilege flags are refused in `extraFlags` — by a new
  evaluation-only `assertions` check, along with the network assertions.

The suite runs in about 50 s of test script with KVM. Keep it affordable.
