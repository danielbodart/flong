# Plan

What is left after the gap analysis of `containers.<name>` against what a flong
actually honours. Everything here is a *runtime* gap: a declaration the NixOS
container module would act on, or something a booting container gets that a
prepared root does not. The image half needs nothing — a closure is a closure.

Done already: the container's own `tmpfs` list, `privateNetwork` (as a
loopback-only namespace), `networkNamespace`, `--console=autopipe` so stdin
survives a pipeline, `--hostname`, `/run/user/<uid>`, `/etc/machine-id`,
`machine.slice` and `properties`, a launch-time identity check against the
prepared root's passwd, an assertion for each declaration flong does not
honour — saying which are structural and which are merely unwritten — and the
README section on what a session is not (no wrappers, no bus, no PAM
session, a root that lives in RAM, `nsenter` rather than `machinectl shell`).

In order.

## 1. Build the network namespace from the declaration

Refused at evaluation today: `hostBridge`, `hostAddress*`, `localAddress*`,
`localMacAddress`, `forwardPorts`, `interfaces`, `macvlans`, `extraVeths`. That
assertion is the to-do list — it shrinks option by option as this gets written,
and the refusal exists so a declaration cannot quietly not happen in the
meantime.

The container module honours them by handing nspawn `--network-veth`,
`--network-bridge`, `--port`, `--network-interface` and `--network-macvlan` and
then finishing the job in two places a session does not have: `containerInit`
renames `host0` to `eth0`, addresses it and adds the routes, and the unit's
`postStart` addresses the host side.

**flong should do it the other way round**: build the namespace on the host,
before nspawn, and hand it over with `--network-namespace-path` — which flong
already supports. `ip netns` and `ip -n` operate on a namespace with no process
in it, so everything `containerInit` did inside can be done from out here, as
root, before anything unprivileged exists. Nothing needs a privileged moment
inside the container; that was only true of the mechanism upstream chose.

Sketch, in the order the launcher would do it:

- Make the namespace. `ip netns add` puts it in `/run/netns/<name>`; pinning our
  own under the session directory instead means the existing sweep already owns
  the cleanup — but a bind-mounted namespace file inside a directory that gets
  `rm -rf`'d has to be unmounted first, exactly like nspawn's unix-export mount.
  Cleanup is the interesting half of this task, not the setup.
- Name the host-side interface. `ve-$machine` will not do: `$machine` is
  `<container>-<pid>-<random>` and `IFNAMSIZ` is 16, so a session needs a short
  unique form of its own (`ve-` plus eight hex is 11 characters). This is the
  same constraint that makes upstream assert container names of 11 characters or
  fewer.
- veth: `ip link add <ve> type veth peer name host0 netns <ns>`, then inside —
  from outside — `ip -n <ns> link set host0 name eth0`, the `localAddress`es, the
  route to `hostAddress`, the default via it, and `localMacAddress` if given. On
  the host either the `hostAddress`es on `<ve>` or `ip link set <ve> master
  <hostBridge>`, then up. `extraVeths` is the same work per entry.
- `interfaces` is `ip link set <iface> netns <ns>`; `macvlans` is create on the
  host and move in. Both are a line each, and both are why this is worth doing:
  they need no addressing decisions at all.
- `forwardPorts` last, and carefully. nspawn's `--port` manages its own DNAT and
  is documented as supported only with one of nspawn's own networking modes
  (`--network-veth`, `--network-zone=`, `--network-bridge=`), so it is not
  available for a namespace we hand over — the rules have to be ours, and a
  launch that is SIGKILLed must not
  leave a port open. Sweep them the way the unix-export mount is swept, on the
  way in, keyed on the owning pid.

**DNS needs deciding, and both existing paths get it wrong.** With
`--private-network`, nspawn's `--resolv-conf=auto` leaves the image's file alone
and prepare has deleted it, so a session has no `resolv.conf` — right for
loopback-only, wrong the moment the namespace has a route. With
`--network-namespace-path` it is not clear nspawn considers the session privately
networked at all; if it does not, it binds the *host's* `/etc/resolv.conf` into a
namespace that may not reach that resolver. Verify which happens, then have the
launcher write the `resolv.conf` the namespace it built should have.

The VM test can cover this properly in both directions: a listener on the host
reachable from a session over the veth, and a session's port reachable from the
host once `forwardPorts` exists.

## 2. `nix` inside a session

A declared container binds `/nix/var/nix/daemon-socket`, plus per-container
`profiles` and `gcroots`. flong binds `store` and `db` only, so `nix build`,
`nix develop`, `nix-shell` and `nix profile` all fail inside a session — which
is awkward for a tool whose stated use is per-project toolchains and build
sandboxes.

It is not a straight fix, which is why it is a task rather than a commit. The
daemon socket is a privilege: through it a session can build arbitrary
derivations, reach the network from a fixed-output derivation, spend unbounded
CPU and disk, and — if the invoking user is a `trusted-user` — set sandbox
options, which is host-equivalent. So:

- `nixDaemon = false` by default, opt-in per launcher, with the caveat in the
  option description rather than only here.
- When on: `--bind-ro=/nix/var/nix/daemon-socket`, and
  `--bind=/nix/var/nix/profiles/per-container/<container>:/nix/var/nix/profiles`
  plus the matching `gcroots`, created on the host by the launcher the way the
  container@ unit's start script creates them.
- Decide whether the profiles are per container (shared between sessions,
  survives a reboot, needs a real directory) or per session (inside the session
  root, dies with it). Per container is what a real container does and what
  makes a warm toolchain worth having.

## 3. Persistence that is not the host's namespace

There is no equivalent of a non-ephemeral container's private `/var`. The only
way to keep anything across sessions today is to bind a host path, which puts
the container's state in the host's tree and under the host's names.

A `state = [ paths ]` option, each path bound from
`/var/lib/flong/<container><path>`, created on first use with the payload's
ownership. "Persists across sessions, invisible to the host's own layout" is
what a package index, a compiler cache or a language server's database wants,
and all three are things an agent pays for repeatedly today.

Note the interaction with `overlays`: an overlay is the same question answered
the other way (lower from the host, writes discarded). Both should be
describable in one sentence each in the README, or nobody will pick correctly.

## 4. Sweep prepared roots from superseded closures

The stale sweep only looks at `s-*` inside the *current* cache directory, so a
rebuild leaves the previous `/run/flong/<container>-<closure>-<prepare>`
directory behind until reboot. It is 48K, so this is hygiene rather than cost —
it is what makes `ls /run/flong` legible, not what makes it cheap.

The shape is: glob `/run/flong/<container>-????????-????????` (both hashes spelt
out, so a container whose name is a prefix of another's cannot sweep its
neighbour), skip the current cache, skip any that still holds an `s-*` whose
owning pid is alive, `chattr -R -i` before `rm -rf` because the prepared root
carries the immutable flag tmpfiles put on `/var/empty`.

**Why it is not done yet.** A superseded cache is not reliably idle. A launcher
from an earlier generation, launching against a warm cache of its own, has no
`s-*` directory between its identity check and its `cp -a` — and a concurrent
sweep in that window deletes the root it is about to copy. The session is
ephemeral so nothing is lost but the launch, and the window is about a
millisecond, but the fix is a `flock` held across prepare-and-copy in every
launcher, which puts a lock in the path of a tool that advertises 117 ms. Decide
that deliberately rather than as a side effect of tidying `/run`.

The cheap test, once it is decided: `mkdir -p
/run/flong/demo-deadbeef-deadbeef/prepared`, run a launcher, assert it is gone.
