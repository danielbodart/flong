# Plan

What is left after the gap analysis of `containers.<name>` against what a flong
actually honours. Everything here is a *runtime* gap: a declaration the NixOS
container module would act on, or something a booting container gets that a
prepared root does not. The image half needs nothing — a closure is a closure.

Done already: the container's own `tmpfs` list, `privateNetwork` (as a
loopback-only namespace), `networkNamespace`, `--console=autopipe` so stdin
survives a pipeline, `--hostname`, `/run/user/<uid>`, `/etc/machine-id`,
`machine.slice` and `properties`, a launch-time identity check against the
prepared root's passwd, an assertion for each declaration flong cannot honour,
and the README section on what a session is not (no wrappers, no bus, no PAM
session, a root that lives in RAM, `nsenter` rather than `machinectl shell`).

In order.

## 1. `nix` inside a session

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

## 2. Persistence that is not the host's namespace

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

## 3. Sweep prepared roots from superseded closures

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
