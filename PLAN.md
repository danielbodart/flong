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

## 5. Let the hook wrap the payload

`mkPayload` runs the consumer's `command` — arbitrary shell, inside the sandbox
— before it execs the workload. A hook that needs the workload wrapped (a
launcher's own gate, say) must therefore be able to put a prefix on the nspawn
command line before the payload, not only inside `command`.

With task 4's ordering this is a correctness nicety rather than a boundary: a
workload that tries once in the first few milliseconds gets `ENETUNREACH`
instead of waiting. Measured from the `command` position without the ordering
fix: 8 of 8 unsteered over 1.8 s.

## 6. A teardown hook

Called from `cleanup` and from the sweep, so a session's external state is
released on both the clean and the killed path. Depends on tasks 2 and 3: the
sweep must be able to tell a dead session from a live one before it is given
anything to tear down.

## 7. `network` — a real network for a private session

`flong.<name>.network = { … }`, present or absent; there is no `enable` flag.
It requires `containers.<name>.privateNetwork = true`, and it is implemented
with [pasta](https://passt.top).

**Why pasta and not a veth pair.** flong runs many concurrent sessions from one
container declaration, and `hostAddress`, `localAddress` and `forwardPorts` are
static per container: two sessions would claim the same address, and the host
cannot route one address to two interfaces. A veth would therefore need flong to
allocate addresses from a pool and keep that allocation across crashes, plus
`ip_forward`, NAT, and firewall rules to stop the sandbox reaching services the
host binds on `0.0.0.0`. pasta needs none of it: no host-side interface, no host
configuration, no addressing, and the sandbox gets no packet-level access at all,
so spoofing is not expressible. It is Podman's default network mode and the
rootless Docker backend.

The declaration's veth, bridge and port options stay refused, and the assertion
should now say why — concurrency, not "not built yet".

Options, in the declaration's own vocabulary:

- `forwardPorts` — host to sandbox, shaped exactly like
  `containers.<name>.forwardPorts`: `{ protocol; hostPort; containerPort; }`.
- `hostPorts` — the reverse: ports on the host's loopback the sandbox may reach.
  The declaration has no equivalent, and this is what a session needs to reach a
  database the host is running.

Everything else is a safe default, not an option:

- `--no-map-gw`. Without it the host's loopback is reachable through the gateway
  address — measured: a host listener on `127.0.0.1:18123` answered from inside
  the sandbox even with every port list set to `none`.
- An explicit `none` for every port class, because `-t`, `-u`, `-T` and `-U` all
  default to `auto`, and `auto` forwards every bound port on the host.
- `--config-net`, so pasta configures the namespace itself.

**Attaching.** pasta cannot attach by pid as root: it calls `isolate_user()`,
which drops to `nobody`, before `pasta_open_ns()` calls `setns()`, and it never
sets `PR_SET_KEEPCAPS`. All three by-pid forms fail with `Permission denied` —
measured, in flong's own `--user=` shape. The working invocation is a
bind-mounted namespace pin plus `--runas 0`:

```
pasta --config-net --netns <pin> --runas 0 -t none -u none -T none -U none --no-map-gw
```

**Releasing.** The pin must be removed with `umount -l` and then `rm`. A plain
`umount` is `target is busy`, rc=32, for as long as pasta lives — measured both
with the container alive and after it had gone — so flong's existing
`umount … 2>/dev/null || true` idiom would silently leak it, and a leaked pin
keeps the dead session's whole namespace alive indefinitely. After `umount -l`
and `rm`, pasta reaps itself in about 60 ms: *"Namespace … is gone, exiting"*.

Note what this costs, honestly: a session with a network has a pin and a process
to clean up. A session without one has neither — no pin, no extra process,
everything dies with the namespace. That, and not "nothing is pinned", is the
shape to document.

`passt` joins `runtimeInputs`, along with `iproute2` for the pin.

## 8. Per-session binds, source ≠ destination

`extraBinds` cannot serve a hook: it takes directories only, binds at the same
path on both sides, is resolved as the caller before `guard`, and is advertised
to the payload through `FLONG_EXTRA_BINDS`. A hook needs to bind a file or a
socket from a host path of its choosing to a fixed path inside, and not tell the
workload about it.

It must refuse `:` and newlines the way `resolve_binds` does. Bind the specific
path, never a shared parent: with a whole directory bound, a workload could list
and write its neighbours' entries — measured.

## 9. Capabilities

Pass `--drop-capability=CAP_NET_ADMIN` and `--no-new-privileges=yes` for a
session with a root hook. Measured to remove exactly `CAP_NET_ADMIN` from the
bounding set and set `NoNewPrivs=1`, with host-side setup unaffected.

Document it as defence in depth and nothing more: `unshare -U` inside the
sandbox restores the full bounding set. What actually holds is namespace
ownership — the namespace is owned by the initial user namespace, so a workload
that is not its owner gets `EPERM` on every write, whatever capabilities it
appears to hold. Measured: it cannot list the ruleset, flush it, change a route,
an address or a link, write `/proc/sys/net/*`, or move an interface into a
namespace it just created.

Refuse `--capability`, `--ambient-capability` and `--private-users` arriving
through `extraFlags`. That contradicts the advice in flong's own assertion
message today, which should be rewritten: `extraFlags` is not a hole for
capabilities.

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

The VM test grows a network section. Each of these is a property the tasks above
are supposed to deliver, and none of them is asserted today:

- A session with no `network` has only `lo`, and an empty route table.
- With a root hook installing a ruleset, the workload cannot list or change it —
  including after `unshare -U`.
- Rules land before any egress exists: with egress deliberately delayed, every
  attempt before it fails, and every attempt after it is steered.
- `network` reaches a host port named in `hostPorts` and nothing else on the
  host's loopback.
- A port in `forwardPorts` is reachable from the host; nothing else is.
- Clean exit releases the pin and pasta.
- A bind added by the hook exists inside and is not named in
  `FLONG_EXTRA_BINDS`.

The suite runs in about 1m11s with KVM and 2m14s under TCG, which is what CI
has. That is affordable; keep it that way.
