<p align="center"><img src="logo.png" alt="flong" width="600"></p>

# flong

Ephemeral [systemd-nspawn](https://www.freedesktop.org/software/systemd/man/systemd-nspawn.html)
containers for [NixOS](https://nixos.org/) that start in about 100ms, run one
foreground process, and leave nothing behind.

> A *flong* is the papier-mâché mould a printer takes from composed type. You
> make it once, then cast as many identical plates from it as you need, cheaply,
> and each plate is used and discarded.

That is the mechanism exactly: one prepared root per boot, copied in about
three milliseconds per session, thrown away when the process exits.

## What it is for

Running a process inside a real [NixOS
container](https://nixos.org/manual/nixos/stable/#ch-containers) when you will
do it many times a day and care what it costs — per-project toolchains, build
sandboxes, untrusted code, coding agents. Anything where the boundary is worth
having but a two-second startup is not.

You declare an ordinary
[`containers.<name>`](https://search.nixos.org/options?query=containers.%3Cname%3E),
so the whole NixOS module system describes it: bind mounts, `allowedDevices`,
its own package set, its own `/etc`. flong changes only how it is *started*,
using the declaration as a closure builder and never starting the `container@`
unit.

## Why it is fast

Measured warm on one machine, timed to first output from the payload:

| approach | time |
|---|---|
| [`extra-container`](https://github.com/erikarvstedt/extra-container), evaluating a config per launch | 4943 ms |
| a declared container, its `.conf` rewritten per launch | 2213 ms |
| **flong: nspawn against a prepared root** | **117 ms** |

**Nothing is evaluated at launch.** Around 2.5 s of the slow cases is Nix
evaluation. The only value that varies per session is the workspace, and the
container module already writes every bind mount into
`/etc/nixos-containers/<name>.conf` as `EXTRA_NSPAWN_FLAGS` — so the closure is
built once by
[`nixos-rebuild`](https://nixos.org/manual/nixos/stable/#sec-changing-config)
and the launcher reads the flags back out.

**Nothing boots.** systemd inside the container costs 1.23 s across thirty-odd
units, to run one foreground process. What it buys is the `/etc` boot would
have produced: `passwd`, `group` and `shadow` come from the activation script,
not the closure, so a root assembled from the store alone cannot resolve a
username. flong pays that once instead — `activate` runs into a prepared root
under `/run`, keyed by the closure hash, and each session gets a `cp -a` of it
in 3 ms.

**The store is shared, not copied.** `/nix/store` is bind-mounted read-only, so
a package set costs nothing to ship — it is already on the machine, which is
the part a Docker-shaped tool cannot do. It also means every container can read
every package on the host.

## Usage

```nix
{
  inputs.flong.url = "github:danielbodart/flong";

  imports = [ inputs.flong.nixosModules.default ];
}
```

Declare the container with NixOS's own option, then point a flong at it:

```nix
{
  containers.sandbox = {
    autoStart = false;          # flong starts it, not systemd

    bindMounts."/home/alice/.cargo" = {
      hostPath = "/home/alice/.cargo";
      isReadOnly = false;
    };

    config = { pkgs, ... }: {
      system.stateVersion = "24.05";
      users.users.alice = {
        isNormalUser = true;
        uid = 1000;
        group = "users";
        home = "/home/alice";
      };
      users.groups.users.gid = 100;
      environment.systemPackages = with pkgs; [ cargo rustc ];
    };
  };

  flong.sandbox = {
    user = "alice";          # the uid, gid and home come from the container
    command = ''set -- cargo "$@"'';
  };
}
```

### Options

| option | type | default | |
|---|---|---|---|
| `container` | string | attribute name | the `containers.<name>` to drive |
| `user` | string | *required* | which account in the container to be; its uid, gid and home are read from the container's own `passwd` |
| `workspace` | lines | `git -C "$PWD" rev-parse --show-toplevel` | shell printing the directory to bind in and `cd` to, run as the *invoking* user; non-zero exit aborts |
| `guard` | lines | `""` | shell run on the host as root, after `workspace`, to refuse if this launcher is not entitled to run |
| `command` | lines | *required* | shell run as `user` inside, with the launcher's arguments in `"$@"`; must leave the command to run in `"$@"` |
| `extraBinds` | lines | `""` | shell printing further directories to bind read-write, one per line, run after `workspace` with `$workspace` exported |
| `extraBindsRo` | lines | `""` | as `extraBinds`, bound read-only |
| `tmpfs` | list of paths | `[ ]` | made container-local and empty; merged with the container's own `tmpfs` |
| `overlays` | `{ target = lower; }` | `{ }` | lower readable, writes discarded |
| `properties` | `{ NAME = value; }` | `{ }` | systemd properties for the session's scope, e.g. `MemoryMax` |
| `attach` | lines | `""` | shell run on the host as root once the session's namespace exists, with it in `$netns`; whatever it installs is in place before any egress |
| `attachBinds` | lines | `""` | shell printing `SOURCE:DESTINATION` lines, run as root before nspawn: a file or socket bound where the hook chooses, not announced to the payload |
| `attachWrap` | lines | `""` | shell printing a command, one word per line, that the payload is exec'd through inside the session |
| `detach` | lines | `""` | shell run on the host as root when a session ends — by its own trap, or by the next launch's sweep if it was killed — with `$machine` in scope |
| `launcherInputs` `payloadInputs` | packages | `[ ]` | extra `PATH` for `guard`/`workspace` and for `command` |
| `launcher` | package | *read-only* | the generated launcher; run it as root |

Only `user` is declared, and deliberately so: which account to be is a choice,
while that account's uid, gid and home are facts the container already carries —
in the `passwd` its own activation script wrote, which is the file nspawn
resolves `--uid` against. flong reads them from the prepared root at launch, so
there is no second copy to keep in step, nothing for an assertion to compare,
and no failure where the launcher owns `TMPDIR` to one uid while the session
runs as another. It also reaches what evaluation cannot see: a container
declared by `path` has no configuration to read, and a `users.users.<name>.uid`
left unset is allocated during activation.

What flong cannot derive, and does not police, is the other end of that number:
the account you name should have the *invoking* user's uid. There is no uid
namespace, so a bind mount carries the host's numbers — a session running as
1001 cannot write a workspace owned by 1000, whatever either side calls the
user. The container declares the uid and nothing in the container knows who will
invoke the launcher, so this is the one identity fact that is still yours to get
right.

### What it takes from the declaration

flong drives the declaration rather than reimplementing it, so most of
`containers.<name>` still means what it means. What it cannot mean is anything
that needed the container's own init: nspawn drops to `user` before pid 1, so
there is no privileged moment inside a session to bring an interface up or grant
a capability to. Some of that is structural — nothing in a session will ever
hold a capability — and some of it is only unwritten, because the launcher is
root on the host and can build out there what a container's init would have
built inside.

| declared | under flong |
|---|---|
| `config` `path` `nixpkgs` `specialArgs` | the closure, which is the only thing flong wants from it |
| `bindMounts` | passed to nspawn, read back out of the generated `.conf` |
| `extraFlags` | passed to nspawn the same way, except `--capability`, `--ambient-capability`, `--private-users` and `-U`, which are **refused at evaluation** |
| `allowedDevices` | `DeviceAllow=` on the session's scope, behind the same `DevicePolicy=closed` the unit uses |
| `tmpfs` | merged with `flong.<name>.tmpfs`, and given the payload's ownership |
| `privateNetwork` | a network namespace holding loopback and nothing else |
| `networkNamespace` | the session joins that namespace |
| `ephemeral` `autoStart` `restartIfChanged` `timeoutStartSec` | inert — they describe the `container@` unit, which is never started. `autoStart = true` warns, because it boots the container you were avoiding |
| `flake` `privateUsers` `additionalCapabilities` `enableTun` | **refused at evaluation** — none of these can work here |
| `hostBridge` `hostAddress*` `localAddress*` `localMacAddress` `forwardPorts` `interfaces` `macvlans` `extraVeths` | **refused at evaluation** — *not built yet*, see `PLAN.md` |

A refusal is not the same as an omission. Every one of these declares *less*
than the default — a uid namespace, a smaller capability set, a network of its
own — so a container that silently is not the one you declared is worse than one
that will not build. The two groups differ in why: the first cannot work here at
all, while the second is simply not written, and the assertion says which.
`extraFlags` is not a way round the first group: a capability, an ambient one
or a user namespace of the container's own each gives a session back something
flong keeps from it on purpose, so those flags are refused there too.

Network isolation is the one worth knowing about, because the default is none:
a session shares the host's network namespace, so it can reach anything on
loopback and bind any port. `privateNetwork = true` takes that away entirely.
Anything in between — NAT, a VPN, an allowlisting proxy — is for now a namespace
you build on the host yourself, with a unit or `ip netns`, and point
`networkNamespace` at. Teaching the launcher to build one from the declaration
is the next thing on `PLAN.md`; the interface for it is already in
`containers.<name>`, which is why those options are refused loudly rather than
quietly dropped.

### Reaching the launcher

`flong.sandbox.launcher` must run as root, by whatever means you prefer —
[sudo](https://www.sudo.ws/), a root-owned unit,
[`doas`](https://man.openbsd.org/doas),
[`run0`](https://www.freedesktop.org/software/systemd/man/latest/run0.html),
[polkit](https://gitlab.freedesktop.org/polkit/polkit). Granting a human
passwordless root over a store path is a decision about your machine, not a
consequence of declaring a container.

```nix
security.sudo.extraRules = [{
  users = [ "alice" ];
  commands = [{
    # A store path, not a command name, so what runs is fixed at build time.
    command = lib.getExe config.flong.sandbox.launcher;
    options = [ "NOPASSWD" ];
  }];
}];
```

Grant the **store path**, never a wrapper or a command name, so what the rule
permits changes only when you rebuild. NOPASSWD is reasonable exactly when the
container is a subset of what the caller already reaches; when it is not, that
is what `guard` is for.

### `command`: deciding what runs

`command` runs as `user` **inside** the container with the launcher's arguments
in `"$@"`. Its job is to decide what to run and leave it in `"$@"`, usually by
ending in a `set -- …`. Whatever it leaves there is exec'd.

```nix
command = ''
  case ''${1-} in
    build) set -- cargo build --release ;;
    test)  set -- cargo test ;;
    *)     echo "usage: build|test" >&2; exit 1 ;;
  esac
'';
```

**Nothing in a session is privileged.** nspawn drops to `user` before it starts
pid 1, so [tini](https://github.com/krallin/tini), this snippet and the payload
it chooses all run as `user` — there is no moment at which anything inside the
container holds root. Privilege that a session genuinely needs is arranged by
the launcher, on the host, before nspawn: a bind mount, a `tmpfs` entry, an
`overlays` upper.

### Taking more than one directory in

`workspace` names the one directory a session is *about*. `extraBinds` names
the others it needs beside it, one path per line:

```nix
# Whatever travels with this checkout, read-write.
extraBinds = ''
  case $workspace in
    */main-project) printf '%s\n' "$HOME/Projects/sibling-project" ;;
  esac
'';

# Reference material: readable, not editable.
extraBindsRo = ''printf '%s\n' "$HOME/src/upstream"'';
```

Both run after `workspace`, with `$workspace` exported, so a snippet can
answer "what travels with *this* directory" instead of naming a fixed set.
Both run as the invoking user and see the launcher's arguments, exactly as
`workspace` does, and every line is resolved with `realpath` and then refused
if it names a `:` or a newline.

`guard` receives them as `$extra_binds` and `$extra_binds_ro`, newline
separated. **A guard that reads only `$workspace` lets a second directory in
unexamined** — if your container grants more than its caller already had,
judge these too.

`command` receives them as `$FLONG_EXTRA_BINDS` and `$FLONG_EXTRA_BINDS_RO`,
`:` separated, because a mount the process does not know about is half of what
the caller asked for.

Read-only is not a boundary on its own: it stops writes, not execution. Use it
for directories a session should read rather than edit, not to make an
untrusted one safe.

### Carving exceptions out of a bind mount

A bind mount is all-or-nothing and `bindMounts` can only emit `--bind`. Because
flong drives nspawn directly, two more options are available, applied after the
container's own mounts so they carve a subdirectory out of one:

```nix
# Container-local and empty: host contents invisible, nothing written survives.
tmpfs = [ "/home/alice/.cache" ];

# Lower readable, every write to an upper layer that dies with the container.
overlays."/home/alice/.state" = "/home/alice/.state";
```

Both are mounted so `user` can write to them. A bare `--tmpfs` is root-owned
0755, which an unprivileged payload cannot write to and fails *quietly* on,
most programs treating an unwritable cache as a missing one; flong mounts each
entry `mode=0755,uid=<uid>,gid=<gid>` instead. Append your own options to
override: `"/home/alice/.cache:mode=0700,uid=1000"`.

`/run/user/<uid>` is one of these whether you ask or not, at `mode=0700` and
owned by the session's user, since
`XDG_RUNTIME_DIR` names it and `/run` is nspawn's own tmpfs — nothing inside a
session could create it. Name it in `tmpfs` yourself to change the options, or
bind a socket at a path beneath it to let exactly one thing through from the
host's session.

An overlay's upper layer is chowned to `user`, but **the merged directory takes
its ownership from the lower one** — so overlay directories the user already
owns, or it cannot create files in the result. Mounts nest either way, a
`tmpfs` hiding part of a bind or a bind reaching back through a `tmpfs`, since
nspawn orders custom mounts by destination rather than by argument.

### `guard` and `workspace`

The launcher is reachable directly by anyone who can run it, so a wrapper in
front of it is a convenience and not a gate. If the container grants more than
its caller already had — devices, credentials, another user's sockets — the
launcher must establish its own entitlement:

```nix
guard = ''
  if [ "$(project-tier "$workspace")" != trusted ]; then
    echo "refusing: this checkout is not trusted" >&2
    exit 1
  fi
'';
```

A container that is a strict *subset* of what the caller already reaches needs
no guard: there is nothing to gain by entering it.

Both hooks run on the host before the container exists, in this order:

**`workspace` first, as the invoking user** — `SUDO_UID` or `PKEXEC_UID`,
falling back to root only when nothing unprivileged invoked it. It runs `git`
in a directory the caller chose, and git reads configuration out of whatever
repository it is pointed at, so it derives a caller's answer without a caller's
privilege. What it prints is resolved with `realpath`, then refused if it names
a `:` or a newline, neither of which `--bind` can express.

**`guard` second, as root**, with `$workspace` in scope, so it judges the
directory that actually gets mounted rather than re-deriving one from `$PWD`.
It stays root because a gate the caller could `ptrace` is not a gate. Note that
a refused caller has already reached `workspace`, which matters only if yours
has side effects.

### `attach`: steering a session from outside

`guard` runs before the session exists, so it cannot touch the one thing a
launcher most wants to steer: the session's network namespace. `attach` runs
as root on the host *after* nspawn has made it, with the leader's pid in
`$leader`, the namespace in `$netns`, and `$machine`, `$uid`, `$gid`, `$home`,
`$workspace` and the extra binds all in scope:

```nix
containers.agent.privateNetwork = true;

flong.agent = {
  launcherInputs = [ pkgs.nftables ];
  attach = ''
    nsenter --net="$netns" nft -f ${./steer.nft}
  '';
};
```

**The contract is an ordering, and it is the whole security property.**
Whatever `attach` installs is in place before anything gives the namespace
egress. A `privateNetwork` namespace starts with `lo` up and an empty route
table, so until egress exists the workload has nowhere to go and nothing to
race: no handshake, no readiness protocol, no window. flong attaches its own
network only after `attach` returns. Provision egress of your own *first* — from
`guard`, or at the top of the hook — and the property is gone without anything
failing: measured, 12 connections out of 12 went round the rules.

What stops the workload undoing what the hook installed is that the namespace
is owned by the *initial* user namespace, which the workload is not in: it gets
`EPERM` on every write — listing or flushing the ruleset, changing a route, an
address or a link — whatever capabilities it appears to hold. A session with a
hook also runs with `CAP_NET_ADMIN` dropped from its bounding set and
`NoNewPrivs` set, but that is defence in depth and nothing more: `unshare -U`
inside the sandbox gives the workload a full set again, in a namespace that
owns nothing of the session's.

A hook that exits non-zero ends the session rather than leaving it running
unsteered; so does a leader that never appears. Without `privateNetwork` the
session shares the host's namespace and `$netns` names that one, so a hook that
installs rules there is steering the host.

`attachBinds` is how a hook gets a socket or a single file into the session,
which `extraBinds` cannot do: it prints `SOURCE:DESTINATION` lines, bound from a
host path of its choosing to a fixed path inside, and nothing of them reaches
`FLONG_EXTRA_BINDS` — they are the launcher's plumbing, not what the caller
asked for. It runs as root before nspawn, because a bind mount is an argument
to nspawn and the mount table is made by the time there is a namespace; but
after the machine name exists and the cleanup trap is armed, so a source can be
made per session and is released on every path. Bind the specific path and never
a shared parent: with a whole directory bound, a workload can list and write
its neighbours' entries.

`detach` releases what the other two made, and it runs on both paths out of a
session: from the launcher's own trap when a session ends, and from the next
launch's sweep when its launcher was killed and no trap ran. That second path
is why only `$machine` is in scope — it is all a killed session leaves — and why
a teardown must be safe to run for state that is already gone. Each session
records which teardown is its own, so the sweep runs *that* one, even when the
launch doing the sweeping is a different launcher over the same container or a
later generation of this one.

`attachWrap` prints a command, one word per line, that the payload is exec'd
through — spliced between the session's pid 1 and the payload, which is the
only place a wrapper can go: `command` is already inside, running as `user`, so
a gate expressed there is one the workload could have declined to run.

## Limitations

**NixOS only.** Built on `containers.<name>` and the NixOS activation script.
There is no portable version of this.

**It reads a generated file.** Bind mounts are recovered by parsing
`EXTRA_NSPAWN_FLAGS` out of `/etc/nixos-containers/<name>.conf`, an
implementation detail nothing upstream promises; the VM test exists mostly to
catch the day it changes. It is written unescaped, so a path containing
whitespace or a `:` would split into two flags each valid and neither correct;
undetectable at runtime, so such a path is refused at evaluation.

**No uid namespace.** `privateUsers = "pick"` is not usable here: a
bind-mounted file owned by the host uid maps to an unmapped uid inside, so
reads fail with `Permission denied`, and `--private-users-ownership=map` does
not change that on a 6.18 kernel. A flong isolates the filesystem, the device
set, the process tree and — if you ask for it — the network. Not a container
escape.

**One process.** No init, no logging, no restart, no dependency ordering. If
you want a service, declare a service.

**Nothing that lives in `/run`.** nspawn makes `/run` fresh at every start, so
anything a NixOS option installs there at boot is declared, carried in the
closure, and absent from a session. `systemd.tmpfiles.rules` is the exception,
because flong applies them while preparing the root — everything else is not:

- **No setuid wrappers.** `security.wrappers` is a unit plus a mount, so
  `/run/wrappers/bin` stays on `PATH` and stays empty: no `sudo`, no `ping`, no
  `fusermount` inside. That is a property and not a bug — setuid root in a
  container with no uid namespace is root over the host's uids, holding
  `CAP_SYS_ADMIN` from nspawn's default set.
- **No bus.** `services.dbus` never starts, so dbus clients fail, and with them
  every `systemd.user` service and anything socket-activated.
- **No PAM session**, so `security.pam.loginLimits` never applies.

**No Nix.** `/nix/store` is bind-mounted read-only and the daemon socket is not,
so `nix build` and `nix develop` do not work in a session. Deliberate for now:
that socket builds arbitrary derivations, reaches the network through a
fixed-output one, and — for a `trusted-user` — sets sandbox options, which is
host-equivalent. See `PLAN.md`.

**A session lives in RAM.** The root is copied under `/run`, and so are
`TMPDIR` and every overlay upper, so a payload that writes ten gigabytes of
build output to `$TMPDIR` spends the host's memory on it. That is what
`properties.MemoryMax` is for.

**Getting into a live session is `nsenter`.** A session registers with machined,
so `machinectl list` shows one and `machinectl status` gives you its leader pid —
but `machinectl shell` asks the container's own systemd to start a unit, and
there isn't one, so a shell is `nsenter --target <leader> --all` as root.
`nixos-container login` and `journalctl -M` want the unit that never starts.

**Killing the launcher does not kill the session.** `systemd-run --scope` makes
the workload a child of the scope, so `kill -9` on a launcher leaves the session
running — with no trap left to tidy up after it, since no trap survives SIGKILL.
End such a session with `systemctl stop <machine>.scope` or `machinectl
terminate <machine>`; `machinectl list` gives you the name.

What a dead session leaves behind — its root, nspawn's `unix-export` mount and
its mount tunnel, and whatever its `detach` would have released — is swept by
the next launch of the same container, across
every prepared root that container has had rather than only the current
closure's. Live sessions are left alone: a launch has no business terminating
its neighbours, and liveness is read from the scope and machined rather than
from the launcher that may already be gone.

## Versions

Every push to `trunk` that passes `nix flake check` is tagged and released
automatically. The version is derived from the repository rather than stored in
it: `./VERSION` is the major, the commit count the minor, the CI run number (or
a UTC timestamp locally) the patch — so releases are unique and monotonic.

Pin it like any flake; `flake.lock` records the exact revision, a stronger
statement than the tag. Bump `VERSION` when the option interface breaks.

## Development

```console
$ nix flake check
```

Boots a VM and exercises every option that changes what the container sees,
plus the hook ordering, the identity every session process runs as, session
cleanup and the sweep that reclaims what a killed session left.

## Licence

MIT.
