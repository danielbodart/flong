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
    ephemeral = true;
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
    user = "alice";
    uid = 1000;              # must match the container's
    gid = 100;
    home = "/home/alice";
    command = ''set -- cargo "$@"'';
  };
}
```

### Options

| option | type | default | |
|---|---|---|---|
| `container` | string | attribute name | the `containers.<name>` to drive |
| `user` `uid` `gid` `home` | | | the identity the session runs as; `uid` must match the container's |
| `workspace` | lines | `git -C "$PWD" rev-parse --show-toplevel` | shell printing the directory to bind in and `cd` to, run as the *invoking* user; non-zero exit aborts |
| `guard` | lines | `""` | shell run on the host as root, after `workspace`, to refuse if this launcher is not entitled to run |
| `command` | lines | *required* | shell run as `user` inside, with the launcher's arguments in `"$@"`; must leave the command to run in `"$@"` |
| `extraBinds` | lines | `""` | shell printing further directories to bind read-write, one per line, run after `workspace` with `$workspace` exported |
| `extraBindsRo` | lines | `""` | as `extraBinds`, bound read-only |
| `tmpfs` | list of paths | `[ ]` | made container-local and empty |
| `overlays` | `{ target = lower; }` | `{ }` | lower readable, writes discarded |
| `launcherInputs` `payloadInputs` | packages | `[ ]` | extra `PATH` for `guard`/`workspace` and for `command` |
| `launcher` | package | *read-only* | the generated launcher; run it as root |

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

An overlay's upper layer is chowned to `user`, but **the merged directory takes
its ownership from the lower one** — so overlay directories the user already
owns, or it cannot create files in the result. Mounts nest either way, a
`tmpfs` hiding part of a bind or a bind reaching back through a `tmpfs`, since
nspawn orders custom mounts by destination rather than by argument.

**[overlayfs](https://docs.kernel.org/filesystems/overlayfs.html) reports
changing device and inode numbers as a file is written**, so never put one over
a path holding a [sqlite](https://sqlite.org/) database.

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
set and the process tree — not a container escape.

**One process.** No init, no logging, no restart, no dependency ordering. If
you want a service, declare a service.

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
plus the hook ordering, the identity every session process runs as and session
cleanup.

## Licence

MIT.
