# flong

Ephemeral [systemd-nspawn](https://www.freedesktop.org/software/systemd/man/systemd-nspawn.html)
containers for NixOS that start in well under a second, run one foreground
process, and leave nothing behind.

A *flong* is the papier-mâché mould a printer takes from composed type. You
make it once, then cast as many identical plates from it as you need, cheaply,
and each plate is used and discarded. That is exactly this: one prepared root
per boot, copied in about three milliseconds per session, thrown away when the
process exits.

```nix
flong.build = {
  user = "alice";
  uid = 1000;
  gid = 100;
  home = "/home/alice";
  command = ''set -- cargo build --release'';
};
```

```console
$ sudo /nix/store/…-build
```

## What it is for

Running a process inside a real NixOS container when you will do that many
times a day and care what it costs. Per-project toolchains, build sandboxes,
untrusted code, and coding agents — anything where the boundary is worth having
but a two-second startup is not.

The container is a genuine `containers.<name>` declaration, so the full NixOS
module system describes it: bind mounts, `allowedDevices`, its own package set,
its own `/etc`. What flong changes is how it is *started*.

## Why it is fast

Three designs, measured warm on the same machine, timed to first output from
the payload:

| approach | time |
|---|---|
| `extra-container`, evaluating a config per launch | 4943 ms |
| a declared container, its `.conf` rewritten per launch | 2213 ms |
| **flong: nspawn against a prepared root** | **673 ms** |

Where that time goes:

| | |
|---|---|
| Nix evaluation of the container config | ~2500 ms |
| `systemctl start` — nspawn plus systemd booting inside | 1453 ms |
| `systemd-nspawn` with no boot at all | 70 ms |
| `activate` into a prepared root (once per boot) | 176 ms |
| copying that prepared root for a session | 3 ms |
| a transient systemd scope | 40 ms |
| the payload itself, no container at all | 537 ms |

Three things account for the difference.

**Nothing is evaluated at launch.** The only value that varies per session is
the workspace, and the NixOS container module already writes every bind mount
into `/etc/nixos-containers/<name>.conf` as `EXTRA_NSPAWN_FLAGS`. So the
closure is built once by `nixos-rebuild` and the launcher reads the flags back
out. The `container@` unit that the declaration also installs is never started;
the declaration is used purely as a closure builder.

**Nothing boots.** Starting systemd inside the container costs 1.23 s of
userspace across thirty-odd units — to run a single foreground process. Skipping
it is most of the remaining win, and the price is the `/etc` that boot would
have produced.

**The store is shared, not copied.** `/nix/store` is bind-mounted read-only, so
a container's package set costs nothing to "ship" — it is already on the
machine. This is the part a Docker-shaped tool cannot do.

## What a skipped boot costs, and how it is paid

The closure carries a complete `/etc` — `nsswitch.conf`, `os-release`,
`profile`, CA certificates — but **not** `passwd`, `group` or `shadow`. Those
are written by the activation script, which is why a root assembled from the
store alone cannot resolve a username.

So `activate` is run once into a prepared root, under `/run`, keyed by the
closure hash. Every session then gets a `cp -a` of that. Keying by the hash
means a rebuilt container gets a *different* cache rather than a stale one, and
living under `/run` means it dies with the boot rather than becoming state.

Nothing of the host leaks into it: it is the container's own closure running
its own `activate`. The only host-derived file is `resolv.conf`, which nspawn
copies in — and which is deleted from the prepared root, so a snapshot of one
network's DNS does not follow a laptop to the next one.

## Usage

```nix
{
  inputs.flong.url = "github:danielbodart/flong";

  # …

  imports = [ inputs.flong.nixosModules.default ];
}
```

Declare the container with NixOS's own option, then point a flong at it:

```nix
{
  containers.sandbox = {
    ephemeral = true;
    autoStart = false;          # flong starts it, not systemd
    privateNetwork = false;

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
      environment.systemPackages = with pkgs; [ cargo rustc coreutils ];
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

### Reaching the launcher

`flong.sandbox.launcher` is the resulting package, and it must run as root.
How you arrange that is deliberately left to you: granting a human passwordless
root over a store path is a decision about your machine, not a consequence of
declaring a container, and sudo is only one of the ways to do it — a root-owned
systemd unit, `doas`, `run0` or polkit are all reasonable.

The common case is a NOPASSWD sudo rule plus a thin wrapper on `PATH`:

```nix
security.sudo.extraRules = [{
  users = [ "alice" ];
  commands = [{
    # A store path, not a command name, so what runs is fixed at build time.
    command = lib.getExe config.flong.sandbox.launcher;
    options = [ "NOPASSWD" ];
  }];
}];

environment.systemPackages = [
  (pkgs.writeShellScriptBin "sandbox-cargo" ''
    exec /run/wrappers/bin/sudo ${lib.getExe config.flong.sandbox.launcher} "$@"
  '')
];
```

Grant the **store path**, never the wrapper or a command name: that way the
thing the rule permits is fixed at build time and changes only when you rebuild.
NOPASSWD is reasonable exactly when the container is a subset of what the user
already reaches. When it is not, see `guard` below.

### Options

| option | type | default | |
|---|---|---|---|
| `container` | string | attribute name | the `containers.<name>` to drive |
| `user` `uid` `gid` `home` | | | the identity to drop to; `uid` must match the container's |
| `workspace` | lines | `git -C "$PWD" rev-parse --show-toplevel` | shell printing the directory to bind in and `cd` to; non-zero exit aborts |
| `guard` | lines | `""` | shell run on the host before launch, to refuse if this launcher is not entitled to run |
| `command` | lines | *required* | shell run as root inside, with the launcher's arguments in `"$@"`; must leave the command to run in `"$@"` |
| `tmpfs` | list of paths | `[ ]` | made container-local and empty |
| `overlays` | `{ target = lower; }` | `{ }` | lower readable, writes discarded |
| `launcherInputs` `payloadInputs` | packages | `[ ]` | extra `PATH` for `guard`/`workspace` and for `command` |
| `launcher` | package | *read-only* | the generated launcher; run it as root |

### `command` and the `"$@"` contract

`command` runs **as root, inside the container**, with the launcher's arguments
in `"$@"`. Its job is to decide what to run and leave it in `"$@"` — usually by
ending in a `set -- …`. Whatever it leaves there is exec'd after privilege is
dropped.

```nix
command = ''
  case ''${1-} in
    build) set -- cargo build --release ;;
    test)  set -- cargo test ;;
    *)     echo "usage: build|test" >&2; exit 1 ;;
  esac
'';
```

It sits outside the privilege drop rather than inside it for two reasons:
`writeShellApplication` runs shellcheck over it there, and the inner shell is
single-quoted, so a snippet containing a quote would break the launch rather
than fail to lint.

### Carving exceptions out of a bind mount

A bind mount is all-or-nothing, and `bindMounts` can only emit `--bind`.
Because flong drives nspawn directly, two more options are available, both
applied *after* the container's own mounts — so they carve a subdirectory out
of one:

```nix
# Container-local and empty. The host's contents are invisible; nothing
# written survives. For caches, scratch, and state captured on the host that
# would be wrong in here.
tmpfs = [ "/home/alice/.cache" ];

# The lower directory is readable and every write goes to an upper layer that
# dies with the container. "Read-only with a layer on top", which a plain bind
# cannot express.
overlays."/home/alice/.state" = "/home/alice/.state";
```

Both are mounted so that `user` can actually write to them, which is less
obvious than it sounds:

* A bare `--tmpfs` mounts **root-owned, 0755**, so an unprivileged payload
  cannot write to it at all — and fails quietly, because most programs treat an
  unwritable cache as a missing one. flong therefore mounts each `tmpfs` entry
  `mode=0755,uid=<uid>,gid=<gid>`. To choose your own, append options to the
  path and they are passed through untouched: `"/home/alice/.cache:mode=0700,uid=1000"`.

* An overlay's upper layer is chowned to the same user, so writes land
  somewhere it owns. **The merged directory still takes its ownership from the
  lower one**, though, and that part is not flong's to fix: overlaying a
  root-owned directory gives you a root-owned merged directory that `user`
  cannot create files in. Overlay directories the user already owns.

The overlay's upper layer is created inside the session root, so the cleanup
that already exists removes it. nspawn's own empty-string form
(`--overlay=lower::dest`) is deliberately not used: it puts the upper under the
host's `/var/tmp` and leaks it if the session is killed.

**overlayfs reports changing device and inode numbers as a file is written**,
so never put one over a path holding a sqlite database.

### `guard` is load-bearing

However you arrange to run the launcher, it is reachable directly by anyone who
can run it — so a wrapper in front of it is a convenience and not a gate. If a
container grants more than its caller already had (devices, credentials,
another user's sockets), the launcher must establish its own entitlement:

```nix
guard = ''
  if [ "$(project-tier "$PWD")" != trusted ]; then
    echo "refusing: this checkout is not trusted" >&2
    exit 1
  fi
'';
```

A container that is a strict *subset* of what the caller already reaches needs
no guard: there is nothing to gain by entering it.

## Design notes

**tini, not `--as-pid2`.** nspawn's stub init reaps orphans, which is half of
what is needed and is documented as if it were all of it. It does not deliver
SIGTERM to the payload — a trap in pid 2 never fires and the stub simply halts
the container. tini forwards, with `-g` so a payload that shells out takes its
children with it. `--kill-signal` is set to SIGTERM explicitly, because nspawn
defaults it to SIGKILL whenever `--boot` is not used.

**A transient scope.** Driving nspawn from a script means there is no unit, and
none of the cgroup confinement `container@.service` provides.
`systemd-run --scope` restores it — `DevicePolicy=closed` plus the container's
own `allowedDevices`, translated from the declaration — and transient units
need no daemon-reload, so it costs ~40 ms rather than the ~5 s a drop-in would.
nspawn is given `--keep-unit`, or it creates a scope of its own and those
properties apply to nothing.

**setpriv, not runuser.** runuser forks and stays alive as the parent, so a
SIGTERM aimed at the container lands on it and the payload never hears about
it. setpriv execs, so the payload becomes the process tini can signal.

**Unique machine names.** One per invocation rather than per workspace, so two
sessions in the same directory do not collide. It costs nothing, because there
is no unit to install — which is what makes concurrent sessions possible at
all.

**Residue is swept on the way in.** A clean exit leaks nothing; a SIGKILL
leaves nspawn's unix-export mount behind, and the next run with the same name
refuses to start. No trap survives SIGKILL, so each launch sweeps first.
Liveness is decided by the owning pid, which is encoded in the session name and
alive from before the directory exists — asking `machinectl` looks more correct
and is racy, because a session that has copied its root but not yet started
nspawn is not registered yet, and a concurrent launch would delete it.

## Limitations

**NixOS only.** It is built on `containers.<name>` and the NixOS activation
script. There is no portable version of this.

**It reads a generated file.** Bind mounts are recovered by parsing
`EXTRA_NSPAWN_FLAGS` out of `/etc/nixos-containers/<name>.conf`. That file is
an implementation detail of the NixOS container module, not a stable interface.
It has been stable for a long time, but nothing upstream promises it, and the
VM test in `tests/` exists mostly to catch the day it changes.

**No uid namespace.** `privateUsers = "pick"` is not usable here: a
bind-mounted file owned by the host uid maps to an unmapped uid inside, so
reads fail with `Permission denied`, and `--private-users-ownership=map` does
not change the outcome on a 6.18 kernel. What a flong isolates is the
filesystem, the device set and the process tree — not a container escape.

**The store is shared.** `/nix/store` is bind-mounted read-only into every
container. That is the source of the speed, and it means the container can read
every package on the host. Secrets do not belong in the store anyway, but it is
worth saying out loud.

**One process.** There is no init, no logging, no restart, no dependency
ordering. If you want a service, declare a service.

## Versions

Every push to `trunk` that passes `nix flake check` is released, tagged and
published automatically. There is no manual step and no tag to cut by hand.

The version is **derived from the repository rather than stored in it**:

| part | from | |
|---|---|---|
| major | `./VERSION` | the one deliberate decision; `0` says the option interface is still moving |
| minor | `git rev-list --count HEAD` | only ever rises, and names exactly one commit |
| patch | `GITHUB_RUN_NUMBER`, else a UTC timestamp | separates two builds of the same commit, and sorts a local build after CI's |

```console
$ ./scripts/version.sh
0.42.20260914102120      # built locally
0.42.317                 # the same commit, built by CI run 317
```

So every release is unique and monotonic, two pushes cannot collide on a tag,
and a re-run of the same commit gets its own. Release notes are the commits
since the previous tag.

Pin it like any flake. `flake.lock` records the exact revision, which is a
stronger statement than the tag:

```console
$ nix flake update flong
```

Bump `VERSION` when the option interface breaks — removing an option, or
changing what an existing one means.

## Development

```console
$ nix flake check          # the VM test, and shellcheck over the version script
$ nix build .#checks.x86_64-linux.basic
```

The test boots a VM and exercises every option that changes what the container
sees: the workspace override, a read-write bind, a tmpfs masking part of that
bind, an overlay whose writes must not reach the lower directory, the privilege
drop, the NOPASSWD grant, exit-status propagation, session cleanup, and reuse
of the prepared root.

## Licence

MIT.
