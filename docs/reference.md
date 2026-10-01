# Reference

The detail behind the [README](../README.md). Every option, with its type and
default, is in [declaration.md](declaration.md). Why it works this way is in
[DESIGN.md](../DESIGN.md).

## Running a container

Run the launcher as yourself. It refuses to run as root, and needs no sudo
rule. `flong launch <name> -- ARGS` does the same from
`/etc/flong/<name>.zon`; `flong list` names every declaration.

The launcher has your privilege and no more. You can enter, change or read
any of your containers from the host, as you can any process you run, so
its checks (`workspace`, `binds`, `guard`) are consistency checks, not a
security boundary. The boundary is between the entrypoint and you.

Exit codes:

| code | meaning |
|---|---|
| the entrypoint's | it ran and exited |
| 128+n | a signal killed it |
| 125 | it never ran: `postStart` failed, the network could not be attached, or the spec was refused |
| 1 | refused before launch: the declaration, the user, the working directory, the id maps, or a failing `workspace`, `binds`, `guard`, `seccompPolicy` or `exec` |
| 2 | usage error, or no such declaration |

If the cached rootfs is removed during a launch, the launcher starts again
with the same arguments.

## Hooks

Each hook is a command, `[ program arg... ]`, run as you with the launcher's
arguments appended, and never read by a shell; use `pkgs.writeShellScript`
for a script. Every hook but `workspace` is a list of commands run in order,
so several modules' lists concatenate (`mkBefore`, `mkAfter`).

| hook | sees |
|---|---|
| `workspace` | `"$@"` |
| `binds` | `"$@"`, `$workspace`, `$workspace_mode` (`ro` or `rw`) |
| `guard` | the above and `$binds` (one `PATH:ro` or `PATH:rw` per line) |
| `seccompPolicy` | the above and `$machine` |
| `exec` | the same |
| `postStart` | the above, `$leader` (the container's pid 1 on the host), `$userns` and `$netns` (its namespaces, as descriptors), `$uid`, `$gid`, `$home` |
| `postStop` | `$machine` only |

- `workspace` prints `PATH` (read-write) or `PATH:ro`. `binds` prints
  `PATH` (read-only) or `PATH:rw`, one per line. Paths are resolved with
  `realpath`, must be directories, and may not contain `:` or a newline.
- `postStart` is where firewall rules go: the entrypoint waits for it, and
  the network is attached after it. `nsenter --user="$userns" --net="$netns"`
  runs a tool as the container's root, with no capability over the host. A
  hook entering the mount namespace must also enter the pid namespace, or
  `/proc/self` does not resolve. Anything a hook starts is in the container's
  cgroup and killed with it.
- `postStop` must depend on `$machine` alone and succeed when what it
  releases is already gone. It runs once for every `$machine` that
  `seccompPolicy` or `exec` saw, whether the container ran or not.

## `exec`

Instead of `command`, `exec` prints the entrypoint on the host at launch, as
NUL-terminated fields:

- `env:NAME=VALUE`, a variable;
- `arg:WORD`, each word of the argument list (`arg:` is an empty word);
- `file:MODE:PATH` then the content, a file written into the user's home
  before the entrypoint starts.

```nix
flong.sandbox.command = lib.mkForce null;
flong.sandbox.exec = [ "${pkgs.writeShellScript "entrypoint" ''
  printf '%s\0' "env:PROJECT=$(basename "$workspace")" arg:cargo
  for a in "$@"; do printf 'arg:%s\0' "$a"; done
  # Assign first: a failing $(...) inside printf's arguments is ignored.
  token=$(tool-token) || exit
  printf '%s\0' file:0600:/home/alice/.config/tool/token "$token"
''}" ];
```

`exec` is not told the home; it uses the one `user` has in the container's
configuration. A variable the container already sets (`PWD` among them) or
`TINI_*`, a mode past `0777`, a path outside the home or given twice, or any
other output refuses the launch. Files are written following no symlink and
crossing no mount, so they live in the container and go with it.

## Seccomp

The profile's base is `seccomp.tier`:

- **`strict`** (default): what systemd-nspawn allows a container, without
  `@keyring`, `userfaultfd`, `@mount`, `io_uring_*`, `ptrace` and
  `process_vm_*`. node, python, go, cargo, gcc, java and the claude and codex
  CLIs work as under `parity`.
- **`parity`**: exactly what systemd-nspawn allows.
- **`null`**: no allow-list. Warns.

Then `debug` adds `ptrace`; `nestedSandbox` allows user namespaces and
mounts, for Chromium's sandbox or a nested bwrap; `allow` adds names or
systemd `@groups` (`systemd-analyze syscall-filter`); `deny` removes them,
last. A refused call returns `errno`: `EPERM` (default), `EACCES` or
`ENOSYS`. Whatever the tier, the container cannot inject keystrokes into your terminal
(`TIOCSTI` and friends), open audit sockets, or, without `nestedSandbox`,
make namespaces. Filters apply on x86_64, i386 and x32.

To find what a program needs, run it once with `log = true` and read the
kernel log:

```sh
journalctl -k --grep 'type=1326' | grep -o 'syscall=[0-9]*' | sort -u
scmp_sys_resolver -a x86_64 425     # -> io_uring_setup
```

A per-project profile goes in `seccompPolicy`, which prints `allow NAME...`
and `deny NAME...` lines. They are compiled at launch and cached by content.
Keep policy files where only you write, never in the working directory,
which the container can write to:

```nix
flong.agent.seccompPolicy = ''
  policy="$HOME/.config/flong/seccomp/$(basename "$workspace")"
  if [ -f "$policy" ]; then cat "$policy"; fi
'';
```

## Inside a container

- The working directory and binds are at their host paths. The entrypoint
  gets the binds as `$FLONG_BINDS`, one `PATH:ro` or `PATH:rw` per line.
- `user`'s uid and primary gid map to yours, so what it writes to a bind is
  yours. Every other id, root included, comes from your subordinate range,
  and shows on the host as that id. Your host groups do not reach inside.
- No capabilities, `no_new_privs`, and no user namespaces unless
  `seccomp.nestedSandbox`.
- `/nix/store` is read-only; the system is at `/run/current-system`. `/run`
  is read-only once mounts are made. `/sys` is the container's own,
  read-only, and shows its cgroup, so `nproc` honours `limits`.
- Directories missing on the way to a mount point are created. Inside the
  home they belong to `user`; inside a host bind they are created on the
  host, as you.
- `TMPDIR` is `~/tmp`, a 0700 tmpfs, or `/tmp` if a mount covers `~/tmp`.
  `XDG_RUNTIME_DIR` is `/run/user/<uid>`.
- The environment starts empty: `PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`,
  `XDG_RUNTIME_DIR`, `TMPDIR`, `TERM`, `COLORTERM`, `FLONG_BINDS`,
  `container=flong`, then what the container's `/etc/set-environment` sets,
  worked out at evaluation, then `exec`'s. Anything in that file only a shell
  could compute fails evaluation, naming the line. Your tokens and agent
  sockets stay outside.
- On a terminal the container has its own pty. `^]^]^]` kills it.
- The hostname is the container's name. pid 1 is
  [tini](https://github.com/krallin/tini).

## `containers.<name>` options

| option | under flong |
|---|---|
| `config`, `pkgs`, `nixpkgs`, `specialArgs` | Build the rootfs. `config` must declare `user`'s uid and gid; `path` alone is refused. |
| `privateNetwork` | Required. |
| `bindMounts` | Mounted with your access. May not reach flong's state, the user manager's sockets, `/proc`, `/sys/fs/cgroup` or a `protect` path. Devices go in `allowedDevices`. |
| `tmpfs` | Mounted empty, owned by `user`, mode 0755, unless `PATH:OPTIONS` sets `mode=`, `size=`, or `uid=` and `gid=` of `user` or root. |
| `allowedDevices` | Bound read-write, with your own permission on the node. |
| `autoStart`, `extraFlags`, `networkNamespace`, `flake`, `privateUsers`, `additionalCapabilities`, `enableTun` | Refused: there is no nspawn, and no namespace but yours. |
| `hostBridge`, `hostAddress*`, `localAddress*`, `localMacAddress`, `forwardPorts`, `interfaces`, `macvlans`, `extraVeths` | Refused: containers run concurrently. Use `flong.<name>.network`. |
| `ephemeral`, `restartIfChanged`, `timeoutStartSec` | Ignored. |

A refused container option or host fails evaluation. A refused declaration
(an unclean path, a mount twice, a source reaching flong's state, ids past
65535, …) fails building `flong-<name>.zon`, with `flong check`'s reason as
the build log's last line.

## Limitations

- **NixOS only.** flong uses `containers.<name>` and the activation script.
- **The entrypoint is your uid on the host.** An escape reaches what you can.
  [PLAN.md](../PLAN.md) §1 is a uid range per container.
- **Ownership is the map's.** A host file owned outside the map, root
  included, reads as `nobody:nogroup` (all of `/nix/store`). ssh refuses
  NixOS's store-owned `20-systemd-ssh-proxy.conf` for that reason: set
  `programs.ssh.systemd-ssh-proxy.enable = false` in the container.
- **No init.** No units, D-Bus, `systemd.user` services, PAM or socket
  activation. `systemd.tmpfiles.rules` apply when the rootfs is built, except
  boot-only rules and paths under `/dev`, `/run` or `/tmp`.
- **No setuid.** `/run/wrappers` is not mounted; `sudo` and `fusermount` do
  not work. `ping` does, with a `network`, through ICMP echo sockets rather
  than setuid: its `net.ipv4.ping_group_range` spans every gid in the
  container.
- **No Nix.** No daemon, and the store database may miss recent paths. See
  [PLAN.md](../PLAN.md) §3.
- **No symlinks on the way to a mount point.** One ends the launch.
- **No published ports below 1024**, or below
  `net.ipv4.ip_unprivileged_port_start`.
- **One container per published port.** A second with the same
  `forwardPorts` entry fails to start. `hostPorts` has no such limit.
- **DNS is fixed at launch.** Relaunch after the host changes network, unless
  it runs a local resolver (systemd-resolved, dnsmasq).
- **Writes use RAM.** The overlay, `/tmp`, `TMPDIR` and overlays are tmpfs,
  charged to the container's cgroup. Set `limits.MemoryMax`; pasta shares
  the cgroup, so the OOM killer may pick it.
- **Overlays need care.** Inode numbers change as a file is written: do not
  overlay a SQLite database.
- **Not in `machinectl`.** `systemctl --user status flong-sessions.service`
  lists every container's processes; enter one with
  `nsenter --target <pid> --user --preserve-credentials --mount --pid --net --uts --ipc`,
  outside its seccomp filter.
- **A container ends with its launcher**, SIGKILL included; `postStop` still
  runs. `systemctl --user stop flong-sessions.service` ends them all.
- **The cached rootfs is as trustworthy as you.** Anything running as you
  outside a container can change what later containers start from.

## Development

`nix flake check` runs NixOS VM tests of every option, hook ordering,
networking, DNS, lifecycle, terminal and seccomp; builds `flong` and the
seccomp compiler with their unit tests, lint and analysis; and evaluates each
refusal.

Option descriptions live in `src/decl.zig` as doc comments. After changing
one, `nix run .#update-options` rewrites `decl-options.json` and
[declaration.md](declaration.md); `decl-options-fresh` and `reference-fresh`
fail until both are committed.

`nix run .#gate` runs the x86_64 checks through
[nix-fast-build](https://github.com/Mic92/nix-fast-build), skipping what a
binary cache has; `GATE_EVAL_WORKERS` sets the evaluators (default one per
10 GiB of RAM). `nix run .#gate-aarch64` evaluates aarch64's checks without
building. CI builds each check in its own job against the `danielbodart`
Cachix cache. Bump `VERSION` when the option interface breaks.
