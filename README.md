<p align="center"><img src="logo.png" alt="flong" width="600"></p>

# flong

Ephemeral rootless containers for [NixOS](https://nixos.org/) that start
**10× faster than Docker**, run with **less privilege by default**, and leave
nothing behind.

> A *flong* is the papier-mâché mould a printer takes from composed type. It is
> made once and casts many identical plates, each used once and discarded.

You declare a container with NixOS's own
[`containers.<name>`](https://search.nixos.org/options?query=containers.%3Cname%3E)
option. flong builds its root filesystem once, then each run gets a fresh
overlay on top, runs your command in it, and throws it away when the command
exits. Everything runs as you, in user namespaces, through
[bubblewrap](https://github.com/containers/bubblewrap). There is no daemon and
no root.

## Why flong

|  | Docker | flong |
|---|---|---|
| **Image** | Pulled or built, stored as layers | None. The container's packages are Nix store paths already on the host |
| **Start time**¹ | ~120 ms, ~200 ms with a network | ~10 ms, ~19 ms with a network |
| **Daemon** | `dockerd`, root's or (rootless) your own | None |
| **Container root** | Host root; your uid in rootless mode | A subordinate id; the user inside is your uid |
| **Files written to the working directory** | The container user's uid, often root; in rootless mode root's are yours and other users' a subordinate id | Yours, whatever user runs inside |
| **Lifetime** | Kept until `docker rm`, unless `--rm` | Always ephemeral: writes are held in memory and gone on exit |
| **Capabilities** | 14 by default; `no_new_privs` off | None; `no_new_privs` on |
| **Seccomp** | Default profile: allows `ptrace` and `process_vm_*` | `strict` profile: also refuses `ptrace` and `process_vm_*` |
| **Per-project policy** | Fixed by `docker run` flags | Hooks decide mounts, seccomp and firewall rules at launch |

¹ Running `true`, medians of 20 launches on the same 24-core desktop
(kernel 6.18): `docker run --rm alpine:3 true` on Docker 29.8, rootful and
rootless alike, and a flong container with the same network choice.

The trade-offs: NixOS only, one process with no init or services, and the
process runs as your uid on the host, so an escape reaches what you can (see
[Limitations](#limitations)).

## Terms

- **container**: one run. A fresh overlay on the rootfs, gone when the
  entrypoint exits.
- **rootfs**: the container's root filesystem, built once from its NixOS
  closure and cached under `$XDG_RUNTIME_DIR/flong`.
- **entrypoint**: the process the container runs, from `command` or `exec`.
- **hooks**: commands run on the host, as you, at fixed points of a launch.

## Example

Add `github:danielbodart/flong` as a flake input and
`flong.nixosModules.default` to your system's modules.

```nix
{ config, pkgs, ... }:
{
  containers.sandbox = {
    privateNetwork = true;           # required; loopback only
    config = { pkgs, ... }: {
      system.stateVersion = "24.05";
      users.users.alice = { isNormalUser = true; uid = 1000; };
      environment.systemPackages = [ pkgs.cargo pkgs.rustc ];
    };
  };

  flong.sandbox = {
    user = "alice";                  # the user inside; mapped to you
    command = [ "cargo" ];           # arguments to `sandbox` are appended
  };

  environment.systemPackages = [ config.flong.sandbox.launcher ];
}
```

`sandbox build` runs `cargo build` in a new container, with the current
directory bind-mounted at the same path as its working directory.

### Network and firewall

`privateNetwork = true` is required, and on its own gives loopback only.
`network` adds user-mode networking through [pasta](https://passt.top). A
`postStart` hook runs before the network is attached, so its firewall rules
apply from the first packet, and the entrypoint has no capability to change
them.

```nix
{ lib, pkgs, ... }:
{
  containers.agent = {
    privateNetwork = true;           # required: a network namespace of its own
    config = { ... }: {
      system.stateVersion = "24.05";
      users.users.alice = { isNormalUser = true; uid = 1000; };
    };
  };

  flong.agent = {
    user = "alice";
    command = [ (lib.getExe pkgs.codex) ];
    network = {
      forwardPorts = "auto";         # publish every port the container listens on
      hostPorts = [ 5432 ];          # host's localhost:5432, reachable inside
    };
    path = [ pkgs.nftables ];
    postStart = [
      [ "${pkgs.writeShellScript "egress" ''
        nsenter --user="$userns" --net="$netns" nft -f ${./egress.nft}
      ''}" ]
    ];
  };
}
```

### Seccomp

Every container runs under the `strict` seccomp profile unless you say
otherwise:

```nix
{
  flong.agent.seccomp = {
    debug = true;                    # allow ptrace, for strace and gdb
    allow = [ "userfaultfd" ];
    deny = [ "@swap" ];
  };
}
```

Set `log = true` to log refused calls instead of failing them, to find what a
program needs. A per-project profile can come from the `seccompPolicy` hook;
see [docs/reference.md](docs/reference.md#seccomp).

## Requirements

- **NixOS** on **Linux 6.13** or later.
- **Subordinate ids**: at least 65536 in `/etc/subuid` and `/etc/subgid`.
  NixOS gives every `isNormalUser` a range.
- **A user manager**. A login session has one; to launch from a service, a
  timer or SSH after logout, set `users.users.<name>.linger = true`.

Evaluation checks the rest (user namespaces, `newuidmap`, bubblewrap 0.12,
systemd 254) and says what is missing.

## Options

All under `flong.<name>`. [docs/declaration.md](docs/declaration.md) has
every field in full; `flong help decl` prints the same.

| option | default | |
|---|---|---|
| `container` | `<name>` | The `containers.<name>` to run. |
| `user` | *required* | The user inside. Mapped to your uid. |
| `command` | `null` | The entrypoint's argument list. |
| `exec` | `null` | Instead of `command`: a hook that prints the entrypoint, its environment and files to put in its home. |
| `network` | `null` | User-mode networking: `forwardPorts`, `hostPorts`, `hostLoopbackToSession`. |
| `seccomp` | `strict` | Profile: `tier`, `debug`, `nestedSandbox`, `allow`, `deny`, `errno`, `log`. |
| `limits` | `{ }` | cgroup limits: `MemoryMax`, `TasksMax`, `CPUQuota`, … |
| `overlays` | `{ }` | Paths given a throwaway writable layer. |
| `masks` | `[ ]` | Paths hidden inside a bind mount. |
| `protect` | `[ ]` | Host paths no mount may reach. |
| `path` | `[ ]` | Packages on `PATH` for hooks. |
| `launcher` | *read-only* | The package whose `bin/<name>` starts a container. |

Mounts known at evaluation go on `containers.<name>` (`bindMounts`, `tmpfs`).
Mounts known only at launch come from hooks.

### Hooks

Each hook is a command, `[ program arg... ]`, run as you, never through a
shell. In launch order:

| hook | runs | a non-zero exit |
|---|---|---|
| `workspace` | first; prints the working directory (default: where you ran it) | refuses the launch |
| `binds` | prints more directories to bind-mount | refuses the launch |
| `guard` | checks the launch is one you meant | refuses the launch |
| `seccompPolicy` | prints per-project seccomp rules | refuses the launch |
| `exec` | prints the entrypoint, instead of `command` | refuses the launch |
| `postStart` | once namespaces exist, before the network and entrypoint | ends the container |
| `postStop` | after the container ends, however it ends | is reported |

The variables each hook sees are in [docs/reference.md](docs/reference.md#hooks).

## Limitations

- **NixOS only.**
- **The entrypoint runs as your uid on the host.** An escape reaches what you
  can.
- **No init.** No systemd units, D-Bus or PAM inside.
- **No setuid.** `sudo` and `ping` do not work inside.
- **No Nix.** `nix build` does not work inside.
- **Writes use RAM.** Set `limits.MemoryMax`.
- **Not in `machinectl`.** Use `systemctl --user status flong-sessions`.

More, with workarounds, in [docs/reference.md](docs/reference.md#limitations).
[DESIGN.md](DESIGN.md) explains how it works and why.

## Development

```console
$ nix flake check      # every test, in NixOS VMs
$ nix run .#gate       # the same, in parallel
$ nix build .#bench    # times launches in a VM
```

Every push to `trunk` that passes is tagged and released as
`<VERSION>.<commit count>.<CI run number>`. Pin by flake input.

## Licence

MIT.
