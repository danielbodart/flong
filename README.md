<p align="center"><img src="logo.png" alt="flong" width="600"></p>

# flong

Ephemeral [systemd-nspawn](https://www.freedesktop.org/software/systemd/man/systemd-nspawn.html)
containers for [NixOS](https://nixos.org/) that start in about 120 ms, run one
foreground process, and leave nothing behind.

> A *flong* is the papier-mâché mould a printer takes from composed type. It is
> made once and casts many identical plates, each used once and discarded.

flong prepares a container's root filesystem once per boot, copies it for each
run, and deletes the copy when the process exits. The container is an ordinary
[`containers.<name>`](https://search.nixos.org/options?query=containers.%3Cname%3E)
declaration; flong replaces only how it starts. Its `container@` unit never
runs.

**Terms.** The **prepared root** is the container's rootfs after its activation
script has run, cached under `/run/flong` per closure. A **session** is one run:
a copy of the prepared root, started by nspawn in its own systemd scope,
registered with machined, and deleted on exit. The **launcher** is the
generated script `flong.<name>.launcher` that starts a session; it runs as
root. The **workspace** is the host directory bind-mounted into the session at
its own path and used as its working directory. The **payload** is the process
`command` names. **Hooks** are the shell options the launcher runs at fixed
points: `workspace`, `binds`, `guard`, `postStart` and `postStop`.

## Examples

Add `github:danielbodart/flong` as a flake input and
`flong.nixosModules.default` to your system's modules.

### A session

Declare the container with NixOS's own option, then name it in `flong`:

```nix
{ pkgs, ... }:
{
  containers.sandbox = {
    bindMounts."/home/alice/.cargo" = {
      hostPath = "/home/alice/.cargo";
      isReadOnly = false;
    };
    config = { pkgs, ... }: {
      system.stateVersion = "24.05";
      users.users.alice = { isNormalUser = true; uid = 1000; };
      environment.systemPackages = [ pkgs.cargo pkgs.rustc ];
    };
  };

  flong.sandbox = {
    user = "alice";                  # uid, gid and home are read from the container
    command = [ "cargo" ];           # the launcher's arguments are appended
    binds = ''                       # more of the caller's directories, read-only unless :rw
      [ -d "$workspace/../shared-crates" ] && printf '%s:rw\n' "$workspace/../shared-crates"
      printf '%s\n' /srv/reference
    '';
  };
}
```

`sudo <launcher> build` runs `cargo build` in the directory it was started
from, bind-mounted into the session, with a sibling
`shared-crates` read-write if there is one and `/srv/reference` read-only.

### A session with a network

`privateNetwork = true` alone gives a session loopback only. `network` adds
user-mode networking through [pasta](https://passt.top): outbound connections,
DNS, published ports, and the host loopback ports you list.

```nix
{ lib, pkgs, ... }:
{
  containers.agent = {
    privateNetwork = true;
    config = { ... }: {
      system.stateVersion = "24.05";
      users.users.alice = { isNormalUser = true; uid = 1000; };
    };
  };

  flong.agent = {
    user = "alice";
    command = [ (lib.getExe pkgs.codex) ];
    network = {
      hostPorts = [ 5432 ];            # the host's 127.0.0.1:5432, at the session's 127.0.0.1:5432
      forwardPorts = [                 # published: host port 8080 on every address -> session port 3000
        { hostPort = 8080; containerPort = 3000; }
      ];
    };
  };
}
```

`network = { };` gives outbound access and no host ports.

### A session with a root hook

Added to the previous example. `postStart` runs as root once the session's
network namespace exists and before it has any route out, so firewall rules
installed there are in place before the payload's first packet.

```nix
{ pkgs, ... }:
{
  flong.agent = {
    path = [ pkgs.nftables ];
    postStart = ''
      nsenter --net="$netns" nft -f ${./egress.nft}
    '';
  };
}
```

## Running the launcher

Run the launcher as root, through sudo, doas, run0, polkit or a unit. Grant
the store path, so the rule changes only when you rebuild:

```nix
{ config, lib, ... }:
{
  security.sudo.extraRules = [{
    users = [ "alice" ];
    commands = [{
      command = lib.getExe config.flong.sandbox.launcher;
      options = [ "NOPASSWD" ];
    }];
  }];
}
```

NOPASSWD is safe when the container grants nothing its caller lacks. When it
grants more (devices, credentials, another user's sockets), use `guard`.

## Options

All under `flong.<name>`. What is known at evaluation is data: `command` is an
argument list, and every mount known then (`bindMounts`, `tmpfs`) belongs on
the `containers.<name>` declaration. Hooks are shell snippets, run under
`set -euo pipefail`, for what is known only at launch. `postStart` and
`postStop` are `lines`, like systemd's: several modules' snippets concatenate,
ordered with `mkBefore` and `mkAfter`.

| option | default | meaning |
|---|---|---|
| `container` | `<name>` | The `containers.<name>` declaration to run. |
| `user` | *required* | Account inside the container that everything in the session runs as. Its uid, gid and home are read from the prepared root's `/etc/passwd`. |
| `command` | *required* | The payload's argument list, e.g. `[ "cargo" ]` or `[ (lib.getExe pkgs.hello) ]`. The launcher's arguments are appended, and it is exec'd as `user` in the workspace, with the container's `PATH` and variables from its `/etc/set-environment`. No element is read by a shell. |
| `workspace` | `pwd` | Prints the directory to bind-mount at its own path and `cd` into: `PATH`, read-write, or `PATH:ro`. |
| `binds` | `""` | Prints more directories to bind-mount, each at its own path, one per line: `PATH`, read-only, or `PATH:rw`. |
| `guard` | `""` | Decides whether the caller may launch. Non-zero exit refuses. |
| `postStart` | `""` | Configures the session once its namespaces exist, before `network` is attached and before the payload starts. Non-zero exit ends the session. |
| `postStop` | `""` | Releases what `postStart` made, after the session ends. |
| `overlays` | `{ }` | `{ target = lower; }`: an overlayfs whose writes go to an upper layer deleted with the session. |
| `network` | `null` | User-mode networking through pasta. Requires `privateNetwork = true`. |
| `network.forwardPorts` | `[ ]` | Published ports, shaped like `containers.<name>.forwardPorts`, bound on every host address. |
| `network.hostPorts` | `[ ]` | Host loopback ports the session reaches at the same port on its own loopback, TCP and UDP. |
| `scopeConfig` | `{ }` | Settings for the session's scope unit, typed as `serviceConfig`, e.g. `MemoryMax = "8G"`. |
| `path` | `[ ]` | Packages on `PATH` for every hook that runs on the host. |
| `launcher` | *read-only* | The generated launcher package. |

[DESIGN.md](DESIGN.md) gives the reasoning behind each hook's privilege and
timing.

### Hooks

In launch order:

| hook | runs as | when | in scope |
|---|---|---|---|
| `workspace` | invoking user (`SUDO_UID` or `PKEXEC_UID`), else root | first | launcher arguments in `"$@"` |
| `binds` | the same | after `workspace` | `"$@"`, `$workspace`, `$workspace_mode` (`ro` or `rw`) |
| `guard` | root, in a subshell | before anything is made | `$workspace`, `$workspace_mode`, `$binds` (one `PATH:ro` or `PATH:rw` per line) |
| `postStart` | root, in a subshell | once the namespaces exist, before `network` and the payload | `$leader` (the session's pid 1), `$netns` (`/proc/$leader/ns/net`), `$machine`, `$root`, `$uid`, `$gid`, `$home`, and the above |
| `postStop` | root | after the session, or from a later launch's sweep | `$machine` only |

A non-zero exit from `workspace`, `binds` or `guard` refuses the launch; from
`postStart` it ends the session; from `postStop` it is reported.

`workspace` and `binds` print paths that are resolved with `realpath`, must be
directories, and may not contain `:` or a newline. A trailing `:ro` or `:rw` is
always the mode.

`postStart` is where rules go that must be in place before the payload has
egress: the payload waits for it, and `network` is attached after it returns.
Without `privateNetwork`, `$netns` is the host's network namespace, and rules
`postStart` installs there apply to the host.

`postStop` must depend on `$machine` alone and succeed when what it releases is
already gone.

### Inside a session

- The workspace and the caller's binds are at their host paths. `command` gets
  the binds as `$FLONG_BINDS`, one `PATH:ro` or `PATH:rw` per line.
- `/nix/store` is read-only; the system closure is at `/run/current-system`.
- `TMPDIR` is `~/tmp`. `XDG_RUNTIME_DIR` is `/run/user/<uid>`, a 0700 tmpfs;
  name it in the declaration's `tmpfs` to change its options.
- The hostname is the container's name. pid 1 is
  [tini](https://github.com/krallin/tini). Nothing runs as root.

## The `containers.<name>` declaration

| option | under flong |
|---|---|
| `config`, `path`, `pkgs`, `nixpkgs`, `specialArgs` | Build the closure. |
| `bindMounts` | Passed to nspawn. Any path works. |
| `extraFlags` | Passed to nspawn, each entry split on whitespace, except `--capability`, `--ambient-capability`, `--private-users` and `-U`, which are refused. |
| `allowedDevices` | `DeviceAllow=` on the scope, with `DevicePolicy=closed`. |
| `tmpfs` | Mounted empty, owned by `user` unless the entry names its own options as `PATH:OPTIONS`. |
| `privateNetwork` | A network namespace with loopback only, or with `flong.<name>.network`, user-mode networking through pasta. |
| `networkNamespace` | The session joins that namespace. |
| `autoStart`, `ephemeral`, `restartIfChanged`, `timeoutStartSec` | Ignored: they configure the `container@` unit. `autoStart = true` warns. |
| `flake`, `privateUsers`, `additionalCapabilities`, `enableTun` | Refused. |
| `hostBridge`, `hostAddress`, `hostAddress6`, `localAddress`, `localAddress6`, `localMacAddress`, `forwardPorts`, `interfaces`, `macvlans`, `extraVeths` | Refused: each is fixed per container, and sessions run concurrently. Use `flong.<name>.network`. |

Refusals are evaluation-time assertions.

## Limitations

[DESIGN.md](DESIGN.md) explains the reasons for each.

- **NixOS only.** flong depends on `containers.<name>` and the NixOS activation
  script.
- **No user namespace.** Session processes run with host uids, so `user` should
  have the invoking user's uid or the workspace will not be writable. nspawn's
  manual says this mode must not be used for untrusted code. See
  [PLAN.md](PLAN.md) §1.
- **No init.** Nothing boots, so no unit starts: no D-Bus, no `systemd.user`
  services, no PAM session, no socket activation. `systemd.tmpfiles.rules` are
  applied when the root is prepared, except boot-only rules and paths under
  `/dev` or `/run`.
- **No setuid wrappers.** `/run/wrappers/bin` is empty, so `sudo`, `ping` and
  `fusermount` are unavailable inside.
- **No Nix daemon.** `nix build` and `nix develop` do not work in a session.
  See [PLAN.md](PLAN.md) §3.
- **DNS is fixed at launch.** A session keeps the host's first nameserver
  and `search` domains from the moment it started. A host with a local stub
  resolver (systemd-resolved, dnsmasq) is unaffected apart from the `search`
  domains; otherwise relaunch after the host changes network.
- **A published port serves one session at a time.** A second concurrent
  session with the same `forwardPorts` entry fails to start. `hostPorts` has no
  such limit.
- **Sessions use RAM.** The session root, `TMPDIR` and overlay upper layers are
  under `/run`. Set `scopeConfig.MemoryMax`.
- **Overlays need care.** The merged directory takes its owner from the lower
  one. overlayfs reports changing device and inode numbers as a file is
  written, so do not overlay a SQLite database.
- **No `machinectl shell`.** Sessions appear in `machinectl list`, but
  `machinectl shell`, `nixos-container login` and `journalctl -M` need the
  container's systemd. Use `nsenter --target <leader> --all`.
- **SIGKILL on the launcher leaves the session running.** Stop it with
  `machinectl terminate <machine>`; the next launch of that container cleans
  up after it.

## Versions

Every push to `trunk` that passes `nix flake check` is tagged and released.
The version is `<VERSION>.<commit count>.<CI run number>`, with a UTC timestamp
as the patch for local builds. Pin by flake input; bump `VERSION` when the
option interface breaks.

## Development

```console
$ nix flake check
```

Runs a NixOS VM test of every option, the hook ordering, networking and DNS,
and session cleanup; evaluates each refusal; and shellchecks the version
script.

## Licence

MIT.
