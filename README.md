<p align="center"><img src="logo.png" alt="flong" width="600"></p>

# flong

Ephemeral rootless containers for [NixOS](https://nixos.org/) that start in
about 15 ms, run one foreground process as the user who started them, and
leave nothing behind.

> A *flong* is the papier-mâché mould a printer takes from composed type. It is
> made once and casts many identical plates, each used once and discarded.

flong prepares a container's root filesystem once, lays a throwaway overlay
over it for each run, and ends the run when the process exits. Nothing runs as
root apart from the setuid `newuidmap` and `newgidmap` that write a session's
id maps: the launcher, the hooks, the network and the session all run as the
caller, in [bubblewrap](https://github.com/containers/bubblewrap) and user
namespaces the caller owns. The container is an ordinary
[`containers.<name>`](https://search.nixos.org/options?query=containers.%3Cname%3E)
declaration; flong replaces only how it starts. Its `container@` unit never
runs.

In a NixOS VM (4 cores, kernel 6.18.51), a warm launch of `true` takes 15 ms,
25 ms with a network and a firewall hook, and 160 ms when the root must be
prepared first.

**Terms.** The **prepared root** is the container's rootfs after its activation
script has run, built once per closure and caller in the caller's own user
namespace and cached under `$XDG_RUNTIME_DIR/flong`. A **session** is one run:
an overlay on the prepared root whose writes are held in memory, started by
bubblewrap in its own cgroup under the caller's user manager, and gone when
it exits. The **launcher** is `flong.<name>.launcher`, a package whose
`bin/<name>` is a link to `flong`, which starts a session from
`/etc/flong/<name>.zon`, the declaration as the module renders it, as
`flong launch <name> -- ARGS` does; the caller runs it directly, and it
refuses root. `flong list` names every declaration and its file. The **workspace** is the host directory bind-mounted into the session at
its own path and used as its working directory. The **payload** is the process
`command` names. **Hooks** are the commands the launcher runs as the
caller at fixed points: `workspace`, `binds`, `guard`, `seccompPolicy`,
`postStart` and `postStop`.

## Examples

Add `github:danielbodart/flong` as a flake input and
`flong.nixosModules.default` to your system's modules.

### A session

Declare the container with NixOS's own option, then name it in `flong`:

```nix
{ pkgs, ... }:
{
  containers.sandbox = {
    privateNetwork = true;           # loopback only; a session never shares the host's network
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
    user = "alice";                  # the account inside; everything runs as it
    command = [ "cargo" ];           # the launcher's arguments are appended
    binds = [                        # commands printing more directories, read-only unless :rw
      [ "${pkgs.writeShellScript "binds" ''
        if [ -d "$workspace/../shared-crates" ]; then printf '%s:rw\n' "$workspace/../shared-crates"; fi
        printf '%s\n' /srv/reference
      ''}" ]
    ];
  };
}
```

`<launcher> build` runs `cargo build` in the directory it was started from,
bind-mounted into the session, with a sibling `shared-crates` read-write if
there is one and `/srv/reference` read-only.

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

### A session with a firewall hook

Added to the previous example. `postStart` runs as the caller once the
session's namespaces exist and before its network has any route out, so
firewall rules installed there are in place before the payload's first packet.
`nsenter --user --net` enters the session as its root, with every capability
over its network namespace and none over the host's.

```nix
{ pkgs, ... }:
{
  flong.agent = {
    path = [ pkgs.nftables ];
    postStart = [
      [ "${pkgs.writeShellScript "egress" ''
        nsenter --user="$userns" --net="$netns" nft -f ${./egress.nft}
      ''}" ]
    ];
  };
}
```

The payload cannot undo the rules: it runs in a user namespace nested inside
the one that owns the network namespace, with no capability over either. nft
loads its kernel modules on demand from a user namespace; a host that turns
module autoloading off lists them in `boot.kernelModules`.

### A session with a syscall filter

Every session runs under a seccomp allow-list, the `strict` tier, unless you
say otherwise. `seccomp` shapes that list for the declaration. The names are
syscalls or systemd's `@groups` (`systemd-analyze syscall-filter` lists them).

```nix
{
  flong.agent.seccomp = {
    tier = "strict";                 # the default: nspawn's list without @keyring, userfaultfd,
                                     # @mount, io_uring_*, ptrace and process_vm_*
    debug = true;                    # adds ptrace, so strace and gdb work inside
    allow = [ "userfaultfd" ];       # added to the tier
    deny = [ "@swap" "@reboot" ];    # removed last, whatever added them
    errno = "ENOSYS";                # what a refused call returns; EPERM by default
  };
}
```

To find out what a program needs, run it once with `log = true`: refused
calls are allowed and logged instead of failing. Then name the numbers:

```sh
journalctl -k --grep 'type=1326' | grep -o 'syscall=[0-9]*' | sort -u
scmp_sys_resolver -a x86_64 425     # -> io_uring_setup
```

The names go into `allow`. `log` is for learning a policy with a payload you
trust, and it warns.

A policy that differs by project goes in `seccompPolicy`. It runs as you at
each launch, sees `$workspace`, and prints `allow NAME...` and
`deny NAME...` lines. flong compiles them onto the declaration's list and
caches the result, so a policy it has seen costs only a hash:

```nix
{
  flong.agent.seccompPolicy = ''
    # One file per project, kept where only you write: never read it from the
    # workspace, which the session can write to widen its own next launch.
    policy="$HOME/.config/flong/seccomp/$(basename "$workspace")"
    if [ -f "$policy" ]; then cat "$policy"; fi
  '';
}
```

```
# ~/.config/flong/seccomp/my-project
allow io_uring_setup io_uring_enter io_uring_register
deny @swap
```

A line flong cannot read, or a name systemd does not list, refuses the launch
and says why. The fixed filters stay whatever a policy says, including
the one against injecting input into your terminal.

## Running the launcher

Run the launcher as yourself. There is no sudo rule to write, and a launcher
run as root refuses to start. It needs:

- **A subordinate id range** of at least 65536 ids in `/etc/subuid` and
  `/etc/subgid`. NixOS gives every `isNormalUser` one; otherwise set
  `users.users.<name>.autoSubUidGidRange = true` or `subUidRanges` and
  `subGidRanges`. The container's other users, root included, are ids from
  this range.
- **`newuidmap` and `newgidmap`**, the setuid wrappers NixOS installs with
  `security.shadow`, which write that range into the session's maps.
- **A user manager**, for `/run/user/<uid>` and the `flong-sessions` unit
  every session's cgroup lives under. A login session has one. For a launch
  from a service, a timer or an SSH command after logout, set
  `users.users.<name>.linger = true`.

```nix
{
  users.users.alice = {
    isNormalUser = true;             # a subordinate range by default
    linger = true;                   # a user manager without a login
  };
}
```

Evaluation checks the host: user namespaces allowed, the `newuidmap` wrappers
present, bubblewrap 0.12 and systemd 254 or later. The launcher checks the
rest at launch, and says which is missing.

flong needs Linux 6.13 or later: its mount helper gives overlayfs its layers
by descriptor (6.13), enters the session's namespaces through the leader's
pidfd (6.11) and finds a mount's parent with `statmount` (6.8). Nothing
asserts it; on an older kernel a launch fails loudly at the first call the
kernel lacks. [The kernel floor](DESIGN.md#the-kernel-floor) lists every call
and its release.

A launcher has the caller's privilege and no more. The caller holds full
capability over a session's mounts and namespaces from the host, and owns its
prepared root and its records, as they own their `~/.bashrc`. So the session
grants nothing the caller lacks, and `guard` is a check the declaration makes
on its own launch, not a gate: the caller can run `flong launch` directly with
any declaration file. Setting `guard` warns, to say so. The boundary is
between the payload and the caller.

The launcher exits with the payload's status, or 128+n when a signal killed
the payload. It exits 125 when the payload never ran: `flong launch` refused
the spec it built, `postStart` failed, or the network could not be attached.
It exits 1 when it refused before building the spec (the declaration, the
caller, the workspace, the maps), or `workspace`, `binds`, `guard` or
`seccompPolicy` failed, and 2 for a usage error or a name with no
declaration. Its message says which. When its prepared root is swept from
under it, it runs itself again, with the same arguments.

## Options

All under `flong.<name>`. What is known at evaluation is data: `command` is an
argument list, and every mount known then (`bindMounts`, `tmpfs`) belongs on
the `containers.<name>` declaration. Hooks are commands, for what is known
only at launch: each an argument list, `[ program arg... ]`, run as the
caller with the launcher's arguments after its own, and never read by a
shell. A hook that wants a shell names a script, `pkgs.writeShellScript`.
Every hook but `workspace` is a list of commands, run in order: several
modules' lists concatenate, ordered with `mkBefore` and `mkAfter`.
`workspace` is one command, or `null` for the directory the launcher starts
in. Each declaration is also written, as data, to `/etc/flong/<name>.zon`.

| option | default | meaning |
|---|---|---|
| `container` | `<name>` | The `containers.<name>` declaration to run. |
| `user` | *required* | Account inside the container that everything in the session runs as. Its uid and its primary group's gid must be declared in the container's `config`; its home is read from the prepared root's `/etc/passwd`. It is mapped onto the caller whatever its uid. Both must be at most 65535. |
| `command` | *required* | The payload's argument list, e.g. `[ "cargo" ]` or `[ (lib.getExe pkgs.hello) ]`. The launcher's arguments are appended, and it is exec'd as `user` in the workspace, with the container's `PATH` and variables from its `/etc/set-environment`. No element is read by a shell. |
| `workspace` | `null` | A command printing the directory to bind-mount at its own path and `cd` into: `PATH`, read-write, or `PATH:ro`. `null` is the directory the launcher starts in. |
| `binds` | `[ ]` | Commands printing more directories to bind-mount, each at its own path, one per line: `PATH`, read-only, or `PATH:rw`. Their outputs are concatenated. |
| `guard` | `[ ]` | Commands checking that the launch is one the declaration means to make. Each must exit 0; the first that does not refuses. A check, not a gate; setting it warns. |
| `seccompPolicy` | `[ ]` | Commands printing a project's `allow NAME...` and `deny NAME...` lines for the syscall filter, concatenated, compiled at launch and cached by content. Non-zero exit refuses. Needs a `seccomp.tier`. |
| `postStart` | `[ ]` | Commands configuring the session once its namespaces exist, before `network` is attached and before the payload starts. The first non-zero exit ends the session. |
| `postStop` | `[ ]` | Commands releasing what `postStart` made, after the session ends, with `$machine` and no arguments. |
| `overlays` | `{ }` | `{ target = lower; }`: an overlayfs whose writes go to an upper layer that goes with the session. |
| `masks` | `[ ]` | Paths replaced by an empty node nobody can read, to carve a file out of a bound directory. **Use with care**: it is a denylist, the path must exist at launch, a file renamed over a masked one on the host shows through, and a mask two or more levels below the root of a writable bind is refused. Bind only what is needed where you can. |
| `network` | `null` | User-mode networking through pasta, run as the caller. |
| `network.forwardPorts` | `[ ]` | Published ports, shaped like `containers.<name>.forwardPorts`, bound on every host address; or `"auto"`, every TCP port the session listens on, while it does. A host port below `net.ipv4.ip_unprivileged_port_start` is refused. |
| `network.hostLoopbackToSession` | `false` | A forwarded connection from the host's loopback arrives on the session's loopback: a dev server on 127.0.0.1 inside is reached at localhost. |
| `network.hostPorts` | `[ ]` | Host loopback ports the session reaches at the same port on its own loopback, TCP and UDP. |
| `limits` | `{ }` | Opt-in resource limits, written into the session's cgroup: `MemoryMax`, `MemoryHigh`, `MemorySwapMax`, `TasksMax`, `CPUQuota`, `CPUWeight`, named as systemd's, and `oomGroup`. Unset is unlimited, bounded only by what bounds the caller. |
| `seccomp.tier` | `"strict"` | The syscall allow-list. `parity` is exactly what systemd-nspawn allows a container. `strict` is parity without `@keyring`, `userfaultfd`, `@mount`, `io_uring_*`, `ptrace` and `process_vm_*`. `null` is no allow-list, and warns. |
| `seccomp.debug` | `false` | Adds `ptrace`, for strace and gdb, within the session. |
| `seccomp.nestedSandbox` | `false` | Lets the payload make user namespaces and mounts of its own, for Chromium's sandbox, `codex sandbox` or a nested bwrap. It still cannot touch the session's network namespace. |
| `seccomp.allow`, `seccomp.deny` | `[ ]` | Syscall names or `@groups` added to the tier, then removed. |
| `seccomp.errno` | `"EPERM"` | What a known call outside the filter returns: `EPERM`, `EACCES` or `ENOSYS`. |
| `seccomp.log` | `false` | Allows and logs what the filter would refuse, to learn a policy. Warns. |
| `protect` | `[ ]` | Host paths no mount of a session may equal, lie inside or contain, such as a daemon's control socket directory. flong's own state, the user manager's sockets, `/proc` and `/sys/fs/cgroup` are always protected. |
| `path` | `[ ]` | Packages on `PATH` for every hook. |
| `launcher` | *read-only* | The declaration's command: a package whose `bin/<name>` is a link to `flong`. |

`scopeConfig` is refused: a session has no scope unit, and `limits` holds what
a user cgroup can enforce.

[DESIGN.md](DESIGN.md) gives the reasoning behind each hook's timing.

### Hooks

Every hook runs as the caller. In launch order:

| hook | when | in scope |
|---|---|---|
| `workspace` | first | launcher arguments in `"$@"` |
| `binds` | after `workspace` | `"$@"`, `$workspace`, `$workspace_mode` (`ro` or `rw`) |
| `guard` | before anything is made, in a subshell | `"$@"`, `$workspace`, `$workspace_mode`, `$binds` (one `PATH:ro` or `PATH:rw` per line) |
| `seccompPolicy` | after `guard` | the above, and `$machine` |
| `postStart` | once the namespaces exist, before `network` and the payload | `$leader` (the session's pid 1 on the host), `$userns` and `$netns` (the session's user and network namespaces, as descriptors the launcher holds), `$machine`, `$uid`, `$gid`, `$home`, and the above |
| `postStop` | after the session, or from the sweeper when the launcher was killed | `$machine` only |

A non-zero exit from `workspace`, `binds`, `guard` or `seccompPolicy` refuses
the launch, and the launcher exits 1; from `postStart` it ends the session
before the payload runs, and the launcher exits 125; from `postStop` it is
reported.

`workspace` and `binds` print paths that are resolved with `realpath`, must be
directories, and may not contain `:` or a newline. A trailing `:ro` or `:rw` is
always the mode.

`postStart` is where rules go that must be in place before the payload has
egress: the payload waits for it, and `network` is attached after it returns.
`nsenter --user="$userns" --net="$netns"` runs a tool as the session's root. A
hook that enters the mount namespace also enters the pid namespace, or
`/proc/self` does not resolve. Anything a hook starts runs in the session's
cgroup and is killed with it.

`postStop` must depend on `$machine` alone and succeed when what it releases is
already gone.

### Inside a session

- The workspace and the caller's binds are at their host paths. `command` gets
  the binds as `$FLONG_BINDS`, one `PATH:ro` or `PATH:rw` per line.
- `user` is the caller on the host: its uid maps onto the caller's uid and its
  primary gid onto the caller's primary gid, so what it writes in the
  workspace is the caller's. Every other id of the container, root included,
  is an id from the caller's subordinate range. Supplementary groups come from
  the container's `/etc/group`; the caller's host groups do not reach it.
- The payload holds no capabilities, runs with `no_new_privs`, and cannot make
  user namespaces of its own unless `seccomp.nestedSandbox` is set.
- The syscall filter is the `seccomp` tier, `strict` by default, on x86_64,
  i386 and x32. Behind every tier, and not options: `TIOCSTI`, `TIOCLINUX`,
  `TIOCSETD` and `TIOCCONS` are refused, so the payload cannot type into the
  caller's terminal; netlink audit sockets are refused; and, unless
  `nestedSandbox`, so are new namespaces.
- `/nix/store` is read-only; the system closure is at `/run/current-system`.
  `/run` is read-only once the session's mounts are made. `/sys` is the
  session's own, read-only, and shows its cgroup, so `nproc` and runtimes
  honour `limits`.
- A directory missing on the way to a mount point is made for the session. On
  the session's own filesystem it is gone with the session, and inside the
  user's home it is owned by the user, so a bind at `~/.cache/tool/data` leaves
  `~/.cache/tool` writable. Inside a host bind it is made as the caller, and
  stays on the host.
- `TMPDIR` is `~/tmp`, a 0700 tmpfs, unless a bind or a declared mount
  covers it, when it is `/tmp`, a fresh 1777 tmpfs. `XDG_RUNTIME_DIR` is `/run/user/<uid>`, a 0700
  tmpfs.
- The environment is built from nothing: `PATH`, `HOME`, `USER`, `LOGNAME`,
  `SHELL`, `XDG_RUNTIME_DIR`, `TMPDIR`, `TERM`, `COLORTERM`, `FLONG_BINDS` and
  `container=flong`, then the container's `/etc/set-environment`. The caller's
  tokens and agent sockets stay outside.
- On a terminal the session has a pty of its own. `^]^]^]` kills it.
- The hostname is the container's name. pid 1 is
  [tini](https://github.com/krallin/tini).

## The `containers.<name>` declaration

| option | under flong |
|---|---|
| `config`, `pkgs`, `nixpkgs`, `specialArgs` | Build the closure. The container must be declared by `config`, which declares `user`'s uid and gid; one declared by `path` alone is refused. |
| `privateNetwork` | Required. A network namespace with loopback only, or with `flong.<name>.network`, user-mode networking through pasta. |
| `bindMounts` | Mounted by the launcher. The source is opened with the caller's access, and may not reach flong's state, the user manager's sockets, `/proc`, `/sys/fs/cgroup` or a `protect` path. A device under `/dev` belongs in `allowedDevices`. |
| `tmpfs` | Mounted empty. An entry without options is `user`'s, mode 0755. `PATH:OPTIONS` may give `mode=`, `size=`, and `uid=` with `gid=` of `user` or root; without them it is root's. Any other option is refused. |
| `allowedDevices` | Each node bound read-write, with modifier `rw` or `rwm`. Access is the caller's own permission on the node, such as a logind ACL. |
| `autoStart`, `extraFlags`, `networkNamespace`, `flake`, `privateUsers`, `additionalCapabilities`, `enableTun` | Refused. `extraFlags` are nspawn's, and there is no nspawn. A namespace something else built is not the caller's to join. |
| `hostBridge`, `hostAddress`, `hostAddress6`, `localAddress`, `localAddress6`, `localMacAddress`, `forwardPorts`, `interfaces`, `macvlans`, `extraVeths` | Refused: each is fixed per container, and sessions run concurrently. Use `flong.<name>.network`. |
| `ephemeral`, `restartIfChanged`, `timeoutStartSec` | Ignored: they configure the `container@` unit. |

A refusal of a container option or of the host is an evaluation-time
assertion. A refusal of what the declaration says -- a path that is not
clean, a destination mounted twice, a source that reaches flong's state or
a protected path, a device, a mask too deep below a writable bind, seccomp
settings with no tier, ids past 65535 -- is `flong check`'s, which judges
`/etc/flong/<name>.zon` as that file is built: `nixos-rebuild` fails
building `flong-<name>.zon`, and the build log's last lines are
`flong check: /nix/store/…-flong-<name>.zon: flong.<name> …`, one line a
refusal.

## Limitations

[DESIGN.md](DESIGN.md) explains the reasons for each.

- **NixOS only.** flong depends on `containers.<name>` and the NixOS activation
  script.
- **The payload is the caller on the host.** Every session maps `user` onto
  the caller's own uid, so a payload that escapes its namespaces reaches what
  the caller can reach. See [PLAN.md](PLAN.md) §1.
- **Ownership inside is the map's.** A host file whose owner is outside the
  session's map, root included, reads as `nobody:nogroup`: all of
  `/nix/store`, for one. ssh refuses NixOS's store-owned include of `20-systemd-ssh-proxy.conf`
  for that reason; set `programs.ssh.systemd-ssh-proxy.enable = false` in the
  container. A file the container's root owns is owned on the host by a
  subordinate id. The session's `/` is the user's, so the payload can make
  top-level entries in its own session.
- **No init.** Nothing boots, so no unit starts: no D-Bus, no `systemd.user`
  services, no PAM session, no socket activation. `systemd.tmpfiles.rules` are
  applied when the root is prepared, except boot-only rules and paths under
  `/dev`, `/run` or `/tmp`.
- **No setuid wrappers.** `/run/wrappers` is not mounted, and `no_new_privs`
  would defeat a setuid binary anyway, so `sudo`, `ping` and `fusermount` are
  unavailable inside.
- **No Nix.** `nix build` and `nix develop` do not work in a session: there is
  no daemon, and the read-only store database can miss paths registered since
  its last checkpoint. See [PLAN.md](PLAN.md) §3.
- **No symlinks on the way to a mount point.** A symlink anywhere on the path
  to a mount's destination ends the launch, rather than be followed.
- **Host ports below 1024 cannot be published.** pasta binds them as the
  caller; `forwardPorts` below `net.ipv4.ip_unprivileged_port_start` are
  refused at evaluation.
- **DNS is fixed at launch.** A session keeps the host's first nameserver
  and `search` domains from the moment it started. A host with a local stub
  resolver (systemd-resolved, dnsmasq) is unaffected apart from the `search`
  domains; otherwise relaunch after the host changes network.
- **A published port serves one session at a time.** A second concurrent
  session with the same `forwardPorts` entry fails to start. `hostPorts` has no
  such limit.
- **Sessions use RAM.** The overlay's writes, `/tmp`, `TMPDIR` and overlay
  upper layers are tmpfs, charged to the session's cgroup. Set
  `limits.MemoryMax`. pasta shares that cgroup, so the kernel's OOM killer may
  pick it over the payload.
- **Overlays need care.** The merged directory takes its owner from the lower
  one. overlayfs reports changing device and inode numbers as a file is
  written, so do not overlay a SQLite database.
- **Sessions are not machines.** They do not appear in `machinectl`, and
  `machinectl shell` and `journalctl -M` do not reach them. `systemctl --user
  status flong-sessions.service` lists every session's processes; enter one
  with `nsenter --target <pid> --user --preserve-credentials --mount --pid
  --net --uts --ipc`, outside its syscall filter.
- **A session ends with its launcher.** Killing the launcher, SIGKILL
  included, ends its session, and the sweeper in `flong-sessions.service`
  runs its `postStop`. `systemctl --user stop flong-sessions.service` ends
  every session.
- **The prepared root is as trustworthy as the caller.** It and the session
  records are the caller's files, so anything running as the caller outside a
  session can change what later sessions start from.

## Versions

Every push to `trunk` that passes `nix flake check` is tagged and released.
The version is `<VERSION>.<commit count>.<CI run number>`, with a UTC timestamp
as the patch for local builds. Pin by flake input; bump `VERSION` when the
option interface breaks.

## Development

```console
$ nix flake check
```

Runs NixOS VM tests of every option, the hook ordering, networking and DNS,
the launcher's lifecycle and terminal, and each seccomp tier's live filters;
builds the launcher (`flong`, whose subcommands are `launch`, `init` and
`sweeper`), the seccomp compiler and the tests' probes and filter dumper in
Zig, with their unit and property tests, lint and analysis; evaluates each
refusal; and shellchecks the version script.
`nix build .#bench` times launches in a VM.

```console
$ nix run .#gate
$ nix run .#gate-aarch64
```

`gate` runs the same x86_64 checks through
[nix-fast-build](https://github.com/Mic92/nix-fast-build): parallel evaluators,
each check built as soon as it evaluates, and those a binary cache already has
skipped. It exits non-zero if any check fails to evaluate or build; its
arguments go to nix-fast-build, and `GATE_EVAL_WORKERS` sets the evaluators
(6, at up to about 4.6 GB each). `gate-aarch64` evaluates aarch64's checks
without building them. CI builds each check in its own job, `nix build
.#checks.x86_64-linux.<name>`, against the `danielbodart` Cachix cache.

## Licence

MIT.
