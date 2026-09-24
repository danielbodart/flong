//! decl.zig: a declaration, the static half of a session, as a type
//! (STANDALONE.md, "The declaration"). The NixOS module renders each
//! `flong.<name>` to a `.zon` file of this shape; `flong check` reads it at
//! build time and `flong launch` at launch, through `parse` here, so the two
//! cannot read it differently.
//!
//! The type is the schema. A field's name is the Nix option's, camelCase and
//! all, with no translation (STANDALONE.md, "Decided": no compatibility
//! layer); its doc comment is the option's description, and the only one:
//! `build/gen_decl_docs.zig` harvests it, and `decl_docs.zig` walks this type
//! into `decl-options.json`, which module.nix builds its options from. A
//! field without a doc comment is a compile error there.
//!
//! What std.zon.parse can refuse, the type says: an unknown field, a missing
//! one, a wrong type, an enum tag that is not one, an integer out of its
//! width. What it cannot, `patterns` and `ranges` on the containing type say,
//! for the schema to carry into Nix, and check.zig to judge; so does a
//! command's being non-empty. A Nix type ZON has no spelling for is a tagged
//! union: `either (enum [ "auto" ]) (listOf ...)` is `.auto` or
//! `.{ .ports = .{ ... } }`, each void field a tag and each other field one
//! of the either's branches.
//!
//! Some fields are not options: `computed` names them. Nix works them out of
//! `containers.<name>` and the closure it builds, and renders them beside the
//! options; a non-Nix config writes them itself.
//!
//! The parser is a trust boundary (STANDALONE.md, "The declaration": any
//! caller can launch any file), so `load` reads at most `max_bytes`, into one
//! arena, and every parse error is a refusal with a line and column, never a
//! panic.

const std = @import("std");
const fd = @import("fd");
const msg = @import("msg");

const Allocator = std.mem.Allocator;

/// A program and its arguments, never read by a shell: the program is run
/// as it is, or looked up on `PATH` when it has no `/`. NUL-terminated,
/// since each word becomes an argv entry as it is. `[:0]const u8` rather
/// than `[]const u8` is also what tells a command from a list of strings
/// (decl_docs.zig).
pub const Command = []const [:0]const u8;

/// One `flong.<name>`.
pub const Declaration = struct {
    /// User inside the container, which everything in the session runs
    /// as.
    ///
    /// Its uid and the gid of its primary group must be declared in the
    /// container's `config`, and the container cannot be declared by
    /// `path`: they name the prepared root's cache and the caller's id
    /// maps, which are needed before anything is prepared. The home is
    /// read at launch from the prepared root's `/etc/passwd`, and a
    /// launch refuses one whose ids disagree. The uid need not be the
    /// caller's: the session's user is mapped onto the caller whatever
    /// its uid.
    user: []const u8,

    /// The payload, as an argument list: the program, then its fixed
    /// arguments. The launcher's own arguments are appended, and it is
    /// exec'd as `user` in the workspace. No element of either list is
    /// read by a shell, so a space, a `;` or a `$` in one is passed as it
    /// is.
    ///
    /// It is exec'd after the container's `/etc/set-environment` has been
    /// sourced, so a bare name is looked up on the container's `PATH` --
    /// its `environment.systemPackages`, the user's `packages` -- and
    /// the payload inherits every variable the container exports. An
    /// absolute path, such as `lib.getExe` of a package, is run as it
    /// is. Anything that needs a script is a package of its own, named
    /// here by `lib.getExe`.
    command: Command,

    /// A command printing the directory to bind into the container at its
    /// own path and start in: `PATH`, bound read-write, or `PATH:ro`,
    /// bound read-only. `null`, the default, runs nothing and takes the
    /// directory the launcher was started in; a consumer that wants a
    /// repository's root asks git for it, with a script printing
    /// `git -C "$PWD" rev-parse --show-toplevel`. Runs on the host
    /// before launch, with the launcher's arguments after its own; a
    /// non-zero exit aborts.
    ///
    /// Runs *before* `guard`, so that the gate can judge the directory
    /// this resolves to rather than re-deriving one of its own.
    ///
    /// Runs as the caller, as every hook does.
    ///
    /// What it prints is resolved with `realpath`, must be a directory,
    /// and is refused if it names a `:` or a newline: a caller's path
    /// travels as `PATH:MODE` lines, which either would make ambiguous.
    /// Later hooks see the path as `$workspace` and the mode as
    /// `$workspace_mode` (`ro` or `rw`). Deciding *which* directory is
    /// allowed is `guard`'s job, not this one's.
    workspace: ?Command = null,

    /// Commands printing more of the caller's directories to bind, one
    /// per line, each at its own path inside the container: `PATH`, bound
    /// read-only, or `PATH:rw`, bound read-write. Their outputs are
    /// concatenated, in order. Empty output binds nothing, and so does
    /// the default, no command.
    ///
    /// Runs after `workspace`, with `$workspace` and `$workspace_mode`
    /// in the environment, so it can answer "what travels with THIS
    /// directory" rather than having to name a fixed set. Runs as the
    /// caller and gets the launcher's arguments after its own, exactly as
    /// `workspace` does; a non-zero exit aborts.
    ///
    /// Every path is resolved with `realpath`, must be a directory, and is
    /// refused if it names a `:` or a newline, as the workspace is.
    /// Deciding *which* directories are allowed is `guard`'s job: it sees
    /// them as `$binds`, one `PATH:ro` or `PATH:rw` per line, with the
    /// mode always spelt out. The payload sees the same list as
    /// `$FLONG_BINDS`, to pass on to an agent's `--add-dir`.
    ///
    /// Read-only is not a boundary on its own -- it stops writes, not
    /// execution -- so it is for directories a session should read rather
    /// than edit, not for making an untrusted one safe.
    binds: []const Command = &.{},

    /// Commands run as the caller before launch, in order, to check that
    /// the launch is one this declaration means to make. A consistency
    /// check, not a gate: the session grants nothing the caller did not
    /// already have, and the caller can run `flong launch` directly with
    /// any declaration. Setting it warns, to say so.
    ///
    /// Runs *after* `workspace` and `binds`, with their answers in its
    /// environment: `$workspace`, absolute and symlink-resolved,
    /// `$workspace_mode`, and `$binds`, one `PATH:ro` or `PATH:rw` per
    /// line. Judge those rather than re-deriving a directory from `$PWD`
    /// -- they are exactly what will be bound, where anything a guard
    /// works out for itself agrees with the mounts only by coincidence.
    ///
    /// Each is a process of its own, with the launcher's arguments after
    /// its own: every one must exit 0 for the launch to go on, the first
    /// that does not refuses it, and nothing a guard sets reaches the
    /// launcher: it judges `$workspace` and cannot change it.
    ///
    /// It runs again when the launcher relaunches itself, which it does
    /// when the prepared root it found was swept before it could lock
    /// it, so a guard that asks a question can ask it twice.
    guard: []const Command = &.{},

    /// Commands run by the launcher as the caller, in order, once per
    /// session, as soon as the session's namespaces exist -- **before**
    /// `network` is attached and **before** the payload starts. The
    /// payload waits for them. `path` is on `PATH`, and each gets the
    /// launcher's arguments after its own.
    ///
    /// `$leader` is the session's pid 1 as seen from the host, `$userns`
    /// the session's user namespace and `$netns` its network namespace,
    /// each a `/proc/<launcher>/fd/<n>` descriptor the launcher holds.
    /// `$machine`, `$uid`, `$gid`, `$home`, `$workspace`,
    /// `$workspace_mode` and `$binds` are in the environment too. The
    /// session's root exists only in its own mount namespace, reached as
    /// `/proc/$leader/root`. The hook enters the session as its root,
    /// with every capability over it and none over the host:
    /// `nsenter --user="$userns" --net="$netns" nft -f ruleset.nft`.
    ///
    /// **The ordering is the contract, and it is the security property.**
    /// Whatever this installs into the namespace is in place before
    /// anything gives it egress: a session's namespace starts with `lo`
    /// up and an empty route table, so until egress exists the workload
    /// has nowhere to go and there is no window to race. flong attaches
    /// `network` only after these return. A consumer that provisions
    /// egress of its own first -- from `guard`, or from the first of
    /// these -- has given the property away without any error.
    ///
    /// A non-zero exit ends the session, and the launcher exits
    /// non-zero.
    ///
    /// Unlike systemd's `ExecStartPost`, the main process is not yet
    /// running: it is held until these and any `network` have finished.
    postStart: []const Command = &.{},

    /// Commands run as the caller after a session ends, in order, to
    /// release whatever `postStart` made outside it. `$machine` is in the
    /// environment, and nothing else is; nothing follows a command's own
    /// arguments.
    ///
    /// They run on two paths: from the launcher once the session has
    /// stopped, and -- for a session whose launcher was SIGKILLed --
    /// from the sweeper in the caller's holder unit, within moments,
    /// where the machine name is all that survives. Each session records
    /// its own `postStop`, so the one belonging to the session is run,
    /// even after a rebuild.
    ///
    /// So each must depend on `$machine` alone and succeed when what it
    /// releases is already gone. `path` is on `PATH`; a non-zero exit is
    /// reported and otherwise ignored, because flong's own release
    /// follows it.
    postStop: []const Command = &.{},

    /// A real network for a `privateNetwork` session, provided by
    /// [pasta](https://passt.top): present or absent, with no `enable` --
    /// `network = { };` is a session that can reach the outside world and
    /// no port on the host.
    ///
    /// pasta rather than a veth, because flong runs many concurrent
    /// sessions from one declaration: a veth needs an address per session,
    /// forwarding, NAT and host firewall rules, and gives the sandbox
    /// packet-level access to spoof with. pasta needs no host interface
    /// and no host configuration, and hands the sandbox sockets rather than
    /// packets.
    ///
    /// Attached after `postStart` returns, never before, which is what
    /// makes the hook's ordering hold. pasta runs as the caller, in the
    /// session's cgroup, and goes with the session.
    ///
    /// Always passed, and not options: `--no-map-gw`, because otherwise
    /// the gateway address reaches the host's loopback; an explicit
    /// `none` for every port class not listed here, because each defaults
    /// to `auto`, which forwards every bound port on the other side; and
    /// `--config-net`.
    ///
    /// DNS goes through pasta as well, and is not an option either. The
    /// session's /etc/resolv.conf is written at launch naming
    /// 169.254.1.1 -- and 100::1, where the host names an IPv6
    /// nameserver -- with the host's `search`, `domain` and `options`
    /// carried over. pasta catches a query sent there and re-sends it
    /// from the host to the host's own first nameserver, so a stub
    /// resolver on the host's loopback answers it. Both read the host's
    /// file once, at launch: a host that moves networks keeps a live
    /// session on the old resolver.
    network: ?Network = null,

    /// Paths mounted as an overlay of `{ target = lower; }`: the lower
    /// directory is readable and every write goes to an upper layer that
    /// dies with the container.
    ///
    /// overlayfs reports changing device and inode numbers as a file is
    /// written, so this must not cover a path holding a sqlite database.
    ///
    /// An overlay below a bind, at any depth, is allowed: a session that
    /// renames its parent on the host only moves where its own writes
    /// land.
    overlays: []const Overlay = &.{},

    /// Paths in the session replaced by an empty node of the same kind
    /// that nobody can read. For carving one file out of a directory a
    /// bind brings in whole.
    ///
    /// USE WITH CARE. Prefer binding only what the session needs to
    /// binding everything and masking the rest:
    ///
    /// - A mask is a denylist. Whatever it does not name is in, so a file
    ///   the host's tool starts keeping beside the masked one next
    ///   release -- a second token, a refresh token -- is visible from
    ///   the day it appears.
    /// - The path must exist when the session starts, or the launch
    ///   fails. A file that is written later, on the host, into a
    ///   directory that is bound through is not masked.
    /// - It masks the file, not the name. A host program that replaces
    ///   the file by renaming a new one over it -- as many write a
    ///   credential -- detaches the mask in every running session, and
    ///   the new file shows through.
    ///
    /// A mask may lie at most one level below the root of a writable
    /// bind: deeper, a session that can write the host directory renames
    /// the masked file's parent, leaves a decoy for the mask, and reads
    /// the file at the new name. A declared writable bind is checked when
    /// the declaration is, and the workspace and `binds` at launch. A
    /// mask below a read-only bind, and a declared `tmpfs` or an overlay
    /// at any depth, is not checked.
    masks: []const []const u8 = &.{},

    /// Host paths no mount of a session may reach: no source may equal,
    /// lie inside or contain one. For a directory whose contents steer
    /// sessions from outside, such as a daemon's control socket.
    ///
    /// The launch protects `/proc`, `/sys/fs/cgroup` and the user
    /// manager's `bus` and `systemd` sockets as well, and the launcher its
    /// own state and the holder's cgroup.
    protect: []const []const u8 = &.{},

    /// Opt-in resource limits for a session, written into its own
    /// cgroup, which the caller's user manager delegates to the
    /// holder unit. Named and spelt as systemd's, and unset means
    /// unlimited, as it does there.
    ///
    /// Only the controllers a user manager is delegated are offered --
    /// memory, pids and cpu -- so there is no `IOWeight`: with no io
    /// controller below `user@.service`, it would have nothing to write
    /// to.
    ///
    /// A session's root, its TMPDIR and every overlay upper layer are
    /// tmpfs, which is RAM: `MemoryMax` makes a payload that fills
    /// them the session's problem rather than the host's.
    limits: Limits = .{},

    /// The session's syscall filter. A tier is an allow-list: the calls
    /// it names are allowed, the rest of systemd's `@known` get
    /// `errno`, and a call outside `@known` gets ENOSYS. It applies on
    /// x86_64, i386 and x32 alike.
    ///
    /// Three fixed filters are stacked behind it and are not options:
    /// the audit mask (`socket(AF_NETLINK, ..., NETLINK_AUDIT)` gets
    /// EAFNOSUPPORT), the tty filter (`ioctl` TIOCSTI, TIOCLINUX,
    /// TIOCSETD and TIOCCONS get EPERM, in every tier and under any
    /// project policy) and, unless `nestedSandbox`, the namespace mask
    /// (clone and unshare with a `CLONE_NEW*` flag, and setns, get
    /// EPERM, and clone3 ENOSYS).
    seccomp: Seccomp = .{},

    /// Commands printing a project's own changes to the `seccomp` filter,
    /// for a policy that is only known at launch. Run as the caller after
    /// `guard`, in order, with the launcher's arguments after their own,
    /// the caller's stdin and stderr, and `$workspace`,
    /// `$workspace_mode`, `$binds` and `$machine` in the environment.
    /// Their outputs are concatenated, and read as lines of `allow X...`
    /// or `deny X...`, where each X is a syscall name or an `@group`.
    /// `#` comments and blank lines are skipped. A non-zero exit refuses
    /// the launch, and so does a line that cannot be read or a name
    /// systemd does not list.
    ///
    /// `$machine` is the session's name, the one `postStart` and
    /// `postStop` see, so anything it approves for them can be staged
    /// per launch rather than per checkout.
    ///
    /// The project's lines apply to the declaration's allow-list: its
    /// allows are added and then its denies removed. The fixed filters
    /// stay, the tty filter included. The result is compiled at launch
    /// and cached under `$XDG_RUNTIME_DIR/flong/seccomp` by the hash of
    /// what is compiled, so a policy already seen costs a hash. Printing
    /// nothing compiles nothing. A relaunch runs them again.
    ///
    /// It needs a tier to act on, and it is a consistency check in the
    /// way `guard` is: the caller can launch with any filter.
    seccompPolicy: []const Command = &.{},

    // ---- computed: not options (see `computed`) ----

    /// The `containers.<name>` declaration this runs: its closure,
    /// `bindMounts`, `tmpfs` and `allowedDevices`, read as option values.
    /// It must set `privateNetwork = true`. Under NixOS it is an option of
    /// its own, written by hand, whose default is the declaration's name;
    /// it also names the cgroup level between the holder and the
    /// sessions.
    container: []const u8,

    /// The container's system closure, the store path the session's root
    /// is prepared from: `containers.<name>.path`.
    closure: []const u8,

    /// The uid `user` has in the container's configuration, which the
    /// caller's id maps and the prepared root's cache are made for. At
    /// most 65535, the container's ids.
    cuid: u32,

    /// The gid of `user`'s primary group in the container's
    /// configuration. At most 65535, as `cuid`.
    cgid: u32,

    /// The first eight hex digits of the sha256 of the cache tool's store
    /// path, which references the prepare program: a change to either is
    /// a different root, so it names a different cache.
    steps8: []const u8,

    /// What the container mounts, from its `bindMounts`, `tmpfs` and
    /// `allowedDevices`, one entry each, in the launcher's words. The
    /// launch sorts them, parents first, so their order does not matter.
    containerMounts: []const ContainerMount = &.{},

    /// The declaration's own name, `<name>` in `flong.<name>`: what every
    /// refusal the launch makes starts with, `<name>: ...`, and the name
    /// of its command.
    name: []const u8,

    /// The program that runs `command` inside the session, as `user`: it
    /// takes the workspace, changes into it, sources the container's
    /// `/etc/set-environment` and execs `command` with the launcher's
    /// arguments after it. module.nix builds it from `command`
    /// (`mkPayload`); the launch hands it to `flong init` as the payload.
    payload: []const u8,

    /// The compiled filter of `seccomp`'s tier, its loosenings, `allow`
    /// and `deny`, installed first; null when `seccomp.tier` is null. A
    /// project's policy (`seccompPolicy`) replaces it at launch with one
    /// compiled from `seccompProject`.
    seccompTierFilter: ?[]const u8 = null,

    /// The fixed filters, compiled, each installed after the tier's in
    /// this order: the audit mask, the tty filter and, unless
    /// `seccomp.nestedSandbox`, the namespace mask.
    seccompFixedFilters: []const []const u8 = &.{},

    /// What a project's policy is compiled against, at launch, by
    /// `flong-seccomp project DUMP NAMES DENY DIR`; null when
    /// `seccompPolicy` is empty, and nothing is compiled.
    seccompProject: ?SeccompProject = null,

    /// Directories put in front of `PATH`, in this order, for the commands
    /// the launch runs as the caller before the session exists --
    /// `workspace`, `binds`, `guard`, `seccompPolicy` -- and in the
    /// environment the launch goes on with, which the hooks start from.
    /// Under NixOS, the `bin` directories of `flong.<name>.path`. Empty,
    /// the default, leaves `PATH` as the caller's.
    commandPath: []const []const u8 = &.{},

    /// The program each `postStart` command is run through: it is given
    /// the command's words and the launcher's arguments, and execs them.
    /// module.nix's hook program, which puts `flong.<name>.path` on `PATH`
    /// first (mkHookProgram). null runs each command as it is.
    postStartProgram: ?[]const u8 = null,

    /// The same for each `postStop` command, which the session's record
    /// keeps whole, program first, for the sweeper to run with `$machine`
    /// alone: module.nix's hook program, which takes the session's name
    /// from its last argument and puts `flong.<name>.path` on `PATH`. A
    /// store path, since the record's program must be one. null runs each
    /// command as it is, and each must then be a store path itself.
    postStopProgram: ?[]const u8 = null,

    /// The fields Nix works out rather than takes as options, in
    /// declaration order: `decl-options.json` lists them with
    /// `nixOption` false, and module.nix generates no option for them.
    /// `container` keeps an option, written by hand in module.nix.
    pub const computed = [_][]const u8{
        "container",       "closure",     "cuid",             "cgid",              "steps8",
        "containerMounts", "name",        "payload",          "seccompTierFilter", "seccompFixedFilters",
        "seccompProject",  "commandPath", "postStartProgram", "postStopProgram",
    };

    /// The strings that must match a pattern (Nix's `strMatching`), by
    /// field; a list's pattern is its elements'.
    pub const patterns = .{ .masks = "/.*", .protect = "/.*" };
};

/// `network`: pasta's ports.
pub const Network = struct {
    /// Ports on the host forwarded into the session, shaped exactly
    /// like `containers.<name>.forwardPorts`, bound on every host
    /// address -- the host's firewall still decides who reaches them.
    /// pasta binds them as the caller, so a port below the host's
    /// `net.ipv4.ip_unprivileged_port_start` is refused.
    ///
    /// A host port is one session's at a time. A second concurrent
    /// session asking for the same one fails to attach its network,
    /// and is ended rather than left running without it.
    ///
    /// `"auto"`: whatever TCP port the session listens on is
    /// published on the host at the same port, while it listens --
    /// a dev server started inside is reached from the host's
    /// browser. A port another session already publishes is not,
    /// and that session is not ended for it.
    forwardPorts: ForwardPorts = .{ .ports = &.{} },

    /// A forwarded connection from the host's loopback arrives on
    /// the session's loopback, rather than from the session's own
    /// address -- pasta's --host-lo-to-ns-lo. A dev server
    /// listening on 127.0.0.1 inside is then reached at
    /// localhost on the host. It also reaches anything else the
    /// session listens on only on its loopback, which is why pasta
    /// no longer does it by default; a connection from anywhere
    /// but the host's loopback is unaffected.
    hostLoopbackToSession: bool = false,

    /// Ports on the host's loopback the session may reach, at the
    /// same port on its own loopback: the database the host is
    /// running, say. TCP and UDP both. Nothing else on the host's
    /// loopback is reachable, the gateway address included.
    hostPorts: []const u16 = &.{},
};

/// `network.forwardPorts`: `.auto`, or `.{ .ports = .{ ... } }`.
pub const ForwardPorts = union(enum) {
    /// Every TCP port the session listens on, while it listens.
    auto,
    /// These ports, and no other.
    ports: []const ForwardPort,
};

/// One of `network.forwardPorts`.
pub const ForwardPort = struct {
    /// The protocol forwarded.
    protocol: Protocol = .tcp,
    /// Port on the host, on every address.
    hostPort: u16,
    /// Port in the session; `hostPort` if null.
    containerPort: ?u16 = null,
};

pub const Protocol = enum { tcp, udp };

/// One of `overlays`: Nix's `{ target = lower; }`, an attribute set, as a
/// list of pairs, since a ZON struct's field names are its type's.
pub const Overlay = struct {
    /// Where the overlay is mounted in the session.
    target: []const u8,
    /// The host directory it shows, read-only, beneath the writes.
    lower: []const u8,

    /// The attribute set's name and value, for decl_docs.zig: the schema
    /// calls a list of these `pathAttrs`.
    pub const attrs = .{ .name = "target", .value = "lower" };
};

/// `limits`: each one unset, the default, is unlimited.
pub const Limits = struct {
    /// `memory.max`: the hard limit.
    MemoryMax: ?MemSize = null,
    /// `memory.high`: the throttling limit.
    MemoryHigh: ?MemSize = null,
    /// `memory.swap.max`.
    MemorySwapMax: ?MemSize = null,
    /// `pids.max`: processes and threads together.
    TasksMax: ?Tasks = null,
    /// `cpu.max`: a share of one CPU, as `N%`; `200%` is two.
    CPUQuota: ?[]const u8 = null,
    /// `cpu.weight`, against the caller's other processes.
    CPUWeight: ?u14 = null,
    /// `memory.oom.group`: an OOM kill takes the whole session
    /// rather than one process of it.
    oomGroup: bool = false,

    pub const patterns = .{ .CPUQuota = "[1-9][0-9]*%" };
    /// Bounds narrower than the type's, inclusive, by field.
    pub const ranges = .{ .CPUWeight = .{ 1, 10000 } };
};

/// A size as systemd writes one, and as the kernel's memparse reads it:
/// `.infinity`, `.{ .bytes = N }` or `.{ .size = "8G" }`. Nix's
/// `either ints.unsigned (strMatching "[0-9]+[KMGT]|infinity")`, split so
/// the parse keeps the number a number. u63 is every Nix integer that is
/// not negative.
pub const MemSize = union(enum) {
    infinity,
    bytes: u63,
    size: []const u8,

    pub const patterns = .{ .size = "[0-9]+[KMGT]" };
};

/// `pids.max`: `.infinity` or `.{ .count = N }`, N at least 1 (Nix's
/// `either ints.positive (enum [ "infinity" ])`).
pub const Tasks = union(enum) {
    infinity,
    count: u63,

    pub const ranges = .{ .count = .{ 1, std.math.maxInt(u63) } };
};

/// `seccomp`: the session's filter.
pub const Seccomp = struct {
    /// `parity` is exactly the allow-list systemd-nspawn installs
    /// for a container. `strict` is parity without `@keyring`,
    /// `userfaultfd`, `@mount`, `io_uring_*`, `ptrace` and
    /// `process_vm_*`, which ordinary tools do without; strace
    /// and gdb need `debug`. `null` installs no allow-list, only
    /// the fixed filters, and warns.
    tier: ?Tier = .strict,
    /// Adds `ptrace`, for strace and gdb. Its reach is the
    /// session's own pid namespace.
    debug: bool = false,
    /// For a payload that sandboxes its own children, such as
    /// Chromium's sandbox, `codex sandbox` or a nested bwrap: the
    /// session may make user namespaces of its own, the namespace
    /// mask goes and `@mount` is allowed. All three are needed
    /// together. The payload still cannot reach the session's
    /// network namespace.
    nestedSandbox: bool = false,
    /// Syscall names or `@groups` added to the tier.
    allow: []const []const u8 = &.{},
    /// Syscall names or `@groups` removed, after the tier, the
    /// loosenings and `allow`, which it overrides.
    deny: []const []const u8 = &.{},
    /// What a call in `@known` that the filter does not allow
    /// returns. ENOSYS makes a program fall back as it would on
    /// an older kernel.
    errno: Errno = .EPERM,
    /// Allows the calls `errno` would refuse and has the kernel
    /// log each (audit `type=1326`, with `syscall=NR`), to learn
    /// a policy. `scmp_sys_resolver -a x86_64 NR` names a number;
    /// the names become `allow` entries or `seccompPolicy` lines.
    /// Not for untrusted payloads, and it warns.
    log: bool = false,

    /// A syscall's name or a systemd group's, as `systemd-analyze
    /// syscall-filter` lists them. The build refuses one it does not
    /// list.
    pub const patterns = .{ .allow = "@?[a-z0-9_-]+", .deny = "@?[a-z0-9_-]+" };
};

pub const Tier = enum { parity, strict };
pub const Errno = enum { EPERM, EACCES, ENOSYS };

/// One of `containerMounts`.
pub const ContainerMount = struct {
    /// `bind_ro` and `bind_rw` are a `bindMounts` entry, `tmpfs` a
    /// `tmpfs` one and `dev` an `allowedDevices` node.
    kind: MountKind,
    /// Where it is mounted in the session: the bind's `mountPoint`, the
    /// tmpfs's path, the device's node.
    dest: []const u8,
    /// What is mounted, for a bind (its `hostPath`, or `mountPoint` when
    /// that is null) and a device (its node); null for a tmpfs.
    src: ?[]const u8 = null,
    /// A tmpfs's octal mode (`0755` when its options give none), or a
    /// device's modifier (`rw`, `rwm`); null for a bind.
    mode: ?[]const u8 = null,
    /// A tmpfs's `size=`, as its options give it; null for none, and for
    /// anything but a tmpfs.
    size: ?[]const u8 = null,
    /// A tmpfs owned by the session's user, rather than root: one with no
    /// options, or with `uid=` and `gid=` naming the user's.
    ownerUser: bool = false,
};

pub const MountKind = enum { bind_ro, bind_rw, dev, tmpfs };

/// `seccompProject`: the arguments of `flong-seccomp project` other than
/// its cache directory, which the launch names. The compiler itself is
/// compiled into flong, never named here.
pub const SeccompProject = struct {
    /// The file of the groups systemd lists, as `systemd-analyze
    /// syscall-filter` prints them: what `@known` and every `@group` in a
    /// project's lines mean.
    dump: []const u8,
    /// The file of the declaration's own names -- its tier, its
    /// loosenings, `allow`, and `deny` as `-name` -- which a project's
    /// lines apply to.
    names: []const u8,
    /// What a call in `@known` the filter does not allow gets: an errno's
    /// number (`1`, `13` or `38`, for `seccomp.errno`), or `log` for
    /// `seccomp.log`.
    deny: []const u8,
};

/// The largest declaration `load` reads. A rendered one is a few
/// kilobytes; the bound is on what a caller can make the launcher allocate.
pub const max_bytes = 1 << 20;

/// Parses ZON `source` into a `Declaration`, in `arena`, which the
/// returned value lives in: it mixes allocated strings with its type's
/// static defaults, so it is freed with the arena, never field by field.
/// `error.ParseZon` leaves the reason, with its line and column, in
/// `diag` (initialized to `.{}`), for `report`; `error.NotZon` is a
/// source `notZon` refuses, and says where and why.
///
/// An unknown field is an error, as a missing required one is: a typo
/// that silently did nothing is what a typed declaration exists to stop.
pub fn parse(arena: Allocator, source: [:0]const u8, diag: ?*std.zon.parse.Diagnostics) error{ OutOfMemory, ParseZon, NotZon }!Declaration {
    if (notZon(source) != null) return error.NotZon;
    // The parser's per-field `inline` switches, over twenty-one fields, pass
    // the default quota of a thousand branches.
    @setEvalBranchQuota(10_000);
    return std.zon.parse.fromSlice(Declaration, arena, source, diag, .{ .free_on_error = false });
}

/// The deepest `.{` a declaration may nest: its own shape needs five
/// (`network.forwardPorts.ports`' elements).
pub const max_depth = 32;

/// What `notZon` refuses, at byte `at` of the source.
pub const NotZon = struct {
    at: usize,
    why: union(enum) {
        /// A token no declaration holds.
        token: std.zig.Token.Tag,
        /// A `{` past `max_depth`.
        deep,
    },
};

/// The first reason `source` cannot be a declaration, found before it is
/// parsed, or null. std.zon.parse parses by Zig's own recursive descent,
/// on the process's stack, as deep as the source nests: a megabyte of
/// `.{`, `(` or `-` would overflow it and end the process with SIGSEGV,
/// where every other bad file gets a line and a column. So what the
/// parser recurses on is bounded first, one token at a time: `{` at most
/// `max_depth` deep, and no token a declaration cannot hold, which is
/// every one but `.{}=,`, a name (`true`, `false` and `null` among them),
/// a string, a number and one `-` before one. A token the tokenizer finds
/// invalid is left to the parser, to say as it does.
pub fn notZon(source: [:0]const u8) ?NotZon {
    var tokens = std.zig.Tokenizer.init(source);
    var depth: usize = 0;
    var prev: std.zig.Token.Tag = .eof;
    while (true) {
        const t = tokens.next();
        switch (t.tag) {
            .eof => return null,
            .l_brace => {
                depth += 1;
                if (depth > max_depth) return .{ .at = t.loc.start, .why = .deep };
            },
            .r_brace => depth -|= 1,
            .minus => if (prev == .minus) return .{ .at = t.loc.start, .why = .{ .token = t.tag } },
            .period,
            .equal,
            .comma,
            .identifier,
            .string_literal,
            .multiline_string_literal_line,
            .char_literal,
            .number_literal,
            .doc_comment,
            .container_doc_comment,
            .invalid,
            .invalid_periodasterisks,
            => {},
            else => return .{ .at = t.loc.start, .why = .{ .token = t.tag } },
        }
        prev = t.tag;
    }
}

/// Reads and parses the declaration at `path`, at most `max_bytes` of
/// it. Every failure is said, the parse's as `path:line:col: why`, one
/// message each, and returned as `error.Reported`.
pub fn load(arena: Allocator, path: [:0]const u8) (msg.Error || error{OutOfMemory})!Declaration {
    const source = try readBounded(arena, path);
    if (notZon(source)) |n| {
        try reportNotZon(arena, path, source, n);
        return error.Reported;
    }
    var diag: std.zon.parse.Diagnostics = .{};
    return parse(arena, source, &diag) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ParseZon => {
            try report(arena, path, &diag);
            return error.Reported;
        },
        // notZon has passed this source above.
        error.NotZon => msg.refuse("{s}: not a declaration", .{path}),
    };
}

/// Says why `notZon` refused `source`, as `path:line:col: why`.
pub fn reportNotZon(arena: Allocator, path: []const u8, source: []const u8, n: NotZon) error{OutOfMemory}!void {
    const before = source[0..n.at];
    const line_start = if (std.mem.lastIndexOfScalar(u8, before, '\n')) |i| i + 1 else 0;
    const loc: std.zig.Ast.Location = .{
        .line = std.mem.count(u8, before, "\n"),
        .column = n.at - line_start,
        .line_start = line_start,
        .line_end = std.mem.indexOfScalarPos(u8, source, n.at, '\n') orelse source.len,
    };
    const Why = struct {
        n: NotZon,
        pub fn format(w: @This(), out: *std.Io.Writer) std.Io.Writer.Error!void {
            switch (w.n.why) {
                .deep => try out.print("nested more than {d} deep", .{max_depth}),
                .token => |tag| {
                    if (tag.lexeme()) |l| try out.print("'{s}'", .{l}) else try out.writeAll(tag.symbol());
                    try out.writeAll(" cannot be in a declaration, which holds only structs and lists of strings, numbers, enum literals, true, false and null");
                },
            }
        }
    };
    try sayAt(arena, path, loc, "", Why{ .n = n });
}

/// `path`'s bytes, NUL-terminated for the parser, refused past
/// `max_bytes`: read in pieces, so a file that never ends (a FIFO,
/// /dev/zero) costs a MiB and not the memory.
fn readBounded(arena: Allocator, path: [:0]const u8) (msg.Error || error{OutOfMemory})![:0]const u8 {
    const f = try msg.check(fd.openFile(fd.cwd, path, .{}, 0), "{s}", .{path});
    defer f.close();
    var buf: std.ArrayList(u8) = .empty;
    while (true) {
        try buf.ensureUnusedCapacity(arena, 64 << 10);
        const room = buf.unusedCapacitySlice();
        const want = @min(room.len, max_bytes + 1 - buf.items.len);
        const n = try msg.check(f.read(room[0..want]), "{s}", .{path});
        if (n == 0) break;
        buf.items.len += n;
        if (buf.items.len > max_bytes) return msg.refuse("{s}: longer than 1 MiB", .{path});
    }
    return buf.toOwnedSliceSentinel(arena, 0);
}

/// Says each error and note in `diag` as `path:line:col: why`, the way
/// the compiler places one, 1-based.
pub fn report(arena: Allocator, path: []const u8, diag: *const std.zon.parse.Diagnostics) error{OutOfMemory}!void {
    var errors = diag.iterateErrors();
    while (errors.next()) |e| {
        try sayAt(arena, path, e.getLocation(diag), "", e.fmtMessage(diag));
        var notes = e.iterateNotes(diag);
        while (notes.next()) |n| try sayAt(arena, path, n.getLocation(diag), "note: ", n.fmtMessage(diag));
    }
}

fn sayAt(arena: Allocator, path: []const u8, loc: std.zig.Ast.Location, kind: []const u8, why: anytype) error{OutOfMemory}!void {
    var text: std.Io.Writer.Allocating = .init(arena);
    text.writer.print("{s}:{d}:{d}: {s}{f}", .{ path, loc.line + 1, loc.column + 1, kind, why }) catch return error.OutOfMemory;
    msg.say("{s}", .{text.written()});
}

// ---- tests ----

const testing = std.testing;

/// Every field set, none to its default, as module.nix would render a
/// busy declaration.
const full =
    \\.{
    \\    .user = "alice",
    \\    .command = .{ "/nix/store/x-hello/bin/hello", "--greeting=hi there" },
    \\    .workspace = .{ "/nix/store/x-root/bin/root", "--git" },
    \\    .binds = .{ .{"/nix/store/x-b1/bin/b1"}, .{ "/nix/store/x-b2/bin/b2", "a" } },
    \\    .guard = .{.{"/nix/store/x-g/bin/g"}},
    \\    .postStart = .{.{"/nix/store/x-s/bin/s"}},
    \\    .postStop = .{.{"/nix/store/x-t/bin/t"}},
    \\    .network = .{
    \\        .forwardPorts = .{ .ports = .{
    \\            .{ .hostPort = 8080, .containerPort = 80 },
    \\            .{ .protocol = .udp, .hostPort = 5353 },
    \\        } },
    \\        .hostLoopbackToSession = true,
    \\        .hostPorts = .{5432},
    \\    },
    \\    .overlays = .{.{ .target = "/home/alice/.state", .lower = "/var/lib/state" }},
    \\    .masks = .{"/home/alice/.cache/tool/token"},
    \\    .protect = .{"/run/frisket"},
    \\    .limits = .{
    \\        .MemoryMax = .{ .size = "8G" },
    \\        .MemoryHigh = .{ .bytes = 4294967296 },
    \\        .MemorySwapMax = .infinity,
    \\        .TasksMax = .{ .count = 4096 },
    \\        .CPUQuota = "400%",
    \\        .CPUWeight = 50,
    \\        .oomGroup = true,
    \\    },
    \\    .seccomp = .{
    \\        .tier = .parity,
    \\        .debug = true,
    \\        .nestedSandbox = true,
    \\        .allow = .{ "@keyring", "userfaultfd" },
    \\        .deny = .{"@swap"},
    \\        .errno = .ENOSYS,
    \\        .log = true,
    \\    },
    \\    .seccompPolicy = .{.{ "/nix/store/x-env/bin/chase-envelope", "approve" }},
    \\    .container = "agent",
    \\    .closure = "/nix/store/x-nixos-system-agent",
    \\    .cuid = 1000,
    \\    .cgid = 100,
    \\    .steps8 = "0123abcd",
    \\    .containerMounts = .{
    \\        .{ .kind = .bind_rw, .dest = "/home/alice/src", .src = "/srv/src" },
    \\        .{ .kind = .tmpfs, .dest = "/scratch", .mode = "1777", .size = "64m" },
    \\        .{ .kind = .dev, .dest = "/dev/fuse", .src = "/dev/fuse", .mode = "rwm" },
    \\    },
    \\    .name = "agent-trusted",
    \\    .payload = "/nix/store/x-payload/bin/flong-payload-agent-trusted",
    \\    .seccompTierFilter = "/nix/store/x-tier/flong-seccomp.bpf",
    \\    .seccompFixedFilters = .{ "/nix/store/x-audit.bpf", "/nix/store/x-tty.bpf" },
    \\    .seccompProject = .{
    \\        .dump = "/nix/store/x-flong-seccomp-groups",
    \\        .names = "/nix/store/x-flong-seccomp-names",
    \\        .deny = "log",
    \\    },
    \\}
;

/// Only what has no default.
const minimal =
    \\.{
    \\    .user = "alice",
    \\    .command = .{"hello"},
    \\    .container = "agent",
    \\    .closure = "/nix/store/x-nixos-system-agent",
    \\    .cuid = 1000,
    \\    .cgid = 100,
    \\    .steps8 = "0123abcd",
    \\    .name = "agent",
    \\    .payload = "/nix/store/x-payload/bin/flong-payload-agent",
    \\}
;

test "a full declaration parses, every field as written" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const d = try parse(arena_state.allocator(), full, null);

    try testing.expectEqualStrings("alice", d.user);
    try testing.expectEqual(2, d.command.len);
    try testing.expectEqualStrings("--greeting=hi there", d.command[1]);
    try testing.expectEqualStrings("--git", d.workspace.?[1]);
    try testing.expectEqual(2, d.binds.len);
    try testing.expectEqualStrings("a", d.binds[1][1]);
    try testing.expectEqualStrings("/nix/store/x-g/bin/g", d.guard[0][0]);
    try testing.expectEqual(1, d.postStart.len);
    try testing.expectEqual(1, d.postStop.len);

    const n = d.network.?;
    const ports = n.forwardPorts.ports;
    try testing.expectEqual(2, ports.len);
    try testing.expectEqual(.tcp, ports[0].protocol);
    try testing.expectEqual(8080, ports[0].hostPort);
    try testing.expectEqual(80, ports[0].containerPort.?);
    try testing.expectEqual(.udp, ports[1].protocol);
    try testing.expectEqual(null, ports[1].containerPort);
    try testing.expect(n.hostLoopbackToSession);
    try testing.expectEqualSlices(u16, &.{5432}, n.hostPorts);

    try testing.expectEqualStrings("/var/lib/state", d.overlays[0].lower);
    try testing.expectEqualStrings("/home/alice/.cache/tool/token", d.masks[0]);
    try testing.expectEqualStrings("/run/frisket", d.protect[0]);

    try testing.expectEqualStrings("8G", d.limits.MemoryMax.?.size);
    try testing.expectEqual(4294967296, d.limits.MemoryHigh.?.bytes);
    try testing.expectEqual(.infinity, d.limits.MemorySwapMax.?);
    try testing.expectEqual(4096, d.limits.TasksMax.?.count);
    try testing.expectEqualStrings("400%", d.limits.CPUQuota.?);
    try testing.expectEqual(50, d.limits.CPUWeight.?);
    try testing.expect(d.limits.oomGroup);

    try testing.expectEqual(.parity, d.seccomp.tier.?);
    try testing.expect(d.seccomp.debug and d.seccomp.nestedSandbox and d.seccomp.log);
    try testing.expectEqualStrings("userfaultfd", d.seccomp.allow[1]);
    try testing.expectEqualStrings("@swap", d.seccomp.deny[0]);
    try testing.expectEqual(.ENOSYS, d.seccomp.errno);
    try testing.expectEqualStrings("approve", d.seccompPolicy[0][1]);

    try testing.expectEqualStrings("agent", d.container);
    try testing.expectEqual(1000, d.cuid);
    try testing.expectEqual(100, d.cgid);
    try testing.expectEqualStrings("0123abcd", d.steps8);
    try testing.expectEqual(3, d.containerMounts.len);
    try testing.expectEqual(.tmpfs, d.containerMounts[1].kind);
    try testing.expectEqual(null, d.containerMounts[1].src);
    try testing.expectEqualStrings("rwm", d.containerMounts[2].mode.?);
}

test "a minimal declaration takes module.nix's defaults" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const d = try parse(arena_state.allocator(), minimal, null);

    try testing.expectEqualStrings("hello", d.command[0]);
    try testing.expectEqual(null, d.workspace);
    try testing.expectEqual(0, d.binds.len + d.guard.len + d.postStart.len + d.postStop.len + d.seccompPolicy.len);
    try testing.expectEqual(null, d.network);
    try testing.expectEqual(0, d.overlays.len + d.masks.len + d.protect.len + d.containerMounts.len);
    try testing.expectEqual(Limits{}, d.limits);
    try testing.expectEqual(null, d.limits.MemoryMax);
    try testing.expect(!d.limits.oomGroup);
    try testing.expectEqual(.strict, d.seccomp.tier.?);
    try testing.expectEqual(.EPERM, d.seccomp.errno);
    try testing.expect(!d.seccomp.debug and !d.seccomp.nestedSandbox and !d.seccomp.log);
    try testing.expectEqual(0, d.seccomp.allow.len + d.seccomp.deny.len);

    // `network = { };` is a network with no ports, and forwardPorts'
    // default is the empty list, not "auto".
    const n = (try parse(arena_state.allocator(), minimal[0 .. minimal.len - 1] ++ "    .network = .{},\n}", null)).network.?;
    try testing.expectEqual(0, n.forwardPorts.ports.len);
    try testing.expect(!n.hostLoopbackToSession);
    const auto = (try parse(arena_state.allocator(), minimal[0 .. minimal.len - 1] ++ "    .network = .{ .forwardPorts = .auto },\n}", null)).network.?;
    try testing.expectEqual(.auto, auto.forwardPorts);
    // tier = null, no allow-list, is said as null.
    const none = try parse(arena_state.allocator(), minimal[0 .. minimal.len - 1] ++ "    .seccomp = .{ .tier = null },\n}", null);
    try testing.expectEqual(null, none.seccomp.tier);
}

/// The first error's message and 1-based line, from parsing `source`.
fn refusal(arena: Allocator, source: [:0]const u8) !struct { line: usize, text: []const u8 } {
    var diag: std.zon.parse.Diagnostics = .{};
    if (parse(arena, source, &diag)) |_| return error.TestUnexpectedResult else |err| try testing.expectEqual(error.ParseZon, err);
    var errors = diag.iterateErrors();
    const e = errors.next().?;
    return .{ .line = e.getLocation(&diag).line + 1, .text = try std.fmt.allocPrint(arena, "{f}", .{e.fmtMessage(&diag)}) };
}

test "an unknown field is refused at its line" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    // A Nix name translated, the way STANDALONE.md forbids.
    const r = try refusal(a, minimal[0 .. minimal.len - 1] ++ "    .post_start = .{},\n}");
    try testing.expectEqual(11, r.line);
    try testing.expectEqualStrings("unexpected field 'post_start'", r.text);

    // And one inside a section.
    const s = try refusal(a,
        \\.{
        \\    .user = "alice",
        \\    .command = .{"hello"},
        \\    .limits = .{
        \\        .IOWeight = 100,
        \\    },
        \\}
    );
    try testing.expectEqual(5, s.line);
    try testing.expectEqualStrings("unexpected field 'IOWeight'", s.text);
}

test "a wrong type is refused at its line" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    // A snippet, as the options took before commands.
    for ([_][]const u8{
        "    .guard = \"test -d $workspace\",\n}",
        "    .seccomp = .{ .tier = .lax },\n}",
        "    .seccomp = .{ .errno = \"EPERM\" },\n}",
        "    .network = .{ .hostPorts = .{65536} },\n}",
        "    .network = .{ .forwardPorts = .all },\n}",
        "    .limits = .{ .MemoryMax = \"8G\" },\n}",
        "    .limits = .{ .oomGroup = 1 },\n}",
        "    .containerMounts = .{.{ .kind = .overlay, .dest = \"/x\" }},\n}",
    }) |line| {
        const r = try refusal(a, try std.mem.concatWithSentinel(a, u8, &.{ minimal[0 .. minimal.len - 1], line }, 0));
        try testing.expectEqual(11, r.line);
    }
}

test "a missing required field is refused" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const r = try refusal(arena_state.allocator(),
        \\.{
        \\    .user = "alice",
        \\}
    );
    try testing.expectEqual(1, r.line);
    try testing.expectEqualStrings("missing required field command", r.text);
}

test "notZon bounds what the parser would recurse on, before it does" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqual(null, notZon(full));
    try testing.expectEqual(null, notZon(minimal));
    // One `-` before a number is ZON, and the parser says what is wrong
    // with it; two is not.
    try testing.expectEqual(null, notZon(".{ .cuid = -1 }"));
    try testing.expectEqual(NotZon{ .at = 12, .why = .{ .token = .minus } }, notZon(".{ .cuid = --1 }").?);
    try testing.expectEqual(NotZon{ .at = 0, .why = .{ .token = .l_paren } }, notZon("(((1)))").?);
    try testing.expectEqual(NotZon{ .at = 11, .why = .{ .token = .keyword_if } }, notZon(".{ .user = if (true) \"a\" else \"b\" }").?);
    try testing.expectEqual(NotZon{ .at = 2, .why = .{ .token = .l_bracket } }, notZon(".{[]u8}").?);
    // `max_depth` of `.{` is enough; one more is refused where it opens.
    const ok = try std.mem.concatWithSentinel(a, u8, &.{ ".{" ** max_depth, "}" ** max_depth }, 0);
    try testing.expectEqual(null, notZon(ok));
    // What would overflow the parser's stack: 100,000 of `.{`, and of
    // `-`, which it recurses on once each.
    const deep = try a.allocSentinel(u8, 200_000, 0);
    for (0..100_000) |i| @memcpy(deep[2 * i ..][0..2], ".{");
    try testing.expectEqual(NotZon{ .at = 2 * max_depth + 1, .why = .deep }, notZon(deep).?);
    try testing.expectError(error.NotZon, parse(a, deep, null));
    const minuses = try a.allocSentinel(u8, 100_001, 0);
    @memset(minuses[0..100_000], '-');
    minuses[100_000] = '1';
    try testing.expectError(error.NotZon, parse(a, minuses, null));
    // Comments and strings are not tokens to it.
    try testing.expectEqual(null, notZon(".{ // (((\n.user = \"(((\" }"));
}

test "load refuses a file that never ends, and one that is not there" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const was = msg.prog;
    msg.prog = "decl-test: planted by decl.zig's test, ignore";
    defer msg.prog = was;
    try testing.expectError(error.Reported, load(a, "/dev/zero"));
    try testing.expectError(error.Reported, load(a, "/nonexistent/flong/agent.zon"));
}
