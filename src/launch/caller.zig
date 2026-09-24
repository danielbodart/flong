//! launch/caller.zig: the caller and the runtime directory
//! (rootless-wrapper.bash:52-82), for `flong launch DECL.zon`'s prologue
//! (STANDALONE.md, "`flong launch DECL.zon -- ARGS`": the caller, the
//! runtime directory).
//!
//! In the wrapper's order: uid 0 refused; the caller's name from
//! /etc/passwd; primary gid 0 refused; /run/user/$UID a directory the
//! caller owns, or refused. Each refusal is the wrapper's text, said
//! through msg with msg.prog set to the declaration's name by the
//! prologue, so it reads "$name: <text>", and comes back as
//! error.Reported, which the prologue exits 1 with
//! (prologue.exit_refused), as die (:41-44) did.
//!
//!   $UID          getuid(), the real uid, as bash's UID is
//!   GROUPS[0]     getgid(), the real gid, which bash puts first
//!   -d, -O $rt    stat(2) of the path, following symlinks: a directory,
//!                 owned by the effective uid, as test(1)'s -O asks
//!
//! The name is what newuidmap matches /etc/subuid against, so it is read
//! from passwd by uid (USER is the caller's to set), and is the uid's
//! decimal text when passwd gives none (:57-65). It is read by
//! passwd.zig, which reads /etc/passwd as glibc's files module does,
//! where the wrapper's `IFS=: read -r n _ u _` loop read it as bash does
//! (Change, invisible on any passwd NixOS writes): a line with leading
//! blanks, a '#' comment and a "+"/"-" compat entry are skipped, not
//! read; the uid field is a decimal number (so 01000 is uid 1000), where
//! the wrapper compared its text; a line with fewer than four fields is
//! skipped; a last line without a newline is read; and an unreadable
//! /etc/passwd leaves the uid's text, where the wrapper's redirection
//! failed and ended it.
//!
//! The runtime directory is always /run/user/$UID, whatever
//! XDG_RUNTIME_DIR says: the holder's sweeper watches that directory's
//! flong, and `systemctl --user` finds the manager there. One that is not
//! the caller's is refused, since records there make the sweeper run
//! programs (:72-80). The wrapper then exported XDG_RUNTIME_DIR=$rt
//! (:81): the prologue puts it in the commands' environment (cmd.zig's
//! Var) and the launch's.

const std = @import("std");
const sys = @import("sys");
const msg = @import("msg");
const passwd = @import("passwd");

const Allocator = std.mem.Allocator;

/// The wrapper's refusal of uid 0 (:55).
pub const refusing_root = "refusing to run as root: flong runs as the calling user, and root has no subordinate range";

/// The wrapper's refusal of primary gid 0 (:69).
pub const refusing_gid0 = "refusing to run with primary group 0: flong never maps host gid 0 into a session";

/// Who runs the launch, and where its state lives.
pub const Caller = struct {
    /// $UID
    uid: u32,
    /// GROUPS[0]: the caller's primary gid, $mygid (:67)
    gid: u32,
    /// $me: the passwd name, or the uid's decimal text (:59-65)
    name: []const u8,
    /// $rt: /run/user/$UID (:77)
    runtime: [:0]const u8,
    /// $state: $rt/flong (:82)
    state: [:0]const u8,
};

/// The wrapper's :52-82, on this process: its real uid and gid,
/// /etc/passwd, and /run/user/$UID against its effective uid. The strings
/// are `gpa`'s, an arena's.
pub fn get(gpa: Allocator) msg.Error!Caller {
    const uid = sys.getuid();
    if (uid == 0) return msg.refuse(refusing_root, .{});
    const who = try identify(gpa, uid, sys.getgid(), passwd.lookup(gpa, uid));
    const rt = std.fmt.allocPrintSentinel(gpa, "/run/user/{d}", .{uid}, 0) catch return oom();
    try checkRuntime(rt, sys.geteuid(), who.name);
    const state = std.fmt.allocPrintSentinel(gpa, "{s}/flong", .{rt}, 0) catch return oom();
    return .{ .uid = who.uid, .gid = who.gid, .name = who.name, .runtime = rt, .state = state };
}

/// The caller's ids and name.
pub const Who = struct { uid: u32, gid: u32, name: []const u8 };

/// :54-70 on given ids: uid 0 refused, then the name (`name`, what
/// passwd gave for `uid`, or the uid's decimal text in `gpa` when null),
/// then gid 0 refused, in the wrapper's order.
pub fn identify(gpa: Allocator, uid: u32, gid: u32, name: ?[]const u8) msg.Error!Who {
    if (uid == 0) return msg.refuse(refusing_root, .{});
    const me = name orelse (std.fmt.allocPrint(gpa, "{d}", .{uid}) catch return oom());
    if (gid == 0) return msg.refuse(refusing_gid0, .{});
    return .{ .uid = uid, .gid = gid, .name = me };
}

/// `[[ ! -d $rt || ! -O $rt ]]` (:78-80): `rt` is a directory, following
/// symlinks, owned by `euid`, or the refusal that names `name` ($me). A
/// stat that fails is refused the same way, as the test is false then.
pub fn checkRuntime(rt: [:0]const u8, euid: u32, name: []const u8) msg.Error!void {
    const owned = switch (sys.fstatat(sys.AT.FDCWD, rt, 0)) {
        .ok => |st| sys.S.ISDIR(st.mode) and st.uid == euid,
        .err => false,
    };
    if (!owned) return msg.refuse(
        "no runtime directory {s} owned by {s}: run it from a login session, or give {s} a user manager with users.users.{s}.linger = true",
        .{ rt, name, name, name },
    );
}

fn oom() msg.Error {
    return msg.fail(.NOMEM, "malloc", .{});
}
