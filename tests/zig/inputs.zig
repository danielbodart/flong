//! inputs.zig: hostile inputs for the sweep's readers, built from a list of
//! tokens (DESIGN.md, "Tests": fuzzing). A token picks a piece that means
//! something to the reader (a key, a separator, a NUL, a number at a
//! limit, a run past a buffer) or a plain byte, so random lists reach the
//! readers' edges far more often than random bytes do, and minish's
//! shrinking of the list shrinks the input. fuzz.zig uses them.

const std = @import("std");

/// Appends the pieces `tokens` pick from `table` into `buf`, as far as it
/// holds them.
fn build(comptime table: []const []const u8, tokens: []const u16, buf: []u8) []u8 {
    var n: usize = 0;
    for (tokens) |t| {
        const piece = table[t % table.len];
        const take = @min(piece.len, buf.len - n);
        @memcpy(buf[n..][0..take], piece[0..take]);
        n += take;
        if (n == buf.len) break;
    }
    return buf[0..n];
}

/// Appends `piece` to `buf` at `n.*`, as far as it holds.
fn put(buf: []u8, n: *usize, piece: []const u8) void {
    const take = @min(piece.len, buf.len - n.*);
    @memcpy(buf[n.*..][0..take], piece[0..take]);
    n.* += take;
}

/// The token at `i.*`, then the next; 0 past the end.
fn nextToken(tokens: []const u16, i: *usize) u16 {
    const v = if (i.* < tokens.len) tokens[i.*] else 0;
    i.* += 1;
    return v;
}

const long_a = "a" ** 4090;
const oversize = "b" ** 8300;

/// A record (record.parse, the C's parse_record). Half the lists (an even
/// first token) build its lines in order, each key present or not, a blank
/// line before it or not, its value made of pieces of values, the last
/// newline there or not, so a good share parse and the rest fail one rule
/// at a time; the others are free pieces, which rarely make a record.
pub fn record(tokens: []const u16, buf: []u8) []u8 {
    if (tokens.len > 0 and tokens[0] % 2 == 0) return recordLines(tokens[1..], buf);
    return build(&.{
        "poststop=",            "cgroup=",                       "leader=",                                      "\n",
        "\n",                   "\n",                            "/",                                            "a",
        "1",                    "0",                             ":",                                            "-",
        "+",                    " ",                             "\x00",                                         "/sys/fs/cgroup",
        "/nix/store/",          "2147483647",                    "2147483648",                                   "18446744073709551615",
        "18446744073709551616", "9",                             "..",                                           "=",
        "leader=1:1\n",         "cgroup=/sys/fs/cgroup/h/c/m\n", "poststop=/nix/store/x\n",                      long_a,
        oversize,               "leader=01:1\n",                 "leader=1:+1\n",                                "x=y\n",
        "\t",                   "leader=4294967297:1\n",         "cgroup=\n",                                    "\r",
        "\x1e",                 "\x1f",                          "poststop=/nix/store/x\x1fa\x1e/nix/store/y\n",
    }, tokens, buf);
}

fn recordLines(tokens: []const u16, buf: []u8) []u8 {
    const keys = [_][]const u8{ "poststop=", "cgroup=", "leader=" };
    const paths = [_][]const u8{ "/nix/store/x", "/sys/fs/cgroup/h/c/m", "/", "a", "..", "", " ", ":", "\x00", long_a, "\x1e", "\x1f" };
    const leaders = [_][]const u8{ "1", ":", "12", "0", "2147483647", "2147483648", "18446744073709551615", "18446744073709551616", "+", " ", "01", "x" };
    var n: usize = 0;
    var i: usize = 0;
    for (keys, 0..) |key, k| {
        const t = nextToken(tokens, &i);
        // poststop= and leader= are there two times in three, cgroup=
        // fifteen in sixteen.
        if (if (k == 1) t % 16 == 15 else t % 3 == 0) continue;
        if (t % 5 == 4) put(buf, &n, "\n");
        put(buf, &n, key);
        var pieces = 1 + (t >> 4) % 3;
        while (pieces > 0) : (pieces -= 1) {
            const v = nextToken(tokens, &i);
            put(buf, &n, if (k == 2) leaders[v % leaders.len] else paths[v % paths.len]);
        }
        if (k != 2 or t % 7 != 6) put(buf, &n, "\n");
    }
    return buf[0..n];
}

/// poststop='s value (record.words, over its commands): store paths, words,
/// both separators, a NUL, and a run past PATH_MAX, so commands of one and
/// of many words, empty ones and ones too long all come up.
pub fn poststopList(tokens: []const u16, buf: []u8) []u8 {
    return build(&.{
        "/nix/store/x", "\x1e", "\x1f", "\x1f", "\x1e", "a", "", "--", "..", "x y", "\x00", long_a, "/", "=", "\n",
    }, tokens, buf);
}

/// A machine name, then a cgroup path, for cgroup.sessionForm: the first
/// token picks the machine.
pub fn sessionForm(tokens: []const u16, machine_buf: []u8, path_buf: []u8) struct { []u8, []u8 } {
    const machines = [_][]const u8{ "m", "demo-1", ".x", "", "a" ** 129, "c", "m\x00x", "h" };
    const m = if (tokens.len > 0) machines[tokens[0] % machines.len] else "m";
    @memcpy(machine_buf[0..m.len], m);
    const rest = if (tokens.len > 0) tokens[1..] else tokens;
    // Half the lists (an even second token) are two to six components
    // under the cgroup root, one in four a bad one, the last the machine
    // or not, so the form's own checks are what refuses them.
    if (rest.len > 0 and rest[0] % 2 == 0) {
        const good = [_][]const u8{ "h", "c", "m", "demo-1", "user.slice" };
        const bad = [_][]const u8{ ".", "..", "", ".c", "a" ** 130, "x\x00" };
        var n: usize = 0;
        put(path_buf, &n, "/sys/fs/cgroup");
        const comps = rest[1..@min(rest.len, 3 + (rest[0] >> 1) % 5)];
        for (comps) |t| {
            put(path_buf, &n, "/");
            put(path_buf, &n, if (t % 4 == 0) bad[(t >> 2) % bad.len] else good[(t >> 2) % good.len]);
        }
        if ((rest[0] >> 4) % 2 == 0) {
            put(path_buf, &n, "/");
            put(path_buf, &n, m);
        }
        return .{ machine_buf[0..m.len], path_buf[0..n] };
    }
    const path = build(&.{
        "/sys/fs/cgroup", "/",        "h",          "c",                    "m",  ".", "..", "demo-1",
        "\x00",           "a" ** 130, "user.slice", "/sys/fs/cgroup/h/c/m", "//", "-", "x/", ".c",
    }, rest, path_buf);
    return .{ machine_buf[0..m.len], path };
}

/// A read of cgroup.events (cgroup.populated).
pub fn events(tokens: []const u16, buf: []u8) []u8 {
    return build(&.{ "populated ", "0", "1", "\n", "\x00", "frozen 0\n", "populated", " ", "x" }, tokens, buf);
}

/// A read of /proc/self/cgroup (cgroup.ownFrom).
pub fn ownCgroup(tokens: []const u16, buf: []u8) []u8 {
    return build(&.{ "0::", "1:name=systemd:", "/", "\n", "\x00", "x", "user.slice", "0:", ":" }, tokens, buf);
}

/// A read of /proc/<pid>/stat (proc.statStarttime).
/// A piece is also a whole stat up to field 22's start, so a good share
/// have one.
pub fn stat(tokens: []const u16, buf: []u8) []u8 {
    return build(&.{ "(", ")", " ", " ", " ", "1", "S", "\x00", "-5", "18446744073709551616", "x", "4242", "\n", "+", "\t", "1 (x) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 ", "7" }, tokens, buf);
}

/// An inotify event's name (record.closedInode).
/// Half the lists (an even first token) are '#' and up to four pieces,
/// one in four not a digit, so a good share name an inode.
pub fn inodeName(tokens: []const u16, buf: []u8) []u8 {
    if (tokens.len > 0 and tokens[0] % 2 == 0) {
        const digits = [_][]const u8{ "1", "0", "9", "42", "18446744073709551615" };
        const other = [_][]const u8{ " ", "+", "-", "18446744073709551616", "x", "\x00" };
        var n: usize = 0;
        put(buf, &n, "#");
        for (tokens[1..@min(tokens.len, 2 + (tokens[0] >> 1) % 4)]) |t|
            put(buf, &n, if (t % 4 == 0) other[(t >> 2) % other.len] else digits[(t >> 2) % digits.len]);
        return buf[0..n];
    }
    return build(&.{ "#", "1", "0", "9", " ", "+", "-", "\x00", "x", "18446744073709551616", "18446744073709551615", "\t" }, tokens, buf);
}

/// One read of an inotify descriptor (record.batch, fd.InotifyEvents):
/// events of every mask that matters, each name a closed_inode input, with
/// lengths that fit, fall short, overrun the buffer, or are 0.
pub fn inotify(tokens: []const u16, buf: []align(4) u8) []u8 {
    const masks = [_]u32{ 0x8, 0x4000, 0x8000, 0, 0x10, 0x8 | 0x4000 };
    const names = [_][]const u8{ "#12", "#", "demo", "#-1", "#18446744073709551616", "#7\x00junk", "" };
    const lens = [_]u32{ 0, 16, 3, 255, 0xffff_ffff, 32 };
    var n: usize = 0;
    var i: usize = 0;
    while (i + 2 < tokens.len and n + 16 <= buf.len) : (i += 3) {
        const len = lens[tokens[i + 2] % lens.len];
        const hdr = [4]u32{ 1, masks[tokens[i] % masks.len], 0, len };
        @memcpy(buf[n..][0..16], std.mem.asBytes(&hdr));
        n += 16;
        const name = names[tokens[i + 1] % names.len];
        const room = @min(@as(usize, len), buf.len - n);
        @memset(buf[n..][0..room], 0);
        @memcpy(buf[n..][0..@min(name.len, room)], name[0..@min(name.len, room)]);
        n += room;
        // A truncated read: stop at some byte of this event.
        if (tokens[i] % 17 == 16) {
            n -= @min(n, tokens[i + 1] % 16);
            break;
        }
    }
    return buf[0..n];
}

/// A read of /proc/self/mountinfo (cgroup.mountinfo, the C's
/// cg_check_nsdelegate). Half the lists (an even first token) are lines,
/// each "id parent dev root POINT options [optional] SEP FSTYPE source
/// SUPER", its point /sys/fs/cgroup two times in three, its separator,
/// file system and superblock options drawn so that cgroup2 with
/// nsdelegate, without it, another file system and a line cut short are
/// each common, and the last such line decides; the others are free
/// pieces.
pub fn mountinfo(tokens: []const u16, buf: []u8) []u8 {
    if (tokens.len > 0 and tokens[0] % 2 == 0) {
        const points = [_][]const u8{ "/sys/fs/cgroup", "/sys/fs/cgroup", "/", "/sys/fs/cgroup/x", "/sys/fs/cgroup ", "" };
        const optional = [_][]const u8{ "", " shared:4", " master:1 shared:9", " -", " - -" };
        const seps = [_][]const u8{ " - ", " - ", " - ", "  - ", " -", "- ", " -  " };
        const fstypes = [_][]const u8{ "cgroup2", "cgroup2", "cgroup", "tmpfs", "cgroup2x", "", " cgroup2" };
        const supers = [_][]const u8{
            "rw,nsdelegate,memory_recursiveprot", "rw,nsdelegate", "nsdelegate", "rw",          "rw,nsdelegatex",
            "rw,xnsdelegate",                     ",,nsdelegate,", "",           " nsdelegate", "rw,nsdelegate\x00",
        };
        var n: usize = 0;
        var i: usize = 1;
        while (i + 4 < tokens.len) : (i += 5) {
            put(buf, &n, "29 23 0:26 / ");
            put(buf, &n, points[tokens[i] % points.len]);
            put(buf, &n, " rw,nosuid,nodev,noexec,relatime");
            put(buf, &n, optional[tokens[i + 1] % optional.len]);
            put(buf, &n, seps[tokens[i + 2] % seps.len]);
            put(buf, &n, fstypes[tokens[i + 3] % fstypes.len]);
            // The source, or the line cut before it.
            if (tokens[i + 4] % 9 == 8) {
                put(buf, &n, "\n");
                continue;
            }
            put(buf, &n, " cgroup2 ");
            put(buf, &n, supers[(tokens[i + 4] >> 4) % supers.len]);
            put(buf, &n, if (tokens[i + 4] % 13 == 12) "" else "\n");
        }
        return buf[0..n];
    }
    return build(&.{
        "29 23 0:26 / /sys/fs/cgroup rw shared:4 - cgroup2 cgroup2 rw,nsdelegate\n",
        "30 23 0:27 / /sys/fs/cgroup rw - tmpfs tmpfs rw\n",
        "/sys/fs/cgroup",
        " ",
        " - ",
        "-",
        "cgroup2",
        "nsdelegate",
        ",",
        "\n",
        "\x00",
        "1",
        "rw",
        "tmpfs",
        long_a,
        "\t",
        "  ",
        "cgroup",
    }, tokens, buf);
}

/// What every declaration must have, as decl.zig's `minimal` has it, but
/// its closing brace.
const decl_head =
    \\.{ .user = "u", .command = .{"true"}, .container = "box",
    \\  .closure = "/nix/store/x-box", .cuid = 1000, .cgid = 100, .steps8 = "0123abcd",
    \\  .payload = "/nix/store/x-payload/bin/flong-payload-box",
    \\
;

/// A declaration (decl.parse, then check.validate). Half the lists (an
/// even first token) build one: the required fields, then up to four of
/// the lines below, most of which parse, each reaching one of flong
/// check's refusals or an edge of one, and some of which do not, one rule
/// at a time (an unknown field, a wrong type, a field given twice when two
/// lines share one). The others are free pieces of ZON, which rarely
/// parse.
pub fn declaration(tokens: []const u16, buf: []u8) []u8 {
    if (tokens.len > 0 and tokens[0] % 2 == 0) {
        const lines = [_][]const u8{
            ".masks = .{ \"/srv/b\", \"/srv/b/x/y\" },",
            ".masks = .{ \"/w/x/y/z\", \"/other/one\", \"/t/a/b\", \"\", \"a\", \"/\" },",
            ".masks = .{\"/" ++ long_a ++ "\"},",
            ".protect = .{ \"/srv/p/\", \"/\", \"/run/user/1000\", \"//a\" },",
            ".protect = .{\"/srv\"},",
            ".overlays = .{.{ .target = \"/srv/b\", .lower = \"/var/run/user/1/bus\" }},",
            ".overlays = .{ .{ .target = \"/o\", .lower = \"/srv/p/q\" }, .{ .target = \"/o\", .lower = \"\" } },",
            ".containerMounts = .{ .{ .kind = .bind_rw, .dest = \"/srv/b\", .src = \"/h//w\" }, .{ .kind = .bind_ro, .dest = \"/w/x\" }, .{ .kind = .bind_rw, .dest = \"/w\", .src = \"/h\" } },",
            ".containerMounts = .{ .{ .kind = .dev, .dest = \"/srv/null\", .mode = \"r\" }, .{ .kind = .dev, .dest = \"/dev/null\" }, .{ .kind = .bind_ro, .dest = \"/snd\", .src = \"/dev/snd\" } },",
            ".containerMounts = .{ .{ .kind = .tmpfs, .dest = \"/t\" }, .{ .kind = .bind_rw, .dest = \"/\", .src = \"/\" }, .{ .kind = .bind_ro, .dest = \"/p\", .src = \"/proc/1\" } },",
            ".containerMounts = .{.{ .kind = .bind_rw, .dest = \"/other\", .src = \"/srv/b\" }},",
            ".seccomp = .{ .tier = null, .allow = .{\"Ptrace\"}, .deny = .{ \"@swap\", \"@\" }, .log = true },",
            ".seccomp = .{ .tier = .parity, .errno = .ENOSYS, .allow = .{ \"@keyring\", \"io_uring-x\" } },",
            ".seccompPolicy = .{ .{\"/p\"}, .{} },",
            ".guard = .{ .{}, .{ \"/g\", \"a b\" } },",
            ".workspace = .{},",
            ".workspace = null,",
            ".limits = .{ .CPUWeight = 0, .TasksMax = .{ .count = 0 }, .CPUQuota = \"0%\", .MemoryMax = .{ .size = \"8g\" } },",
            ".limits = .{ .CPUWeight = 10000, .TasksMax = .infinity, .CPUQuota = \"1%\", .MemoryHigh = .{ .bytes = 9223372036854775807 } },",
            ".network = .{ .forwardPorts = .auto, .hostPorts = .{ 0, 65535 } },",
            ".network = .{ .forwardPorts = .{ .ports = .{.{ .protocol = .udp, .hostPort = 1 }} } },",
            ".postStop = .{.{\"/s\"}},",
            ".seccompTierFilter = \"/nix/store/x-tier.bpf\", .seccompFixedFilters = .{ \"/a\", \"/b\" },",
            ".seccompProject = .{ .dump = \"/d\", .names = \"/n\", .deny = \"1\" },",
            ".cuid = 70000,",
            ".post_start = .{},",
            ".guard = \"true\",",
            ".cuid = -1,",
            ".limits = .{ .IOWeight = 1 },",
            ".masks = .{ \"\\x00\", \"/a\\n/b\" },",
        };
        // Its name, a subcommand's one time in four.
        const names = [_][]const u8{ ".name = \"box\",\n", ".name = \"a\",\n", ".name = \"box-2\",\n", ".name = \"check\",\n" };
        var n: usize = 0;
        put(buf, &n, decl_head);
        var i: usize = 1;
        put(buf, &n, names[nextToken(tokens, &i) % names.len]);
        const count = nextToken(tokens, &i) % 5;
        for (0..count) |_| {
            put(buf, &n, lines[nextToken(tokens, &i) % lines.len]);
            put(buf, &n, "\n");
        }
        put(buf, &n, "}");
        return buf[0..n];
    }
    return build(&.{
        ".{",                  "}",                                                    "=",           ",",
        ".user = ",            "\"u\"",                                                ".command = ", ".{\"x\"}",
        ".masks = ",           "null",                                                 ".infinity",   "0",
        "65536",               "-",                                                    "\"/\"",       "\"..\"",
        "//",                  "\n",                                                   "(",           "\\\\x\n",
        "@\"a\"",              "'a'",                                                  "0x10",        "\"\\x00\"",
        ".{ .ports = ",        ".cuid = 1",                                            ".cgid = 1",   ".container = \"c\"",
        ".closure = \"/c\"",   ".steps8 = \"s\"",                                      ".",           "\"",
        ".containerMounts = ", ".{ .kind = .bind_rw, .dest = \"/a\", .src = \"/a\" }", long_a,        "if",
    }, tokens, buf);
}
