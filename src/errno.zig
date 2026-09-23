//! errno.zig: an errno's text and name as glibc gives them, strerror(3) and
//! strerrorname_np(3), for the programs that link no libc and for messages
//! that must stay byte-identical to the C's (ZIG.md, quirk 18).
//!
//! The table is glibc 2.42's for 0-134, taken from the locked nixpkgs'
//! glibc; test-libc (tests/zig/libc_errno.zig) holds it equal to glibc's
//! own for every number from 0 to 4096. It runs to 134, not 133: glibc 2.42
//! added EFTYPE there, which Linux never returns. Anything beyond, and the
//! two holes, 41 and 58, read as glibc reads them: "Unknown error N", with
//! no name. The numbers are the generic Linux ones, which x86_64 and aarch64
//! share (MIPS, Alpha, SPARC and PA-RISC differ, and flong builds for none).

const std = @import("std");
const sys = @import("sys");

/// The longest text `describe` can return: "Unknown error " and a u16.
pub const max_len = blk: {
    var n: usize = unknown.len + 5;
    for (table) |t| {
        if (t[1]) |t_text| n = @max(n, t_text.len);
    }
    break :blk n;
};

const unknown = "Unknown error ";

/// glibc's text for `e`, or null where glibc says "Unknown error N".
pub fn text(e: sys.E) ?[]const u8 {
    const n = @intFromEnum(e);
    return if (n < table.len) table[n][1] else null;
}

/// glibc's name for `e` ("EPERM"; "0" for 0, as strerrorname_np), or null
/// where glibc has none.
pub fn name(e: sys.E) ?[]const u8 {
    const n = @intFromEnum(e);
    return if (n < table.len) table[n][0] else null;
}

/// strerror(e): the text, or "Unknown error N" written into `buf`.
pub fn describe(e: sys.E, buf: *[max_len]u8) []const u8 {
    if (text(e)) |t| return t;
    @memcpy(buf[0..unknown.len], unknown);
    const digits = std.fmt.printInt(buf[unknown.len..], @intFromEnum(e), 10, .lower, .{});
    return buf[0 .. unknown.len + digits];
}

// { strerrorname_np(n), strerror(n) } for n = 0..134, from glibc 2.42.
const table = [_]struct { ?[]const u8, ?[]const u8 }{
    .{ "0", "Success" }, // 0
    .{ "EPERM", "Operation not permitted" }, // 1
    .{ "ENOENT", "No such file or directory" }, // 2
    .{ "ESRCH", "No such process" }, // 3
    .{ "EINTR", "Interrupted system call" }, // 4
    .{ "EIO", "Input/output error" }, // 5
    .{ "ENXIO", "No such device or address" }, // 6
    .{ "E2BIG", "Argument list too long" }, // 7
    .{ "ENOEXEC", "Exec format error" }, // 8
    .{ "EBADF", "Bad file descriptor" }, // 9
    .{ "ECHILD", "No child processes" }, // 10
    .{ "EAGAIN", "Resource temporarily unavailable" }, // 11
    .{ "ENOMEM", "Cannot allocate memory" }, // 12
    .{ "EACCES", "Permission denied" }, // 13
    .{ "EFAULT", "Bad address" }, // 14
    .{ "ENOTBLK", "Block device required" }, // 15
    .{ "EBUSY", "Device or resource busy" }, // 16
    .{ "EEXIST", "File exists" }, // 17
    .{ "EXDEV", "Invalid cross-device link" }, // 18
    .{ "ENODEV", "No such device" }, // 19
    .{ "ENOTDIR", "Not a directory" }, // 20
    .{ "EISDIR", "Is a directory" }, // 21
    .{ "EINVAL", "Invalid argument" }, // 22
    .{ "ENFILE", "Too many open files in system" }, // 23
    .{ "EMFILE", "Too many open files" }, // 24
    .{ "ENOTTY", "Inappropriate ioctl for device" }, // 25
    .{ "ETXTBSY", "Text file busy" }, // 26
    .{ "EFBIG", "File too large" }, // 27
    .{ "ENOSPC", "No space left on device" }, // 28
    .{ "ESPIPE", "Illegal seek" }, // 29
    .{ "EROFS", "Read-only file system" }, // 30
    .{ "EMLINK", "Too many links" }, // 31
    .{ "EPIPE", "Broken pipe" }, // 32
    .{ "EDOM", "Numerical argument out of domain" }, // 33
    .{ "ERANGE", "Numerical result out of range" }, // 34
    .{ "EDEADLK", "Resource deadlock avoided" }, // 35
    .{ "ENAMETOOLONG", "File name too long" }, // 36
    .{ "ENOLCK", "No locks available" }, // 37
    .{ "ENOSYS", "Function not implemented" }, // 38
    .{ "ENOTEMPTY", "Directory not empty" }, // 39
    .{ "ELOOP", "Too many levels of symbolic links" }, // 40
    .{ null, null }, // 41
    .{ "ENOMSG", "No message of desired type" }, // 42
    .{ "EIDRM", "Identifier removed" }, // 43
    .{ "ECHRNG", "Channel number out of range" }, // 44
    .{ "EL2NSYNC", "Level 2 not synchronized" }, // 45
    .{ "EL3HLT", "Level 3 halted" }, // 46
    .{ "EL3RST", "Level 3 reset" }, // 47
    .{ "ELNRNG", "Link number out of range" }, // 48
    .{ "EUNATCH", "Protocol driver not attached" }, // 49
    .{ "ENOCSI", "No CSI structure available" }, // 50
    .{ "EL2HLT", "Level 2 halted" }, // 51
    .{ "EBADE", "Invalid exchange" }, // 52
    .{ "EBADR", "Invalid request descriptor" }, // 53
    .{ "EXFULL", "Exchange full" }, // 54
    .{ "ENOANO", "No anode" }, // 55
    .{ "EBADRQC", "Invalid request code" }, // 56
    .{ "EBADSLT", "Invalid slot" }, // 57
    .{ null, null }, // 58
    .{ "EBFONT", "Bad font file format" }, // 59
    .{ "ENOSTR", "Device not a stream" }, // 60
    .{ "ENODATA", "No data available" }, // 61
    .{ "ETIME", "Timer expired" }, // 62
    .{ "ENOSR", "Out of streams resources" }, // 63
    .{ "ENONET", "Machine is not on the network" }, // 64
    .{ "ENOPKG", "Package not installed" }, // 65
    .{ "EREMOTE", "Object is remote" }, // 66
    .{ "ENOLINK", "Link has been severed" }, // 67
    .{ "EADV", "Advertise error" }, // 68
    .{ "ESRMNT", "Srmount error" }, // 69
    .{ "ECOMM", "Communication error on send" }, // 70
    .{ "EPROTO", "Protocol error" }, // 71
    .{ "EMULTIHOP", "Multihop attempted" }, // 72
    .{ "EDOTDOT", "RFS specific error" }, // 73
    .{ "EBADMSG", "Bad message" }, // 74
    .{ "EOVERFLOW", "Value too large for defined data type" }, // 75
    .{ "ENOTUNIQ", "Name not unique on network" }, // 76
    .{ "EBADFD", "File descriptor in bad state" }, // 77
    .{ "EREMCHG", "Remote address changed" }, // 78
    .{ "ELIBACC", "Can not access a needed shared library" }, // 79
    .{ "ELIBBAD", "Accessing a corrupted shared library" }, // 80
    .{ "ELIBSCN", ".lib section in a.out corrupted" }, // 81
    .{ "ELIBMAX", "Attempting to link in too many shared libraries" }, // 82
    .{ "ELIBEXEC", "Cannot exec a shared library directly" }, // 83
    .{ "EILSEQ", "Invalid or incomplete multibyte or wide character" }, // 84
    .{ "ERESTART", "Interrupted system call should be restarted" }, // 85
    .{ "ESTRPIPE", "Streams pipe error" }, // 86
    .{ "EUSERS", "Too many users" }, // 87
    .{ "ENOTSOCK", "Socket operation on non-socket" }, // 88
    .{ "EDESTADDRREQ", "Destination address required" }, // 89
    .{ "EMSGSIZE", "Message too long" }, // 90
    .{ "EPROTOTYPE", "Protocol wrong type for socket" }, // 91
    .{ "ENOPROTOOPT", "Protocol not available" }, // 92
    .{ "EPROTONOSUPPORT", "Protocol not supported" }, // 93
    .{ "ESOCKTNOSUPPORT", "Socket type not supported" }, // 94
    .{ "EOPNOTSUPP", "Operation not supported" }, // 95
    .{ "EPFNOSUPPORT", "Protocol family not supported" }, // 96
    .{ "EAFNOSUPPORT", "Address family not supported by protocol" }, // 97
    .{ "EADDRINUSE", "Address already in use" }, // 98
    .{ "EADDRNOTAVAIL", "Cannot assign requested address" }, // 99
    .{ "ENETDOWN", "Network is down" }, // 100
    .{ "ENETUNREACH", "Network is unreachable" }, // 101
    .{ "ENETRESET", "Network dropped connection on reset" }, // 102
    .{ "ECONNABORTED", "Software caused connection abort" }, // 103
    .{ "ECONNRESET", "Connection reset by peer" }, // 104
    .{ "ENOBUFS", "No buffer space available" }, // 105
    .{ "EISCONN", "Transport endpoint is already connected" }, // 106
    .{ "ENOTCONN", "Transport endpoint is not connected" }, // 107
    .{ "ESHUTDOWN", "Cannot send after transport endpoint shutdown" }, // 108
    .{ "ETOOMANYREFS", "Too many references: cannot splice" }, // 109
    .{ "ETIMEDOUT", "Connection timed out" }, // 110
    .{ "ECONNREFUSED", "Connection refused" }, // 111
    .{ "EHOSTDOWN", "Host is down" }, // 112
    .{ "EHOSTUNREACH", "No route to host" }, // 113
    .{ "EALREADY", "Operation already in progress" }, // 114
    .{ "EINPROGRESS", "Operation now in progress" }, // 115
    .{ "ESTALE", "Stale file handle" }, // 116
    .{ "EUCLEAN", "Structure needs cleaning" }, // 117
    .{ "ENOTNAM", "Not a XENIX named type file" }, // 118
    .{ "ENAVAIL", "No XENIX semaphores available" }, // 119
    .{ "EISNAM", "Is a named type file" }, // 120
    .{ "EREMOTEIO", "Remote I/O error" }, // 121
    .{ "EDQUOT", "Disk quota exceeded" }, // 122
    .{ "ENOMEDIUM", "No medium found" }, // 123
    .{ "EMEDIUMTYPE", "Wrong medium type" }, // 124
    .{ "ECANCELED", "Operation canceled" }, // 125
    .{ "ENOKEY", "Required key not available" }, // 126
    .{ "EKEYEXPIRED", "Key has expired" }, // 127
    .{ "EKEYREVOKED", "Key has been revoked" }, // 128
    .{ "EKEYREJECTED", "Key was rejected by service" }, // 129
    .{ "EOWNERDEAD", "Owner died" }, // 130
    .{ "ENOTRECOVERABLE", "State not recoverable" }, // 131
    .{ "ERFKILL", "Operation not possible due to RF-kill" }, // 132
    .{ "EHWPOISON", "Memory page has hardware error" }, // 133
    .{ "EFTYPE", "Inappropriate file type or format" }, // 134
};

comptime {
    // The generic numbers this table is indexed by (see the file comment).
    std.debug.assert(@intFromEnum(sys.E.NOENT) == 2);
    std.debug.assert(@intFromEnum(sys.E.AGAIN) == 11);
    std.debug.assert(@intFromEnum(sys.E.DEADLK) == 35);
    std.debug.assert(@intFromEnum(sys.E.OPNOTSUPP) == 95);
    std.debug.assert(@intFromEnum(sys.E.HWPOISON) == 133);
}

const testing = std.testing;

test "known numbers read as glibc's" {
    try testing.expectEqualStrings("Operation not permitted", text(.PERM).?);
    try testing.expectEqualStrings("EPERM", name(.PERM).?);
    try testing.expectEqualStrings("Success", text(.SUCCESS).?);
    try testing.expectEqualStrings("0", name(.SUCCESS).?);
    try testing.expectEqualStrings("Memory page has hardware error", text(.HWPOISON).?);
    try testing.expectEqualStrings("EFTYPE", name(@enumFromInt(134)).?);
}

test "holes and numbers beyond the table read as Unknown error N" {
    var buf: [max_len]u8 = undefined;
    try testing.expectEqualStrings("Unknown error 41", describe(@enumFromInt(41), &buf));
    try testing.expectEqualStrings("Unknown error 58", describe(@enumFromInt(58), &buf));
    try testing.expectEqualStrings("Unknown error 135", describe(@enumFromInt(135), &buf));
    try testing.expectEqualStrings("Unknown error 65535", describe(@enumFromInt(65535), &buf));
    try testing.expectEqual(null, name(@enumFromInt(41)));
    try testing.expectEqual(null, name(@enumFromInt(4095)));
    try testing.expectEqualStrings("Bad file descriptor", describe(.BADF, &buf));
}

test "every name is E and upper case, every text has no newline" {
    for (table, 0..) |t, n| {
        if (n == 0 or t[0] == null) continue;
        try testing.expect(t[0].?[0] == 'E');
        for (t[0].?) |ch| try testing.expect(std.ascii.isUpper(ch) or std.ascii.isDigit(ch));
        try testing.expect(std.mem.indexOfScalar(u8, t[1].?, '\n') == null);
    }
}
