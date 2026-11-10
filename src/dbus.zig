//! dbus.zig: the D-Bus wire format, as much of it as the launcher's talk
//! with its user manager needs (manager.zig; the D-Bus Specification,
//! "Message Protocol"), and nothing that touches a descriptor.
//!
//! Built: a method call, little-endian, with PATH, INTERFACE, MEMBER,
//! DESTINATION and SIGNATURE in its header, and a body made of strings,
//! object paths, uint32s, arrays, structs and variants (`Writer`). Read: any
//! message of either byte order, framed by `frameLen` and taken apart by
//! `parse` into its type, serial, REPLY_SERIAL, PATH, INTERFACE, MEMBER,
//! ERROR_NAME and SIGNATURE, with a `Reader` over its body for the strings,
//! object paths and uint32s the manager's replies and signals carry.
//! Anything else in a header is skipped by its signature; anything that
//! does not hold together is error.Malformed, never a crash, since the
//! bytes are another process's.
//!
//! Alignment is the body's own: a body starts at an offset that is a
//! multiple of 8 in its message, so an offset within it aligns as the same
//! offset within the message would.

const std = @import("std");

pub const Type = enum(u8) {
    call = 1,
    reply = 2,
    @"error" = 3,
    signal = 4,
    _,
};

/// The most the launcher reads as one message. The specification allows
/// 128 MiB; nothing the manager answers the launcher with comes near 1.
pub const max_message = 1 << 20;

pub const Malformed = error{Malformed};

/// The deepest a value nests: 32 arrays and 32 structs, the specification's
/// limits, counted together, variants as containers.
const max_depth = 64;

// ---- building ----

/// A body, or a header's fields, built little-endian in `buf`; offsets
/// align from the start of `buf`.
pub const Writer = struct {
    gpa: std.mem.Allocator,
    buf: std.ArrayList(u8) = .empty,

    pub fn init(gpa: std.mem.Allocator) Writer {
        return .{ .gpa = gpa };
    }

    /// What has been written.
    pub fn bytes(w: *const Writer) []u8 {
        return w.buf.items;
    }

    /// `b` as it is, after what has been written.
    pub fn put(w: *Writer, b: []const u8) !void {
        try w.buf.appendSlice(w.gpa, b);
    }

    fn pad(b: *Writer, n: usize) !void {
        while (b.buf.items.len % n != 0) try b.buf.append(b.gpa, 0);
    }

    pub fn byte(b: *Writer, v: u8) !void {
        try b.buf.append(b.gpa, v);
    }

    pub fn uint32(b: *Writer, v: u32) !void {
        try b.pad(4);
        try b.buf.appendSlice(b.gpa, &std.mem.toBytes(std.mem.nativeToLittle(u32, v)));
    }

    /// A STRING or an OBJECT_PATH: its length, its bytes, a NUL.
    pub fn string(b: *Writer, s: []const u8) !void {
        try b.uint32(@intCast(s.len));
        try b.buf.appendSlice(b.gpa, s);
        try b.buf.append(b.gpa, 0);
    }

    /// A SIGNATURE: a byte of length, its bytes, a NUL.
    pub fn signature(b: *Writer, g: []const u8) !void {
        try b.buf.append(b.gpa, @intCast(g.len));
        try b.buf.appendSlice(b.gpa, g);
        try b.buf.append(b.gpa, 0);
    }

    /// A STRUCT or DICT_ENTRY starts on 8.
    pub fn structStart(b: *Writer) !void {
        try b.pad(8);
    }

    /// An ARRAY of elements aligned to `elem_align`: its length is
    /// written by `arrayEnd(the returned mark)`, counting from the first
    /// element, after the padding to it.
    pub fn arrayStart(b: *Writer, elem_align: usize) !ArrayMark {
        try b.uint32(0);
        const at = b.buf.items.len - 4;
        try b.pad(elem_align);
        return .{ .len_at = at, .start = b.buf.items.len };
    }

    pub fn arrayEnd(b: *Writer, m: ArrayMark) void {
        const n: u32 = @intCast(b.buf.items.len - m.start);
        b.buf.items[m.len_at..][0..4].* = std.mem.toBytes(std.mem.nativeToLittle(u32, n));
    }

    /// An ARRAY with no elements, padded to where its first would be.
    pub fn emptyArray(b: *Writer, elem_align: usize) !void {
        b.arrayEnd(try b.arrayStart(elem_align));
    }

    /// A VARIANT holding one STRING.
    pub fn variantString(b: *Writer, s: []const u8) !void {
        try b.signature("s");
        try b.string(s);
    }

    /// A VARIANT holding an ARRAY of UINT32.
    pub fn variantUint32s(b: *Writer, vs: []const u32) !void {
        try b.signature("au");
        const m = try b.arrayStart(4);
        for (vs) |v| try b.uint32(v);
        b.arrayEnd(m);
    }
};

pub const ArrayMark = struct { len_at: usize, start: usize };

/// A method call's addressing.
pub const Call = struct {
    destination: []const u8,
    path: []const u8,
    interface: []const u8,
    member: []const u8,
    /// the body's signature, empty for none
    signature: []const u8 = "",
};

/// The whole message for `call` with serial `serial` and `body`, which
/// `signature` describes.
pub fn methodCall(gpa: std.mem.Allocator, serial: u32, call: Call, body: []const u8) ![]u8 {
    var h: Writer = .init(gpa);
    try h.byte('l');
    try h.byte(@intFromEnum(Type.call));
    try h.byte(0); // flags: a reply is wanted, and the destination may be started
    try h.byte(1); // protocol version
    try h.uint32(@intCast(body.len));
    try h.uint32(serial);
    const m = try h.arrayStart(8);
    try field(&h, 1, "o", call.path);
    try field(&h, 2, "s", call.interface);
    try field(&h, 3, "s", call.member);
    try field(&h, 6, "s", call.destination);
    if (call.signature.len > 0) {
        try h.structStart();
        try h.byte(8);
        try h.signature("g");
        try h.signature(call.signature);
    }
    h.arrayEnd(m);
    try h.pad(8);
    try h.put(body);
    return h.bytes();
}

fn field(h: *Writer, code: u8, comptime g: []const u8, v: []const u8) !void {
    try h.structStart();
    try h.byte(code);
    try h.signature(g);
    try h.string(v);
}

// ---- reading ----

const Endian = std.builtin.Endian;

fn endianOf(b: u8) Malformed!Endian {
    return switch (b) {
        'l' => .little,
        'B' => .big,
        else => error.Malformed,
    };
}

/// The length of the whole message at the start of `buf`, once its fixed
/// header is there (16 bytes); null while fewer have arrived.
/// error.Malformed for a byte order that is neither, or a message longer
/// than max_message.
pub fn frameLen(buf: []const u8) Malformed!?usize {
    if (buf.len < 16) return null;
    const e = try endianOf(buf[0]);
    const body_len = std.mem.readInt(u32, buf[4..8], e);
    const fields_len = std.mem.readInt(u32, buf[12..16], e);
    if (body_len > max_message or fields_len > max_message) return error.Malformed;
    const total = std.mem.alignForward(usize, 16 + @as(usize, fields_len), 8) + body_len;
    if (total > max_message) return error.Malformed;
    return total;
}

/// One message, its header fields slices of the bytes it was parsed from.
pub const Message = struct {
    type: Type,
    serial: u32,
    reply_serial: ?u32 = null,
    path: ?[]const u8 = null,
    interface: ?[]const u8 = null,
    member: ?[]const u8 = null,
    error_name: ?[]const u8 = null,
    signature: []const u8 = "",
    endian: Endian,
    body: []const u8,

    pub fn reader(m: *const Message) Reader {
        return .{ .buf = m.body, .endian = m.endian };
    }
};

/// The message `buf` holds exactly (frameLen's length of it).
pub fn parse(buf: []const u8) Malformed!Message {
    const total = (try frameLen(buf)) orelse return error.Malformed;
    if (total != buf.len) return error.Malformed;
    const e = try endianOf(buf[0]);
    if (buf[3] != 1) return error.Malformed;
    const fields_len = std.mem.readInt(u32, buf[12..16], e);
    const body_at = std.mem.alignForward(usize, 16 + @as(usize, fields_len), 8);
    var m: Message = .{
        .type = @enumFromInt(buf[1]),
        .serial = std.mem.readInt(u32, buf[8..12], e),
        .endian = e,
        .body = buf[body_at..],
    };
    if (m.serial == 0) return error.Malformed;
    // The fields, read as a body would be: offsets in the message.
    var r: Reader = .{ .buf = buf[0 .. 16 + fields_len], .endian = e, .pos = 16 };
    while (true) {
        // The last field is not padded out to 8 within the array.
        if (std.mem.alignForward(usize, r.pos, 8) >= r.buf.len) break;
        try r.alignTo(8);
        const code = try r.byte();
        const g = try r.signature();
        // A field the launcher does not read, of any type, container types
        // included, is read past by its signature, as the specification
        // says unknown fields must be.
        if (g.len != 1) {
            try r.skip(g);
            continue;
        }
        switch (g[0]) {
            's', 'o' => {
                const v = try r.string();
                switch (code) {
                    1 => m.path = v,
                    2 => m.interface = v,
                    3 => m.member = v,
                    4 => m.error_name = v,
                    else => {},
                }
            },
            'g' => {
                const v = try r.signature();
                if (code == 8) m.signature = v;
            },
            'u' => {
                const v = try r.uint32();
                if (code == 5) m.reply_serial = v;
            },
            else => try r.skip(g),
        }
    }
    return m;
}

/// A cursor over a body (or a header's fields), aligning as it reads.
pub const Reader = struct {
    buf: []const u8,
    endian: Endian,
    pos: usize = 0,

    fn alignTo(r: *Reader, n: usize) Malformed!void {
        const to = (r.pos + n - 1) / n * n;
        if (to > r.buf.len) return error.Malformed;
        r.pos = to;
    }

    fn take(r: *Reader, n: usize) Malformed![]const u8 {
        if (n > r.buf.len - r.pos) return error.Malformed;
        defer r.pos += n;
        return r.buf[r.pos..][0..n];
    }

    /// To the start of a STRUCT or DICT_ENTRY.
    pub fn structStart(r: *Reader) Malformed!void {
        try r.alignTo(8);
    }

    pub fn byte(r: *Reader) Malformed!u8 {
        return (try r.take(1))[0];
    }

    pub fn uint32(r: *Reader) Malformed!u32 {
        try r.alignTo(4);
        return std.mem.readInt(u32, (try r.take(4))[0..4], r.endian);
    }

    /// A STRING or an OBJECT_PATH, without its NUL.
    pub fn string(r: *Reader) Malformed![]const u8 {
        const n = try r.uint32();
        const s = try r.take(@as(usize, n) + 1);
        if (s[n] != 0) return error.Malformed;
        return s[0..n];
    }

    pub fn signature(r: *Reader) Malformed![]const u8 {
        const n = try r.byte();
        const s = try r.take(@as(usize, n) + 1);
        if (s[n] != 0) return error.Malformed;
        return s[0..n];
    }

    /// Reads past one value of each complete type in `g`.
    fn skip(r: *Reader, g: []const u8) Malformed!void {
        try r.skipAt(g, 0);
    }

    fn skipAt(r: *Reader, g: []const u8, depth: usize) Malformed!void {
        var rest = g;
        while (rest.len > 0) rest = try r.skipOne(rest, depth);
    }

    /// One value, `depth` containers deep: past max_depth, the
    /// specification's own bound on nesting, it is Malformed, so a peer's
    /// variants within variants cannot run the stack out.
    fn skipOne(r: *Reader, g: []const u8, depth: usize) Malformed![]const u8 {
        if (depth > max_depth) return error.Malformed;
        switch (g[0]) {
            'y' => _ = try r.take(1),
            'b', 'i', 'u', 'h' => {
                try r.alignTo(4);
                _ = try r.take(4);
            },
            'n', 'q' => {
                try r.alignTo(2);
                _ = try r.take(2);
            },
            'x', 't', 'd' => {
                try r.alignTo(8);
                _ = try r.take(8);
            },
            's', 'o' => _ = try r.string(),
            'g' => _ = try r.signature(),
            'v' => {
                const inner = try r.signature();
                try r.skipAt(inner, depth + 1);
            },
            'a' => {
                const elem = try oneType(g[1..]);
                const n = try r.uint32();
                try r.alignTo(alignOf(elem[0]));
                const end = r.pos + n;
                if (end > r.buf.len) return error.Malformed;
                while (r.pos < end) _ = try r.skipOne(elem, depth + 1);
                if (r.pos != end) return error.Malformed;
                return g[1 + elem.len ..];
            },
            '(', '{' => {
                const whole = try oneType(g);
                try r.alignTo(8);
                try r.skipAt(whole[1 .. whole.len - 1], depth + 1);
                return g[whole.len..];
            },
            else => return error.Malformed,
        }
        return g[1..];
    }
};

/// The first complete type in `g`.
fn oneType(g: []const u8) Malformed![]const u8 {
    if (g.len == 0) return error.Malformed;
    switch (g[0]) {
        'a' => return g[0 .. 1 + (try oneType(g[1..])).len],
        '(', '{' => {
            const close: u8 = if (g[0] == '(') ')' else '}';
            var i: usize = 1;
            while (i < g.len and g[i] != close) i += (try oneType(g[i..])).len;
            if (i >= g.len or i == 1) return error.Malformed;
            return g[0 .. i + 1];
        },
        else => return g[0..1],
    }
}

fn alignOf(c: u8) usize {
    return switch (c) {
        'y', 'g', 'v' => 1,
        'n', 'q' => 2,
        'x', 't', 'd', '(', '{' => 8,
        else => 4,
    };
}

// ---- tests ----

const testing = std.testing;

test "a method call with no body is the specification's bytes" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const got = try methodCall(arena.allocator(), 1, .{
        .destination = "org.freedesktop.DBus",
        .path = "/org/freedesktop/DBus",
        .interface = "org.freedesktop.DBus",
        .member = "Hello",
    }, "");
    // Worked by hand from the specification: 16 bytes of fixed header (the
    // fields' length, 109, last), then each field a struct on 8, then the
    // padding to the body's 8.
    const want = "l\x01\x00\x01" ++ "\x00\x00\x00\x00" ++ "\x01\x00\x00\x00" ++ "\x6d\x00\x00\x00" ++
        "\x01\x01o\x00" ++ "\x15\x00\x00\x00/org/freedesktop/DBus\x00" ++ "\x00\x00" ++
        "\x02\x01s\x00" ++ "\x14\x00\x00\x00org.freedesktop.DBus\x00" ++ "\x00\x00\x00" ++
        "\x03\x01s\x00" ++ "\x05\x00\x00\x00Hello\x00" ++ "\x00\x00" ++
        "\x06\x01s\x00" ++ "\x14\x00\x00\x00org.freedesktop.DBus\x00" ++ "\x00\x00\x00";
    try testing.expectEqualSlices(u8, want, got);
    // And it reads back.
    const m = try parse(got);
    try testing.expectEqual(Type.call, m.type);
    try testing.expectEqual(@as(u32, 1), m.serial);
    try testing.expectEqualStrings("/org/freedesktop/DBus", m.path.?);
    try testing.expectEqualStrings("Hello", m.member.?);
    try testing.expectEqual(@as(usize, 0), m.body.len);
}

test "a body of a string, an array of (sv) and an empty array reads back" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var b: Writer = .init(gpa);
    try b.string("flong-launch-7.scope");
    try b.string("fail");
    const props = try b.arrayStart(8);
    try b.structStart();
    try b.string("PIDs");
    try b.variantUint32s(&.{7});
    try b.structStart();
    try b.string("Slice");
    try b.variantString("app.slice");
    b.arrayEnd(props);
    try b.emptyArray(8);
    const msg = try methodCall(gpa, 9, .{
        .destination = "org.freedesktop.systemd1",
        .path = "/org/freedesktop/systemd1",
        .interface = "org.freedesktop.systemd1.Manager",
        .member = "StartTransientUnit",
        .signature = "ssa(sv)a(sa(sv))",
    }, b.buf.items);
    try testing.expectEqual(@as(?usize, msg.len), try frameLen(msg));
    const m = try parse(msg);
    try testing.expectEqualStrings("ssa(sv)a(sa(sv))", m.signature);
    var r = m.reader();
    try testing.expectEqualStrings("flong-launch-7.scope", try r.string());
    try testing.expectEqualStrings("fail", try r.string());
    try r.skip("a(sv)a(sa(sv))");
    try testing.expectEqual(m.body.len, r.pos);
}

test "a big-endian signal reads by its own byte order" {
    // JobRemoved(u 5, o "/j/5", s "x.scope", s "done"), as a big-endian peer
    // would send it, with an unknown header field (code 9, a uint32) and an
    // array-typed one to read past.
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    const a = testing.allocator;
    const be = struct {
        fn u(l: *std.ArrayList(u8), al: std.mem.Allocator, v: u32) !void {
            try l.appendSlice(al, &std.mem.toBytes(std.mem.nativeToBig(u32, v)));
        }
        fn pad(l: *std.ArrayList(u8), al: std.mem.Allocator, n: usize) !void {
            while (l.items.len % n != 0) try l.append(al, 0);
        }
        fn s(l: *std.ArrayList(u8), al: std.mem.Allocator, v: []const u8) !void {
            try pad(l, al, 4);
            try u(l, al, @intCast(v.len));
            try l.appendSlice(al, v);
            try l.append(al, 0);
        }
    };
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(a);
    try be.u(&body, a, 5);
    try be.s(&body, a, "/j/5");
    try be.s(&body, a, "x.scope");
    try be.s(&body, a, "done");
    try buf.appendSlice(a, "B\x04\x00\x01");
    try be.u(&buf, a, @intCast(body.items.len));
    try be.u(&buf, a, 3);
    try be.u(&buf, a, 0); // the fields' length, patched below
    try buf.appendSlice(a, "\x03\x01s\x00");
    try be.s(&buf, a, "JobRemoved");
    try be.pad(&buf, a, 8);
    try buf.appendSlice(a, "\x09\x01u\x00");
    try be.u(&buf, a, 42);
    try be.pad(&buf, a, 8);
    try buf.appendSlice(a, "\x0a\x02au\x00");
    try be.pad(&buf, a, 4);
    try be.u(&buf, a, 8);
    try be.u(&buf, a, 1);
    try be.u(&buf, a, 2);
    try be.pad(&buf, a, 8);
    try buf.appendSlice(a, "\x08\x01g\x00\x04uoss\x00");
    const fields_len: u32 = @intCast(buf.items.len - 16);
    buf.items[12..16].* = std.mem.toBytes(std.mem.nativeToBig(u32, fields_len));
    try be.pad(&buf, a, 8);
    try buf.appendSlice(a, body.items);

    const m = try parse(buf.items);
    try testing.expectEqual(Type.signal, m.type);
    try testing.expectEqualStrings("JobRemoved", m.member.?);
    try testing.expectEqualStrings("uoss", m.signature);
    var r = m.reader();
    try testing.expectEqual(@as(u32, 5), try r.uint32());
    try testing.expectEqualStrings("/j/5", try r.string());
    try testing.expectEqualStrings("x.scope", try r.string());
    try testing.expectEqualStrings("done", try r.string());
}

test "what does not hold together is Malformed" {
    try testing.expectEqual(@as(?usize, null), try frameLen("l\x01\x00\x01"));
    try testing.expectError(error.Malformed, frameLen("x\x01\x00\x01" ++ "\x00" ** 12));
    // A body longer than max_message.
    try testing.expectError(error.Malformed, frameLen("l\x02\x00\x01" ++ "\xff\xff\xff\x7f" ++ "\x01\x00\x00\x00" ++ "\x00\x00\x00\x00"));
    // Serial 0.
    try testing.expectError(error.Malformed, parse("l\x02\x00\x01" ++ "\x00" ** 12));
    // A field whose string runs past the fields.
    try testing.expectError(error.Malformed, parse("l\x02\x00\x01" ++ "\x00\x00\x00\x00" ++ "\x01\x00\x00\x00" ++ "\x08\x00\x00\x00" ++ "\x04\x01s\x00\xff\x00\x00\x00"));
    var r: Reader = .{ .buf = "\x02\x00\x00\x00ab", .endian = .little };
    try testing.expectError(error.Malformed, r.string());
    try testing.expectError(error.Malformed, oneType("a"));
    try testing.expectError(error.Malformed, oneType("()"));
    try testing.expectError(error.Malformed, oneType("(s"));
    // Variants within variants, past max_depth.
    var deep: [3 * (max_depth + 2)]u8 = undefined;
    for (0..max_depth + 2) |i| deep[3 * i ..][0..3].* = "\x01v\x00".*;
    var dr: Reader = .{ .buf = &deep, .endian = .little };
    try testing.expectError(error.Malformed, dr.skip("v"));
}
