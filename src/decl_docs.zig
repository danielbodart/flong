//! decl_docs.zig: the declaration's fields, their types, defaults and
//! descriptions, in one walk (STANDALONE.md, "The declaration": generated
//! options), as capsper's src/shared/config_docs.zig walks its settings.
//!
//! decl.zig holds the type, and the doc comment beside each field holds its
//! description. `@typeInfo` sees the first and not the second, so
//! build/gen_decl_docs.zig reads the source at build time and hands the
//! prose back as data, `decl_field_docs`. This is where the two meet.
//!
//! Every field the walk reaches must carry a doc comment: a missing one is a
//! compile error naming the field (`docFor`), which is what keeps the
//! descriptions from rotting quietly behind the type as fields are added.
//!
//! `writeSchema` is `decl-options.json`: a JSON array with one entry per
//! field of `Declaration`, in declaration order, each
//!
//!   path       the field's dotted path; a list's element is `*`
//!   type       one of the grammar below
//!   default    the default as a Nix value, null when required
//!   required   true when the field has no default
//!   doc        the doc comment, Markdown, lines kept
//!   merge      `ordered` for a list (a command included): Nix concatenates
//!              its definitions in mkOrder order, so mkBefore, mkAfter and
//!              mkMerge keep working; `single` for anything else
//!   nixOption  false for `Declaration.computed` and everything below one:
//!              Nix works those out and generates no option for them
//!
//! and a type is an object whose `type` is one of, with `nullable: true`
//! added when null is a value:
//!
//!   string                          any string
//!   strMatching {pattern}           a string matching `pattern` whole, as
//!                                   Nix's strMatching (`patterns`)
//!   bool
//!   port                            0-65535, a u16
//!   int {min, max}                  inclusive, the type's or `ranges`'
//!   enum {tags}                     a Nix string, a ZON enum literal
//!   command                         a non-empty list of strings, a ZON
//!                                   tuple of them (decl.Command)
//!   list {of}
//!   pathAttrs {name, value}         Nix `attrsOf path`, a ZON list of
//!                                   `.{ .name = ..., .value = ... }` under
//!                                   those field names, sorted by name
//!   struct {fields}                 a submodule; `fields` are entries
//!   either {options}                a tagged union: each option is a type
//!                                   with its union field as `tag`; a void
//!                                   field is `enum {tags: [tag]}`, a ZON
//!                                   `.tag`, and any other `.{ .tag = V }`
//!
//! The grammar's names are Nix's where Nix has one: strMatching rather
//! than the blueprint's `pathMatching`, since a syscall name and a CPU
//! quota are patterns too and neither is a path.

const std = @import("std");
const decl = @import("decl");
const generated = @import("decl_field_docs");

/// `decl.Limits` as the generator wrote it: `Limits`.
fn containerName(comptime T: type) []const u8 {
    const full = @typeName(T);
    const dot = std.mem.lastIndexOfScalar(u8, full, '.') orelse return full;
    return full[dot + 1 ..];
}

/// The doc comment on `T`'s field `name`, or a compile error naming the
/// field. A description that exists for some fields only is worse than
/// none: the gap is invisible until someone reads the manual and finds an
/// option with nothing beside it.
///
/// One `comptime` block, as capsper's is: called from runtime code, the
/// search would be analysed as a runtime loop whose `break` the compiler
/// cannot prove is reached, and every field would fall through to the
/// error.
pub fn docFor(comptime T: type, comptime name: []const u8, comptime path: []const u8) []const u8 {
    return comptime found: {
        @setEvalBranchQuota(200_000);
        const container = containerName(T);
        for (generated.fields) |f| {
            if (std.mem.eql(u8, f.container, container) and std.mem.eql(u8, f.name, name)) {
                if (f.doc.len == 0) break;
                break :found f.doc;
            }
        }
        @compileError("declaration field '" ++ path ++ "' has no doc comment. " ++
            "Every field needs one: it is the option's only description.");
    };
}

/// What a field's container says of it beyond its type: a pattern
/// (`patterns`) and bounds (`ranges`), by field name.
const Meta = struct {
    pattern: ?[]const u8 = null,
    range: ?struct { comptime_int, comptime_int } = null,
};

fn metaOf(comptime T: type, comptime name: []const u8) Meta {
    var m: Meta = .{};
    if (@hasDecl(T, "patterns") and @hasField(@TypeOf(T.patterns), name)) m.pattern = @field(T.patterns, name);
    if (@hasDecl(T, "ranges") and @hasField(@TypeOf(T.ranges), name)) m.range = @field(T.ranges, name);
    return m;
}

fn isComputed(comptime name: []const u8) bool {
    for (decl.Declaration.computed) |c| {
        if (std.mem.eql(u8, c, name)) return true;
    }
    return false;
}

/// A list of `T` is pathAttrs when `T` says which fields are the
/// attribute's name and value.
fn isAttrs(comptime T: type) bool {
    return @typeInfo(T) == .@"struct" and @hasDecl(T, "attrs");
}

fn isString(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .pointer => |p| p.size == .slice and p.child == u8,
        else => false,
    };
}

fn unwrap(comptime T: type) type {
    return switch (@typeInfo(T)) {
        .optional => |o| o.child,
        else => T,
    };
}

/// Every list merges in order; nothing else is a sequence.
fn ordered(comptime T: type) bool {
    const U = unwrap(T);
    if (U == decl.Command) return true;
    return switch (@typeInfo(U)) {
        .pointer => |p| p.size == .slice and !isString(U) and !isAttrs(p.child),
        else => false,
    };
}

/// Writes decl-options.json, the whole of it, ending in a newline.
pub fn writeSchema(w: *std.Io.Writer) std.Io.Writer.Error!void {
    var s: std.json.Stringify = .{ .writer = w, .options = .{ .whitespace = .indent_2 } };
    try writeFields(&s, decl.Declaration, "", true);
    try w.writeByte('\n');
}

fn writeFields(s: *std.json.Stringify, comptime T: type, comptime prefix: []const u8, comptime option: bool) std.Io.Writer.Error!void {
    try s.beginArray();
    inline for (@typeInfo(T).@"struct".fields) |f| {
        const path = if (prefix.len == 0) f.name else prefix ++ "." ++ f.name;
        const is_option = comptime option and !(T == decl.Declaration and isComputed(f.name));
        const default = f.defaultValue();
        try s.beginObject();
        try s.objectField("path");
        try s.write(path);
        try s.objectField("type");
        try writeType(s, f.type, path, metaOf(T, f.name), null, is_option);
        try s.objectField("default");
        if (default) |d| try writeValue(s, f.type, d) else try s.write(null);
        try s.objectField("required");
        try s.write(default == null);
        try s.objectField("doc");
        try s.write(comptime docFor(T, f.name, path));
        try s.objectField("merge");
        try s.write(if (comptime ordered(f.type)) "ordered" else "single");
        try s.objectField("nixOption");
        try s.write(is_option);
        try s.endObject();
    }
    try s.endArray();
}

/// A type as the grammar says it, `tag` first when it is an either's
/// option.
fn writeType(
    s: *std.json.Stringify,
    comptime T: type,
    comptime path: []const u8,
    comptime m: Meta,
    comptime tag: ?[]const u8,
    comptime option: bool,
) std.Io.Writer.Error!void {
    const U = unwrap(T);
    try s.beginObject();
    if (tag) |t| {
        try s.objectField("tag");
        try s.write(t);
    }
    try s.objectField("type");
    if (U == decl.Command) {
        try s.write("command");
    } else switch (@typeInfo(U)) {
        .bool => try s.write("bool"),
        .int => |i| if (U == u16 and m.range == null) {
            try s.write("port");
        } else {
            if (i.signedness != .unsigned) @compileError(path ++ ": a signed integer, which no option is");
            try s.write("int");
            const range = m.range orelse .{ 0, std.math.maxInt(U) };
            try s.objectField("min");
            try s.write(@as(i64, range[0]));
            try s.objectField("max");
            try s.write(@as(i64, range[1]));
        },
        .@"enum" => |e| {
            try s.write("enum");
            try s.objectField("tags");
            try s.beginArray();
            inline for (e.fields) |x| try s.write(x.name);
            try s.endArray();
        },
        .pointer => |p| if (comptime isString(U)) {
            if (m.pattern) |pattern| {
                try s.write("strMatching");
                try s.objectField("pattern");
                try s.write(pattern);
            } else {
                try s.write("string");
            }
        } else if (comptime isAttrs(p.child)) {
            try s.write("pathAttrs");
            try s.objectField("name");
            try s.write(p.child.attrs.name);
            try s.objectField("value");
            try s.write(p.child.attrs.value);
        } else {
            try s.write("list");
            try s.objectField("of");
            try writeType(s, p.child, path ++ ".*", m, null, option);
        },
        .@"struct" => {
            try s.write("struct");
            try s.objectField("fields");
            try writeFields(s, U, path, option);
        },
        .@"union" => |u| {
            if (u.tag_type == null) @compileError(path ++ ": an untagged union");
            try s.write("either");
            try s.objectField("options");
            try s.beginArray();
            inline for (u.fields) |x| {
                if (x.type == void) {
                    try s.beginObject();
                    try s.objectField("tag");
                    try s.write(x.name);
                    try s.objectField("type");
                    try s.write("enum");
                    try s.objectField("tags");
                    try s.beginArray();
                    try s.write(x.name);
                    try s.endArray();
                    try s.endObject();
                } else {
                    try writeType(s, x.type, path, metaOf(U, x.name), x.name, option);
                }
            }
            try s.endArray();
        },
        else => @compileError(path ++ ": no schema type for " ++ @typeName(U)),
    }
    if (U != T) {
        try s.objectField("nullable");
        try s.write(true);
    }
    try s.endObject();
}

/// A value as Nix would write it: an enum's tag and a void union field as
/// its name, a union otherwise as its payload, pathAttrs as an attribute
/// set, a struct as the fields that differ from its own defaults (`{}` for
/// `.{}`, as module.nix's submodule defaults are).
fn writeValue(s: *std.json.Stringify, comptime T: type, v: T) std.Io.Writer.Error!void {
    switch (@typeInfo(T)) {
        .optional => |o| if (v) |x| try writeValue(s, o.child, x) else try s.write(null),
        .bool, .int => try s.write(v),
        .@"enum" => try s.write(@tagName(v)),
        .pointer => |p| if (comptime isString(T)) {
            try s.write(v);
        } else if (comptime isAttrs(p.child)) {
            try s.beginObject();
            for (v) |x| {
                try s.objectField(@field(x, p.child.attrs.name));
                try s.write(@field(x, p.child.attrs.value));
            }
            try s.endObject();
        } else {
            try s.beginArray();
            for (v) |x| try writeValue(s, p.child, x);
            try s.endArray();
        },
        .@"struct" => |st| {
            try s.beginObject();
            inline for (st.fields) |f| {
                const x = @field(v, f.name);
                const same = if (f.defaultValue()) |d| equal(f.type, x, d) else false;
                if (!same) {
                    try s.objectField(f.name);
                    try writeValue(s, f.type, x);
                }
            }
            try s.endObject();
        },
        .@"union" => switch (v) {
            inline else => |x, t| if (@FieldType(T, @tagName(t)) == void)
                try s.write(@tagName(t))
            else
                try writeValue(s, @FieldType(T, @tagName(t)), x),
        },
        else => @compileError("no Nix value for " ++ @typeName(T)),
    }
}

/// Equality that reads a slice as its elements, where `std.meta.eql`
/// compares the pointer.
fn equal(comptime T: type, a: T, b: T) bool {
    return switch (@typeInfo(T)) {
        .optional => |o| if (a) |x| (if (b) |y| equal(o.child, x, y) else false) else b == null,
        .pointer => |p| blk: {
            if (a.len != b.len) break :blk false;
            for (a, b) |x, y| {
                if (!equal(p.child, x, y)) break :blk false;
            }
            break :blk true;
        },
        .@"struct" => |st| inline for (st.fields) |f| {
            if (!equal(f.type, @field(a, f.name), @field(b, f.name))) break false;
        } else true,
        .@"union" => std.meta.activeTag(a) == std.meta.activeTag(b) and switch (a) {
            inline else => |x, t| equal(@TypeOf(x), x, @field(b, @tagName(t))),
        },
        else => a == b,
    };
}

// ---- tests ----

const testing = std.testing;

fn schema(arena: std.mem.Allocator) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(arena);
    try writeSchema(&out.writer);
    return out.written();
}

/// The entry at `path` in a parsed schema, looking inside structs, lists
/// and eithers.
fn find(entries: []const std.json.Value, path: []const u8) ?std.json.ObjectMap {
    for (entries) |e| {
        const o = e.object;
        if (std.mem.eql(u8, o.get("path").?.string, path)) return o;
        if (findIn(o.get("type").?.object, path)) |x| return x;
    }
    return null;
}

fn findIn(t: std.json.ObjectMap, path: []const u8) ?std.json.ObjectMap {
    if (t.get("fields")) |f| return find(f.array.items, path);
    if (t.get("of")) |of| return findIn(of.object, path);
    if (t.get("options")) |opts| for (opts.array.items) |o| {
        if (findIn(o.object, path)) |x| return x;
    };
    return null;
}

test "the schema is JSON, one entry per field, in declaration order" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const text = try schema(a);
    try testing.expect(std.mem.endsWith(u8, text, "]\n"));

    const top = (try std.json.parseFromSliceLeaky(std.json.Value, a, text, .{})).array.items;
    const fields = @typeInfo(decl.Declaration).@"struct".fields;
    try testing.expectEqual(fields.len, top.len);
    inline for (fields, 0..) |f, i| try testing.expectEqualStrings(f.name, top[i].object.get("path").?.string);

    // Twice the same bytes: nothing in it depends on the run.
    try testing.expectEqualStrings(text, try schema(a));
}

test "the schema says each kind of field as the grammar does" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const top = (try std.json.parseFromSliceLeaky(std.json.Value, a, try schema(a), .{})).array.items;

    const user = find(top, "user").?;
    try testing.expectEqualStrings("string", user.get("type").?.object.get("type").?.string);
    try testing.expect(user.get("required").?.bool);
    try testing.expectEqual(.null, std.meta.activeTag(user.get("default").?));
    try testing.expect(user.get("nixOption").?.bool);
    try testing.expect(std.mem.startsWith(u8, user.get("doc").?.string, "User inside the container, which everything in the session runs\nas.\n\nIts uid"));

    const command = find(top, "command").?;
    try testing.expectEqualStrings("command", command.get("type").?.object.get("type").?.string);
    try testing.expectEqualStrings("ordered", command.get("merge").?.string);

    const workspace = find(top, "workspace").?.get("type").?.object;
    try testing.expectEqualStrings("command", workspace.get("type").?.string);
    try testing.expect(workspace.get("nullable").?.bool);

    const guard = find(top, "guard").?;
    try testing.expectEqualStrings("list", guard.get("type").?.object.get("type").?.string);
    try testing.expectEqualStrings("command", guard.get("type").?.object.get("of").?.object.get("type").?.string);
    try testing.expectEqualStrings("ordered", guard.get("merge").?.string);
    try testing.expectEqual(0, guard.get("default").?.array.items.len);

    const masks = find(top, "masks").?.get("type").?.object.get("of").?.object;
    try testing.expectEqualStrings("strMatching", masks.get("type").?.string);
    try testing.expectEqualStrings("/.*", masks.get("pattern").?.string);

    const overlays = find(top, "overlays").?;
    try testing.expectEqualStrings("pathAttrs", overlays.get("type").?.object.get("type").?.string);
    try testing.expectEqualStrings("single", overlays.get("merge").?.string);
    try testing.expectEqual(0, overlays.get("default").?.object.count());

    const network = find(top, "network").?;
    try testing.expect(network.get("type").?.object.get("nullable").?.bool);
    const fp = find(top, "network.forwardPorts").?;
    try testing.expectEqual(0, fp.get("default").?.array.items.len);
    const opts = fp.get("type").?.object.get("options").?.array.items;
    try testing.expectEqualStrings("auto", opts[0].object.get("tag").?.string);
    try testing.expectEqualStrings("enum", opts[0].object.get("type").?.string);
    try testing.expectEqualStrings("ports", opts[1].object.get("tag").?.string);
    try testing.expectEqualStrings("list", opts[1].object.get("type").?.string);
    const host_port = find(top, "network.forwardPorts.*.hostPort").?;
    try testing.expectEqualStrings("port", host_port.get("type").?.object.get("type").?.string);
    try testing.expectEqualStrings("tcp", find(top, "network.forwardPorts.*.protocol").?.get("default").?.string);

    const limits = find(top, "limits").?;
    try testing.expectEqual(0, limits.get("default").?.object.count());
    const weight = find(top, "limits.CPUWeight").?.get("type").?.object;
    try testing.expectEqualStrings("int", weight.get("type").?.string);
    try testing.expectEqual(1, weight.get("min").?.integer);
    try testing.expectEqual(10000, weight.get("max").?.integer);
    const mem = find(top, "limits.MemoryMax").?.get("type").?.object.get("options").?.array.items;
    try testing.expectEqualStrings("infinity", mem[0].object.get("tag").?.string);
    try testing.expectEqual(std.math.maxInt(u63), mem[1].object.get("max").?.integer);
    try testing.expectEqualStrings("[0-9]+[KMGT]", mem[2].object.get("pattern").?.string);
    try testing.expectEqual(1, find(top, "limits.TasksMax").?.get("type").?.object.get("options").?.array.items[1].object.get("min").?.integer);

    const tier = find(top, "seccomp.tier").?;
    try testing.expectEqualStrings("strict", tier.get("default").?.string);
    try testing.expect(tier.get("type").?.object.get("nullable").?.bool);
    try testing.expectEqualStrings("EPERM", find(top, "seccomp.errno").?.get("default").?.string);

    for ([_][]const u8{ "container", "closure", "cuid", "cgid", "steps8", "containerMounts", "containerMounts.*.kind" }) |p| {
        try testing.expect(!find(top, p).?.get("nixOption").?.bool);
    }
    try testing.expectEqual(std.math.maxInt(u32), find(top, "cuid").?.get("type").?.object.get("max").?.integer);
}

test "a default is written as Nix would write it" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const Case = struct { v: decl.Limits, json: []const u8 };
    for ([_]Case{
        .{ .v = .{}, .json = "{}" },
        .{ .v = .{ .MemoryMax = .infinity, .TasksMax = .{ .count = 4096 } }, .json = "{\"MemoryMax\":\"infinity\",\"TasksMax\":4096}" },
        .{ .v = .{ .MemoryHigh = .{ .size = "8G" }, .oomGroup = true }, .json = "{\"MemoryHigh\":\"8G\",\"oomGroup\":true}" },
    }) |c| {
        var out: std.Io.Writer.Allocating = .init(a);
        var s: std.json.Stringify = .{ .writer = &out.writer };
        try writeValue(&s, decl.Limits, c.v);
        try testing.expectEqualStrings(c.json, out.written());
    }

    var out: std.Io.Writer.Allocating = .init(a);
    var s: std.json.Stringify = .{ .writer = &out.writer };
    const overlays: []const decl.Overlay = &.{.{ .target = "/home/a/.state", .lower = "/var/lib/state" }};
    try writeValue(&s, []const decl.Overlay, overlays);
    try testing.expectEqualStrings("{\"/home/a/.state\":\"/var/lib/state\"}", out.written());
}
