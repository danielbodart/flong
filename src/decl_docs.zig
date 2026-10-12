//! decl_docs.zig: the declaration's fields, their types, defaults and
//! descriptions, in one walk (DESIGN.md, "The declaration": one
//! description), as capsper's src/shared/config_docs.zig walks its settings.
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
//!   x-scope    `host` for a field a project's layer may never set, and
//!              everything below one, every computed field among them;
//!              `tighten` for one it may set only to a stricter value
//!              (decl.Scope); absent for the rest, which a project may set
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
//!   enum {tags}                     a string, one of `tags`
//!   command                         a non-empty list of strings
//!                                   (decl.Command)
//!   list {of}
//!   pathAttrs {name, value}         Nix `attrsOf path`, a JSON object
//!                                   whose names are the `name` field and
//!                                   values the `value` field of decl's type
//!   attrsOf {name, value, of}       Nix `attrsOf`, the same, its values
//!                                   of the type `of` rather than paths
//!   struct {fields}                 a submodule; `fields` are entries
//!   either {options}                a union: each option is a type with
//!                                   its union field as `tag`; a void field
//!                                   is `enum {tags: [tag]}`, the string
//!                                   `"tag"`, and any other its value, with
//!                                   no tag around it (decl.zig)
//!
//! A declaration's JSON is these types' Nix values, as `builtins.toJSON`
//! writes them, so a type here is also how a declaration file spells it.
//!
//! The grammar's names are Nix's where Nix has one: strMatching rather
//! than the blueprint's `pathMatching`, since a syscall name and a CPU
//! quota are patterns too and neither is a path.
//!
//! `writeReference` is the same fields for a reader writing JSON by hand
//! (DESIGN.md, "The declaration"): `flong help decl` in text, and with
//! `--markdown` docs/declaration.md, which the reference-fresh check holds
//! to it. Its rows, `rows`, come from the same helpers at comptime, with
//! types and defaults spelt as JSON writes them.

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
pub const Meta = struct {
    pattern: ?[]const u8 = null,
    range: ?struct { comptime_int, comptime_int } = null,
};

pub fn metaOf(comptime T: type, comptime name: []const u8) Meta {
    var m: Meta = .{};
    if (@hasDecl(T, "patterns") and @hasField(@TypeOf(T.patterns), name)) m.pattern = @field(T.patterns, name);
    if (@hasDecl(T, "ranges") and @hasField(@TypeOf(T.ranges), name)) m.range = @field(T.ranges, name);
    return m;
}

/// A field's scope where it lies `within` another's: everything below a
/// host field is the host's.
fn scopeIn(comptime within: decl.Scope, comptime T: type, comptime name: []const u8) decl.Scope {
    return if (within == .host) .host else decl.scopeOf(T, name);
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
    try writeFields(&s, decl.Declaration, "", true, .project);
    try w.writeByte('\n');
}

fn writeFields(s: *std.json.Stringify, comptime T: type, comptime prefix: []const u8, comptime option: bool, comptime within: decl.Scope) std.Io.Writer.Error!void {
    try s.beginArray();
    inline for (@typeInfo(T).@"struct".fields) |f| {
        const path = if (prefix.len == 0) f.name else prefix ++ "." ++ f.name;
        const is_option = comptime option and !(T == decl.Declaration and isComputed(f.name));
        const scope = comptime scopeIn(within, T, f.name);
        const default = f.defaultValue();
        try s.beginObject();
        try s.objectField("path");
        try s.write(path);
        try s.objectField("type");
        try writeType(s, f.type, path, metaOf(T, f.name), null, is_option, scope);
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
        if (scope != .project) {
            try s.objectField("x-scope");
            try s.write(@tagName(scope));
        }
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
    comptime scope: decl.Scope,
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
            const V = @FieldType(p.child, p.child.attrs.value);
            try s.write(if (comptime isString(V)) "pathAttrs" else "attrsOf");
            try s.objectField("name");
            try s.write(p.child.attrs.name);
            try s.objectField("value");
            try s.write(p.child.attrs.value);
            if (comptime !isString(V)) {
                try s.objectField("of");
                try writeType(s, V, path ++ ".*", metaOf(p.child, p.child.attrs.value), null, option, scope);
            }
        } else {
            try s.write("list");
            try s.objectField("of");
            try writeType(s, p.child, path ++ ".*", m, null, option, scope);
        },
        .@"struct" => {
            try s.write("struct");
            try s.objectField("fields");
            try writeFields(s, U, path, option, scope);
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
                    try writeType(s, x.type, path, metaOf(U, x.name), x.name, option, scope);
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
                try writeValue(s, @FieldType(p.child, p.child.attrs.value), @field(x, p.child.attrs.value));
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

// ---- the reference: flong help decl, and docs/declaration.md ----
//
// The same walk again, for a reader writing a declaration by hand rather
// than for Nix: the same fields, in the same order, with the same
// `docFor`, `metaOf`, `ordered` and `isComputed`, flattened at comptime
// into `rows`, one a field. The types and defaults are spelt as a
// declaration's JSON writes them, and a path is decl-options.json's: a
// union's option adds nothing to it, and a pathAttrs element's fields are
// under `*`. Both renderings are one loop over the table, so
// the binary carries the doc text once, the text `flong schema` already
// holds, and a table beside it.

/// One field of the declaration, as the reference prints it.
pub const Entry = struct {
    /// Dotted, from the declaration's top: a list's element is `*`, and a
    /// union's option adds nothing, `network.forwardPorts.*.hostPort`.
    path: []const u8,
    /// The type, in the reference's words (`typeText`).
    type: []const u8,
    /// The default as JSON writes it, or null when the field is required.
    default: ?[]const u8,
    /// A list whose definitions Nix concatenates in order: decl-options.json's
    /// `merge: ordered`.
    ordered: bool,
    /// `Declaration.computed`, or below one: the NixOS module works it out,
    /// and a declaration written by hand sets it.
    computed: bool,
    /// Who may set it in a layer (decl.Scope), the schema's `x-scope`.
    scope: decl.Scope,
    /// The doc comment, Markdown, lines kept.
    doc: []const u8,
};

/// Every field, in declaration order, a struct's fields after it.
pub const rows: []const Entry = blk: {
    @setEvalBranchQuota(1_000_000);
    const all = entriesOf(decl.Declaration, "", false, .project);
    // The reference heads the computed fields once, so they come last.
    var seen = false;
    for (all) |e| {
        if (e.computed) seen = true else if (seen) @compileError(e.path ++ " follows a computed field: computed fields come last in Declaration");
    }
    const table = all[0..all.len].*;
    break :blk &table;
};

fn entriesOf(comptime T: type, comptime prefix: []const u8, comptime computed: bool, comptime within: decl.Scope) []const Entry {
    var out: []const Entry = &.{};
    for (@typeInfo(T).@"struct".fields) |f| {
        const path = if (prefix.len == 0) f.name else prefix ++ "." ++ f.name;
        const c = computed or (T == decl.Declaration and isComputed(f.name));
        const scope = scopeIn(within, T, f.name);
        out = out ++ [_]Entry{.{
            .path = path,
            .type = typeText(f.type, metaOf(T, f.name)),
            .default = if (f.defaultValue()) |d| jsonValue(f.type, d) else null,
            .ordered = ordered(f.type),
            .computed = c,
            .scope = scope,
            .doc = docFor(T, f.name, path),
        }};
        out = out ++ childrenOf(f.type, path, c, scope);
    }
    return out;
}

/// The fields a value of `T` holds, when it holds any: a struct's, a list
/// element's under `*`, a union option's under the union's own path.
fn childrenOf(comptime T: type, comptime path: []const u8, comptime computed: bool, comptime scope: decl.Scope) []const Entry {
    const U = unwrap(T);
    if (U == decl.Command or isString(U)) return &.{};
    return switch (@typeInfo(U)) {
        .pointer => |p| childrenOf(p.child, path ++ ".*", computed, scope),
        .@"struct" => entriesOf(U, path, computed, scope),
        .@"union" => |u| blk: {
            var out: []const Entry = &.{};
            for (u.fields) |x| out = out ++ childrenOf(x.type, path, computed, scope);
            break :blk out;
        },
        else => &.{},
    };
}

/// A type as the reference says it; `reference_intro` explains the words.
fn typeText(comptime T: type, comptime m: Meta) []const u8 {
    const U = unwrap(T);
    const base = if (U == decl.Command) "command" else switch (@typeInfo(U)) {
        .bool => "bool",
        .int => |i| blk: {
            if (i.signedness != .unsigned) @compileError(@typeName(U) ++ ": a signed integer, which no field is");
            const range = m.range orelse .{ 0, std.math.maxInt(U) };
            break :blk std.fmt.comptimePrint("integer {d}..{d}", .{ range[0], range[1] });
        },
        .@"enum" => |e| blk: {
            var s: []const u8 = "one of";
            for (e.fields, 0..) |x, n| s = s ++ (if (n == 0) " \"" else ", \"") ++ x.name ++ "\"";
            break :blk s;
        },
        .pointer => |p| if (isString(U))
            (if (m.pattern) |pattern| "string matching " ++ pattern else "string")
        else if (isAttrs(p.child))
            "object of " ++ p.child.attrs.name ++ " to " ++ attrsValueText(p.child)
        else
            "list of " ++ typeText(p.child, m),
        .@"struct" => "struct",
        .@"union" => |u| blk: {
            var s: []const u8 = "";
            for (u.fields, 0..) |x, n| {
                s = s ++ (if (n == 0) "" else " | ") ++ if (x.type == void)
                    "\"" ++ x.name ++ "\""
                else
                    typeText(x.type, metaOf(U, x.name));
            }
            break :blk s;
        },
        else => @compileError("no reference type for " ++ @typeName(U)),
    };
    return if (U != T) base ++ ", or null" else base;
}

/// An attribute set's value in the reference: the value field's name when
/// it is a string (`lower`), its type otherwise.
fn attrsValueText(comptime A: type) []const u8 {
    const V = @FieldType(A, A.attrs.value);
    return if (isString(V)) A.attrs.value else typeText(V, metaOf(A, A.attrs.value));
}

/// A value as a declaration's JSON writes it, which is as Nix writes it
/// (`writeValue`): an enum's tag and a void union field as a string, a
/// union's other fields as their value, pathAttrs as an object, and a
/// struct as the fields that differ from its own defaults, `{}` for none.
fn jsonValue(comptime T: type, comptime v: T) []const u8 {
    return switch (@typeInfo(T)) {
        .optional => |o| if (v) |x| jsonValue(o.child, x) else "null",
        .bool => if (v) "true" else "false",
        .int => std.fmt.comptimePrint("{d}", .{v}),
        .@"enum" => jsonString(@tagName(v)),
        .pointer => |p| if (isString(T))
            jsonString(v)
        else if (isAttrs(p.child)) blk: {
            var s: []const u8 = "";
            for (v, 0..) |x, n| s = s ++ (if (n == 0) "{ " else ", ") ++ jsonString(@field(x, p.child.attrs.name)) ++ ": " ++ jsonValue(@FieldType(p.child, p.child.attrs.value), @field(x, p.child.attrs.value));
            break :blk if (s.len == 0) "{}" else s ++ " }";
        } else if (v.len == 0)
            "[]"
        else blk: {
            var s: []const u8 = "[";
            for (v, 0..) |x, n| s = s ++ (if (n == 0) "" else ", ") ++ jsonValue(p.child, x);
            break :blk s ++ "]";
        },
        .@"struct" => |st| blk: {
            var s: []const u8 = "";
            for (st.fields) |f| {
                const x = @field(v, f.name);
                const same = if (f.defaultValue()) |d| equal(f.type, x, d) else false;
                if (!same) s = s ++ (if (s.len == 0) "{ " else ", ") ++ jsonString(f.name) ++ ": " ++ jsonValue(f.type, x);
            }
            break :blk if (s.len == 0) "{}" else s ++ " }";
        },
        .@"union" => blk: {
            const tag = @tagName(std.meta.activeTag(v));
            const P = @FieldType(T, tag);
            break :blk if (P == void) jsonString(tag) else jsonValue(P, @field(v, tag));
        },
        else => @compileError("no JSON value for " ++ @typeName(T)),
    };
}

/// A JSON string literal, escaped as std.json writes one.
fn jsonString(comptime s: []const u8) []const u8 {
    var out: []const u8 = "\"";
    for (s) |c| out = out ++ switch (c) {
        '"' => "\\\"",
        '\\' => "\\\\",
        '\n' => "\\n",
        '\t' => "\\t",
        0...8, 11...0x1f => std.fmt.comptimePrint("\\u{x:0>4}", .{c}),
        else => &[_]u8{c},
    };
    return out ++ "\"";
}

/// How the reference is written: plain text for a terminal (`flong help
/// decl`), or Markdown (`flong help decl --markdown`, docs/declaration.md).
pub const Style = enum { text, markdown };

/// What a declaration is and how the types read, before the fields; the
/// same words in both styles, backticks and all.
const reference_intro =
    \\A declaration is one JSON object holding the fields below, each under
    \\its own name, the NixOS option's. `flong check` judges one and `flong
    \\launch` runs one, with the same parser: a field not listed here, one
    \\given twice, a required one left out, or a value of the wrong type is
    \\refused with its line and column. A field with a default may be left
    \\out. JSON is all it takes: no comment, no trailing comma.
    \\
    \\The NixOS module writes each `flong.<name>` to `/etc/flong/<name>.json`,
    \\`builtins.toJSON` of options of the same names, and works out the
    \\computed fields at the end. A declaration written by hand sets those
    \\too. Every value is spelt as Nix's is, so the descriptions, which are
    \\the module's too, read the same either way: `[ ]` is `[]`, `{ }` is
    \\`{}`, `"auto"` is `"auto"`, and `{ target = lower; }` is
    \\`{ "target": "lower" }`.
    \\
    \\Each field has its path, dotted from the top: a list's element is `*`.
    \\Its type is one of:
    \\
;

/// The types' words: a list in text, a table in Markdown, whose cells
/// read each newline as a space.
const type_words = [_]struct { []const u8, []const u8 }{
    .{ "string", "a JSON string, `\"text\"`" },
    .{ "string matching P", "a string the regular expression P matches whole" },
    .{ "bool", "`true` or `false`" },
    .{ "integer A..B", "a whole number from A to B, with no fraction or\nexponent" },
    .{ "one of \"a\", \"b\"", "one of those strings" },
    .{ "command", "`[\"program\", \"argument\", ...]`, not empty, and never\nread by a shell: the program is run as it is, or looked up\non `PATH` when it has no `/`" },
    .{ "list of X", "`[X, X, ...]`; `[]` is empty" },
    .{ "object of A to B", "`{ \"A\": \"B\", ... }`, each name once" },
    .{ "struct", "`{ \"field\": value, ... }`, its fields listed after it" },
    .{ "A | B", "a union: a value of one of its options, with nothing\naround it; an option in quotes is that string" },
    .{ "..., or null", "`null` is a value too" },
};

const reference_ordered =
    \\A list marked ordered keeps its order, so a list of commands runs
    \\them one after another; the NixOS module concatenates its
    \\definitions in `mkOrder` order (`mkBefore`, `mkAfter`).
    \\
;

const reference_scope =
    \\A project may bring a layer of its own, a JSON object of these
    \\fields, any of them left out, merged over the declaration as a JSON
    \\Merge Patch (RFC 7396): an object merges field by field, `null`
    \\removes what is beneath, and anything else replaces it. `flong check
    \\--layer project LAYER.json` judges one. A field marked host only is
    \\the host's to set, never a project's, and so is everything below it;
    \\a field marked as one a project only tightens takes a value at least
    \\as strict as the one beneath it. The schema says the same as
    \\`x-scope`: `host` or `tighten`.
    \\
;

const reference_computed =
    \\The NixOS module works these out of `containers.<name>`, the closure it
    \\builds and the rest of the declaration, and has no option for them. A
    \\declaration written by hand sets each one that is required.
    \\
;

/// Writes the reference, the whole of it, ending in a newline.
pub fn writeReference(w: *std.Io.Writer, style: Style) std.Io.Writer.Error!void {
    try heading(w, 1, "The declaration", style);
    if (style == .markdown) try w.writeAll(
        \\<!-- Generated by `flong help decl --markdown` from src/decl.zig's
        \\doc comments. Do not edit: run `nix run .#update-options`. -->
        \\
        \\
    );
    try writeProse(w, reference_intro, "", style);
    try w.writeByte('\n');
    switch (style) {
        .text => for (type_words) |t| {
            try w.print("  {s}\n", .{t[0]});
            try writeProse(w, t[1], "      ", style);
            try w.writeByte('\n');
        },
        .markdown => {
            try w.writeAll("| type | written |\n|---|---|\n");
            for (type_words) |t| {
                try w.writeAll("| `");
                try cell(w, t[0]);
                try w.writeAll("` | ");
                try cell(w, t[1]);
                try w.writeAll(" |\n");
            }
        },
    }
    try w.writeByte('\n');
    try writeProse(w, reference_ordered, "", style);
    try w.writeByte('\n');
    try writeProse(w, reference_scope, "", style);
    try w.writeByte('\n');

    try heading(w, 2, "Fields", style);
    var in_computed = false;
    for (rows, 0..) |e, n| {
        if (e.computed and !in_computed) {
            in_computed = true;
            try w.writeByte('\n');
            try heading(w, 2, "Computed fields", style);
            try writeProse(w, reference_computed, "", style);
            try w.writeByte('\n');
        } else if (n > 0) try w.writeByte('\n');
        try writeEntry(w, e, style);
    }
}

/// A title and a blank line: `#` or `##` in Markdown, underlined with `=`
/// or `-` in text.
fn heading(w: *std.Io.Writer, comptime level: u2, title: []const u8, style: Style) std.Io.Writer.Error!void {
    switch (style) {
        .text => {
            try w.print("{s}\n", .{title});
            try w.splatByteAll(if (level == 1) '=' else '-', title.len);
            try w.writeAll("\n\n");
        },
        .markdown => try w.print("{s} {s}\n\n", .{ "##"[0..level], title }),
    }
}

/// A Markdown table cell: a newline read as a space, a `|` escaped.
fn cell(w: *std.Io.Writer, text: []const u8) std.Io.Writer.Error!void {
    for (text) |c| switch (c) {
        '\n' => try w.writeByte(' '),
        '|' => try w.writeAll("\\|"),
        else => try w.writeByte(c),
    };
}

/// What the reference says of a field's scope, where it says anything:
/// a computed field's is the host's, which `computed` says already.
fn scopeWords(e: Entry) ?[]const u8 {
    if (e.computed) return null;
    return switch (e.scope) {
        .project => null,
        .host => "host only",
        .tighten => "a project only tightens it",
    };
}

fn writeEntry(w: *std.Io.Writer, e: Entry, style: Style) std.Io.Writer.Error!void {
    switch (style) {
        .text => {
            try w.print("{s}\n    type: {s}\n", .{ e.path, e.type });
            if (e.default) |d| try w.print("    default: {s}\n", .{d}) else try w.writeAll("    required\n");
            if (e.ordered) try w.writeAll("    ordered\n");
            if (e.computed) try w.writeAll("    computed\n");
            if (scopeWords(e)) |x| try w.print("    {s}\n", .{x});
            try w.writeByte('\n');
            try writeProse(w, e.doc, "    ", style);
            try w.writeByte('\n');
        },
        .markdown => {
            try w.print("### `{s}`\n\n- type: `{s}`\n", .{ e.path, e.type });
            if (e.default) |d| try w.print("- default: `{s}`\n", .{d}) else try w.writeAll("- required\n");
            if (e.ordered) try w.writeAll("- ordered\n");
            if (e.computed) try w.writeAll("- computed\n");
            if (scopeWords(e)) |x| try w.print("- {s}\n", .{x});
            try w.writeByte('\n');
            try w.writeAll(e.doc);
            try w.writeByte('\n');
        },
    }
}

/// Markdown prose, as it is for `.markdown`; for `.text`, each line after
/// `indent` (a blank line bare), with `**` dropped and a link
/// `[text](url)` written `text (url)`. Backticks stay: they read as quotes.
fn writeProse(w: *std.Io.Writer, text: []const u8, indent: []const u8, style: Style) std.Io.Writer.Error!void {
    if (style == .markdown) return w.writeAll(text);
    var lines = std.mem.splitScalar(u8, text, '\n');
    var first = true;
    while (lines.next()) |line| {
        if (!first) try w.writeByte('\n');
        first = false;
        if (line.len == 0) continue;
        try w.writeAll(indent);
        try plainLine(w, line);
    }
}

fn plainLine(w: *std.Io.Writer, line: []const u8) std.Io.Writer.Error!void {
    var i: usize = 0;
    while (i < line.len) {
        if (std.mem.startsWith(u8, line[i..], "**")) {
            i += 2;
            continue;
        }
        if (line[i] == '[') link: {
            const close = std.mem.indexOfPos(u8, line, i, "](") orelse break :link;
            const end = std.mem.indexOfScalarPos(u8, line, close, ')') orelse break :link;
            try w.print("{s} ({s})", .{ line[i + 1 .. close], line[close + 2 .. end] });
            i = end + 1;
            continue;
        }
        try w.writeByte(line[i]);
        i += 1;
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
    try testing.expect(std.mem.startsWith(u8, user.get("doc").?.string, "User inside the container, which everything in the container runs\nas.\n\nIts uid"));

    const command = find(top, "command").?;
    try testing.expectEqualStrings("command", command.get("type").?.object.get("type").?.string);
    try testing.expect(command.get("type").?.object.get("nullable").?.bool);
    try testing.expect(!command.get("required").?.bool);

    const exec = find(top, "exec").?;
    try testing.expectEqualStrings("command", exec.get("type").?.object.get("type").?.string);
    try testing.expect(exec.get("nixOption").?.bool);

    const environment = find(top, "environment").?;
    try testing.expectEqualStrings("list", environment.get("type").?.object.get("type").?.string);
    try testing.expect(!environment.get("nixOption").?.bool);

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

    // seccomp.syscalls: an attribute set of an enum, which Nix reads as
    // attrsOf, its default the empty set.
    const calls = find(top, "seccomp.syscalls").?;
    const calls_type = calls.get("type").?.object;
    try testing.expectEqualStrings("attrsOf", calls_type.get("type").?.string);
    try testing.expectEqualStrings("name", calls_type.get("name").?.string);
    try testing.expectEqualStrings("action", calls_type.get("value").?.string);
    try testing.expectEqualStrings("enum", calls_type.get("of").?.object.get("type").?.string);
    try testing.expectEqual(3, calls_type.get("of").?.object.get("tags").?.array.items.len);
    try testing.expectEqual(0, calls.get("default").?.object.count());
    try testing.expectEqualStrings("single", calls.get("merge").?.string);
    // overlays stays pathAttrs, with no `of`.
    try testing.expect(find(top, "overlays").?.get("type").?.object.get("of") == null);
}

test "x-scope: host for what a project may never set, tighten for the tier" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const top = (try std.json.parseFromSliceLeaky(std.json.Value, a, try schema(a), .{})).array.items;
    const host = [_][]const u8{
        "user",                   "command",                  "exec",                          "workspace",
        "binds",                  "guard",                    "postStart",                     "postStop",
        "network.forwardAddress", "network.forwardInterface", "network.hostLoopbackToSession", "overlays",
        "masks",                  "protect",                  "seccomp.nestedSandbox",         "seccomp.errno",
        "seccompPolicy",          "container",                "closure",                       "cuid",
        "cgid",                   "steps8",                   "containerMounts",               "containerMounts.*.kind",
        "name",                   "environment",              "environment.*.value",           "seccompTierFilter",
        "seccompFixedFilters",    "seccompProject",           "seccompProject.logged",         "commandPath",
        "postStartProgram",       "postStopProgram",
    };
    for (host) |p| {
        const x = find(top, p) orelse return error.NoSuchPath;
        try testing.expectEqualStrings("host", (x.get("x-scope") orelse return error.NoScope).string);
    }
    try testing.expectEqualStrings("tighten", find(top, "seccomp.tier").?.get("x-scope").?.string);
    for ([_][]const u8{ "network", "network.forwardPorts", "network.forwardPorts.*.hostPort", "network.hostPorts", "limits", "limits.MemoryMax", "seccomp", "seccomp.debug", "seccomp.allow", "seccomp.deny", "seccomp.syscalls", "seccomp.log" }) |p| {
        try testing.expect(find(top, p).?.get("x-scope") == null);
    }
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

    var calls_out: std.Io.Writer.Allocating = .init(a);
    var cs: std.json.Stringify = .{ .writer = &calls_out.writer };
    const calls: []const decl.SyscallRule = &.{ .{ .name = "ptrace", .action = .deny }, .{ .name = "io_uring_setup", .action = .log } };
    try writeValue(&cs, []const decl.SyscallRule, calls);
    try testing.expectEqualStrings("{\"ptrace\":\"deny\",\"io_uring_setup\":\"log\"}", calls_out.written());
    try testing.expectEqualStrings("{ \"ptrace\": \"deny\" }", comptime jsonValue([]const decl.SyscallRule, &.{.{ .name = "ptrace", .action = .deny }}));
}

fn reference(arena: std.mem.Allocator, style: Style) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(arena);
    try writeReference(&out.writer, style);
    return out.written();
}

fn entry(path: []const u8) ?Entry {
    for (rows) |e| {
        if (std.mem.eql(u8, e.path, path)) return e;
    }
    return null;
}

test "the reference has every field the schema has, with the same doc" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const top = (try std.json.parseFromSliceLeaky(std.json.Value, a, try schema(a), .{})).array.items;

    // Every top-level field, in order, each with the schema's doc, its
    // `required` and `merge`, and computed exactly where `nixOption` is
    // false.
    var n: usize = 0;
    for (rows) |e| {
        if (std.mem.indexOfScalar(u8, e.path, '.') != null) continue;
        const o = top[n].object;
        n += 1;
        try testing.expectEqualStrings(o.get("path").?.string, e.path);
        try testing.expectEqualStrings(o.get("doc").?.string, e.doc);
        try testing.expectEqual(o.get("required").?.bool, e.default == null);
        try testing.expectEqual(!o.get("nixOption").?.bool, e.computed);
        try testing.expectEqual(std.mem.eql(u8, o.get("merge").?.string, "ordered"), e.ordered);
    }
    try testing.expectEqual(top.len, n);

    // And the fields below them, by the same paths.
    for ([_][]const u8{ "network.hostPorts", "network.forwardPorts.*.hostPort", "limits.CPUWeight", "seccomp.errno", "containerMounts.*.kind", "seccompProject.dump" }) |p| {
        try testing.expectEqualStrings(find(top, p).?.get("doc").?.string, entry(p).?.doc);
    }
}

test "the reference spells each type and default as JSON does" {
    const Case = struct { path: []const u8, type: []const u8, default: ?[]const u8 };
    for ([_]Case{
        .{ .path = "user", .type = "string", .default = null },
        .{ .path = "command", .type = "command, or null", .default = "null" },
        .{ .path = "exec", .type = "command, or null", .default = "null" },
        .{ .path = "environment", .type = "list of struct", .default = "[]" },
        .{ .path = "environment.*.name", .type = "string", .default = null },
        .{ .path = "workspace", .type = "command, or null", .default = "null" },
        .{ .path = "guard", .type = "list of command", .default = "[]" },
        .{ .path = "masks", .type = "list of string matching /.*", .default = "[]" },
        .{ .path = "network", .type = "struct, or null", .default = "null" },
        .{ .path = "network.forwardPorts", .type = "\"auto\" | list of struct", .default = "[]" },
        .{ .path = "network.forwardPorts.*.protocol", .type = "one of \"tcp\", \"udp\"", .default = "\"tcp\"" },
        .{ .path = "network.forwardPorts.*.hostPort", .type = "integer 0..65535", .default = null },
        .{ .path = "network.forwardPorts.*.containerPort", .type = "integer 0..65535, or null", .default = "null" },
        .{ .path = "network.hostLoopbackToSession", .type = "bool", .default = "false" },
        .{ .path = "overlays", .type = "object of target to lower", .default = "{}" },
        .{ .path = "overlays.*.target", .type = "string", .default = null },
        .{ .path = "limits", .type = "struct", .default = "{}" },
        .{ .path = "limits.MemoryMax", .type = "\"infinity\" | integer 0..9223372036854775807 | string matching [0-9]+[KMGT], or null", .default = "null" },
        .{ .path = "limits.TasksMax", .type = "\"infinity\" | integer 1..9223372036854775807, or null", .default = "null" },
        .{ .path = "limits.CPUQuota", .type = "string matching [1-9][0-9]*%, or null", .default = "null" },
        .{ .path = "limits.CPUWeight", .type = "integer 1..10000, or null", .default = "null" },
        .{ .path = "seccomp.tier", .type = "one of \"parity\", \"strict\", or null", .default = "\"strict\"" },
        .{ .path = "seccomp.errno", .type = "one of \"EPERM\", \"EACCES\", \"ENOSYS\"", .default = "\"EPERM\"" },
        .{ .path = "seccomp.syscalls", .type = "object of name to one of \"allow\", \"deny\", \"log\"", .default = "{}" },
        .{ .path = "seccomp.syscalls.*.action", .type = "one of \"allow\", \"deny\", \"log\"", .default = null },
        .{ .path = "cuid", .type = "integer 0..4294967295", .default = null },
        .{ .path = "seccompProject", .type = "struct, or null", .default = "null" },
    }) |c| {
        const e = entry(c.path) orelse return error.NoSuchEntry;
        try testing.expectEqualStrings(c.type, e.type);
        if (c.default) |d| try testing.expectEqualStrings(d, e.default.?) else try testing.expectEqual(null, e.default);
    }
    try testing.expect(entry("guard").?.ordered and !entry("overlays").?.ordered and !entry("user").?.ordered);
    try testing.expect(entry("containerMounts.*.kind").?.computed and entry("name").?.computed);
    try testing.expect(!entry("seccomp.tier").?.computed);
    // A union's option adds nothing to the path, as in the schema.
    try testing.expectEqual(null, entry("network.forwardPorts.ports.*.hostPort"));
}

test "a default that is not its type's own is written out" {
    try testing.expectEqualStrings(
        "{ \"MemoryMax\": \"infinity\", \"TasksMax\": 4096, \"CPUQuota\": \"200%\" }",
        comptime jsonValue(decl.Limits, .{ .MemoryMax = .infinity, .TasksMax = .{ .count = 4096 }, .CPUQuota = "200%" }),
    );
    try testing.expectEqualStrings(
        "{ \"/a\": \"/b \\\"c\\\"\\u0001\" }",
        comptime jsonValue([]const decl.Overlay, &.{.{ .target = "/a", .lower = "/b \"c\"\x01" }}),
    );
    try testing.expectEqualStrings("[\"git\", \"status\"]", comptime jsonValue(decl.Command, &.{ "git", "status" }));
    try testing.expectEqualStrings("\"auto\"", comptime jsonValue(decl.ForwardPorts, .auto));
}

test "text prose: indented, bold dropped, links spelt out" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var out: std.Io.Writer.Allocating = .init(arena_state.allocator());
    try writeProse(&out.writer, "**USE** [pasta](https://passt.top) `a[0]`\n\n- [x] (y)\n", "  ", .text);
    try testing.expectEqualStrings("  USE pasta (https://passt.top) `a[0]`\n\n  - [x] (y)\n", out.written());

    out.clearRetainingCapacity();
    try writeProse(&out.writer, "**USE** [pasta](https://passt.top)\n", "  ", .markdown);
    try testing.expectEqualStrings("**USE** [pasta](https://passt.top)\n", out.written());
}

test "the reference, in text and in Markdown" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const text = try reference(a, .text);
    try testing.expect(std.mem.startsWith(u8, text, "The declaration\n===============\n\nA declaration is one JSON object"));
    try testing.expect(std.mem.endsWith(u8, text, ".\n") and !std.mem.endsWith(u8, text, "\n\n"));
    try testing.expect(std.mem.indexOf(u8, text, "\nFields\n------\n\nuser\n    type: string\n    required\n    host only\n\n    User inside the container") != null);
    try testing.expect(std.mem.indexOf(u8, text, "\nseccomp.tier\n    type: one of \"parity\", \"strict\", or null\n    default: \"strict\"\n    a project only tightens it\n\n    `parity` is exactly") != null);
    try testing.expect(std.mem.indexOf(u8, text, "\nguard\n    type: list of command\n    default: []\n    ordered\n    host only\n\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "\ncuid\n    type: integer 0..4294967295\n    required\n    computed\n\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "provided by\n    pasta (https://passt.top):") != null);
    try testing.expect(std.mem.indexOf(u8, text, "**") == null);
    // The computed fields come under their own heading, after the rest.
    const computed = std.mem.indexOf(u8, text, "\n\nComputed fields\n---------------\n\nThe NixOS module works these out").?;
    try testing.expect(computed > std.mem.indexOf(u8, text, "\nseccompPolicy\n").?);
    try testing.expect(computed < std.mem.indexOf(u8, text, "\ncontainer\n").?);
    // Every field has its entry.
    for (rows) |e| {
        const line = try std.fmt.allocPrint(a, "\n{s}\n    type: ", .{e.path});
        try testing.expect(std.mem.indexOf(u8, text, line) != null);
    }

    const md = try reference(a, .markdown);
    try testing.expect(std.mem.startsWith(u8, md, "# The declaration\n\n<!-- Generated by `flong help decl --markdown`"));
    try testing.expect(std.mem.endsWith(u8, md, ".\n") and !std.mem.endsWith(u8, md, "\n\n"));
    try testing.expect(std.mem.indexOf(u8, md, "\n## Fields\n\n### `user`\n\n- type: `string`\n- required\n- host only\n\nUser inside") != null);
    try testing.expect(std.mem.indexOf(u8, md, "\n### `seccomp.tier`\n\n- type: `one of \"parity\", \"strict\", or null`\n- default: `\"strict\"`\n- a project only tightens it\n\n") != null);
    try testing.expect(std.mem.indexOf(u8, md, "\n## Computed fields\n\n") != null);
    // A table cell's `|` is escaped, and its newlines are spaces.
    try testing.expect(std.mem.indexOf(u8, md, "| `A \\| B` | a union: a value of one of its options, with nothing around it; an option in quotes is that string |\n") != null);
    // Markdown as it was written.
    try testing.expect(std.mem.indexOf(u8, md, "[pasta](https://passt.top)") != null);

    // Twice the same bytes.
    try testing.expectEqualStrings(md, try reference(a, .markdown));
}
