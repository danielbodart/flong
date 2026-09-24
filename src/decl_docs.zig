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
//!
//! `writeReference` is the same fields for a reader writing ZON by hand
//! (STANDALONE.md, S4): `flong help decl` in text, and with `--markdown`
//! docs/declaration.md, which the reference-fresh check holds to it. Its
//! rows, `rows`, come from the same helpers at comptime, with types and
//! defaults spelt as ZON writes them.

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

// ---- the reference: flong help decl, and docs/declaration.md ----
//
// The same walk again, for a reader writing a declaration by hand rather
// than for Nix: the same fields, in the same order, with the same
// `docFor`, `metaOf`, `ordered` and `isComputed`, flattened at comptime
// into `rows`, one a field. The types and defaults are spelt as
// ZON writes them, so a path names a union's option by its tag and a
// pathAttrs list's element by its fields, where decl-options.json, being
// Nix's, does neither. Both renderings are one loop over the table, so
// the binary carries the doc text once, the text `flong schema` already
// holds, and a table beside it.

/// One field of the declaration, as the reference prints it.
pub const Entry = struct {
    /// Dotted, from the declaration's top: a list's element is `*`, and
    /// a union's option is its tag, `network.forwardPorts.ports.*.hostPort`.
    path: []const u8,
    /// The type as ZON writes it (`typeText`).
    type: []const u8,
    /// The default as ZON writes it, or null when the field is required.
    default: ?[]const u8,
    /// A list whose definitions Nix concatenates in order: decl-options.json's
    /// `merge: ordered`.
    ordered: bool,
    /// `Declaration.computed`, or below one: the NixOS module works it out,
    /// and a declaration written by hand sets it.
    computed: bool,
    /// The doc comment, Markdown, lines kept.
    doc: []const u8,
};

/// Every field, in declaration order, a struct's fields after it.
pub const rows: []const Entry = blk: {
    @setEvalBranchQuota(1_000_000);
    const all = entriesOf(decl.Declaration, "", false);
    // The reference heads the computed fields once, so they come last.
    var seen = false;
    for (all) |e| {
        if (e.computed) seen = true else if (seen) @compileError(e.path ++ " follows a computed field: computed fields come last in Declaration");
    }
    const table = all[0..all.len].*;
    break :blk &table;
};

fn entriesOf(comptime T: type, comptime prefix: []const u8, comptime computed: bool) []const Entry {
    var out: []const Entry = &.{};
    for (@typeInfo(T).@"struct".fields) |f| {
        const path = if (prefix.len == 0) f.name else prefix ++ "." ++ f.name;
        const c = computed or (T == decl.Declaration and isComputed(f.name));
        out = out ++ [_]Entry{.{
            .path = path,
            .type = typeText(f.type, metaOf(T, f.name)),
            .default = if (f.defaultValue()) |d| zonValue(f.type, d) else null,
            .ordered = ordered(f.type),
            .computed = c,
            .doc = docFor(T, f.name, path),
        }};
        out = out ++ childrenOf(f.type, path, c);
    }
    return out;
}

/// The fields a value of `T` holds, when it holds any: a struct's, a list
/// element's under `*`, a union option's under its tag.
fn childrenOf(comptime T: type, comptime path: []const u8, comptime computed: bool) []const Entry {
    const U = unwrap(T);
    if (U == decl.Command or isString(U)) return &.{};
    return switch (@typeInfo(U)) {
        .pointer => |p| childrenOf(p.child, path ++ ".*", computed),
        .@"struct" => entriesOf(U, path, computed),
        .@"union" => |u| blk: {
            var out: []const Entry = &.{};
            for (u.fields) |x| out = out ++ childrenOf(x.type, path ++ "." ++ x.name, computed);
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
            for (e.fields, 0..) |x, n| s = s ++ (if (n == 0) " ." else ", .") ++ x.name;
            break :blk s;
        },
        .pointer => |p| if (isString(U))
            (if (m.pattern) |pattern| "string matching " ++ pattern else "string")
        else
            "list of " ++ typeText(p.child, m),
        .@"struct" => "struct",
        .@"union" => |u| blk: {
            var s: []const u8 = "";
            for (u.fields, 0..) |x, n| {
                s = s ++ (if (n == 0) "" else " | ") ++ if (x.type == void)
                    "." ++ x.name
                else
                    ".{ ." ++ x.name ++ " = " ++ typeText(x.type, metaOf(U, x.name)) ++ " }";
            }
            break :blk s;
        },
        else => @compileError("no reference type for " ++ @typeName(U)),
    };
    return if (U != T) base ++ ", or null" else base;
}

/// A value as ZON writes it: `.tag` for an enum's tag and a void union
/// field, `.{ .tag = V }` for a union's other fields, `.{}` for an empty
/// list and for a struct of its own defaults, whose other fields it
/// names otherwise.
fn zonValue(comptime T: type, comptime v: T) []const u8 {
    return switch (@typeInfo(T)) {
        .optional => |o| if (v) |x| zonValue(o.child, x) else "null",
        .bool => if (v) "true" else "false",
        .int => std.fmt.comptimePrint("{d}", .{v}),
        .@"enum" => "." ++ @tagName(v),
        .pointer => |p| if (isString(T))
            std.fmt.comptimePrint("\"{f}\"", .{std.zig.fmtString(v)})
        else if (v.len == 0)
            ".{}"
        else blk: {
            var s: []const u8 = ".{ ";
            for (v, 0..) |x, n| s = s ++ (if (n == 0) "" else ", ") ++ zonValue(p.child, x);
            break :blk s ++ " }";
        },
        .@"struct" => |st| blk: {
            var s: []const u8 = "";
            for (st.fields) |f| {
                const x = @field(v, f.name);
                const same = if (f.defaultValue()) |d| equal(f.type, x, d) else false;
                if (!same) s = s ++ (if (s.len == 0) ".{ ." else ", .") ++ f.name ++ " = " ++ zonValue(f.type, x);
            }
            break :blk if (s.len == 0) ".{}" else s ++ " }";
        },
        .@"union" => blk: {
            const tag = @tagName(std.meta.activeTag(v));
            const P = @FieldType(T, tag);
            break :blk if (P == void) "." ++ tag else ".{ ." ++ tag ++ " = " ++ zonValue(P, @field(v, tag)) ++ " }";
        },
        else => @compileError("no ZON value for " ++ @typeName(T)),
    };
}

/// How the reference is written: plain text for a terminal (`flong help
/// decl`), or Markdown (`flong help decl --markdown`, docs/declaration.md).
pub const Style = enum { text, markdown };

/// What a declaration is and how the types read, before the fields; the
/// same words in both styles, backticks and all.
const reference_intro =
    \\A declaration is one ZON file (Zig Object Notation): a struct literal,
    \\`.{ .field = value, ... }`, holding the fields below. `flong check`
    \\judges one and `flong launch` runs one, with the same parser: a field
    \\not listed here, a required one left out, or a value of the wrong type
    \\is refused with its line and column. A field with a default may be
    \\left out.
    \\
    \\The NixOS module writes each `flong.<name>` to `/etc/flong/<name>.zon`,
    \\from options of the same names, and works out the computed fields at
    \\the end. A declaration written by hand sets those too. The
    \\descriptions are the module's as well, so some examples are Nix's:
    \\`[ ]` and `{ }` are `.{}` in ZON, a string such as `"auto"` is the
    \\enum literal `.auto`, and `{ target = lower; }` is
    \\`.{ .{ .target = "...", .lower = "..." } }`.
    \\
    \\Each field has its path, dotted from the top: a list's element is `*`
    \\and a union's option is its tag. Its type is one of:
    \\
;

/// The types' words: a list in text, a table in Markdown, whose cells
/// read each newline as a space.
const type_words = [_]struct { []const u8, []const u8 }{
    .{ "string", "a string literal, `\"text\"`" },
    .{ "string matching P", "a string the regular expression P matches whole" },
    .{ "bool", "`true` or `false`" },
    .{ "integer A..B", "a whole number from A to B" },
    .{ "one of .a, .b", "an enum literal, `.a`" },
    .{ "command", "`.{ \"program\", \"argument\", ... }`, not empty, and never\nread by a shell: the program is run as it is, or looked up\non `PATH` when it has no `/`" },
    .{ "list of X", "`.{ X, X, ... }`; `.{}` is empty" },
    .{ "struct", "`.{ .field = value, ... }`, its fields listed after it" },
    .{ "A | B", "a union: one of its options, each `.tag` alone or\n`.{ .tag = value }`" },
    .{ "..., or null", "`null` is a value too" },
};

const reference_ordered =
    \\A list marked ordered keeps its order, so a list of commands runs
    \\them one after another; the NixOS module concatenates its
    \\definitions in `mkOrder` order (`mkBefore`, `mkAfter`).
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

fn writeEntry(w: *std.Io.Writer, e: Entry, style: Style) std.Io.Writer.Error!void {
    switch (style) {
        .text => {
            try w.print("{s}\n    type: {s}\n", .{ e.path, e.type });
            if (e.default) |d| try w.print("    default: {s}\n", .{d}) else try w.writeAll("    required\n");
            if (e.ordered) try w.writeAll("    ordered\n");
            if (e.computed) try w.writeAll("    computed\n");
            try w.writeByte('\n');
            try writeProse(w, e.doc, "    ", style);
            try w.writeByte('\n');
        },
        .markdown => {
            try w.print("### `{s}`\n\n- type: `{s}`\n", .{ e.path, e.type });
            if (e.default) |d| try w.print("- default: `{s}`\n", .{d}) else try w.writeAll("- required\n");
            if (e.ordered) try w.writeAll("- ordered\n");
            if (e.computed) try w.writeAll("- computed\n");
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

    // And the fields below them, where ZON's path and Nix's agree.
    for ([_][]const u8{ "network.hostPorts", "limits.CPUWeight", "seccomp.errno", "containerMounts.*.kind", "seccompProject.dump" }) |p| {
        try testing.expectEqualStrings(find(top, p).?.get("doc").?.string, entry(p).?.doc);
    }
}

test "the reference spells each type and default as ZON does" {
    const Case = struct { path: []const u8, type: []const u8, default: ?[]const u8 };
    for ([_]Case{
        .{ .path = "user", .type = "string", .default = null },
        .{ .path = "command", .type = "command", .default = null },
        .{ .path = "workspace", .type = "command, or null", .default = "null" },
        .{ .path = "guard", .type = "list of command", .default = ".{}" },
        .{ .path = "masks", .type = "list of string matching /.*", .default = ".{}" },
        .{ .path = "network", .type = "struct, or null", .default = "null" },
        .{ .path = "network.forwardPorts", .type = ".auto | .{ .ports = list of struct }", .default = ".{ .ports = .{} }" },
        .{ .path = "network.forwardPorts.ports.*.protocol", .type = "one of .tcp, .udp", .default = ".tcp" },
        .{ .path = "network.forwardPorts.ports.*.hostPort", .type = "integer 0..65535", .default = null },
        .{ .path = "network.forwardPorts.ports.*.containerPort", .type = "integer 0..65535, or null", .default = "null" },
        .{ .path = "network.hostLoopbackToSession", .type = "bool", .default = "false" },
        .{ .path = "overlays", .type = "list of struct", .default = ".{}" },
        .{ .path = "overlays.*.target", .type = "string", .default = null },
        .{ .path = "limits", .type = "struct", .default = ".{}" },
        .{ .path = "limits.MemoryMax", .type = ".infinity | .{ .bytes = integer 0..9223372036854775807 } | .{ .size = string matching [0-9]+[KMGT] }, or null", .default = "null" },
        .{ .path = "limits.TasksMax", .type = ".infinity | .{ .count = integer 1..9223372036854775807 }, or null", .default = "null" },
        .{ .path = "limits.CPUQuota", .type = "string matching [1-9][0-9]*%, or null", .default = "null" },
        .{ .path = "limits.CPUWeight", .type = "integer 1..10000, or null", .default = "null" },
        .{ .path = "seccomp.tier", .type = "one of .parity, .strict, or null", .default = ".strict" },
        .{ .path = "seccomp.errno", .type = "one of .EPERM, .EACCES, .ENOSYS", .default = ".EPERM" },
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
    // A union's option is its tag, where the schema's path skips it.
    try testing.expectEqual(null, entry("network.forwardPorts.*.hostPort"));
}

test "a default that is not its type's own is written out" {
    try testing.expectEqualStrings(
        ".{ .MemoryMax = .infinity, .TasksMax = .{ .count = 4096 }, .CPUQuota = \"200%\" }",
        comptime zonValue(decl.Limits, .{ .MemoryMax = .infinity, .TasksMax = .{ .count = 4096 }, .CPUQuota = "200%" }),
    );
    try testing.expectEqualStrings(
        ".{ .{ .target = \"/a\", .lower = \"/b \\\"c\\\"\" } }",
        comptime zonValue([]const decl.Overlay, &.{.{ .target = "/a", .lower = "/b \"c\"" }}),
    );
    try testing.expectEqualStrings(".{ \"git\", \"status\" }", comptime zonValue(decl.Command, &.{ "git", "status" }));
    try testing.expectEqualStrings(".auto", comptime zonValue(decl.ForwardPorts, .auto));
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
    try testing.expect(std.mem.startsWith(u8, text, "The declaration\n===============\n\nA declaration is one ZON file"));
    try testing.expect(std.mem.endsWith(u8, text, ".\n") and !std.mem.endsWith(u8, text, "\n\n"));
    try testing.expect(std.mem.indexOf(u8, text, "\nFields\n------\n\nuser\n    type: string\n    required\n\n    User inside the container") != null);
    try testing.expect(std.mem.indexOf(u8, text, "\nseccomp.tier\n    type: one of .parity, .strict, or null\n    default: .strict\n\n    `parity` is exactly") != null);
    try testing.expect(std.mem.indexOf(u8, text, "\nguard\n    type: list of command\n    default: .{}\n    ordered\n\n") != null);
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
    try testing.expect(std.mem.indexOf(u8, md, "\n## Fields\n\n### `user`\n\n- type: `string`\n- required\n\nUser inside") != null);
    try testing.expect(std.mem.indexOf(u8, md, "\n### `seccomp.tier`\n\n- type: `one of .parity, .strict, or null`\n- default: `.strict`\n\n") != null);
    try testing.expect(std.mem.indexOf(u8, md, "\n## Computed fields\n\n") != null);
    // A table cell's `|` is escaped, and its newlines are spaces.
    try testing.expect(std.mem.indexOf(u8, md, "| `A \\| B` | a union: one of its options, each `.tag` alone or `.{ .tag = value }` |\n") != null);
    // Markdown as it was written.
    try testing.expect(std.mem.indexOf(u8, md, "[pasta](https://passt.top)") != null);

    // Twice the same bytes.
    try testing.expectEqualStrings(md, try reference(a, .markdown));
}
