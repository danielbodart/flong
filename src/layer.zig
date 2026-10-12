//! layer.zig: `flong check --layer project [--base BASE.json] LAYER.json`,
//! a project's layer judged before it is merged over a declaration
//! (DESIGN.md, "Layers").
//!
//! A layer is a JSON object of the declaration's fields, any of them left
//! out, merged over the declaration beneath it as a JSON Merge Patch (RFC
//! 7396): an object merges field by field, `null` removes what is beneath,
//! and anything else, a list included, replaces it whole. A project's layer
//! is refused when it:
//!
//!   - sets a field whose scope is `host` (decl.Scope, the schema's
//!     `x-scope`), or anything below one, whatever the value: the field is
//!     the host's to set;
//!   - gives `null` for a field with a host field below it, which would
//!     remove that too (`seccomp`, `network`);
//!   - gives a field the declaration does not have, or a value its type
//!     does not take, judged as `flong check` judges a declaration's;
//!   - gives `network` where the base has none, which would make one whose
//!     host fields no host set;
//!   - leaves `seccomp.tier`, the one `tighten` field, less strict than the
//!     base's: strict over parity over none (decl.tierRank).
//!
//! With `--base`, the base is that declaration, and the merged result is
//! then judged whole, as `flong check` judges any declaration; without, it
//! is the declaration's defaults, `strict` and no network, and each value
//! the layer gives is judged on its own.
//!
//! Every refusal is collected, not only the first, and each is said as
//! `flong check: LAYER: why`; a layer or base that cannot be read or
//! parsed is said with its line and column. Exit as `flong check`'s.

const std = @import("std");
const msg = @import("msg");
const decl = @import("decl");
const check = @import("check.zig");

const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const Declaration = decl.Declaration;

/// What a layer is judged against: a declaration file, or the defaults.
pub const Base = union(enum) {
    defaults,
    file: [:0]const u8,
};

/// Every refusal of the layer at `path` over `base`, each one line; empty
/// when it may be merged. A file that cannot be read or parsed is said
/// here and returned as `error.Reported`.
pub fn judge(arena: Allocator, path: [:0]const u8, base: Base) (msg.Error || error{OutOfMemory})![]const []const u8 {
    const layer = try readJson(arena, path);
    var l: Layer = .{ .arena = arena, .judge_values = base == .defaults };
    if (layer != .object) {
        try l.say("a layer is a JSON object of the declaration's fields, not {s}", .{kindName(layer)});
        return l.out.items;
    }
    try l.fields(Declaration, layer.object, "");
    // A value of the wrong type, judged on its own already, would only be
    // said again by the merge.
    if (l.out.items.len != 0) return l.out.items;

    const below: Value = switch (base) {
        .defaults => .{ .object = .init(arena) },
        .file => |b| blk: {
            // A base that is no declaration is said as `flong check`
            // says it, at its own line and column.
            _ = try decl.load(arena, b);
            break :blk try readJson(arena, b);
        },
    };
    const merged = try mergePatch(arena, below, layer);
    try l.network(below, merged);
    try l.tier(below, merged);

    if (base == .file) {
        const text = try std.json.Stringify.valueAlloc(arena, merged, .{});
        var diag: decl.Diag = .{};
        const d = decl.parse(arena, text, &diag) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.ParseJson => {
                try l.say("merged over {s}: {s}", .{ base.file, diag.message });
                return l.out.items;
            },
        };
        try l.out.appendSlice(arena, try check.validate(arena, &d));
    }
    return l.out.items;
}

/// The file at `path` as JSON, strictly: a field given twice is refused,
/// as decl.parse refuses one. Numbers are kept as written, so a value
/// judged on its own is judged as the file spells it.
fn readJson(arena: Allocator, path: [:0]const u8) (msg.Error || error{OutOfMemory})!Value {
    const source = try decl.readBounded(arena, path);
    var scanner = std.json.Scanner.initCompleteInput(arena, source);
    var diagnostics: std.json.Diagnostics = .{};
    scanner.enableDiagnostics(&diagnostics);
    return std.json.parseFromTokenSourceLeaky(Value, arena, &scanner, .{
        .duplicate_field_behavior = .@"error",
        .parse_numbers = false,
    }) catch |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        const why = switch (err) {
            error.DuplicateField => "a field given twice",
            error.UnexpectedEndOfInput => "not JSON: unexpected end of file",
            else => "not JSON",
        };
        msg.say("{s}", .{try std.fmt.allocPrint(arena, "{s}:{d}:{d}: {s}", .{ path, diagnostics.getLine(), diagnostics.getColumn(), why })});
        return error.Reported;
    };
}

/// RFC 7396's MergePatch(target, patch), in `arena`: a patch that is not
/// an object replaces the target; an object's `null` removes the target's
/// field, and any other field is merged into the target's own.
pub fn mergePatch(arena: Allocator, target: Value, patch: Value) Allocator.Error!Value {
    if (patch != .object) return patch;
    var out: std.json.ObjectMap = .init(arena);
    if (target == .object) {
        var it = target.object.iterator();
        while (it.next()) |kv| try out.put(kv.key_ptr.*, kv.value_ptr.*);
    }
    var it = patch.object.iterator();
    while (it.next()) |kv| {
        if (kv.value_ptr.* == .null) {
            _ = out.orderedRemove(kv.key_ptr.*);
        } else {
            const beneath = out.get(kv.key_ptr.*) orelse .null;
            try out.put(kv.key_ptr.*, try mergePatch(arena, beneath, kv.value_ptr.*));
        }
    }
    return .{ .object = out };
}

fn kindName(v: Value) []const u8 {
    return switch (v) {
        .null => "null",
        .bool => "a boolean",
        .integer, .float, .number_string => "a number",
        .string => "a string",
        .array => "an array",
        .object => "an object",
    };
}

fn unwrap(comptime T: type) type {
    return switch (@typeInfo(T)) {
        .optional => |o| o.child,
        else => T,
    };
}

fn isStruct(comptime T: type) bool {
    return @typeInfo(T) == .@"struct" and !@hasDecl(T, "attrs");
}

fn isAttrs(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .pointer => |p| @typeInfo(p.child) == .@"struct" and @hasDecl(p.child, "attrs"),
        else => false,
    };
}

/// The host fields below a struct `T`'s, by their paths under `prefix`,
/// comma-separated: what a `null` for it would remove.
fn hostFields(comptime T: type, comptime prefix: []const u8) []const u8 {
    return comptime blk: {
        var s: []const u8 = "";
        for (@typeInfo(T).@"struct".fields) |f| {
            const path = prefix ++ "." ++ f.name;
            const U = unwrap(f.type);
            const more = if (decl.scopeOf(T, f.name) == .host)
                path
            else if (isStruct(U))
                hostFields(U, path)
            else
                "";
            if (more.len != 0) s = s ++ (if (s.len == 0) "" else ", ") ++ more;
        }
        break :blk s;
    };
}

const Layer = struct {
    arena: Allocator,
    /// Without a base, each value is judged on its own, as nothing judges
    /// the merged result.
    judge_values: bool,
    out: std.ArrayList([]const u8) = .empty,

    fn say(l: *Layer, comptime fmt: []const u8, args: anytype) Allocator.Error!void {
        try l.out.append(l.arena, try std.fmt.allocPrint(l.arena, fmt, args));
    }

    /// The fields of `obj`, a layer of a `T` at `prefix`.
    fn fields(l: *Layer, comptime T: type, obj: std.json.ObjectMap, comptime prefix: []const u8) Allocator.Error!void {
        var it = obj.iterator();
        while (it.next()) |kv| {
            const name = kv.key_ptr.*;
            var known = false;
            inline for (@typeInfo(T).@"struct".fields) |f| {
                if (std.mem.eql(u8, f.name, name)) {
                    known = true;
                    const path = if (prefix.len == 0) f.name else prefix ++ "." ++ f.name;
                    try l.field(T, f.name, f.type, kv.value_ptr.*, path);
                }
            }
            if (!known) {
                const where = if (prefix.len == 0) "the declaration" else prefix;
                try l.say("{f} is not a field of {s}", .{ std.json.fmt(name, .{}), where });
            }
        }
    }

    fn field(l: *Layer, comptime T: type, comptime name: []const u8, comptime F: type, v: Value, comptime path: []const u8) Allocator.Error!void {
        const U = unwrap(F);
        if (decl.scopeOf(T, name) == .host)
            return l.say(path ++ " is the host's to set, and a project's layer may not set it", .{});
        if (v == .null) {
            if (comptime isStruct(U)) {
                const host = comptime hostFields(U, path);
                if (host.len != 0)
                    return l.say(path ++ ": null would remove " ++ host ++ " with it, which are the host's to set", .{});
            }
            return;
        }
        // An object merges into the struct beneath, field by field.
        if (comptime isStruct(U)) if (v == .object) return l.fields(U, v.object, path);
        // An attribute set merges name by name, and a null removes one.
        const given = if (comptime isAttrs(U)) if (v == .object) try withoutNulls(l.arena, v) else v else v;
        try l.value(F, given, path);
    }

    /// A value the layer gives whole, judged as the declaration's parse,
    /// then its check, would judge the field's.
    fn value(l: *Layer, comptime F: type, v: Value, comptime path: []const u8) Allocator.Error!void {
        const text = try std.json.Stringify.valueAlloc(l.arena, v, .{});
        var diag: decl.Diag = .{};
        const x = decl.parseAs(l.arena, F, text, &diag) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.ParseJson => {
                if (diag.note) |n| return l.say(path ++ ": {s} ({s})", .{ diag.message, n });
                return l.say(path ++ ": {s}", .{diag.message});
            },
        };
        if (!l.judge_values) return;
        var c: check.Checker = .{ .arena = l.arena, .d = undefined, .n = "project" };
        try c.walk(F, x, path, false, .{});
        try l.out.appendSlice(l.arena, c.out.items);
    }

    /// `network` given where there is none beneath: a network whose
    /// forwardAddress, forwardInterface and hostLoopbackToSession nobody
    /// set but the defaults.
    fn network(l: *Layer, below: Value, merged: Value) Allocator.Error!void {
        if (present(below, "network") or !present(merged, "network")) return;
        try l.say("network is given where the base has none, and a project's layer cannot add one: whether a container has a network, and its " ++
            comptime hostFields(decl.Network, "network") ++ ", are the host's to set", .{});
    }

    /// `seccomp.tier` no less strict than beneath (`Scope.tighten`).
    fn tier(l: *Layer, below: Value, merged: Value) Allocator.Error!void {
        const was = tierOf(l.arena, below) orelse return;
        const is = tierOf(l.arena, merged) orelse return;
        if (decl.tierRank(is) >= decl.tierRank(was)) return;
        try l.say("seccomp.tier would be {s} over the base's {s}: a project's layer may make the tier stricter, never less strict (strict, then parity, then null)", .{ tierName(is), tierName(was) });
    }
};

fn present(v: Value, name: []const u8) bool {
    if (v != .object) return false;
    const x = v.object.get(name) orelse return false;
    return x != .null;
}

/// The tier a declaration's JSON says, its default when it says none;
/// null when it says something that is not a tier, which its own
/// judging refuses.
fn tierOf(arena: Allocator, v: Value) ??decl.Tier {
    const default: decl.Seccomp = .{};
    if (v != .object) return default.tier;
    const s = v.object.get("seccomp") orelse return default.tier;
    if (s != .object) return default.tier;
    const t = s.object.get("tier") orelse return default.tier;
    const text = std.json.Stringify.valueAlloc(arena, t, .{}) catch return null;
    const tier_given = decl.parseAs(arena, ?decl.Tier, text, null) catch return null;
    return tier_given;
}

fn tierName(t: ?decl.Tier) []const u8 {
    return if (t) |x| @tagName(x) else "null";
}

/// An attribute set's entries without the ones a merge removes.
fn withoutNulls(arena: Allocator, v: Value) Allocator.Error!Value {
    var out: std.json.ObjectMap = .init(arena);
    var it = v.object.iterator();
    while (it.next()) |kv| if (kv.value_ptr.* != .null) try out.put(kv.key_ptr.*, kv.value_ptr.*);
    return .{ .object = out };
}

// ---- tests ----

const testing = std.testing;

fn parsed(arena: Allocator, text: []const u8) !Value {
    return std.json.parseFromSliceLeaky(Value, arena, text, .{ .parse_numbers = false });
}

fn mergedText(arena: Allocator, target: []const u8, patch: []const u8) ![]const u8 {
    return std.json.Stringify.valueAlloc(arena, try mergePatch(arena, try parsed(arena, target), try parsed(arena, patch)), .{});
}

test "mergePatch is RFC 7396's, its appendix's cases" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const cases = [_][3][]const u8{
        .{ "{\"a\":\"b\"}", "{\"a\":\"c\"}", "{\"a\":\"c\"}" },
        .{ "{\"a\":\"b\"}", "{\"b\":\"c\"}", "{\"a\":\"b\",\"b\":\"c\"}" },
        .{ "{\"a\":\"b\"}", "{\"a\":null}", "{}" },
        .{ "{\"a\":\"b\",\"b\":\"c\"}", "{\"a\":null}", "{\"b\":\"c\"}" },
        .{ "{\"a\":[\"b\"]}", "{\"a\":\"c\"}", "{\"a\":\"c\"}" },
        .{ "{\"a\":\"c\"}", "{\"a\":[\"b\"]}", "{\"a\":[\"b\"]}" },
        .{ "{\"a\":{\"b\":\"c\"}}", "{\"a\":{\"b\":\"d\",\"c\":null}}", "{\"a\":{\"b\":\"d\"}}" },
        .{ "{\"a\":[{\"b\":\"c\"}]}", "{\"a\":[1]}", "{\"a\":[1]}" },
        .{ "[\"a\",\"b\"]", "[\"c\",\"d\"]", "[\"c\",\"d\"]" },
        .{ "{\"a\":\"b\"}", "[\"c\"]", "[\"c\"]" },
        .{ "{\"a\":\"foo\"}", "null", "null" },
        .{ "{\"a\":\"foo\"}", "\"bar\"", "\"bar\"" },
        .{ "{\"e\":null}", "{\"a\":1}", "{\"e\":null,\"a\":1}" },
        .{ "[1,2]", "{\"a\":\"b\",\"c\":null}", "{\"a\":\"b\"}" },
        .{ "{}", "{\"a\":{\"bb\":{\"ccc\":null}}}", "{\"a\":{\"bb\":{}}}" },
    };
    for (cases) |c| try testing.expectEqualStrings(c[2], try mergedText(a, c[0], c[1]));
}

test "a syscall's entry merges name by name, and null removes one" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualStrings(
        "{\"seccomp\":{\"tier\":\"strict\",\"syscalls\":{\"ptrace\":\"allow\",\"io_uring_setup\":\"log\"}}}",
        try mergedText(a,
            \\{"seccomp":{"tier":"strict","syscalls":{"ptrace":"deny","kexec_load":"deny"}}}
        ,
            \\{"seccomp":{"syscalls":{"ptrace":"allow","kexec_load":null,"io_uring_setup":"log"}}}
        ),
    );
}

test "the host fields a null would remove" {
    try testing.expectEqualStrings("seccomp.nestedSandbox, seccomp.errno", hostFields(decl.Seccomp, "seccomp"));
    try testing.expectEqualStrings("network.forwardAddress, network.forwardInterface, network.hostLoopbackToSession", hostFields(decl.Network, "network"));
    try testing.expectEqualStrings("", hostFields(decl.Limits, "limits"));
}

/// The refusals of a layer's text over the defaults, as `judge` makes them
/// from a file.
fn refusalsOf(arena: Allocator, text: []const u8) ![]const []const u8 {
    const layer = try parsed(arena, text);
    var l: Layer = .{ .arena = arena, .judge_values = true };
    try l.fields(Declaration, layer.object, "");
    if (l.out.items.len != 0) return l.out.items;
    const below: Value = .{ .object = .init(arena) };
    const m = try mergePatch(arena, below, layer);
    try l.network(below, m);
    try l.tier(below, m);
    return l.out.items;
}

test "a project's layer: what it may set, and what is the host's" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqual(@as(usize, 0), (try refusalsOf(a,
        \\{"seccomp":{"syscalls":{"io_uring_setup":"allow","ptrace":null},"debug":true,"tier":"strict"},
        \\ "limits":{"MemoryMax":"8G","TasksMax":null}}
    )).len);
    const r = try refusalsOf(a,
        \\{"user":"root","seccomp":{"nestedSandbox":true,"errno":"ENOSYS","syscalls":{"nope":"allow"}},
        \\ "masks":[],"seccompTierFilter":null,"limits":null,"bogus":1}
    );
    try testing.expectEqualStrings("user is the host's to set, and a project's layer may not set it", r[0]);
    try testing.expectEqualStrings("seccomp.nestedSandbox is the host's to set, and a project's layer may not set it", r[1]);
    try testing.expectEqualStrings("seccomp.errno is the host's to set, and a project's layer may not set it", r[2]);
    try testing.expect(std.mem.startsWith(u8, r[3], "flong.project.seccomp.syscalls has \"nope\", which is not a system call"));
    try testing.expectEqualStrings("masks is the host's to set, and a project's layer may not set it", r[4]);
    try testing.expectEqualStrings("seccompTierFilter is the host's to set, and a project's layer may not set it", r[5]);
    try testing.expectEqualStrings("\"bogus\" is not a field of the declaration", r[6]);
    try testing.expectEqual(@as(usize, 7), r.len);
}

test "a null over a struct holding host fields, and a network made" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const r = try refusalsOf(a,
        \\{"seccomp":null}
    );
    try testing.expectEqualStrings("seccomp: null would remove seccomp.nestedSandbox, seccomp.errno with it, which are the host's to set", r[0]);
    const n = try refusalsOf(a,
        \\{"network":{"hostPorts":[5432]}}
    );
    try testing.expectEqual(@as(usize, 1), n.len);
    try testing.expect(std.mem.startsWith(u8, n[0], "network is given where the base has none"));
    const t = try refusalsOf(a,
        \\{"network":{"forwardPorts":"auto","forwardAddress":"0.0.0.0"}}
    );
    try testing.expectEqualStrings("network.forwardAddress is the host's to set, and a project's layer may not set it", t[0]);
}

test "seccomp.tier only tightens: strict, then parity, then null" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // Over the defaults' strict, parity loosens, and null removes the
    // field, which the default puts back.
    const p = try refusalsOf(a,
        \\{"seccomp":{"tier":"parity"}}
    );
    try testing.expectEqualStrings("seccomp.tier would be parity over the base's strict: a project's layer may make the tier stricter, never less strict (strict, then parity, then null)", p[0]);
    try testing.expectEqual(@as(usize, 0), (try refusalsOf(a,
        \\{"seccomp":{"tier":null}}
    )).len);
    // Over parity, strict tightens; over none, either does.
    const below = try parsed(a,
        \\{"seccomp":{"tier":"parity"}}
    );
    var l: Layer = .{ .arena = a, .judge_values = true };
    try l.tier(below, try mergePatch(a, below, try parsed(a,
        \\{"seccomp":{"tier":"strict"}}
    )));
    const none = try parsed(a,
        \\{"seccomp":{"tier":null}}
    );
    try l.tier(none, try mergePatch(a, none, try parsed(a,
        \\{"seccomp":{"tier":"parity"}}
    )));
    try testing.expectEqual(@as(usize, 0), l.out.items.len);
    try l.tier(below, try mergePatch(a, below, try parsed(a,
        \\{"seccomp":{"tier":null}}
    )));
    // Null over parity removes it: the default, strict, tightens.
    try testing.expectEqual(@as(usize, 0), l.out.items.len);
}

test "a value of the wrong type is said at its field" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const r = try refusalsOf(a,
        \\{"seccomp":{"syscalls":{"ptrace":"maybe"},"tier":"loose","debug":1},"limits":7}
    );
    try testing.expectEqualStrings("seccomp.syscalls: unexpected value \"maybe\" (supported: \"allow\", \"deny\", \"log\")", r[0]);
    try testing.expectEqualStrings("seccomp.tier: unexpected value \"loose\" (supported: \"parity\", \"strict\")", r[1]);
    try testing.expectEqualStrings("seccomp.debug: expected true or false", r[2]);
    try testing.expectEqualStrings("limits: expected an object", r[3]);
}
