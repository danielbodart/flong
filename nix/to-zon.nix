# Rendering a Nix value as ZON, so module.nix can hand flong a declaration
# as a file (src/decl.zig) instead of a header of shell assignments.
# Adapted from capsper's nix/to-zon.nix.
#
# There is no `pkgs.formats.zon`, and ZON is not JSON: containers are
# `.{ ... }` rather than `{ ... }` or `[ ... ]`, struct fields are
# `.name = value`, and an enum is the bare literal `.strict` rather than a
# quoted string.
#
# That last one is the only part with no Nix equivalent, because Nix has no
# enums. Two ways round it, and both are here:
#
#   * `enumPaths` names the fields whose values are enums, so an ordinary Nix
#     string renders as a ZON enum literal: `seccomp.tier = "strict"` stays
#     the option's own value.
#   * `tag "auto"` says so at the point of use, for a tagged union's void
#     field: `forwardPorts = "auto"` is `.auto`, and `TasksMax =
#     "infinity"` `.infinity`, where the union's other fields are
#     `.{ .ports = ... }` and `.{ .count = ... }`.
#
# `enumPaths` duplicates a little of src/decl.zig's schema. What makes it
# safe is that the rendered file is parsed by decl.zig itself -- by the
# decl-render check today, and by `flong check` in the declaration's own
# derivation when that lands -- so drift is a failed build naming the field,
# not a launch that refuses.
{ lib }:

let
  # A ZON enum literal, for a field `enumPaths` does not cover.
  tag = name: { __zonTag = name; };

  isTag = v: builtins.isAttrs v && v ? __zonTag;

  indent = depth: lib.concatStrings (lib.genList (_: "    ") depth);

  # Every control character a Nix string can hold (it cannot hold NUL), and
  # DEL, as Zig's `\xNN`: a Zig string literal refuses them raw. A command's
  # word is data and may hold any of them. The rest of UTF-8 is written as
  # it is, which a Zig literal takes.
  hex2 = i: let h = lib.toLower (lib.toHexString i); in if lib.stringLength h == 1 then "0${h}" else h;
  controls = lib.filter (i: i != 9 && i != 10 && i != 13) (lib.range 1 31 ++ [ 127 ]);
  controlChars = map (i: builtins.fromJSON ''"\u00${hex2 i}"'') controls;
  controlEscapes = map (i: "\\x${hex2 i}") controls;

  # ZON string literals escape as Zig's do.
  escapeString =
    s:
    ''"''
    + lib.replaceStrings
      ([ "\\" "\"" "\n" "\r" "\t" ] ++ controlChars)
      ([ "\\\\" "\\\"" "\\n" "\\r" "\\t" ] ++ controlEscapes)
      s
    + ''"'';

  # `path` is the dotted name of the value being rendered, which is how
  # `enumPaths` is matched; a list's elements have the list's. The top level
  # has no name, so it starts empty.
  render =
    enumPaths: depth: path: value:
    let
      isEnum = builtins.elem path enumPaths;
      pad = indent depth;
      inner = indent (depth + 1);
    in
    if isTag value then
      ".${value.__zonTag}"
    else if value == null then
      "null"
    else if builtins.isBool value then
      (if value then "true" else "false")
    else if builtins.isInt value then
      builtins.toString value
    else if builtins.isString value then
      (if isEnum then ".${value}" else escapeString value)
    else if builtins.isPath value then
      escapeString (toString value)
    else if builtins.isList value then
      (
        if value == [ ] then
          ".{}"
        else
          ".{\n"
          + lib.concatMapStrings (v: "${inner}${render enumPaths (depth + 1) path v},\n") value
          + "${pad}}"
      )
    else if lib.isDerivation value then
      escapeString "${value}"
    else if builtins.isAttrs value then
      (
        let
          # Sorted, so the same declaration always renders to the same bytes
          # and a rebuild that changed nothing makes no new store path.
          names = builtins.attrNames value;
          field =
            name:
            let
              child = if path == "" then name else "${path}.${name}";
            in
            "${inner}.${name} = ${render enumPaths (depth + 1) child value.${name}},\n";
        in
        if names == [ ] then ".{}" else ".{\n" + lib.concatMapStrings field names + "${pad}}"
      )
    else
      throw "toZON: cannot render ${builtins.typeOf value} at '${path}'";

in
{
  inherit tag;

  # The fields src/decl.zig declares as enums, by path. A list's element
  # has its list's path.
  enumPaths = [
    "seccomp.tier"
    "seccomp.errno"
    "network.forwardPorts.ports.protocol"
    "containerMounts.kind"
  ];

  toZON = enumPaths: value: render enumPaths 0 "" value + "\n";
}
