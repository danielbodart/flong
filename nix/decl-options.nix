# decl-options.json read back as NixOS options: `{ lib }: entries:` is an
# attrset of lib.mkOption, one per entry with `nixOption`, named by the last
# component of its path. The grammar is src/decl_docs.zig's, which says what
# each type means; this is the one place it becomes lib.types.
#
# An entry's `doc` is its description, Markdown as NixOS reads a plain
# string; `default` is its default unless it is `required`, which has none.
# `merge` needs no reading: a list type concatenates its definitions in
# mkOrder order, which is what `ordered` promises, and every other type
# merges as a single value.
#
# `examples` maps a path (`network.hostPorts`) to an option's example, which
# the schema does not carry: an example is Nix, and is written in Nix.
{
  lib,
  examples ? { },
}:
let
  inherit (lib) types;

  # The largest i64, the schema's max for a u63 and an unbounded count.
  maxInt = 9223372036854775807;

  typeOf =
    t:
    let
      base =
        if t.type == "string" then
          types.str
        else if t.type == "strMatching" then
          types.strMatching t.pattern
        else if t.type == "bool" then
          types.bool
        else if t.type == "port" then
          types.port
        else if t.type == "int" then
          intType t.min t.max
        else if t.type == "enum" then
          types.enum t.tags
        else if t.type == "command" then
          types.nonEmptyListOf types.str
        else if t.type == "list" then
          types.listOf (typeOf t.of)
        else if t.type == "pathAttrs" then
          types.attrsOf types.path
        else if t.type == "struct" then
          types.submodule { options = optionsOf t.fields; }
        else if t.type == "either" then
          types.oneOf (map typeOf t.options)
        else
          throw "decl-options.nix: a type this does not know: ${builtins.toJSON t}";
    in
    if t.nullable or false then types.nullOr base else base;

  # The names Nix has for the ranges the schema writes, so the manual reads
  # "positive integer" rather than a bound no one would type.
  intType =
    min: max:
    if max == maxInt && min == 0 then
      types.ints.unsigned
    else if max == maxInt && min == 1 then
      types.ints.positive
    else if max == maxInt then
      types.addCheck types.int (x: x >= min)
    else
      types.ints.between min max;

  optionOf =
    e:
    lib.mkOption (
      {
        type = typeOf e.type;
        description = e.doc;
      }
      // lib.optionalAttrs (!e.required) { inherit (e) default; }
      // lib.optionalAttrs (examples ? ${e.path}) { example = examples.${e.path}; }
    );

  optionsOf =
    entries:
    lib.listToAttrs (
      map (e: lib.nameValuePair (lib.last (lib.splitString "." e.path)) (optionOf e)) (
        lib.filter (e: e.nixOption) entries
      )
    );
in
optionsOf
