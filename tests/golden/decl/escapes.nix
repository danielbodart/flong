# The declaration escapes.json is, as builtins.toJSON writes it: every
# control character a Nix string can hold (all but NUL), DEL, a quote, a
# backslash and some UTF-8, in a command's words. tests/golden.nix holds
# escapes.json to being this value's render, so the case pins what Nix
# writes as well as what decl.zig reads of it.
{ lib }:
let
  controls = map (i: builtins.fromJSON ''"\u00${lib.fixedWidthString 2 "0" (lib.toHexString i)}"'')
    (lib.range 1 31 ++ [ 127 ]);
in
{
  user = "u";
  command = [ "printf" (lib.concatStrings controls) "\"quoted\" \\ back" "é ☃" ];
  container = "box";
  closure = "/nix/store/x-nixos-system-box";
  cuid = 1000;
  cgid = 100;
  steps8 = "0123abcd";
  name = "box";
  seccomp.tier = "parity";
  network.forwardPorts = "auto";
}
