# The declaration escapes.zon is rendered from, by nix/to-zon.nix: every
# control character a Nix string can hold (all but NUL), DEL, a quote, a
# backslash and some UTF-8, in a command's words. tests/golden.nix holds
# escapes.zon to being this value's render, so the case pins what to-zon
# writes as well as what decl.zig reads of it.
{ lib, toZon }:
let
  controls = map (i: builtins.fromJSON ''"\u00${lib.fixedWidthString 2 "0" (lib.toHexString i)}"'')
    (lib.range 1 31 ++ [ 127 ]);
in
toZon.toZON toZon.enumPaths {
  user = "u";
  command = [ "printf" (lib.concatStrings controls) "\"quoted\" \\ back" "é ☃" ];
  container = "box";
  closure = "/nix/store/x-nixos-system-box";
  cuid = 1000;
  cgid = 100;
  steps8 = "0123abcd";
  name = "box";
  payload = "/nix/store/x-payload/bin/flong-payload-box";
  seccomp.tier = "parity";
  network.forwardPorts = toZon.tag "auto";
}
