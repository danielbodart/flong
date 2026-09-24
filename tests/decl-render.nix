# Every declaration the VM tests make, as module.nix renders it to
# /etc/flong/<name>.zon, parsed by src/decl.zig's own parser
# (tests/zig/declparse.zig): what a launch will read is what the type says.
# `flong check` in each declaration's derivation makes the same parse, and
# judges what it read, at every build (STANDALONE.md, S2), so building the
# rendered files here runs it on every test declaration too; this adds the
# escapes and the control.
#
# `nodes` is each VM test's node, by test name; flake.nix passes them from
# the checks, whose nodes are the evaluated NixOS configurations. Only
# their rendered files are built, never a VM.
#
# Two more files: a declaration whose strings hold every character a
# rendered string must escape, which must parse, and the control, a
# declaration of the wrong shape, which must not.
{ pkgs, nodes }:
let
  inherit (pkgs) lib;
  native = import ../native.nix { inherit pkgs; };
  toZon = import ../nix/to-zon.nix { inherit lib; };

  parser = native.zigSet {
    pname = "flong-decl-parse";
    steps = "decl-parse";
    optimizeFlag = "";
    files = [
      ../src/sys.zig
      ../src/errno.zig
      ../src/msg.zig
      ../src/fd.zig
      ../src/decl.zig
      ../tests/zig/declparse.zig
    ];
  };

  rendered = lib.concatLists (lib.mapAttrsToList
    (_: node: lib.mapAttrsToList (_: e: toString e.source)
      (lib.filterAttrs (n: _: lib.hasPrefix "flong/" n && lib.hasSuffix ".zon" n) node.environment.etc))
    nodes);

  # Every control character a Nix string can hold, DEL, a quote, a
  # backslash and some UTF-8, in a command's words.
  controls = map (i: builtins.fromJSON ''"\u00${lib.fixedWidthString 2 "0" (lib.toHexString i)}"'')
    (lib.range 1 31 ++ [ 127 ]);
  escapes = pkgs.writeText "escapes.zon" (toZon.toZON toZon.enumPaths {
    user = "alice";
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
  });

  # The control: a snippet where a command goes, as the options took one
  # before S2.
  wrong = pkgs.writeText "wrong.zon" (toZon.toZON toZon.enumPaths {
    user = "alice";
    command = [ "true" ];
    guard = "test -d $workspace";
    container = "box";
    closure = "/nix/store/x-nixos-system-box";
    cuid = 1000;
    cgid = 100;
    steps8 = "0123abcd";
    name = "box";
    payload = "/nix/store/x-payload/bin/flong-payload-box";
  });
in
assert rendered != [ ];
pkgs.runCommand "decl-render" { nativeBuildInputs = [ parser ]; } ''
  flong-decl-parse ${lib.escapeShellArgs rendered} ${escapes} 2>parsed || {
    cat parsed >&2
    exit 1
  }
  cat parsed
  n=$(grep -c '^ok ' parsed)
  [ "$n" -eq ${toString (lib.length rendered + 1)} ] || { echo "decl-render: $n parsed" >&2; exit 1; }

  if flong-decl-parse ${wrong} 2>refused; then
    echo "decl-render: the control parsed" >&2
    exit 1
  fi
  grep -q 'wrong.zon:[0-9]*:[0-9]*: ' refused || { cat refused >&2; exit 1; }

  echo "${toString (lib.length rendered)} rendered declarations parse" > $out
''
