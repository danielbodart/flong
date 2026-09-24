# flong's native launcher: one binary, bin/flong, whose subcommands are
# launch, init and sweeper (src/main.zig), built by native.nix's `launcher`
# set, static and without libc, with the compiled-in store paths there.
# This file stays so that module.nix, flake.nix and the tests import it as
# before.
#
# pkgs defaults to the flake's locked nixpkgs, whose bubblewrap is 0.12: the
# launcher needs 0.12's --overlay-src, --tmp-overlay and --add-seccomp-fd, and
# a channel's <nixpkgs> may be older.
{
  pkgs ?
    let
      locked = (builtins.fromJSON (builtins.readFile ../flake.lock)).nodes.nixpkgs.locked;
    in
    import (fetchTarball {
      url = "https://github.com/${locked.owner}/${locked.repo}/archive/${locked.rev}.tar.gz";
      sha256 = locked.narHash;
    }) { },
}:
(import ../native.nix { inherit pkgs; }).launcher
