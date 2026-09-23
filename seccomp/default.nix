# flong-seccomp: the compiler from flong's policy lines to a BPF filter, in
# Zig (src/seccomp/), built by native.nix's `seccomp` set. This file stays
# so that module.nix, flake.nix and tests/parity.nix import it as before.
#
# pkgs defaults to the flake's locked nixpkgs, as the launcher's does, so a
# build outside the flake links the same libseccomp.
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
(import ../native.nix { inherit pkgs; }).seccomp
