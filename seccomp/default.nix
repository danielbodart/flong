# flong-seccomp: the compiler from flong's policy lines to a BPF filter.
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
pkgs.runCommandCC "flong-seccomp" { buildInputs = [ pkgs.libseccomp ]; } ''
  mkdir -p $out/bin
  $CC -std=gnu11 -O2 -D_GNU_SOURCE -Wall -Wextra -Werror \
    -o $out/bin/flong-seccomp ${./flong-seccomp.c} -lseccomp
''
