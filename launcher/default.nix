# flong's native launcher: flong-launch, flong-sweeper and flong-init.
#
# The store paths of the programs the launcher runs are compiled in, so the
# wrapper cannot hand it a different bwrap, pasta, tini or flong-init.
# newuidmap and newgidmap are NixOS's setuid wrappers, which have no store
# path.
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
let
  inherit (pkgs) lib;
in
pkgs.runCommandCC "flong-launcher"
  {
    src = lib.fileset.toSource {
      root = ./.;
      fileset = lib.fileset.fileFilter (f: f.hasExt "c" || f.hasExt "h") ./.;
    };
  }
  ''
    mkdir -p $out/bin
    cd $src
    cflags=(
      -std=gnu11 -O2 -D_GNU_SOURCE -Wall -Wextra -Werror
      -DFLONG_BWRAP='"${pkgs.bubblewrap}/bin/bwrap"'
      -DFLONG_PASTA='"${pkgs.passt}/bin/pasta"'
      -DFLONG_TINI='"${pkgs.tini}/bin/tini"'
      -DFLONG_NEWUIDMAP='"/run/wrappers/bin/newuidmap"'
      -DFLONG_NEWGIDMAP='"/run/wrappers/bin/newgidmap"'
      -DFLONG_INIT="\"$out/bin/flong-init\""
    )
    $CC "''${cflags[@]}" -o $out/bin/flong-init flong-init.c
    $CC "''${cflags[@]}" -o $out/bin/flong-launch \
      flong-launch.c flong-spec.c flong-ns.c flong-cgroup.c flong-record.c \
      flong-mount.c flong-tty.c flong-util.c
    $CC "''${cflags[@]}" -o $out/bin/flong-sweeper \
      flong-sweeper.c flong-cgroup.c flong-record.c flong-util.c
  ''
