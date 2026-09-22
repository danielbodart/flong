# The launcher and util-linux in one tree, for the test wrapper:
#   nix-build launcher/test -o launcher/test/result
# launch.sh finds flong-launch, flong-sweeper and flong-init in result/bin, and
# the unshare, nsenter and flock it prepares roots and takes locks with next to
# them. pkgs is the launcher's own default, the flake's locked nixpkgs, so both
# come from one package set.
{
  pkgs ?
    let
      locked = (builtins.fromJSON (builtins.readFile ../../flake.lock)).nodes.nixpkgs.locked;
    in
    import (fetchTarball {
      url = "https://github.com/${locked.owner}/${locked.repo}/archive/${locked.rev}.tar.gz";
      sha256 = locked.narHash;
    }) { },
}:
pkgs.symlinkJoin {
  name = "flong-launcher-test";
  paths = [
    (import ../. { inherit pkgs; })
    pkgs.util-linux
  ];
}
