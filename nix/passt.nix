# passt, whose pasta flong launch runs for a network, from flake.lock's
# nixpkgs-unstable whatever nixpkgs flong is built with: what -t means
# changed in 2026_07 (auto became a modifier on a port set, and an address
# may bind it), flong's checks run that pasta, and nixos-26.05, the
# nixpkgs everything else comes from, has 2025_09_19. So a host on 26.05,
# or one whose flake input `follows` its own nixpkgs, gets the pasta the
# checks ran. Read from the lock rather than taken as an input, so that
# module.nix, which has no flake inputs, gets it too.
{ system }:
let
  lock = builtins.fromJSON (builtins.readFile ../flake.lock);
  locked = lock.nodes.${lock.nodes.root.inputs.nixpkgs-unstable}.locked;
in
(import (fetchTarball {
  url = "https://github.com/${locked.owner}/${locked.repo}/archive/${locked.rev}.tar.gz";
  sha256 = locked.narHash;
}) { inherit system; }).passt
