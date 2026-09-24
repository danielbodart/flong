# The parity test's two tools: bpfdump, which dumps a live process's seccomp
# filters and evaluates a stack of them, and syscall-probe, which a session runs as
# its payload. Taken from the seccomp spike, with the sweep made exact. Since
# phase 6 they are Zig (src/fixtures/), native.nix's fixtures set, which also
# holds rootless.nix's ioctl-probe and swapper (tests/probes.nix).
#
# pkgs defaults to the flake's locked nixpkgs, as the launcher's does.
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
(import ../../native.nix { inherit pkgs; }).fixtures
