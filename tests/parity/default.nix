# The parity test's two tools: bpfdump, which dumps a live process's seccomp
# filters and evaluates a stack of them, and syscall-probe, which a session runs as
# its payload. Taken from the seccomp spike, with the sweep made exact.
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
pkgs.runCommandCC "flong-parity-tools" { buildInputs = [ pkgs.libseccomp ]; } ''
  mkdir -p $out/bin
  cflags=(-std=gnu11 -O2 -D_GNU_SOURCE -Wall -Wextra -Werror)
  $CC "''${cflags[@]}" -o $out/bin/bpfdump ${./bpfdump.c} -lseccomp
  $CC "''${cflags[@]}" -o $out/bin/syscall-probe ${./probe.c}
''
