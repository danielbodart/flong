# The parity test's two tools: bpfdump, which dumps a live process's seccomp
# filters and evaluates a stack of them, and syscall-probe, which a session runs as
# its payload. Taken from the seccomp spike, with the sweep made exact. Since
# phase 6 they are Zig (src/fixtures/), native.nix's fixtures set, which also
# holds rootless.nix's ioctl-probe and swapper (tests/probes.nix).
#
# `c` is the C they port (bpfdump.c, probe.c), built as this file built it
# before phase 6 and installed as bpfdump-c and syscall-probe-c, for phase 6
# (a)'s transition (tests/fixtures-transition.nix, tests/parity.nix); never
# an output.
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
let
  c = pkgs.runCommandCC "flong-parity-tools-c" { buildInputs = [ pkgs.libseccomp ]; } ''
    mkdir -p $out/bin
    cflags=(-std=gnu11 -O2 -D_GNU_SOURCE -Wall -Wextra -Werror)
    $CC "''${cflags[@]}" -o $out/bin/bpfdump-c ${./bpfdump.c} -lseccomp
    $CC "''${cflags[@]}" -o $out/bin/syscall-probe-c ${./probe.c}
  '';
in
(import ../../native.nix { inherit pkgs; }).fixtures.overrideAttrs (old: {
  passthru = (old.passthru or { }) // {
    inherit c;
  };
})
