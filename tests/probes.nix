# The probes a payload runs to make calls no shell tool makes, shared by
# rootless.nix (the tty filter, the swap race) and tests/native.nix (the
# walker, the Zig port's phase 4). A function of the node's pkgs. Since phase 6
# they are Zig (src/fixtures/ioctl_probe.zig, swapper.zig), from
# native.nix's fixtures set; this output holds those two alone.
#
# ioctl-probe REQUEST prints the errno name of ioctl(0, REQUEST, buf), or
# ok. The buffer holds whatever a request it is asked about writes back:
# TCGETS on a real terminal writes a whole termios. With standard input not a terminal, a request the filters let
# through reaches the kernel and fails with ENOTTY, and one they refuse
# fails with the filter's errno. The request is passed whole, all 64 bits,
# which the C library's ioctl would truncate to an int.
#
# swapper DIR exchanges DIR/sub and DIR/sublink until it is killed, as a
# payload racing another session's mounts would.
pkgs:
let
  fixtures = (import ../native.nix { inherit pkgs; }).fixtures;
in
pkgs.runCommand "flong-probes" { } ''
  mkdir -p $out/bin
  ln -s ${fixtures}/bin/ioctl-probe ${fixtures}/bin/swapper $out/bin/
''
