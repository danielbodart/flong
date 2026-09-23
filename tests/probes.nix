# The probes a payload runs to make calls no shell tool makes, shared by
# rootless.nix (the tty filter, the swap race) and tests/native.nix (the
# walker, ZIG.md phase 4). A function of the node's pkgs.
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
pkgs: pkgs.runCommandCC "flong-probes"
  {
    swapper = pkgs.writeText "swapper.c" ''
      #include <fcntl.h>
      #include <stdio.h>
      #include <unistd.h>

      int main(int argc, char **argv)
      {
      	if (argc != 2) {
      		fputs("usage: swapper DIR\n", stderr);
      		return 2;
      	}
      	if (chdir(argv[1]) != 0) {
      		perror(argv[1]);
      		return 1;
      	}
      	for (;;) {
      		if (renameat2(AT_FDCWD, "sub", AT_FDCWD, "sublink", RENAME_EXCHANGE) != 0) {
      			perror("renameat2");
      			return 1;
      		}
      	}
      }
    '';
    src = pkgs.writeText "ioctl-probe.c" ''
      #include <errno.h>
      #include <stdio.h>
      #include <stdlib.h>
      #include <string.h>
      #include <sys/syscall.h>
      #include <unistd.h>

      int main(int argc, char **argv)
      {
      	char buf[256] = { 0 };
      	if (argc != 2) {
      		fputs("usage: ioctl-probe REQUEST\n", stderr);
      		return 2;
      	}
      	unsigned long request = strtoul(argv[1], NULL, 0);
      	if (syscall(SYS_ioctl, 0, request, buf) == 0) {
      		puts("ok");
      	} else {
      		puts(strerrorname_np(errno));
      	}
      	return 0;
      }
    '';
  } ''
  mkdir -p $out/bin
  $CC -std=gnu11 -O2 -D_GNU_SOURCE -Wall -Wextra -Werror -o $out/bin/ioctl-probe $src
  $CC -std=gnu11 -O2 -D_GNU_SOURCE -Wall -Wextra -Werror -o $out/bin/swapper $swapper
''
