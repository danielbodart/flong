# The engine, driven the way it is meant to be: by a lingering user
# through her own user manager, on a host with no sudo at all. It covers a
# launch cold and warm, the environment a payload is given, a postStart hook
# with and without a network, that nothing of a session runs as host root,
# the refusal of root and of a caller with no subordinate ids, the gate, the
# sweeper releasing a SIGKILLed launcher's session, the lifecycle of hook
# daemons, records and caches under concurrency, the session cgroup and its
# limits, a caller with no user manager, the declaration's mounts and their
# races, the seccomp stack (the tiers, their loosenings, a project's policy
# and its cache, the tty filter, and learning a policy from a logging
# filter), the terminal, and a switch under a running session.
#
# Kept small for CI's software emulation: one VM, every declaration runs the
# same container closure, and the one thing in it built for this test is a
# pair of one-file probes. No assertion is about time: the one hook that
# sleeps does so to outlast any timeout the engine might have, and the
# subtests after it run while it does.
{ lib, ... }:

let
  # One closure for every container: a container's closure depends on its
  # `config` alone, and the mounts are the container's other options.
  # strace is the payload that ptrace separates the tiers by; the probes
  # make the calls no shell tool makes, an ioctl with a 64-bit request and
  # an atomic exchange of two names. nftables is what a payload would undo a
  # hook's rules with.
  boxConfig = { pkgs, ... }: {
    system.stateVersion = "24.05";
    users.users.alice = { isNormalUser = true; uid = 1000; group = "users"; };
    users.groups.users.gid = 100;
    environment.systemPackages = [ pkgs.strace pkgs.nftables (probes pkgs) (fenceProbe pkgs) ];
    # A symlink in the prepared root, which the payload could have planted in
    # its own home, pointing at a directory the caller can write.
    systemd.tmpfiles.rules = [ "L /home/alice/escape - - - - /escview" ];
  };

  # ioctl-probe REQUEST prints the errno name of ioctl(0, REQUEST, buf), or
  # ok. The buffer holds whatever a request it is asked about writes back:
  # TCGETS on a real terminal writes a whole termios. With standard input not a terminal, a request the filters let
  # through reaches the kernel and fails with ENOTTY, and one they refuse
  # fails with the filter's errno. The request is passed whole, all 64 bits,
  # which the C library's ioctl would truncate to an int.
  #
  # swapper DIR exchanges DIR/sub and DIR/sublink until it is killed, as a
  # payload racing another session's mounts would.
  probes = pkgs: pkgs.runCommandCC "flong-probes"
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
  '';

  # fence-probe tries, from inside a session, everything that would undo a
  # hook's network setup or the session's cgroup, and prints each attempt's
  # name with allowed or refused. The limits it would lift are the ones the
  # fence declarations set. The nested attempt is the escape DESIGN.md
  # measured: a user and cgroup namespace of the payload's own, mounting
  # cgroup2 at the session's cgroup. Without nestedSandbox it cannot even
  # start. A cgroup.kill that went through would end the probe before its
  # last line.
  fenceProbe = pkgs: pkgs.writeShellScriptBin "fence-probe" ''
    try() {
      local what=$1
      shift
      if "$@" >/dev/null 2>&1; then echo "$what allowed"; else echo "$what refused"; fi
    }
    try nft-flush nft flush ruleset
    try nft-delete nft delete table inet fence
    try link-add ip link add fence0 type dummy
    try route-add ip route add blackhole 198.51.100.0/24
    try net-sysctl sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
    try userns-nft unshare -Ur nft flush ruleset
    try cg-memory sh -c 'echo max > /sys/fs/cgroup/memory.max'
    try cg-pids sh -c 'echo max > /sys/fs/cgroup/pids.max'
    try cg-kill sh -c 'echo 1 > /sys/fs/cgroup/cgroup.kill'
    try cg-procs sh -c 'echo $$ > /sys/fs/cgroup/cgroup.procs'
    try cg-mkdir mkdir /sys/fs/cgroup/out
    unshare -UrmC sh -c '
      mkdir /tmp/cg && mount -t cgroup2 cgroup2 /tmp/cg || exit 1
      echo "nested-mount allowed"
      for f in memory.max pids.max; do
        if echo max > /tmp/cg/$f; then echo "nested-$f allowed"; else echo "nested-$f refused"; fi
      done
      if echo 1 > /tmp/cg/cgroup.kill; then echo "nested-cgroup.kill allowed"; else echo "nested-cgroup.kill refused"; fi
    ' 2>/dev/null || echo "nested-mount refused"
    echo probe-done
  '';

  # A project's policy, as the caller's environment states it, so that one
  # declaration covers a policy, none, a refusal and a failing snippet. It
  # records the session it was asked for, which postStart must share.
  seccompPolicy = ''
    [ -z "''${FLONG_TEST_POLICY_FAIL:-}" ] || { echo "the policy snippet fails" >&2; exit 3; }
    echo "$machine" > /tmp/project-policy
    printf '%s\n' "''${FLONG_TEST_POLICY:-}"
  '';

  # Records what the hook is promised: who it runs as, the session it is
  # for, and how many routes the session's namespace had while the hook held
  # it. Then it leaves a daemon behind in the hooks leaf, with its output
  # redirected so that nothing waiting on the launcher's waits on it too, and
  # its pid where the test can look for it. A background job of a
  # non-interactive shell reads /dev/null already.
  #
  # The caller's environment reaches the hook, so FLONG_TEST_HOOK picks a
  # failure, a hook that never ends (for killing the launcher while it
  # runs), or a sleep longer than any timeout the engine might hold.
  postStart = ''
    case ''${FLONG_TEST_HOOK:-} in
      fail) echo "the hook fails" >&2; exit 3 ;;
      hang) sleep infinity >/dev/null 2>&1 & echo $! > "/tmp/hook-hang-$machine"; wait ;;
      sleep) touch "/tmp/hook-sleeping-$machine"; sleep 90; touch "/tmp/hook-slept-$machine" ;;
    esac
    {
      id -u
      echo "$machine"
      nsenter --user="$userns" --net="$netns" cat /proc/net/route | tail -n +2 | wc -l
    } > "/tmp/poststart-$machine"
    sleep infinity >/dev/null 2>&1 &
    echo $! > "/tmp/daemon-$machine"
  '';

  # Keyed on $machine alone, because on the sweeper's path that is all there
  # is. Appended, so a second run would show.
  postStop = ''
    echo "$machine" >> "/tmp/poststop-$machine"
  '';

  # A hook that sets up the session's network as a consumer would: an nft
  # table, entered as U1's root. The payload then tries to undo it.
  fenceHook = ''
    id -u > "/tmp/fence-hook-$machine"
    nsenter --user="$userns" --net="$netns" nft -f - <<'EOF'
    table inet fence {
      chain out {
        type filter hook output priority 0;
        tcp dport 9 drop
      }
    }
    EOF
  '';
in
{
  name = "flong-rootless";

  nodes.machine = { config, pkgs, ... }: {
    imports = [ ../module.nix ];

    virtualisation.memorySize = 2048;
    # The races and the concurrent launches need more than one CPU to race.
    virtualisation.cores = 4;

    # No sudo rule can exist when there is no sudo.
    security.sudo.enable = false;

    # The tty filter is tested where TIOCSTI would inject, so it is the
    # filter that stops it and not the kernel's default.
    boot.kernel.sysctl."dev.tty.legacy_tiocsti" = 1;

    # A networked session's resolv.conf lists pasta's address for a family
    # only when the host has a nameserver in it. None answers: the test
    # reads the file and never resolves.
    networking.nameservers = [ "192.0.2.1" ];

    users.users.alice = {
      isNormalUser = true;
      uid = 1000;
      group = "users";
      linger = true;
      # Stated rather than allocated, so the cache key below is known.
      autoSubUidGidRange = false;
      subUidRanges = [ { startUid = 100000; count = 65536; } ];
      subGidRanges = [ { startGid = 100000; count = 65536; } ];
    };

    # A caller with a user manager and no subordinate ids, refused for the
    # ids rather than for the runtime directory.
    users.users.carol = {
      isNormalUser = true;
      uid = 1001;
      group = "users";
      linger = true;
      autoSubUidGidRange = false;
    };

    # A caller with subordinate ids and no user manager: she does not
    # linger, and never logs in. She launches from system units.
    users.users.dave = {
      isNormalUser = true;
      uid = 1002;
      group = "users";
      autoSubUidGidRange = false;
      subUidRanges = [ { startUid = 200000; count = 65536; } ];
      subGidRanges = [ { startGid = 200000; count = 65536; } ];
    };

    systemd.tmpfiles.rules = [
      "d /srv/work 0755 root root -"
      # Written through a read-write bind, so it is the payload user's.
      "d /srv/rw 0755 alice users -"
      "f /srv/rw/secret 0644 root root - should-be-masked"
      "d /srv/lower 0755 alice users -"
      "f /srv/lower/seed 0644 alice users - from-the-lower-layer"
      "d /srv/companion 0755 alice users -"
      "d /srv/protected 0755 root root -"
      # The swap race and the planted symlink. Everything a session could
      # write is alice's, so that an escape would succeed if the engine let
      # it: the workspace the swapper works in, and the view its symlink and
      # the root's symlink point at. The source bound under the workspace is
      # root's and read-only.
      "d /srv/race 0755 alice users -"
      "d /srv/race/ws 0755 alice users -"
      "d /srv/race/ws/sub 0755 alice users -"
      "d /srv/race/ws/sub/deep 0755 alice users -"
      "d /srv/race/ws/sub/deep/x 0755 alice users -"
      "L /srv/race/ws/sublink - - - - /escview"
      "d /srv/race/view 0755 alice users -"
      "d /srv/race/other 0755 root root -"
      "f /srv/race/other/marker 0644 root root - other"
    ];

    # One switch, to a system whose holder unit differs, with sessions
    # running.
    specialisation.changed.configuration = {
      systemd.user.services.flong-sessions.environment.FLONG_TEST_GENERATION = "changed";
    };

    # What hostPorts reaches: a banner on the host's loopback, so that a
    # reply proves the far side answered, which a bare connect through pasta
    # does not.
    systemd.services.host-listener = {
      wantedBy = [ "multi-user.target" ];
      script = ''
        while true; do
          echo host-18123 | ${pkgs.netcat}/bin/nc -N -l 127.0.0.1 18123
        done
      '';
    };

    containers.box = {
      privateNetwork = true;
      config = boxConfig;
    };

    # A container of its own for the hook that sleeps, so that the subtests
    # which remove box's cache while it sleeps leave its root alone.
    containers.slow = {
      privateNetwork = true;
      config = boxConfig;
    };

    # The swap race's second session: a bind nested under the workspace,
    # below the directory the first session swaps with a symlink to /escview.
    containers.race = {
      privateNetwork = true;
      config = boxConfig;
      bindMounts."/escview" = { hostPath = "/srv/race/view"; isReadOnly = false; };
      bindMounts."/srv/race/ws/sub/deep/x".hostPath = "/srv/race/other";
    };

    # A bind under the symlink the prepared root holds in alice's home.
    # /escview sorts before /home, so the symlink's target is mounted by the
    # time the walker meets it.
    containers.esc = {
      privateNetwork = true;
      config = boxConfig;
      bindMounts."/escview" = { hostPath = "/srv/race/view"; isReadOnly = false; };
      bindMounts."/home/alice/escape/inner".hostPath = "/srv/race/other";
    };

    containers.mnt = {
      privateNetwork = true;
      config = boxConfig;
      # A space in both paths, which reaches the launcher as data.
      bindMounts."/data ro".hostPath = "/srv/ro dir";
      bindMounts."/rw" = { hostPath = "/srv/rw"; isReadOnly = false; };
      tmpfs = [ "/scratch" "/sticky:mode=1777,size=10M" "/rootish:uid=0,gid=0" ];
      allowedDevices = [ { node = "/dev/null"; modifier = "rwm"; } ];
    };

    flong =
      let
        base = {
          container = "box";
          user = "alice";
          command = [ "bash" "-c" ];
        };
        hooked = base // {
          inherit postStart postStop;
        };
        # A hook's nft table and declared limits: what the payload tries to
        # undo.
        fenced = base // {
          postStart = fenceHook;
          path = [ pkgs.nftables ];
          limits = { MemoryMax = "256M"; TasksMax = 64; };
        };
      in
      {
        # The default workspace, `pwd`, and nothing else.
        plain = base;

        inherit hooked fenced;
        fencednested = fenced // { seccomp.nestedSandbox = true; };
        patient = hooked // { container = "slow"; };
        race = base // { container = "race"; };
        esc = base // { container = "esc"; };

        nethook = hooked // {
          network = {
            hostPorts = [ 18123 ];
            forwardPorts = [ { hostPort = 18200; containerPort = 18201; } ];
          };
        };

        limited = base // {
          limits = {
            MemoryMax = "256M";
            TasksMax = 64;
            CPUQuota = "50%";
            CPUWeight = 200;
            oomGroup = true;
          };
        };

        mounts = base // {
          container = "mnt";
          overlays."/ovl" = "/srv/lower";
          # One level below the writable bind, which the depth rule allows.
          masks = [ "/rw/secret" ];
          protect = [ "/srv/protected" ];
          workspace = "echo /srv/work:ro";
          # The caller's bind, and one more the caller's environment names.
          binds = ''
            printf '%s:rw\n' /srv/companion
            if [ -n "''${FLONG_TEST_BIND:-}" ]; then printf '%s\n' "$FLONG_TEST_BIND"; fi
          '';
          guard = ''[ -z "''${FLONG_TEST_DENY:-}" ] || { echo "the guard refuses" >&2; exit 1; }'';
        };

        # The tiers and loosenings beside plain's default, strict.
        parity = base // { seccomp.tier = "parity"; };
        debugged = base // { seccomp.debug = true; };
        nested = base // { seccomp.nestedSandbox = true; };
        learner = base // { seccomp.log = true; };
        project = base // {
          inherit seccompPolicy;
          postStart = ''echo "$machine" > /tmp/project-poststart'';
        };
      };

    environment.systemPackages =
      map (n: config.flong.${n}.launcher) [
        "plain" "hooked" "nethook" "limited" "mounts"
        "parity" "debugged" "nested" "learner" "project"
        "fenced" "fencednested" "patient" "race" "esc"
      ]
      ++ [
        # The driver reads a session's ruleset and links from outside.
        pkgs.nftables
        # scmp_sys_resolver, which names the numbers a logging filter records.
        (lib.getBin pkgs.libseccomp)

        # The machine name of CONTAINER's session whose payload is asleep,
        # read from the cgroups, which only the launcher names.
        (pkgs.writeShellScriptBin "session-of" ''
          cg=/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/flong-sessions.service
          for procs in "$cg/$1"/*/sandbox/cgroup.procs; do
            [ -e "$procs" ] || continue
            while read -r pid; do
              if [ "$(cat "/proc/$pid/comm" 2>/dev/null)" = sleep ]; then
                basename "$(dirname "$(dirname "$procs")")"
                exit 0
              fi
            done < "$procs"
          done
          exit 1
        '')

        # Fails when any process under the holder has a host uid or gid of
        # 0, or sits in a user namespace that maps host uid or gid 0. A
        # process in the host's own namespace maps every id to itself, so
        # only the ids it runs as are asked of it. Prints the leaf of every
        # process seen.
        (pkgs.writeShellScriptBin "no-host-root" ''
          cg=/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/flong-sessions.service
          init=$(readlink /proc/1/ns/user)
          for procs in $(find "$cg" -name cgroup.procs); do
            while read -r pid; do
              status=$(cat "/proc/$pid/status" 2>/dev/null) || continue
              ids=$(printf '%s\n' "$status" | awk '/^(Uid|Gid):/ { printf "%s %s %s %s ", $2, $3, $4, $5 }')
              case " $ids" in
                *" 0 "*) echo "$pid in $procs runs with host id 0: $ids"; exit 1 ;;
              esac
              if [ "$(readlink "/proc/$pid/ns/user")" != "$init" ]; then
                for map in uid_map gid_map; do
                  # Read from the host's namespace, the second column is a
                  # host id, and an extent starting above 0 cannot hold it.
                  if awk '$2 == 0 { found = 1 } END { exit !found }' "/proc/$pid/$map" 2>/dev/null; then
                    echo "$pid in $procs has host id 0 in its $map"
                    exit 1
                  fi
                done
              fi
              echo "''${procs#"$cg"/}"
            done < "$procs"
          done
        '')

        # race-mounts N: the swap race. Session A, a plain one on
        # /srv/race/ws, exchanges ws/sub (a directory) with ws/sublink (a
        # symlink to /escview) as fast as it can, while session B launches
        # N times with a bind nested at ws/sub/deep/x: first with deep/x
        # there, then with it removed before each launch, so that B's own
        # walker has to make it under the race. One line per launch of B:
        # refused (for the symlink), contained (the bind landed inside the
        # workspace), ESCAPED (it landed under /escview), or odd; and
        # host-made when B made a directory in the view on the host.
        (pkgs.writeShellScriptBin "race-mounts" ''
          set -u
          n=$1
          cd /srv/race/ws
          plain 'exec swapper .' >/tmp/race-a.out 2>&1 &
          a=$!
          # A is running once the host sees the symlink under sub's name.
          until [ -L sub ]; do :; done
          for fixture in exists missing; do
            for _ in $(seq "$n"); do
              if [ "$fixture" = missing ]; then rm -rf sub/deep sublink/deep 2>/dev/null || true; fi
              rc=0
              out=$(race "grep -F ' /srv/race/other ' /proc/self/mountinfo | cut -d' ' -f5" 2>&1) || rc=$?
              if [ -e /srv/race/view/deep ]; then
                echo host-made
                rm -rf /srv/race/view/deep
              fi
              if [ "$rc" != 0 ]; then
                case $out in
                  *"a symlink is on the way"*) echo refused ;;
                  *) echo "odd: rc=$rc $out" ;;
                esac
              else
                case $out in
                  /srv/race/ws/*) echo contained ;;
                  /escview/*) echo ESCAPED ;;
                  *) echo "odd: $out" ;;
                esac
              fi
            done
          done
          kill -TERM "$a"
          rc=0
          wait "$a" || rc=$?
          echo "a=$rc"
        '')

        # interrupt pty|pipe: a ^C typed at a terminal while a payload
        # sleeps, once the payload has said it is running. `pty` runs the
        # launcher with the terminal on both stdin and stdout, so it relays
        # a pty of its own and the ^C reaches it as a byte; `pipe` pipes its
        # output through cat, so the payload shares the terminal and the ^C
        # is a signal to the foreground group. The shell around the launcher
        # traps SIGINT so that it survives to report the launcher's status.
        (pkgs.writeShellScriptBin "interrupt" ''
          set -u
          out=$(mktemp)
          case $1 in
            pty) inner=${pkgs.writeShellScript "interrupt-pty" ''
              trap true INT
              plain 'echo ready; sleep infinity'
              echo "launcher=$?"
            ''} ;;
            pipe) inner=${pkgs.writeShellScript "interrupt-pipe" ''
              trap true INT
              plain 'echo ready; sleep infinity' | cat
              echo "launcher=''${PIPESTATUS[0]}"
            ''} ;;
          esac
          {
            until grep -q ready "$out"; do sleep 0.1; done
            printf '\003'
            until grep -q launcher= "$out"; do sleep 0.1; done
          } | script -qfec "$inner" /dev/null >"$out"
          tr -d '\r' <"$out"
          rm -f "$out"
        '')

        # tty-probe: the tty filter where it matters, with the caller's
        # terminal on the payload's stdin and its output piped, so that the
        # payload holds the real terminal. TCGETS with bit 32 set shows the
        # high bits are dropped by the kernel and the ioctl reaches it.
        (pkgs.writeShellScriptBin "tty-probe" ''
          script -qfec ${pkgs.writeShellScript "tty-probe-inner" ''
            plain '[ -t 0 ] && echo stdin-tty; ioctl-probe 0x5412; ioctl-probe 0x100005412; ioctl-probe 0x100005401' | cat
          ''} /dev/null | tr -d '\r'
        '')
      ];
  };

  testScript = ''
    import shlex
    import time

    CG = "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/flong-sessions.service"
    STATE = "/run/user/1000/flong"

    # A command as USER, through her own user manager, with an explicit PATH
    # and the workspace as the current directory. `sudo` is nowhere in it.
    def as_user(script, user="alice"):
        inner = "export PATH=/run/wrappers/bin:/run/current-system/sw/bin; cd /srv/work; " + script
        return (f"systemd-run -M {user}@ --user --wait --pipe --quiet --collect "
                f"--expand-environment=no -- /run/current-system/sw/bin/bash -c {shlex.quote(inner)} </dev/null")

    # The same from a system unit of dave's, who has no user manager. PROPS
    # are the unit's properties.
    def as_dave(script, props=""):
        inner = "export PATH=/run/wrappers/bin:/run/current-system/sw/bin; cd /srv/work; " + script
        return (f"systemd-run --wait --pipe --quiet --collect -p User=dave {props} "
                f"-- /run/current-system/sw/bin/bash -c {shlex.quote(inner)} </dev/null")

    # A launch of SCRIPT through LAUNCHER, left running; its status lands in
    # /tmp/rc-TAG when it ends. The status is written in alice's unit, next
    # to the launcher, so it does not depend on a client left running in the
    # background of the driver's shell.
    def start(launcher, script, tag):
        run = as_user(f"{launcher} {shlex.quote(script)}; echo $? > /tmp/rc-{tag}")
        machine.succeed(f"rm -f /tmp/rc-{tag}; {run} >/tmp/out-{tag} 2>&1 &")

    # The launcher's pid, out of the middle of <container>-<pid>-<random>.
    def launcher_pid(name):
        return name.split("-")[1]

    def stop(name, tag):
        machine.succeed(f"kill -TERM {launcher_pid(name)}")
        machine.wait_until_succeeds(f"test -s /tmp/rc-{tag}")
        rc = machine.succeed(f"cat /tmp/rc-{tag}").strip()
        assert rc == "143", rc
        machine.succeed(f"test ! -e {CG}/box/{name}")

    # The pid of the sleep a session of box runs as its payload.
    def payload_pid(name):
        return machine.succeed(
            f"for p in $(cat {CG}/box/{name}/sandbox/cgroup.procs); do "
            "[ \"$(cat /proc/$p/comm)\" = sleep ] && echo $p; done; true").strip()

    # A hook's daemon, by the pid it left in /tmp, is gone.
    def daemon_gone(name):
        pid = machine.succeed(f"cat /tmp/daemon-{name}").strip()
        machine.wait_until_succeeds(f"test ! -e /proc/{pid}")

    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("user@1000.service")
    machine.wait_for_unit("user@1001.service")
    machine.wait_for_unit("host-listener.service")

    with subtest("a lingering user launches with no sudo, cold then warm"):
        machine.fail("test -e /run/wrappers/bin/sudo")
        out = machine.succeed(as_user("plain 'id -u; id -G; echo ok'"))
        assert out.split() == ["1000", "100", "ok"], out

        # The cache key, from the ranges as the host wrote them.
        sub = machine.succeed("awk -F: '$1 == \"alice\" { print $2; exit }' /etc/subuid").strip()
        gsub = machine.succeed("awk -F: '$1 == \"alice\" { print $2; exit }' /etc/subgid").strip()
        KEY = f"1000.100.{sub}.{gsub}.100"
        prepared = machine.succeed(f"ls -d {STATE}/box-*-*-{KEY}/prepared").strip()
        assert machine.succeed(f"stat -c %u {prepared}").strip() == sub
        mtime = machine.succeed(f"stat -c %Y {prepared}")

        # The holder, started by the launcher on demand, with its sweeper.
        machine.succeed(f"test -d {CG}/supervisor")

        again = machine.succeed(as_user("plain 'id -u; id -G; echo ok'"))
        assert again == out, again
        assert machine.succeed(f"stat -c %Y {prepared}") == mtime

    with subtest("no timeouts: a postStart that sleeps 90 s holds the gate"):
        # It sleeps while the subtests below run, and is checked at the end.
        start("FLONG_TEST_HOOK=sleep patient", "echo payload-ran", "patient")
        machine.wait_until_succeeds("ls /tmp/hook-sleeping-slow-*")
        machine.fail("grep -qx payload-ran /tmp/out-patient")
        machine.fail("test -e /tmp/rc-patient")

    with subtest("a caller of uid 0 is refused, by the wrapper and by the launcher"):
        # The driver's shell stops at the first failing command, so each
        # status is echoed from the same list.
        out = machine.succeed("cd /srv/work && plain true 2>&1 && echo rc=0 || echo rc=$?")
        assert "refusing to run as root" in out and out.split()[-1] == "rc=1", out
        # The launcher and the sweeper refuse root themselves, before
        # reading anything else, for a caller who runs them directly.
        launch = machine.succeed(
            "grep -m 1 -o '/nix/store/[^/]*/bin/flong-launch' \"$(readlink -f \"$(command -v plain)\")\"").strip()
        out = machine.succeed(f"{launch} -- true 2>&1 && echo rc=0 || echo rc=$?")
        assert "refusing to run as root" in out and out.split()[-1] == "rc=125", out
        out = machine.succeed(f"{launch.removesuffix('launch')}sweeper /tmp 2>&1 && echo rc=0 || echo rc=$?")
        assert "refusing to run as root" in out and out.split()[-1] == "rc=125", out
        machine.fail("test -e /run/user/0/flong")

    with subtest("the payload gets none of the caller's environment"):
        out = machine.succeed(as_user(
            "FLONG_SENTINEL=x FLONG_TRACE=1 plain "
            "'env | cut -d= -f1; echo \"xdg=$XDG_RUNTIME_DIR\"' 2>&1"))
        names = out.split()
        assert "FLONG_SENTINEL" not in names, out
        # Set by systemd-run in the caller's unit.
        assert "INVOCATION_ID" not in names, out
        for n in ("container", "FLONG_BINDS", "HOME", "TMPDIR"):
            assert n in names, out
        assert "xdg=/run/user/1000" in names, out
        assert "launcher-start" in out, out

    with subtest("the caller's RLIMIT_STACK reaches the payload unchanged"):
        # ZIG.md quirk 20: nothing between the caller and the payload (the
        # wrapper, flong-launch, bwrap, flong-init, tini) sets it.
        out = machine.succeed(as_user("ulimit -s 4096; plain 'ulimit -s'"))
        assert out == "4096\n", out
        # The soft limit alone, the hard one left as it was: a program that
        # raised the soft limit toward the hard one (Zig's default start code
        # sets 16 MiB, ZIG.md "Measured", P2) would show here and not above.
        out = machine.succeed(as_user("ulimit -S -s 4096; ulimit -H -s; plain 'ulimit -S -s; ulimit -H -s'")).split()
        assert len(out) == 3 and out[1:] == ["4096", out[0]], out
        # The hard limit is above the soft one, else the soft one had nowhere
        # to rise and the check above could not fail.
        assert out[0] == "unlimited" or int(out[0]) > 4096, out
        # The control: another value arrives as itself, so the one above is
        # not a constant of the session.
        out = machine.succeed(as_user("ulimit -s 6144; plain 'ulimit -s'"))
        assert out == "6144\n", out

    with subtest("a hook without a network"):
        machine.succeed("rm -f /tmp/poststart-* /tmp/poststop-*")
        out = machine.succeed(as_user("hooked 'tail -n +2 /proc/net/route | wc -l'"))
        assert out.strip() == "0", out
        path = machine.succeed("ls /tmp/poststart-box-*").strip()
        assert machine.succeed(f"stat -c %u {path}").strip() == "1000"
        uid, name, routes = machine.succeed(f"cat {path}").split()
        assert uid == "1000" and routes == "0", (uid, name, routes)
        machine.wait_until_succeeds(f"test -s /tmp/poststop-{name}")
        assert machine.succeed(f"cat /tmp/poststop-{name}").strip() == name
        # The hook's daemon went with the session on a clean exit.
        daemon_gone(name)

    with subtest("a hook with a network"):
        machine.succeed("rm -f /tmp/poststart-* /tmp/poststop-*")
        out = machine.succeed(as_user(
            "nethook 'exec 3<>/dev/tcp/127.0.0.1/18123 && read -r banner <&3 && echo \"$banner\"; "
            "echo ---; cat /etc/resolv.conf; echo ---; tail -n +2 /proc/net/route | wc -l'"))
        banner, resolv, routes = out.split("---")
        assert banner.strip() == "host-18123", out
        assert "nameserver 169.254.1.1" in resolv, out
        assert int(routes) > 0, out
        _, _, hook_routes = machine.succeed("cat /tmp/poststart-box-*").split()
        assert hook_routes == "0", hook_routes

    with subtest("no process of a session, its hook or its pasta has host uid 0"):
        start("nethook", "sleep infinity", "nethook")
        name = machine.wait_until_succeeds("session-of box").strip()
        leaves = machine.succeed("no-host-root")
        for leaf in ("supervisor", f"box/{name}/sandbox", f"box/{name}/hooks", f"box/{name}/pasta"):
            assert f"{leaf}/cgroup.procs" in leaves, leaves
        # The forwarded port is the session's while it runs, and no longer.
        machine.succeed("ss -Hltn 'sport = :18200' | grep -q .")
        # No limit is declared, so the session enables no controller and
        # its leaves have no limit file to write.
        machine.succeed(f"test -z \"$(cat {CG}/box/{name}/cgroup.subtree_control)\"")
        for f in ("memory.max", "memory.high", "pids.max", "cpu.max", "cpu.weight"):
            machine.succeed(f"test ! -e {CG}/box/{name}/sandbox/{f}")
        stop(name, "nethook")
        machine.fail("ss -Hltn 'sport = :18200' | grep -q .")
        # The hook's daemon went with the session on SIGTERM.
        daemon_gone(name)

    with subtest("limits are written into the session's cgroup"):
        start("limited", "sleep infinity", "limited")
        name = machine.wait_until_succeeds("session-of box").strip()
        leaf = f"{CG}/box/{name}/sandbox"
        for f, want in (("memory.max", "268435456"), ("pids.max", "64"),
                        ("cpu.max", "50000 100000"), ("cpu.weight", "200"),
                        ("memory.oom.group", "1")):
            got = machine.succeed(f"cat {leaf}/{f}").strip()
            assert got == want, (f, got)
        # Enabled at the session for the leaf, and only what the limits need.
        enabled = machine.succeed(f"cat {CG}/box/{name}/cgroup.subtree_control").split()
        assert sorted(enabled) == ["cpu", "memory", "pids"], enabled
        stop(name, "limited")

    with subtest("a caller without a subordinate id range is refused"):
        out = machine.succeed(as_user("plain true 2>&1; echo rc=$?", user="carol"))
        assert "subUidRanges" in out and out.split()[-1] == "rc=1", out

    with subtest("the sweeper releases a session whose launcher was SIGKILLed"):
        machine.succeed("rm -f /tmp/poststart-* /tmp/poststop-*")
        start("hooked", "sleep infinity", "sweep")
        name = machine.wait_until_succeeds("session-of box").strip()
        machine.succeed(f"kill -KILL {launcher_pid(name)}")
        machine.wait_until_succeeds(f"test -s /tmp/poststop-{name}")
        machine.wait_until_succeeds(f"test ! -e {CG}/box/{name}")
        machine.wait_until_succeeds(f"test ! -e {STATE}/sessions/{name}")
        machine.succeed(f"test -d {CG}/supervisor")
        # The hook's daemon lasted until the sweep, and no longer.
        daemon_gone(name)
        assert machine.succeed(f"cat /tmp/poststop-{name}").split() == [name]

    with subtest("the gate: a failing hook, or a launcher killed in its hook, and the payload never runs"):
        out = machine.succeed(as_user("FLONG_TEST_HOOK=fail hooked 'echo payload-ran' 2>&1; echo rc=$?"))
        assert "the hook fails" in out and "postStart failed" in out, out
        # The status ends the output, but not always on a line of its own:
        # the C flong-init writes its refusal in three writes
        # (flong-init.c:61-66), and the launcher kills the sandbox right
        # after closing the gate (flong-launch.c:792-797), so a kill between
        # them drops the newline and "rc=125" follows the message.
        assert "payload-ran" not in out and out.rstrip("\n").endswith("rc=125"), out

        machine.succeed("rm -f /tmp/hook-hang-* /tmp/poststop-*")
        start("FLONG_TEST_HOOK=hang hooked", "echo payload-ran", "hang")
        path = machine.wait_until_succeeds("f=$(ls /tmp/hook-hang-box-*) && test -s \"$f\" && echo \"$f\"").strip()
        name = path.removeprefix("/tmp/hook-hang-")
        hook_sleep = machine.succeed(f"cat {path}").strip()
        machine.succeed(f"kill -KILL {launcher_pid(name)}")
        machine.wait_until_succeeds("test -s /tmp/rc-hang")
        assert machine.succeed("cat /tmp/rc-hang").strip() == "137"
        # A whole line: bash's report of the killed launcher quotes its
        # command, payload-ran included.
        machine.fail("grep -qx payload-ran /tmp/out-hang")
        # The record came before the hook, so the sweeper releases the
        # session, the hook with it, and runs postStop.
        machine.wait_until_succeeds(f"test ! -e {CG}/box/{name}")
        machine.wait_until_succeeds(f"test ! -e /proc/{hook_sleep}")
        machine.wait_until_succeeds(f"test -s /tmp/poststop-{name}")

    with subtest("the hook runs as the caller, and the payload cannot undo it"):
        for launcher in ("fenced", "fencednested"):
            start(launcher, "fence-probe; sleep infinity", launcher)
            machine.wait_until_succeeds(f"grep -q probe-done /tmp/out-{launcher}")
            name = machine.succeed("session-of box").strip()
            pid = payload_pid(name)
            assert machine.succeed(f"cat /tmp/fence-hook-{name}").strip() == "1000"
            assert machine.succeed(f"stat -c %u /tmp/fence-hook-{name}").strip() == "1000"
            results = dict(l.rsplit(" ", 1) for l in machine.succeed(f"cat /tmp/out-{launcher}").splitlines()
                           if l.endswith((" allowed", " refused")))
            nested = launcher == "fencednested"
            # nestedSandbox lets the payload mount cgroup2 in a namespace of
            # its own, so there the writes through that mount are tried too.
            assert results.pop("nested-mount") == ("allowed" if nested else "refused"), (launcher, results)
            assert set(results.values()) == {"refused"}, (launcher, results)
            if nested:
                assert {"nested-memory.max", "nested-pids.max", "nested-cgroup.kill"} <= results.keys(), results
            # From outside: the hook's table is intact, no link was added,
            # and the limits are what the declaration says.
            table = machine.succeed(f"nsenter -t {pid} -n nft list table inet fence")
            assert "tcp dport 9 drop" in table, table
            machine.fail(f"nsenter -t {pid} -n ip link show fence0")
            leaf = f"{CG}/box/{name}/sandbox"
            assert machine.succeed(f"cat {leaf}/memory.max").strip() == "268435456"
            assert machine.succeed(f"cat {leaf}/pids.max").strip() == "64"
            machine.succeed(f"test ! -e {leaf}/out")
            stop(name, launcher)

    with subtest("ten concurrent cold launches, whose ten sweeps run a dead session's postStop once"):
        machine.succeed("rm -f /tmp/poststop-* /tmp/daemon-*")
        start("hooked", "sleep infinity", "dead")
        name = machine.wait_until_succeeds("session-of box").strip()
        daemon = machine.succeed(f"cat /tmp/daemon-{name}").strip()
        # The holder's sweeper is stopped, so the launches' own sweeps are
        # the only ones.
        sweeper = machine.succeed(f"cat {CG}/supervisor/cgroup.procs").strip()
        machine.succeed(f"kill -STOP {sweeper}")
        machine.succeed(f"kill -KILL {launcher_pid(name)}")
        machine.wait_until_succeeds(f"test -z \"$(cat {CG}/box/{name}/sandbox/cgroup.procs)\"")
        machine.succeed(f"test -e /proc/{daemon} && test ! -e /tmp/poststop-{name}")
        # Cold: no prepared root for any of them.
        machine.succeed(f"rm -rf {STATE}/box-*")
        out = machine.succeed(as_user(
            "for i in $(seq 10); do { plain 'echo ok'; echo rc=$?; } >/tmp/cold-$i 2>&1 & done; wait; "
            "cat /tmp/cold-*"))
        words = out.split()
        assert words.count("ok") == 10 and words.count("rc=0") == 10, out
        assert machine.succeed(f"cat /tmp/poststop-{name}").split() == [name]
        machine.succeed(f"test ! -e /proc/{daemon}")
        machine.succeed(f"test ! -e {CG}/box/{name} && test ! -e {STATE}/sessions/{name}")
        # One root, and no preparer's staging left behind.
        caches = machine.succeed(f"ls -d {STATE}/box-*").split()
        assert len(caches) == 1, caches
        left = machine.succeed(f"ls -A {caches[0]}").split()
        assert sorted(left) == [".prepare.lock", "prepare.log", "prepared"], left
        machine.succeed(f"kill -CONT {sweeper}")
        machine.succeed(as_user("plain true"))
        assert machine.succeed(f"cat /tmp/poststop-{name}").split() == [name]

    with subtest("a superseded cache a live session uses is kept"):
        start("plain", "sleep infinity", "live")
        name = machine.wait_until_succeeds("session-of box").strip()
        pid = payload_pid(name)
        cache = machine.succeed(f"ls -d {STATE}/box-*-*-{KEY}").strip()
        # Renamed to another generation's name, as an upgrade would leave it.
        old = f"{STATE}/box-00000000-00000000-{KEY}"
        machine.succeed(f"mv -T {cache} {old}")
        out = machine.succeed(as_user("plain 'echo ok' 2>&1"))
        assert "ok" in out.split() and "in use, kept" in out, out
        machine.succeed(f"test -d {old}/prepared")
        # The live session still reads its root through the renamed lower.
        machine.succeed(f"nsenter -t {pid} -m grep -q ^alice: /etc/passwd")
        stop(name, "live")
        # Unused, it goes at the next cold launch.
        machine.succeed(f"rm -rf {cache}")
        machine.succeed(as_user("plain true"))
        machine.succeed(f"test ! -e {old}")

    with subtest("no user manager: refused loudly, or a delegated system unit"):
        # No runtime directory at all.
        out = machine.succeed(as_dave("plain true 2>&1; echo rc=$?"))
        assert "users.users.dave.linger = true" in out and out.split()[-1] == "rc=1", out
        # A runtime directory, and a cgroup that is not dave's to delegate.
        rt = "-p RuntimeDirectory=user/1002 -p RuntimeDirectoryMode=0700"
        out = machine.succeed(as_dave("plain true 2>&1; echo rc=$?", rt))
        assert "no user manager for dave" in out and out.split()[-1] == "rc=125", out
        # A system unit with Delegate=yes: the session lives under the
        # unit's own cgroup, and the declared limits apply.
        out = machine.succeed(as_dave(
            "limited 'cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/pids.max /sys/fs/cgroup/cpu.max; id -u'",
            rt + " -p Delegate=yes -p DelegateSubgroup=launcher"))
        assert out.splitlines() == ["268435456", "64", "50000 100000", "1000"], out

    with subtest("the declaration's mounts"):
        # Made here rather than by tmpfiles, whose syntax needs a space escaped.
        machine.succeed("mkdir -p '/srv/ro dir' && echo read-only-marker > '/srv/ro dir/marker'")
        out = machine.succeed(as_user("mounts " + shlex.quote(
            "pwd; "
            "cat '/data ro/marker'; "
            "touch '/data ro/new' 2>/dev/null && echo ro-writable || echo ro-refused; "
            "touch /srv/work/new 2>/dev/null && echo ws-writable || echo ws-refused; "
            "echo from-session > /rw/written && echo rw-written; "
            "cat /rw/secret 2>&1; "
            "stat -c 'mode %n %a %u' /scratch /sticky /rootish; "
            "cat /ovl/seed; echo; echo new > /ovl/added && echo ovl-written; "
            "echo x > /dev/null && echo devnull-ok; "
            "echo \"binds=$FLONG_BINDS\"; "
            "touch /srv/companion/from-session && echo companion-written; "
            "touch \"$HOME/tmp/t\" && echo hometmp-ok")))
        lines = out.splitlines()
        for want in ("/srv/work", "read-only-marker", "ro-refused", "ws-refused", "rw-written",
                     "mode /scratch 755 1000", "mode /rootish 755 0",
                     "from-the-lower-layer", "ovl-written", "devnull-ok",
                     "binds=/srv/companion:rw", "companion-written", "hometmp-ok"):
            assert want in lines, (want, out)
        assert any(l.startswith("mode /sticky 1777 ") for l in lines), out
        assert "should-be-masked" not in out, out
        machine.succeed("grep -qx from-session /srv/rw/written")
        machine.succeed("test -e /srv/companion/from-session")
        machine.fail("test -e /srv/lower/added")
        machine.fail("test -e '/srv/ro dir/new'")

        out = machine.succeed(as_user("FLONG_TEST_DENY=1 mounts true 2>&1; echo rc=$?"))
        assert "the guard refuses" in out and out.split()[-1] == "rc=1", out

    with subtest("a mask one level below a writable bind holds against a rename"):
        out = machine.succeed(as_user("mounts " + shlex.quote(
            "mv /rw/secret /rw/secret.real 2>/dev/null && echo moved || echo move-refused; "
            "rm -f /rw/secret 2>/dev/null && echo removed || echo remove-refused; "
            "echo decoy > /rw/secret 2>/dev/null && echo written || echo write-refused; "
            "cat /rw/secret 2>/dev/null || echo masked; "
            "test -e /rw/secret.real && echo real-visible || echo no-real")))
        assert out.split() == ["move-refused", "remove-refused", "write-refused", "masked", "no-real"], out
        machine.succeed("grep -qx should-be-masked /srv/rw/secret")

    with subtest("a bind that reaches flong's state or a protected path is refused"):
        for path in ("/run/user/1000", "/run/user/1000/flong", "/srv/protected", "/srv"):
            out = machine.succeed(as_user(f"FLONG_TEST_BIND={path} mounts true 2>&1; echo rc=$?"))
            assert "which no session may reach" in out and out.split()[-1] == "rc=125", (path, out)
        # The workspace too.
        out = machine.succeed(as_user("cd /run/user/1000 && plain true 2>&1; echo rc=$?"))
        assert "which no session may reach" in out and out.split()[-1] == "rc=125", out

    with subtest("a symlink in the prepared root ends the launch, and makes nothing on the host"):
        out = machine.succeed(as_user("esc true 2>&1; echo rc=$?"))
        assert "a symlink is on the way" in out and out.split()[-1] == "rc=125", out
        machine.succeed("test -z \"$(ls -A /srv/race/view)\"")

    with subtest("the swap race: nothing escapes the workspace"):
        out = machine.succeed(as_user("race-mounts 20"))
        lines = out.splitlines()
        assert lines[-1] == "a=143", out
        results = lines[:-1]
        assert len(results) == 40, out
        assert set(results) <= {"refused", "contained"}, out
        print(f"swap race: {results.count('refused')} refused, {results.count('contained')} contained")
        machine.succeed("test -z \"$(ls -A /srv/race/view)\"")

    # The Seccomp_filters count a payload sees: the stack its launcher
    # installed, as the kernel reports it.
    def filters(launcher):
        out = machine.succeed(as_user(f"{launcher} 'grep ^Seccomp /proc/self/status'"))
        fields = dict(l.split(":") for l in out.splitlines())
        assert fields["Seccomp"].strip() == "2", out
        return int(fields["Seccomp_filters"])

    with subtest("the default tier is strict, and applied"):
        # The tier, the audit mask, the tty filter and the namespace mask.
        assert filters("plain") == 4
        # ptrace is in parity and not in strict, so it gets the tier's errno.
        out = machine.succeed(as_user("plain 'strace true 2>&1; echo rc=$?'"))
        assert "Operation not permitted" in out and out.split()[-1] != "rc=0", out
        # The namespace mask refuses with EPERM. Without it, the absent
        # nested-userns token would refuse with ENOSPC instead.
        out = machine.succeed(as_user("plain 'unshare -U true 2>&1; echo rc=$?'"))
        assert "Operation not permitted" in out and out.split()[-1] != "rc=0", out

    with subtest("tiers and loosenings differ on ptrace"):
        for launcher in ("parity", "debugged"):
            out = machine.succeed(as_user(f"{launcher} 'strace true 2>&1; echo rc=$?'"))
            assert "+++ exited with 0 +++" in out and out.split()[-1] == "rc=0", (launcher, out)
        assert filters("debugged") == 4

    with subtest("nestedSandbox allows a nested user namespace and a mount in it"):
        # No namespace mask.
        assert filters("nested") == 3
        out = machine.succeed(as_user(
            "nested 'unshare -U true && echo userns-ok; "
            "unshare -Urm sh -c \"mount -t tmpfs nested /tmp && echo mount-ok\"'"))
        assert out.split() == ["userns-ok", "mount-ok"], out

    with subtest("the tty filter refuses TIOCSTI, also with bit 32 set"):
        assert machine.succeed("sysctl -n dev.tty.legacy_tiocsti").strip() == "1"
        for launcher in ("plain", "nested"):
            out = machine.succeed(as_user(
                f"{launcher} 'ioctl-probe 0x5412; ioctl-probe 0x100005412; "
                "ioctl-probe 0x10000541c; ioctl-probe 0x100005401'"))
            # TCGETS with the same high bit is let through, and fails only
            # for not being asked of a terminal.
            assert out.split() == ["EPERM", "EPERM", "EPERM", "ENOTTY"], (launcher, out)
        # On the caller's real terminal, where TIOCSTI would inject.
        out = machine.succeed(as_user("tty-probe"))
        assert out.split() == ["stdin-tty", "EPERM", "EPERM", "ok"], out

    with subtest("^C ends the payload with 130, under a pty and in a pipeline"):
        for mode in ("pty", "pipe"):
            out = machine.succeed(as_user(f"interrupt {mode}"))
            # The terminal echoes the ^C in front of the status.
            assert any(l.endswith("launcher=130") for l in out.splitlines()), (mode, out)

    with subtest("log = true allows and logs, and what it logs is a policy"):
        since = machine.succeed("date +%s").strip()
        out = machine.succeed(as_user("learner 'strace true 2>&1; echo rc=$?'"))
        assert "+++ exited with 0 +++" in out and out.split()[-1] == "rc=0", out
        # The kernel's SECCOMP_RET_LOG records, as the learning path reads them.
        numbers = machine.wait_until_succeeds(
            f"journalctl -k --since @{since} -o cat --no-pager"
            " | grep -F type=1326 | grep -o 'syscall=[0-9]*' | cut -d= -f2 | sort -un | grep .").split()
        learned = machine.succeed(
            "for n in " + " ".join(numbers) + "; do scmp_sys_resolver \"$n\"; done").split()
        assert "ptrace" in learned, learned
        learned_policy = "allow " + " ".join(learned)

    with subtest("a project's policy compiles, is cached, and applies"):
        cache = f"{STATE}/seccomp"
        machine.succeed(f"rm -rf {cache}")
        # A snippet that prints nothing compiles nothing.
        out = machine.succeed(as_user("project 'strace true 2>&1; echo rc=$?'"))
        assert "Operation not permitted" in out and out.split()[-1] != "rc=0", out
        # The snippet saw the name postStart saw.
        named = machine.succeed("cat /tmp/project-policy /tmp/project-poststart").split()
        assert len(named) == 2 and named[0] == named[1] and named[0].startswith("box-"), named
        machine.succeed(f"test ! -e {cache} || test -z \"$(ls -A {cache})\"")

        # The policy learned above, as a project's.
        policy = shlex.quote(learned_policy)
        out = machine.succeed(as_user(f"FLONG_TEST_POLICY={policy} project 'strace true 2>&1; echo rc=$?'"))
        assert "+++ exited with 0 +++" in out and out.split()[-1] == "rc=0", out
        cached = machine.succeed(f"ls {cache}").split()
        assert len(cached) == 1 and cached[0].endswith(".bpf"), cached
        assert machine.succeed(f"stat -c '%a %u' {cache}").split() == ["700", "1000"]
        mtime = machine.succeed(f"stat -c %Y {cache}/{cached[0]}")

        # Warm: the same policy is the same file, not compiled again.
        out = machine.succeed(as_user(f"FLONG_TEST_POLICY={policy} project 'strace true 2>&1; echo rc=$?'"))
        assert out.split()[-1] == "rc=0", out
        assert machine.succeed(f"ls {cache}").split() == cached
        assert machine.succeed(f"stat -c %Y {cache}/{cached[0]}") == mtime

        # A name systemd does not list refuses the launch.
        out = machine.succeed(as_user(
            "FLONG_TEST_POLICY='allow no_such_call' project true 2>&1; echo rc=$?"))
        assert "seccomp policy was refused" in out and out.split()[-1] == "rc=1", out
        # So does a failing snippet.
        out = machine.succeed(as_user("FLONG_TEST_POLICY_FAIL=1 project true 2>&1; echo rc=$?"))
        assert "the policy snippet fails" in out and out.split()[-1] == "rc=1", out
        assert machine.succeed(f"ls {cache}").split() == cached

    with subtest("a launch with a project policy writes nothing to stderr"):
        # Cold, compiling the policy, and warm, reusing it: nothing is said on
        # success, the compiler's stats line included (ZIG.md quirk 34).
        cache = f"{STATE}/seccomp"
        policy = shlex.quote(learned_policy)
        machine.succeed(f"rm -rf {cache}")
        for run in ("cold", "warm"):
            # Reported, never gated (ZIG.md, "Phase 2": the cold project
            # compile time): the launch's wall time, from the test driver.
            began = time.monotonic()
            out = machine.succeed(as_user(f"FLONG_TEST_POLICY={policy} project 'echo payload-ran' 2>&1"))
            print(f"project policy, {run} launch: {time.monotonic() - began:.3f} s")
            assert out == "payload-ran\n", (run, out)
            assert len(machine.succeed(f"ls {cache}").split()) == 1, run
        # The control: the tool's own stderr does reach the caller's.
        out = machine.succeed(as_user(
            "FLONG_TEST_POLICY='allow no_such_call' project true 2>&1; echo rc=$?"))
        assert "unknown syscall no_such_call" in out and out.split()[-1] == "rc=1", out

    with subtest("no timeouts: after its 90 s, the hook opens the gate and the payload runs"):
        machine.wait_until_succeeds("test -s /tmp/rc-patient")
        assert machine.succeed("cat /tmp/rc-patient").strip() == "0"
        machine.succeed("grep -qx payload-ran /tmp/out-patient")
        machine.succeed("ls /tmp/hook-slept-slow-*")

    with subtest("switch-to-configuration leaves running sessions alone"):
        start("plain", "sleep infinity", "switch")
        name = machine.wait_until_succeeds("session-of box").strip()
        sweeper = machine.succeed(f"cat {CG}/supervisor/cgroup.procs").strip()
        machine.succeed("/run/current-system/specialisation/changed/bin/switch-to-configuration test")
        machine.succeed("grep -q FLONG_TEST_GENERATION /etc/systemd/user/flong-sessions.service")
        assert machine.succeed(f"cat {CG}/supervisor/cgroup.procs").strip() == sweeper
        assert machine.succeed("session-of box").strip() == name
        stop(name, "switch")
  '';
}
