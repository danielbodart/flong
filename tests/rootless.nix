# The rootless engine, driven the way it is meant to be: by a lingering user
# through her own user manager, on a host with no sudo at all. It covers a
# launch cold and warm, the environment a payload is given, a postStart hook
# with and without a network, that nothing of a session runs as host root,
# the refusal of a caller with no subordinate ids, the sweeper releasing a
# SIGKILLed launcher's session, the limits, the declaration's mounts, and
# the seccomp stack: the tiers, their loosenings, a project's policy and its
# cache, the tty filter, and learning a policy from a logging filter.
#
# Kept small for CI's software emulation: every declaration runs the same
# container closure, and the one thing in it built for this test is a
# one-file probe. No assertion is about time.
{ lib, ... }:

let
  # One closure for both containers: a container's closure depends on its
  # `config` alone, and the mounts are the container's other options.
  # strace is the payload that ptrace separates the tiers by; the probe
  # makes the one call no shell tool makes, an ioctl with a 64-bit request.
  boxConfig = { pkgs, ... }: {
    system.stateVersion = "24.05";
    users.users.alice = { isNormalUser = true; uid = 1000; group = "users"; };
    users.groups.users.gid = 100;
    environment.systemPackages = [ pkgs.strace (ioctlProbe pkgs) ];
  };

  # ioctl-probe REQUEST prints the errno name of ioctl(0, REQUEST, &byte),
  # or ok. Standard input is never a terminal here, so a request the filters
  # let through reaches the kernel and fails with ENOTTY, and one they refuse
  # fails with the filter's errno. The request is passed whole, all 64 bits,
  # which the C library's ioctl would truncate to an int.
  ioctlProbe = pkgs: pkgs.runCommandCC "ioctl-probe"
    {
      src = pkgs.writeText "ioctl-probe.c" ''
        #include <errno.h>
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>
        #include <sys/syscall.h>
        #include <unistd.h>

        int main(int argc, char **argv)
        {
        	char byte = 0;
        	if (argc != 2) {
        		fputs("usage: ioctl-probe REQUEST\n", stderr);
        		return 2;
        	}
        	unsigned long request = strtoul(argv[1], NULL, 0);
        	if (syscall(SYS_ioctl, 0, request, &byte) == 0) {
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
  '';

  # A project's policy, as the caller's environment states it, so that one
  # declaration covers a policy, none, a refusal and a failing snippet.
  seccompPolicy = ''
    [ -z "''${FLONG_TEST_POLICY_FAIL:-}" ] || { echo "the policy snippet fails" >&2; exit 3; }
    printf '%s\n' "''${FLONG_TEST_POLICY:-}"
  '';

  # Records what the hook is promised: who it runs as, the session it is
  # for, and how many routes the session's namespace had while the hook held
  # it. Then it leaves a daemon behind in the hooks leaf, with its output
  # redirected so that nothing waiting on the launcher's waits on it too. A
  # background job of a non-interactive shell reads /dev/null already.
  postStart = ''
    {
      id -u
      echo "$machine"
      nsenter --user="$userns" --net="$netns" cat /proc/net/route | tail -n +2 | wc -l
    } > "/tmp/poststart-$machine"
    sleep infinity >/dev/null 2>&1 &
  '';

  # Keyed on $machine alone, because on the sweeper's path that is all there
  # is.
  postStop = ''
    echo "$machine" > "/tmp/poststop-$machine"
  '';
in
{
  name = "flong-rootless";

  nodes.machine = { config, pkgs, ... }: {
    imports = [ ../module.nix ];

    virtualisation.memorySize = 2048;

    # No sudo rule can exist when there is no sudo.
    security.sudo.enable = false;

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

    systemd.tmpfiles.rules = [
      "d /srv/work 0755 root root -"
      # Written through a read-write bind, so it is the payload user's.
      "d /srv/rw 0755 alice users -"
      "f /srv/rw/secret 0644 root root - should-be-masked"
      "d /srv/lower 0755 alice users -"
      "f /srv/lower/seed 0644 alice users - from-the-lower-layer"
      "d /srv/companion 0755 alice users -"
      "d /srv/protected 0755 root root -"
    ];

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
          engine = "rootless";
          container = "box";
          user = "alice";
          command = [ "bash" "-c" ];
        };
        hooked = base // {
          inherit postStart postStop;
        };
      in
      {
        # The default workspace, `pwd`, and nothing else.
        plain = base;

        inherit hooked;

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
          binds = "printf '%s:rw\\n' /srv/companion";
          guard = ''[ -z "''${FLONG_TEST_DENY:-}" ] || { echo "the guard refuses" >&2; exit 1; }'';
        };

        # The tiers and loosenings beside plain's default, strict.
        parity = base // { seccomp.tier = "parity"; };
        debugged = base // { seccomp.debug = true; };
        nested = base // { seccomp.nestedSandbox = true; };
        learner = base // { seccomp.log = true; };
        project = base // { inherit seccompPolicy; };
      };

    environment.systemPackages =
      map (n: config.flong.${n}.launcher) [
        "plain" "hooked" "nethook" "limited" "mounts"
        "parity" "debugged" "nested" "learner" "project"
      ]
      ++ [
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
        # 0, or sits in a user namespace that maps host uid 0. A process in
        # the host's own namespace maps every id to itself, so only the ids
        # it runs as are asked of it. Prints the leaf of every process seen.
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
              if [ "$(readlink "/proc/$pid/ns/user")" != "$init" ] \
                && awk '$2 == 0 { found = 1 } END { exit !found }' "/proc/$pid/uid_map" 2>/dev/null; then
                echo "$pid in $procs maps host uid 0"
                exit 1
              fi
              echo "''${procs#"$cg"/}"
            done < "$procs"
          done
        '')
      ];
  };

  testScript = ''
    import shlex

    CG = "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/flong-sessions.service"
    STATE = "/run/user/1000/flong"

    # A command as USER, through her own user manager, with an explicit PATH
    # and the workspace as the current directory. `sudo` is nowhere in it.
    def as_user(script, user="alice"):
        inner = "export PATH=/run/wrappers/bin:/run/current-system/sw/bin; cd /srv/work; " + script
        return (f"systemd-run -M {user}@ --user --wait --pipe --quiet --collect "
                f"--expand-environment=no -- /run/current-system/sw/bin/bash -c {shlex.quote(inner)} </dev/null")

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
        prepared = machine.succeed(f"ls -d {STATE}/box-*-*-1000.100.{sub}.{gsub}.100/prepared").strip()
        assert machine.succeed(f"stat -c %u {prepared}").strip() == sub
        mtime = machine.succeed(f"stat -c %Y {prepared}")

        # The holder, started by the launcher on demand, with its sweeper.
        machine.succeed(f"test -d {CG}/supervisor")

        again = machine.succeed(as_user("plain 'id -u; id -G; echo ok'"))
        assert again == out, again
        assert machine.succeed(f"stat -c %Y {prepared}") == mtime

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
        # No limit is written unless one is declared. The memory controller
        # is enabled only for a declared limit, so the file may be absent.
        mem = f"{CG}/box/{name}/sandbox/memory.max"
        machine.succeed(f"test ! -e {mem} || grep -qx max {mem}")
        stop(name, "nethook")
        machine.fail("ss -Hltn 'sport = :18200' | grep -q .")

    with subtest("limits are written into the session's cgroup"):
        start("limited", "sleep infinity", "limited")
        name = machine.wait_until_succeeds("session-of box").strip()
        leaf = f"{CG}/box/{name}/sandbox"
        for f, want in (("memory.max", "268435456"), ("pids.max", "64"),
                        ("cpu.max", "50000 100000"), ("cpu.weight", "200"),
                        ("memory.oom.group", "1")):
            got = machine.succeed(f"cat {leaf}/{f}").strip()
            assert got == want, (f, got)
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
        for launcher in ("plain", "nested"):
            out = machine.succeed(as_user(
                f"{launcher} 'ioctl-probe 0x5412; ioctl-probe 0x100005412; "
                "ioctl-probe 0x10000541c; ioctl-probe 0x100005401'"))
            # TCGETS with the same high bit is let through, and fails only
            # for not being asked of a terminal.
            assert out.split() == ["EPERM", "EPERM", "EPERM", "ENOTTY"], (launcher, out)

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
  '';
}
