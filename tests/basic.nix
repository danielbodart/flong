# Exercises every option that changes what the container sees: the workspace
# override, a read-write bind, a tmpfs mask over part of that bind, an overlay,
# the extra binds in both modes, the privilege drop, the NOPASSWD grant, the
# root hook and its binds, wrapper and teardown, the network, its DNS and the
# ports it does and does not reach, the session cleanup and the sweep that
# reclaims what a killed session left.
{ lib, ... }:

{
  name = "flong-basic";

  nodes.machine = { config, pkgs, ... }: {
    imports = [ ../module.nix ];

    virtualisation.memorySize = 3072;
    virtualisation.diskSize = 8192;
    virtualisation.additionalPaths = [ ];

    # To read a session's ruleset from outside, where the workload cannot.
    environment.systemPackages = [ pkgs.nftables ];

    # The host's resolver, on the host's loopback and nowhere else: the stub
    # case -- resolved's 127.0.0.53, a dnsmasq on 127.0.0.1 -- which is the
    # whole reason a session's DNS is re-sent from the host by pasta rather
    # than the host's resolv.conf copied in, where 127.0.0.1 would name the
    # session's own loopback. resolveLocalQueries writes both families into
    # the host's resolv.conf, so both of a session's forwards are exercised.
    services.dnsmasq = {
      enable = true;
      resolveLocalQueries = true;
      settings = {
        listen-address = [ "127.0.0.1" "::1" ];
        bind-interfaces = true;
        no-resolv = true;
        address = [ "/dns.flong.test/192.0.2.53" ];
      };
    };
    # Carried into a networked session's resolv.conf, and proved to be by a
    # short name that resolves only through the search domain.
    networking.search = [ "flong.test" ];
    networking.resolvconf.extraOptions = [ "ndots:2" ];

    # What a workload tries against what the hook installed. A file in the
    # store, which every session can read, rather than a script quoted through
    # the test's shell, the launcher's and the session's.
    environment.etc."flong-tamper".source = pkgs.writeText "tamper.sh" ''
      nft list ruleset >/dev/null 2>&1 && echo listed
      nft flush ruleset >/dev/null 2>&1 && echo flushed
      grep -E '^(CapBnd|NoNewPrivs)' /proc/self/status
      # -r, so that it holds every capability the new namespace can give.
      unshare -Ur bash -c '
        grep ^CapEff /proc/self/status | sed s/CapEff/UserNsCapEff/
        nft flush ruleset >/dev/null 2>&1 && echo flushed-from-userns
        ip link add dummy0 type dummy >/dev/null 2>&1 && echo linked-from-userns
        ip route add default dev lo >/dev/null 2>&1 && echo routed-from-userns
      '
      echo attempted
      sleep 5
    '';

    users.users.alice = {
      isNormalUser = true;
      uid = 1000;
      group = "users";
      home = "/home/alice";
    };

    systemd.tmpfiles.rules = [
      "d /srv/work 0755 root root -"
      "f /srv/work/marker 0644 root root - in-the-workspace"
      "d /srv/shared 0777 root root -"
      "d /srv/shared/masked 0755 root root -"
      "f /srv/shared/masked/host-only 0644 root root - should-not-be-visible"

      # Masked by the CONTAINER's own tmpfs list rather than flong's, which the
      # container module would have passed to nspawn and flong used to drop.
      "d /srv/shared/declared 0755 root root -"
      "f /srv/shared/declared/host-only 0644 root root - should-not-be-visible"
      "d /srv/lower 0755 alice users -"
      "f /srv/lower/seed 0644 alice users - from-the-lower-layer"

      # A bind mount nested inside a flong tmpfs: the tmpfs hides the host's
      # /srv/nested, and the bind reaches through it to /srv/keep.
      "d /srv/nested 0755 root root -"
      "f /srv/nested/hidden 0644 root root - masked-by-the-tmpfs"
      "d /srv/keep 0755 root root -"
      "f /srv/keep/marker 0644 root root - through-the-tmpfs"

      # Exists, and names a character nspawn's --bind cannot express.
      "d /srv/odd:name 0755 root root -"

      # Travels with the workspace, read-write: the pairing case. Owned by
      # alice, or a session could not write to it for reasons that have
      # nothing to do with the mount being read-write.
      "d /srv/companion 0755 alice users -"
      "f /srv/companion/marker 0644 alice users - in-the-companion"

      # Reference material, read-only. Root-owned, so a write failing proves
      # the mount rather than the ownership -- the mode is what is under test,
      # and it is asserted from inside a session that CAN write to /srv/work.
      "d /srv/reference 0755 root root -"
      "f /srv/reference/marker 0644 root root - read-only-reference"

      # Written by whoever evaluates `workspace`, which is the point of the
      # subtest that reads it -- so it has to be writable by root AND by
      # alice, or the second caller to come along fails on the file rather
      # than on anything this test is about.
      "f /tmp/workspace-uid 0666 root root -"
      "f /tmp/workspace-args 0666 root root -"
    ];

    containers.demo = {
      autoStart = false;
      privateNetwork = false;

      # Declared here rather than in `flong.demo.tmpfs`: the two lists mean the
      # same thing, so flong merges them, and this is the half that used to be
      # dropped.
      tmpfs = [ "/srv/shared/declared" ];

      bindMounts."/srv/shared" = {
        hostPath = "/srv/shared";
        isReadOnly = false;
      };

      # Nested inside the tmpfs declared below. nspawn sorts custom mounts by
      # destination rather than honouring argument order, so the tmpfs lands
      # first and this reaches through it -- which is how a single socket is
      # carved out of a runtime directory that must otherwise stay hidden.
      bindMounts."/srv/nested/keep" = {
        hostPath = "/srv/keep";
        isReadOnly = false;
      };

      config = { pkgs, ... }: {
        system.stateVersion = "24.05";
        services.openssh.enable = false;
        users.users.alice = {
          isNormalUser = true;
          uid = 1000;
          group = "users";
          # Declared into a second group, so the subtest below can tell a
          # session that initialised its supplementary groups from one that
          # merely arrived with the right uid.
          extraGroups = [ "audio" ];
          home = "/home/alice";
        };
        users.groups.users.gid = 100;
        environment.systemPackages = [ pkgs.coreutils ];

        # Declared by the container and applied by nobody unless the prepare
        # step runs tmpfiles: a session never boots, so the unit that would
        # normally do it never starts. The symlink is the case that matters
        # in practice -- programs.nix-ld installs its libraries through the
        # closure and creates /lib64/ld-linux-x86-64.so.2 this way, and
        # without it every binary built for generic Linux refuses to start.
        systemd.tmpfiles.rules = [
          "d /srv/by-tmpfiles 0755 root root -"
          "f /srv/by-tmpfiles/marker 0644 root root - made-by-tmpfiles"
          "L+ /srv/by-tmpfiles/link - - - - /srv/by-tmpfiles/marker"
        ];
      };
    };

    # The one network isolation a session can have: a namespace with loopback
    # in it and nothing else. Separate from demo because every other subtest
    # wants the host's network, and because what is under test is that the
    # declaration reaches nspawn at all.
    containers.netless = {
      autoStart = false;
      privateNetwork = true;

      config = { pkgs, ... }: {
        system.stateVersion = "24.05";
        users.users.alice = {
          isNormalUser = true;
          uid = 1000;
          group = "users";
          home = "/home/alice";
        };
        users.groups.users.gid = 100;
        # So that a session can TRY to read and flush what the hook installed,
        # and to add a link and a route of its own. nc, curl, unshare and
        # nsenter are in every NixOS closure already.
        #
        # dig, to query each of pasta's DNS addresses directly.
        environment.systemPackages = [ pkgs.nftables pkgs.iproute2 pkgs.dig ];
      };
    };

    flong.netless = {
      user = "alice";
      workspace = ''realpath /srv/work'';
      command = ''set -- bash -c "$1"'';
    };

    # The same container with a root hook on it, which is the only way to reach
    # a session's namespace from outside.
    flong.hooked = {
      container = "netless";
      user = "alice";
      workspace = ''realpath /srv/work'';
      launcherInputs = [ pkgs.nftables pkgs.netcat pkgs.procps ];

      # What the caller asked for, so that FLONG_EXTRA_BINDS has something in
      # it for the hook's binds to be absent from.
      extraBinds = ''printf '%s\n' /srv/companion'';

      # A file and a socket, each from a host path named for this session, each
      # at a fixed path inside that is nothing like its source. The listener
      # is backgrounded with its output elsewhere, or the substitution this runs
      # in would wait for it.
      attachBinds = ''
        printf 'for-%s\n' "$machine" > "/run/hook-file-$machine"
        nc -lkU "/run/hook-sock-$machine" </dev/null >/dev/null 2>&1 &
        for _ in $(seq 100); do
          [ -S "/run/hook-sock-$machine" ] && break
          sleep 0.05
        done
        printf '%s\n' \
          "/run/hook-file-$machine:/run/hook/file" \
          "/run/hook-sock-$machine:/run/hook/sock"
      '';

      # Releases what attachBinds made, and says so. Keyed on $machine alone,
      # because on the sweep's path that is all there is.
      detach = ''
        pkill -f "hook-sock-$machine" || true
        rm -f "/run/hook-file-$machine" "/run/hook-sock-$machine"
        echo "$machine" >> /tmp/detached
      '';

      attach = ''
        # The binds reach the hook resolved, so it knows where it put them.
        grep -q ":/run/hook/sock$" <<< "$attach_binds"

        # Everything the hook is promised, written down for the test to read
        # back: who it runs as, that the namespace it was handed is not the
        # host's, and -- the ordering that is the whole point -- that there is
        # no egress in it at the moment the hook has it.
        {
          id -u
          readlink /proc/self/ns/net
          readlink "$netns"
          nsenter --net="$netns" cat /proc/net/route | tail -n +2 | wc -l
          echo "$machine"
        } > /tmp/attach-facts

        # And something installed through it, for the session to fail to undo.
        nsenter --net="$netns" nft \
          'add table inet flong
           add chain inet flong out { type filter hook output priority 0; policy accept; }
           add rule inet flong out tcp dport 19999 drop'
      '';

      # Exec'd between tini and the payload, inside the session. env is in
      # every NixOS closure, so this needs nothing declared to prove it ran.
      attachWrap = ''printf '%s\n' /run/current-system/sw/bin/env "FLONG_WRAPPED=$machine"'';

      command = ''set -- bash -c "$1"'';
    };

    # An attach bind naming a colon, which --bind cannot express. The source
    # exists, so this is the refusal and not a missing path.
    flong.badattachbind = {
      container = "netless";
      user = "alice";
      workspace = ''realpath /srv/work'';
      attachBinds = ''printf '%s\n' "/srv/odd:name:/run/odd"'';
      command = ''set -- true'';
    };

    # A real network, through pasta, over the same private container -- with a
    # hook that installs a rule first, because the ordering between the two is
    # the property under test.
    flong.networked = {
      container = "netless";
      user = "alice";
      workspace = ''realpath /srv/work'';
      launcherInputs = [ pkgs.nftables ];

      network = {
        # 18124 is listening on the host too, and is not named: it is the
        # "nothing else" half. 19999 is named, and the hook refuses it.
        hostPorts = [ 18123 19999 ];
        forwardPorts = [ { hostPort = 18200; containerPort = 18201; } ];
      };

      attach = ''
        # How much egress the namespace had while the hook held it. pasta is
        # attached after this returns, so the answer must be none.
        nsenter --net="$netns" cat /proc/net/route | tail -n +2 | wc -l \
          > /tmp/networked-routes-at-hook
        nsenter --net="$netns" nft \
          'add table inet flong
           add chain inet flong out { type filter hook output priority 0; policy accept; }
           add rule inet flong out tcp dport 19999 reject with tcp reset'
      '';

      # Records that it ran, and whether the session was still running when
      # it did -- which it must not be, whichever way the launcher ended.
      detach = ''
        if /run/current-system/sw/bin/systemctl is-active --quiet "$machine.scope"; then
          echo "live-at-detach" >> /tmp/detached
        fi
        echo "$machine" >> /tmp/detached
      '';

      command = ''set -- bash -c "$1"'';
    };

    # A hook that plants what a workload would, if it could ever write the
    # session's /run: an absolute symlink where the attach marker goes. Walked
    # beneath /proc/<pid>/root, that resolves against the HOST's root -- so
    # the launcher must refuse it, not follow it to /tmp/escaped.
    flong.plantedmarker = {
      container = "netless";
      user = "alice";
      workspace = ''realpath /srv/work'';
      attach = ''
        ln -s /tmp/escaped "/proc/$leader/root/run/flong-attached"
      '';
      command = ''set -- sleep 300'';
    };

    # A hook that refuses. The payload would outlive the launcher if nothing
    # killed it, which is exactly what must not happen to a session whose hook
    # never finished.
    flong.badhook = {
      container = "netless";
      user = "alice";
      workspace = ''realpath /srv/work'';
      attach = ''
        echo "the hook refuses this session" >&2
        exit 1
      '';
      command = ''set -- sleep 300'';
    };

    flong.demo = {
      user = "alice";

      # Applied to the session's scope. A limit rather than a nicety: the
      # session root, TMPDIR and every overlay upper are in /run, which is RAM.
      properties.MemoryMax = "1G";

      # Not a git checkout, which is the point: the default asks git, and a
      # fast container is not obliged to be a repository.
      #
      # The uid is recorded so the test can assert WHO evaluated this: the
      # invoking user when there is one, root only when there is not.
      workspace = ''
        id -u > /tmp/workspace-uid
        printf '%s\n' "$*" > /tmp/workspace-args
        realpath /srv/work
      '';

      # Proves the gate sees the resolved workspace rather than having to
      # work one out from $PWD. Refusing here would fail every subtest below,
      # which is the point: the value has to be there and has to be right.
      guard = ''
        [ "$workspace" = /srv/work ] || {
          echo "guard saw workspace='$workspace'" >&2
          exit 1
        }
        # The gate has to see the extra mounts too, or a second directory
        # gets in unexamined -- which is the whole reason they are resolved
        # before this runs rather than spliced in afterwards.
        [ "$extra_binds" = /srv/companion ] || {
          echo "guard saw extra_binds='$extra_binds'" >&2
          exit 1
        }
        [ "$extra_binds_ro" = /srv/reference ] || {
          echo "guard saw extra_binds_ro='$extra_binds_ro'" >&2
          exit 1
        }
      '';

      # Resolved with $workspace in scope, which is what lets a consumer pair
      # directories rather than name a fixed set.
      extraBinds = ''[ "$workspace" = /srv/work ] && printf '%s\n' /srv/companion'';
      extraBindsRo = ''printf '%s\n' /srv/reference'';

      # Masks part of the read-write bind above, and -- at /srv/nested --
      # hides a host directory that a nested bind then reaches through.
      tmpfs = [ "/srv/shared/masked" "/srv/nested" ];

      # Readable from the lower directory; writes must not reach it.
      overlays."/opt/layered" = "/srv/lower";

      command = ''set -- bash -c "$1"'';
    };

    # A second launcher over the SAME container, differing only in what its
    # workspace resolves to. The directory exists, so this is the colon being
    # refused rather than a missing path.
    flong.badworkspace = {
      container = "demo";
      user = "alice";
      workspace = ''realpath "/srv/odd:name"'';
      command = ''set -- true'';
    };

    # A fourth, whose extra bind names the colon nspawn cannot express. The
    # workspace is fine, so this is the extra list getting the same refusal
    # the workspace gets rather than sharing its code by accident.
    flong.badextrabind = {
      container = "demo";
      user = "alice";
      workspace = ''realpath /srv/work'';
      extraBinds = ''realpath "/srv/odd:name"'';
      command = ''set -- true'';
    };

    # Names a user the container does not have. Since the uid, gid and home are
    # read out of the container's passwd rather than declared, this is the whole
    # of what can now go wrong with an identity -- and it has to be caught out
    # here, because nspawn's own failure for an unknown --user arrives after a
    # root has been prepared and copied.
    flong.badusername = {
      container = "demo";
      user = "absent";
      workspace = ''realpath /srv/work'';
      command = ''set -- true'';
    };

    # A third over the same container, taking the DEFAULT workspace. It exists
    # so that the default snippet is built -- and therefore shellchecked --
    # rather than only the overrides the other two declare, which is how a
    # `$PWD` inside it once reached a release unlinted. It also covers the
    # documented contract that a non-zero exit from `workspace` aborts.
    flong.defaultworkspace = {
      container = "demo";
      user = "alice";
      command = ''set -- true'';
    };

    # Reaching the launcher is the consumer's business, not the module's.
    # This is the pattern the README documents, so the test covers that rather
    # than a module feature.
    security.sudo.extraRules = [{
      users = [ "alice" ];
      commands = [{
        command = lib.getExe config.flong.demo.launcher;
        options = [ "NOPASSWD" ];
      }];
    }];
  };

  testScript = { nodes, ... }:
    let
      launcher = lib.getExe nodes.machine.flong.demo.launcher;
      badWorkspace = lib.getExe nodes.machine.flong.badworkspace.launcher;
      defaultWorkspace = lib.getExe nodes.machine.flong.defaultworkspace.launcher;
      badExtraBind = lib.getExe nodes.machine.flong.badextrabind.launcher;
      badUsername = lib.getExe nodes.machine.flong.badusername.launcher;
      netless = lib.getExe nodes.machine.flong.netless.launcher;
      hooked = lib.getExe nodes.machine.flong.hooked.launcher;
      badHook = lib.getExe nodes.machine.flong.badhook.launcher;
      badAttachBind = lib.getExe nodes.machine.flong.badattachbind.launcher;
      plantedMarker = lib.getExe nodes.machine.flong.plantedmarker.launcher;
      networked = lib.getExe nodes.machine.flong.networked.launcher;
      # The container's own closure, for the one nspawn this file runs itself:
      # the prepared root has no PATH of its own until nspawn is given one.
      closure = nodes.machine.containers.demo.path;
    in
    ''
      machine.wait_for_unit("multi-user.target")

      # A session in the background, identified by the directory it makes: the
      # machine name carries the launcher's pid and a random number, so nothing
      # outside the launcher can know it in advance.
      def start_session(command):
          machine.succeed(f"${launcher} '{command}' >/dev/null 2>&1 &")
          return machine.wait_until_succeeds(
              "ls -d /run/flong/demo-*/s-demo-*").strip().split("/s-")[-1]

      # The launcher's own pid, out of the middle of <container>-<pid>-<random>.
      def launcher_pid(name):
          return name.split("-")[1]

      with subtest("runs as the declared user, in the declared workspace"):
          out = machine.succeed("${launcher} 'id -un; pwd; cat marker'")
          assert "alice" in out, out
          assert "/srv/work" in out, out
          assert "in-the-workspace" in out, out

      with subtest("a launch is not accompanied by a deprecation warning"):
          # systemd 261 deprecates --user= in favour of --uid= and prints a
          # warning for it on every single launch, so a tool that advertises
          # 117 ms and a clean exit spent one line of every session apologising
          # for its own command line.
          out = machine.succeed("${launcher} 'true' 2>&1")
          assert "deprecat" not in out.lower(), out

      with subtest("nothing in the session runs as root"):
          # pid 1 is tini, and nspawn drops before starting it, so there is no
          # process in here for a root phase to have belonged to.
          out = machine.succeed("${launcher} 'id -u; grep ^Uid /proc/1/status'")
          assert out.split()[0] == "1000", out
          assert "Uid:\t1000" in out, out

      with subtest("the supplementary groups come with the user"):
          out = machine.succeed("${launcher} 'id -Gn'")
          assert "audio" in out, out

      with subtest("the container's tmpfiles rules are applied to the root"):
          out = machine.succeed("${launcher} 'cat /srv/by-tmpfiles/marker; readlink /srv/by-tmpfiles/link'")
          assert "made-by-tmpfiles" in out, out
          assert "/srv/by-tmpfiles/marker" in out, out

      with subtest("the system is reachable at /run/current-system"):
          # A bind over the mount point rather than a symlink written from
          # inside, which nothing unprivileged could have written.
          machine.succeed("${launcher} 'test -x /run/current-system/sw/bin/bash'")

      with subtest("TMPDIR exists and belongs to the payload"):
          out = machine.succeed("${launcher} 'echo $TMPDIR; stat -c %U:%a \"$TMPDIR\"'")
          assert "/home/alice/tmp" in out, out
          assert "alice:700" in out, out

      with subtest("stdin reaches the payload when the launcher is not on a tty"):
          # nspawn's console default is read-only off a terminal: output
          # propagates and input is never read, so this arrived empty and
          # nothing said so.
          out = machine.succeed("echo from-the-pipe | ${launcher} 'cat'")
          assert "from-the-pipe" in out, out

      with subtest("the hostname is the container's, not the session's"):
          # The machine name carries a pid and a random number to keep
          # concurrent sessions apart, and nspawn would use it as the hostname.
          out = machine.succeed("${launcher} 'cat /proc/sys/kernel/hostname'")
          assert out.strip() == "demo", out

      with subtest("XDG_RUNTIME_DIR exists and belongs to the payload"):
          # /run is nspawn's own tmpfs, made fresh at every start, and nothing
          # inside a session can create a directory in it -- so the variable
          # named a directory that was not there.
          out = machine.succeed("${launcher} 'echo $XDG_RUNTIME_DIR; stat -c %U:%a \"$XDG_RUNTIME_DIR\"'")
          assert "/run/user/1000" in out, out
          assert "alice:700" in out, out

      with subtest("the root carries a machine id"):
          # Written by a container's init from the uuid nspawn hands it, and a
          # session has no init -- so this was absent and every reader got
          # ENOENT.
          out = machine.succeed("${launcher} 'cat /etc/machine-id'")
          assert len(out.strip()) == 32, out

      with subtest("the container's own tmpfs list is honoured too"):
          machine.succeed("test -e /srv/shared/declared/host-only")
          out = machine.succeed("${launcher} 'ls -A /srv/shared/declared | wc -l'")
          assert out.strip().endswith("0"), out

      with subtest("privateNetwork gives the session loopback and nothing else"):
          # sysfs is per-namespace, so this needs no tools in the container.
          out = machine.succeed("${launcher} 'ls /sys/class/net'")
          assert "eth0" in out, out
          out = machine.succeed("${netless} 'ls /sys/class/net'")
          assert out.split() == ["lo"], out
          # And no route out of it, in either family: this, not the missing
          # interface, is why a workload has nowhere to go until something
          # gives it egress -- which is what a hook's ordering rests on.
          out = machine.succeed("${netless} 'tail -n +2 /proc/net/route | wc -l; cat /proc/net/ipv6_route | grep -vc \" lo$\" || true'")
          assert out.split() == ["0", "0"], out

      with subtest("a private session without a network has no resolv.conf"):
          # It has nowhere to send a query, so it is not told of anywhere.
          out = machine.succeed("${netless} 'test -e /etc/resolv.conf && echo present || echo absent'")
          assert out.strip() == "absent", out

      with subtest("the root hook runs as root, in the session's namespace, before any egress"):
          # The hook is the only moment a session's namespace can be steered
          # from outside, and what makes it safe is that it happens before the
          # namespace has anywhere to go: an empty route table at hook time is
          # the ordering the whole design rests on, asserted rather than
          # assumed.
          machine.succeed("${hooked} 'true'")
          uid, host_ns, session_ns, routes, name = \
              machine.succeed("cat /tmp/attach-facts").split()
          assert uid == "0", uid
          assert session_ns != host_ns, f"{session_ns} == {host_ns}"
          assert routes == "0", f"the namespace had {routes} routes at hook time"
          assert name.startswith("netless-"), name

      with subtest("the hook wraps the payload"):
          # Between tini and the payload, so it is the workload's own parent
          # rather than something the workload's shell could decline to run.
          out = machine.succeed("${hooked} 'echo $FLONG_WRAPPED'")
          assert out.strip().startswith("netless-"), out

      with subtest("the attach marker is a directory the launcher made"):
          out = machine.succeed("${hooked} 'stat -c \"%F %U\" /run/flong-attached'")
          assert out.strip() == "directory root", out

      with subtest("an entry already at the marker's path fails the attach, and is not followed"):
          # mkdir, not touch: an absolute symlink under /proc/<pid>/root
          # resolves against the host's root, so following it would have root
          # create a host path of the session's choosing.
          machine.succeed("rm -f /tmp/escaped")
          err = machine.fail("${plantedMarker} 2>&1")
          machine.fail("test -e /tmp/escaped")
          assert "could not mark" in err, err
          machine.fail("machinectl list --no-legend | grep -q netless-")
          machine.succeed("test -z \"$(find /run/flong -maxdepth 2 -name 's-netless-*')\"")

      with subtest("the hook's binds are inside, and the payload is not told about them"):
          # A file and a socket, which extraBinds cannot carry, each at a path
          # the hook chose rather than at its own.
          out = machine.succeed("${hooked} 'cat /run/hook/file; test -S /run/hook/sock && echo socket'")
          assert "for-netless-" in out, out
          assert "socket" in out, out
          # FLONG_EXTRA_BINDS says what the CALLER asked to have mounted, and
          # the hook's plumbing is not that.
          out = machine.succeed("${hooked} 'echo $FLONG_EXTRA_BINDS'")
          assert out.strip() == "/srv/companion", out

      with subtest("an attach bind naming ':' is refused, like an extra bind"):
          err = machine.fail("${badAttachBind} 2>&1")
          assert "attach bind names" in err, err

      with subtest("the workload cannot change what the hook installed, even after unshare -U"):
          machine.succeed("${hooked} \"bash $(readlink -f /etc/flong-tamper)\" >/tmp/tamper.out 2>&1 &")
          machine.wait_until_succeeds("grep -q attempted /tmp/tamper.out")
          out = machine.succeed("cat /tmp/tamper.out")
          lines = out.split()
          assert "listed" not in lines, out
          assert "flushed" not in lines, out
          assert "flushed-from-userns" not in lines, out
          assert "linked-from-userns" not in lines, out
          assert "routed-from-userns" not in lines, out
          caps = dict(l.split(":\t") for l in out.splitlines() if ":\t" in l)
          # Defence in depth: gone from the bounding set, and nothing new to be
          # had through exec ...
          assert not int(caps["CapBnd"], 16) & (1 << 12), caps
          assert caps["NoNewPrivs"] == "1", caps
          # ... and ONLY defence in depth: inside a user namespace of its own the
          # workload holds CAP_NET_ADMIN again, which is what makes the failed
          # flush above a statement about who owns the namespace rather than
          # about which capabilities were dropped.
          assert int(caps["UserNsCapEff"], 16) & (1 << 12), caps
          # And from outside, the rule the hook installed is still there.
          name = machine.succeed("ls -d /run/flong/netless-*/s-netless-*").strip().split("/s-")[-1]
          leader = machine.succeed(f"machinectl show {name} --property=Leader --value").strip()
          rules = machine.succeed(f"nsenter --net=/proc/{leader}/ns/net nft list table inet flong")
          assert "dport 19999 drop" in rules, rules
          machine.wait_until_fails(f"machinectl show {name} >/dev/null 2>&1")

      with subtest("a session's teardown runs when it ends"):
          machine.succeed("rm -f /tmp/detached")
          machine.succeed("${hooked} 'true'")
          name = machine.succeed("cat /tmp/attach-facts").split()[4]
          assert machine.succeed("cat /tmp/detached").split() == [name]
          machine.fail(f"test -e /run/hook-file-{name}")
          machine.fail(f"test -e /run/hook-sock-{name}")
          machine.fail(f"pgrep -f hook-sock-{name}")

      with subtest("and when its launcher was killed, from the next launch's sweep"):
          # No trap survives SIGKILL, so the sweep has to -- and it has to run
          # the dead session's teardown rather than its own: the launch that
          # sweeps here is `netless`, over the same container, and has none.
          machine.succeed("rm -f /tmp/detached")
          machine.succeed("${hooked} 'sleep 300' >/dev/null 2>&1 &")
          name = machine.wait_until_succeeds(
              "ls -d /run/flong/netless-*/s-netless-*").strip().split("/s-")[-1]
          machine.wait_until_succeeds(f"machinectl show {name} >/dev/null 2>&1")
          machine.wait_until_succeeds(f"test -S /run/hook-sock-{name}")
          machine.succeed(f"kill -9 {launcher_pid(name)}")
          machine.succeed(f"systemctl kill -s KILL {name}.scope")
          machine.wait_until_fails(f"machinectl show {name} >/dev/null 2>&1")
          # Nothing has run it yet, and what it releases is still there.
          machine.fail("test -e /tmp/detached")
          machine.succeed(f"test -e /run/hook-file-{name}")
          machine.succeed(f"pgrep -f hook-sock-{name}")

          machine.succeed("${netless} 'true'")
          assert machine.succeed("cat /tmp/detached").split() == [name]
          machine.fail(f"test -e /run/hook-file-{name}")
          machine.fail(f"pgrep -f hook-sock-{name}")
          machine.fail(f"ls -d /run/flong/netless-*/s-{name}")

      # Listeners on the host's loopback, each answering with its own port so a
      # reply cannot be mistaken for another's. A banner and not a bare connect:
      # pasta accepts on its side before it knows whether the far side will, so
      # a connection that opens proves nothing.
      for port in (18123, 18124, 19999):
          machine.succeed(
              f"systemd-run --unit=listen-{port} /run/current-system/sw/bin/bash -c "
              f"'while true; do echo host-{port} | /run/current-system/sw/bin/nc -N -l 127.0.0.1 {port}; done'")
          machine.wait_until_succeeds(f"nc -d -w 2 127.0.0.1 {port} | grep -q host-{port}")

      def reach(target):
          return f"nc -d -w 3 {target} </dev/null 2>/dev/null || true"

      with subtest("rules a hook installs are in place before any egress exists"):
          # The hook saw no route at all, and pasta added some afterwards: the
          # rule was installed into a namespace with nowhere to go. And it
          # holds once there is somewhere -- 19999 is a host port the session
          # was given, and the hook's rule refuses it.
          out = machine.succeed("${networked} '"
              "tail -n +2 /proc/net/route | wc -l; "
              + reach("127.0.0.1 19999") + "'")
          assert machine.succeed("cat /tmp/networked-routes-at-hook").strip() == "0"
          routes, *rest = out.split()
          assert int(routes) > 0, out
          assert "host-19999" not in out, out

      with subtest("hostPorts reach the host's loopback, and nothing else on it does"):
          out = machine.succeed("${networked} '"
              + reach("127.0.0.1 18123") + "; echo ---; "
              + reach("127.0.0.1 18124") + "; echo ---; "
              # --no-map-gw: the gateway address is not a way to the host's
              # loopback either, for a named port or an unnamed one.
              + "gw=$(ip -4 route show default | awk \"{ print \\$3 }\"); "
              + reach("$gw 18123") + "; echo ---; "
              + reach("$gw 18124") + "'")
          named, unnamed, gw_named, gw_unnamed = out.split("---")
          assert "host-18123" in named, out
          assert "host-18124" not in unnamed, out
          assert "host-18123" not in gw_named, out
          assert "host-18124" not in gw_unnamed, out

      with subtest("a networked session resolves through the host's loopback resolver"):
          # The premise: the host's resolver is a stub on its loopback, in
          # both families, and on nothing else.
          machine.succeed("grep -qx 'nameserver 127.0.0.1' /etc/resolv.conf")
          machine.succeed("grep -qx 'nameserver ::1' /etc/resolv.conf")
          listening = machine.succeed("ss -Hlun 'sport = :53' | awk '{ print $4 }'").split()
          assert sorted(listening) == ["127.0.0.1:53", "[::1]:53"], listening

          out = machine.succeed("${networked} '"
              "cat /etc/resolv.conf; echo ---; "
              "getent ahostsv4 dns.flong.test; echo ---; "
              "getent ahostsv4 dns; echo ---; "
              "ip -6 route show default; echo ---; "
              "dig -4 +short +time=2 +tries=1 @169.254.1.1 dns.flong.test; echo ---; "
              "dig -6 +short +time=2 +tries=1 @100::1 dns.flong.test'")
          resolv, full, short, route6, via4, via6 = out.split("---")
          lines = resolv.strip().splitlines()
          assert [l for l in lines if l.startswith("nameserver")] == \
              ["nameserver 169.254.1.1", "nameserver 100::1"], resolv
          assert "search flong.test" in lines, resolv
          assert any(l.startswith("options") and "ndots:2" in l.split() for l in lines), resolv
          assert "192.0.2.53" in full, out
          # Found only through the search domain carried over from the host.
          assert "192.0.2.53" in short, out
          # Each family's address, asked directly: pasta configured IPv6 in
          # the namespace, so the second is a real path and not a skipped one.
          assert "default" in route6, out
          assert via4.strip() == "192.0.2.53", out
          assert via6.strip() == "192.0.2.53", out

      with subtest("a forwarded port reaches the session from the host"):
          # And a second listener on a port that is not forwarded, left up past
          # the one-second scan with which pasta's default `auto` would have
          # forwarded it -- so that "nothing else" is a statement about -t
          # none, and not about there being nothing to find.
          machine.succeed("${networked} '"
              "echo not-forwarded | timeout 6 nc -N -l 18202 & "
              "echo from-the-session | nc -N -l 18201; wait' >/dev/null 2>&1 &")
          machine.wait_until_succeeds("nc -d -w 3 127.0.0.1 18200 | grep -q from-the-session")
          out = machine.succeed("sleep 2; nc -d -w 2 127.0.0.1 18202 </dev/null 2>&1 || true")
          assert "not-forwarded" not in out, out
          machine.wait_until_succeeds("test -z \"$(ls -A /run/flong/netns)\"")

          # One host port, one session: a second session asking for the same
          # one cannot bind it, and is ended rather than run without it.
          machine.succeed("${networked} 'sleep 300' >/dev/null 2>&1 &")
          first = machine.wait_until_succeeds(
              "ls /run/flong/netns | grep -v pid").split()
          assert len(first) == 1, first
          machine.fail("${networked} 'echo ran'")
          machine.succeed(f"systemctl kill -s KILL {first[0]}.scope")
          machine.wait_until_fails(f"machinectl show {first[0]} >/dev/null 2>&1")
          machine.wait_until_succeeds("test -z \"$(ls -A /run/flong/netns)\"")

      # By command line, not by name: nixpkgs' pasta execs passt.avx2 where the
      # CPU has it, and `pgrep pasta` then matches nothing whether pasta is
      # there or not. The bracket keeps the pattern from matching the shell
      # that runs pgrep, whose own command line holds it too.
      def pasta_for(name=""):
          return f"pgrep -f '[/]run/flong/netns/{name}'"

      with subtest("a clean exit releases the pin and pasta"):
          machine.succeed("${networked} 'sleep 1' >/dev/null 2>&1 &")
          name = machine.wait_until_succeeds(
              "ls /run/flong/netns | grep -v pid").strip()
          machine.wait_until_succeeds(pasta_for(name + " "))
          machine.wait_until_fails(f"machinectl show {name} >/dev/null 2>&1")
          machine.wait_until_succeeds("test -z \"$(ls -A /run/flong/netns)\"")
          machine.wait_until_fails(pasta_for())

      with subtest("a killed session's pin and pasta are reaped by the next launch"):
          # The leak this has to catch: the pin keeps a dead session's
          # namespace alive, and pasta alive with it, for as long as the host
          # runs -- and neither is inside the scope that was killed.
          machine.succeed("${networked} 'sleep 300' >/dev/null 2>&1 &")
          name = machine.wait_until_succeeds(
              "ls /run/flong/netns | grep -v pid").strip()
          machine.wait_until_succeeds(f"test -s /run/flong/netns/{name}.pid")
          machine.succeed(f"kill -9 {launcher_pid(name)}")
          machine.succeed(f"systemctl kill -s KILL {name}.scope")
          machine.wait_until_fails(f"machinectl show {name} >/dev/null 2>&1")
          machine.succeed(f"mountpoint -q /run/flong/netns/{name}")
          machine.succeed(pasta_for(name + " "))

          # An unrelated launch over the same container, with no network of
          # its own, is where the sweep runs.
          machine.succeed("${netless} 'true'")
          machine.fail(f"test -e /run/flong/netns/{name}")
          machine.fail(f"test -e /run/flong/netns/{name}.pid")
          machine.wait_until_fails(pasta_for())

      with subtest("SIGTERM to the launcher ends the session before releasing it"):
          # The launcher owns its session: asked to stop, it stops the scope
          # and waits, and only then runs detach, pulls the pin and removes the
          # root. Releasing first did all three under a session still running.
          machine.succeed("rm -f /tmp/detached")
          machine.succeed("${networked} 'sleep 300' >/dev/null 2>&1 &")
          name = machine.wait_until_succeeds(
              "ls /run/flong/netns | grep -v pid").strip()
          machine.wait_until_succeeds(f"test -s /run/flong/netns/{name}.pid")
          machine.wait_until_succeeds(pasta_for(name + " "))
          machine.succeed(f"kill -TERM {launcher_pid(name)}")
          machine.wait_until_fails(f"test -d /proc/{launcher_pid(name)}")
          machine.fail(f"systemctl is-active --quiet {name}.scope")
          machine.fail(f"machinectl show {name} >/dev/null 2>&1")
          machine.fail(f"test -e /run/flong/netns/{name}")
          machine.fail(f"test -e /run/flong/netns/{name}.pid")
          machine.wait_until_fails(pasta_for(name + " "))
          machine.fail(f"ls -d /run/flong/netless-*/s-{name}")
          assert machine.succeed("cat /tmp/detached").split() == [name], \
              machine.succeed("cat /tmp/detached")

      for port in (18123, 18124, 19999):
          machine.succeed(f"systemctl stop listen-{port}")

      with subtest("a session whose hook refuses does not run"):
          # The payload is `sleep 300`: if the launcher merely gave up, the
          # session would outlive it -- systemd-run makes the workload a child
          # of the scope, not of the launcher -- and would be running with
          # nothing installed in its namespace and nobody left to install it.
          err = machine.fail("${badHook} 2>&1")
          assert "the hook refuses this session" in err, err
          machine.fail("machinectl list --no-legend | grep -q netless-")
          machine.succeed("test -z \"$(find /run/flong -maxdepth 2 -name 's-netless-*')\"")

      with subtest("the scope is in machine.slice and carries its properties"):
          # Both facts in one read, and from the host deliberately: the session
          # has a cgroup namespace of its own, so from inside it the limit is on
          # an ancestor it cannot see and /sys/fs/cgroup/memory.max says "max".
          machine.succeed("${launcher} 'sleep 5' >/dev/null 2>&1 &")
          limit = machine.wait_until_succeeds(
              "cat /sys/fs/cgroup/machine.slice/demo-*.scope/memory.max").strip()
          assert limit == str(1024 * 1024 * 1024), limit
          # And nothing of that session survives it, which the subtests after
          # this one assume.
          machine.wait_until_succeeds("test -z \"$(find /run/flong -maxdepth 2 -name 's-*')\"")

      with subtest("a SIGKILLed session's machine name can be used again"):
          # nspawn mounts a tmpfs at /run/systemd/nspawn/<machine>/unix-export
          # and removes it on the way out. A SIGKILL leaves it, and nspawn
          # refuses to start a machine of that name over it -- so what the
          # sweep unmounts has to be the path nspawn actually used, which is
          # not the one it used before systemd 257.
          name = start_session("sleep 300")
          machine.wait_until_succeeds(f"mountpoint -q /run/systemd/nspawn/{name}/unix-export")
          # The launcher first and with SIGKILL, so no trap runs, and then the
          # scope, which is what actually holds nspawn: the order matters,
          # because a launcher that outlives its scope cleans up after it.
          machine.succeed(f"kill -9 {launcher_pid(name)}")
          machine.succeed(f"systemctl kill -s KILL {name}.scope")
          machine.wait_until_fails(f"machinectl show {name} >/dev/null 2>&1")
          machine.succeed(f"mountpoint -q /run/systemd/nspawn/{name}/unix-export")

          # A root of its own to start over, because the prepared one is shared
          # with every later subtest and nspawn writes to the tree it is given.
          machine.succeed("cp -a $(echo /run/flong/demo-*/prepared) /tmp/reuse-root")
          reuse = (f"systemd-nspawn -q --machine={name} --directory=/tmp/reuse-root"
                   " --bind-ro=/nix/store --bind-ro=/nix/var/nix/db"
                   " ${closure}/sw/bin/true")
          # The failure this is really about, so the sweep below is not proving
          # something that would have worked anyway.
          err = machine.fail(f"{reuse} 2>&1")
          assert "exists already" in err, err

          # An unrelated launch is where the sweep runs.
          machine.succeed("${launcher} 'true'")
          machine.fail(f"test -e /run/systemd/nspawn/{name}")
          machine.succeed(reuse)
          machine.succeed("rm -rf /tmp/reuse-root")

      with subtest("the sweep leaves a session whose launcher was killed but whose container is alive"):
          # `systemd-run --scope` makes the workload a child of the SCOPE, so
          # SIGKILLing the launcher leaves the scope active, nspawn alive and
          # the payload running. The sweep read /proc for the launcher pid in
          # the session's name, called that dead, and deleted the root of a
          # session that was still using it.
          name = start_session("sleep 300")
          machine.succeed(f"kill -9 {launcher_pid(name)}")
          machine.wait_until_fails(f"test -d /proc/{launcher_pid(name)}")
          machine.succeed("${launcher} 'true'")
          machine.succeed(f"ls -d /run/flong/demo-*/s-{name}")
          machine.succeed(f"systemctl is-active --quiet {name}.scope")
          machine.succeed(f"machinectl show {name} >/dev/null")

          # And once nothing owns it either, the next launch does take it --
          # or a killed launcher would leave a root nothing ever reclaims.
          machine.succeed(f"systemctl kill -s KILL {name}.scope")
          machine.wait_until_fails(f"machinectl show {name} >/dev/null 2>&1")
          machine.succeed("${launcher} 'true'")
          machine.fail(f"ls -d /run/flong/demo-*/s-{name}")

      with subtest("a leftover from a superseded closure is swept"):
          # The cache is keyed on the closure hash, so a nixos-rebuild strands
          # the previous generation's cache in a directory the old sweep --
          # this launch's own s-* and nothing else -- never looked at again.
          #
          # The fixture is spelt like a real cache: a prepared root carrying
          # the immutable directory tmpfiles leaves behind, and a session whose
          # owner pid is one greater than the greatest the kernel will hand
          # out, so /proc can never hold it and it is unambiguously dead.
          dead = machine.succeed("cat /proc/sys/kernel/pid_max").strip()
          stale = "/run/flong/demo-00000000-00000000"
          machine.succeed(f"mkdir -p {stale}/prepared/var/empty {stale}/s-demo-{dead}-1")
          machine.succeed(f"chattr +i {stale}/prepared/var/empty")

          # A container whose name begins with this one's, which the sweep must
          # not touch: both hashes are spelt out so the glob cannot reach it.
          neighbour = "/run/flong/demo-two-00000000-00000000"
          machine.succeed(f"mkdir -p {neighbour}/prepared")

          machine.succeed("${launcher} 'true'")
          machine.fail(f"test -e {stale}")
          machine.succeed(f"test -d {neighbour}/prepared")
          machine.succeed(f"rm -rf {neighbour}")
          # The cache this launch actually uses is not swept with it.
          machine.succeed("test -e /run/flong/demo-*/prepared/etc/passwd")

      with subtest("a user the container does not have is refused"):
          err = machine.fail("${badUsername} 2>&1")
          assert "absent is not a user in containers.demo" in err, err

      with subtest("the identity comes from the container, not from the module"):
          # Nothing declares 1000, 100 or /home/alice to flong: they are read
          # out of the prepared root's passwd, so this proves the read rather
          # than an agreement between two copies of the same number.
          out = machine.succeed("${launcher} 'id -u; id -g; echo $HOME; stat -c %u:%g \"$TMPDIR\"'")
          uid, gid, home, tmpdir = out.split()
          assert (uid, gid) == ("1000", "100"), out
          assert home == "/home/alice", out
          assert tmpdir == "1000:100", out

      with subtest("a tmpfs masks part of a read-write bind"):
          machine.succeed("test -e /srv/shared/masked/host-only")
          out = machine.succeed("${launcher} 'ls -A /srv/shared/masked | wc -l'")
          assert out.strip().endswith("0"), out

      with subtest("the masked path is writable by the payload's user"):
          machine.succeed("${launcher} 'echo scratch > /srv/shared/masked/mine; test -s /srv/shared/masked/mine'")
          machine.fail("test -e /srv/shared/masked/mine")

      with subtest("writes to the bind reach the host"):
          machine.succeed("${launcher} 'echo through > /srv/shared/passthrough'")
          machine.succeed("grep -q through /srv/shared/passthrough")

      with subtest("an overlay reads the lower layer"):
          out = machine.succeed("${launcher} 'cat /opt/layered/seed'")
          assert "from-the-lower-layer" in out, out

      with subtest("overlay writes are discarded, not passed down"):
          machine.succeed("${launcher} 'echo scratch > /opt/layered/new; test -e /opt/layered/new'")
          machine.fail("test -e /srv/lower/new")
          machine.succeed("test -e /srv/lower/seed")

      with subtest("extra binds are mounted at their own paths"):
          out = machine.succeed("${launcher} 'cat /srv/companion/marker; cat /srv/reference/marker'")
          assert "in-the-companion" in out, out
          assert "read-only-reference" in out, out

      with subtest("a read-write extra bind takes writes and a read-only one refuses"):
          machine.succeed("${launcher} 'echo written > /srv/companion/from-session'")
          machine.succeed("grep -q written /srv/companion/from-session")
          machine.fail("${launcher} 'echo nope > /srv/reference/from-session'")
          machine.fail("test -e /srv/reference/from-session")

      with subtest("the command is told about the extra binds"):
          # A mount the process does not know about is half of what the
          # caller asked for, so the paths reach it in the environment.
          out = machine.succeed("${launcher} 'echo $FLONG_EXTRA_BINDS'")
          assert out.strip() == "/srv/companion", out
          out = machine.succeed("${launcher} 'echo $FLONG_EXTRA_BINDS_RO'")
          assert out.strip() == "/srv/reference", out

      with subtest("an extra bind naming ':' is refused, like a workspace"):
          err = machine.fail("${badExtraBind} 2>&1")
          assert "extra bind names" in err, err

      with subtest("the exit status of the command is the exit status of the launcher"):
          machine.succeed("${launcher} 'exit 0'")
          machine.fail("${launcher} 'exit 3'")

      with subtest("an unprivileged user can be granted the launcher"):
          out = machine.succeed("sudo -u alice sudo -n ${launcher} 'id -un'")
          assert "alice" in out, out

      with subtest("workspace is evaluated as the invoking user, not as root"):
          # The line above went through sudo, so the caller was alice.
          uid = machine.succeed("cat /tmp/workspace-uid").strip()
          assert uid == "1000", f"workspace ran as uid {uid}, expected alice"

      with subtest("workspace falls back to root when there is no caller"):
          # Invoked straight from the test's root shell: no SUDO_UID to drop
          # to, so root is the only identity available and the launch stands.
          machine.succeed("${launcher} 'true'")
          uid = machine.succeed("cat /tmp/workspace-uid").strip()
          assert uid == "0", f"workspace ran as uid {uid}, expected root"

      with subtest("guard runs after workspace and sees the resolved path"):
          # The guard above refuses unless $workspace is already resolved, so
          # every launch in this file proves the ordering. Assert it directly
          # too, or a guard silently emptied of its check would still pass.
          out = machine.succeed("${launcher} 'echo ok'")
          assert "ok" in out, out
          err = machine.fail("${badWorkspace} 2>&1")
          assert "workspace contains" in err, err

      with subtest("workspace sees the launcher's arguments, caller or not"):
          machine.succeed("sudo -u alice sudo -n ${launcher} 'true'")
          assert machine.succeed("cat /tmp/workspace-args").strip() == "true"
          # The root fallback takes a different code path to reach the same
          # snippet, and used to disagree with it about "$@".
          machine.succeed("${launcher} 'false || true'")
          assert machine.succeed("cat /tmp/workspace-args").strip() == "false || true"

      with subtest("a workspace naming a colon is refused, not mounted"):
          machine.succeed("test -d '/srv/odd:name'")
          err = machine.fail("${badWorkspace} 2>&1")
          assert "workspace contains" in err, err

      with subtest("the default workspace aborts outside a git checkout"):
          machine.fail("cd /srv && ${defaultWorkspace}")

      with subtest("a bind mount nested inside a tmpfs reaches through it"):
          # The tmpfs hides the host's /srv/nested ...
          out = machine.succeed("${launcher} 'ls -A /srv/nested'")
          assert "hidden" not in out, out
          # ... and the bind beneath it is still mounted, because nspawn
          # orders custom mounts by destination rather than by argument.
          out = machine.succeed("${launcher} 'cat /srv/nested/keep/marker'")
          assert "through-the-tmpfs" in out, out

      with subtest("nothing is left behind"):
          machine.succeed("test -z \"$(find /run/flong -maxdepth 2 -name 's-*' 2>/dev/null)\"")
          # nspawn's own leftovers, at the paths it actually uses: a directory
          # per machine holding the unix-export tmpfs, and the mount tunnel
          # under propagate/<machine>.
          # A killed session leaves a directory named for its machine here,
          # holding the unix-export tmpfs, and a mount tunnel under
          # propagate/. A machine name is <container>-<pid>-<random>, which is
          # what tells one from `locks` and `propagate` -- nspawn's own two,
          # which outlive every session.
          machine.succeed("test -z \"$(ls -d /run/systemd/nspawn/*-*-* 2>/dev/null)\"")
          machine.succeed("test -z \"$(ls -A /run/systemd/nspawn/propagate)\"")

      with subtest("the prepared root is reused rather than rebuilt"):
          before = machine.succeed("stat -c %Y /run/flong/demo-*/prepared").strip()
          machine.succeed("${launcher} 'true'")
          after = machine.succeed("stat -c %Y /run/flong/demo-*/prepared").strip()
          assert before == after, f"prepared root was rebuilt: {before} -> {after}"

      with subtest("the cache is named for the prepare steps as well as the closure"):
          # A root prepared by an older flong is not a root this one would
          # build, so the directory has to stop matching when prepare changes.
          # Nothing in one VM run can change prepare and look again, so what is
          # checked is that the name carries a second hash at all -- which is
          # what a revert to keying on the closure alone would lose.
          import re
          name = machine.succeed("basename $(dirname /run/flong/demo-*/prepared)").strip()
          assert re.fullmatch(r"demo-[a-z0-9]{8}-[a-z0-9]{8}", name), name
    '';
}
