# Exercises every option that changes what the container sees: the workspace
# override, a read-write bind, a tmpfs mask over part of that bind, an overlay,
# the extra binds in both modes, the privilege drop, the NOPASSWD grant, the
# session cleanup and the sweep that reclaims what a killed session left.
{ lib, ... }:

{
  name = "flong-basic";

  nodes.machine = { config, pkgs, ... }: {
    imports = [ ../module.nix ];

    virtualisation.memorySize = 3072;
    virtualisation.diskSize = 8192;
    virtualisation.additionalPaths = [ ];

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

      config = {
        system.stateVersion = "24.05";
        users.users.alice = {
          isNormalUser = true;
          uid = 1000;
          group = "users";
          home = "/home/alice";
        };
        users.groups.users.gid = 100;
      };
    };

    flong.netless = {
      user = "alice";
      workspace = ''realpath /srv/work'';
      command = ''set -- bash -c "$1"'';
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
