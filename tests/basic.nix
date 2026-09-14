# Exercises every option that changes what the container sees: the workspace
# override, a read-write bind, a tmpfs mask over part of that bind, an overlay,
# the privilege drop, the NOPASSWD grant and the session cleanup.
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

      # Written by whoever evaluates `workspace`, which is the point of the
      # subtest that reads it -- so it has to be writable by root AND by
      # alice, or the second caller to come along fails on the file rather
      # than on anything this test is about.
      "f /tmp/workspace-uid 0666 root root -"
      "f /tmp/workspace-args 0666 root root -"
    ];

    containers.demo = {
      ephemeral = true;
      autoStart = false;
      privateNetwork = false;

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
          home = "/home/alice";
        };
        users.groups.users.gid = 100;
        environment.systemPackages = [ pkgs.coreutils ];
      };
    };

    flong.demo = {
      user = "alice";
      uid = 1000;
      gid = 100;
      home = "/home/alice";

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
      '';

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
      uid = 1000;
      gid = 100;
      home = "/home/alice";
      workspace = ''realpath "/srv/odd:name"'';
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
      uid = 1000;
      gid = 100;
      home = "/home/alice";
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
    in
    ''
      machine.wait_for_unit("multi-user.target")

      with subtest("runs as the declared user, in the declared workspace"):
          out = machine.succeed("${launcher} 'id -un; pwd; cat marker'")
          assert "alice" in out, out
          assert "/srv/work" in out, out
          assert "in-the-workspace" in out, out

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
          machine.succeed("test -z \"$(ls -A /run/systemd/nspawn/unix-export 2>/dev/null)\"")

      with subtest("the prepared root is reused rather than rebuilt"):
          before = machine.succeed("stat -c %Y /run/flong/demo-*/prepared").strip()
          machine.succeed("${launcher} 'true'")
          after = machine.succeed("stat -c %Y /run/flong/demo-*/prepared").strip()
          assert before == after, f"prepared root was rebuilt: {before} -> {after}"
    '';
}
