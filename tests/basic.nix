# Exercises every option that changes what the container sees: the workspace
# override, a read-write bind, a tmpfs mask over part of that bind, an overlay,
# the privilege drop, the NOPASSWD grant and the session cleanup.
{ lib, ... }:

{
  name = "flong-basic";

  nodes.machine = { pkgs, ... }: {
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
    ];

    containers.demo = {
      ephemeral = true;
      autoStart = false;
      privateNetwork = false;

      bindMounts."/srv/shared" = {
        hostPath = "/srv/shared";
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
      sudoUsers = [ "alice" ];

      # Not a git checkout, which is the point: the default asks git, and a
      # fast container is not obliged to be a repository.
      workspace = ''realpath /srv/work'';

      # Masks part of the read-write bind above.
      tmpfs = [ "/srv/shared/masked" ];

      # Readable from the lower directory; writes must not reach it.
      overlays."/opt/layered" = "/srv/lower";

      command = ''set -- bash -c "$1"'';
    };
  };

  testScript = { nodes, ... }:
    let
      launcher = lib.getExe nodes.machine.flong.demo.launcher;
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

      with subtest("sudoUsers grants NOPASSWD on the launcher"):
          out = machine.succeed("sudo -u alice sudo -n ${launcher} 'id -un'")
          assert "alice" in out, out

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
