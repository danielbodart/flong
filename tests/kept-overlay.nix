# A kept overlay, `binds`' PATH:overlay:LAYERS, over /nix/store, launched as a
# consumer that gives a container a Nix store of its own would launch it
# (PLAN.md §3): by a lingering user with no sudo, under the default strict
# tier and the three fixed filters. It covers where the writes land and that
# they outlast the container, the upper's root taking the lower root's shape
# so the payload cannot unlink what the host's store holds, the mount landing
# over bwrap's /nix/store, single-user nix over a local-overlay store built
# with it, one holder of the layers at a time and for the cgroup's whole
# life, the caller removing what is left, and each refusal in words.
#
# One VM, one container closure, with nix in it. Nothing is fetched: the
# store's derivation is built from nothing, by the container's own bash.
{ lib, ... }:

let
  boxConfig = { pkgs, ... }: {
    system.stateVersion = "24.05";
    users.users.alice = { isNormalUser = true; uid = 1000; group = "users"; };
    users.groups.users.gid = 100;
    environment.systemPackages = [ pkgs.nix ];
  };

  # Where alice keeps what a consumer would keep per launch: the layers, and
  # the local-overlay store's own state and its read-only lower's.
  home = "/home/alice";
  layers = "${home}/kept/L";
  nixDir = "${home}/nixs";
in
{
  name = "flong-kept-overlay";

  nodes.machine = { config, pkgs, ... }:
    let
      script = name: text: "${pkgs.writeShellScript "flong-test-${name}" ("set -euo pipefail\n" + text)}";
      hook = name: text: [ [ (script name text) ] ];

      # What the payload runs, from the store, which it reads through the
      # overlay's lower. `mounts`: the mounts at /nix/store, fstype and
      # options, bottom first. `nix [PATH]`: the payload's nix over a
      # local-overlay store, the host's database read through the lower's
      # state, the store's own beside it, the upper named but never bound
      # inside, its mount not checked since flong passes the layers by
      # descriptor, sandbox off since a build is the container's own
      # process under its filter; with PATH, whether the store knows it,
      # else a derivation of nothing but the container's bash built, so
      # nothing is fetched.
      probe = pkgs.writeShellScript "flong-test-kept-probe" ''
        set -euo pipefail
        case $1 in
          mounts)
            awk '$5 == "/nix/store" { for (i = 7; $i != "-"; i++); print $(i + 1), $6 }' /proc/self/mountinfo
            ;;
          nix)
            export NIX_CONF_DIR=$HOME/nix-conf NIX_USER_CONF_FILES= NIX_LOG_DIR=${nixDir}/state/log
            mkdir -p "$NIX_CONF_DIR"
            lower='local%3Freal%3D%2Fnix%2Fstore%26state%3D${lib.strings.escapeURL "${nixDir}/lower"}%26read-only%3Dtrue'
            cat > "$NIX_CONF_DIR/nix.conf" <<EOF
        experimental-features = nix-command local-overlay-store read-only-local-store
        store = local-overlay://?real=/nix/store&state=${nixDir}/state&lower-store=$lower&upper-layer=${layers}/upper&check-mount=false
        sandbox = false
        build-users-group =
        substituters =
        EOF
            if [ $# -gt 1 ]; then
              nix path-info "$2" >/dev/null && echo still-known
              exit
            fi
            bash=$(readlink -f "$(command -v bash)")
            dir=''${bash#/nix/store/}
            nix path-info "/nix/store/''${dir%%/*}" >/dev/null && echo lower-known
            out=$(nix build --no-link --print-out-paths --impure --expr \
              "derivation { name = \"kept-probe\"; system = builtins.currentSystem; builder = \"$bash\"; args = [ \"-c\" \"echo built > \$out\" ]; }")
            echo "out=$out"
            cat "$out"
            nix path-info "$out" >/dev/null && echo upper-known
            ;;
        esac
      '';
    in
    {
      imports = [ ../module.nix ];

      virtualisation.memorySize = 2048;
      virtualisation.cores = 2;

      security.sudo.enable = false;

      users.users.alice = {
        isNormalUser = true;
        uid = 1000;
        group = "users";
        linger = true;
        autoSubUidGidRange = false;
        subUidRanges = [ { startUid = 100000; count = 65536; } ];
        subGidRanges = [ { startGid = 100000; count = 65536; } ];
      };

      systemd.tmpfiles.rules = [
        "d /srv/work 0755 alice users -"
        "d /srv/protected 0755 alice users -"
      ];

      containers.box = {
        privateNetwork = true;
        config = boxConfig;
      };

      flong.kept = {
        container = "box";
        user = "alice";
        command = [ "bash" "-c" ];
        protect = [ "/srv/protected" ];
        # The layers the caller names, and with FLONG_TEST_NIX the store's
        # state, writable, and its lower's, read-only. It records the
        # session it was asked for, which postStop must be run for.
        binds = hook "binds" ''
          echo "$machine" >> /tmp/binds-machines
          printf '%s\n' "/nix/store:overlay:''${FLONG_TEST_LAYERS:-${layers}}"
          if [ -n "''${FLONG_TEST_NIX:-}" ]; then
            printf '%s\n' "${nixDir}/state:rw" "${nixDir}/lower"
          fi
        '';
        # A daemon in the hooks leaf, which keeps the cgroup populated
        # after the payload has gone, until the sweep.
        postStart = hook "poststart" ''
          if [ -n "''${FLONG_TEST_DAEMON:-}" ]; then
            sleep infinity >/dev/null 2>&1 &
            echo $! > "/tmp/daemon-$machine"
          fi
        '';
        postStop = hook "poststop" ''echo "$machine" >> /tmp/poststop-machines'';
      };

      environment.systemPackages = [ config.flong.kept.launcher ];
      environment.etc."flong-test/probe".source = probe;
    };

  testScript = ''
    import shlex

    CG = "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/flong-sessions.service"
    L = "${layers}"
    N = "${nixDir}"

    def as_user(script):
        inner = "export PATH=/run/wrappers/bin:/run/current-system/sw/bin; cd /srv/work; " + script
        return ("systemd-run -M alice@ --user --wait --pipe --quiet --collect "
                f"--expand-environment=no -- /run/current-system/sw/bin/bash -c {shlex.quote(inner)} </dev/null")

    def start(script, tag, env=""):
        run = as_user(f"{env} kept {shlex.quote(script)}; echo $? > /tmp/rc-{tag}")
        machine.succeed(f"rm -f /tmp/rc-{tag}; {run} >/tmp/out-{tag} 2>&1 &")

    def session():
        # The machine name of kept's session whose payload is asleep.
        return machine.wait_until_succeeds(
            f"for p in {CG}/box/*/sandbox/cgroup.procs; do "
            "for q in $(cat $p); do [ \"$(cat /proc/$q/comm)\" = sleep ] && basename $(dirname $(dirname $p)) && exit 0; done; done; exit 1").strip()

    def refused(env, want, rc):
        out = machine.succeed(as_user(f"{env} kept true 2>&1; echo rc=$?"))
        assert want in out and out.split()[-1] == f"rc={rc}", (env, want, out)

    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("user@1000.service")
    machine.succeed(as_user(f"mkdir -p {L}"))
    # The probe's store path, which the container reads through the lower.
    PROBE = machine.succeed("readlink -f /etc/flong-test/probe").strip()

    with subtest("binds sees $machine, and postStop runs for it"):
        machine.succeed("rm -f /tmp/binds-machines /tmp/poststop-machines")
        machine.succeed(as_user("kept true"))
        seen = machine.succeed("cat /tmp/binds-machines").split()
        stopped = machine.succeed("cat /tmp/poststop-machines").split()
        assert len(seen) == 1 and seen == stopped and seen[0].startswith("box-"), (seen, stopped)
        # A refusal after binds, here the guard's place, still runs postStop
        # for the name binds saw.
        machine.succeed("rm -f /tmp/binds-machines /tmp/poststop-machines")
        refused("FLONG_TEST_LAYERS=relative", "its layers are not an absolute path: relative", 1)
        assert machine.succeed("cat /tmp/binds-machines").split() == machine.succeed("cat /tmp/poststop-machines").split()

    with subtest("writes land in the upper, the caller's, and outlast the container"):
        out = machine.succeed(as_user("kept 'echo hi > /nix/store/kept-x && cat /nix/store/kept-x && echo \"$FLONG_BINDS\"'"))
        assert out.split() == ["hi", "/nix/store:overlay"], out
        assert machine.succeed(f"stat -c %u:%g {L}/upper/kept-x").strip() == "1000:100"
        machine.fail("test -e /nix/store/kept-x")
        assert machine.succeed(as_user("kept 'cat /nix/store/kept-x'")).strip() == "hi"

    with subtest("the upper's root is shaped as the lower's: the payload cannot unlink the host's paths"):
        assert machine.succeed(f"stat -c '%u:%g %a' {L}/upper").strip() == "100000:100 1775"
        out = machine.succeed(as_user(
            "kept 'f=$(find /nix/store -maxdepth 1 -type f | head -1); "
            "rm -f \"$f\" 2>&1 || true; test -e \"$f\" && echo kept; "
            "echo own > /nix/store/kept-own && rm /nix/store/kept-own && echo own-removed'"))
        assert "Operation not permitted" in out and "kept" in out.split() and "own-removed" in out.split(), out

    with subtest("the overlay lands over bwrap's /nix/store, nosuid and nodev"):
        out = machine.succeed(as_user(f"kept '{PROBE} mounts'"))
        lines = out.strip().split("\n")
        assert len(lines) == 2, out
        fstype, opts = lines[-1].split()
        assert fstype == "overlay" and "nosuid" in opts.split(",") and "nodev" in opts.split(","), out

    with subtest("single-user nix over a local-overlay store, under the strict filters"):
        machine.succeed(as_user(
            f"mkdir -p {N}/state {N}/lower/gcroots/per-user {N}/lower/profiles/per-user {N}/lower/temproots "
            f"&& ln -s /nix/var/nix/db {N}/lower/db"))
        out = machine.succeed(as_user(f"FLONG_TEST_NIX=1 kept '{PROBE} nix' 2>&1"))
        assert "lower-known" in out and "built" in out and "upper-known" in out, out
        path = [w for w in out.split() if w.startswith("out=")][0].removeprefix("out=")
        name = path.removeprefix("/nix/store/")
        assert machine.succeed(f"stat -c %u {L}/upper/{name}").strip() == "1000", out
        machine.fail(f"test -e {path}")
        # The next container finds it valid in the store's own database.
        out = machine.succeed(as_user(f"FLONG_TEST_NIX=1 kept '{PROBE} nix {path}' 2>&1"))
        assert "still-known" in out, out

    with subtest("one holder: a second container of the same layers is refused"):
        start("sleep infinity", "a")
        name = session()
        refused("", f"its layers {L} are in use by another container", 125)
        machine.succeed(f"kill -TERM {name.split('-')[1]}")
        machine.wait_until_succeeds("test -s /tmp/rc-a")
        machine.succeed(as_user("kept true"))

    with subtest("one holder for the cgroup's life: a SIGKILLed launcher's keeper holds the lock until it is empty"):
        sweeper = machine.succeed(f"cat {CG}/supervisor/cgroup.procs").strip()
        machine.succeed(f"kill -STOP {sweeper}")
        start("sleep infinity", "k", env="FLONG_TEST_DAEMON=1")
        name = session()
        daemon = machine.wait_until_succeeds(f"cat /tmp/daemon-{name}").strip()
        machine.succeed(f"kill -KILL {name.split('-')[1]}")
        machine.wait_until_succeeds("test -s /tmp/rc-k")
        # The payload went with its launcher; the hook's daemon keeps the
        # cgroup populated, and the keeper the layers locked.
        machine.wait_until_succeeds(f"grep -qx 'populated 0' {CG}/box/{name}/sandbox/cgroup.events")
        machine.succeed(f"test -e /proc/{daemon}")
        machine.fail(as_user(f"flock -n -x {L} true"))
        machine.succeed(f"test -e {CG}/box/{name}")
        # The next launch's own sweep releases the session: its cgroup
        # empties, the keeper lets go, and the launch goes on.
        machine.succeed(as_user("kept true"))
        machine.succeed(f"test ! -e {CG}/box/{name}")
        machine.succeed(f"test ! -e /proc/{daemon}")
        machine.succeed(as_user(f"flock -n -x {L} true"))
        machine.succeed(f"kill -CONT {sweeper}")

    with subtest("the caller removes what is left"):
        assert machine.succeed(f"stat -c %u {L}/work/work").strip() == "1000"
        # The upper's root is container root's, so its own mode is not the
        # caller's to change; everything in it is.
        machine.succeed(as_user(f"chmod -R u+w {L} 2>/dev/null; rm -rf {L} && test ! -e {L}"))
        machine.succeed(as_user(f"mkdir -p {L}"))

    with subtest("refusals, each in words"):
        machine.succeed(as_user(f"ln -s {L} ${home}/kept/S && mkdir -p /srv/protected/L ${home}/kept/W/work"))
        refused("FLONG_TEST_LAYERS=${home}/kept/S", "a symlink is on the way to its layers", 125)
        machine.succeed("install -d -o 100000 -g 100000 ${home}/kept/sub")
        refused("FLONG_TEST_LAYERS=${home}/kept/sub", "are not yours: their owner is uid 100000", 125)
        refused("FLONG_TEST_LAYERS=/nix/store/x", "LAYERS lies inside PATH", 1)
        refused("FLONG_TEST_LAYERS=/srv/protected/L", "is, holds or lies inside /srv/protected", 125)
        refused("FLONG_TEST_LAYERS=/srv/work/L", "lie in the workspace /srv/work", 1)
        refused("FLONG_TEST_LAYERS=${home}/kept/missing", "are not a directory", 125)
        machine.succeed("mount -t tmpfs -o mode=0700,uid=1000,gid=100 tmpfs ${home}/kept/W/work")
        refused("FLONG_TEST_LAYERS=${home}/kept/W", "LAYERS must be one filesystem", 125)
        machine.succeed("umount ${home}/kept/W/work")
  '';
}
