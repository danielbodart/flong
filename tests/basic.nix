# Exercises every option that changes what the container sees: the workspace
# override, a read-write bind, a tmpfs mask over part of that bind, an overlay,
# the caller's binds in both modes, the declaration's file and socket binds,
# the command as an argument list, the identity, the caller's hooks and their
# teardown, the network, its DNS and the ports it does and does not reach, the
# session cleanup and the sweep that reclaims what a killed session left.
#
# Every launch is made by a lingering alice through her own user manager, on a
# host with no sudo at all.
#
# In two parts, basic-a and basic-b (flake.nix), each its own VM with about
# half the subtests (tests/parts.nix). A subtest that names no part is in
# part b.
{ config, lib, ... }:

let
  inherit (config) part;
  parts = import ./parts.nix { inherit part; default = "b"; };

  # How a hook reaches the session's network namespace. The hook is the
  # caller, and the namespace belongs to the session's user namespace, which
  # it must enter first to hold any capability there.
  enter = ''nsenter --user="$userns" --net="$netns"'';

  # Where a hook leaves what postStop releases: somewhere the caller can
  # write, which /run is not.
  hookDir = "/tmp";

  # The holder unit's cgroup, under which every session of alice's
  # lives: <container>/<machine>/{sandbox,hooks,pasta}.
  holderCgroup = "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/flong-sessions.service";
in
{
  imports = [ parts.module ];

  name = "flong-basic" + lib.optionalString (part != "all") "-${part}";

  nodes.machine = { pkgs, ... }:
    let
      # A hook is a list of commands, and `workspace` one: each snippet
      # below is a script of its own, under the options the snippets had.
      script = name: text: "${pkgs.writeShellScript "flong-test-${name}" ("set -euo pipefail\n" + text)}";
      ws = text: [ (script "workspace" text) ];
      hook = name: text: [ [ (script name text) ] ];
    in
    {
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
      # A workload may not make a user namespace of its own.
      unshare -U true 2>/dev/null || echo unshare-refused
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
      # A user manager from boot, which every launch goes through.
      linger = true;
      # Stated rather than allocated, so the cache's name is known.
      autoSubUidGidRange = false;
      subUidRanges = [ { startUid = 100000; count = 65536; } ];
      subGidRanges = [ { startGid = 100000; count = 65536; } ];
    };

    # No sudo rule can exist when there is no sudo.
    security.sudo.enable = false;

    systemd.tmpfiles.rules = [
      "d /srv/work 0755 root root -"
      "f /srv/work/marker 0644 root root - in-the-workspace"
      "d /srv/shared 0777 root root -"
      "d /srv/shared/masked 0755 root root -"
      "f /srv/shared/masked/host-only 0644 root root - should-not-be-visible"

      # Masked by a second entry in the declaration's tmpfs list.
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

      # Masked by flong.demo's `masks`, inside the read-write bind of
      # /srv/shared: one stays as it is, and one the host renames a new file
      # over while a session is running.
      "f /srv/shared/secret 0644 root root - should-be-masked"
      "f /srv/shared/renamed 0644 root root - masked-at-launch"

      # Where containers.demo's symlink in alice's home points, on the host.
      # A launcher that followed it would make a directory in here. alice's,
      # as the launcher is, so nothing but the refusal stops the directory
      # being made.
      "d /srv/escape-target 0755 alice users -"

      # Exists, and names the character a bind list separates modes with.
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

      # The sources of containers.netless's file binds, owned by the payload's
      # user, so a write that fails is refused by the mount and not by
      # permissions. The socket beside them is bound-sock's.
      "d /srv/bound 0755 alice users -"
      "f /srv/bound/file 0644 alice users - declared-file"
      "f /srv/bound/rw 0644 alice users -"
    ];

    # A listener on a unix socket owned by the payload's user, which every
    # netless session binds read-only. It keeps what it is sent in a file of
    # its own for the test to read back.
    systemd.services.bound-sock = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig.User = "alice";
      script = "exec ${pkgs.netcat}/bin/nc -lkU /srv/bound/sock >> /tmp/bound-sock-received";
    };

    containers.demo = {
      autoStart = false;
      # A session always has a network namespace of its own, and flong
      # refuses a declaration that says otherwise.
      privateNetwork = true;

      # Masks part of the read-write bind below, and -- at /srv/nested --
      # hides a host directory that a nested bind then reaches through. The
      # last names a path with a space and no options: flong reads the path
      # out of it and gives it the payload's ownership. (Not a colon, which
      # nspawn would take as `\:`: the container module splices this list
      # into its own unit's script, and shellcheck refuses that build.)
      tmpfs = [
        "/srv/shared/masked"
        "/srv/shared/declared"
        "/srv/nested"
        "/srv/tmp masked"
      ];

      # A bind whose paths hold a space, a colon and a backslash on both
      # sides. Read as data, each reaches the launcher as one path; the
      # container module's own unit would split it into mounts nobody
      # declared. Read-only, the declaration's default.
      bindMounts."/srv/odd: in\\side".hostPath = "/srv/odd: out\\side";

      bindMounts."/srv/shared" = {
        hostPath = "/srv/shared";
        isReadOnly = false;
      };

      # Nested inside the tmpfs declared below. flong sorts mounts by
      # destination rather than by declaration, so the tmpfs lands first and
      # this reaches through it -- which is how a single socket is
      # carved out of a runtime directory that must otherwise stay hidden.
      bindMounts."/srv/nested/keep" = {
        hostPath = "/srv/keep";
        isReadOnly = false;
      };

      # Deep in alice's home, where the root has neither ~/deep nor
      # ~/deep/er: the launcher makes both, and makes them hers.
      bindMounts."/home/alice/deep/er/keep".hostPath = "/srv/keep";

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
          # On the PATH /etc/set-environment gives the payload, and nowhere
          # else: not in the system profile.
          packages = [ pkgs.hello ];
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
          # A symlink in the root's home to an absolute path, which from the
          # launcher's side is the host's.
          "d /home/alice 0700 alice users -"
          "L+ /home/alice/escape - - - - /srv/escape-target"
        ];
      };
    };

    # A session with no network: a namespace with loopback in it and nothing
    # else. Separate from demo, so that the networked declarations and hooks
    # over it share its closure and not demo's mounts.
    containers.netless = {
      autoStart = false;
      privateNetwork = true;

      # Single files and a socket, which the caller's `binds` cannot carry,
      # each at a path nothing like its source: a file, read-only by default;
      # a file bound read-write; and a socket, read-only, which must still
      # connect.
      bindMounts."/run/bound/file".hostPath = "/srv/bound/file";
      bindMounts."/run/bound/rw" = {
        hostPath = "/srv/bound/rw";
        isReadOnly = false;
      };
      bindMounts."/run/bound/sock".hostPath = "/srv/bound/sock";

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
      workspace = ws ''realpath /srv/work'';
      command = [ "bash" "-c" ];
    };

    # The same container with a hook on it, which is the only way to reach a
    # session's namespace from outside, and runs as the caller.
    flong.hooked = {
      container = "netless";
      user = "alice";
      workspace = ws ''realpath /srv/work'';
      path = [ pkgs.nftables pkgs.netcat pkgs.procps ];

      # What the caller asked for, so that FLONG_BINDS has something in it
      # for the hook's binds to be absent from.
      binds = hook "binds" ''printf '%s:rw\n' /srv/companion'';

      # Releases what postStart made, and says so. Keyed on $machine alone,
      # because on the sweep's path that is all there is.
      # Two commands, run in order.
      postStop = hook "poststop" ''
        pkill -f "hook-sock-$machine" || true
        rm -f "${hookDir}/hook-file-$machine" "${hookDir}/hook-sock-$machine"
      '' ++ hook "poststop-after" ''
        echo "$machine" >> /tmp/stopped
      '';

      postStart = hook "poststart" ''
        # The caller's binds reach the hook, as they reached the guard.
        [ "$binds" = /srv/companion:rw ]

        # Everything the hook is promised, written down for the test to read
        # back: who it runs as, that the namespace it was handed is not the
        # host's, and -- the ordering that is the whole point -- that there is
        # no egress in it at the moment the hook has it.
        {
          id -u
          readlink /proc/self/ns/net
          readlink "$netns"
          ${enter} cat /proc/net/route | tail -n +2 | wc -l
          echo "$machine"
        } > /tmp/poststart-facts

        # And something installed through it, for the session to fail to undo.
        ${enter} nft \
          'add table inet flong
           add chain inet flong out { type filter hook output priority 0; policy accept; }
           add rule inet flong out tcp dport 19999 drop'

        # Resources made for this session alone, named for it, for postStop
        # to release: a file, and a listener that outlives the hook. Its
        # output is redirected only so that the test's own shell, waiting on
        # the launcher's output, does not wait on the listener as well.
        printf 'for-%s\n' "$machine" > "${hookDir}/hook-file-$machine"
        nc -lkU "${hookDir}/hook-sock-$machine" </dev/null >/dev/null 2>&1 &
        for _ in $(seq 100); do
          [ -S "${hookDir}/hook-sock-$machine" ] && break
          sleep 0.05
        done
      '';

      command = [ "bash" "-c" ];
    };

    # A real network, through pasta, over the same private container -- with a
    # hook that installs a rule first, because the ordering between the two is
    # the property under test.
    # Every port the session listens on, published while it listens.
    flong.autoPorts = {
      container = "netless";
      user = "alice";
      workspace = ws ''realpath /srv/work'';
      network.forwardPorts = "auto";
      network.hostLoopbackToSession = true;
      command = [ "bash" "-c" ];
    };

    flong.networked = {
      container = "netless";
      user = "alice";
      workspace = ws ''realpath /srv/work'';
      path = [ pkgs.nftables ];

      network = {
        # 18124 is listening on the host too, and is not named: it is the
        # "nothing else" half. 19999 is named, and the hook refuses it.
        hostPorts = [ 18123 19999 ];
        forwardPorts = [ { hostPort = 18200; containerPort = 18201; } ];
      };

      postStart = hook "poststart" ''
        # How much egress the namespace had while the hook held it. pasta is
        # attached after this returns, so the answer must be none.
        ${enter} cat /proc/net/route | tail -n +2 | wc -l \
          > /tmp/networked-routes-at-hook
        ${enter} nft \
          'add table inet flong
           add chain inet flong out { type filter hook output priority 0; policy accept; }
           add rule inet flong out tcp dport 19999 reject with tcp reset'
      '';

      # Records that it ran, and whether the session was still running when
      # it did -- which it must not be, whichever way the launcher ended. A
      # session is its cgroup's sandbox leaf, which has a process in it for as
      # long as the session runs.
      postStop = hook "poststop" ''
        if read -r _ 2>/dev/null <"${holderCgroup}/netless/$machine/sandbox/cgroup.procs"; then
          echo "live-at-poststop" >> /tmp/stopped
        fi
        echo "$machine" >> /tmp/stopped
      '';

      command = [ "bash" "-c" ];
    };

    # A hook that holds its launch until the test lets it go, so the session's
    # record can be read while its launcher has written all of it
    # (flong-launch.c:727, 522 and 755: the record, leader=, then the hook).
    # The postStop is there to be named by poststop=; it says it ran.
    flong.recorded = {
      container = "netless";
      user = "alice";
      workspace = ws ''realpath /srv/work'';
      postStart = hook "poststart" ''
        echo "$machine" > /tmp/recorded-hook
        for _ in $(seq 1200); do
          [ -e /tmp/recorded-go ] && exit 0
          sleep 0.1
        done
        exit 1
      '';
      postStop = hook "poststop" ''
        echo "$machine" >> /tmp/recorded-stopped
      '';
      command = [ "bash" "-c" ];
    };

    # Hooks that list what they hold. The launcher spawns postStart
    # (flong-launch.c:586-609) and postStop (flong-record.c:436-466) through
    # fl_spawn, whose child marks everything above 2 close-on-exec
    # (flong-util.c:435-438) and keeps nothing (.nkeep = 0), so the hook's
    # ls sees 0-2 and its own directory, 3. The control lists again with a
    # descriptor the hook opened itself, as one the launcher leaked would
    # be: held by the hook's bash across the exec of ls.
    flong.hookfds = {
      container = "netless";
      user = "alice";
      workspace = ws ''realpath /srv/work'';
      postStart = hook "poststart" ''
        ls /proc/self/fd > /tmp/hookfds-poststart
        exec 7</dev/null
        ls /proc/self/fd > /tmp/hookfds-poststart-control
      '';
      postStop = hook "poststop" ''
        ls /proc/self/fd > /tmp/hookfds-poststop
        exec 7</dev/null
        ls /proc/self/fd > /tmp/hookfds-poststop-control
      '';
      command = [ "bash" "-c" ];
    };

    # A hook that refuses. The payload would outlive the launcher if nothing
    # killed it, which is exactly what must not happen to a session whose hook
    # never finished.
    flong.badhook = {
      container = "netless";
      user = "alice";
      workspace = ws ''realpath /srv/work'';
      # The first command refuses, so the second never runs.
      postStart = hook "poststart" ''
        echo "the hook refuses this session" >&2
        exit 1
      '' ++ hook "poststart-after" ''
        touch "/tmp/badhook-after-$machine"
      '';
      command = [ "sleep" "300" ];
    };

    flong.demo = {
      user = "alice";

      # Written into the session's cgroup. A limit rather than a nicety: the
      # session's writable layers and TMPDIR are tmpfs, which is RAM.
      limits = {
        MemoryMax = "1G";
        TasksMax = 512;
      };

      # The uid is recorded so the test can assert WHO evaluated this: the
      # caller, as everything outside the session runs.
      workspace = ws ''
        id -u > /tmp/workspace-uid
        printf '%s\n' "$*" > /tmp/workspace-args
        realpath /srv/work
      '';

      # Proves the gate sees the resolved workspace rather than having to
      # work one out from $PWD. Refusing here would fail every subtest below,
      # which is the point: the value has to be there and has to be right.
      guard = hook "guard" ''
        [ "$workspace" = /srv/work ] || {
          echo "guard saw workspace='$workspace'" >&2
          exit 1
        }
        # The gate has to see the extra mounts too, or a second directory
        # gets in unexamined -- which is the whole reason they are resolved
        # before this runs rather than spliced in afterwards.
        # With the mode spelt out on every entry, the default included, so
        # the gate sees what it is granting.
        [ "$binds" = "/srv/companion:rw
/srv/reference:ro" ] || {
          echo "guard saw binds='$binds'" >&2
          exit 1
        }
        [ "$workspace_mode" = rw ] || {
          echo "guard saw workspace_mode='$workspace_mode'" >&2
          exit 1
        }
      '';

      # Resolved with $workspace in scope, which is what lets a consumer pair
      # directories rather than name a fixed set.
      # One read-write because it says so, one read-only by default, each
      # from a command of its own: their outputs are concatenated in order.
      binds = hook "binds" ''
        [ "$workspace" = /srv/work ] && printf '%s:rw\n' /srv/companion
      '' ++ hook "binds-after" ''
        printf '%s\n' /srv/reference
      '';

      # Readable from the lower directory; writes must not reach it.
      overlays."/opt/layered" = "/srv/lower";

      # Carved out of the read-write bind of /srv/shared.
      masks = [ "/srv/shared/secret" "/srv/shared/renamed" ];

      command = [ "bash" "-c" ];
    };

    # `command` as data: fixed arguments holding what a shell would act on --
    # a `;`, a `$`, a glob and a trailing backslash -- which printf prints one
    # per line, each in brackets, with the launcher's arguments after them.
    flong.argv = {
      container = "demo";
      user = "alice";
      workspace = ws ''realpath /srv/work'';
      command = [ "printf" "[%s]\\n" "fixed; $HOME *" "trailing\\" ];
    };

    # A program that only the container's /etc/set-environment puts on PATH:
    # hello is in alice's per-user profile, and absent from the system
    # profile.
    flong.userpath = {
      container = "demo";
      user = "alice";
      workspace = ws ''realpath /srv/work'';
      command = [ "hello" "--greeting" ];
    };

    # A second launcher over the SAME container, differing only in what its
    # workspace resolves to. The directory exists, so this is the colon being
    # refused rather than a missing path.
    # An overlay whose mount point is through containers.demo's symlink.
    flong.symlinkoverlay = {
      container = "demo";
      user = "alice";
      workspace = ws ''realpath /srv/work'';
      overlays."/home/alice/escape/inner" = "/srv/lower";
      command = [ "true" ];
    };

    # A mask over a path the session does not have.
    flong.badmask = {
      container = "demo";
      user = "alice";
      workspace = ws ''realpath /srv/work'';
      masks = [ "/srv/no-such-path" ];
      command = [ "true" ];
    };

    flong.badworkspace = {
      container = "demo";
      user = "alice";
      workspace = ws ''realpath "/srv/odd:name"'';
      command = [ "true" ];
    };

    # A fourth, whose bind names a colon. The workspace is fine, so this is
    # the bind list getting the same refusal the workspace gets rather than
    # sharing its code by accident.
    flong.badbinds = {
      container = "demo";
      user = "alice";
      workspace = ws ''realpath /srv/work'';
      binds = hook "binds" ''realpath "/srv/odd:name"'';
      command = [ "true" ];
    };

    # A bind snippet that fails, which must abort the launch rather than
    # mount a shorter list.
    flong.failingbinds = {
      container = "demo";
      user = "alice";
      workspace = ws ''realpath /srv/work'';
      # After one that succeeds, whose output is not mounted alone either.
      binds = hook "binds-before" ''
        printf '%s\n' /srv/companion
      '' ++ hook "binds" ''
        printf '%s\n' /srv/reference
        false
      '';
      command = [ "true" ];
    };

    # A read-only workspace, which the guard sees as such.
    flong.roworkspace = {
      container = "demo";
      user = "alice";
      workspace = ws ''printf '%s:ro\n' /srv/work'';
      guard = hook "guard" ''
        [ "$workspace" = /srv/work ] && [ "$workspace_mode" = ro ]
      '';
      command = [ "bash" "-c" ];
    };

    # Guards that would each subvert the launch if they ran in the launcher's
    # own shell: one ends early with success, which must allow the launch and
    # not end it with nothing launched -- nor end the guards after it, each a
    # process of its own, which must still run and pass; the other reassigns
    # the workspace it has just judged, which must not change what gets
    # mounted.
    flong.guardexit = {
      container = "demo";
      user = "alice";
      workspace = ws ''realpath /srv/work'';
      guard = hook "guard" ''
        if [ -n "$workspace" ]; then exit 0; fi
        exit 1
      '' ++ hook "guard-after" ''
        printf '%s\n' "$*" > /tmp/guardexit-after
      '';
      command = [ "bash" "-c" ];
    };
    flong.guardreassign = {
      container = "demo";
      user = "alice";
      workspace = ws ''realpath /srv/work'';
      guard = hook "guard" ''
        workspace=/srv/reference
        export workspace
      '';
      command = [ "bash" "-c" ];
    };

    # A third over the same container, taking the DEFAULT workspace, null: no
    # command runs, and the launch takes the directory it was started in.
    flong.defaultworkspace = {
      container = "demo";
      user = "alice";
      command = [ "pwd" ];
    };

    # A workspace snippet that fails, which must abort the launch: the
    # documented contract for a non-zero exit from `workspace`.
    flong.failingworkspace = {
      container = "demo";
      user = "alice";
      workspace = ws "false";
      command = [ "true" ];
    };
  };

  testScript = { nodes, ... }:
    let
      exe = n: lib.getExe nodes.machine.flong.${n}.launcher;
      launcher = exe "demo";
      badWorkspace = exe "badworkspace";
      defaultWorkspace = exe "defaultworkspace";
      failingWorkspace = exe "failingworkspace";
      badBinds = exe "badbinds";
      failingBinds = exe "failingbinds";
      roWorkspace = exe "roworkspace";
      guardExit = exe "guardexit";
      guardReassign = exe "guardreassign";
      netless = exe "netless";
      hooked = exe "hooked";
      recorded = exe "recorded";
      badHook = exe "badhook";
      hookFds = exe "hookfds";
      argv = exe "argv";
      userPath = exe "userpath";
      networked = exe "networked";
      badMask = exe "badmask";
      symlinkOverlay = exe "symlinkoverlay";
      autoPorts = exe "autoPorts";
      # The container's own closure, whose system profile hello is not in.
      closure = nodes.machine.containers.demo.path;
    in
    ''
      import re
      import shlex

      ${parts.prelude}

      HOOK_DIR = "${hookDir}"
      STATE = "/run/user/1000/flong"
      CG = "${holderCgroup}"

      machine.wait_for_unit("multi-user.target")
      machine.wait_for_unit("user@1000.service")
      # Every netless session binds this socket, so it has to be there first.
      machine.wait_for_unit("bound-sock.service")
      machine.wait_until_succeeds("test -S /srv/bound/sock")

      # The source of containers.demo's bind with a space, a colon and a
      # backslash in its paths, which every demo session mounts. Made here
      # rather than by tmpfiles, whose own syntax would need escaping of its
      # own. Python's "\\" is one backslash.
      odd_out = "/srv/odd: out\\side"
      machine.succeed(f"mkdir -p '{odd_out}' && echo odd-path > '{odd_out}/marker'")

      # The launcher's own pid, out of the middle of <container>-<pid>-<random>.
      def launcher_pid(name):
          return name.split("-")[1]

      # A command as alice, through her own user manager, with an explicit
      # PATH and /srv/work as the current directory. `sudo` is nowhere in
      # it, and nowhere on the host.
      def by_caller(command):
          inner = "export PATH=/run/wrappers/bin:/run/current-system/sw/bin; cd /srv/work; " + command
          return ("systemd-run -M alice@ --user --wait --pipe --quiet --collect "
                  "--expand-environment=no -- /run/current-system/sw/bin/bash -c "
                  + shlex.quote(inner) + " </dev/null")

      # CONTAINER's session, once bwrap has reported its leader. Its record
      # is named for it, and nothing outside the launcher knows the name
      # before.
      def session_of(container):
          return machine.wait_until_succeeds(
              f"for r in {STATE}/sessions/{container}-*; do "
              "grep -qs '^leader=' \"$r\" && basename \"$r\"; done | grep .").strip()

      # The session's pid 1, as the host sees it.
      def leader_of(name):
          return machine.succeed(
              f"sed -n 's/^leader=\\([0-9]*\\):.*/\\1/p' {STATE}/sessions/{name}").strip()

      def start_session(command):
          machine.succeed(by_caller(f"${launcher} '{command}'") + " >/dev/null 2>&1 &")
          return session_of("demo")

      # The holder's sweeper, which releases a dead session within
      # milliseconds of its launcher's death. Stopped, the next launch's
      # own sweep is the one left.
      def sweeper():
          return machine.succeed(f"cat {CG}/supervisor/cgroup.procs").split()[0]

      # By command line: pasta's pid file is a descriptor of its launcher's.
      def pasta_for(name=""):
          pid = launcher_pid(name) if name else "[0-9]*"
          return f"pgrep -f '[-]-pid /proc/{pid}/fd/'"

      # The pid and starttime (/proc/<pid>/stat's field 22) of the session's
      # pid 1, found without its record: the one process of its sandbox leaf
      # that is pid 1 in the pid namespace below the host's.
      def pid1_of(leaf):
          pids = machine.succeed(
              f"for p in $(cat {leaf}/cgroup.procs); do "
              "grep -qP '^NSpid:\\t\\d+\\t1$' /proc/$p/status && echo $p; done || true").split()
          assert len(pids) == 1, pids
          stat = machine.succeed(f"cat /proc/{pids[0]}/stat")
          return pids[0], stat[stat.rindex(")") + 2:].split()[19]

      # A record as tests/golden/records/ spells it, each @VAR@ replaced.
      def golden_record(text, **values):
          for k, v in values.items():
              text = text.replace(f"@{k}@", v)
          assert not re.search(r"@[A-Z]+@", text), text
          return text

      NO_SESSIONS = f"test -z \"$(ls -A {STATE}/sessions)\""
      NO_SESSION_CGROUPS = f"test -z \"$(find {CG} -mindepth 2 -maxdepth 2 -type d)\""
      PREPARED = f"{STATE}/demo-*/prepared"

      @test("runs as the declared user, in the declared workspace", part="a")
      def _():
          out = machine.succeed(by_caller("${launcher} 'id -un; pwd; cat marker'"))
          assert "alice" in out, out
          assert "/srv/work" in out, out
          assert "in-the-workspace" in out, out

      @test("command is an argument list, with the launcher's arguments appended verbatim", part="a")
      def _():
          # Nothing is read by a shell: not the fixed arguments, and not the
          # launcher's -- a double space, a command substitution, a variable,
          # quotes, a glob and an empty argument each arrive as exactly that
          # argument. The `$` ones are for systemd-run as much as for any
          # shell: it expands them itself unless told not to.
          # The substitution names a path the session shares with the host,
          # so a shell that ran it would leave a mark there. Python's \\ is
          # one backslash; the test's shell keeps what single quotes hold.
          machine.succeed("rm -f /srv/shared/argv-ran")
          out = machine.succeed(by_caller(
              "${argv} 'a  b' '$(touch /srv/shared/argv-ran)' '$HOME' '\"quoted\"' '*' \"\""))
          assert out.splitlines() == [
              "[fixed; $HOME *]",
              "[trailing\\]",
              "[a  b]",
              "[$(touch /srv/shared/argv-ran)]",
              "[$HOME]",
              "[\"quoted\"]",
              "[*]",
              "[]",
          ], out
          machine.fail("test -e /srv/shared/argv-ran")

      @test("command runs with the container's PATH, from its set-environment", part="a")
      def _():
          # hello is in alice's per-user profile and not in the system
          # profile, so a bare `hello` is found only if
          # /etc/set-environment was sourced before the exec -- and the
          # argument after it arrives unread, as the others do.
          machine.succeed("test ! -e ${closure}/sw/bin/hello")
          out = machine.succeed(by_caller("${userPath} 'from the profile; $(false) *'"))
          assert out.strip() == "from the profile; $(false) *", out

      @test("a clean launch writes nothing to stderr", part="a")
      def _():
          # Nothing is to be said on success: a line on every launch is a line
          # in every consumer's output.
          out = machine.succeed(by_caller("${launcher} 'true' 2>&1"))
          assert out == "", out

      # The record contract (DESIGN.md, "Tests"): the bytes the launcher writes, which a
      # sweeper of either language must read. rec_create writes poststop=
      # (when there is a postStop) and cgroup= in one write
      # (flong-record.c:337-341), and rec_set_leader appends leader= once
      # bwrap has said the child's pid (:391-398); nothing else is written
      # before the hook runs.
      @test("a record holds poststop=, cgroup= and leader=, byte for byte, during a hook", part="a")
      def _():
          machine.succeed("rm -f /tmp/recorded-hook /tmp/recorded-go /tmp/recorded-stopped")
          machine.succeed(by_caller("${recorded} 'true'") + " >/tmp/recorded-out 2>&1 &")
          try:
              name = machine.wait_until_succeeds("cat /tmp/recorded-hook").strip()
              record = machine.succeed(f"cat {STATE}/sessions/{name}")
              pid, start = pid1_of(f"{CG}/netless/{name}/sandbox")
              poststop = machine.succeed(
                  "grep -o '/nix/store/[a-z0-9]*-flong-poststop-recorded/bin/flong-poststop-recorded' "
                  "${recorded} | sort -u").split()
              assert len(poststop) == 1, poststop
              want = golden_record(${builtins.toJSON (builtins.readFile ./golden/records/poststop)},
                                   POSTSTOP=poststop[0], CGROUP=f"{CG}/netless/{name}",
                                   PID=pid, START=start)
              assert record == want, (record, want)
          finally:
              machine.succeed("touch /tmp/recorded-go")
          machine.wait_until_fails(f"test -e {STATE}/sessions/{name}")
          assert machine.succeed("cat /tmp/recorded-stopped").split() == [name], \
              machine.succeed("cat /tmp/recorded-stopped")
          out = machine.succeed("cat /tmp/recorded-out")
          assert out == "", out

      @test("a record without a postStop holds cgroup= and leader=, byte for byte", part="a")
      def _():
          name = start_session("sleep 300")
          try:
              record = machine.succeed(f"cat {STATE}/sessions/{name}")
              pid, start = pid1_of(f"{CG}/demo/{name}/sandbox")
              want = golden_record(${builtins.toJSON (builtins.readFile ./golden/records/no-poststop)},
                                   CGROUP=f"{CG}/demo/{name}", PID=pid, START=start)
              assert record == want, (record, want)
          finally:
              machine.succeed(f"kill -TERM {launcher_pid(name)}")
          machine.wait_until_fails(f"test -e {STATE}/sessions/{name}")
          machine.wait_until_fails(f"test -e {CG}/demo/{name}")

      @test("the payload holds descriptors 0-2 and nothing else", part="a")
      def _():
          # flong init closes everything above stderr before it execs tini
          # (src/init.zig:240-241): bwrap leaks its namespace descriptors,
          # and the seccomp and pipe ends reach it too. The `; true` keeps
          # bash from exec'ing ls, so ls lists the payload's own table, $$.
          out = machine.succeed(by_caller("${launcher} 'ls /proc/$$/fd; true'"))
          assert out.split() == ["0", "1", "2"], out
          # The control: a descriptor the payload opens itself is listed.
          out = machine.succeed(by_caller("${launcher} 'exec 7</dev/null; ls /proc/$$/fd; true'"))
          assert out.split() == ["0", "1", "2", "7"], out

      @test("nothing in the session runs as root", part="a")
      def _():
          # pid 1 is tini, and the engine drops before starting it, so there is
          # no process in here for a root phase to have belonged to. That no
          # process of a session has host uid 0 is checks.rootless's.
          out = machine.succeed(by_caller("${launcher} 'id -u; grep ^Uid /proc/1/status'"))
          assert out.split()[0] == "1000", out
          assert "Uid:\t1000" in out, out

      @test("the supplementary groups come with the user", part="a")
      def _():
          out = machine.succeed(by_caller("${launcher} 'id -Gn'"))
          assert "audio" in out, out

      @test("the container's tmpfiles rules are applied to the root", part="a")
      def _():
          out = machine.succeed(by_caller("${launcher} 'cat /srv/by-tmpfiles/marker; readlink /srv/by-tmpfiles/link'"))
          assert "made-by-tmpfiles" in out, out
          assert "/srv/by-tmpfiles/marker" in out, out

      @test("the system is reachable at /run/current-system", part="a")
      def _():
          # A bind over the mount point rather than a symlink written from
          # inside, which nothing unprivileged could have written.
          machine.succeed(by_caller("${launcher} 'test -x /run/current-system/sw/bin/bash'"))

      @test("TMPDIR exists and belongs to the payload", part="a")
      def _():
          out = machine.succeed(by_caller("${launcher} 'echo $TMPDIR; stat -c %U:%a \"$TMPDIR\"'"))
          assert "/home/alice/tmp" in out, out
          assert "alice:700" in out, out

      @test("stdin reaches the payload when the launcher is not on a tty", part="a")
      def _():
          # Off a terminal the launcher relays no pty, and the pipe itself must
          # reach the payload rather than arrive empty with nothing said.
          out = machine.succeed(by_caller("echo from-the-pipe | ${launcher} 'cat'"))
          assert "from-the-pipe" in out, out

      @test("the hostname is the container's, not the session's", part="a")
      def _():
          # The session's name carries a pid and a random number to keep
          # concurrent sessions apart, and is not what the payload should see.
          out = machine.succeed(by_caller("${launcher} 'cat /proc/sys/kernel/hostname'"))
          assert out.strip() == "demo", out

      @test("XDG_RUNTIME_DIR exists and belongs to the payload", part="a")
      def _():
          # /run is a tmpfs made fresh at every start, and nothing inside a
          # session can create a directory in it -- so the launcher must, or
          # the variable names a directory that is not there.
          out = machine.succeed(by_caller("${launcher} 'echo $XDG_RUNTIME_DIR; stat -c %U:%a \"$XDG_RUNTIME_DIR\"'"))
          assert "/run/user/1000" in out, out
          assert "alice:700" in out, out

      @test("the root carries a machine id", part="a")
      def _():
          # Written by a booted container's init, and a session has no init --
          # so without the prepare step every reader gets ENOENT.
          out = machine.succeed(by_caller("${launcher} 'cat /etc/machine-id'"))
          assert len(out.strip()) == 32, out

      @test("every entry in the declaration's tmpfs list is mounted", part="a")
      def _():
          machine.succeed("test -e /srv/shared/declared/host-only")
          out = machine.succeed(by_caller("${launcher} 'ls -A /srv/shared/declared | wc -l'"))
          assert out.strip().endswith("0"), out

      @test("a declared path holding a space, a colon or a backslash is mounted as declared", part="a")
      def _():
          # Python's "\\" is one backslash, and single quotes carry it to
          # the session's shell, where double quotes leave it alone.
          odd_in = "/srv/odd: in\\side"
          out = machine.succeed(by_caller(
              f"${launcher} 'cat \"{odd_in}/marker\"; touch \"{odd_in}/new\" 2>/dev/null || echo refused'"))
          assert out.split() == ["odd-path", "refused"], out
          machine.fail(f"test -e '{odd_out}/new'")
          # The tmpfs entry is found under its unescaped path, empty, and
          # owned by the payload's user because it named no options.
          out = machine.succeed(by_caller(
              "${launcher} 'stat -c %U \"/srv/tmp masked\"; touch \"/srv/tmp masked/mine\" && echo wrote'"))
          assert out.split() == ["alice", "wrote"], out

      @test("privateNetwork gives the session loopback and nothing else", part="a")
      def _():
          # sysfs is per-namespace, so this needs no tools in the container.
          # A session never shares the host's network, so the interface beside
          # loopback is pasta's, in a networked session.
          out = machine.succeed(by_caller("${networked} 'ls /sys/class/net'"))
          assert "lo" in out.split() and len(out.split()) > 1, out
          out = machine.succeed(by_caller("${netless} 'ls /sys/class/net'"))
          assert out.split() == ["lo"], out
          # And no route out of it, in either family: this, not the missing
          # interface, is why a workload has nowhere to go until something
          # gives it egress -- which is what a hook's ordering rests on.
          out = machine.succeed(by_caller("${netless} 'tail -n +2 /proc/net/route | wc -l; cat /proc/net/ipv6_route | grep -vc \" lo$\" || true'"))
          assert out.split() == ["0", "0"], out

      @test("a private session without a network has no resolv.conf", part="a")
      def _():
          # It has nowhere to send a query, so it is not told of anywhere.
          out = machine.succeed(by_caller("${netless} 'test -e /etc/resolv.conf && echo present || echo absent'"))
          assert out.strip() == "absent", out

      @test("the hook runs as the caller, in the session's namespace, before any egress", part="a")
      def _():
          # The hook is the only moment a session's namespace can be steered
          # from outside, and what makes it safe is that it happens before the
          # namespace has anywhere to go: an empty route table at hook time is
          # the ordering the whole design rests on, asserted rather than
          # assumed.
          machine.succeed(by_caller("${hooked} 'true'"))
          uid, host_ns, session_ns, routes, name = \
              machine.succeed("cat /tmp/poststart-facts").split()
          assert uid == "1000", uid
          assert session_ns != host_ns, f"{session_ns} == {host_ns}"
          assert routes == "0", f"the namespace had {routes} routes at hook time"
          assert name.startswith("netless-"), name

      @test("the declaration binds single files and a socket, at paths of its choosing", part="a")
      def _():
          # tmpfiles writes the file's content without a newline, hence echo.
          out = machine.succeed(by_caller("${netless} 'cat /run/bound/file; echo; test -S /run/bound/sock && echo socket'"))
          assert out.split() == ["declared-file", "socket"], out

      @test("the payload cannot write through a read-only file bind, though it owns the file", part="a")
      def _():
          # EROFS for the write and for the chmod alike: the mount refuses
          # both, whoever owns the file. The read-write bind beside it takes a
          # write.
          out = machine.succeed(by_caller("${netless} '"
              "stat -c %U /run/bound/file; findmnt -no OPTIONS /run/bound/file; "
              "{ echo forged >> /run/bound/file; } 2>&1 || true; "
              "chmod u+x /run/bound/file 2>&1 || true; "
              "cat /run/bound/file; echo; "
              "echo written >> /run/bound/rw && cat /run/bound/rw'"))
          lines = out.splitlines()
          assert lines[0] == "alice", out
          assert lines[1].split(",")[0] == "ro", out
          assert "Read-only file system" in lines[2], out
          assert "Read-only file system" in lines[3], out
          assert lines[4] == "declared-file", out
          assert lines[5] == "written", out
          machine.succeed("grep -qx written /srv/bound/rw")

      @test("a socket bound read-only still connects", part="a")
      def _():
          # As Docker's docker.sock:ro does: connect() is not a write to the
          # filesystem, so a read-only mount does not refuse it.
          out = machine.succeed(by_caller("${netless} '"
              "findmnt -no OPTIONS /run/bound/sock; "
              "echo through-a-read-only-bind | nc -NU /run/bound/sock && echo sent'"))
          options, sent = out.split()
          assert options.split(",")[0] == "ro", out
          assert sent == "sent", out
          machine.wait_until_succeeds("grep -qx through-a-read-only-bind /tmp/bound-sock-received")

      @test("the workload cannot change what the hook installed, even after unshare -U", part="a")
      def _():
          machine.succeed(by_caller("${hooked} \"bash $(readlink -f /etc/flong-tamper)\"")
                          + " >/tmp/tamper.out 2>&1 &")
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
          # ... and a second lock: the payload may not make a user
          # namespace, so no capability comes back in one.
          assert "unshare-refused" in lines, out
          assert "UserNsCapEff" not in caps, caps
          name = session_of("netless")
          leader = leader_of(name)
          # And from outside, the rule the hook installed is still there.
          rules = machine.succeed(f"nsenter --net=/proc/{leader}/ns/net nft list table inet flong")
          assert "dport 19999 drop" in rules, rules
          machine.wait_until_fails(f"test -e {STATE}/sessions/{name}")

      @test("postStop runs when a session ends", part="a")
      def _():
          machine.succeed("rm -f /tmp/stopped")
          machine.succeed(by_caller("${hooked} 'true'"))
          name = machine.succeed("cat /tmp/poststart-facts").split()[4]
          assert machine.succeed("cat /tmp/stopped").split() == [name]
          machine.fail(f"test -e {HOOK_DIR}/hook-file-{name}")
          machine.fail(f"test -e {HOOK_DIR}/hook-sock-{name}")
          machine.fail(f"pgrep -f hook-sock-{name}")

      @test("and when its launcher was killed, from the next launch's sweep", part="a")
      def _():
          # No trap survives SIGKILL, so the sweep has to -- and it has to run
          # the dead session's postStop rather than its own: the launch that
          # sweeps here is `netless`, over the same container, and has none.
          machine.succeed("rm -f /tmp/stopped")
          # The holder's sweeper would release the session first, which
          # checks.rootless covers; stopped, the next launch's sweep is
          # the one under test. The payload goes with its launcher, and
          # the hook's listener and file stay until a sweep.
          paused = sweeper()
          machine.succeed(f"kill -STOP {paused}")
          try:
              machine.succeed(by_caller("${hooked} 'sleep 300'") + " >/dev/null 2>&1 &")
              name = session_of("netless")
              leader = leader_of(name)
              machine.wait_until_succeeds(f"test -S /tmp/hook-sock-{name}")
              machine.succeed(f"kill -9 {launcher_pid(name)}")
              machine.wait_until_fails(f"test -d /proc/{leader}")
              # Nothing has run it yet, and what it releases is still there.
              machine.fail("test -e /tmp/stopped")
              machine.succeed(f"test -e /tmp/hook-file-{name}")
              machine.succeed(f"pgrep -f hook-sock-{name}")

              machine.succeed(by_caller("${netless} 'true'"))
              assert machine.succeed("cat /tmp/stopped").split() == [name]
              machine.fail(f"test -e /tmp/hook-file-{name}")
              machine.fail(f"pgrep -f hook-sock-{name}")
              machine.fail(f"test -e {STATE}/sessions/{name}")
              machine.fail(f"test -e {CG}/netless/{name}")
          finally:
              machine.succeed(f"kill -CONT {paused}")

      @test("postStart and postStop inherit descriptors 0-2 and nothing else", part="a")
      def _():
          # Each hook's ls lists 0-2 and the directory it reads, 3; its
          # control, with 7 opened by the hook, shows that a descriptor the
          # hook was handed would be listed too.
          machine.succeed("rm -f /tmp/hookfds-*")
          machine.succeed(by_caller("${hookFds} 'true'"))
          for hook in ("poststart", "poststop"):
              out = machine.succeed(f"cat /tmp/hookfds-{hook}")
              assert out.split() == ["0", "1", "2", "3"], (hook, out)
              out = machine.succeed(f"cat /tmp/hookfds-{hook}-control")
              assert out.split() == ["0", "1", "2", "3", "7"], (hook, out)

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

      @test("rules a hook installs are in place before any egress exists", part="a")
      def _():
          # The hook saw no route at all, and pasta added some afterwards: the
          # rule was installed into a namespace with nowhere to go. And it
          # holds once there is somewhere -- 19999 is a host port the session
          # was given, and the hook's rule refuses it.
          out = machine.succeed(by_caller("${networked} '"
              "tail -n +2 /proc/net/route | wc -l; "
              + reach("127.0.0.1 19999") + "'"))
          assert machine.succeed("cat /tmp/networked-routes-at-hook").strip() == "0"
          routes, *rest = out.split()
          assert int(routes) > 0, out
          assert "host-19999" not in out, out

      @test("hostPorts reach the host's loopback, and nothing else on it does", part="a")
      def _():
          out = machine.succeed(by_caller("${networked} '"
              + reach("127.0.0.1 18123") + "; echo ---; "
              + reach("127.0.0.1 18124") + "; echo ---; "
              # --no-map-gw: the gateway address is not a way to the host's
              # loopback either, for a named port or an unnamed one.
              + "gw=$(ip -4 route show default | awk \"{ print \\$3 }\"); "
              + reach("$gw 18123") + "; echo ---; "
              + reach("$gw 18124") + "'"))
          named, unnamed, gw_named, gw_unnamed = out.split("---")
          assert "host-18123" in named, out
          assert "host-18124" not in unnamed, out
          assert "host-18123" not in gw_named, out
          assert "host-18124" not in gw_unnamed, out

      @test("a networked session resolves through the host's loopback resolver", part="a")
      def _():
          # The premise: the host's resolver is a stub on its loopback, in
          # both families, and on nothing else.
          machine.succeed("grep -qx 'nameserver 127.0.0.1' /etc/resolv.conf")
          machine.succeed("grep -qx 'nameserver ::1' /etc/resolv.conf")
          listening = machine.succeed("ss -Hlun 'sport = :53' | awk '{ print $4 }'").split()
          assert sorted(listening) == ["127.0.0.1:53", "[::1]:53"], listening

          out = machine.succeed(by_caller("${networked} '"
              "cat /etc/resolv.conf; echo ---; "
              "getent ahostsv4 dns.flong.test; echo ---; "
              "getent ahostsv4 dns; echo ---; "
              "ip -6 route show default; echo ---; "
              "dig -4 +short +time=2 +tries=1 @169.254.1.1 dns.flong.test; echo ---; "
              "dig -6 +short +time=2 +tries=1 @100::1 dns.flong.test'"))
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

      @test("a family the host has no nameserver in is neither forwarded nor listed", part="a")
      def _():
          # pasta sends a family's queries to the host's first nameserver of
          # that family, and for a family with none it has only the unspecified
          # address. The resolver here answers on 127.0.0.1 AND ::1, so a query
          # that reaches the host's loopback through the missing family shows
          # up as an answer rather than as a failure. Each direction in turn,
          # through the missing family's forward address and the unspecified
          # one, over UDP and TCP.
          machine.succeed("cp /etc/resolv.conf /tmp/resolv.conf.both")
          try:
              for kept, forward, missing, unspecified, flag in (
                  ("127.0.0.1", "169.254.1.1", "100::1", "::", "-6"),
                  ("::1", "100::1", "169.254.1.1", "0.0.0.0", "-4"),
              ):
                  machine.succeed(f"printf 'nameserver {kept}\nsearch flong.test\n' > /etc/resolv.conf")
                  probes = "; ".join(
                      f"dig {flag} {proto} +short +time=1 +tries=1 @{addr} dns.flong.test 2>&1"
                      for addr in (missing, unspecified) for proto in ("+notcp", "+tcp"))
                  machine.succeed(by_caller("${networked} '"
                      "cat /etc/resolv.conf; echo ---; "
                      "getent ahostsv4 dns.flong.test; echo ---; "
                      + probes + "; echo probed; sleep 300'") + " > /tmp/dns-single 2>&1 &")
                  # pasta is the one process in the session's pasta leaf,
                  # and it goes with the session's cgroup.
                  name = session_of("netless")
                  machine.wait_until_succeeds("grep -qx probed /tmp/dns-single", timeout=60)
                  pasta = machine.succeed(
                      f"tr '\\0' ' ' < /proc/$(head -n 1 {CG}/netless/{name}/pasta/cgroup.procs)/cmdline")
                  machine.succeed(f"kill -KILL {launcher_pid(name)}")
                  machine.wait_until_succeeds(NO_SESSIONS)

                  out = machine.succeed("cat /tmp/dns-single")
                  resolv, resolved, reached = out.split("---")
                  assert [l for l in resolv.splitlines() if l.startswith("nameserver")] == \
                      [f"nameserver {forward}"], out
                  assert f"--dns-forward {forward}" in pasta, pasta
                  assert missing not in pasta, pasta
                  # The family that is there works, so the probes below fail
                  # for want of a way to the host and not of a network.
                  assert "192.0.2.53" in resolved, out
                  assert "192.0.2.53" not in reached, out
          finally:
              machine.succeed("cp /tmp/resolv.conf.both /etc/resolv.conf")

      @test("with forwardPorts auto, whatever the session listens on reaches it from the host", part="a")
      def _():
          # Declared nowhere: pasta finds the listener in its once-a-second
          # scan and publishes the same port on the host.
          # Listening on the session's loopback only, as a dev server does:
          # reached because the host's loopback arrives on the session's.
          machine.succeed(by_caller("${autoPorts} 'echo from-auto | nc -N -l 127.0.0.1 18300'")
                          + " >/dev/null 2>&1 &")
          machine.wait_until_succeeds("nc -d -w 3 127.0.0.1 18300 | grep -q from-auto", timeout=30)
          machine.wait_until_succeeds(NO_SESSIONS)

      @test("a forwarded port reaches the session from the host", part="a")
      def _():
          # And a second listener on a port that is not forwarded, left up past
          # the one-second scan with which pasta's default `auto` would have
          # forwarded it -- so that "nothing else" is a statement about -t
          # none, and not about there being nothing to find.
          machine.succeed(by_caller("${networked} '"
              "echo not-forwarded | timeout 6 nc -N -l 18202 & "
              "echo from-the-session | nc -N -l 18201; wait'") + " >/dev/null 2>&1 &")
          machine.wait_until_succeeds("nc -d -w 3 127.0.0.1 18200 | grep -q from-the-session")
          out = machine.succeed("sleep 2; nc -d -w 2 127.0.0.1 18202 </dev/null 2>&1 || true")
          assert "not-forwarded" not in out, out
          machine.wait_until_succeeds(NO_SESSIONS)

          # One host port, one session: a second session asking for the same
          # one cannot bind it, and is ended rather than run without it.
          machine.succeed(by_caller("${networked} 'sleep 300'") + " >/dev/null 2>&1 &")
          first = session_of("netless").split()
          assert len(first) == 1, first
          machine.fail(by_caller("${networked} 'echo ran'"))
          machine.succeed(f"kill -KILL {launcher_pid(first[0])}")
          machine.wait_until_fails(f"test -e {CG}/netless/{first[0]}")
          machine.wait_until_succeeds(NO_SESSIONS)

      # pasta attaches to the session's namespace through the launcher's
      # descriptors, and lives in the session's cgroup.
      @test("a clean exit releases pasta")
      def _():
          machine.succeed(by_caller("${networked} 'sleep 1'") + " >/dev/null 2>&1 &")
          name = session_of("netless")
          machine.wait_until_succeeds(pasta_for(name))
          machine.wait_until_fails(f"test -e {STATE}/sessions/{name}")
          machine.fail(f"test -e {CG}/netless/{name}")
          machine.wait_until_fails(pasta_for())

      @test("a killed session's pasta is reaped by the next launch")
      def _():
          # The leak this has to catch: pasta alive for as long as the host
          # runs after its session is gone. It is in the session's cgroup,
          # which outlives a SIGKILLed launcher until a sweep kills it; the
          # sweeper is stopped, so the sweep is the next launch's. pasta may also quit by itself
          # once the namespace's last process is gone, so what is asserted
          # before the sweep is the cgroup, not pasta.
          paused = sweeper()
          machine.succeed(f"kill -STOP {paused}")
          try:
              machine.succeed(by_caller("${networked} 'sleep 300'") + " >/dev/null 2>&1 &")
              name = session_of("netless")
              leader = leader_of(name)
              machine.wait_until_succeeds(pasta_for(name))
              machine.succeed(f"kill -9 {launcher_pid(name)}")
              machine.wait_until_fails(f"test -d /proc/{leader}")
              machine.succeed(f"test -d {CG}/netless/{name}/pasta")
              machine.succeed(f"test -e {STATE}/sessions/{name}")

              # An unrelated launch over the same container, with no network
              # of its own, is where the sweep runs.
              machine.succeed(by_caller("${netless} 'true'"))
              machine.fail(f"test -e {CG}/netless/{name}")
              machine.fail(f"test -e {STATE}/sessions/{name}")
              machine.wait_until_fails(pasta_for())
          finally:
              machine.succeed(f"kill -CONT {paused}")

      @test("SIGTERM to the launcher ends the session before releasing it")
      def _():
          # The launcher owns its session: asked to stop, it kills the
          # session's cgroup and waits for it to empty, and only then runs
          # postStop and removes it. Releasing first would do both under a
          # session still running.
          machine.succeed("rm -f /tmp/stopped")
          machine.succeed(by_caller("${networked} 'sleep 300'") + " >/dev/null 2>&1 &")
          name = session_of("netless")
          machine.wait_until_succeeds(pasta_for(name))
          machine.succeed(f"kill -TERM {launcher_pid(name)}")
          machine.wait_until_fails(f"test -d /proc/{launcher_pid(name)}")
          machine.fail(f"test -e {CG}/netless/{name}")
          machine.fail(f"test -e {STATE}/sessions/{name}")
          machine.wait_until_fails(pasta_for(name))
          assert machine.succeed("cat /tmp/stopped").split() == [name], \
              machine.succeed("cat /tmp/stopped")

      for port in (18123, 18124, 19999):
          machine.succeed(f"systemctl stop listen-{port}")

      @test("a session whose hook refuses does not run")
      def _():
          # The payload is `sleep 300`: if the launcher merely gave up and the
          # session outlived it, it would be running with nothing installed
          # in its namespace and nobody left to install it.
          err = machine.fail(by_caller("${badHook} 2>&1"))
          assert "the hook refuses this session" in err, err
          # The failing command was the first of two: the rest never ran.
          machine.fail("ls /tmp/badhook-after-*")
          machine.succeed(NO_SESSIONS)
          machine.succeed(NO_SESSION_CGROUPS)

      @test("the session's cgroup carries its limits")
      def _():
          # Both facts in one read, and from the host deliberately: the session
          # has a cgroup namespace of its own, so from inside it the limit is on
          # an ancestor it cannot see and /sys/fs/cgroup/memory.max says "max".
          machine.succeed(by_caller("${launcher} 'sleep 5'") + " >/dev/null 2>&1 &")
          # Written into the sandbox leaf before bwrap is started in it,
          # so by the time the leader is known.
          name = session_of("demo")
          leaf = f"{CG}/demo/{name}/sandbox"
          limit = machine.succeed(f"cat {leaf}/memory.max").strip()
          assert limit == str(1024 * 1024 * 1024), limit
          tasks = machine.succeed(f"cat {leaf}/pids.max").strip()
          assert tasks == "512", tasks
          # And nothing of that session survives it, which the subtests
          # after this one assume.
          machine.wait_until_succeeds(NO_SESSIONS)
          machine.succeed(NO_SESSION_CGROUPS)

      # A session does not outlive its launcher, and a lock still held means
      # the session is not the sweep's, whatever else the sweep sees.
      @test("a SIGKILLed launcher takes its payload with it")
      def _():
          name = start_session("sleep 300")
          leader = leader_of(name)
          machine.succeed(f"kill -9 {launcher_pid(name)}")
          machine.wait_until_fails(f"test -d /proc/{leader}")
          # And the holder's sweeper releases what it left.
          machine.wait_until_fails(f"test -e {CG}/demo/{name}")
          machine.wait_until_fails(f"test -e {STATE}/sessions/{name}")

      @test("the sweep never releases a session whose lock is held")
      def _():
          # The launcher is stopped, so it holds its record's lock and
          # reacts to nothing, and the session's pid 1 is killed: half of
          # what makes a session dead, and not the half that is the lock.
          # A launch sweeps and the sweeper is running, and neither may
          # touch it. The launcher, let go, releases its session itself.
          machine.succeed("rm -f /tmp/stopped")
          machine.succeed(by_caller("${hooked} 'sleep 300'") + " >/dev/null 2>&1 &")
          name = session_of("netless")
          leader = leader_of(name)
          machine.wait_until_succeeds(f"test -S /tmp/hook-sock-{name}")
          machine.succeed(f"kill -STOP {launcher_pid(name)}")
          try:
              machine.succeed(f"kill -9 {leader}")
              machine.wait_until_fails(f"test -d /proc/{leader}")
              machine.succeed(by_caller("${netless} 'true'"))
              machine.succeed(f"test -e {STATE}/sessions/{name}")
              machine.succeed(f"test -d {CG}/netless/{name}")
              machine.succeed(f"pgrep -f hook-sock-{name}")
              machine.fail("test -e /tmp/stopped")
          finally:
              machine.succeed(f"kill -CONT {launcher_pid(name)}")
          machine.wait_until_fails(f"test -d /proc/{launcher_pid(name)}")
          assert machine.succeed("cat /tmp/stopped").split() == [name], \
              machine.succeed("cat /tmp/stopped")
          machine.fail(f"test -e {STATE}/sessions/{name}")
          machine.fail(f"test -e {CG}/netless/{name}")

      @test("a leftover from a superseded closure is swept")
      def _():
          # The cache is keyed on the closure hash, so a nixos-rebuild strands
          # the previous generation's cache in a directory nothing of the new
          # generation would look at again unless the sweep does. A cache is
          # swept by the next cold launch of the same container
          # with the same maps, so this one's is removed first. The stale
          # root is owned by container root, a subordinate id, as a real
          # one is, which the caller can remove only through the user
          # namespace that maps it. Its cache directory is the caller's.
          key = "1000.100.100000.100000.100"
          machine.succeed(f"rm -rf {STATE}/demo-*-*-{key}")
          stale = f"{STATE}/demo-00000000-00000000-{key}"
          machine.succeed(f"mkdir -p {stale}/prepared/var/empty && touch {stale}/prepared/var/empty/file")
          machine.succeed(f"chown -R 100000:100000 {stale}/prepared && chown 1000:100 {stale}")
          machine.fail(by_caller(f"rm -rf {stale}/prepared 2>/dev/null"))

          # A container whose name begins with this one's, which the sweep must
          # not touch: both hashes are spelt out so the glob cannot reach it.
          neighbour = f"{STATE}/demo-two-00000000-00000000-{key}"
          machine.succeed(f"mkdir -p {neighbour}/prepared && chown -R 1000:100 {neighbour}")

          machine.succeed(by_caller("${launcher} 'true'"))
          machine.fail(f"test -e {stale}")
          machine.succeed(f"test -d {neighbour}/prepared")
          machine.succeed(f"rm -rf {neighbour}")
          # The cache this launch actually uses is not swept with it.
          machine.succeed(f"test -e {PREPARED}/etc/passwd")

      @test("the identity comes from the container, not from the module")
      def _():
          # Nothing declares 1000, 100 or /home/alice to flong: they are read
          # out of the prepared root's passwd, so this proves the read rather
          # than an agreement between two copies of the same number.
          out = machine.succeed(by_caller("${launcher} 'id -u; id -g; echo $HOME; stat -c %u:%g \"$TMPDIR\"'"))
          uid, gid, home, tmpdir = out.split()
          assert (uid, gid) == ("1000", "100"), out
          assert home == "/home/alice", out
          assert tmpdir == "1000:100", out

      @test("a tmpfs masks part of a read-write bind")
      def _():
          machine.succeed("test -e /srv/shared/masked/host-only")
          out = machine.succeed(by_caller("${launcher} 'ls -A /srv/shared/masked | wc -l'"))
          assert out.strip().endswith("0"), out

      @test("the masked path is writable by the payload's user")
      def _():
          machine.succeed(by_caller("${launcher} 'echo scratch > /srv/shared/masked/mine; test -s /srv/shared/masked/mine'"))
          machine.fail("test -e /srv/shared/masked/mine")

      @test("writes to the bind reach the host")
      def _():
          machine.succeed(by_caller("${launcher} 'echo through > /srv/shared/passthrough'"))
          machine.succeed("grep -q through /srv/shared/passthrough")

      @test("an overlay reads the lower layer")
      def _():
          out = machine.succeed(by_caller("${launcher} 'cat /opt/layered/seed'"))
          assert "from-the-lower-layer" in out, out

      @test("overlay writes are discarded, not passed down")
      def _():
          machine.succeed(by_caller("${launcher} 'echo scratch > /opt/layered/new; test -e /opt/layered/new'"))
          machine.fail("test -e /srv/lower/new")
          machine.succeed("test -e /srv/lower/seed")

      @test("the caller's binds are mounted at their own paths")
      def _():
          out = machine.succeed(by_caller("${launcher} 'cat /srv/companion/marker; cat /srv/reference/marker'"))
          assert "in-the-companion" in out, out
          assert "read-only-reference" in out, out

      @test("a bind is read-only unless it says :rw")
      def _():
          # /srv/reference is root-owned, so a write there fails anyway: what
          # proves the mount is EROFS rather than EACCES.
          machine.succeed(by_caller("${launcher} 'echo written > /srv/companion/from-session'"))
          machine.succeed("grep -q written /srv/companion/from-session")
          out = machine.fail(by_caller("${launcher} 'echo nope > /srv/reference/from-session' 2>&1"))
          assert "Read-only file system" in out, out
          machine.fail("test -e /srv/reference/from-session")

      @test("the command is told about the caller's binds, with their modes")
      def _():
          # A mount the process does not know about is half of what the
          # caller asked for, so the paths reach it in the environment: one
          # list, a PATH:MODE per line. The declaration's own binds are not
          # the caller's, and are not in it.
          out = machine.succeed(by_caller("${launcher} 'printf \"%s\\n\" \"$FLONG_BINDS\"'"))
          assert out.splitlines() == ["/srv/companion:rw", "/srv/reference:ro"], out

      @test("a bind naming ':' is refused, like a workspace")
      def _():
          err = machine.fail(by_caller("${badBinds} 2>&1"))
          assert "bind contains ':'" in err, err

      @test("a bind snippet that fails aborts the launch")
      def _():
          machine.fail(by_caller("${failingBinds}"))

      @test("a workspace printed as PATH:ro is bound read-only, and the guard is told")
      def _():
          out = machine.succeed(by_caller("${roWorkspace} 'pwd; cat marker; touch from-session 2>&1 || true'"))
          assert "/srv/work" in out, out
          assert "in-the-workspace" in out, out
          assert "Read-only file system" in out, out
          machine.fail("test -e /srv/work/from-session")

      @test("the exit status of the command is the exit status of the launcher")
      def _():
          machine.succeed(by_caller("${launcher} 'exit 0'"))
          machine.fail(by_caller("${launcher} 'exit 3'"))

      # The launcher is the caller's own program, and the host has no sudo
      # to grant it with.
      @test("an unprivileged user runs the launcher with no sudo rule")
      def _():
          machine.fail("test -e /run/wrappers/bin/sudo")
          out = machine.succeed(by_caller("${launcher} 'id -un'"))
          assert "alice" in out, out

      @test("workspace is evaluated as the invoking user, not as root")
      def _():
          # The line above was alice's, through her own manager.
          uid = machine.succeed("cat /tmp/workspace-uid").strip()
          assert uid == "1000", f"workspace ran as uid {uid}, expected alice"

      # There is no root phase to fall back to, and root has no subordinate
      # range.
      @test("the launcher refuses to run as root")
      def _():
          machine.succeed("echo untouched > /tmp/workspace-args")
          err = machine.fail("${launcher} 'true' 2>&1")
          assert "refusing to run as root" in err, err
          # Refused before the workspace snippet ran.
          assert machine.succeed("cat /tmp/workspace-args").strip() == "untouched"

      @test("guard runs after workspace and sees the resolved path")
      def _():
          # The guard above refuses unless $workspace is already resolved, so
          # every launch in this file proves the ordering. Assert it directly
          # too, or a guard silently emptied of its check would still pass.
          out = machine.succeed(by_caller("${launcher} 'echo ok'"))
          assert "ok" in out, out
          err = machine.fail(by_caller("${badWorkspace} 2>&1"))
          assert "workspace contains" in err, err

      @test("a guard's exit 0 allows the launch rather than ending it")
      def _():
          machine.succeed("rm -f /tmp/guardexit-after")
          out = machine.succeed(by_caller("${guardExit} 'echo the-payload-ran'"))
          assert "the-payload-ran" in out, out
          # The guard after it ran too, with the launcher's arguments.
          after = machine.succeed("cat /tmp/guardexit-after").strip()
          assert after == "echo the-payload-ran", after

      @test("a guard cannot change the workspace it judged")
      def _():
          out = machine.succeed(by_caller("${guardReassign} 'pwd; test -e /srv/reference && echo reference-bound || true'"))
          assert out.split() == ["/srv/work"], out

      @test("workspace sees the launcher's arguments")
      def _():
          machine.succeed(by_caller("${launcher} 'true'"))
          assert machine.succeed("cat /tmp/workspace-args").strip() == "true"
          machine.succeed(by_caller("${launcher} 'false || true'"))
          assert machine.succeed("cat /tmp/workspace-args").strip() == "false || true"

      @test("a workspace naming a colon is refused, not mounted")
      def _():
          machine.succeed("test -d '/srv/odd:name'")
          err = machine.fail(by_caller("${badWorkspace} 2>&1"))
          assert "workspace contains" in err, err

      @test("the default workspace is the directory the launcher starts in")
      def _():
          out = machine.succeed(by_caller("cd /srv/work && ${defaultWorkspace}"))
          assert "/srv/work" in out, out

      @test("a workspace snippet that fails aborts the launch")
      def _():
          machine.fail(by_caller("${failingWorkspace}"))

      @test("a bind mount nested inside a tmpfs reaches through it")
      def _():
          # The tmpfs hides the host's /srv/nested ...
          out = machine.succeed(by_caller("${launcher} 'ls -A /srv/nested'"))
          assert "hidden" not in out, out
          # ... and the bind beneath it is still mounted, because the engine
          # orders custom mounts by destination rather than by argument.
          out = machine.succeed(by_caller("${launcher} 'cat /srv/nested/keep/marker'"))
          assert "through-the-tmpfs" in out, out

      @test("a symlink on the way to a mount point in home ends the launch, and makes nothing on the host")
      def _():
          machine.fail(by_caller("${symlinkOverlay}"))
          machine.fail("test -e /srv/escape-target/inner")

      @test("a mask hides a file inside a read-write bind, and leaves the host's alone")
      def _():
          out = machine.succeed(by_caller("${launcher} 'cat /srv/shared/secret 2>&1 || echo refused; ls /srv/shared'"))
          assert "should-be-masked" not in out, out
          assert "refused" in out, out
          machine.fail(by_caller("${launcher} 'echo x > /srv/shared/secret'"))
          assert "should-be-masked" in machine.succeed("cat /srv/shared/secret")

      @test("a mask over a path the session does not have fails the launch")
      def _():
          machine.fail(by_caller("${badMask}"))

      @test("a file renamed over a masked one on the host shows through")
      def _():
          # What `masks` warns of: the mask is on the file, and a rename on
          # the host detaches it in the session's namespace.
          machine.succeed(by_caller("${launcher} 'cat /srv/shared/renamed 2>&1 || echo before-refused; sleep 6; cat /srv/shared/renamed 2>&1 || echo after-refused'")
                          + " > /tmp/renamed-out 2>&1 &")
          machine.wait_until_succeeds("grep -q before-refused /tmp/renamed-out")
          machine.succeed("printf renamed-in > /srv/shared/renamed.new && mv /srv/shared/renamed.new /srv/shared/renamed")
          machine.wait_until_succeeds("grep -q -e renamed-in -e after-refused /tmp/renamed-out", timeout=30)
          out = machine.succeed("cat /tmp/renamed-out")
          assert "renamed-in" in out, out

      @test("the directories on the way to a bind inside home are the payload's")
      def _():
          out = machine.succeed(by_caller("${launcher} 'stat -c %U /home/alice/deep /home/alice/deep/er; touch /home/alice/deep/er/beside && echo wrote; cat /home/alice/deep/er/keep/marker'"))
          assert out.split()[:2] == ["alice", "alice"], out
          assert "wrote" in out, out
          assert "through-the-tmpfs" in out, out
          # Outside home, as ever: the tmpfs mask's parents, /srv, container
          # root's, which the session sees as root.
          assert machine.succeed(by_caller("${launcher} 'stat -c %U /srv'")).strip() == "root"

      @test("nothing is left behind")
      def _():
          # No record, no session's cgroup, and no pasta. Nothing of a
          # session is anywhere else: its root was an overlay
          # in its own mount namespace.
          machine.succeed(NO_SESSIONS)
          machine.succeed(NO_SESSION_CGROUPS)
          machine.fail(pasta_for())

      @test("the prepared root is reused rather than rebuilt")
      def _():
          before = machine.succeed(f"stat -c %Y {PREPARED}").strip()
          machine.succeed(by_caller("${launcher} 'true'"))
          after = machine.succeed(f"stat -c %Y {PREPARED}").strip()
          assert before == after, f"prepared root was rebuilt: {before} -> {after}"

      @test("the cache is named for the prepare steps as well as the closure")
      def _():
          # A root prepared by an older flong is not a root this one would
          # build, so the directory has to stop matching when prepare changes.
          # Nothing in one VM run can change prepare and look again, so what is
          # checked is that the name carries a second hash at all -- which is
          # what a revert to keying on the closure alone would lose. It
          # carries the maps too, which decide the root's owners.
          name = machine.succeed(f"basename $(dirname {PREPARED})").strip()
          assert re.fullmatch(r"demo-[a-z0-9]{8}-[a-z0-9]{8}-1000\.100\.100000\.100000\.100", name), name

      ${parts.done}
    '';
}
