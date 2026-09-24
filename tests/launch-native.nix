# The Zig port's L2 in checks.native (DESIGN.md, "Tests":
# checks.native): a testScript fragment, Python run in tests/native.nix's scope
# (`machine`, `shlex`, `as_alice`), after the common setup: alice, uid
# 1000, lingering, subordinate ids 100000-165535, a delegated unit per
# as_alice, and flong-launch-driver (tests/zig/launchdriver.zig) on PATH.
#
#   - U1 and U2 through /run/wrappers/bin/newuidmap and newgidmap, the
#     prologue's three extents, each namespace's maps read back from inside
#     it, U2's split along U1's, its user.max_user_namespaces; a map
#     program refusing, both refusing, one that cannot be run, U2's limit
#     refused, and nothing left after each
#   - SIGTERM during the U2 wait: Aborted, and no helper, pipe or process
#     left (ordering checkpoint 4); U2's helper refused its map write, and
#     nothing left
#   - the nsdelegate check, on the node, under a tmpfs, and on a cgroup2
#     mounted in a namespace of alice's
#   - the holder found, started, not started
#   - the session made with a limit, and an EINVAL limit leaving nothing;
#     a controller the holder lacks
#   - a record the driver wrote and closed, swept by the launcher's Zig
#     flong sweeper from its watch: postStop once, cgroup and record gone
#   - passwd against getent, and the uid form
#
# Nothing in it is about time: every wait is for a state, bounded. Each
# ns and u2-abort run is under timeout(1), killed after 60 s, so a
# cleanup that reaps a helper before it closes the helper's pipes (the
# order checkpoint 4 forbids) ends red (rc=137) instead of hanging the
# check: the unit, not the test driver's own timeout, holds the output
# pipe open.
{ pkgs, launcher }:
let
  # postStop for the swept record: logs its machine.
  psLog = pkgs.writeShellScript "flong-l2-poststop" ''
    echo "$machine $1" >>/tmp/l2-ps.log
  '';
  maps = "0:100000:1000,1000:1000:1,1001:101000:64536";
  gmaps = "0:100000:100,100:100:1,101:100100:65436";
in
''
  with subtest("L2 ns: U1 and U2 through the newuidmap wrapper, the maps read back"):
      for nested in ("0", "5"):
          out = machine.succeed(as_alice(
              "timeout -s KILL 60 flong-launch-driver ns /run/wrappers/bin/newuidmap /run/wrappers/bin/newgidmap "
              f"${maps} ${gmaps} {nested} 2>&1; echo rc=$?")).splitlines()
          print("\n".join(out))
          # What the launch keeps: U1, U2 and the signalfd; no pipe, no
          # helper, nothing else in the unit's cgroup.
          assert out[:1] == ["made"], out
          assert "live: 3" in out and "pipes: 0" in out and "children: none" in out, out
          assert "others in the cgroup: 0" in out, out
          opened = [l for l in out if l.startswith("open: ")][0].split()[1:]
          assert sorted(o.split(":")[0] for o in opened) == ["anon_inode", "user", "user"], out
          # U1, the caller's keep-id map as the prologue builds it; U2 the
          # identity, split along U1's extents; U2's own limit.
          assert "u1 uid_map: 0 100000 1000 / 1000 1000 1 / 1001 101000 64536" in out, out
          assert "u1 gid_map: 0 100000 100 / 100 100 1 / 101 100100 65436" in out, out
          assert "u2 uid_map: 0 0 1000 / 1000 1000 1 / 1001 1001 64536" in out, out
          assert "u2 gid_map: 0 0 100 / 100 100 1 / 101 101 65436" in out, out
          assert f"u2 max_user_namespaces: {nested}" in out, out
          assert out[-1] == "rc=0", out

  with subtest("L2 ns: a map program refusing, both refusing, one that cannot run; nothing left"):
      # After a refusal only the signalfd is left: every pipe closed, the
      # map programs and U1's child reaped (ordering checkpoint 4).
      nothing_left = ["live: 1", "open: anon_inode:[signalfd]", "pipes: 0", "children: none", "others in the cgroup: 0", "rc=1"]
      uid_says = ("flong launch: newuidmap failed (status 1): the caller needs a range of at least 65536 ids "
                  "in /etc/subuid (users.users.<name>.subUidRanges)")
      gid_says = ("flong launch: newgidmap failed (status 1): the caller needs a range of at least 65536 ids "
                  "in /etc/subgid (users.users.<name>.subGidRanges)")
      # Ids outside alice's range: newuidmap refuses, and the launch says
      # which file and option to fix; newgidmap ran as well and is reaped.
      # Both refusing: both are reaped before either is judged, so both
      # are said, newuidmap's first (flong-ns.c:186-197). A limit the
      # kernel refuses (past INT_MAX): U2's child says why and exits 125
      # after the maps, the helper reaps it and exits 125, and neither
      # 125 is said again (flong-ns.c:28-40, 222-235, 251-253).
      for uids, gids, nested, said in (
          ("0:200000:1000,1000:1000:1", "${gmaps}", "0", [uid_says]),
          ("0:200000:1000,1000:1000:1", "0:200000:100,100:100:1", "0", [uid_says, gid_says]),
          ("${maps}", "${gmaps}", "4294967296",
           ["flong launch: write 4294967296 to /proc/sys/user/max_user_namespaces: Invalid argument"]),
      ):
          out = machine.succeed(as_alice(
              "timeout -s KILL 60 flong-launch-driver ns /run/wrappers/bin/newuidmap /run/wrappers/bin/newgidmap "
              f"{uids} {gids} {nested} 2>&1; echo rc=$?")).splitlines()
          print("\n".join(out))
          assert [l for l in out if l.startswith("flong launch: ")] == said, out
          assert out[-len(nothing_left):] == nothing_left, out
      # A map program that cannot be exec'd: the spawned child says so,
      # and its 127 is not said again (flong-ns.c:132-139).
      out = machine.succeed(as_alice(
          "timeout -s KILL 60 flong-launch-driver ns /nonexistent/newuidmap /run/wrappers/bin/newgidmap "
          "${maps} ${gmaps} 0 2>&1; echo rc=$?")).splitlines()
      print("\n".join(out))
      assert out == ["flong launch: exec /nonexistent/newuidmap: No such file or directory"] + nothing_left, out

  with subtest("L2 ns: SIGTERM during the U2 wait gives Aborted, no helper or pipe left"):
      out = machine.succeed(as_alice(
          "timeout -s KILL 60 flong-launch-driver u2-abort ${maps} ${gmaps} 2>&1; echo rc=$?")).splitlines()
      print("\n".join(out))
      assert out[0] == "u1 made", out
      assert "u2: Aborted, signal 15" in out, out
      # U1 and the signalfd, nothing else: every pipe closed before the
      # helper was reaped, and the helper and its child gone.
      assert "live: 2" in out and "pipes: 0" in out and "children: none" in out, out
      assert "others in the cgroup: 0" in out, out
      opened = [l for l in out if l.startswith("open: ")][0].split()[1:]
      assert sorted(o.split(":")[0] for o in opened) == ["anon_inode", "user"], out
      # The helper finished its handshake with U2's child and found the
      # launcher gone, as the C's does (flong-ns.c:303-306).
      assert set(l for l in out if l.startswith("flong launch: ")) <= {"flong launch: send U2's pid: Broken pipe"}, out
      # The driver says what it saw and exits 0.
      assert out[-1] == "rc=0", out

  with subtest("L2 ns: U2's helper failing to write U2's maps; nothing left"):
      # U2's uid extents outside U1's: the helper's write of uid_map is
      # refused, it closes the maps pipe, which ends U2's child, reaps it and
      # exits 125, unsaid again. Only because "m" follows the maps (ordering
      # checkpoint 4, flong-ns.c:291-300) is U2's child still waiting for
      # it; had it been sent first, the child would be holding U2 on the
      # launcher's release pipe while the helper waits for it, and the run
      # would hang until timeout(1) kills it (rc=137).
      out = machine.succeed(as_alice(
          "timeout -s KILL 60 flong-launch-driver u2-maps ${maps} ${gmaps} 70000:0:1 2>&1; echo rc=$?")).splitlines()
      print("\n".join(out))
      import re
      out = [re.sub(r"/proc/[0-9]+/", "/proc/PID/", l) for l in out]
      assert out[:4] == ["u1 made", "flong launch: write 70000 70000 1", " to /proc/PID/uid_map: Operation not permitted", "u2: Reported"], out
      assert out[4:] == ["live: 2"] + [l for l in out if l.startswith("open: ")] + ["pipes: 0", "children: none", "others in the cgroup: 0", "rc=0"], out
      assert sorted(o.split(":")[0] for o in [l for l in out if l.startswith("open: ")][0].split()[1:]) == ["anon_inode", "user"], out

  with subtest("L2 cgroup: the nsdelegate check"):
      out = machine.succeed(as_alice("flong-launch-driver nsdelegate 2>&1; echo rc=$?"))
      assert out == "nsdelegate: yes\nrc=0\n", out
      # Something else on top of /sys/fs/cgroup: the last line decides.
      out = machine.succeed(as_alice(
          "unshare --user --map-root-user --mount sh -c "
          "'mount -t tmpfs none /sys/fs/cgroup && flong-launch-driver nsdelegate' 2>&1; echo rc=$?"))
      assert out == "flong launch: cgroup2 is not mounted at /sys/fs/cgroup: sessions need the unified hierarchy\nrc=1\n", out
      # cgroup2 has one superblock, so a mount of it in a namespace of
      # alice's still says nsdelegate: the refusal without it is held by
      # test-libc's differential over mountinfo text (libc_launch.zig).
      out = machine.succeed(as_alice(
          "unshare --user --map-root-user --mount --cgroup sh -c "
          "'mount -t cgroup2 none /sys/fs/cgroup && flong-launch-driver nsdelegate' 2>&1; echo rc=$?"))
      assert out == "nsdelegate: yes\nrc=0\n", out

  with subtest("L2 cgroup: the holder under the user manager, found, started, not started"):
      out = machine.succeed(as_alice(
          "M=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup | sed 's|\\(/user@1000.service\\)/.*|\\1|'); "
          "echo manager=$M; "
          "flong-launch-driver holder l2-holder nolimits 2>&1; echo rc=$?; "
          "flong-launch-driver holder l2-holder nolimits /run/current-system/sw/bin/false 2>&1; echo rc=$?; "
          "flong-launch-driver holder l2-holder nolimits /run/current-system/sw/bin/mkdir $M/l2-holder 2>&1; echo rc=$?; "
          "flong-launch-driver holder l2-holder nolimits 2>&1; echo rc=$?; "
          "rmdir $M/l2-holder")).splitlines()
      print("\n".join(out))
      M = out[0].split("=", 1)[1]
      assert M.endswith("/user.slice/user-1000.slice/user@1000.service"), out
      assert out[1:] == [
          f"flong launch: the holder's cgroup {M}/l2-holder does not exist, and there is no way to start it", "rc=1",
          "flong launch: starting the holder failed (/run/current-system/sw/bin/false exited 1)", "rc=1",
          f"holder: {M}/l2-holder", "rc=0",
          f"holder: {M}/l2-holder", "rc=0",
      ], out

  with subtest("L2 cgroup: a session with a limit, an EINVAL limit leaving nothing, a controller missing"):
      # The shell moves into a leaf, so the unit's cgroup can give pids to
      # the holder h below it.
      out = machine.succeed(as_alice(
          "cg=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup); "
          "mkdir $cg/leaf && echo $$ > $cg/leaf/cgroup.procs && echo +pids > $cg/cgroup.subtree_control && mkdir $cg/h; "
          "echo controllers: $(cat $cg/h/cgroup.controllers); "
          "flong-launch-driver session $cg/h c m pids.max=bogus 2>&1; echo rc=$?; "
          "test -e $cg/h/c/m && echo session left || echo session gone; "
          "test -d $cg/h/c && echo container kept; "
          "flong-launch-driver session $cg/h c m hugetlb.2MB.max=0 2>&1 | sed \"s|$cg|CG|\"; "
          "test -e $cg/h/c/m && echo session left || echo session gone; "
          "flong-launch-driver session $cg/h c m pids.max=10 2>&1 | sed \"s|$cg|CG|\"; "
          "echo subtree: $(cat $cg/h/cgroup.subtree_control) / $(cat $cg/h/c/cgroup.subtree_control) / $(cat $cg/h/c/m/cgroup.subtree_control); "
          "echo leaves: $(find $cg/h/c/m -mindepth 1 -maxdepth 1 -type d -printf '%f ' | tr ' ' '\\n' | sort | tr '\\n' ' '); "
          "rmdir $cg/h/c/m/sandbox $cg/h/c/m/hooks $cg/h/c/m/pasta $cg/h/c/m $cg/h/c $cg/h")).splitlines()
      print("\n".join(out))
      assert "pids" in out[0].split(), out
      assert out[1:] == [
          "flong launch: write bogus to pids.max: Invalid argument", "rc=1",
          "session gone",
          "container kept",
          "flong launch: the limit hugetlb.2MB.max needs the hugetlb controller, which CG/h does not have",
          "session gone",
          "session: CG/h/c/m",
          "sandbox pids.max: 10",
          "subtree: pids / pids / pids",
          "leaves: hooks pasta sandbox",
      ], out

  with subtest("L2 record: created, closed, and swept by the Zig flong sweeper from its watch"):
      out = machine.succeed(as_alice(
          "cg=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup); H=$cg/h2; S=/tmp/l2-state; "
          "rm -rf $S /tmp/l2-ps.log; mkdir -m 0700 $S; mkdir -p $H/supervisor; "
          "(echo $BASHPID > $H/supervisor/cgroup.procs; exec ${launcher}/bin/flong sweeper $S) 2>/tmp/l2-sweeper.err & swp=$!; "
          "blocked() { local s fd; read -r s fd _ </proc/$swp/syscall 2>/dev/null || return 1; "
          "[ \"$s\" = 0 ] && [ \"$(readlink /proc/$swp/fd/$((fd)))\" = anon_inode:inotify ]; }; "
          "for i in $(seq 600); do blocked && break; sleep 0.05; done; blocked && echo watching; "
          "flong-launch-driver record $S $H c m ${psLog} > /tmp/l2-record 2>&1; echo rc=$?; "
          "sed -e \"s|$H|H|\" -e 's|leader=[0-9]*:[0-9]*$|leader=PID:START|' /tmp/l2-record; "
          "for i in $(seq 600); do [ -e $S/sessions/m ] || break; sleep 0.05; done; "
          "for i in $(seq 600); do blocked && break; sleep 0.05; done; "
          "test -e $S/sessions/m && echo record left || echo record gone; "
          "test -e $H/c/m && echo cgroup left || echo cgroup gone; "
          "echo poststop: $(cat /tmp/l2-ps.log); "
          "kill -TERM $swp; wait $swp; echo sweeper $?; "
          "sed \"s|$H|H|\" /tmp/l2-sweeper.err; "
          "rmdir $H/c $H/supervisor $H; rm -rf $S /tmp/l2-ps.log /tmp/l2-record /tmp/l2-sweeper.err")).splitlines()
      print("\n".join(out))
      assert out == [
          "watching",
          "rc=0",
          "poststop=${psLog}",
          "cgroup=H/c/m",
          "leader=PID:START",
          "record gone",
          "cgroup gone",
          "poststop: m m",
          "sweeper 143",
          "flong sweeper: released 1 dead session",
      ], out

  with subtest("L2 passwd: /etc/passwd against getent, and the uid form"):
      for uid in ("1000", "0"):
          out = machine.succeed(as_alice(f"flong-launch-driver passwd {uid} 2>&1"))
          name = machine.succeed(f"getent passwd {uid} | cut -d: -f1").strip()
          assert name in ("alice", "root"), name
          assert out == (f"name: {name}\n"
                         f"flong launch: no user manager for {name}: set users.users.{name}.linger = true\n"), out
      machine.fail("getent passwd 4242")
      out = machine.succeed(as_alice("flong-launch-driver passwd 4242 2>&1"))
      assert out == "name: none\nflong launch: no user manager for uid 4242: set users.users.<name>.linger = true\n", out
''
