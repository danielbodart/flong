# P3, processes (ZIG.md, "Phase 0: proofs"): Zig on std.os.linux alone
# driving clone3, a fork whose body cannot return, and setns. No fallback: a
# failure here is a Zig ABI bug.
#
#   build   p3-proc installed as flong's binaries will be (stripped,
#           single-threaded, stack_size 0, no libc); `compile-fail`: a fork
#           body returning void does not compile, with the message checked
#           (build.zig); `cross`: the same code compiles for aarch64, so
#           CloneArgs' 88-byte assert holds there too; and, in the build
#           sandbox, `fork` and `fork-panic` run: the child runs its body
#           once, the parent's defer runs once, in the parent.
#   VM      as alice, in a Delegate=yes unit of her user manager:
#           clone3(CLONE_INTO_CGROUP|CLONE_PIDFD) into an O_PATH leaf of the
#           unit's cgroup, the child reading that leaf in /proc/self/cgroup;
#           the same into a cgroup that is not hers refused (the control);
#           and a fork after setns(CLONE_NEWUSER) into a namespace held by
#           `unshare --map-auto`, the child uid 0 there, with the
#           namespace's capabilities, and in the leaf.
{ pkgs, lib, zigSet, ... }:
let
  proc = zigSet {
    pname = "p3-proc";
    root = ./.;
    files = [ ./src ./probes ];
    steps = "install compile-fail cross";
    nativeBuildInputs = [ pkgs.file ];
    extra = ''
      file -b $out/bin/p3-proc | tee /dev/stderr | grep -q 'statically linked, stripped'
      for mode in fork fork-panic; do
        $out/bin/p3-proc $mode >out 2>err || { cat out err; echo "p3: $mode failed"; exit 1; }
        cat out err
        test "$(grep -c '^child ran: ' out)" = 1
        test "$(grep -c '^parent defer ran: ' out)" = 1
        # The defer's line comes last, from the parent's pid.
        parent=$(sed -n 's/^child ran: pid [0-9]*, parent \([0-9]*\)$/\1/p' out)
        test "$(tail -n 1 out)" = "parent defer ran: pid $parent"
      done
      grep -qx 'child exited 125' out
      grep -qx 'p3-proc: internal error: planted' err
    '';
  };
in
{
  build = proc;
  bins = proc;

  vmScript = ''
    with subtest("p3: the noreturn fork, as alice"):
        for mode, status in (("fork", "7"), ("fork-panic", "125")):
            out = machine.succeed(as_alice(f"p3-proc {mode} 2>&1")).splitlines()
            print("\n".join(out))
            assert len([l for l in out if l.startswith("child ran: ")]) == 1, out
            assert out[-2:-1] == [f"child exited {status}"], out
            assert out[-1].startswith("parent defer ran: "), out

    with subtest("p3: clone3(CLONE_INTO_CGROUP) into an O_PATH leaf of a delegated unit"):
        out = machine.succeed(as_alice(
            "cg=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup); mkdir $cg/leaf; "
            "p3-proc cgroup $cg/leaf; rc=$?; rmdir $cg/leaf; exit $rc")).splitlines()
        print("\n".join(out))
        child = [l for l in out if l.startswith("child cgroup: ")]
        parent = [l for l in out if l.startswith("parent cgroup: ")]
        assert len(child) == 1 and len(parent) == 1, out
        assert child[0] == parent[0].replace("parent", "child", 1) + "/leaf", out
        assert "/user@1000.service/" in child[0], out
        # The control: a cgroup that is not alice's refuses the child.
        out = machine.fail(as_alice("p3-proc cgroup /sys/fs/cgroup/system.slice 2>&1"))
        print(out)
        assert "p3-proc: clone3: ACCES" in out, out

    with subtest("p3: a fork after setns(CLONE_NEWUSER), into the leaf"):
        out = machine.succeed(as_alice(
            "unshare --user --map-auto --map-root-user sleep 600 & h=$!; "
            "for i in $(seq 100); do grep -q 100000 /proc/$h/uid_map && break; sleep 0.1; done; "
            "cg=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup); mkdir $cg/leaf; "
            "p3-proc userns /proc/$h/ns/user $cg/leaf 2>&1; rc=$?; "
            "kill $h; wait $h; rmdir $cg/leaf; exit $rc")).splitlines()
        print("\n".join(out))
        assert "parent uid after setns: 0" in out, out
        assert "child uid: 0" in out, out
        assert "child uid_map: 0 1000 1 / 1 100000 65536" in out, out
        assert "child hostname: p3-userns" in out, out
        assert any(l.startswith("child cgroup: ") and l.endswith("/leaf") for l in out), out
        assert out[-1] == "child exited 0", out
  '';
}
