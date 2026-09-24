# A VM test's subtests, run in parts: each part is a check of its own
# (flake.nix: basic-a and basic-b, rootless-a and rootless-b) that boots its
# own VM, so the parts run on parallel CI legs. The test file stays the one
# source of its subtests.
#
# A test module imports `module`, which declares its `part` ("all", the
# default, runs every subtest), and puts `prelude` at the head of its
# testScript and `done` at its end. A subtest is then a function under a
# decorator, which runs it under the driver's subtest() when its part is
# this run's:
#
#     @test("the subtest's name")            # in part DEFAULT
#     def _():
#         ...
#
#     @test("another", part="b")
#     def _():
#         ...
#
# A subtest is a function, so a name it sets for a later subtest is
# declared `global`, and the two go in the same part. The driver's
# `with subtest(...)` raises: a subtest written that way would run in
# every part.
{ part, default }:
{
  module = { lib, ... }: {
    options.part = lib.mkOption {
      type = lib.types.enum [ "a" "b" "all" ];
      default = "all";
      description = "The part of the subtests this run is: a, b, or all of them.";
    };
  };

  prelude = ''
    PART = "${part}"
    SUBTESTS = []
    RAN = []
    driver_subtest = subtest

    def test(name, part="${default}"):
        assert part in ("a", "b"), (name, part)
        def run(body):
            assert name not in SUBTESTS, f"two subtests are called {name!r}"
            SUBTESTS.append(name)
            if PART in (part, "all"):
                RAN.append(name)
                with driver_subtest(name):
                    body()
        return run

    def subtest(name):
        raise Exception(f"subtest {name!r}: write it as @test(...) over a function, "
                        "so that it runs in one part (tests/parts.nix)")
  '';

  # The control that the run was not empty: a part that ran no subtest would
  # pass.
  done = ''
    print(f"part {PART}: ran {len(RAN)} of {len(SUBTESTS)} subtests")
    assert RAN, f"part {PART} ran no subtest"
  '';
}
