# The seccomp pipeline, at build time: systemd's syscall groups, the tiers'
# names, a declaration's names, the rendered policy and the compiled filters.
#
# Every derivation is named by what it holds rather than by the declaration,
# so declarations with equal policies share one store path. systemd-analyze
# runs once, here; nothing at launch calls it.
{
  pkgs,
  lib,
  systemd,
  compiler,
}:
let
  inherit (pkgs) runCommand writeText;

  # Every group systemd knows, with its members. The comment lines are the
  # builder kernel's own list of calls no group names, so they are dropped:
  # the dump then depends on systemd alone.
  dump = runCommand "flong-seccomp-groups" { } ''
    ${systemd}/bin/systemd-analyze syscall-filter | sed '/^[[:space:]]*#/d' > $out
  '';

  # The names a list of spec files adds, minus those it subtracts, sorted.
  # An unknown group or name fails the build with the expander's message
  # (flong-seccomp expand, src/seccomp/expand.zig).
  expand =
    specs:
    runCommand "flong-seccomp-names" { } ''
      ${compiler}/bin/flong-seccomp expand ${dump} ${lib.concatMapStringsSep " " (s: "${s}") specs} > $out
    '';

  # The strict tier starts from parity's names, so it is parity minus its
  # subtractions by construction.
  tierNames = rec {
    parity = expand [ ./parity.groups ];
    strict = expand [
      parity
      ./strict.groups
    ];
  };

  # A declaration's names: its tier, then its loosenings and allow entries,
  # then its deny entries, which win over all of them; then its syscalls
  # map, which wins over everything before it, call by call. The expander
  # takes the adds less the subtractions whatever their order, so the map
  # is a second expansion over the first's names: an "allow" added back
  # whatever deny took, a "deny" or "log" taken out whatever added it.
  namesFor =
    s:
    let
      extras =
        lib.optional s.debug "ptrace"
        ++ lib.optional s.nestedSandbox "@mount"
        ++ s.allow
        ++ map (x: "-${x}") s.deny;
      listed =
        if extras == [ ] then
          tierNames.${s.tier}
        else
          expand [
            tierNames.${s.tier}
            (writeText "flong-seccomp-extra" (lib.concatLines extras))
          ];
      calls = s.syscalls or { };
      mapped = lib.mapAttrsToList (n: a: if a == "allow" then n else "-${n}") calls;
    in
    if calls == { } then
      listed
    else
      expand [
        listed
        (writeText "flong-seccomp-calls" (lib.concatLines mapped))
      ];

  # The calls a declaration's syscalls map logs, expanded and so sorted
  # and checked, or null when it logs none: what render and project log in
  # place of the errno.
  loggedFor =
    s:
    let
      logged = lib.attrNames (lib.filterAttrs (_: a: a == "log") (s.syscalls or { }));
    in
    if logged == [ ] then
      null
    else
      expand [ (writeText "flong-seccomp-logged" (lib.concatLines logged)) ];

  # What a @known call outside the names gets: an errno, or `log`.
  deny =
    s:
    if s.log then
      "log"
    else
      {
        EPERM = "1";
        EACCES = "13";
        ENOSYS = "38";
      }
      .${s.errno};

  # A declaration's tier filter, or null when it has no tier. `flong-seccomp
  # render DUMP NAMES DENY [LOGGED]` prints its policy: the names allowed, the rest
  # of the dump's @known refused with DENY or logged, and everything else
  # ENOSYS (src/seccomp/render.zig). The same code renders at build time and,
  # in `project`, at launch, so both compile the same text.
  filterFor =
    s:
    if s.tier == null then
      null
    else
      let
        logged = loggedFor s;
      in
      runCommand "flong-seccomp.bpf" { } ''
        set -o pipefail
        ${compiler}/bin/flong-seccomp render ${dump} ${namesFor s} ${deny s} ${
          lib.optionalString (logged != null) "${logged}"
        } |
          ${compiler}/bin/flong-seccomp > $out
      '';

  # The filters every session gets whatever its tier: the audit mask, the
  # terminal filter, and the namespace mask unless nestedSandbox.
  fixed = lib.genAttrs [ "audit" "tty" "nsmask" ] (
    n:
    runCommand "flong-seccomp-${n}.bpf" { } ''
      ${compiler}/bin/flong-seccomp < ${./. + "/${n}.policy"} > $out
    ''
  );

  # A project's policy is compiled at launch by `flong-seccomp project DUMP
  # NAMES DENY DIR [LOGGED] < POLICY` (src/seccomp/project.zig), which
  # module.nix hands the launch with this dump, the declaration's names, its
  # deny and its logged.
in
{
  inherit
    dump
    expand
    tierNames
    namesFor
    loggedFor
    deny
    filterFor
    fixed
    ;
}
