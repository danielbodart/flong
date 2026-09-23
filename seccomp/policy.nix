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
  # then its deny entries, which win over all of them.
  namesFor =
    s:
    let
      extras =
        lib.optional s.debug "ptrace"
        ++ lib.optional s.nestedSandbox "@mount"
        ++ s.allow
        ++ map (x: "-${x}") s.deny;
    in
    if extras == [ ] then
      tierNames.${s.tier}
    else
      expand [
        tierNames.${s.tier}
        (writeText "flong-seccomp-extra" (lib.concatLines extras))
      ];

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
  # render DUMP NAMES DENY` prints its policy: the names allowed, the rest
  # of the dump's @known refused with DENY or logged, and everything else
  # ENOSYS (src/seccomp/render.zig). The same code renders at build time and,
  # in `project`, at launch, so both compile the same text.
  filterFor =
    s:
    if s.tier == null then
      null
    else
      runCommand "flong-seccomp.bpf" { } ''
        set -o pipefail
        ${compiler}/bin/flong-seccomp render ${dump} ${namesFor s} ${deny s} |
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
  # NAMES DENY DIR < POLICY` (src/seccomp/project.zig), which module.nix
  # hands the wrapper with this dump, the declaration's names and its deny.
in
{
  inherit
    dump
    expand
    tierNames
    namesFor
    deny
    filterFor
    fixed
    ;
}
