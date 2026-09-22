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
  inherit (pkgs) runCommand writeText writeShellApplication;

  # Every group systemd knows, with its members. The comment lines are the
  # builder kernel's own list of calls no group names, so they are dropped:
  # the dump then depends on systemd alone.
  dump = runCommand "flong-seccomp-groups" { } ''
    ${systemd}/bin/systemd-analyze syscall-filter | sed '/^[[:space:]]*#/d' > $out
  '';

  # The names a list of spec files adds, minus those it subtracts, sorted.
  # An unknown group or name fails the build with the expander's message.
  expand =
    specs:
    runCommand "flong-seccomp-names" { } ''
      set -o pipefail
      awk -f ${./expand.awk} ${dump} ${lib.concatMapStringsSep " " (s: "${s}") specs} |
        LC_ALL=C sort > $out
    '';

  known = expand [ (writeText "known" "@known") ];

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

  # render NAMES DENY prints the tier filter's policy: the names allowed, the
  # rest of @known refused with DENY or logged, and everything else ENOSYS.
  # The same program renders at build time and at launch, so both compile the
  # same text.
  render = writeShellApplication {
    name = "flong-seccomp-render";
    runtimeInputs = [ pkgs.coreutils ];
    text = ''
      if (($# != 2)); then
        echo "usage: flong-seccomp-render NAMES 1|13|38|log" >&2
        exit 2
      fi
      case $2 in
        1 | 13 | 38) rule="errno $2" ;;
        log) rule=log ;;
        *)
          echo "flong-seccomp-render: not 1, 13, 38 or log: $2" >&2
          exit 2
          ;;
      esac
      # NAMES is read once, so it may be a pipe.
      mapfile -t names <"$1"
      echo "default 38"
      for n in "''${names[@]}"; do echo "allow $n"; done
      # The default is already ENOSYS, and libseccomp refuses a rule that
      # repeats the default, so ENOSYS needs no rule per name.
      if [[ $2 != 38 ]]; then
        LC_ALL=C comm -23 ${known} <(printf '%s\n' "''${names[@]}") |
          while IFS= read -r n; do echo "$rule $n"; done
      fi
    '';
  };

  # A declaration's tier filter, or null when it has no tier.
  filterFor =
    s:
    if s.tier == null then
      null
    else
      runCommand "flong-seccomp.bpf" { } ''
        set -o pipefail
        ${render}/bin/flong-seccomp-render ${namesFor s} ${deny s} |
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

  # flong-seccomp-project NAMES DENY DIR reads a project's `allow X...` and
  # `deny X...` lines on stdin, and prints the path of the tier filter they
  # make of the declaration's NAMES, compiled once into DIR and then reused.
  project = writeShellApplication {
    name = "flong-seccomp-project";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.gawk
    ];
    text = ''
      if (($# != 3)); then
        echo "usage: flong-seccomp-project NAMES 1|13|38|log DIR < POLICY" >&2
        exit 2
      fi
      names=$1 deny=$2 dir=$3

      spec=()
      line=0
      while IFS= read -r text || [[ -n $text ]]; do
        line=$((line + 1))
        read -r -a words <<<"$text"
        if ((''${#words[@]} == 0)) || [[ ''${words[0]} == \#* ]]; then continue; fi
        case ''${words[0]} in
          allow) sign="" ;;
          deny) sign=- ;;
          *)
            echo "flong-seccomp-project: line $line: not an allow or deny line: ''${words[0]}" >&2
            exit 1
            ;;
        esac
        if ((''${#words[@]} < 2)); then
          echo "flong-seccomp-project: line $line: ''${words[0]} names nothing" >&2
          exit 1
        fi
        for x in "''${words[@]:1}"; do
          if [[ ! $x =~ ^@?[a-z0-9_-]+$ ]]; then
            echo "flong-seccomp-project: line $line: not a syscall or @group: $x" >&2
            exit 1
          fi
          spec+=("$sign$x")
        done
      done

      # The project's denies win over the declaration's names and its own
      # allows, as a declaration's deny entries do.
      if ! list=$(printf '%s\n' "''${spec[@]}" | awk -f ${./expand.awk} ${dump} "$names" - | LC_ALL=C sort); then
        exit 1
      fi
      policy=$(${render}/bin/flong-seccomp-render <(printf '%s\n' "$list") "$deny")

      # The key is exactly what is compiled, and by what, so a new compiler
      # makes new filters rather than reusing old ones.
      key=$(printf '%s\n%s' ${compiler} "$policy" | sha256sum)
      key=''${key%% *}
      if [[ -e $dir/$key.bpf ]]; then
        printf '%s\n' "$dir/$key.bpf"
        exit 0
      fi

      # The policy runs before the launch prepares its state, so the
      # directories may not exist yet. Another launch may make them first.
      for d in "''${dir%/*}" "$dir"; do
        mkdir -m 0700 -- "$d" 2>/dev/null || [[ -d $d ]] || {
          echo "flong-seccomp-project: cannot make $d" >&2
          exit 1
        }
      done
      # Two launches racing here compile the same bytes, so whichever rename
      # lands last is as good as the first.
      tmp=$(mktemp "$dir/.$key.XXXXXX")
      if ! err=$(${compiler}/bin/flong-seccomp <<<"$policy" 2>&1 >"$tmp"); then
        rm -f -- "$tmp"
        printf '%s\n' "$err" >&2
        exit 1
      fi
      mv -T -- "$tmp" "$dir/$key.bpf"
      printf '%s\n' "$dir/$key.bpf"
    '';
  };
in
{
  inherit
    dump
    expand
    known
    tierNames
    namesFor
    deny
    render
    filterFor
    fixed
    project
    ;
}
