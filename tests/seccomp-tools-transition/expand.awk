# Usage: awk -f expand.awk DUMP SPEC...
# DUMP is the output of `systemd-analyze syscall-filter`, every group in one
# call. Each SPEC line is "@group" or "name", with a leading "-" to subtract.
# Prints the adds minus the subtractions, whatever their order, unsorted.
# An unknown group or name fails with exit 2, so a typo cannot quietly drop a
# call from a filter.
FNR == NR {
  if ($0 ~ /^@/) { g = $1; next }
  if ($0 ~ /^[ \t]*#/ || $0 ~ /^[ \t]*$/) next
  if (g != "") {
    m = $1; members[g] = members[g] " " m
    if (substr(m, 1, 1) != "@") known[m] = 1
  }
  next
}
function add(e, sign,   n, a, i) {
  if (substr(e, 1, 1) == "@") {
    if (!(e in members)) { print "unknown group " e > "/dev/stderr"; bad = 2; exit }
    if ((e SUBSEP sign) in seen) return
    seen[e SUBSEP sign] = 1
    n = split(members[e], a, " ")
    for (i = 1; i <= n; i++) add(a[i], sign)
  } else if (!(e in known)) { print "unknown syscall " e > "/dev/stderr"; bad = 2; exit }
  else if (sign > 0) set[e] = 1
  else del[e] = 1
}
{ sub(/[ \t]*#.*/, ""); if ($0 == "") next
  if (substr($1, 1, 1) == "-") add(substr($1, 2), -1); else add($1, 1) }
# exit runs END too, so a refusal must not print the partial set.
END { if (bad) exit bad; for (s in set) if (!(s in del)) print s }
