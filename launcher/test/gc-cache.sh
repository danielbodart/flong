#!/usr/bin/env bash
# gc-cache.sh DIR: delete a superseded cache, or the trash a killed run of this
# script left, when no launcher holds it.
#
# Every launcher holds a shared flock on its cache for its whole life, so an
# exclusive lock here means no session reads this root as its overlay's lower.
# The lock is tried, never waited for: a cache in use is simply kept for a later
# run. Holding it, the cache is renamed to a trash name, so a launcher that
# opened the path before the rename and locks it after finds the path no longer
# names what it locked, and relaunches. Renaming a live overlay lower is
# harmless where deleting it is not. The tree is subordinate ids' files, so it
# is deleted as container root in the keep-id namespace.
set -u
old=$1
if [[ ${BASH_SOURCE[0]} == */* ]]; then . "${BASH_SOURCE[0]%/*}/asroot.sh"; else . ./asroot.sh; fi
fl_identity || exit 1

# Braced, so the 2>/dev/null does not stay on the shell as exec would leave it.
{ exec {l}<"$old"; } 2>/dev/null || exit 0
"$FLONG_BUILD/bin/flock" -xn "$l" || { echo "gc-cache: $old is in use, kept" >&2; exit 0; }
# Locked what the name no longer names: somebody else has it in hand.
[[ $old -ef /proc/self/fd/$l ]] || exit 0
trash=$old
if [[ ${old##*/} != .trash.* ]]; then
	trash=${old%/*}/.trash.${old##*/}.$$
	mv -T -- "$old" "$trash" || exit 0
fi
# The lock stays held until the script exits, across the deletion: another
# run that finds this trash gets "in use, kept" instead of a second rm -rf
# over the same tree.
asroot rm -rf -- "$trash" && echo "gc-cache: removed $old" >&2
