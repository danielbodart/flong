#!/usr/bin/env bash
# The test wrapper's identity and its keep-id namespace.
#
#   asroot.sh COMMAND...     run COMMAND as container root in the keep-id namespace
#   . asroot.sh              define fl_identity and asroot, for launch.sh and gc-cache.sh
#
# The keep-id namespace maps the container's ids exactly as a session's U1 does:
# the container user onto the caller, its primary group onto the caller's
# primary group, everything else from the caller's subordinate range. Container
# root in it owns the prepared root, so it is how a root is prepared, how a test
# plants a fixture in one and how a subuid-owned tree is deleted: the caller
# cannot remove what a subordinate id owns.
#
# Sourced, it only defines things and reads no file, so launch.sh pays for it
# with a file read and no fork.

# Where the programs and the container come from. The defaults are the two
# nix-build results next to this file; both are covered by .gitignore.
if [[ ${BASH_SOURCE[0]} == */* ]]; then fl_here=${BASH_SOURCE[0]%/*}; else fl_here=.; fi
[[ $fl_here == /* ]] || fl_here=$PWD/$fl_here
FLONG_BUILD=${FLONG_BUILD:-$fl_here/result}
FLONG_CLOSURE=${FLONG_CLOSURE:-$fl_here/result-closure}

# fl_identity: the caller, its subordinate ranges and U1's maps.
# Sets me, mygid, cuid, cgid, UMAP and GMAP (arrays of IN OUT COUNT triples)
# and key (the part of the cache's name the maps decide). Builtins only: it runs
# on every warm launch. Returns 1 with a message when the caller has no range.
fl_identity() {
	local n u s c
	# The name newuidmap matches /etc/subuid against. USER is unset in a unit,
	# and `id -un` would be a fork.
	me=${USER:-}
	if [[ -z $me ]]; then
		while IFS=: read -r n _ u _; do [[ $u == "$UID" ]] && { me=$n; break; }; done </etc/passwd
	fi
	# bash puts the real gid first in GROUPS.
	mygid=${GROUPS[0]}
	cuid=${FLONG_CUID:-1000} cgid=${FLONG_CGID:-100}
	if ((UID == 0)); then
		echo "flong: refusing to run as root: root has no subordinate range, and nothing in flong runs as root" >&2
		return 1
	fi
	if ((cuid > 65535 || cgid > 65535)); then
		echo "flong: the container user $cuid:$cgid is outside the container's ids 0-65535" >&2
		return 1
	fi

	# The first entry at least 65536 wide. NixOS allocates automatic ranges in
	# user-name order, so nothing may assume 100000.
	sub='' gsub=''
	while IFS=: read -r n s c; do
		[[ ($n == "$me" || $n == "$UID") && $c -ge 65536 ]] && { sub=$s subn=$c; break; }
	done </etc/subuid
	while IFS=: read -r n s c; do
		[[ ($n == "$me" || $n == "$UID") && $c -ge 65536 ]] && { gsub=$s gsubn=$c; break; }
	done </etc/subgid
	if [[ -z $sub || -z $gsub ]]; then
		echo "flong: $me has no /etc/subuid and /etc/subgid range 65536 wide: give it users.users.$me.subUidRanges and subGidRanges (or autoSubUidGidRange)" >&2
		return 1
	fi

	fl_map "$cuid" "$UID" "$sub" "$subn"; UMAP=("${MAP[@]}")
	fl_map "$cgid" "$mygid" "$gsub" "$gsubn"; GMAP=("${MAP[@]}")
	# The prepared root's on-disk owners depend on the maps, so they name the cache.
	key=$cuid.$cgid.$sub.$gsub
}

# fl_map CONTAINER-ID HOST-ID SUB WIDTH: one special id mapped onto the caller's,
# the ids below and above it filled from the subordinate range in order. Sets
# MAP to the extents as IN OUT COUNT triples. The fill is at most 65536 ids
# whatever the range's width, as the spikes measured it: 0-999 from SUB, 1000
# onto the caller, 1001-65536 from SUB+1000 for the container user 1000.
fl_map() {
	local c=$1 host=$2 h=$3 left=$4
	((left > 65536)) && left=65536
	MAP=()
	((c > 0)) && { MAP+=(0 "$h" "$c"); h=$((h + c)); left=$((left - c)); }
	MAP+=("$c" "$host" 1)
	((left > 0)) && MAP+=($((c + 1)) "$h" "$left")
}

# asroot [unshare options...] COMMAND...: container root in the keep-id
# namespace. The mapped host ids are the caller's own and its range, whatever
# FLONG_CUID and FLONG_CGID were when a tree was made, so container root here
# can delete any cache of this caller. util-linux's unshare execs newuidmap from
# PATH, and the closure's copy is not setuid: /run/wrappers/bin goes first.
asroot() {
	local a=() i
	for ((i = 0; i < ${#UMAP[@]}; i += 3)); do a+=("--map-users=${UMAP[i]}:${UMAP[i+1]}:${UMAP[i+2]}"); done
	for ((i = 0; i < ${#GMAP[@]}; i += 3)); do a+=("--map-groups=${GMAP[i]}:${GMAP[i+1]}:${GMAP[i+2]}"); done
	PATH=/run/wrappers/bin:$FLONG_BUILD/bin:$FLONG_CLOSURE/sw/bin \
		"$FLONG_BUILD/bin/unshare" --user "${a[@]}" --setuid 0 --setgid 0 "$@"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
	set -u
	(($# > 0)) || { echo "usage: asroot.sh COMMAND..." >&2; exit 2; }
	fl_identity || exit 1
	asroot "$@"
	exit
fi
