#!/usr/bin/env bash
# The phase-1 test wrapper: a stand-in for phase 2's mkLauncher, by hand.
#   launch.sh WORKSPACE RO_DIR COMMAND...
#
# It does the wrapper's jobs (runtime directory, identity, the prepared root and
# its cache, the payload's identity, the spec) and execs flong-launch with the
# spec as its arguments. The warm path is bash builtins only, so its cost is
# comparable with the spikes'. The knobs are CONTRACT.md's section 10; each one
# only adds to the spec.
set -u
[[ -n ${FLONG_TRACE:-} ]] && echo "T ${EPOCHREALTIME/./} launch.sh-start" >&2
(($# >= 3)) || { echo "usage: launch.sh WORKSPACE RO_DIR COMMAND..." >&2; exit 2; }

# The launcher execs this argv again when a sweep renamed the cache before the
# launcher locked it. Absolute, because it runs without a PATH search.
self=$0
[[ $self == /* ]] || self=$PWD/$self
orig=("$@")

if [[ ${BASH_SOURCE[0]} == */* ]]; then . "${BASH_SOURCE[0]%/*}/asroot.sh"; else . ./asroot.sh; fi
fl_identity || exit 1

# The spikes' already-compiled filters, until phase 3 compiles them from
# policy. FLONG_FILTER_DIR names the directory holding parity.bpf, strict.bpf,
# audit.bpf, nsmask.bpf, learn.bpf and tty.bpf, which the spikes built with
# spikes/rootless/r2-compat/filters/gen.sh. FLONG_POLICY=none needs none of
# them, and a policy that does is refused below when the directory has none.
filters=${FLONG_FILTER_DIR:-} tty_bpf=$filters/tty.bpf

# ---- canonical paths, by cd -P and $PWD rather than a realpath fork
# The workspace and RO_DIR are bound exact: the launcher opens them with
# RESOLVE_NO_SYMLINKS, so they must be canonical, and a symlink met then is a
# race. The closure is resolved for its hash. The caller's directory is
# restored, since hooks run in it.
cwd=$PWD
# canon PATH: sets canon to PATH's physical path, relative to the caller's
# directory. CDPATH is cleared so cd neither searches nor prints.
canon() {
	CDPATH='' cd -P -- "$1" 2>/dev/null || return 1
	canon=$PWD
	cd -- "$cwd" || { echo "flong: cannot return to $cwd" >&2; exit 1; }
}
canon "$1" || { echo "flong: workspace is not a directory: $1" >&2; exit 1; }
workspace=$canon
canon "$2" || { echo "flong: not a directory: $2" >&2; exit 1; }
rodir=$canon
canon "$FLONG_CLOSURE" || { echo "flong: no container closure at $FLONG_CLOSURE (nix-build spikes/rootless/shared/container.nix -o launcher/test/result-closure)" >&2; exit 1; }
closure=$canon
shift 2
[[ -x $FLONG_BUILD/bin/flong-launch ]] || { echo "flong: no launcher at $FLONG_BUILD (nix-build launcher/test -o launcher/test/result)" >&2; exit 1; }

# ---- the runtime directory
# A unit with User= gets no XDG_RUNTIME_DIR even when the user's manager runs
# (linger): derive it. A directory that is not the caller's is refused, since
# records there make the sweep run programs.
if [[ -z ${XDG_RUNTIME_DIR:-} && -d /run/user/$UID && -O /run/user/$UID ]]; then
	export XDG_RUNTIME_DIR=/run/user/$UID
fi
if [[ -z ${XDG_RUNTIME_DIR:-} || ! -d $XDG_RUNTIME_DIR || ! -O $XDG_RUNTIME_DIR ]]; then
	echo "flong: no runtime directory for $me (XDG_RUNTIME_DIR is unset or not yours)." >&2
	echo "flong: run it from a login session, or give $me a user manager: users.users.$me.linger = true" >&2
	exit 1
fi
# Its own name, so it never meets a real flong's state.
state=$XDG_RUNTIME_DIR/flong-p1

# ---- the prepared root
name=demo
storename=${closure#/nix/store/}
tag=${FLONG_CACHE_TAG:-${storename:0:8}}
cache=$state/$name-$tag-$key
P=$cache/prepared
[[ -d $cache ]] || { mkdir -p -m 0700 -- "$state" && mkdir -p -- "$cache"; } || exit 1
if [[ ! -d $P ]]; then
	# Cold. The cache's shared lock is held across the prepare and kept open
	# into flong-launch, which takes its own before closing this one: no sweep
	# renames the cache under a prepare or between the two locks.
	# A launch of another generation may have swept the cache since the mkdir.
	{ exec {cfd}<"$cache"; } 2>/dev/null || {
		[[ -e $cache ]] || exec "$self" "${orig[@]}"
		echo "flong: cannot open $cache" >&2
		exit 1
	}
	"$FLONG_BUILD/bin/flock" -s "$cfd" || exit 1
	# Swept between the mkdir and the lock: start over, without the lock on
	# the swept inode, which would keep its deletion waiting.
	[[ $cache -ef /proc/self/fd/$cfd ]] || { exec {cfd}<&-; exec "$self" "${orig[@]}"; }
	# One preparer at a time; the rest wait for it and find the root made.
	exec {pl}>"$cache/.prepare.lock" || exit 1
	"$FLONG_BUILD/bin/flock" -x "$pl" || exit 1
	if [[ ! -d $P ]]; then
		# Any staging here is a SIGKILLed preparer's, which held this lock
		# until its orphaned prepare finished, so it goes.
		for st in "$cache"/.prepare.??????; do
			[[ -d $st ]] && { asroot rm -rf -- "$st" "$st.log" || exit 1; }
		done
		staging=$(mktemp -d "$cache/.prepare.XXXXXX") || exit 1
		asroot --mount --pid --fork --kill-child "$fl_here/prepare-inner.sh" "$staging" "$closure" >"$staging.log" 2>&1 &&
			grep -q '^ACTIVATE_RC=0' "$staging.log" && grep -q '^MACHINEID_RC=0' "$staging.log" ||
			{ echo "flong: prepare failed, see $staging.log" >&2; exit 1; }
		# The rename is the second line behind the lock: a loser's root goes,
		# through the namespace that owns it.
		if mv -T -- "$staging" "$P" 2>/dev/null; then
			mv -f -- "$staging.log" "$cache/prepare.log"
		else
			[[ -d $P ]] || { echo "flong: could not install the prepared root in $cache" >&2; exit 1; }
			asroot rm -rf -- "$staging" "$staging.log"
		fi
		[[ -n ${FLONG_TRACE:-} ]] && echo "T ${EPOCHREALTIME/./} prepared" >&2
	fi
	exec {pl}>&-
fi
# Superseded caches of this container: the other generations with the same maps.
# Only a generation (an 8-character tag) sweeps or is swept, so a test's named
# fixture root (FLONG_CACHE_TAG=e4) is left alone. .trash.* is what a killed
# gc-cache.sh left.
if ((${#tag} == 8)); then
	for old in "$state/$name-"????????"-$key" "$state"/.trash.*; do
		[[ $old == "$cache" || ! -d $old ]] && continue
		"$fl_here/gc-cache.sh" "$old"
	done
fi

# ---- the payload's identity, from the prepared root
# On the warm path nothing is locked yet, so a launch of another generation may
# sweep this cache (gc-cache.sh renames it away, then deletes it) between the
# check above and these opens. Then the wrapper starts over and prepares the
# root afresh, as flong-launch's own relaunch does. Each turn follows a sweep's
# rename, an event, so there is no count. Once open, the files are read whole
# whatever happens to their names.
{ exec {pw}<"$P/etc/passwd" {gr}<"$P/etc/group"; } 2>/dev/null || {
	[[ -d $P ]] || exec "$self" "${orig[@]}"
	echo "flong: cannot read $P/etc/passwd and $P/etc/group" >&2
	exit 1
}
user='' uid='' gid='' home=''
while IFS=: read -r n _ u g _ h _; do
	[[ $u == "$cuid" ]] && { user=$n uid=$u gid=$g home=$h; break; }
done <&$pw
[[ -n $user ]] || { echo "flong: no user with uid $cuid in $P/etc/passwd" >&2; exit 1; }
[[ $gid == "$cgid" ]] || { echo "flong: $user's group is $gid in the root, the maps say $cgid (FLONG_CGID)" >&2; exit 1; }
# Supplementary groups: the primary one first, then every group naming the user.
# flong-init sets exactly these, so the caller's host groups never leak in.
groups=("$gid")
while IFS=: read -r _ _ g m; do
	[[ ,$m, == *,"$user",* && $g != "$gid" ]] && groups+=("$g")
done <&$gr
exec {pw}<&- {gr}<&-
[[ -n ${FLONG_TRACE:-} ]] && echo "T ${EPOCHREALTIME/./} root-ready" >&2

# What hooks see, as on trunk.
workspace_mode=${FLONG_WS_MODE:-rw}
binds="$rodir:ro"
export workspace workspace_mode binds uid gid home

# ---- the holder unit
# The module declares it as systemd.user.services.flong-sessions. Here it is a
# runtime unit file, written once and started with `systemctl --user start`,
# which, unlike a transient `systemd-run --unit`, any number of concurrent
# first launches may run: the losers wait for the winner's start. Type=exec:
# with the default Type=simple, start returns while the sweeper is still in
# the holder's own cgroup, before it moves to supervisor/, and enabling a
# limit's controller in the holder then fails with EBUSY. systemd nests a slice
# under the one its name's dashes spell, so flong-p1.slice lives in
# flong.slice, and the holder's cgroup path says so.
unit="[Service]
Type=exec
Slice=flong-p1.slice
Delegate=yes
DelegateSubgroup=supervisor
OOMPolicy=continue
ExecStart=$FLONG_BUILD/bin/flong-sweeper $state"
unit_file=$XDG_RUNTIME_DIR/systemd/user/flong-p1-sessions.service
# hash and BASH_CMDS find it without the fork a $(type -P) would cost.
hash systemctl 2>/dev/null || { echo "flong: no systemctl on PATH" >&2; exit 1; }
if [[ ! -e $unit_file || $(<"$unit_file") != "$unit" ]]; then
	mkdir -p "${unit_file%/*}"
	printf '%s\n' "$unit" >"$unit_file.$$" && mv -f "$unit_file.$$" "$unit_file"
	"${BASH_CMDS[systemctl]}" --user daemon-reload
fi

# ---- the spec
spec=(
	machine "${FLONG_MACHINE:-$name-$$-$RANDOM}" container "$name"
	state "$state" cache "$cache" closure "$closure"
)
for a in "$self" "${orig[@]}"; do spec+=(relaunch "$a"); done
for ((i = 0; i < ${#UMAP[@]}; i += 3)); do spec+=(uidmap "${UMAP[@]:i:3}"); done
for ((i = 0; i < ${#GMAP[@]}; i += 3)); do spec+=(gidmap "${GMAP[@]:i:3}"); done
spec+=(user "$uid" "$gid" "$home")
for g in "${groups[@]}"; do spec+=(group "$g"); done
spec+=(chdir "$workspace")
case $workspace_mode in
	rw) spec+=(mount bind-rw-exact "$workspace" "$workspace") ;;
	ro) spec+=(mount bind-ro-exact "$workspace" "$workspace") ;;
	*) echo "flong: FLONG_WS_MODE is rw or ro" >&2; exit 2 ;;
esac
spec+=(
	mount bind-ro-exact "$rodir" "$rodir"
	mount tmpfs "$home/tmp" 0700 '' user
	holder flong.slice/flong-p1.slice/flong-p1-sessions.service
)
for a in "${BASH_CMDS[systemctl]}" --user start flong-p1-sessions.service; do
	spec+=(holder-start "$a")
done
for a in --clearenv \
	--setenv PATH "$closure/sw/bin${FLONG_EXTRA_PATH:+:$FLONG_EXTRA_PATH}" \
	--setenv HOME "$home" --setenv USER "$user" \
	--setenv XDG_RUNTIME_DIR "/run/user/$uid" --setenv TERM "${TERM:-dumb}" \
	--setenv TMPDIR "$home/tmp" --hostname "$name"; do
	spec+=(bwrap-arg "$a")
done

# ---- the knobs
# Seccomp: a named stack of the spikes' filters (FLONG_POLICY), each ending with
# tty.bpf, the masked terminal-ioctl filter; or exactly the files FLONG_FILTERS
# names, colon-separated, none when it is empty.
if [[ -n ${FLONG_FILTERS+set} ]]; then
	IFS=: read -r -a stack <<<"$FLONG_FILTERS"
else
	policy=${FLONG_POLICY:-strict}
	if [[ $policy != none && ! -e $tty_bpf ]]; then
		echo "flong: FLONG_POLICY=$policy needs compiled filters: set FLONG_FILTER_DIR to a directory holding tty.bpf and the tier's own, built by the spikes' gen.sh" >&2
		exit 2
	fi
	case $policy in
		none) stack=() ;;
		parity) stack=("$filters/parity.bpf" "$filters/audit.bpf") ;;
		parity-ns) stack=("$filters/parity.bpf" "$filters/audit.bpf" "$filters/nsmask.bpf") ;;
		strict) stack=("$filters/strict.bpf" "$filters/audit.bpf" "$filters/nsmask.bpf") ;;
		strict-nons) stack=("$filters/strict.bpf" "$filters/audit.bpf") ;;
		nons-plus-*) stack=("$filters/${policy#nons-}.bpf" "$filters/audit.bpf") ;;
		plus-*) stack=("$filters/$policy.bpf" "$filters/audit.bpf" "$filters/nsmask.bpf") ;;
		learn) stack=("$filters/learn.bpf" "$filters/audit.bpf") ;;
		*) echo "flong: unknown FLONG_POLICY: $policy" >&2; exit 2 ;;
	esac
	stack+=("$tty_bpf")
fi
for f in "${stack[@]}"; do spec+=(seccomp "$f"); done

[[ -n ${FLONG_NESTED:-} ]] && spec+=(nested-userns "$FLONG_NESTED")

# FLONG_LIMITS="memory.max=1G cpu.max=50000 100000": a word without "=" belongs
# to the value before it, since cpu.max's value has a space.
if [[ -n ${FLONG_LIMITS:-} ]]; then
	set -f; words=($FLONG_LIMITS); set +f
	lf='' lv=''
	for w in "${words[@]}"; do
		if [[ $w == *=* ]]; then
			[[ -n $lf ]] && spec+=(limit "$lf" "$lv")
			lf=${w%%=*} lv=${w#*=}
		else
			[[ -n $lf ]] || { echo "flong: FLONG_LIMITS: '$w' before any FILE=VALUE" >&2; exit 2; }
			lv+=" $w"
		fi
	done
	spec+=(limit "$lf" "$lv")
fi

if [[ -n ${FLONG_NET:-} ]]; then
	set -f; pa=(${FLONG_PORTS:--t none -u none} -T "${FLONG_HOSTPORT:-none}" -U none --no-map-gw --dns-forward 169.254.1.1 ${FLONG_PASTA_EXTRA:-}); set +f
	spec+=(network)
	# A fixed forwarded port is bound on the host, and the next launch on it
	# fails until pasta has exited: the teardown waits for it. none and auto
	# bind nothing fixed.
	pwait=
	for ((i = 0; i < ${#pa[@]}; i++)); do
		spec+=(pasta-arg "${pa[i]}")
		case ${pa[i]} in
			-t | -u | --tcp-ports | --udp-ports) v=${pa[i+1]:-none} ;;
			-t?* | -u?*) v=${pa[i]:2} ;;
			--tcp-ports=* | --udp-ports=*) v=${pa[i]#*=} ;;
			*) continue ;;
		esac
		[[ $v == none || $v == auto ]] || pwait=1
	done
	[[ -n $pwait ]] && spec+=(pasta-wait)
	# pasta answers DNS at this address and forwards it to the host's resolver.
	exec 9<<<"nameserver 169.254.1.1
options edns0"
	spec+=(keep-fd 9 bwrap-arg --ro-bind-data bwrap-arg 9 bwrap-arg /etc/resolv.conf)
fi

if [[ -n ${FLONG_HOOK:-} ]]; then
	spec+=(post-start /bin/sh post-start "${FLONG_HOOK_FILE:-$fl_here/../../spikes/rootless/prototype/hook.sh}")
	export HOOK_SW=$closure/sw
fi
[[ -n ${FLONG_POSTSTOP:-} ]] && spec+=(post-stop "$FLONG_POSTSTOP")
set -f; for d in ${FLONG_DEVS:-}; do spec+=(mount dev "$d" "$d"); done; set +f
[[ -n ${FLONG_TRACE:-} ]] && spec+=(trace)
# FLONG_SPEC_EXTRA: a file of NUL-separated tokens, so a test's paths may hold
# tabs and newlines.
if [[ -n ${FLONG_SPEC_EXTRA:-} ]]; then
	[[ -r $FLONG_SPEC_EXTRA ]] || { echo "flong: cannot read FLONG_SPEC_EXTRA=$FLONG_SPEC_EXTRA" >&2; exit 2; }
	while IFS= read -r -d '' t || [[ -n $t ]]; do spec+=("$t"); done <"$FLONG_SPEC_EXTRA"
fi

exec "$FLONG_BUILD/bin/flong-launch" "${spec[@]}" -- "$@"
