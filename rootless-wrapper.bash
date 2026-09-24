# The launcher's body. module.nix puts a header of assignments in
# front of it (name, container, user, closure, cuid, cgid, closure8, steps8,
# static, declared_dests, declared_binds, masks, mask_hosts, launcher,
# cache_tool, flock, mkdir, payload, network, dns_forward4, dns_forward6, the
# seccomp filters and tool, the caller's commands and postStart's) and
# writeShellApplication runs it under errexit, nounset and pipefail. It works
# out what only the launch can know -- the caller, the workspace and binds,
# the project's seccomp policy, the maps, the prepared root and the payload's
# identity -- and execs flong launch with the spec.
#
# The caller's commands are arrays: workspace_command one command, or empty
# for none; binds_commands, guard_commands, seccomp_policy_commands and
# post_start_commands a list of them, flat, as module.nix's flatCommands
# writes one -- each command's length, then its words.
#
# The warm path of a default declaration runs bash builtins only: every fork
# is on the cold path or in a command the declaration chose. So there is no
# command substitution outside those, and every test is an `if`, because a
# function or a list ending in a false test is a failure under errexit.
#
# Everything checked here is a consistency check. The caller can run
# flong launch with any spec it likes, and the launcher's own checks are the
# boundary against the payload.

# The body's own names, un-exported for the reason the header's are: a name
# the caller's environment exports stays exported through an assignment, into
# the launcher and the hooks.
export -n self launcher_args me mygid rt state cwd canon nl out raw line p mode \
	workspace_raw bind_paths bind_modes i found root m h n u g s c sub subn gsub gsubn \
	MAP UMAP GMAP mapargs key cache P cfd pl old pw gr shell groups \
	home_tmp tmpdir machine spec a resolv_conf forward4 forward6 ns rkey value rest rfd \
	policy tier_bpf

if [[ -n ${FLONG_TRACE:-} ]]; then printf 'T %s wrapper-start\n' "${EPOCHREALTIME/./}" >&2; fi

# The launcher execs this argv again when the cache was swept before it locked
# it, and execv searches no PATH, so the path is made absolute.
self=$0
if [[ $self != /* ]]; then self=$PWD/$self; fi
# Every command, the payload and postStart see the launcher's own arguments,
# and "$@" inside a function would be the function's.
launcher_args=("$@")
nl='
'

die() {
	printf '%s: %s\n' "$name" "$1" >&2
	exit "${2:-1}"
}

# run_as_caller N WORD... runs each command of a flat list in order, as the
# caller, who is already who this runs as: its words, then the launcher's
# arguments, exec'd as they are and never read by a shell. The first that
# fails ends this shell, with 1: the wrapper's own, where a guard's refusal
# refuses the launch, or a command substitution's, whose failure the caller
# of it turns into the same exit.
run_as_caller() {
	local n
	while (($# > 0)); do
		n=$1
		shift
		"${@:1:n}" "${launcher_args[@]}" || exit 1
		shift "$n"
	done
}

# ---- the caller

if ((UID == 0)); then
	die "refusing to run as root: flong runs as the calling user, and root has no subordinate range"
fi
# The name newuidmap matches /etc/subuid against, from passwd by uid, since
# USER is the caller's to set. A user passwd does not list is matched by uid.
me=$UID
while IFS=: read -r n _ u _; do
	if [[ $u == "$UID" ]]; then
		me=$n
		break
	fi
done </etc/passwd
# bash puts the real gid first in GROUPS.
mygid=${GROUPS[0]}
if ((mygid == 0)); then
	die "refusing to run with primary group 0: flong never maps host gid 0 into a session"
fi

# ---- the runtime directory
# Always /run/user/$UID, whatever XDG_RUNTIME_DIR says: the holder's sweeper
# watches that directory's flong, and `systemctl --user` finds the manager
# there. A directory that is not the caller's is refused, since records there
# make the sweeper run programs.
rt=/run/user/$UID
if [[ ! -d $rt || ! -O $rt ]]; then
	die "no runtime directory $rt owned by $me: run it from a login session, or give $me a user manager with users.users.$me.linger = true"
fi
export XDG_RUNTIME_DIR=$rt
state=$rt/flong

# ---- the workspace

# canon PATH sets canon to PATH's physical path, relative to the caller's
# directory, by cd -P and $PWD rather than a realpath fork. The ./ keeps
# `cd -P -- -` from meaning $OLDPWD, and the empty CDPATH keeps cd from
# searching and printing. The caller's directory is restored, since the
# commands, the hooks and the launcher run in it.
cwd=$PWD
canon() {
	local p=$1
	if [[ $p != /* ]]; then p=./$p; fi
	if ! CDPATH='' cd -P -- "$p" 2>/dev/null; then return 1; fi
	canon=$PWD
	CDPATH='' cd -- "$cwd" || die "cannot return to $cwd"
}

# refuse_path WHAT PATH: what PATH:MODE lines cannot carry, and what the
# session could not be given. A ':' or a newline would make $binds and
# FLONG_BINDS ambiguous to anything that splits them, a guard included. / is
# the whole host. A declared destination is mounted already, and the
# launcher would refuse the second mount there as a spec error.
refuse_path() {
	local d
	case $2 in
	*:* | *"$nl"*) die "$1 contains ':' or a newline: $2" ;;
	/) die "$1 resolves to /" ;;
	esac
	for d in "${declared_dests[@]}"; do
		if [[ $2 == "$d" ]]; then
			die "$1 $2 is where the declaration already mounts something"
		fi
	done
}

# No command is the caller's directory, taken without a fork. A command runs
# as the caller and prints the directory, with an optional :ro or :rw.
if ((${#workspace_command[@]} == 0)); then
	workspace_raw=$cwd
else
	workspace_raw=$(run_as_caller "${#workspace_command[@]}" "${workspace_command[@]}") || exit 1
fi
case $workspace_raw in
*:ro) workspace_mode=ro workspace_raw=${workspace_raw%:ro} ;;
*:rw) workspace_mode=rw workspace_raw=${workspace_raw%:rw} ;;
*) workspace_mode=rw ;;
esac
# Resolved before it is checked, so what is checked is what is mounted, and
# the guard judges the path the launcher is given.
if ! canon "$workspace_raw"; then die "workspace is not a directory: $workspace_raw"; fi
workspace=$canon
refuse_path workspace "$workspace"
export workspace workspace_mode

# ---- the caller's binds
# One PATH (read-only), PATH:ro or PATH:rw per line, resolved and refused as
# the workspace is. A path named twice is bound once, writable if either line
# says so. A bind of the workspace itself is the workspace, which it makes
# writable when it says rw, since the launcher refuses a destination twice.
# The commands' outputs are concatenated, in order, in one substitution.
bind_paths=() bind_modes=()
binds=
if ((${#binds_commands[@]} > 0)); then
	raw=$(run_as_caller "${binds_commands[@]}") || exit 1
	while IFS= read -r line; do
		if [[ -z $line ]]; then continue; fi
		case $line in
		*:rw) mode=rw p=${line%:rw} ;;
		*:ro) mode=ro p=${line%:ro} ;;
		*) mode=ro p=$line ;;
		esac
		if ! canon "$p"; then die "bind is not a directory: $p"; fi
		p=$canon
		refuse_path bind "$p"
		if [[ $p == "$workspace" ]]; then
			if [[ $mode == rw ]]; then workspace_mode=rw; fi
			continue
		fi
		found=0
		for i in "${!bind_paths[@]}"; do
			if [[ ${bind_paths[i]} == "$p" ]]; then
				if [[ $mode == rw ]]; then bind_modes[i]=rw; fi
				found=1
			fi
		done
		if ((found == 0)); then
			bind_paths+=("$p")
			bind_modes+=("$mode")
		fi
	done <<<"$raw"
	# What the guard and the payload read, with the mode on every line so a
	# reader sees what is granted without knowing the default.
	for i in "${!bind_paths[@]}"; do
		if [[ -n $binds ]]; then binds+=$nl; fi
		binds+=${bind_paths[i]}:${bind_modes[i]}
	done
fi
export binds

# ---- the guard
# It runs as the caller, so it is a consistency check and not a gate. Each
# command sees $workspace, $workspace_mode and $binds as they will be
# mounted, and must pass, in order. A relaunch runs them again.
if ((${#guard_commands[@]} > 0)); then
	run_as_caller "${guard_commands[@]}"
fi

# ---- the project's seccomp policy
# It runs as the caller after the guard, with what the guard sees, and prints
# `allow X...` and `deny X...` lines that change the declaration's allow-list.
# A failing command refuses the launch. A policy that says nothing compiles
# nothing, so the warm path stays builtins-only; one already seen is a hash
# and a cached filter under $state/seccomp, where no session can write. A
# relaunch runs it again, as it runs the guard. It sees $machine, the name
# postStart and postStop will see, so what it approves can be handed to them
# by launch and not by checkout, where two launches at once would mix.
machine=$container-$$-$RANDOM
export machine
tier_bpf=$seccomp_tier
if ((${#seccomp_policy_commands[@]} > 0)); then
	policy=$(run_as_caller "${seccomp_policy_commands[@]}") || exit 1
	if [[ -n ${policy//[[:space:]]/} ]]; then
		tier_bpf=$("${seccomp_project[@]}" "$state/seccomp" <<<"$policy") ||
			die "the project's seccomp policy was refused"
	fi
fi

# ---- the depth rule, for the caller's writable binds
# A mask two or more levels below the root of a writable bind can be moved
# from under it: a session renames the masked name's parent and leaves a decoy
# in its place, so the mask covers the decoy and the real file is readable at
# the new name. The declaration's own binds were checked at evaluation; the
# workspace and the caller's binds exist only now. A mask is checked by its
# own path, where the workspace and caller binds land, and by its host path
# through the declared bind it lies in.
for i in "${!bind_paths[@]}" workspace; do
	if [[ $i == workspace ]]; then
		root=$workspace mode=$workspace_mode
	else
		root=${bind_paths[i]} mode=${bind_modes[i]}
	fi
	if [[ $mode != rw ]]; then continue; fi
	for m in "${!masks[@]}"; do
		for h in "${masks[m]}" "${mask_hosts[m]}"; do
			if [[ -n $h && $h == "$root"/*/* ]]; then
				die "the mask ${masks[m]} hides $h, two or more levels below the writable bind $root, where a session could rename its parent from under it"
			fi
		done
	done
done

# ---- the maps
# The first /etc/subuid and /etc/subgid entry for the caller, by name or uid,
# at least 65536 wide. NixOS allocates automatic ranges in user-name order, so
# nothing assumes 100000.
sub='' subn='' gsub='' gsubn=''
while IFS=: read -r n s c; do
	if [[ ($n == "$me" || $n == "$UID") && $s =~ ^[0-9]+$ && $c =~ ^[0-9]+$ ]] && ((c >= 65536)); then
		sub=$s subn=$c
		break
	fi
done </etc/subuid
while IFS=: read -r n s c; do
	if [[ ($n == "$me" || $n == "$UID") && $s =~ ^[0-9]+$ && $c =~ ^[0-9]+$ ]] && ((c >= 65536)); then
		gsub=$s gsubn=$c
		break
	fi
done </etc/subgid
if [[ -z $sub || -z $gsub ]]; then
	die "$me has no /etc/subuid and /etc/subgid range 65536 wide: give it users.users.$me.subUidRanges and subGidRanges, or autoSubUidGidRange = true"
fi

# fl_map CONTAINER-ID HOST-ID SUB WIDTH sets MAP to IN OUT COUNT triples: the
# container id onto the caller's, the ids below and above it filled from the
# subordinate range in order, 65536 ids from it at most.
fl_map() {
	local c=$1 host=$2 h=$3 left=$4
	if ((left > 65536)); then left=65536; fi
	MAP=()
	if ((c > 0)); then
		MAP+=(0 "$h" "$c")
		h=$((h + c)) left=$((left - c))
	fi
	MAP+=("$c" "$host" 1)
	if ((left > 0)); then MAP+=($((c + 1)) "$h" "$left"); fi
}
fl_map "$cuid" "$UID" "$sub" "$subn"
UMAP=("${MAP[@]}")
fl_map "$cgid" "$mygid" "$gsub" "$gsubn"
GMAP=("${MAP[@]}")
mapargs=()
for ((i = 0; i < ${#UMAP[@]}; i += 3)); do mapargs+=("--map-users=${UMAP[i]}:${UMAP[i + 1]}:${UMAP[i + 2]}"); done
for ((i = 0; i < ${#GMAP[@]}; i += 3)); do mapargs+=("--map-groups=${GMAP[i]}:${GMAP[i + 1]}:${GMAP[i + 2]}"); done

# ---- the prepared root
# The maps decide the root's on-disk owners, and the caller's primary gid owns
# the container group's files, so all of them name the cache.
key=$cuid.$cgid.$sub.$gsub.$mygid
cache=$state/$container-$closure8-$steps8-$key
P=$cache/prepared

if [[ ! -d $P ]]; then
	# Cold: the only path with forks besides the commands, and the only one
	# that collects garbage. mkdir is the header's, by store path, so a
	# caller outside a NixOS login, or on a host whose running system lacks
	# coreutils, still finds it. $rt exists, so only $state may need making;
	# a concurrent launch may make it first.
	if ! "$mkdir" -m 0700 -- "$state" 2>/dev/null && [[ ! -d $state ]]; then
		die "cannot make $state"
	fi
	"$mkdir" -p -- "$cache"
	# The cache's shared lock is held across the prepare and kept open into
	# flong launch, which takes its own before this one closes: no sweep
	# renames the cache under a prepare or between the two locks. A launch of
	# another generation may have swept it since the mkdir.
	if ! { exec {cfd}<"$cache"; } 2>/dev/null; then
		if [[ ! -e $cache ]]; then exec "$self" "${launcher_args[@]}"; fi
		die "cannot open $cache"
	fi
	"$flock" -s "$cfd"
	# Swept between the mkdir and the lock: start over, without the lock on
	# the swept inode, which would keep its deletion waiting.
	if [[ ! $cache -ef /proc/self/fd/$cfd ]]; then
		exec {cfd}<&-
		exec "$self" "${launcher_args[@]}"
	fi
	# One preparer at a time; the rest wait for it and find the root made.
	exec {pl}>"$cache/.prepare.lock"
	"$flock" -x "$pl"
	if [[ ! -d $P ]]; then
		"$cache_tool" prepare "${mapargs[@]}" -- "$cache" "$closure" "$user" ||
			die "preparing the root for $container failed, see $cache/.prepare.*.log"
		if [[ -n ${FLONG_TRACE:-} ]]; then printf 'T %s prepared\n' "${EPOCHREALTIME/./}" >&2; fi
	fi
	exec {pl}>&-
	# Superseded generations of this container with these maps, and the trash
	# a killed collection left. The fixed widths keep another container whose
	# name only starts with this one's out. A cache still in use is kept, and
	# goes at a later cold launch or with the runtime directory at logout.
	for old in "$state/$container-"????????-????????"-$key" "$state"/.trash.*; do
		if [[ $old != "$cache" && -d $old ]]; then
			"$cache_tool" gc "${mapargs[@]}" -- "$old" ||
				printf '%s: could not remove %s, kept\n' "$name" "$old" >&2
		fi
	done
fi

# ---- the payload's identity, from the prepared root
# On the warm path nothing is locked yet, so a launch of another generation
# may sweep this cache between the test above and these opens. The wrapper
# then starts over and prepares the root afresh, as flong launch's own
# relaunch does. Once open, the files are read whole whatever happens to
# their names.
if ! { exec {pw}<"$P/etc/passwd" {gr}<"$P/etc/group"; } 2>/dev/null; then
	if [[ ! -d $P ]]; then exec "$self" "${launcher_args[@]}"; fi
	die "cannot read $P/etc/passwd and $P/etc/group"
fi
uid='' gid='' home='' shell=''
while IFS=: read -r n _ u g _ h s; do
	if [[ $n == "$user" ]]; then
		uid=$u gid=$g home=$h shell=$s
		break
	fi
done <&"$pw"
if [[ -z $uid ]]; then die "$user is not a user in $P/etc/passwd"; fi
# The maps were made from the declared ids, so ids the root disagrees with
# would put the user's files on the wrong host ids.
if [[ $uid != "$cuid" || $gid != "$cgid" ]]; then
	die "$user is $uid:$gid in the prepared root, and the declaration says $cuid:$cgid"
fi
# The primary group first, then every group naming the user. flong init sets
# exactly these, so the caller's host groups never reach the payload.
groups=("$gid")
while IFS=: read -r _ _ g m; do
	if [[ ,$m, == *,"$user",* && $g != "$gid" ]]; then groups+=("$g"); fi
done <&"$gr"
exec {pw}<&- {gr}<&-
export uid gid home

# ---- $home/tmp
# A private tmpfs, unless it would land on the host through a bind, where the
# host's directory would be covered, or on a declared mount's destination,
# where the launcher refuses a second mount.
home_tmp=1
for p in "$workspace" "${bind_paths[@]}" "${declared_binds[@]}"; do
	if [[ $home/tmp == "$p" || $home/tmp == "$p"/* ]]; then home_tmp=0; fi
done
for p in "${declared_dests[@]}"; do
	if [[ $p == "$home/tmp" ]]; then home_tmp=0; fi
done
tmpdir=/tmp
if ((home_tmp)); then tmpdir=$home/tmp; fi

# ---- the spec
# The user manager's bus and private socket could stop the holder or start a
# unit outside the sandbox, so no mount may reach them.
spec=(machine "$machine" state "$state" cache "$cache" "${static[@]}"
	protect "$rt/bus" protect "$rt/systemd")
# The tier's filter, then audit, tty and the namespace mask, each one
# --add-seccomp-fd in this order. The order decides only which errno a call
# two of them refuse gets: the most recently installed filter's.
if [[ -n $tier_bpf ]]; then spec+=(seccomp "$tier_bpf"); fi
for a in "${seccomp_fixed[@]}"; do spec+=(seccomp "$a"); done
for a in "$self" "${launcher_args[@]}"; do spec+=(relaunch "$a"); done
for ((i = 0; i < ${#UMAP[@]}; i += 3)); do spec+=(uidmap "${UMAP[@]:i:3}"); done
for ((i = 0; i < ${#GMAP[@]}; i += 3)); do spec+=(gidmap "${GMAP[@]:i:3}"); done
spec+=(user "$uid" "$gid" "$home")
for g in "${groups[@]}"; do spec+=(group "$g"); done
# The workspace and the caller's binds are canonical, so they are bound exact:
# a symlink the launcher meets on the way is a race, and refused.
spec+=(chdir "$workspace" mount "bind-$workspace_mode-exact" "$workspace" "$workspace")
for i in "${!bind_paths[@]}"; do
	spec+=(mount "bind-${bind_modes[i]}-exact" "${bind_paths[i]}" "${bind_paths[i]}")
done
if ((home_tmp)); then spec+=(mount tmpfs "$home/tmp" 0700 '' user); fi
# postStart keeps trunk's positional parameters: the launcher's arguments.
# One post-start per command, in order: its word count, then its words (the
# hook program first, as module.nix put it) and the launcher's arguments.
i=0
while ((i < ${#post_start_commands[@]})); do
	n=${post_start_commands[i]}
	spec+=(post-start $((n + ${#launcher_args[@]})) "${post_start_commands[@]:i+1:n}" "${launcher_args[@]}")
	i=$((i + 1 + n))
done

if ((network)); then
	# A networked session's resolver is pasta. One synthetic nameserver per
	# family the host's resolv.conf names a nameserver in, in the host's
	# order, each with its --dns-forward: for a family with none, pasta would
	# send the queries to the host's own loopback. search, domain and options
	# come across as they are, so a short name means in here what it means out
	# there. Read once, as pasta reads it once: a host that moves networks
	# keeps a live session on the old resolver.
	forward4='' forward6=''
	resolv_conf="# flong: pasta forwards queries sent here to the host's resolver.$nl"
	if [[ -r /etc/resolv.conf ]]; then
		while read -r rkey value rest || [[ -n $rkey ]]; do
			case $rkey in
			nameserver)
				case $value in
				*:*)
					if [[ -n $forward6 ]]; then continue; fi
					forward6=$dns_forward6 ns=$forward6
					;;
				*.*)
					if [[ -n $forward4 ]]; then continue; fi
					forward4=$dns_forward4 ns=$forward4
					;;
				*) continue ;;
				esac
				spec+=(pasta-arg --dns-forward pasta-arg "$ns")
				resolv_conf+="nameserver $ns$nl"
				;;
			search | domain | options)
				resolv_conf+="$rkey $value${rest:+ $rest}$nl"
				;;
			esac
		done </etc/resolv.conf
	fi
	# A here-string ends in a newline of its own, which the file already has.
	exec {rfd}<<<"${resolv_conf%"$nl"}"
	spec+=(keep-fd "$rfd" bwrap-arg --perms bwrap-arg 0644
		bwrap-arg --ro-bind-data bwrap-arg "$rfd" bwrap-arg /etc/resolv.conf)
fi

# The payload's environment is built from nothing, so the caller's tokens and
# agent sockets never reach it.
for a in --clearenv \
	--setenv PATH "$closure/sw/bin" --setenv HOME "$home" \
	--setenv USER "$user" --setenv LOGNAME "$user" --setenv SHELL "$shell" \
	--setenv XDG_RUNTIME_DIR "/run/user/$uid" --setenv TMPDIR "$tmpdir" \
	--setenv FLONG_BINDS "$binds" --setenv container flong \
	--setenv TERM "${TERM:-dumb}" --hostname "$container"; do
	spec+=(bwrap-arg "$a")
done
if [[ -n ${COLORTERM:-} ]]; then spec+=(bwrap-arg --setenv bwrap-arg COLORTERM bwrap-arg "$COLORTERM"); fi
if [[ -n ${FLONG_TRACE:-} ]]; then spec+=(trace); fi

# TRANSITION ONLY (STANDALONE.md, S3), deleted with this file: the spec as
# the words flong launch would be given, each ending in a NUL, the
# resolver's text first, for tests/transition.nix to diff with
# `flong launch --dump-argv`; nothing is launched.
if [[ -n ${FLONG_DUMP_SPEC:-} ]]; then
	if ((network)); then printf 'resolv:%s\0' "$resolv_conf"; else printf 'resolv:\0'; fi
	printf '%s\0' "${spec[@]}" -- "$payload" "$workspace" "${launcher_args[@]}"
	exit 0
fi

exec "$launcher" launch "${spec[@]}" -- "$payload" "$workspace" "${launcher_args[@]}"
