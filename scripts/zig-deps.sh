#!/usr/bin/env bash
# Moves each build.zig.zon dependency pinned to a GitHub release tag to its
# upstream's latest one (`zig fetch --save`, which rewrites its url and hash
# and keeps .lazy), then works native.nix's zigDeps hash out again: the
# fetch built with a fake hash, the hash Nix reports written back. Called by
# the weekly update; prints a line per dependency that moved, "name vA ->
# vB".
#
# Only plain vX.Y.Z tags count, never a pre-release, and only one whose
# build.zig.zon asks for no newer Zig than mise.toml's (its
# minimum_zig_version): minish 0.2.0 on needs Zig 0.16, zwanzig 0.16 would
# too, and Zig's minor moves by hand, with zig_0_NN in native.nix.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

zig=$(zig version)

# Whether Zig $zig builds tag $2 of GitHub repository $1 by its
# minimum_zig_version (none declared: yes; no build.zig.zon read: no).
fits() {
	local zon min
	zon=$(curl -fsSL "https://raw.githubusercontent.com/${1#https://github.com/}/$2/build.zig.zon") || return 1
	min=$(sed -n 's/.*\.minimum_zig_version = "\([^"]*\)".*/\1/p' <<<"$zon")
	[ -z "$min" ] || [ "$(printf '%s\n' "$min" "$zig" | sort -V | head -n1)" = "$min" ]
}

# "name url" for every dependency whose url is a tag's archive.
deps=$(awk '
	/^ *\.[a-z_0-9]+ = \.\{/ { name = $1; sub(/^\./, "", name) }
	/^ *\.url = "https:\/\/github\.com\/.*\/archive\/refs\/tags\/.*\.tar\.gz"/ {
		url = $3; gsub(/[",]/, "", url); print name, url
	}
' build.zig.zon)

while read -r name url; do
	[ -n "$name" ] || continue
	repo=${url%/archive/refs/tags/*}
	was=${url##*/refs/tags/}
	was=${was%.tar.gz}
	now=
	# Newest first, down to the pinned one.
	for tag in $(git ls-remote --tags --refs "$repo" | sed -n 's|.*refs/tags/\(v[0-9]*\.[0-9]*\.[0-9]*\)$|\1|p' | sort -rV); do
		if [ "$tag" = "$was" ]; then break; fi
		if fits "$repo" "$tag"; then now=$tag; break; fi
	done
	if [ -n "$now" ]; then
		zig fetch --save="$name" "$repo/archive/refs/tags/$now.tar.gz" >&2
		echo "$name $was -> $now"
	fi
done <<<"$deps"

if git diff --quiet build.zig.zon; then exit 0; fi

# native.nix's zigDeps hash, for the new build.zig.zon.
fake=sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
old=$(sed -n '/deps = zigDeps {/,/};/s/.*hash = "\(sha256-[^"]*\)";.*/\1/p' native.nix)
if [ "$(wc -l <<<"$old")" -ne 1 ] || [ -z "$old" ]; then
	echo "zig-deps: native.nix must have exactly one zigDeps hash" >&2
	exit 1
fi
sed -i "s|$old|$fake|" native.nix
got=$(nix build --no-link -f native.nix deps 2>&1 | sed -n 's/.*got: *//p' || true)
if [ -z "$got" ]; then
	sed -i "s|$fake|$old|" native.nix
	echo "zig-deps: no hash came out of the fetch; native.nix's hash is left as it was" >&2
	exit 1
fi
sed -i "s|$fake|$got|" native.nix
echo "zig-deps: zigDeps hash $got" >&2
