#!/bin/sh
# Recompute Dockerfile SHA-256 pins after version updates.
# A marker directly above an ARG declares the artifact URL.
set -eu

usage() {
  printf 'usage: repin-sha.sh <depName> <newVersion> [dockerfile ...]\n' >&2
  exit 2
}

[ $# -ge 2 ] || usage
dep=$1
version=$2
shift 2
[ -n "$dep" ] && [ -n "$version" ] || usage

# The third-party version reaches sed and curl, so accept only literal version characters.
case $version in
  *[!A-Za-z0-9._+~-]*)
    printf 'repin: refusing version with unexpected characters: %s\n' "$version" >&2
    exit 1
    ;;
esac

version_nov=${version#v}

if [ $# -eq 0 ]; then
  set -- Dockerfile
fi

tmp=$(mktemp -d)
staged=
cleanup() {
  rm -rf "$tmp"
  [ -n "$staged" ] && rm -f "$staged"
  return 0
}
trap cleanup EXIT INT TERM HUP

# Resolve symlinks: rename must replace the target, not the symlink.
resolve_target() {
  if command -v realpath >/dev/null 2>&1; then
    realpath "$1"
  elif command -v readlink >/dev/null 2>&1 && readlink -f "$1" >/dev/null 2>&1; then
    readlink -f "$1"
  else
    if [ -L "$1" ]; then
      printf 'repin: %s: cannot safely update symlink without realpath or readlink -f\n' "$1" >&2
      return 1
    fi
    printf '%s\n' "$1"
  fi
}

updated=0

for dockerfile in "$@"; do
  [ -f "$dockerfile" ] || continue

  dockerfile_target=$(resolve_target "$dockerfile") || {
    printf 'repin: %s: cannot resolve target path\n' "$dockerfile" >&2
    exit 1
  }

  awk -v dep="$dep" '
		/^#[[:space:]]*repin:/ {
			if (pending_dep != "") { exit 3 }
			d = ""; u = ""
			for (i = 1; i <= NF; i++) {
				if ($i ~ /^dep=/) { d = substr($i, 5) }
				if ($i ~ /^url=/) { u = substr($i, 5) }
			}
			if (d == "" || u == "") {
				printf "repin: malformed marker at %s:%d (need dep= and url=\n", FILENAME, FNR > "/dev/stderr"
				exit 3
			}
			pending_dep = d; pending_url = u; pending_line = FNR
			next
		}
		pending_dep != "" {
			if ($0 !~ /^ARG [A-Za-z_][A-Za-z0-9_]*=/) { exit 3 }
			if (pending_dep == dep) {
				name = $0
				sub(/^ARG /, "", name)
				sub(/=.*/, "", name)
				printf "%s %s\n", name, pending_url
			}
			pending_dep = ""
			next
		}
		END {
			if (pending_dep != "") {
				printf "repin: marker at %s:%d is not followed by an ARG assignment\n", FILENAME, pending_line > "/dev/stderr"
				exit 3
			}
		}
	' "$dockerfile_target" >"$tmp/pins" || exit $?

  while read -r name url; do
    [ -n "$name" ] || continue

    resolved=$(printf '%s\n' "$url" \
      | sed -e "s|{version}|$version|g" -e "s|{version_nov}|$version_nov|g")

    case $resolved in
      https://*) ;;
      *)
        printf 'repin: %s: refusing non-https URL: %s\n' "$name" "$resolved" >&2
        exit 1
        ;;
    esac

    printf 'repin: %s: %s <- %s\n' "$dockerfile" "$name" "$resolved"
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 \
      --connect-timeout 20 --max-time 300 --retry 3 --retry-delay 5 \
      -fsSL -o "$tmp/artifact" "$resolved"

    sha=$(sha256sum "$tmp/artifact" | cut -d' ' -f1)
    case $sha in
      [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) ;;
      *)
        printf 'repin: %s: sha256sum produced no digest\n' "$name" >&2
        exit 1
        ;;
    esac

    sed -E "s|^(ARG ${name}=)[0-9a-f]{64}([[:space:]].*)?\$|\1${sha}\2|" \
      "$dockerfile_target" >"$tmp/rewritten"

    if ! grep -qE "^ARG ${name}=${sha}([[:space:]]|\$)" "$tmp/rewritten"; then
      printf 'repin: %s: no 64-hex pin to rewrite in %s\n' "$name" "$dockerfile" >&2
      exit 1
    fi

    # Stage beside the target so the replacement is atomic across filesystems.
    staged=$(mktemp "$dockerfile_target.repin.XXXXXX")
    cp -p "$dockerfile_target" "$staged"
    cat "$tmp/rewritten" >"$staged"
    mv -f "$staged" "$dockerfile_target"
    staged=
    updated=$((updated + 1))
  done <"$tmp/pins"
done

if [ "$updated" -eq 0 ]; then
  printf 'repin: no pin declares dep=%s; nothing to do\n' "$dep"
fi
