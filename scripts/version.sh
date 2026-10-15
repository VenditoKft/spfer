#!/usr/bin/env bash
# Reviews the latest version tag and the commits since, and proposes the next
# semantic version based on Conventional Commit prefixes:
#
#   BREAKING CHANGE / type!:  -> major
#   feat:                     -> minor
#   anything else             -> patch
#
# Usage:
#   scripts/version.sh            print a human-readable report
#   scripts/version.sh --next     print only the proposed version (e.g. v0.2.0)
#   scripts/version.sh --next BUMP  print the next version for BUMP=major|minor|patch
set -euo pipefail

mode="report"
forced_bump=""
case "${1:-}" in
  "") ;;
  --next) mode="next"; forced_bump="${2:-}" ;;
  -h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) echo "unknown argument: $1" >&2; exit 2 ;;
esac

last_tag="$(git describe --tags --abbrev=0 --match 'v[0-9]*.[0-9]*.[0-9]*' 2>/dev/null || true)"
if [[ -n "$last_tag" ]]; then
  range="${last_tag}..HEAD"
  base="$last_tag"
else
  range="HEAD"
  base="v0.0.0"
fi

if [[ ! "$base" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  echo "cannot parse version tag: $base" >&2
  exit 1
fi
major="${BASH_REMATCH[1]}" minor="${BASH_REMATCH[2]}" patch="${BASH_REMATCH[3]}"

subjects="$(git log --format='%s' "$range")"
bodies="$(git log --format='%b' "$range")"

if [[ -z "$subjects" ]]; then
  if [[ "$mode" == "next" ]]; then
    echo "no commits since $base" >&2
    exit 1
  fi
  echo "Latest version: $base"
  echo "No commits since $base - nothing to release."
  exit 0
fi

bump="patch"
reason="only fixes/chores since $base"
if grep -qE '^[a-zA-Z]+(\([^)]*\))?!:' <<<"$subjects" || grep -qE '^BREAKING[ -]CHANGE:' <<<"$bodies"; then
  bump="major"
  reason="breaking change found (type!: or BREAKING CHANGE:)"
elif grep -qE '^feat(\([^)]*\))?:' <<<"$subjects"; then
  bump="minor"
  reason="new feature(s) found (feat:)"
fi

next_version() {
  case "$1" in
    major) echo "v$((major + 1)).0.0" ;;
    minor) echo "v${major}.$((minor + 1)).0" ;;
    patch) echo "v${major}.${minor}.$((patch + 1))" ;;
    *) echo "invalid bump: $1 (want major, minor or patch)" >&2; return 1 ;;
  esac
}

if [[ "$mode" == "next" ]]; then
  next_version "${forced_bump:-$bump}"
  exit 0
fi

echo "Latest version: ${last_tag:-<none, starting from v0.0.0>}"
echo
echo "Commits since ${last_tag:-the beginning} ($(wc -l <<<"$subjects")):"
git log --format='  %h %s' "$range"
echo
echo "Options:"
for b in major minor patch; do
  marker=" "
  [[ "$b" == "$bump" ]] && marker="*"
  printf '  %s %-5s -> %s\n' "$marker" "$b" "$(next_version "$b")"
done
echo
echo "Proposed: $bump -> $(next_version "$bump")  ($reason)"
if [[ "$bump" == "major" && "$major" -ge 1 ]]; then
  echo
  echo "Note: Go modules at v2+ need the major version in the module path"
  echo "      (e.g. github.com/VenditoKft/spfer/v$((major + 1))) - update go.mod first."
fi
