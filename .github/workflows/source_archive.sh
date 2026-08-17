#!/usr/bin/env bash

set -o errexit -o nounset -o pipefail

# Build the source archive that the Bazel Central Registry points at.
#
# Usage: source_archive.sh <prefix> <output.tar.gz>
#
# GNU tar: --transform and --owner are not in the BSD tar that macOS ships,
# so this runs on Linux, which is where the release job calls it.
#
# What goes in is everything git tracks, minus the paths listed below.

EXCLUDE=(
  # The integration harness: clones other people's repositories and records
  # what Ahab found in them.
  "fishery/"
  # CI and release automation, including this script.
  ".github/"
  # Registry publishing templates, read from the repository at the tag.
  ".bcr/"
  # Starlark formatting check.
  "tools/"
  # The development environment.
  ".envrc"
  "flake.lock"
  "flake.nix"
  ".gitignore"
)

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <prefix> <output.tar.gz>" >&2
  exit 1
fi

PREFIX="$1"
OUTPUT="$2"

included() {
  local path="$1" pattern
  for pattern in "${EXCLUDE[@]}"; do
    case "$pattern" in
      */) [[ "$path" == "$pattern"* ]] && return 1 ;;
      *) [[ "$path" == "$pattern" ]] && return 1 ;;
    esac
  done
  return 0
}

FILES=()
while IFS= read -r path; do
  if included "$path"; then
    FILES+=("$path")
  fi
done < <(git ls-files)

if [ "${#FILES[@]}" -eq 0 ]; then
  echo "$0: nothing to archive" >&2
  exit 1
fi

SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"

# Read from the working tree rather than from the tag, because release
# preparation writes the table of published binaries into
# private/prebuilt_versions.bzl first and that has to be in here.
tar --create --file "$OUTPUT" \
  --use-compress-program "gzip -n" \
  --transform "s,^,${PREFIX}/," \
  --owner=0 --group=0 --numeric-owner \
  --sort=name \
  --mtime="@$SOURCE_DATE_EPOCH" \
  --files-from <(printf '%s\n' "${FILES[@]}")
