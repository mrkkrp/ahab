#!/usr/bin/env bash

set -o errexit -o nounset -o pipefail

# Build Ahab and copy the binary out of Bazel's output tree.
#
# Usage: build_ahab.sh <directory> [bazel flags...]
#
# The binary keeps its name, which on Windows ends in `.exe`. The flags go
# to both the build and the cquery, so that the file found is the one just
# built. The exec configuration's copy is skipped.

DEST="$1"
shift

bazel build "$@" //rust:ahab
BUILT="$(bazel cquery "$@" --output=files //rust:ahab | grep -v -- '-exec/' | head -1)"
mkdir -p "$DEST"
cp "$(bazel info execution_root)/$BUILT" "$DEST"
chmod +x "$DEST/$(basename "$BUILT")"
