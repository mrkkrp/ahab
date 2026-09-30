#!/usr/bin/env bash

set -o errexit -o nounset -o pipefail

# Build Ahab and copy the binary out of Bazel's output tree.
#
# Usage: build_ahab.sh <destination> [bazel flags...]
#
# The flags go to both the build and the cquery, so that the file found is
# the one just built. The exec configuration's copy is skipped.

DEST="$1"
shift

bazel build "$@" //rust:ahab
BUILT="$(bazel cquery "$@" --output=files //rust:ahab | grep -v -- '-exec/' | head -1)"
mkdir -p "$(dirname "$DEST")"
cp "$(bazel info execution_root)/$BUILT" "$DEST"
chmod +x "$DEST"
