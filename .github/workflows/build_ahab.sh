#!/usr/bin/env bash

set -o errexit -o nounset -o pipefail

# Build Ahab and copy the binary out of Bazel's output tree.
#
# Usage: build_ahab.sh <directory>
#
# The binary keeps its name, which on Windows ends in `.exe`. How it is
# built, as released, is .bazelrc's to say. The exec configuration's copy is
# skipped.

DEST="$1"

bazel build //rust:ahab
BUILT="$(bazel cquery --output=files //rust:ahab | grep -v -- '-exec/' | head -1)"
mkdir -p "$DEST"
cp "$(bazel info execution_root)/$BUILT" "$DEST"
chmod +x "$DEST/$(basename "$BUILT")"
