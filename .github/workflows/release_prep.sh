#!/usr/bin/env bash

set -o errexit -o nounset -o pipefail

# Build the release archive and print the release notes, as
# `bazel-contrib/.github`'s release_ruleset workflow expects: the archive is
# uploaded as a release asset and attested, and whatever this prints is
# pre-pended to the generated notes.
#
# The archive is built here rather than taken from GitHub's automatic tag
# tarball because the Bazel Central Registry wants an attestation for the
# file its entry points at, and only a file we built ourselves can have one.

# The tag arrives as the first argument. `GITHUB_REF_NAME` is the fallback
# and only agrees with it when a tag push started the run—on a manual
# re-run it is the branch, which would silently produce a version like
# "aster".
TAG="${1:-${GITHUB_REF_NAME}}"
VERSION="${TAG:1}"
# Chosen to match what GitHub generates for source archives, so that
# `strip_prefix` in .bcr/source.template.json is right either way.
PREFIX="ahab-$VERSION"
ARCHIVE="$PREFIX.tar.gz"
git archive --format=tar --prefix="${PREFIX}"/ "${TAG}" | gzip >"$ARCHIVE"

cat <<EOF
## Setup

Add Ahab to your \`MODULE.bazel\`:

\`\`\`starlark
bazel_dep(name = "ahab", version = "$VERSION")
\`\`\`

Then declare a target for whatever you want analyzed:

\`\`\`starlark
load("@ahab//:defs.bzl", "ahab")

ahab(
    name = "hermeticity",
    label = "//...",
)
\`\`\`

\`\`\`
bazel run //:hermeticity
\`\`\`

Ahab requires Bazel 8 or later. See the
[readme](https://github.com/mrkkrp/ahab) for the checks it runs, how to
describe your own tools, and how to record a baseline.
EOF
