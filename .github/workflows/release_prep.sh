#!/usr/bin/env bash

set -o errexit -o nounset -o pipefail

# Prepare the release, as `bazel-contrib/.github`'s release_ruleset workflow
# expects: whatever this prints is pre-pended to the generated notes, and
# every file matching the workflow's `release_files` glob is uploaded and
# attested.
#
# The binaries are built by the `binaries` job and downloaded before this
# runs. What this adds is the record of them: a consumer's build reads
# private/prebuilt_versions.bzl to know which platforms a release published
# and what each archive should hash to, so that file has to be written
# before the source archive is assembled around it.

# The tag arrives as the first argument. `GITHUB_REF_NAME` is the fallback
# and only agrees with it when a tag push started the run—on a manual
# re-run it is the branch, which would silently produce a version like
# "aster".
TAG="${1:-${GITHUB_REF_NAME}}"
case "$TAG" in
  v*) VERSION="${TAG:1}" ;;
  *) echo "release_prep: $TAG is not a v-prefixed tag" >&2; exit 1 ;;
esac
# Chosen to match what GitHub generates for source archives, so that
# `strip_prefix` in .bcr/source.template.json is right either way.
PREFIX="ahab-$VERSION"
ARCHIVE="$PREFIX.tar.gz"
VERSIONS_FILE="private/prebuilt_versions.bzl"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

fail() {
  echo "release_prep: $*" >&2
  exit 1
}

# The module version is what the prebuilt extension builds download URLs
# out of, so a tag that disagrees with it would publish binaries nobody can
# fetch.
module_version="$(sed -n 's/^ *version = "\([^"]*\)",.*/\1/p' MODULE.bazel |
  head -1)"
if [ "$module_version" != "$VERSION" ]; then
  fail "MODULE.bazel says version $module_version, tag says $VERSION"
fi

# The platforms a release is meant to publish for, taken from the same file
# the repository rule reads, so the two cannot drift.
mapfile -t expected < <(sed -n '/^AHAB_PLATFORMS = {/,/^}/p' "$VERSIONS_FILE" |
  sed -n 's/^ *"\([a-z0-9_]*\)": \[/\1/p' | sort)
[ "${#expected[@]}" -gt 0 ] || fail "no platforms found in $VERSIONS_FILE"

# Each `binaries` job uploads one artifact named after its platform, and
# the reusable workflow downloads all of them before running this. Where
# they land is not worth betting on: `actions/download-artifact` puts each
# artifact in a directory of its own, under whatever `path` it was given,
# and the reusable workflow gives it none—so they arrive beside this
# checkout rather than under artifacts/, whatever its comment says. Look
# for them a level or two down, wherever they are.
declare -A digest
found=()
table="$(mktemp)"
for platform in "${expected[@]}"; do
  binary_archive="ahab-$VERSION-$platform.tar.gz"
  path="$(find . -mindepth 2 -maxdepth 3 -type f -name "$binary_archive" |
    head -1)"
  [ -n "$path" ] || fail "no $binary_archive among the built artifacts"
  digest["$platform"]="$(sha256sum "$path" | cut -d' ' -f1)"
  found+=("$platform")
  mv "$path" "$binary_archive"
done

# The other direction: an artifact for a platform the module does not know
# about would be published and never fetched.
while IFS= read -r stray; do
  fail "artifact $stray does not correspond to any platform in $VERSIONS_FILE"
done < <(find . -mindepth 2 -maxdepth 3 -type f -name 'ahab-*.tar.gz')

{
  printf 'AHAB_PREBUILT = {\n'
  for platform in "${found[@]}"; do
    printf '    "%s": "%s",\n' "$platform" "${digest[$platform]}"
  done
  printf '}\n'
} > "$table"

python3 - "$VERSIONS_FILE" "$table" <<'PY'
import re
import sys

path, replacement = sys.argv[1], sys.argv[2]
source = open(path).read()
table = open(replacement).read()
updated, count = re.subn(
    r"AHAB_PREBUILT = \{\n(?:.*?\n)*?\}\n", table, source, count=1
)
if count != 1:
    sys.exit(f"release_prep: could not find AHAB_PREBUILT in {path}")
open(path, "w").write(updated)
PY
rm "$table"

"$HERE/source_archive.sh" "$PREFIX" "$ARCHIVE"

# Unpack the archive and run the packaging module from inside the unpacked
# copy, against the binary this release built for the platform we are on. A
# file left out of source_archive.sh's list, or a binary archive whose
# layout does not match what the repository rule expects, fails here—before
# anything is uploaded—rather than in somebody's build afterwards.
#
# Everything but the release notes goes to stderr: this script's stdout is
# pre-pended to the release notes.
case "$(uname -m)" in
  x86_64) host_platform="linux_x86_64" ;;
  aarch64 | arm64) host_platform="linux_arm64" ;;
  *) fail "no binary for $(uname -m) to verify the archive with" ;;
esac

verify_root="$(mktemp -d)"
binary_dir="$verify_root/binary"
mkdir "$binary_dir"
tar -xzf "ahab-$VERSION-$host_platform.tar.gz" -C "$binary_dir"
tar -xzf "$ARCHIVE" -C "$verify_root"
(
  cd "$verify_root/$PREFIX/packaging"
  export AHAB_PREBUILT_LOCAL="$binary_dir"
  bazel build //:ahab.report //:ahab.check //:ahab.update //:ahab.explain
  bazel run //:ahab.check
  bazel shutdown
) >&2
rm -rf "$verify_root"

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

Ahab requires Bazel 8 or later. Nothing is built from source: the binary
for your platform is downloaded from this release, so Ahab brings no Rust
toolchain, no crate dependencies and no protobuf compiler into your module
graph. This release publishes binaries for $(printf '%s, ' "${found[@]}" |
  sed 's/, $//').

See the [readme](https://github.com/mrkkrp/ahab) for the checks it runs,
how to describe your own tools, and how to record a baseline.
EOF
