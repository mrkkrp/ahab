"""Which prebuilt Ahab binaries exist, and how to find them.

`AHAB_PREBUILT` is written by release automation: cutting a release builds
a binary per platform, uploads each as a release asset, and records its
digest here before the source archive that the registry points at is
assembled. It is empty until a release does that, and while it is empty
the only ways to get a binary are `AHAB_PREBUILT_LOCAL` and building from
source—see `//private:extensions.bzl`.
"""

AHAB_PREBUILT = {
}

AHAB_PLATFORMS = {
    "darwin_arm64": [
        "@platforms//os:macos",
        "@platforms//cpu:arm64",
    ],
    "darwin_x86_64": [
        "@platforms//os:macos",
        "@platforms//cpu:x86_64",
    ],
    "linux_arm64": [
        "@platforms//os:linux",
        "@platforms//cpu:arm64",
    ],
    "linux_x86_64": [
        "@platforms//os:linux",
        "@platforms//cpu:x86_64",
    ],
}

AHAB_URL_TEMPLATE = (
    "https://github.com/mrkkrp/ahab/releases/download/v{version}/ahab-{version}-{platform}.tar.gz"
)
