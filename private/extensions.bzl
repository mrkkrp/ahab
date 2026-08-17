"""Where a consumer's Ahab binary comes from.

Ahab is written in Rust and its build needs a Rust toolchain, crate
dependencies and a protobuf compiler. None of that is a consumer's business:
making them build the analyzer from source would put all of it in their
module graph, where it can collide with whatever else they build Rust with.
So the build-time dependencies are declared `dev_dependency` and a consumer
takes the binary that the release built for their platform.

`AHAB_PREBUILT_LOCAL` names a directory holding an `ahab` binary to use
instead of downloading one. It exists so that Ahab's own tests can exercise
the path a consumer takes—`packaging/` runs against a binary this repository
just built—and it is the only way to get a binary before a release has
published any.
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load(
    ":prebuilt_versions.bzl",
    "AHAB_PLATFORMS",
    "AHAB_PREBUILT",
    "AHAB_URL_TEMPLATE",
)

LOCAL_ENV_VAR = "AHAB_PREBUILT_LOCAL"

_ARCHIVE_BUILD = """\
load("@bazel_skylib//rules:native_binary.bzl", "native_binary")

native_binary(
    name = "binary",
    src = "ahab",
    out = "ahab_exe",
    visibility = ["//visibility:public"],
)
"""

_LOCAL_BUILD = """\
load("@bazel_skylib//rules:native_binary.bzl", "native_binary")

native_binary(
    name = "ahab",
    src = "ahab_local",
    out = "ahab_exe",
    visibility = ["//visibility:public"],
)
"""

_UNAVAILABLE = """\
No prebuilt Ahab binary is available for version {version}.

Release automation records the published binaries in
private/prebuilt_versions.bzl, and this version has none—which is a broken
release rather than anything you did. Please report it at
https://github.com/mrkkrp/ahab/issues. To carry on meanwhile, set
{env}=<directory containing an `ahab` binary>. """

def _hub_impl(repository_ctx):
    version = repository_ctx.attr.version
    local = repository_ctx.os.environ.get(LOCAL_ENV_VAR)
    if local:
        repository_ctx.symlink(
            repository_ctx.path(local).get_child("ahab"),
            "ahab_local",
        )
        repository_ctx.file("BUILD.bazel", _LOCAL_BUILD)
        return

    if not AHAB_PREBUILT:
        fail(_UNAVAILABLE.format(
            version = version,
            env = LOCAL_ENV_VAR,
        ))

    lines = ["""\
package(default_visibility = ["//visibility:public"])
"""]
    branches = []
    for platform in sorted(AHAB_PREBUILT):
        constraints = AHAB_PLATFORMS[platform]
        lines.append("""\
config_setting(
    name = "{platform}",
    constraint_values = {constraints},
)
""".format(
            platform = platform,
            constraints = repr(constraints),
        ))
        branches.append('        ":{platform}": "@ahab_prebuilt_{platform}//:binary",'.format(
            platform = platform,
        ))

    lines.append("""\
alias(
    name = "ahab",
    actual = select(
        {{
{branches}
        }},
        no_match_error = "Ahab {version} publishes a binary for {published}, and this build is for none of them. Ask for your platform at https://github.com/mrkkrp/ahab/issues.",
    ),
)
""".format(
        branches = "\n".join(branches),
        published = ", ".join(sorted(AHAB_PREBUILT)),
        version = version,
    ))

    repository_ctx.file("BUILD.bazel", "\n".join(lines))

_hub = repository_rule(
    implementation = _hub_impl,
    attrs = {
        "version": attr.string(
            doc = "The version of Ahab whose binaries this repository names.",
            mandatory = True,
        ),
    },
    environ = [LOCAL_ENV_VAR],
    doc = "Picks the binary for the platform being built for.",
)

def _ahab_version(module_ctx):
    """The version of the module that declared this extension.
    """
    for mod in module_ctx.modules:
        if mod.name == "ahab":
            return mod.version
    fail("the prebuilt extension was evaluated without the ahab module")

def _prebuilt_impl(module_ctx):
    version = _ahab_version(module_ctx)
    for platform, sha256 in AHAB_PREBUILT.items():
        http_archive(
            name = "ahab_prebuilt_" + platform,
            build_file_content = _ARCHIVE_BUILD,
            sha256 = sha256,
            urls = [AHAB_URL_TEMPLATE.format(
                platform = platform,
                version = version,
            )],
        )
    _hub(
        name = "ahab_prebuilt",
        version = version,
    )

prebuilt = module_extension(
    implementation = _prebuilt_impl,
    doc = "Fetches the released Ahab binary for the target platform.",
)
