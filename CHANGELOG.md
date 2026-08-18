## Unreleased

* Ahab is no longer built from source by the projects that use it. Each
  release publishes a binary for Linux and macOS on x86-64 and arm64, and
  the module downloads the one for the platform being built on and checks
  it against a digest the release recorded. The Rust toolchain, the crates
  and the protobuf compiler that building Ahab needs are now development
  dependencies, so a consumer's module graph gains Ahab, `platforms` and
  `bazel_skylib` and nothing else. In particular Ahab no longer imposes a
  Rust rule set on projects that have one of their own.

  The Linux binaries are static and so do not depend on the machine's libc.
  Windows is not supported. Consuming Ahab through `git_override` rather
  than from a registry no longer works, because the binaries a release
  publishes are recorded by that release; `AHAB_PREBUILT_LOCAL` names a
  directory holding a binary to use instead.

* The binary a consumer runs is now `@ahab//:ahab_bin` rather than
  `@ahab//:ahab`, which is the Rust target and has moved to
  `@ahab//rust:ahab`. The macros are unaffected.

* The path in a program's name may now be a pattern, with the same `*` and
  `?` that exceptions use, as in `@rules_rs+toolchains//*/bin/rustc`. This
  is for rule sets that put the platform or the toolchain version in the
  path rather than in the repository name, where an exact name would have
  had to state both and would have stopped matching at the next bump of
  either. Naming a program outright beats a pattern that covers it, and
  between two patterns the one written later wins.

## Ahab 0.1.0

* Initial release.
