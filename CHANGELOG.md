## Unreleased

* Ahab knows the Apple toolchain, and the answer is the same for all of it:
  an Apple build works from the Xcode installed on the machine, so its tools
  are host-derived.

* Bazel's `zipper` is recognized under the path it is built at,
  `@bazel_tools//third_party/ijar/zipper`, and not only as the
  `//tools/zip:zipper` alias for it—which is the name an action records.

* The macros take `bazel_flags`, and the binary a `--bazel-flag` that may be
  repeated, each value handed to `bazel aquery` as it stands.

* Two placeholders that well-known rule sets write into their actions on
  purpose no longer count as absolute paths. `/PLACEHOLDER_DEVELOPER_DIR` is
  what `apple_support` and `rules_swift` map the Xcode developer directory
  onto—it is the string that stands in the output instead of wherever Xcode
  is installed. `/bazel_rules_apple/fakepath` is the `--binary-file`
  argument `rules_apple` hands to `appintentsmetadataprocessor`, which
  insists on the flag having a value even when compile-time extraction reads
  no binary.

## Ahab 0.2.1

* Add reproducibility specs for Closure and J2CL build tools, the metadata
  merger shipped by `rules_webtesting`, and Brotli compression.

* Ahab now knows the Zig compiler as `rules_zig` registers it. A
  compilation that emits machine code is reported unless it asked for one
  of the three release optimization modes or for LLVM. Zig's language
  reference promises a reproducible build in `ReleaseFast`, `ReleaseSafe`
  and `ReleaseSmall` and disclaims one in `Debug`, which is the default and
  which is also the mode that reaches for Zig's own code generator—it emits
  from every core at once and writes out whichever thread finished first.
  A compilation is reported again unless it strips, because debugging
  information records the directory the compilation ran in and Zig has no
  `--remap-path-prefix` to rewrite it; a release mode is no help there. A
  static archive is reported whatever else was asked for: it stores the
  name of a temporary directory drawn afresh for every invocation.
  Documentation builds and `translate-c` are held to none of this, having
  no code generator to answer for.

* Ahab now asks for the host platform when it runs `bazel info` to find the
  output base. `bazel info` resolves `--platforms` without the main
  repository's mapping, so a project whose rc files point it at a platform
  in an external module—`--platforms=@myrepo//foo`—made the command fail
  even though the same flag builds fine. None of the keys Ahab reads depend
  on the target platform, and the aquery still runs under whatever platform
  the project configured. Thanks to Kaylie for reporting and for the fix.

## Ahab 0.2.0

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

* A `[…]` group in a path is read as part of the path around it, so a
  directory whose name contains brackets no longer looks like the end of
  one value and the start of another. `src/routes/axes/[...id]/+page.svelte`
  reported the phantom absolute path `/+page.svelte`, and
  `/usr/lib/[abi]/libfoo.so` was reported as `/usr/lib/`. A bracket that
  opens a list still starts a path, so `--paths=[/usr/lib,/opt/lib]` yields
  both. Thanks to Aidan Grant for reporting the phantom path and for the
  first fix.

## Ahab 0.1.0

* Initial release.
