## Unreleased

* A `PATH` is no longer required to be exactly
  `/bin:/usr/bin:/usr/local/bin`. Any combination of these three
  directories and relative entries is accepted, and only an absolute entry
  outside of them is reported.

* Added the new `--module-name` option which allows us to specify the name
  of the published module we are analyzing, so that its programs are looked
  up in the library of reproducibility specs accordingly, rather than as
  programs in the main repository. This is mainly relevant for the fishery,
  not for the end users.

* The built-in library no longer names programs by a main-repository path.
  This eliminates the latent bug where if you had a program in your main
  repository at the same path as one of the 14 entries that defined a
  main-repository synonym Ahab would assume that your program has the same
  reproducibility spec as the one its library described.

* The TypeScript compiler and `rules_ts`'s options validator are named by
  the module whose extension builds them, `@aspect_rules_ts+typescript//`.
  They were named as an extension of the main repository, which is how they
  appear only when `rules_ts` itself is the workspace under analysis, so a
  project merely *using* `rules_ts` matched neither.

* The package directory given to `rules_pkg`'s tar and zip tools, and the
  paths `pkg_tar`'s `modes`, `owners` and `ownernames` are keyed by, are no
  longer reported as absolute paths. They name places inside the archive,
  e.g. `package_dir = "/usr/bin"`, not anything on the build machine.

* A reference to an empty param file is no longer spliced away. `bazel
  aquery --include_param_files` reports such a file on some runs and leaves
  it out on others, so the verdict on the action changed from one run to
  the next—notably for `tar` from `tar.bzl` packing an empty archive.

## Ahab 0.3.0

* A `/` roots a path only where something in the text says a value begins
  there, and the list of such things is closed: the start of the text, a
  word separator, an opening quote, the `=` of an assignment, the `:` or `,`
  between list elements, the `[`, and a known prefix such as `-I` in
  `-I/usr/include`. Ahab used to ask the opposite question—whether the
  character before the `/` merely looked like a separator—and almost every
  character that is not a filename character looks like one, so it answered
  yes to text that was not a path.

* No expansion roots a path. `${pwd}/proto` was already understood, from a
  list of three names that rules_rust substitutes; but whatever an expansion
  becomes, the `/` after it separates the segments of a path relative to
  that, so the name inside the brackets need not be consulted and is not.
  `${RUNFILES_DIR}/bazel_tools/…`, `$(dirname x)/keytool` and the
  `{pkg}`-style placeholder of a template all read the same way now,
  wherever in a value they sit. A path rooted at a host-dependent variable,
  as `${HOME}/lib` is, stops being reported with them; it deserves a finding
  that names the variable rather than one that prints `/lib`.

* A run holding a backslash before a regular expression's metacharacter is
  not a path: `/R\.class,/BR\.class` names no directory called `R`. A
  backslash before anything else belongs to the text around the path rather
  than to a pattern, so `echo \"/opt/toolchain/bin/cc\"` and `printf
  "prefix=/opt/x\n"` still report the path they hold.

* A genrule's `cmd` is read as the shell script it is, which is what tells
  the `<` of a quoted `'</manifest>'` from the one redirecting `cat
  </etc/passwd`.

* The `#!/bin/bash` of a script a genrule generates is no longer reported.
  A shebang is a thing a *file* begins with, and what Ahab reads is an
  argument, a param file line or an environment variable value—so the `#!`
  there is two characters and not a prefix a path hangs off. Nothing is lost
  by it: the `/bin/bash` such a genrule runs is reported as a program from
  outside the build, which is the same host dependency said once.

* A path is reported as it is written. `/usr/lib/*` used to come out as
  `/usr/lib/` and `/opt/café/bin` as `/opt/caf`—in both cases a path nothing
  has. A glob character belongs to the pattern it is part of, and a filename
  is in whatever language its author wrote it in.

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

* A `bazel query` run by a module that depends on Ahab works again.
  `//:ahab_bin` used to choose between the built binary and the downloaded
  one with a `select()`, and `bazel query`, which follows both branches,
  tried to load `//rust`, whose build dependencies a consumer does not have
  and is not meant to have. The choice is now made while BUILD files load,
  from whether Ahab is the root module. The `--//:from_source` flag is gone
  with the `select()` that read it.

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
