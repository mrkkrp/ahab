# LLVM module consumer test

This workspace exercises the `llvm` module's prebuilt Clang, Clang++, strip
tool and platform link wrapper. Its empty Ahab report uses only built-in
specifications, with no exceptions. The C and C++ programs use all three
date/time macros; their compilation must replace those values, and debug
information must use a stable compilation directory.

From the Ahab repository root, build a local binary, then run the consumer:

```sh
.github/workflows/build_ahab.sh "$PWD/packaging/llvm/.ahab/ahab"
export AHAB_PREBUILT_LOCAL="$PWD/packaging/llvm/.ahab"
cd packaging/llvm
bazel test //:c //:cpp
bazel build //:c.stripped //:cpp.stripped
bazel run //:check
```

CI runs the workspace on Linux and macOS, on both x86-64 and arm64. Unit
tests cover missing compiler flags, nondeterministic archive options and
link-wrapper modes that still require analysis. This is a policy and
consumer test; it does not compare artifacts from independent rebuilds.
