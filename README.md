# Ahab

This is Ahab—an advanced hermeticity analyzer for Bazel.

## Development

* `bazel build //:clippy` lints every crate in this repository.
* `bazel test //:rustfmt_test` can be used to check if all Rust source code
  is formatted.
* `bazel run //:format` formats the Rust source code.
* `bazel test //tools:buildifier_test` can be used to check if all Starlark
  source code is formatted.
* `bazel run //tools:buildifier` formats the Starlark source code.

## The fishery

`fishery/` runs Ahab against real open-source Bazel projects and records
what it finds, so that a change to a check can be judged by its effect on
somebody else's build. See [fishery/README.md](fishery/README.md).

## License

Copyright 2026–present Mark Karpov

Distributed under the MIT license.
