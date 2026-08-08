# Ahab

This is Ahab—an advanced hermeticity analyzer for Bazel.

## Development

* `bazel build //:clippy` lints every crate in this repository.
* `bazel test //:rustfmt_test` can be used to check if all Rust source code
  is formatted.
* `bazel run //:format` formats the Rust source code.
* `bazel test //:buildifier_test` can be used to check if all Starlark
  source code is formatted.
* `bazel run //:buildifier` formats the Starlark source code.

## License

Copyright 2026–present Mark Karpov

Distributed under the MIT license.
