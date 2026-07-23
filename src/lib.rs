//! Ahab — an advanced hermeticity analyzer for Bazel.
//!
//! Shell out to `bazel aquery` with a deliberately-controlled environment, ask
//! for the action graph in binary protobuf form, decode the resulting
//! `analysis.ActionGraphContainer`, and run a series of hermeticity checks over
//! the actions Bazel plans to execute.
//!
//! The crate is split into these modules:
//! - [`cli`] — the [`Cli`] parser and the top-level orchestration.
//! - [`aquery`] — running `bazel aquery`/`info` and decoding the action graph.
//! - [`checks`] — the pure hermeticity checks over a decoded action graph.
//! - [`reproducibility_spec`] — modelling a program's reproducibility.

mod aquery;
mod checks;
mod cli;
pub mod reproducibility_spec;

pub use cli::Cli;

// Re-exported for callers that want to run and inspect an aquery directly.
pub use aquery::run_aquery;

// Generated Rust types for the vendored Bazel `analysis_v2.proto` come from the
// `//proto:analysis_v2_rs_proto` target, which rules_rust exposes as the
// `analysis_v2_proto` crate. `analysis_v2.proto` declares `package analysis;`,
// so its messages live under the `analysis` module of that crate.
pub use analysis_v2_proto::analysis::ActionGraphContainer;
