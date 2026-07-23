//! Ahab — an advanced hermeticity analyzer for Bazel.
//!
//! First approximation: shell out to `bazel aquery`, ask it for the action
//! graph in binary protobuf form, decode the resulting
//! `analysis.ActionGraphContainer`, and hand it back to the caller.

use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::Parser;
use prost::Message;

// Generated Rust types for the vendored Bazel `analysis_v2.proto` come from the
// `//proto:analysis_v2_rs_proto` target, which rules_rust exposes as the
// `analysis_v2_proto` crate. `analysis_v2.proto` declares `package analysis;`,
// so its messages live under the `analysis` module of that crate.
pub use analysis_v2_proto::analysis::ActionGraphContainer;

/// Command-line interface for Ahab.
#[derive(Debug, Parser)]
#[command(
    name = "ahab",
    about = "Advanced hermeticity analyzer for Bazel",
    version
)]
pub struct Cli {
    /// A `--config=<name>` to forward to `bazel aquery`. May be repeated zero
    /// or more times; each value is passed through verbatim.
    #[arg(long = "config", value_name = "NAME")]
    pub configs: Vec<String>,

    /// The Bazel label or wildcard to query (e.g. `//foo:bar` or `//...`).
    ///
    /// In this first approximation it is an opaque string forwarded to
    /// `bazel aquery` as the query expression.
    #[arg(value_name = "LABEL")]
    pub label: String,
}

impl Cli {
    /// Run Ahab end to end: invoke `bazel aquery` and decode its output.
    pub fn run(&self) -> Result<ActionGraphContainer> {
        run_aquery(&self.configs, &self.label)
    }
}

/// Invoke `bazel aquery` for `label`, forwarding each `--config` value, and
/// decode the binary-proto response into an [`ActionGraphContainer`].
pub fn run_aquery(configs: &[String], label: &str) -> Result<ActionGraphContainer> {
    let mut command = Command::new("bazel");
    command.arg("aquery");

    // When Ahab itself is launched via `bazel run`, our working directory is the
    // runfiles tree *inside* the bazel output base, and a nested `bazel` refuses
    // to run from there. Bazel exports the original invocation directory so
    // wrappers like this can recover it; prefer BUILD_WORKING_DIRECTORY (where
    // the user ran `bazel run`), then BUILD_WORKSPACE_DIRECTORY (the workspace
    // root). If neither is set (Ahab wasn't launched by Bazel), inherit the CWD.
    if let Some(dir) = std::env::var_os("BUILD_WORKING_DIRECTORY")
        .or_else(|| std::env::var_os("BUILD_WORKSPACE_DIRECTORY"))
    {
        command.current_dir(dir);
    }

    // Forward each requested config.
    for config in configs {
        command.arg(format!("--config={config}"));
    }

    // Ask for the action graph as a binary protobuf ActionGraphContainer.
    command.arg("--output=proto");

    // The query expression (label or wildcard) comes last.
    command.arg(label);

    let output = command
        .output()
        .context("failed to spawn `bazel aquery` subprocess")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "`bazel aquery` exited with {}:\n{}",
            output.status,
            stderr.trim_end()
        );
    }

    ActionGraphContainer::decode(output.stdout.as_slice())
        .context("failed to decode analysis.ActionGraphContainer from `bazel aquery` output")
}
