//! Talking to Bazel: run `bazel aquery` (and `bazel info`) under a
//! deliberately-controlled environment and decode the resulting action
//! graph.

use std::process::Command;

use anyhow::{Context, Result, bail};
use prost::Message;

use analysis_v2_proto::analysis::ActionGraphContainer;

/// The value Ahab substitutes for `USER` while querying.
pub(crate) const USER_SENTINEL: &str =
    "ahab-sentinel-user-4f8a1c6b9d2e7350";

/// The `HOSTNAME` counterpart. Neither sentinel may be a substring of the
/// other: the checks look for each with `contains`, and a shared tail would
/// report one leak as both.
pub(crate) const HOSTNAME_SENTINEL: &str =
    "ahab-sentinel-hostname-4f8a1c6b9d2e7350";

/// The directory from which nested `bazel` invocations should run.
///
/// Under `bazel run` our working directory is the runfiles tree inside the
/// output base, and a nested `bazel` refuses to run from there. Bazel
/// exports the original invocation directory for wrappers to recover.
/// `None` means Bazel did not launch us; inherit the current directory.
fn workspace_dir() -> Option<std::ffi::OsString> {
    std::env::var_os("BUILD_WORKING_DIRECTORY")
        .or_else(|| std::env::var_os("BUILD_WORKSPACE_DIRECTORY"))
}

/// Run `bazel info` with the *unmodified* environment and parse its `key:
/// value` lines, learning the paths the project normally uses.
fn bazel_info() -> Result<std::collections::HashMap<String, String>> {
    let mut command = Command::new("bazel");
    command.arg("info");

    // `bazel info` resolves `--platforms` without the main repository's
    // mapping, so rc files pointing it at an external module
    // (`--platforms=@myrepo//foo`) make it fail where a build would not.
    // No key we read depends on the target platform.
    command.arg("--platforms=@platforms//host");

    if let Some(dir) = workspace_dir() {
        command.current_dir(dir);
    }

    let output = command
        .output()
        .context("failed to spawn `bazel info` subprocess")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "`bazel info` exited with {}:\n{}",
            output.status,
            stderr.trim_end()
        );
    }

    let stdout = String::from_utf8(output.stdout)
        .context("`bazel info` produced non-UTF-8 output")?;
    let info = stdout
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| {
            (key.trim().to_owned(), value.trim().to_owned())
        })
        .collect();
    Ok(info)
}

/// Invoke `bazel aquery` for `label`, forwarding `--config` values and
/// `bazel_flags` verbatim and overriding `env` on top of the inherited
/// environment, then decode the response.
///
/// `USER` feeds Bazel's output base and output-user root, so overriding it
/// naively would send the nested `bazel` to a different server than the
/// project uses and stall on the workspace lock. Both are therefore
/// discovered with the unmodified environment and pinned as startup flags,
/// so only the actions' environment changes. `output_base` overrides that
/// discovery.
pub fn run_aquery(
    configs: &[String],
    compilation_mode: Option<&str>,
    bazel_flags: &[String],
    label: &str,
    env: &[(&str, &str)],
    output_base: Option<&str>,
) -> Result<ActionGraphContainer> {
    let discovered;
    let output_base = match output_base {
        Some(given) => given,
        None => {
            discovered = bazel_info()?
                .get("output_base")
                .context(
                    "`bazel info` did not report an \"output_base\" key",
                )?
                .clone();
            &discovered
        }
    };

    // `bazel info` doesn't expose output_user_root, but it is the parent of
    // output_base (the `_bazel_$USER` directory).
    let output_user_root = std::path::Path::new(output_base)
        .parent()
        .with_context(|| {
            format!("output_base {output_base:?} has no parent directory")
        })?
        .to_str()
        .with_context(|| {
            format!(
                "output_base parent of {output_base:?} is not valid UTF-8"
            )
        })?;

    let mut command = Command::new("bazel");

    command.arg(format!("--output_base={output_base}"));
    command.arg(format!("--output_user_root={output_user_root}"));

    command.arg("aquery");

    for (name, value) in env {
        command.env(name, value);
    }

    if let Some(dir) = workspace_dir() {
        command.current_dir(dir);
    }

    for config in configs {
        command.arg(format!("--config={config}"));
    }

    // After the configs, so an outright mode beats what a named
    // configuration in the project's rc files chose.
    if let Some(mode) = compilation_mode {
        command.arg(format!("--compilation_mode={mode}"));
    }

    // Last, and so the final word on any option the other two also set.
    for flag in bazel_flags {
        command.arg(flag);
    }

    command.arg("--output=proto");

    // Without this the arguments of exactly the largest actions—the ones
    // spilled into param files—would be invisible to the checks.
    command.arg("--include_param_files");

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sentinels_cannot_be_mistaken_for_each_other() {
        assert!(!USER_SENTINEL.contains(HOSTNAME_SENTINEL));
        assert!(!HOSTNAME_SENTINEL.contains(USER_SENTINEL));
        assert_ne!(USER_SENTINEL, HOSTNAME_SENTINEL);
    }

    #[test]
    fn the_sentinels_are_findable_and_long_enough() {
        for sentinel in [USER_SENTINEL, HOSTNAME_SENTINEL] {
            assert!(sentinel.starts_with("ahab-"), "{sentinel}");
            assert!(sentinel.len() >= 32, "{sentinel}");
        }
    }
}
