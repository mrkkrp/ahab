//! Talking to Bazel: run `bazel aquery` (and `bazel info`) under a
//! deliberately-controlled environment and decode the resulting action
//! graph.

use std::process::Command;

use anyhow::{Context, Result, bail};
use prost::Message;

use analysis_v2_proto::analysis::ActionGraphContainer;

/// The value Ahab substitutes for `USER` while querying, and the one for
/// `HOSTNAME`.
pub(crate) const USER_SENTINEL: &str =
    "ahab-sentinel-user-4f8a1c6b9d2e7350";

/// The `HOSTNAME` counterpart. Distinct from [`USER_SENTINEL`] and not a
/// substring of it, since the checks look for each with `contains` and a
/// shared tail would report one leak as both.
pub(crate) const HOSTNAME_SENTINEL: &str =
    "ahab-sentinel-hostname-4f8a1c6b9d2e7350";

/// The directory from which nested `bazel` invocations should run.
///
/// When Ahab is launched via `bazel run`, our working directory is the
/// runfiles tree *inside* the bazel output base, and a nested `bazel`
/// refuses to run from there. Bazel exports the original invocation
/// directory so wrappers like this can recover it; prefer
/// `BUILD_WORKING_DIRECTORY` (where the user ran `bazel run`), then
/// `BUILD_WORKSPACE_DIRECTORY` (the workspace root). If neither is set
/// (Ahab wasn't launched by Bazel), inherit the current directory.
fn workspace_dir() -> Option<std::ffi::OsString> {
    std::env::var_os("BUILD_WORKING_DIRECTORY")
        .or_else(|| std::env::var_os("BUILD_WORKSPACE_DIRECTORY"))
}

/// Run `bazel info` (all keys) with the *unmodified* environment and parse
/// its `key: value` lines into a map, so we learn the paths the project
/// normally uses in a single invocation.
fn bazel_info() -> Result<std::collections::HashMap<String, String>> {
    let mut command = Command::new("bazel");
    command.arg("info");
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

/// Invoke `bazel aquery` for `label`, forwarding each `--config` value and
/// overriding the given environment variables `env` (as `(name, value)`
/// pairs) on top of the inherited environment, and decode the binary-proto
/// response into an [`ActionGraphContainer`].
///
/// Overriding `USER` matters here: it feeds both Bazel's output base and
/// its output-user (install) root, so a naive env override would send the
/// nested `bazel` to a *different* server than the project normally uses
/// and stall on the workspace lock. To keep using the same server, we first
/// discover the real `output_base` and `output_user_root` with the
/// unmodified environment and then pin them as startup flags, so only the
/// actions' environment changes.
///
/// `output_base` overrides that discovery, for a caller that would rather
/// say where the analysis goes than find out afterwards.
pub fn run_aquery(
    configs: &[String],
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

    // `bazel info` doesn't expose output_user_root, but it's simply the parent
    // of output_base (the `_bazel_$USER` directory), so derive it from there.
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

    // Override just the requested variables (the sentinel USER/HOSTNAME)
    // while otherwise inheriting Ahab's environment.
    for (name, value) in env {
        command.env(name, value);
    }

    if let Some(dir) = workspace_dir() {
        command.current_dir(dir);
    }

    for config in configs {
        command.arg(format!("--config={config}"));
    }

    // Ask for the action graph as a binary protobuf ActionGraphContainer.
    command.arg("--output=proto");

    // Long command lines are spilled into param files, and the proto's
    // `param_files` field is populated only when explicitly requested.
    // Without this the arguments of exactly the largest actions would be
    // invisible to the checks—see `crate::param_files`.
    command.arg("--include_param_files");

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sentinels_cannot_be_mistaken_for_each_other() {
        // The checks search with `contains`, so either being a substring
        // of the other would report one leak as two.
        assert!(!USER_SENTINEL.contains(HOSTNAME_SENTINEL));
        assert!(!HOSTNAME_SENTINEL.contains(USER_SENTINEL));
        assert_ne!(USER_SENTINEL, HOSTNAME_SENTINEL);
    }

    #[test]
    fn the_sentinels_are_findable_and_long_enough() {
        // Long and distinctive is what keeps them from occurring by
        // accident; `ahab` in the text is what lets someone who finds one
        // work out where it came from.
        for sentinel in [USER_SENTINEL, HOSTNAME_SENTINEL] {
            assert!(sentinel.starts_with("ahab-"), "{sentinel}");
            assert!(sentinel.len() >= 32, "{sentinel}");
        }
    }
}
