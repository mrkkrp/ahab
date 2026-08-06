//! Talking to Bazel: run `bazel aquery` (and `bazel info`) under a
//! deliberately-controlled environment and decode the resulting action graph.

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use prost::Message;

use analysis_v2_proto::analysis::ActionGraphContainer;

/// Generate a random alphanumeric token long enough to be extremely unlikely to
/// occur incidentally in an action's arguments or environment. No `rand`
/// dependency: we seed a small xorshift PRNG from the current time and the
/// process id, which is plenty for a leak sentinel.
pub(crate) fn random_token(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut state = nanos ^ ((std::process::id() as u64) << 32) ^ 0x9e37_79b9_7f4a_7c15;

    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut token = String::from(prefix);
    token.push('-');
    for _ in 0..32 {
        // xorshift64
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        token.push(ALPHABET[(state % ALPHABET.len() as u64) as usize] as char);
    }
    token
}

/// The directory from which nested `bazel` invocations should run.
///
/// When Ahab is launched via `bazel run`, our working directory is the runfiles
/// tree *inside* the bazel output base, and a nested `bazel` refuses to run from
/// there. Bazel exports the original invocation directory so wrappers like this
/// can recover it; prefer BUILD_WORKING_DIRECTORY (where the user ran `bazel
/// run`), then BUILD_WORKSPACE_DIRECTORY (the workspace root). If neither is set
/// (Ahab wasn't launched by Bazel), inherit the current directory.
fn workspace_dir() -> Option<std::ffi::OsString> {
    std::env::var_os("BUILD_WORKING_DIRECTORY")
        .or_else(|| std::env::var_os("BUILD_WORKSPACE_DIRECTORY"))
}

/// Run `bazel info` (all keys) with the *unmodified* environment and parse its
/// `key: value` lines into a map, so we learn the paths the project normally
/// uses in a single invocation.
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
        bail!("`bazel info` exited with {}:\n{}", output.status, stderr.trim_end());
    }

    let stdout =
        String::from_utf8(output.stdout).context("`bazel info` produced non-UTF-8 output")?;
    let info = stdout
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
        .collect();
    Ok(info)
}

/// Invoke `bazel aquery` for `label`, forwarding each `--config` value and
/// overriding the given environment variables `env` (as `(name, value)` pairs)
/// on top of the inherited environment, and decode the binary-proto response
/// into an [`ActionGraphContainer`].
///
/// Overriding `USER` matters here: it feeds both Bazel's output base and its
/// output-user (install) root, so a naive env override would send the nested
/// `bazel` to a *different* server than the project normally uses and stall on
/// the workspace lock. To keep using the same server, we first discover the
/// real `output_base` and `output_user_root` with the unmodified environment and
/// then pin them as startup flags, so only the actions' environment changes.
pub fn run_aquery(
    configs: &[String],
    label: &str,
    env: &[(&str, &str)],
) -> Result<ActionGraphContainer> {
    let info = bazel_info()?;
    let output_base = info
        .get("output_base")
        .context("`bazel info` did not report an \"output_base\" key")?;

    // `bazel info` doesn't expose output_user_root, but it's simply the parent
    // of output_base (the `_bazel_$USER` directory), so derive it from there.
    let output_user_root = std::path::Path::new(output_base)
        .parent()
        .with_context(|| format!("output_base {output_base:?} has no parent directory"))?
        .to_str()
        .with_context(|| format!("output_base parent of {output_base:?} is not valid UTF-8"))?;

    let mut command = Command::new("bazel");

    // Startup flags (before the command) pin the server so the USER override
    // below can't move it.
    command.arg(format!("--output_base={output_base}"));
    command.arg(format!("--output_user_root={output_user_root}"));

    command.arg("aquery");

    // Override just the requested variables (the sentinel USER/HOSTNAME) while
    // otherwise inheriting Ahab's environment — the nested `bazel` still needs a
    // working PATH, HOME, etc. to run.
    for (name, value) in env {
        command.env(name, value);
    }

    if let Some(dir) = workspace_dir() {
        command.current_dir(dir);
    }

    // Forward each requested config.
    for config in configs {
        command.arg(format!("--config={config}"));
    }

    // Ask for the action graph as a binary protobuf ActionGraphContainer.
    command.arg("--output=proto");

    // Long command lines are spilled into param files, and the proto's
    // `param_files` field is populated only when explicitly requested. Without
    // this the arguments of exactly the largest actions would be invisible to
    // the checks — see `crate::param_files`.
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
    fn random_token_has_expected_shape() {
        let token = random_token("ahab-user");
        let prefix = "ahab-user-";
        assert!(token.starts_with(prefix), "{token}");
        // prefix + 32 random chars.
        assert_eq!(token.len(), prefix.len() + 32, "{token}");
        let suffix = &token[prefix.len()..];
        assert!(
            suffix.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
            "unexpected char in {suffix}"
        );
    }
}
