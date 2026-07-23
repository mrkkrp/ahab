//! Ahab — an advanced hermeticity analyzer for Bazel.
//!
//! Shell out to `bazel aquery` with a deliberately-controlled environment, ask
//! for the action graph in binary protobuf form, decode the resulting
//! `analysis.ActionGraphContainer`, and run a series of hermeticity checks over
//! the actions Bazel plans to execute.

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use clap::Parser;
use prost::Message;

// Generated Rust types for the vendored Bazel `analysis_v2.proto` come from the
// `//proto:analysis_v2_rs_proto` target, which rules_rust exposes as the
// `analysis_v2_proto` crate. `analysis_v2.proto` declares `package analysis;`,
// so its messages live under the `analysis` module of that crate.
pub use analysis_v2_proto::analysis::ActionGraphContainer;

/// The exact value of `PATH` that every action is required to use.
const EXPECTED_PATH: &str = "/bin:/usr/bin:/usr/local/bin";

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
    /// Run Ahab end to end: query the action graph under a controlled
    /// environment and run the hermeticity checks over it.
    pub fn run(&self) -> Result<()> {
        // Generate sentinel values for USER and HOSTNAME and hand them to the
        // aquery subprocess. If Bazel bakes the invoking user's identity into any
        // action, these sentinels — being what the environment actually holds —
        // are what would leak into the action graph.
        let user = random_token("ahab-user");
        let hostname = random_token("ahab-host");

        let env = [("USER", user.as_str()), ("HOSTNAME", hostname.as_str())];

        let container = run_aquery(&self.configs, &self.label, &env)?;

        check_environment_leaks(&container, &user, &hostname)?;
        check_path(&container)?;

        println!("All hermeticity checks passed.");
        Ok(())
    }
}

/// Generate a random alphanumeric token long enough to be extremely unlikely to
/// occur incidentally in an action's arguments or environment. No `rand`
/// dependency: we seed a small xorshift PRNG from the current time and the
/// process id, which is plenty for a leak sentinel.
fn random_token(prefix: &str) -> String {
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

/// Check that neither sentinel (the values we passed as USER and HOSTNAME)
/// leaks into any action's `arguments` or into the value of any of its
/// `environment_variables`. Aborts on the first leak found.
fn check_environment_leaks(
    container: &ActionGraphContainer,
    user: &str,
    hostname: &str,
) -> Result<()> {
    for action in &container.actions {
        let describe = |a: &analysis_v2_proto::analysis::Action| {
            if a.mnemonic.is_empty() {
                format!("action for target_id {}", a.target_id)
            } else {
                format!("{} action for target_id {}", a.mnemonic, a.target_id)
            }
        };

        for (sentinel, source) in [(user, "USER"), (hostname, "HOSTNAME")] {
            for arg in &action.arguments {
                if arg.contains(sentinel) {
                    bail!(
                        "hermeticity violation: {source} leaked into an argument of {} \
                         (found sentinel {sentinel:?} in argument {arg:?})",
                        describe(action),
                    );
                }
            }

            for kv in &action.environment_variables {
                if kv.value.contains(sentinel) {
                    bail!(
                        "hermeticity violation: {source} leaked into environment variable \
                         {key:?} of {} (found sentinel {sentinel:?} in value {value:?})",
                        describe(action),
                        key = kv.key,
                        value = kv.value,
                    );
                }
            }
        }
    }

    Ok(())
}

/// Check that every action which sets `PATH` sets it to exactly
/// [`EXPECTED_PATH`]. Aborts on the first deviation found.
fn check_path(container: &ActionGraphContainer) -> Result<()> {
    for action in &container.actions {
        for kv in &action.environment_variables {
            if kv.key == "PATH" && kv.value != EXPECTED_PATH {
                let target = if action.mnemonic.is_empty() {
                    format!("target_id {}", action.target_id)
                } else {
                    format!("{} action for target_id {}", action.mnemonic, action.target_id)
                };
                bail!(
                    "hermeticity violation: {target} sets PATH to {:?}, expected {:?}",
                    kv.value,
                    EXPECTED_PATH,
                );
            }
        }
    }

    Ok(())
}
