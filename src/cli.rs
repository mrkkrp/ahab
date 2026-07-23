//! Command-line interface and top-level orchestration for Ahab.

use anyhow::{bail, Result};
use clap::Parser;

use crate::aquery::{random_token, run_aquery};
use crate::checks::{check_environment_leaks, check_path, Violation};

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
    /// environment, run the pure hermeticity checks over it, and turn any
    /// violations into a non-zero exit.
    pub fn run(&self) -> Result<()> {
        // Generate sentinel values for USER and HOSTNAME and hand them to the
        // aquery subprocess. If Bazel bakes the invoking user's identity into any
        // action, these sentinels — being what the environment actually holds —
        // are what would leak into the action graph.
        let user = random_token("ahab-user");
        let hostname = random_token("ahab-host");

        let env = [("USER", user.as_str()), ("HOSTNAME", hostname.as_str())];

        let container = run_aquery(&self.configs, &self.label, &env)?;

        // The checks are pure: they return every violation they find. Collect
        // across all checks, then decide the exit status here.
        let mut violations = check_environment_leaks(&container, &user, &hostname);
        violations.extend(check_path(&container));

        if !violations.is_empty() {
            bail!("{}", report_violations(&violations));
        }

        println!("All hermeticity checks passed.");
        Ok(())
    }
}

/// Format one or more violations into a numbered, human-readable report. The
/// caller guarantees `violations` is non-empty.
fn report_violations(violations: &[Violation]) -> String {
    let count = violations.len();
    let noun = if count == 1 { "violation" } else { "violations" };

    // We collect every violation across all checks, so report them all as a
    // numbered list rather than stopping at the first.
    let mut report = format!("found {count} hermeticity {noun}:");
    for (i, v) in violations.iter().enumerate() {
        report.push_str(&format!("\n  {}. {}", i + 1, v.render()));
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::{ActionRef, Violation};

    fn bad_path(mnemonic: &str, target_id: u32, actual: &str) -> Violation {
        Violation::BadPath {
            action: ActionRef {
                mnemonic: mnemonic.to_owned(),
                target_id,
            },
            actual: actual.to_owned(),
        }
    }

    #[test]
    fn single_violation_uses_singular_noun_and_is_numbered() {
        let report = report_violations(&[bad_path("CppCompile", 1, "/bin")]);
        assert!(report.starts_with("found 1 hermeticity violation:\n"), "{report}");
        assert!(report.contains("\n  1. "), "{report}");
    }

    #[test]
    fn multiple_violations_are_pluralized_and_numbered() {
        let report = report_violations(&[
            bad_path("CppCompile", 1, "/bin"),
            bad_path("Genrule", 2, "/usr/bin"),
        ]);
        assert!(report.starts_with("found 2 hermeticity violations:\n"), "{report}");
        // Each violation appears on its own numbered line.
        assert!(report.contains("\n  1. "), "{report}");
        assert!(report.contains("\n  2. "), "{report}");
        assert_eq!(report.lines().count(), 3);
    }
}
