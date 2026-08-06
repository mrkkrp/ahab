//! Command-line interface and top-level orchestration for Ahab.

use anyhow::{bail, Result};
use clap::Parser;

use crate::aquery::{random_token, run_aquery};
use crate::checks::{check_all, Violation};
use crate::melville;

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
    #[arg(value_name = "LABEL")]
    pub label: String,

    /// Print every action we analyze (useful for debugging). Other parts of the
    /// parsed action graph are omitted, as the checks don't use them.
    #[arg(short, long)]
    pub verbose: bool,

    /// Suppress the Moby-Dick quote appended to the violation report.
    #[arg(long = "shut-up")]
    pub shut_up: bool,
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

        // For debugging, dump every action we're about to analyze. We print only
        // the actions; the other parts of the container aren't used by the checks.
        if self.verbose {
            println!("analyzing {} action(s):", container.actions.len());
            for (i, action) in container.actions.iter().enumerate() {
                println!("action {i}:\n{action:#?}");
            }
        }

        // The checks are pure: they return every violation they find, in a
        // deterministic order regardless of how Bazel ordered the actions.
        let violations = check_all(&container, &user, &hostname);

        if !violations.is_empty() {
            bail!("{}", report_violations(&violations, !self.shut_up));
        }

        println!("All hermeticity checks passed.");
        Ok(())
    }
}

/// Format one or more violations into a numbered, human-readable report. The
/// caller guarantees `violations` is non-empty. When `quote` is set, a Moby-Dick
/// line is appended as a sign-off; `--shut-up` clears it.
fn report_violations(violations: &[Violation], quote: bool) -> String {
    let count = violations.len();
    let noun = if count == 1 { "violation" } else { "violations" };

    // We collect every violation across all checks, so report them all as a
    // numbered list rather than stopping at the first.
    let mut report = format!("found {count} hermeticity {noun}:");
    for (i, v) in violations.iter().enumerate() {
        report.push_str(&format!("\n  {}. {}", i + 1, v.render()));
    }

    // Sign off with a displeased line from the novel, chosen deterministically
    // from the violations so the same problems always draw the same quote —
    // unless the caller asked us to keep quiet.
    if quote {
        report.push_str(&format!("\n\n  {}", melville::quote_for(&violations)));
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
                target: format!("//test:t{target_id}"),
            },
            actual: actual.to_owned(),
        }
    }

    #[test]
    fn single_violation_uses_singular_noun_and_is_numbered() {
        let report = report_violations(&[bad_path("CppCompile", 1, "/bin")], true);
        assert!(report.starts_with("found 1 hermeticity violation:\n"), "{report}");
        assert!(report.contains("\n  1. "), "{report}");
    }

    #[test]
    fn multiple_violations_are_pluralized_and_numbered() {
        let report = report_violations(
            &[
                bad_path("CppCompile", 1, "/bin"),
                bad_path("Genrule", 2, "/usr/bin"),
            ],
            true,
        );
        assert!(report.starts_with("found 2 hermeticity violations:\n"), "{report}");
        // Each violation appears on its own numbered line.
        assert!(report.contains("\n  1. "), "{report}");
        assert!(report.contains("\n  2. "), "{report}");
        // Header + two numbered lines + blank separator + Ahab quote.
        assert_eq!(report.lines().count(), 5);
    }

    #[test]
    fn report_ends_with_a_melville_quote() {
        let violations = [bad_path("CppCompile", 1, "/bin")];
        let report = report_violations(&violations, true);
        let quote = melville::quote_for(&&violations[..]);
        assert!(report.ends_with(&format!("\n\n  {quote}")), "{report}");
    }

    #[test]
    fn quote_is_stable_for_the_same_violations() {
        let violations = [bad_path("CppCompile", 1, "/bin")];
        assert_eq!(
            report_violations(&violations, true),
            report_violations(&violations, true)
        );
    }

    #[test]
    fn shut_up_suppresses_the_quote() {
        let violations = [bad_path("CppCompile", 1, "/bin")];
        let report = report_violations(&violations, false);
        // The violations are still reported...
        assert!(report.starts_with("found 1 hermeticity violation:\n"), "{report}");
        assert!(report.contains("\n  1. "), "{report}");
        // ...but no quote and no sign-off separator are appended.
        assert!(!report.contains("  — "), "{report}");
        let quote = melville::quote_for(&&violations[..]);
        assert!(!report.contains(quote), "{report}");
    }
}
