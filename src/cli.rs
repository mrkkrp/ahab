//! Command-line interface and top-level orchestration for Ahab.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Parser;
use serde::Serialize;

use crate::aquery::{random_token, run_aquery};

use crate::checks::{Violation, check_all};
use crate::melville;

/// Command-line interface for Ahab.
#[derive(Debug, Parser)]
#[command(
    name = "ahab",
    about = "Advanced hermeticity analyzer for Bazel",
    version
)]
pub struct Cli {
    /// A `--config=<name>` to forward to `bazel aquery`. May be repeated
    /// zero or more times; each value is passed through verbatim.
    #[arg(long = "config", value_name = "NAME")]
    pub configs: Vec<String>,

    /// The Bazel label or wildcard to query (e.g. `//foo:bar` or `//...`).
    #[arg(value_name = "LABEL")]
    pub label: String,

    /// Print every action we analyze (useful for debugging). Other parts of
    /// the parsed action graph are omitted, as the checks don't use them.
    #[arg(short, long)]
    pub verbose: bool,

    /// Suppress the Moby-Dick quote appended to the violation report.
    #[arg(long = "shut-up")]
    pub shut_up: bool,

    /// Write the violations to this file as JSON, while still printing the
    /// usual output on the screen.
    #[arg(long = "write-json", value_name = "FILENAME")]
    pub write_json: Option<PathBuf>,
}

impl Cli {
    /// Run Ahab end to end: query the action graph under a controlled
    /// environment, run the pure hermeticity checks over it, and turn any
    /// violations into a non-zero exit.
    pub fn run(&self) -> Result<()> {
        let user = random_token("ahab-user");
        let hostname = random_token("ahab-host");
        let env =
            [("USER", user.as_str()), ("HOSTNAME", hostname.as_str())];
        let container = run_aquery(&self.configs, &self.label, &env)?;

        // For debugging, dump every action we're about to analyze. We print
        // only the actions; the other parts of the container aren't used by
        // the checks.
        if self.verbose {
            println!("analyzing {} action(s):", container.actions.len());
            for (i, action) in container.actions.iter().enumerate() {
                println!("action {i}:\n{action:#?}");
            }
        }

        // The checks are pure: they return every violation they find, in a
        // deterministic order regardless of how Bazel ordered the actions.
        let violations = check_all(&container, &user, &hostname);

        if let Some(path) = &self.write_json {
            write_json(path, &violations)?;
        }

        if !violations.is_empty() {
            bail!("{}", report_violations(&violations, !self.shut_up));
        }

        println!("All hermeticity checks passed.");
        Ok(())
    }
}

/// One violation as it appears in the JSON report: the violation's own
/// fields, plus how many times it occurred.
#[derive(Debug, Serialize)]
struct CountedViolation<'a> {
    /// How many times this exact violation occurred.
    count: usize,
    /// The violation itself.
    violation: &'a Violation,
}

/// The whole JSON document.
///
/// An object with a named field rather than a bare array, so that later
/// additions—a schema version, the label queried, a summary—do not change
/// the type of the top-level value and break every consumer.
#[derive(Debug, Serialize)]
struct JsonReport<'a> {
    /// Distinct violations, in the same order as the printed report.
    violations: Vec<CountedViolation<'a>>,
}

/// Write `violations` to `path` as indented JSON, replacing any existing
/// file.
fn write_json(
    path: &Path,
    violations: &BTreeMap<Violation, usize>,
) -> Result<()> {
    let report = JsonReport {
        violations: violations
            .iter()
            .map(|(violation, count)| CountedViolation {
                count: *count,
                violation,
            })
            .collect(),
    };

    let mut json = serde_json::to_string_pretty(&report)
        .context("failed to serialize violations as JSON")?;
    json.push('\n');

    std::fs::write(path, json).with_context(|| {
        format!("failed to write JSON report to {}", path.display())
    })
}

/// Format one or more violations into a numbered, human-readable report.
/// The caller guarantees `violations` is non-empty.
fn report_violations(
    violations: &BTreeMap<Violation, usize>,
    quote: bool,
) -> String {
    let distinct = violations.len();
    let occurrences: usize = violations.values().sum();
    let noun = if distinct == 1 {
        "violation"
    } else {
        "violations"
    };

    let mut report = if distinct == occurrences {
        format!("found {distinct} hermeticity {noun}:")
    } else {
        format!(
            "found {distinct} distinct hermeticity {noun} ({occurrences} occurrences):"
        )
    };

    for (i, (violation, count)) in violations.iter().enumerate() {
        let multiplicity = if *count == 1 {
            String::new()
        } else {
            format!("×{count} ")
        };
        report.push_str(&format!(
            "\n  {}. {}{}",
            i + 1,
            multiplicity,
            violation.render()
        ));
    }

    if quote {
        report.push_str(&format!(
            "\n\n  {}",
            melville::quote_for(&violations)
        ));
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::{ActionRef, LeakSite, Violation};

    fn bad_path(mnemonic: &str, target_id: u32, actual: &str) -> Violation {
        Violation::BadPath {
            action: ActionRef {
                mnemonic: mnemonic.to_owned(),
                target: format!("//test:t{target_id}"),
            },
            actual: actual.to_owned(),
        }
    }

    /// A scratch file path, under the directory Bazel gives the test.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::var("TEST_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir());
        dir.join(name)
    }

    /// Write `violations` to a scratch file and parse it back.
    fn round_trip(
        name: &str,
        violations: &BTreeMap<Violation, usize>,
    ) -> serde_json::Value {
        let path = scratch(name);
        write_json(&path, violations).expect("write should succeed");
        let text =
            std::fs::read_to_string(&path).expect("file should exist");
        serde_json::from_str(&text).expect("output should be valid JSON")
    }

    #[test]
    fn json_report_carries_each_violation_with_its_count() {
        let violations: BTreeMap<Violation, usize> = [
            (bad_path("CppCompile", 1, "/bin"), 342),
            (bad_path("Genrule", 2, "/usr/bin"), 1),
        ]
        .into_iter()
        .collect();
        let json = round_trip("counts.json", &violations);

        let listed = json["violations"].as_array().unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0]["count"], 342);
        assert_eq!(listed[0]["violation"]["kind"], "bad_path");
        assert_eq!(listed[0]["violation"]["actual"], "/bin");
        assert_eq!(listed[1]["count"], 1);
    }

    #[test]
    fn a_leak_site_names_its_kind_without_repeating_the_field() {
        // The field is already `site`, so the tag inside says which kind of
        // location it is; `"site": {"site": ...}` reads as a mistake.
        let violations = once([Violation::AbsolutePath {
            action: ActionRef {
                mnemonic: "CppCompile".to_owned(),
                target: "//test:t1".to_owned(),
            },
            path: "/usr/include".to_owned(),
            site: LeakSite::Argument {
                value: "-I/usr/include".to_owned(),
            },
        }]);
        let json = round_trip("site.json", &violations);

        let site = &json["violations"][0]["violation"]["site"];
        assert_eq!(site["location"], "argument");
        assert_eq!(site["value"], "-I/usr/include");
        assert!(site.get("site").is_none(), "{site}");
    }

    #[test]
    fn json_report_preserves_the_order_of_the_printed_report() {
        // Same order as the text report, so the two can be read together
        // and a diff between runs means a real change.
        let violations = once([
            bad_path("Genrule", 2, "/usr/bin"),
            bad_path("CppCompile", 1, "/bin"),
        ]);
        let json = round_trip("order.json", &violations);

        let listed: Vec<&str> = json["violations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["violation"]["action"]["mnemonic"].as_str().unwrap())
            .collect();
        let printed = report_violations(&violations, false);
        assert_eq!(listed, ["CppCompile", "Genrule"]);
        assert!(
            printed.find("CppCompile").unwrap()
                < printed.find("Genrule").unwrap()
        );
    }

    #[test]
    fn json_report_is_written_even_when_nothing_was_found() {
        // A consumer must be able to tell "ran, found nothing" from "never
        // ran", so the file is written either way.
        let json = round_trip("empty.json", &BTreeMap::new());
        assert_eq!(json["violations"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn json_report_overwrites_an_existing_file() {
        let path = scratch("overwrite.json");
        std::fs::write(&path, "PREEXISTING GARBAGE").unwrap();
        write_json(&path, &BTreeMap::new()).expect("write should succeed");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("GARBAGE"), "{text}");
        assert!(text.starts_with('{'), "{text}");
    }

    #[test]
    fn json_report_is_indented_and_newline_terminated() {
        let violations = once([bad_path("CppCompile", 1, "/bin")]);
        let path = scratch("indent.json");
        write_json(&path, &violations).expect("write should succeed");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\n  \"violations\""), "{text}");
        assert!(text.ends_with('\n'), "{text:?}");
    }

    fn once<const N: usize>(
        violations: [Violation; N],
    ) -> BTreeMap<Violation, usize> {
        violations.into_iter().map(|v| (v, 1)).collect()
    }

    #[test]
    fn single_violation_uses_singular_noun_and_is_numbered() {
        let report = report_violations(
            &once([bad_path("CppCompile", 1, "/bin")]),
            true,
        );
        assert!(
            report.starts_with("found 1 hermeticity violation:\n"),
            "{report}"
        );
        assert!(report.contains("\n  1. "), "{report}");
    }

    #[test]
    fn multiple_violations_are_pluralized_and_numbered() {
        let report = report_violations(
            &once([
                bad_path("CppCompile", 1, "/bin"),
                bad_path("Genrule", 2, "/usr/bin"),
            ]),
            true,
        );
        assert!(
            report.starts_with("found 2 hermeticity violations:\n"),
            "{report}"
        );
        // Each violation appears on its own numbered line.
        assert!(report.contains("\n  1. "), "{report}");
        assert!(report.contains("\n  2. "), "{report}");
        // Header + two numbered lines + blank separator + Ahab quote.
        assert_eq!(report.lines().count(), 5);
    }

    #[test]
    fn a_violation_occurring_once_carries_no_multiplicity_marker() {
        let report = report_violations(
            &once([bad_path("CppCompile", 1, "/bin")]),
            false,
        );
        assert!(!report.contains('×'), "{report}");
        // With no repeats the occurrence count would only be noise.
        assert!(!report.contains("occurrences"), "{report}");
    }

    #[test]
    fn a_repeated_violation_is_listed_once_with_its_count() {
        let violations: BTreeMap<Violation, usize> =
            [(bad_path("CppCompile", 1, "/bin"), 342)]
                .into_iter()
                .collect();
        let report = report_violations(&violations, false);

        // One numbered line, carrying the multiplicity.
        assert!(
            report.starts_with("found 1 distinct hermeticity violation (342 occurrences):\n"),
            "{report}",
        );
        assert!(
            report.contains("\n  1. ×342 hermeticity violation:"),
            "{report}"
        );
        assert!(!report.contains("\n  2. "), "{report}");
    }

    #[test]
    fn the_header_totals_occurrences_across_distinct_violations() {
        let violations: BTreeMap<Violation, usize> = [
            (bad_path("CppCompile", 1, "/bin"), 3),
            (bad_path("Genrule", 2, "/usr/bin"), 4),
        ]
        .into_iter()
        .collect();
        let report = report_violations(&violations, false);
        assert!(
            report.starts_with(
                "found 2 distinct hermeticity violations (7 occurrences):\n"
            ),
            "{report}",
        );
    }

    #[test]
    fn report_ends_with_a_melville_quote() {
        let violations = once([bad_path("CppCompile", 1, "/bin")]);
        let report = report_violations(&violations, true);
        let quote = melville::quote_for(&violations);
        assert!(report.ends_with(&format!("\n\n  {quote}")), "{report}");
    }

    #[test]
    fn quote_is_stable_for_the_same_violations() {
        let violations = once([bad_path("CppCompile", 1, "/bin")]);
        assert_eq!(
            report_violations(&violations, true),
            report_violations(&violations, true)
        );
    }

    #[test]
    fn shut_up_suppresses_the_quote() {
        let violations = once([bad_path("CppCompile", 1, "/bin")]);
        let report = report_violations(&violations, false);
        // The violations are still reported...
        assert!(
            report.starts_with("found 1 hermeticity violation:\n"),
            "{report}"
        );
        assert!(report.contains("\n  1. "), "{report}");
        // ...but no quote and no sign-off separator are appended.
        assert!(!report.contains("  — "), "{report}");
        let quote = melville::quote_for(&violations);
        assert!(!report.contains(quote), "{report}");
    }
}
