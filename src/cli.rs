//! Command-line interface and top-level orchestration for Ahab.

use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::Parser;
use serde::{Deserialize, Serialize};
use similar::TextDiff;

use crate::aquery::{random_token, run_aquery};

use crate::checks::{Violation, check_all};
use crate::melville;

/// Command-line interface for Ahab.
#[derive(Debug, Parser)]
#[command(
    name = "ahab",
    about = "Advanced hermeticity analyzer for Bazel",
    version,
    max_term_width = 76
)]
pub struct Cli {
    /// A `--config=<name>` to forward to `bazel aquery`. May be repeated
    /// zero or more times; each value is passed through verbatim.
    #[arg(long = "config", value_name = "NAME")]
    pub configs: Vec<String>,

    /// The Bazel label or wildcard to query (e.g. `//foo:bar` or `//...`).
    ///
    /// Not needed with `--explain-json`, which reads a saved report rather
    /// than querying Bazel.
    #[arg(value_name = "LABEL", required_unless_present = "explain_json")]
    pub label: Option<String>,

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

    /// Print the report from a JSON file written earlier by `--write-json`,
    /// instead of analyzing anything.
    ///
    /// Bazel is not consulted, so no label is needed and the other options
    /// are ignored—except `--shut-up`, which still suppresses the quote.
    #[arg(long = "explain-json", value_name = "FILENAME")]
    pub explain_json: Option<PathBuf>,

    /// Compare the violations found against a JSON file written earlier by
    /// `--write-json`, instead of printing them.
    ///
    /// Exits 0 and prints nothing when they match exactly, counts included.
    /// Otherwise prints a diff to stderr and exits 1.
    #[arg(long = "expect-json", value_name = "FILENAME")]
    pub expect_json: Option<PathBuf>,
}

impl Cli {
    /// Run Ahab end to end: query the action graph under a controlled
    /// environment, run the pure hermeticity checks over it, and turn any
    /// violations into a non-zero exit.
    pub fn run(&self) -> Result<ExitCode> {
        if let Some(path) = &self.explain_json {
            let path =
                resolve_output_path(path, invocation_dir().as_deref());
            self.report(&read_json(&path)?)?;
            return Ok(ExitCode::SUCCESS);
        }

        let user = random_token("ahab-user");
        let hostname = random_token("ahab-host");
        let env =
            [("USER", user.as_str()), ("HOSTNAME", hostname.as_str())];
        let label = self.label.as_deref().unwrap_or_default();
        let container = run_aquery(&self.configs, label, &env)?;

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
            let path =
                resolve_output_path(path, invocation_dir().as_deref());
            write_json(&path, &violations)?;
        }

        if let Some(path) = &self.expect_json {
            return self.expect(path, &violations);
        }

        self.report(&violations)?;
        Ok(ExitCode::SUCCESS)
    }

    /// Compare what we found against a saved report, printing a diff and
    /// failing when they differ.
    fn expect(
        &self,
        path: &Path,
        found: &BTreeMap<Violation, usize>,
    ) -> Result<ExitCode> {
        let path = resolve_output_path(path, invocation_dir().as_deref());
        let expected = read_json(&path)?;

        if *found == expected {
            return Ok(ExitCode::SUCCESS);
        }

        eprint!("{}", render_diff(&expected, found, use_color()));
        Ok(ExitCode::FAILURE)
    }

    /// Print a set of violations and turn a non-empty one into a non-zero
    /// exit.
    fn report(
        &self,
        violations: &BTreeMap<Violation, usize>,
    ) -> Result<()> {
        if !violations.is_empty() {
            bail!("{}", report_violations(violations, !self.shut_up));
        }

        println!("All hermeticity checks passed.");
        Ok(())
    }
}

/// The directory the user ran Ahab from, when Bazel told us.
///
/// Under `bazel run` the process starts in the runfiles tree inside the
/// output base, not where the command was typed. Bazel exports the real
/// invocation directory for exactly this reason.
fn invocation_dir() -> Option<PathBuf> {
    std::env::var_os("BUILD_WORKING_DIRECTORY").map(PathBuf::from)
}

/// Resolve a path the user gave us against the directory they gave it in.
fn resolve_output_path(path: &Path, base: Option<&Path>) -> PathBuf {
    match base {
        Some(base) if path.is_relative() => base.join(path),
        _ => path.to_path_buf(),
    }
}

/// One violation as it appears in the JSON report: the violation's own
/// fields, plus how many times it occurred.
#[derive(Debug, Serialize, Deserialize)]
struct CountedViolation {
    /// How many times this exact violation occurred.
    count: usize,
    /// The violation itself.
    violation: Violation,
}

/// The whole JSON document.
///
/// An object with a named field rather than a bare array, so that later
/// additions—a schema version, the label queried, a summary—do not change
/// the type of the top-level value and break every consumer.
#[derive(Debug, Serialize, Deserialize)]
struct JsonReport {
    /// Distinct violations, in the same order as the printed report.
    violations: Vec<CountedViolation>,
}

/// Read a report written earlier by [`write_json`].
fn read_json(path: &Path) -> Result<BTreeMap<Violation, usize>> {
    let text = std::fs::read_to_string(path).with_context(|| {
        format!("failed to read JSON report from {}", path.display())
    })?;
    let report: JsonReport =
        serde_json::from_str(&text).with_context(|| {
            format!("{} is not a report Ahab wrote", path.display())
        })?;

    let mut violations = BTreeMap::new();
    for counted in report.violations {
        // Summed rather than overwritten: a hand-edited file listing the
        // same violation twice should report the total, not the last one.
        *violations.entry(counted.violation).or_insert(0) += counted.count;
    }
    Ok(violations)
}

impl JsonReport {
    /// Build the document for a set of violations, preserving their order.
    fn of(violations: &BTreeMap<Violation, usize>) -> JsonReport {
        JsonReport {
            violations: violations
                .iter()
                .map(|(violation, count)| CountedViolation {
                    count: *count,
                    violation: violation.clone(),
                })
                .collect(),
        }
    }
}

/// Write `violations` to `path` as indented JSON, replacing any existing
/// file.
fn write_json(
    path: &Path,
    violations: &BTreeMap<Violation, usize>,
) -> Result<()> {
    let mut json =
        serde_json::to_string_pretty(&JsonReport::of(violations))
            .context("failed to serialize violations as JSON")?;
    json.push('\n');

    std::fs::write(path, json).with_context(|| {
        format!("failed to write JSON report to {}", path.display())
    })
}

/// Whether to colorize the diff.
///
/// Colour only when stderr is a terminal, so a redirected or piped diff
/// stays plain text; and never when `NO_COLOR` is set, which is the
/// convention for turning it off regardless.
fn use_color() -> bool {
    std::env::var_os("NO_COLOR").is_none()
        && std::io::stderr().is_terminal()
}

/// A diff between the violations expected and the violations found.
fn render_diff(
    expected: &BTreeMap<Violation, usize>,
    found: &BTreeMap<Violation, usize>,
    color: bool,
) -> String {
    const RED: &str = "\x1b[31m";
    const GREEN: &str = "\x1b[32m";
    const CYAN: &str = "\x1b[36m";
    const RESET: &str = "\x1b[0m";

    let render = |violations: &BTreeMap<Violation, usize>| {
        serde_json::to_string_pretty(&JsonReport::of(violations))
            .unwrap_or_else(|_| String::from("<unserializable>"))
    };
    let (expected, found) = (render(expected), render(found));

    let diff = TextDiff::from_lines(&expected, &found);
    let unified = diff.unified_diff().context_radius(3).to_string();

    if !color {
        return unified;
    }

    // Every line of a unified diff is prefixed by its marker, so the first
    // character is all that has to be looked at.
    let mut colored = String::with_capacity(unified.len());
    for line in unified.lines() {
        let tint = match line.chars().next() {
            Some('-') => RED,
            Some('+') => GREEN,
            Some('@') => CYAN,
            _ => "",
        };
        if tint.is_empty() {
            colored.push_str(line);
        } else {
            colored.push_str(&format!("{tint}{line}{RESET}"));
        }
        colored.push('\n');
    }
    colored
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
    use crate::checks::{ActionRef, EnvSource, LeakSite, Violation};
    use crate::reproducibility_spec::program_id::ProgramId;

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
    fn a_relative_output_path_lands_where_the_user_ran_ahab() {
        // Under `bazel run` the working directory is the runfiles tree, so
        // a relative path would otherwise be written somewhere nobody looks.
        assert_eq!(
            resolve_output_path(
                Path::new("out.json"),
                Some(Path::new("/home/mark/project")),
            ),
            PathBuf::from("/home/mark/project/out.json"),
        );
    }

    #[test]
    fn an_absolute_output_path_is_left_alone() {
        assert_eq!(
            resolve_output_path(
                Path::new("/tmp/out.json"),
                Some(Path::new("/home/mark/project")),
            ),
            PathBuf::from("/tmp/out.json"),
        );
    }

    #[test]
    fn without_an_invocation_directory_the_path_is_used_as_given() {
        // Not launched by `bazel run`, so the working directory is already
        // the user's own and resolving against anything would be wrong.
        assert_eq!(
            resolve_output_path(Path::new("out.json"), None),
            PathBuf::from("out.json"),
        );
    }

    /// The changed lines of `diff` carrying this sign, joined. Hunk headers
    /// (`---`, `+++`) are skipped: they start with the same characters but
    /// are not content.
    fn signed(diff: &str, sign: char) -> String {
        let header: String = std::iter::repeat_n(sign, 3).collect();
        diff.lines()
            .filter(|line| {
                line.starts_with(sign) && !line.starts_with(&header)
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The diff between two sets of violations, uncoloured.
    fn diff(
        expected: &BTreeMap<Violation, usize>,
        found: &BTreeMap<Violation, usize>,
    ) -> String {
        render_diff(expected, found, false)
    }

    #[test]
    fn identical_violations_produce_no_diff() {
        let violations = once([bad_path("CppCompile", 1, "/bin")]);
        assert_eq!(diff(&violations, &violations), "");
    }

    #[test]
    fn a_violation_only_found_is_added_and_only_expected_is_removed() {
        let expected = once([bad_path("A", 1, "/expected-only")]);
        let found = once([bad_path("B", 2, "/found-only")]);
        let d = diff(&expected, &found);
        assert!(signed(&d, '-').contains("/expected-only"), "{d}");
        assert!(signed(&d, '+').contains("/found-only"), "{d}");
        assert!(!signed(&d, '+').contains("/expected-only"), "{d}");
    }

    #[test]
    fn a_changed_count_shows_both_sides() {
        // The reason counts are compared at all: the same violation on one
        // action and on three is not the same result.
        let violation = bad_path("CppCompile", 1, "/bin");
        let expected: BTreeMap<Violation, usize> =
            [(violation.clone(), 3)].into_iter().collect();
        let found: BTreeMap<Violation, usize> =
            [(violation, 5)].into_iter().collect();
        let d = diff(&expected, &found);
        assert!(signed(&d, '-').contains("\"count\": 3"), "{d}");
        assert!(signed(&d, '+').contains("\"count\": 5"), "{d}");
        // Only the count line changed, so the violation itself is context.
        assert!(!signed(&d, '-').contains("bad_path"), "{d}");
    }

    #[test]
    fn unchanged_violations_are_left_out_of_the_diff() {
        let same = bad_path("A", 1, "/same");
        let expected: BTreeMap<Violation, usize> =
            [(same.clone(), 1)].into_iter().collect();
        let mut found = expected.clone();
        found.insert(bad_path("B", 2, "/new"), 1);

        let d = diff(&expected, &found);
        assert!(signed(&d, '+').contains("/new"), "{d}");
        // The unchanged one may appear as context, but never as a change.
        assert!(!signed(&d, '+').contains("/same"), "{d}");
        assert!(!signed(&d, '-').contains("/same"), "{d}");
    }

    #[test]
    fn the_diff_is_plain_text_unless_colour_is_asked_for() {
        let expected = once([bad_path("A", 1, "/a")]);
        let found = once([bad_path("B", 2, "/b")]);

        let plain = render_diff(&expected, &found, false);
        assert!(!plain.contains('\x1b'), "{plain:?}");

        let coloured = render_diff(&expected, &found, true);
        assert!(coloured.contains("\x1b[31m-"), "{coloured:?}");
        assert!(coloured.contains("\x1b[32m+"), "{coloured:?}");
        // Every tinted line resets, so the terminal is not left coloured.
        for line in coloured.lines() {
            let tinted = line.starts_with('\x1b');
            assert_eq!(tinted, line.ends_with("\x1b[0m"), "{line:?}");
        }
    }

    #[test]
    fn the_diff_is_the_same_bytes_every_time() {
        // Both documents are serialized in the report's own order, so the
        // diff of a given difference is reproducible—without which a diff
        // between two runs would be worthless.
        let expected = once([
            bad_path("Genrule", 2, "/b"),
            bad_path("CppCompile", 1, "/a"),
        ]);
        let found = once([bad_path("CppCompile", 1, "/a")]);
        assert_eq!(diff(&expected, &found), diff(&expected, &found));
        assert!(signed(&diff(&expected, &found), '-').contains("/b"));
    }

    #[test]
    fn one_changed_field_diffs_as_one_line() {
        // The reason this is a line diff and not an entry diff: an entry-wise
        // comparison keys on the whole violation, so any edit deletes and
        // re-inserts the lot—60 lines of noise for a one-word change.
        let program = |module: &str| Violation::UnknownProgram {
            action: ActionRef {
                mnemonic: "Rustc".to_owned(),
                target: "//test:t1".to_owned(),
            },
            program: ProgramId::module(module, "bin/tool"),
            wrappers: Vec::new(),
        };
        let d = diff(
            &once([program("rules_haskell")]),
            &once([program("rules_rust")]),
        );

        assert_eq!(signed(&d, '-').lines().count(), 1, "{d}");
        assert_eq!(signed(&d, '+').lines().count(), 1, "{d}");
        assert!(signed(&d, '-').contains("rules_haskell"), "{d}");
        assert!(signed(&d, '+').contains("rules_rust"), "{d}");
    }

    #[test]
    fn a_written_report_reads_back_unchanged() {
        // The property `--explain-json` rests on: what comes back is the
        // same value that was written, so it renders identically.
        let violations: BTreeMap<Violation, usize> = [
            (bad_path("CppCompile", 1, "/bin"), 342),
            (
                Violation::AbsolutePath {
                    action: ActionRef {
                        mnemonic: String::new(),
                        target: "//test:t2".to_owned(),
                    },
                    path: "/usr/include".to_owned(),
                    site: LeakSite::ParamFile {
                        exec_path: "out/foo.params".to_owned(),
                        // Quotes and newlines: the round trip has to
                        // survive the arguments real actions carry.
                        value: "-I/usr/include -D__X__=\"y\"\nnext"
                            .to_owned(),
                    },
                },
                7,
            ),
        ]
        .into_iter()
        .collect();

        let path = scratch("roundtrip.json");
        write_json(&path, &violations).expect("write should succeed");
        let read = read_json(&path).expect("read should succeed");

        assert_eq!(read, violations);
        assert_eq!(
            report_violations(&read, false),
            report_violations(&violations, false),
        );
    }

    #[test]
    fn every_violation_kind_survives_the_round_trip() {
        // Each variant is tagged separately, so each can break separately.
        let program = ProgramId::of("external/llvm+/bin/clang");
        let wrappers = vec![ProgramId::module(
            "rules_rust",
            "util/process_wrapper/pw",
        )];
        let action = ActionRef {
            mnemonic: "A".to_owned(),
            target: "//test:t1".to_owned(),
        };
        let violations = once([
            Violation::EnvironmentLeak {
                action: action.clone(),
                source: EnvSource::Hostname,
                sentinel: "s".to_owned(),
                site: LeakSite::EnvVar {
                    key: "K".to_owned(),
                    value: "v".to_owned(),
                },
            },
            bad_path("A", 1, "/bin"),
            Violation::AbsolutePath {
                action: action.clone(),
                path: "/x".to_owned(),
                site: LeakSite::Argument {
                    value: "-I/x".to_owned(),
                },
            },
            Violation::SystemProgram {
                action: action.clone(),
                program: ProgramId::of("/bin/bash"),
                wrappers: Vec::new(),
            },
            Violation::UnknownProgram {
                action: action.clone(),
                program: program.clone(),
                wrappers: wrappers.clone(),
            },
            Violation::NeverReproducible {
                action: action.clone(),
                program: program.clone(),
                wrappers: wrappers.clone(),
                synonym: Some(ProgramId::module("m", "bin/other")),
            },
            Violation::ConditionalReproducibility {
                action,
                program,
                wrappers,
                synonym: None,
                missing_required: vec!["--deterministic".to_owned()],
                present_breaking: vec!["--timestamp".to_owned()],
            },
        ]);

        let path = scratch("kinds.json");
        write_json(&path, &violations).expect("write should succeed");
        assert_eq!(
            read_json(&path).expect("read should succeed"),
            violations
        );
    }

    #[test]
    fn reading_a_file_that_is_not_a_report_says_so() {
        let path = scratch("garbage.json");
        std::fs::write(&path, "{\"something\": 1}").unwrap();
        let message = read_json(&path).unwrap_err().to_string();
        assert!(
            message.contains("is not a report Ahab wrote"),
            "{message}"
        );
    }

    #[test]
    fn reading_a_missing_file_names_it() {
        let path = scratch("does-not-exist.json");
        let _ = std::fs::remove_file(&path);
        let message = read_json(&path).unwrap_err().to_string();
        assert!(
            message.contains("failed to read JSON report"),
            "{message}"
        );
        assert!(message.contains("does-not-exist.json"), "{message}");
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
