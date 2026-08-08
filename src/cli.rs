//! Command-line interface and top-level orchestration for Ahab.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::Parser;
use serde::{Deserialize, Serialize};
use similar::TextDiff;

use crate::aquery::{random_token, run_aquery};

use crate::checks::{Violation, check_all};
use crate::exceptions::{
    Exception, Exceptions, Suppressed, parse_exceptions, stale_warning,
};
use crate::melville;
use crate::reproducibility_spec::library::{Entry, Library, parse_entries};
use crate::reproducibility_spec::program_id::ProgramId;
use crate::terminal_color::Palette;

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

    /// Report the violations as usual, but exit 0 even when there are some.
    ///
    /// For recording rather than judging: writing a baseline with
    /// `--write-json` is not a failure just because the build it describes
    /// has violations in it. Refused together with `--expect-json`, whose
    /// entire purpose is the exit code.
    #[arg(long = "no-fail", conflicts_with = "expect_json")]
    pub no_fail: bool,

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

    /// Load additional reproducibility specs from a JSON file. May be
    /// repeated.
    ///
    /// These take precedence over Ahab's built-in knowledge, so a project
    /// can describe its own tools and correct what Ahab believes about
    /// anyone else's. A file given later overrides one given earlier.
    #[arg(long = "repro-specs", value_name = "FILENAME")]
    pub repro_specs: Vec<PathBuf>,

    /// Load exceptions from a JSON file, filtering out the violations they
    /// excuse. May be repeated.
    #[arg(long = "exceptions-json", value_name = "FILENAME")]
    pub exceptions_json: Vec<PathBuf>,
}

impl Cli {
    /// Run Ahab end to end: query the action graph under a controlled
    /// environment, run the pure hermeticity checks over it, and turn any
    /// violations into a non-zero exit.
    pub fn run(&self) -> Result<ExitCode> {
        if let Some(path) = &self.explain_json {
            let path = resolve_against_invocation_dir(path);
            self.report(&read_json(&path)?, Suppressed::default())?;
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
        let mut library = Library::builtin();
        for path in &self.repro_specs {
            let path = resolve_against_invocation_dir(path);
            library.extend(read_specs(&path)?);
        }

        let violations = check_all(&container, &user, &hostname, &library);

        let mut exceptions = Vec::new();
        for path in &self.exceptions_json {
            let path = resolve_against_invocation_dir(path);
            exceptions.extend(read_exceptions(&path)?);
        }
        let filtered = Exceptions::new(exceptions).filter(violations);

        if let Some(warning) = stale_warning(&filtered.unused) {
            eprintln!("{warning}");
        }

        let violations = filtered.kept;

        if let Some(path) = &self.write_json {
            let path = resolve_against_invocation_dir(path);
            write_json(&path, &violations)?;
        }

        if let Some(path) = &self.expect_json {
            return self.expect(path, &violations);
        }

        self.report(&violations, filtered.suppressed)?;
        Ok(ExitCode::SUCCESS)
    }

    /// Compare what we found against a saved report, printing a diff and
    /// failing when they differ.
    fn expect(
        &self,
        path: &Path,
        found: &BTreeMap<Violation, usize>,
    ) -> Result<ExitCode> {
        let path = resolve_against_invocation_dir(path);
        let expected = read_json(&path)?;

        if *found == expected {
            return Ok(ExitCode::SUCCESS);
        }

        eprint!("{}", render_diff(&expected, found, Palette::for_stderr()));
        Ok(ExitCode::FAILURE)
    }

    /// Print a set of violations and turn a non-empty one into a non-zero
    /// exit.
    fn report(
        &self,
        violations: &BTreeMap<Violation, usize>,
        suppressed: Suppressed,
    ) -> Result<()> {
        if !violations.is_empty() {
            let report = report_violations(
                violations,
                suppressed,
                !self.shut_up,
                Palette::for_stderr(),
            );
            if self.no_fail {
                eprintln!("{report}");
                return Ok(());
            }
            bail!("{report}");
        }

        let palette = Palette::for_stdout();
        let mut passed = "All hermeticity checks passed.".to_owned();
        if !suppressed.is_empty() {
            passed.push_str(&format!(
                "\n  {}",
                palette.faint(&{ suppressed.note() })
            ));
        }
        println!("{passed}");
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

/// Resolve a path the user gave us against the directory they typed it in.
fn resolve_output_path(path: &Path, base: Option<&Path>) -> PathBuf {
    match base {
        Some(base) if path.is_relative() => base.join(path),
        _ => path.to_path_buf(),
    }
}

/// A path as the user gave it, resolved against the invocation directory.
fn resolve_against_invocation_dir(path: &Path) -> PathBuf {
    resolve_output_path(path, invocation_dir().as_deref())
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

/// Read user-defined library entries from `path`.
fn read_specs(path: &Path) -> Result<Vec<(ProgramId, Entry)>> {
    let text = std::fs::read_to_string(path).with_context(|| {
        format!("failed to read specs from {}", path.display())
    })?;
    parse_entries(&text)
        .map_err(|why| anyhow::anyhow!("{}: {why}", path.display()))
}

/// Read exceptions from `path`.
fn read_exceptions(path: &Path) -> Result<Vec<Exception>> {
    let text = std::fs::read_to_string(path).with_context(|| {
        format!("failed to read exceptions from {}", path.display())
    })?;
    let origin = path.file_name().map_or_else(
        || path.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    );
    parse_exceptions(&text, &origin)
        .map_err(|why| anyhow::anyhow!("{}: {why}", path.display()))
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

/// A diff between the violations expected and the violations found.
fn render_diff(
    expected: &BTreeMap<Violation, usize>,
    found: &BTreeMap<Violation, usize>,
    palette: Palette,
) -> String {
    let render = |violations: &BTreeMap<Violation, usize>| {
        serde_json::to_string_pretty(&JsonReport::of(violations))
            .unwrap_or_else(|_| String::from("<unserializable>"))
    };
    let (expected, found) = (render(expected), render(found));

    let diff = TextDiff::from_lines(&expected, &found);
    let unified = diff.unified_diff().context_radius(3).to_string();

    let mut colored = String::with_capacity(unified.len());
    for line in unified.lines() {
        colored.push_str(&palette.diff_line(line));
        colored.push('\n');
    }
    colored
}

/// Format one or more violations into a numbered, human-readable report.
/// The caller guarantees `violations` is non-empty.
fn report_violations(
    violations: &BTreeMap<Violation, usize>,
    suppressed: Suppressed,
    quote: bool,
    palette: Palette,
) -> String {
    let distinct = violations.len();
    let occurrences: usize = violations.values().sum();
    let noun = if distinct == 1 {
        "violation"
    } else {
        "violations"
    };

    let heading = if distinct == occurrences {
        format!("found {distinct} hermeticity {noun}:")
    } else {
        format!(
            "found {distinct} distinct hermeticity {noun} ({occurrences} occurrences):"
        )
    };
    let mut report = palette.heading(&heading);

    for (i, (violation, count)) in violations.iter().enumerate() {
        // The number is framing, so it recedes; the multiplicity is a
        // quantity worth noticing, so it does not.
        let number = palette.faint(&format!("{}.", i + 1));
        let multiplicity = if *count == 1 {
            String::new()
        } else {
            palette.caution(&format!("×{count}")) + " "
        };
        report.push_str(&format!(
            "\n  {number} {multiplicity}{}",
            violation.render(palette)
        ));
    }

    if !suppressed.is_empty() {
        report.push_str(&format!(
            "\n  {}",
            palette.faint(&suppressed.note())
        ));
    }

    if quote {
        report.push_str(&format!(
            "\n\n  {}",
            palette.faint(melville::quote_for(&violations))
        ));
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::{ActionRef, EnvSource, LeakSite, Violation};
    use crate::reproducibility_spec::Reproducibility;
    use crate::reproducibility_spec::library::Transition;
    use crate::reproducibility_spec::program_id::ProgramId;

    fn report_violations(
        violations: &BTreeMap<Violation, usize>,
        quote: bool,
        palette: Palette,
    ) -> String {
        super::report_violations(
            violations,
            Suppressed::default(),
            quote,
            palette,
        )
    }

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

    /// The diff between two sets of violations, uncolored.
    fn diff(
        expected: &BTreeMap<Violation, usize>,
        found: &BTreeMap<Violation, usize>,
    ) -> String {
        render_diff(expected, found, Palette::plain())
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
    fn the_diff_is_plain_text_unless_color_is_asked_for() {
        let expected = once([bad_path("A", 1, "/a")]);
        let found = once([bad_path("B", 2, "/b")]);

        let plain = render_diff(&expected, &found, Palette::plain());
        assert!(!plain.contains('\x1b'), "{plain:?}");

        let colored = render_diff(&expected, &found, Palette::color());
        assert!(colored.contains("\x1b[31m-"), "{colored:?}");
        assert!(colored.contains("\x1b[32m+"), "{colored:?}");
        // Every tinted line resets, so the terminal is not left colored.
        for line in colored.lines() {
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

    /// Write `text` to a scratch file and read library entries from it.
    fn specs_from(
        name: &str,
        text: &str,
    ) -> Result<Vec<(ProgramId, Entry)>> {
        let path = scratch(name);
        std::fs::write(&path, text).unwrap();
        read_specs(&path)
    }

    #[test]
    fn a_file_names_programs_the_way_a_report_does() {
        let specs = specs_from(
            "specs.json",
            r#"{"programs": {
                 "@rules_rust//util/pw": {
                   "spec": {
                     "reproducibility": "sometimes",
                     "required_flags": ["--deterministic"],
                     "breaking_flags": ["-O"],
                     "recognize": {"-O2": "-O"}
                   }
                 }
               }}"#,
        )
        .expect("should load");

        assert_eq!(specs.len(), 1);
        let (program, entry) = &specs[0];
        assert_eq!(*program, ProgramId::module("rules_rust", "util/pw"));
        let Entry::Spec(spec) = entry else {
            panic!("expected a spec, got {entry:?}");
        };
        assert_eq!(spec.reproducibility, Reproducibility::Sometimes);
        assert!(spec.required_flags.contains("--deterministic"));
        assert_eq!(spec.recognize("-O2"), Some("-O".to_owned()));
    }

    #[test]
    fn a_file_can_declare_a_synonym() {
        let specs = specs_from(
            "synonym.json",
            r#"{"programs": {
                 "@llvm+t//bin/clang++": {"same_as": "@llvm+t//bin/clang"}
               }}"#,
        )
        .expect("should load");

        assert_eq!(
            specs[0].1,
            Entry::SameAs(ProgramId::extension("llvm", "t", "bin/clang")),
        );
    }

    #[test]
    fn a_file_can_declare_a_wrapper() {
        let specs = specs_from(
            "wrapper.json",
            r#"{"programs": {
                 "@my_rules//tools/wrap": {
                   "wraps": {"after_separator": "--"}
                 }
               }}"#,
        )
        .expect("should load");

        let Entry::Wraps(transition) = &specs[0].1 else {
            panic!("expected a wrapper, got {:?}", specs[0].1);
        };
        assert_eq!(
            *transition,
            Transition::AfterSeparator {
                separator: "--".to_owned(),
            },
        );
    }

    #[test]
    fn a_user_declared_wrapper_unwraps_like_a_built_in_one() {
        // The point of letting a file say this: a project's own wrapper is
        // invisible to Ahab until someone can describe it.
        let mut library = Library::default();
        library.extend(
            specs_from(
                "unwrap.json",
                r#"{"programs": {
                     "@my_rules//tools/wrap": {
                       "wraps": {"after_separator": "--"}
                     },
                     "@llvm+t//bin/clang": {
                       "spec": {"reproducibility": "never"}
                     }
                   }}"#,
            )
            .expect("should load"),
        );

        let resolved = library.resolve(
            ProgramId::module("my_rules", "tools/wrap"),
            vec!["--quiet", "--", "external/llvm++t+r/bin/clang", "-c"],
        );
        assert_eq!(
            resolved.program,
            ProgramId::extension("llvm", "t", "bin/clang"),
        );
        assert_eq!(resolved.args, vec!["-c"]);
        assert_eq!(
            resolved.wrappers,
            vec![ProgramId::module("my_rules", "tools/wrap")],
        );
        assert!(resolved.spec.is_some());
    }

    #[test]
    fn the_flag_sets_and_translations_may_be_left_out() {
        let specs = specs_from(
            "minimal.json",
            r#"{"programs": {
                 "//tools/gen": {"spec": {"reproducibility": "never"}}
               }}"#,
        )
        .expect("should load");

        let Entry::Spec(spec) = &specs[0].1 else {
            panic!("expected a spec");
        };
        assert!(spec.required_flags.is_empty());
        assert!(spec.breaking_flags.is_empty());
        // No translations means every argument stands for itself.
        assert_eq!(
            spec.recognize("--anything"),
            Some("--anything".to_owned())
        );
    }

    #[test]
    fn a_user_entry_takes_precedence_over_a_built_in_one() {
        // The built-in library treats process_wrapper as a wrapper; a
        // project may know better about its own build.
        let pw = ProgramId::module(
            "rules_rust",
            "util/process_wrapper/process_wrapper",
        );
        let mut library = Library::builtin();
        assert!(
            library.resolve(pw.clone(), vec!["--", "x"]).program != pw,
            "the built-in entry should unwrap",
        );

        library.extend(
            specs_from(
                "override.json",
                r#"{"programs": {
                     "@rules_rust//util/process_wrapper/process_wrapper": {
                       "spec": {"reproducibility": "always"}
                     }
                   }}"#,
            )
            .expect("should load"),
        );

        let resolved = library.resolve(pw.clone(), vec!["--", "x"]);
        assert_eq!(resolved.program, pw, "the user entry should win");
        assert!(resolved.spec.is_some());
        assert!(resolved.wrappers.is_empty());
    }

    #[test]
    fn a_later_file_overrides_an_earlier_one() {
        let mut library = Library::default();
        for (name, disposition) in
            [("first.json", "never"), ("second.json", "always")]
        {
            let text = format!(
                r#"{{"programs": {{"//t": {{"spec": {{"reproducibility": "{disposition}"}}}}}}}}"#
            );
            library.extend(specs_from(name, &text).expect("should load"));
        }

        let resolved = library.resolve(ProgramId::main("t"), vec![]);
        let (_, spec) = resolved.spec.expect("should have a spec");
        assert_eq!(spec.reproducibility, Reproducibility::Always);
    }

    #[test]
    fn a_bad_program_name_says_which_file_and_which_program() {
        let message = specs_from(
            "bad-program.json",
            r#"{"programs": {"@rules_rust": {"spec":
                 {"reproducibility": "never"}}}}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(message.contains("bad-program.json"), "{message}");
        assert!(message.contains("@rules_rust"), "{message}");
        assert!(message.contains("names a repository"), "{message}");
    }

    #[test]
    fn a_bad_synonym_target_says_which_program_declared_it() {
        let message = specs_from(
            "bad-synonym.json",
            r#"{"programs": {"//a": {"same_as": "@nope"}}}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(message.contains("//a: same_as"), "{message}");
    }

    #[test]
    fn a_file_that_is_not_a_spec_file_says_so() {
        let message = specs_from("not-specs.json", r#"{"violations": []}"#)
            .unwrap_err()
            .to_string();
        assert!(message.contains("not-specs.json"), "{message}");
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
            report_violations(&read, false, Palette::plain()),
            report_violations(&violations, false, Palette::plain()),
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
        let printed =
            report_violations(&violations, false, Palette::plain());
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
            Palette::plain(),
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
            Palette::plain(),
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
    fn the_report_is_plain_text_unless_color_is_asked_for() {
        let violations: BTreeMap<Violation, usize> =
            [(bad_path("CppCompile", 1, "/bin"), 3)]
                .into_iter()
                .collect();

        let plain = report_violations(&violations, false, Palette::plain());
        assert!(!plain.contains('\x1b'), "{plain:?}");

        let colored =
            report_violations(&violations, false, Palette::color());
        assert!(colored.contains('\x1b'), "{colored:?}");
        // Stripping the escapes gets the plain report back, so color adds
        // nothing to what the text says.
        assert_eq!(strip_ansi(&colored), plain);
    }

    #[test]
    fn color_marks_the_kind_the_action_and_the_finding() {
        let violations = once([Violation::UnknownProgram {
            action: ActionRef {
                mnemonic: "Rustc".to_owned(),
                target: "//test:t1".to_owned(),
            },
            program: ProgramId::module("rules_rust", "bin/tool"),
            wrappers: Vec::new(),
        }]);
        let r = report_violations(&violations, false, Palette::color());
        // Caution for a finding Ahab cannot vouch for either way, cyan for
        // whose action it is, bold for the program itself.
        // The kind opens the line, so it carries no color of its own.
        assert!(r.contains("reproducibility unknown"), "{r}");
        assert!(!r.contains("\x1b[33mreproducibility"), "{r}");
        assert!(r.contains("\x1b[35mRustc action for target"), "{r}");
        assert!(
            r.contains("\x1b[36m\"@rules_rust//bin/tool\"\x1b[0m"),
            "{r}"
        );
        // Bold means heading and nothing else, so it must not appear on a
        // finding.
        assert!(!r.contains("\x1b[1m\"@rules_rust//bin/tool\""), "{r}");
    }

    /// Remove ANSI escapes, to compare colored output against plain.
    fn strip_ansi(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut chars = text.chars();
        while let Some(c) = chars.next() {
            if c != '\x1b' {
                out.push(c);
                continue;
            }
            for c in chars.by_ref() {
                if c == 'm' {
                    break;
                }
            }
        }
        out
    }

    #[test]
    fn a_violation_occurring_once_carries_no_multiplicity_marker() {
        let report = report_violations(
            &once([bad_path("CppCompile", 1, "/bin")]),
            false,
            Palette::plain(),
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
        let report =
            report_violations(&violations, false, Palette::plain());

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
        let report =
            report_violations(&violations, false, Palette::plain());
        assert!(
            report.starts_with(
                "found 2 distinct hermeticity violations (7 occurrences):\n"
            ),
            "{report}",
        );
    }

    #[test]
    fn the_command_line_definition_is_well_formed() {
        // clap's own audit of the option definitions: duplicate names,
        // conflicts naming arguments that do not exist, and so on.
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn no_fail_is_refused_together_with_expect_json() {
        // `--expect-json` exists to produce an exit code, so asking for it
        // and then asking not to fail is a contradiction rather than a
        // preference.
        let both = Cli::try_parse_from([
            "ahab",
            "//...",
            "--no-fail",
            "--expect-json",
            "base.json",
        ]);
        assert!(both.is_err(), "{both:?}");

        // Each on its own is fine.
        assert!(
            Cli::try_parse_from(["ahab", "//...", "--no-fail"]).is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "ahab",
                "//...",
                "--expect-json",
                "base.json"
            ])
            .is_ok()
        );
    }

    #[test]
    fn a_label_is_required_unless_a_report_is_being_explained() {
        assert!(Cli::try_parse_from(["ahab"]).is_err());
        assert!(
            Cli::try_parse_from(["ahab", "--explain-json", "saved.json"])
                .is_ok()
        );
    }

    #[test]
    fn the_report_notes_what_exceptions_suppressed() {
        let suppressed = Suppressed {
            distinct: 1,
            occurrences: 3,
            exceptions: 1,
        };
        let report = super::report_violations(
            &once([bad_path("CppCompile", 1, "/bin")]),
            suppressed,
            false,
            Palette::plain(),
        );
        // The finding still leads; the note is a footnote under it.
        assert!(
            report.starts_with("found 1 hermeticity violation:\n"),
            "{report}"
        );
        assert!(
            report
                .ends_with("\n  (3 violations suppressed by 1 exception)"),
            "{report}"
        );
    }

    #[test]
    fn the_report_is_silent_when_nothing_was_suppressed() {
        let report = super::report_violations(
            &once([bad_path("CppCompile", 1, "/bin")]),
            Suppressed::default(),
            false,
            Palette::plain(),
        );
        assert!(!report.contains("suppressed"), "{report}");
    }

    #[test]
    fn report_ends_with_a_melville_quote() {
        let violations = once([bad_path("CppCompile", 1, "/bin")]);
        let report = report_violations(&violations, true, Palette::plain());
        let quote = melville::quote_for(&violations);
        assert!(report.ends_with(&format!("\n\n  {quote}")), "{report}");
    }

    #[test]
    fn shut_up_suppresses_the_quote() {
        let violations = once([bad_path("CppCompile", 1, "/bin")]);
        let report =
            report_violations(&violations, false, Palette::plain());
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
