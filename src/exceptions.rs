//! User-supplied exceptions: filters applied to the final violation map.

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;

use crate::checks::{EnvSource, LeakSite, Violation};
use crate::glob::Glob;

/// The kind of violation an exception applies to, named as the JSON report
/// names it so that one can be copied straight out of the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    EnvironmentLeak,
    BadPath,
    ExecutionRequirement,
    AbsolutePath,
    WorkspaceStatus,
    SystemProgram,
    HostDerivedProgram,
    UnknownProgram,
    NeverReproducible,
    ConditionalReproducibility,
}

impl Kind {
    /// Every kind, in the order [`Violation`] declares them.
    const ALL: [Kind; 10] = [
        Kind::EnvironmentLeak,
        Kind::BadPath,
        Kind::ExecutionRequirement,
        Kind::AbsolutePath,
        Kind::WorkspaceStatus,
        Kind::SystemProgram,
        Kind::HostDerivedProgram,
        Kind::UnknownProgram,
        Kind::NeverReproducible,
        Kind::ConditionalReproducibility,
    ];

    /// The tag [`Violation`]'s serialization uses.
    fn as_str(self) -> &'static str {
        match self {
            Kind::EnvironmentLeak => "environment_leak",
            Kind::BadPath => "bad_path",
            Kind::ExecutionRequirement => "execution_requirement",
            Kind::AbsolutePath => "absolute_path",
            Kind::WorkspaceStatus => "workspace_status",
            Kind::SystemProgram => "system_program",
            Kind::HostDerivedProgram => "host_derived_program",
            Kind::UnknownProgram => "unknown_program",
            Kind::NeverReproducible => "never_reproducible",
            Kind::ConditionalReproducibility => {
                "conditional_reproducibility"
            }
        }
    }

    /// Whether a violation of this kind carries a program.
    fn has_program(self) -> bool {
        matches!(
            self,
            Kind::SystemProgram
                | Kind::HostDerivedProgram
                | Kind::UnknownProgram
                | Kind::NeverReproducible
                | Kind::ConditionalReproducibility
        )
    }

    /// Whether a violation of this kind records where in the action it was
    /// found.
    fn has_site(self) -> bool {
        matches!(self, Kind::EnvironmentLeak | Kind::AbsolutePath)
    }
}

/// Parse `text` as one of a closed vocabulary, listing the alternatives
/// when it is not one of them.
fn parse_one_of<T: Copy>(
    what: &str,
    text: &str,
    values: &[T],
    name: fn(T) -> &'static str,
) -> Result<T, String> {
    values
        .iter()
        .copied()
        .find(|value| name(*value) == text)
        .ok_or_else(|| {
            let known: Vec<&str> =
                values.iter().map(|value| name(*value)).collect();
            format!(
                "unknown {what} {text:?}, expected one of: {}",
                known.join(", "),
            )
        })
}

/// Where in an action a violation was found, as an exception names it.
/// Mirrors the `location` tag of [`LeakSite`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Location {
    Argument,
    ParamFile,
    EnvVar,
}

impl Location {
    const ALL: [Location; 3] =
        [Location::Argument, Location::ParamFile, Location::EnvVar];

    fn as_str(self) -> &'static str {
        match self {
            Location::Argument => "argument",
            Location::ParamFile => "param_file",
            Location::EnvVar => "env_var",
        }
    }

    /// Which location a site is.
    fn of(site: &LeakSite) -> Location {
        match site {
            LeakSite::Argument { .. } => Location::Argument,
            LeakSite::ParamFile { .. } => Location::ParamFile,
            LeakSite::EnvVar { .. } => Location::EnvVar,
        }
    }
}

/// The sources an exception file may name, for [`parse_one_of`].
const SOURCES: [EnvSource; 2] = [EnvSource::User, EnvSource::Hostname];

/// How an exception file spells a source. Its own function rather than
/// [`EnvSource`]'s, whose `as_str` answers a different question—the name of
/// the environment variable, not the word the file uses for it.
fn source_name(source: EnvSource) -> &'static str {
    match source {
        EnvSource::User => "user",
        EnvSource::Hostname => "hostname",
    }
}

/// One exception: a conjunction of predicates, every one of which a
/// violation must satisfy to be excused. A field left unset is not a
/// predicate and constrains nothing.
#[derive(Debug, Clone)]
pub(crate) struct Exception {
    /// Why this exception exists. Never matched against anything—it is here
    /// so that the report can name an exception the way its author would,
    /// and so that a stale one can be recognized years later.
    pub(crate) reason: Option<String>,
    /// The file this came from, for the same reason.
    pub(crate) origin: String,
    kind: Option<Kind>,
    mnemonic: Option<Glob>,
    target: Option<Glob>,
    program: Option<Glob>,
    path: Option<Glob>,
    actual: Option<Glob>,
    requirement: Option<Glob>,
    source: Option<EnvSource>,
    location: Option<Location>,
    env_var: Option<Glob>,
}

impl Exception {
    /// Whether this exception excuses `violation`.
    pub(crate) fn matches(&self, violation: &Violation) -> bool {
        let facets = violation.facets();

        // A predicate over a facet the violation does not have fails rather
        // than passes vacuously: asking about a program is asking for a
        // violation that has one.
        let glob = |pattern: &Option<Glob>, text: Option<&str>| match (
            pattern, text,
        ) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(glob), Some(text)) => glob.matches(text),
        };

        if self.kind.is_some_and(|kind| kind.as_str() != facets.kind) {
            return false;
        }
        if !glob(&self.mnemonic, Some(&facets.action.mnemonic)) {
            return false;
        }
        if !glob(&self.target, Some(&facets.action.target)) {
            return false;
        }
        // Rendered rather than compared field by field so that a person
        // writes the label form they already read in the report.
        let program = facets.program.map(ToString::to_string);
        if !glob(&self.program, program.as_deref()) {
            return false;
        }
        if !glob(&self.path, facets.path) {
            return false;
        }
        if !glob(&self.actual, facets.actual) {
            return false;
        }
        if !glob(&self.requirement, facets.requirement) {
            return false;
        }
        if self.source.is_some() && self.source != facets.source {
            return false;
        }
        if self.location.is_some()
            && self.location != facets.site.map(Location::of)
        {
            return false;
        }
        let env_var = match facets.site {
            Some(LeakSite::EnvVar { key, .. }) => Some(key.as_str()),
            _ => None,
        };
        if !glob(&self.env_var, env_var) {
            return false;
        }

        true
    }
}

impl fmt::Display for Exception {
    /// Name the exception by its reason when it has one, and by the
    /// predicates it is made of when it does not. The second is uglier, but
    /// an exception with no reason still has to be findable in the file
    /// once we report it as stale.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(reason) = &self.reason {
            return write!(f, "{reason:?} ({})", self.origin);
        }

        let mut parts = Vec::new();
        let mut push = |name: &str, value: Option<String>| {
            if let Some(value) = value {
                parts.push(format!("{name}: {value:?}"));
            }
        };
        push("kind", self.kind.map(|k| k.as_str().to_owned()));
        push("mnemonic", self.mnemonic.as_ref().map(ToString::to_string));
        push("target", self.target.as_ref().map(ToString::to_string));
        push("program", self.program.as_ref().map(ToString::to_string));
        push("path", self.path.as_ref().map(ToString::to_string));
        push("actual", self.actual.as_ref().map(ToString::to_string));
        push(
            "requirement",
            self.requirement.as_ref().map(ToString::to_string),
        );
        push("source", self.source.map(|s| source_name(s).to_owned()));
        push("location", self.location.map(|l| l.as_str().to_owned()));
        push("env_var", self.env_var.as_ref().map(ToString::to_string));

        write!(f, "{{{}}} ({})", parts.join(", "), self.origin)
    }
}

/// Every exception in force, from every `--exceptions-json` file.
#[derive(Debug, Clone, Default)]
pub(crate) struct Exceptions {
    exceptions: Vec<Exception>,
}

impl Exceptions {
    /// Collect exceptions from however many files supplied them. Files
    /// compose by union: a filter cannot be un-said by a later file, so
    /// there is nothing for a later one to override.
    pub(crate) fn new(
        exceptions: impl IntoIterator<Item = Exception>,
    ) -> Exceptions {
        Exceptions {
            exceptions: exceptions.into_iter().collect(),
        }
    }

    /// Drop every violation some exception excuses, and report what was
    /// dropped and which exceptions did the dropping.
    pub(crate) fn filter(
        &self,
        violations: BTreeMap<Violation, usize>,
    ) -> Filtered {
        let mut used = vec![false; self.exceptions.len()];
        let mut kept = BTreeMap::new();
        let mut summary = Suppressed::default();

        for (violation, count) in violations {
            // Every exception is consulted, not just the first to match, so
            // that overlapping ones are not reported stale by accident of
            // ordering.
            let mut excused = false;
            for (i, exception) in self.exceptions.iter().enumerate() {
                if exception.matches(&violation) {
                    used[i] = true;
                    excused = true;
                }
            }

            if excused {
                summary.distinct += 1;
                summary.occurrences += count;
            } else {
                kept.insert(violation, count);
            }
        }
        summary.exceptions = used.iter().filter(|used| **used).count();

        let unused = self
            .exceptions
            .iter()
            .zip(&used)
            .filter(|(_, used)| !**used)
            .map(|(exception, _)| exception.clone())
            .collect();

        Filtered {
            kept,
            suppressed: summary,
            unused,
        }
    }
}

/// What filtering removed, for the one-line note the report ends with.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Suppressed {
    /// Distinct violations excused.
    pub(crate) distinct: usize,
    /// Occurrences those violations stood for.
    pub(crate) occurrences: usize,
    /// How many exceptions did the excusing.
    pub(crate) exceptions: usize,
}

impl Suppressed {
    pub(crate) fn is_empty(self) -> bool {
        self.distinct == 0
    }

    /// The parenthetical appended to the report. Suppression is never
    /// silent: an exception file that quietly grew to cover half the build
    /// is exactly the failure this tool exists to prevent.
    pub(crate) fn note(self) -> String {
        let violations = if self.occurrences == 1 {
            "violation"
        } else {
            "violations"
        };
        let exceptions = if self.exceptions == 1 {
            "exception"
        } else {
            "exceptions"
        };
        format!(
            "({} {violations} suppressed by {} {exceptions})",
            self.occurrences, self.exceptions,
        )
    }
}

/// The outcome of applying exceptions to a violation map.
#[derive(Debug)]
pub(crate) struct Filtered {
    /// The violations no exception excused.
    pub(crate) kept: BTreeMap<Violation, usize>,
    /// What was excused.
    pub(crate) suppressed: Suppressed,
    /// Exceptions that matched nothing at all. Warned about rather than
    /// rejected: an exception outliving the problem it excused is good
    /// news, and turning good news into a failed build teaches people to
    /// stop fixing things.
    pub(crate) unused: Vec<Exception>,
}

/// The JSON form of an `--exceptions-json` file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExceptionFile {
    exceptions: Vec<ExceptionEntry>,
}

/// The JSON form of an [`Exception`]: every predicate flat and optional.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExceptionEntry {
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    mnemonic: Option<String>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    program: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    actual: Option<String>,
    #[serde(default)]
    requirement: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    env_var: Option<String>,
}

/// Whether `field` is a predicate a violation of `kind` could satisfy.
///
/// Only used to reject contradictions at load time: a predicate about a
/// facet the stated kind never carries cannot match, and saying so now is
/// kinder than a stale-exception warning that does not explain itself.
fn applies_to(field: &str, kind: Kind) -> bool {
    match field {
        "program" => kind.has_program(),
        "path" => kind == Kind::AbsolutePath,
        "actual" => kind == Kind::BadPath,
        "requirement" => kind == Kind::ExecutionRequirement,
        "source" => kind == Kind::EnvironmentLeak,
        "location" | "env_var" => kind.has_site(),
        _ => true,
    }
}

/// Parse the exceptions a `--exceptions-json` file declares.
///
/// `origin` names the file, and is carried into every exception so that a
/// warning about a stale one can say where to go and delete it.
pub(crate) fn parse_exceptions(
    json: &str,
    origin: &str,
) -> Result<Vec<Exception>, String> {
    let file: ExceptionFile =
        serde_json::from_str(json).map_err(|why| why.to_string())?;

    file.exceptions
        .into_iter()
        .enumerate()
        .map(|(i, entry)| compile(entry, i, origin))
        .collect()
}

/// Turn one parsed entry into an [`Exception`], rejecting the ways it can
/// be self-defeating.
fn compile(
    entry: ExceptionEntry,
    index: usize,
    origin: &str,
) -> Result<Exception, String> {
    // Errors are positional because an exception need not have a reason and
    // often has no field unique enough to name it by.
    let at = |why: String| format!("exception {}: {why}", index + 1);

    let kind = entry
        .kind
        .as_deref()
        .map(|text| parse_one_of("kind", text, &Kind::ALL, Kind::as_str))
        .transpose()
        .map_err(at)?;
    let source = entry
        .source
        .as_deref()
        .map(|text| parse_one_of("source", text, &SOURCES, source_name))
        .transpose()
        .map_err(at)?;
    let location = entry
        .location
        .as_deref()
        .map(|text| {
            parse_one_of("location", text, &Location::ALL, Location::as_str)
        })
        .transpose()
        .map_err(at)?;

    // A predicate that no violation of the stated kind could ever carry is
    // a mistake worth naming now. It would otherwise match nothing, and the
    // author would learn only from a stale-exception warning that does not
    // say why.
    if let Some(kind) = kind {
        let stated = [
            ("program", entry.program.is_some()),
            ("path", entry.path.is_some()),
            ("actual", entry.actual.is_some()),
            ("requirement", entry.requirement.is_some()),
            ("source", entry.source.is_some()),
            ("location", entry.location.is_some()),
            ("env_var", entry.env_var.is_some()),
        ];
        for (field, present) in stated {
            if present && !applies_to(field, kind) {
                return Err(at(format!(
                    "{field:?} does not apply to a {:?} violation",
                    kind.as_str()
                )));
            }
        }
    }

    // `env_var` is itself a claim about the location, so a contradicting
    // `location` cannot be what the author meant.
    if entry.env_var.is_some()
        && location.is_some_and(|l| l != Location::EnvVar)
    {
        return Err(at(format!(
            "\"env_var\" needs location \"env_var\", not {:?}",
            location.unwrap_or(Location::EnvVar).as_str()
        )));
    }

    let exception = Exception {
        reason: entry.reason,
        origin: origin.to_owned(),
        kind,
        mnemonic: entry.mnemonic.as_deref().map(Glob::new),
        target: entry.target.as_deref().map(Glob::new),
        program: entry.program.as_deref().map(Glob::new),
        path: entry.path.as_deref().map(Glob::new),
        actual: entry.actual.as_deref().map(Glob::new),
        requirement: entry.requirement.as_deref().map(Glob::new),
        source,
        location,
        env_var: entry.env_var.as_deref().map(Glob::new),
    };

    if !exception.constrains_anything() {
        return Err(at(
            "no conditions, so it would suppress every violation; \
             give it at least one field besides \"reason\""
                .to_owned(),
        ));
    }

    Ok(exception)
}

impl Exception {
    /// Whether this exception says anything at all about a violation.
    fn constrains_anything(&self) -> bool {
        self.kind.is_some()
            || self.mnemonic.is_some()
            || self.target.is_some()
            || self.program.is_some()
            || self.path.is_some()
            || self.actual.is_some()
            || self.requirement.is_some()
            || self.source.is_some()
            || self.location.is_some()
            || self.env_var.is_some()
    }
}

/// Render the warning for exceptions that matched nothing.
///
/// Returns `None` when there is nothing to say, so the caller does not have
/// to know how the sentence is built to decide whether to print it.
pub(crate) fn stale_warning(unused: &[Exception]) -> Option<String> {
    if unused.is_empty() {
        return None;
    }

    let noun = if unused.len() == 1 {
        "exception"
    } else {
        "exceptions"
    };
    let mut warning =
        format!("warning: {} {noun} matched nothing:", unused.len());
    for exception in unused {
        warning.push_str(&format!("\n  - {exception}"));
    }
    Some(warning)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::ActionRef;
    use crate::reproducibility_spec::program_id::ProgramId;

    fn action(mnemonic: &str, target: &str) -> ActionRef {
        ActionRef {
            mnemonic: mnemonic.to_owned(),
            target: target.to_owned(),
        }
    }

    fn absolute_path(
        mnemonic: &str,
        target: &str,
        path: &str,
    ) -> Violation {
        Violation::AbsolutePath {
            action: action(mnemonic, target),
            path: path.to_owned(),
            site: LeakSite::Argument {
                value: format!("-I{path}"),
            },
        }
    }

    fn unknown_program(
        mnemonic: &str,
        target: &str,
        program: &str,
    ) -> Violation {
        Violation::UnknownProgram {
            action: action(mnemonic, target),
            program: program.parse::<ProgramId>().expect("a program"),
            wrappers: Vec::new(),
        }
    }

    fn leak(mnemonic: &str, target: &str, key: &str) -> Violation {
        Violation::EnvironmentLeak {
            action: action(mnemonic, target),
            source: EnvSource::User,
            sentinel: "ahab-user-1234".to_owned(),
            site: LeakSite::EnvVar {
                key: key.to_owned(),
                value: "/home/ahab-user-1234".to_owned(),
            },
        }
    }

    /// Compile a single exception from the JSON body of one entry.
    fn one(entry: &str) -> Result<Exception, String> {
        let json = format!("{{\"exceptions\": [{entry}]}}");
        parse_exceptions(&json, "test.json").map(|mut all| {
            assert_eq!(all.len(), 1);
            all.remove(0)
        })
    }

    /// Compile an exception that is expected to be well-formed.
    fn good(entry: &str) -> Exception {
        one(entry).expect("a valid exception")
    }

    // ---- conjunction ----

    #[test]
    fn a_lone_mnemonic_excuses_every_violation_of_that_action() {
        let exception = good(r#"{"mnemonic": "CppCompile"}"#);
        assert!(exception.matches(&absolute_path(
            "CppCompile",
            "//a:a",
            "/usr/lib"
        )));
        assert!(exception.matches(&unknown_program(
            "CppCompile",
            "//b:b",
            "/bin/sh"
        )));
        assert!(
            !exception
                .matches(&absolute_path("Rustc", "//a:a", "/usr/lib"))
        );
    }

    #[test]
    fn a_mnemonic_and_a_path_excuse_only_that_path_there() {
        let exception =
            good(r#"{"mnemonic": "CppCompile", "path": "/usr/include/*"}"#);
        assert!(exception.matches(&absolute_path(
            "CppCompile",
            "//a:a",
            "/usr/include/stdio.h"
        )));
        // Right action, wrong path.
        assert!(!exception.matches(&absolute_path(
            "CppCompile",
            "//a:a",
            "/opt/thing"
        )));
        // Right path, wrong action.
        assert!(!exception.matches(&absolute_path(
            "Rustc",
            "//a:a",
            "/usr/include/stdio.h"
        )));
    }

    #[test]
    fn a_facet_the_violation_lacks_never_matches() {
        // A path predicate is a claim that there is a path to look at, so
        // it must not excuse violations that have none.
        let exception = good(r#"{"path": "*"}"#);
        assert!(exception.matches(&absolute_path(
            "CppCompile",
            "//a:a",
            "/usr/lib"
        )));
        assert!(!exception.matches(&unknown_program(
            "CppCompile",
            "//a:a",
            "/bin/sh"
        )));
    }

    #[test]
    fn a_program_is_matched_by_its_label_form() {
        let exception = good(r#"{"program": "@rules_rust//util/*"}"#);
        assert!(exception.matches(&unknown_program(
            "Rustc",
            "//a:a",
            "@rules_rust//util/process_wrapper/process_wrapper"
        )));
        assert!(!exception.matches(&unknown_program(
            "Rustc",
            "//a:a",
            "@llvm//bin/clang"
        )));
    }

    #[test]
    fn a_target_glob_selects_a_subtree() {
        let exception = good(r#"{"target": "//third_party/*"}"#);
        assert!(exception.matches(&absolute_path(
            "CppCompile",
            "//third_party/zlib:zlib",
            "/usr/lib"
        )));
        assert!(exception.matches(&absolute_path(
            "CppCompile",
            "//third_party/a/b:c",
            "/usr/lib"
        )));
        assert!(!exception.matches(&absolute_path(
            "CppCompile",
            "//src:main",
            "/usr/lib"
        )));
    }

    #[test]
    fn an_env_var_predicate_matches_the_variable_name() {
        let exception = good(r#"{"env_var": "HOME"}"#);
        assert!(exception.matches(&leak("Genrule", "//a:a", "HOME")));
        assert!(!exception.matches(&leak("Genrule", "//a:a", "TMPDIR")));
    }

    #[test]
    fn a_kind_predicate_restricts_to_that_variant() {
        let exception = good(r#"{"kind": "unknown_program"}"#);
        assert!(
            exception
                .matches(&unknown_program("Rustc", "//a:a", "/bin/sh"))
        );
        assert!(
            !exception
                .matches(&absolute_path("Rustc", "//a:a", "/usr/lib"))
        );
    }

    // ---- filtering ----

    #[test]
    fn filtering_keeps_what_no_exception_excuses() {
        let violations = BTreeMap::from([
            (absolute_path("CppCompile", "//a:a", "/usr/include/x.h"), 3),
            (absolute_path("Rustc", "//a:a", "/opt/thing"), 1),
        ]);
        let exceptions =
            Exceptions::new([good(r#"{"mnemonic": "CppCompile"}"#)]);

        let filtered = exceptions.filter(violations);

        assert_eq!(filtered.kept.len(), 1);
        assert!(filtered.kept.keys().all(|v| {
            matches!(v.facets().action.mnemonic.as_str(), "Rustc")
        }));
        // One distinct violation, but it stood for three occurrences.
        assert_eq!(filtered.suppressed.distinct, 1);
        assert_eq!(filtered.suppressed.occurrences, 3);
        assert_eq!(filtered.suppressed.exceptions, 1);
        assert!(filtered.unused.is_empty());
    }

    #[test]
    fn an_exception_that_matches_nothing_is_reported_unused() {
        let violations =
            BTreeMap::from([(absolute_path("Rustc", "//a:a", "/opt"), 1)]);
        let exceptions = Exceptions::new([
            good(r#"{"reason": "stale", "mnemonic": "CppCompile"}"#),
            good(r#"{"mnemonic": "Rustc"}"#),
        ]);

        let filtered = exceptions.filter(violations);

        assert_eq!(filtered.unused.len(), 1);
        assert_eq!(filtered.unused[0].reason.as_deref(), Some("stale"));
        let warning = stale_warning(&filtered.unused).expect("a warning");
        assert!(
            warning.contains("1 exception matched nothing"),
            "{warning}"
        );
        assert!(warning.contains("\"stale\" (test.json)"), "{warning}");
    }

    #[test]
    fn overlapping_exceptions_are_all_credited() {
        // Both match the only violation. Neither may be called stale just
        // because the other was consulted first.
        let violations = BTreeMap::from([(
            absolute_path("CppCompile", "//a:a", "/usr/lib"),
            1,
        )]);
        let exceptions = Exceptions::new([
            good(r#"{"mnemonic": "CppCompile"}"#),
            good(r#"{"path": "/usr/*"}"#),
        ]);

        let filtered = exceptions.filter(violations);

        assert!(filtered.kept.is_empty());
        assert!(filtered.unused.is_empty(), "{:?}", filtered.unused);
        assert_eq!(filtered.suppressed.exceptions, 2);
    }

    #[test]
    fn no_exceptions_means_nothing_is_filtered() {
        let violations =
            BTreeMap::from([(absolute_path("Rustc", "//a:a", "/opt"), 2)]);
        let filtered = Exceptions::default().filter(violations.clone());

        assert_eq!(filtered.kept, violations);
        assert!(filtered.suppressed.is_empty());
        assert!(stale_warning(&filtered.unused).is_none());
    }

    #[test]
    fn the_note_counts_occurrences_and_exceptions() {
        let suppressed = Suppressed {
            distinct: 2,
            occurrences: 3,
            exceptions: 2,
        };
        assert_eq!(
            suppressed.note(),
            "(3 violations suppressed by 2 exceptions)"
        );

        let one = Suppressed {
            distinct: 1,
            occurrences: 1,
            exceptions: 1,
        };
        assert_eq!(one.note(), "(1 violation suppressed by 1 exception)");
    }

    // ---- loading ----

    #[test]
    fn an_exception_with_no_conditions_is_rejected() {
        let why = one(r#"{"reason": "everything"}"#)
            .expect_err("an exception with no conditions");
        assert!(why.contains("no conditions"), "{why}");
        assert!(why.contains("exception 1"), "{why}");
    }

    #[test]
    fn an_unknown_field_is_rejected() {
        // A misspelled predicate would otherwise be dropped, silently
        // widening the exception.
        let why = one(r#"{"mnemonics": "CppCompile"}"#)
            .expect_err("an unknown field");
        assert!(why.contains("mnemonics"), "{why}");
    }

    #[test]
    fn an_unknown_kind_lists_the_known_ones() {
        let why =
            one(r#"{"kind": "absolute_paths"}"#).expect_err("a bad kind");
        assert!(why.contains("unknown kind"), "{why}");
        assert!(why.contains("absolute_path"), "{why}");
        assert!(why.contains("conditional_reproducibility"), "{why}");
    }

    #[test]
    fn a_predicate_that_the_kind_cannot_carry_is_rejected() {
        let why = one(r#"{"kind": "bad_path", "path": "/usr/*"}"#)
            .expect_err("a contradiction");
        assert!(why.contains("does not apply"), "{why}");
        assert!(why.contains("bad_path"), "{why}");
    }

    #[test]
    fn a_program_predicate_needs_a_kind_that_has_one() {
        assert!(one(r#"{"kind": "bad_path", "program": "*"}"#).is_err());
        assert!(
            one(r#"{"kind": "unknown_program", "program": "*"}"#).is_ok()
        );
    }

    #[test]
    fn env_var_contradicting_location_is_rejected() {
        let why = one(r#"{"env_var": "HOME", "location": "argument"}"#)
            .expect_err("a contradiction");
        assert!(why.contains("env_var"), "{why}");
    }

    #[test]
    fn an_unknown_source_or_location_is_rejected() {
        assert!(one(r#"{"source": "username"}"#).is_err());
        assert!(one(r#"{"location": "params"}"#).is_err());
        assert!(one(r#"{"source": "hostname"}"#).is_ok());
        assert!(one(r#"{"location": "param_file"}"#).is_ok());
    }

    #[test]
    fn errors_name_the_exception_by_position() {
        let json = r#"{"exceptions": [
            {"mnemonic": "CppCompile"},
            {"reason": "no conditions here"}
        ]}"#;
        let why =
            parse_exceptions(json, "test.json").expect_err("an error");
        assert!(why.contains("exception 2"), "{why}");
    }

    #[test]
    fn an_exception_without_a_reason_is_named_by_its_predicates() {
        let exception = good(r#"{"mnemonic": "Cpp*", "path": "/usr/*"}"#);
        let shown = exception.to_string();
        assert!(shown.contains("mnemonic: \"Cpp*\""), "{shown}");
        assert!(shown.contains("path: \"/usr/*\""), "{shown}");
        assert!(shown.contains("(test.json)"), "{shown}");
    }

    #[test]
    fn files_compose_by_union() {
        let mut all = parse_exceptions(
            r#"{"exceptions": [{"mnemonic": "Rustc"}]}"#,
            "a.json",
        )
        .expect("a.json");
        all.extend(
            parse_exceptions(
                r#"{"exceptions": [{"mnemonic": "CppCompile"}]}"#,
                "b.json",
            )
            .expect("b.json"),
        );

        let violations = BTreeMap::from([
            (absolute_path("Rustc", "//a:a", "/opt"), 1),
            (absolute_path("CppCompile", "//a:a", "/opt"), 1),
        ]);
        let filtered = Exceptions::new(all).filter(violations);

        assert!(filtered.kept.is_empty());
        assert_eq!(filtered.suppressed.exceptions, 2);
    }
}
