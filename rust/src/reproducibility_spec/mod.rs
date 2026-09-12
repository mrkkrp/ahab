//! Modeling *reproducibility*: whether a program (a tool invoked by a build
//! action) behaves deterministically, and the exact conditions that affect
//! it.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::glob::Glob;

pub mod library;
pub mod per_lang;
pub mod program_id;

/// A program's baseline disposition, before the flags it was invoked with
/// (see [`ReproducibilitySpec`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reproducibility {
    /// The program is always reproducible, regardless of how it is invoked.
    Always,
    /// The program is never reproducible; no set of flags can make it so.
    Never,
    /// The program works with what the machine has rather than what the
    /// build declares: Bazel wrote it by inspecting the machine, or it
    /// reaches for a tool installed there.
    HostDerived,
    /// Reproducible only under the spec's requirements and prohibitions.
    Sometimes,
}

/// How a program's raw arguments are read as canonical options.
pub type Recognize = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// Compile patterns into the set every rule here matches against.
pub fn globs<P>(patterns: P) -> BTreeSet<Glob>
where
    P: IntoIterator,
    P::Item: AsRef<str>,
{
    patterns
        .into_iter()
        .map(|pattern| Glob::new(pattern.as_ref()))
        .collect()
}

/// A condition on an invocation, by which a [`Clause`] applies or does not:
/// a family of flags that turn something on, and those that turn it off.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Guard {
    /// Flags that turn the condition on.
    pub family: BTreeSet<Glob>,
    /// Flags of the same family that turn it off again.
    pub off: BTreeSet<Glob>,
}

impl Guard {
    /// A condition nothing turns off again.
    pub fn on<F>(family: F) -> Guard
    where
        F: IntoIterator,
        F::Item: AsRef<str>,
    {
        Guard {
            family: globs(family),
            off: BTreeSet::new(),
        }
    }

    /// A condition `off` turns back off.
    pub fn toggled<F, O>(family: F, off: O) -> Guard
    where
        F: IntoIterator,
        F::Item: AsRef<str>,
        O: IntoIterator,
        O::Item: AsRef<str>,
    {
        Guard {
            family: globs(family),
            off: globs(off),
        }
    }
}

impl Guard {
    /// Whether the condition holds, decided by the last argument that
    /// speaks to it: compilers read their flags last-wins, so `-g -g0`
    /// leaves debugging off and `-g0 -g` leaves it on.
    fn holds(&self, args: &[String]) -> bool {
        args.iter()
            .rev()
            .find_map(|arg| {
                if self.off.iter().any(|glob| glob.matches(arg)) {
                    Some(false)
                } else if self.family.iter().any(|glob| glob.matches(arg)) {
                    Some(true)
                } else {
                    None
                }
            })
            .unwrap_or(false)
    }
}

/// One thing that has to be true of an invocation, and why. A requirement
/// is met and a prohibition breached when any one of `any_of` matches, and
/// either way only when the guard holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Clause {
    /// The condition under which this clause applies. `None` is always.
    pub when: Option<Guard>,
    /// The patterns, any one of which satisfies the clause.
    pub any_of: BTreeSet<Glob>,
    /// What the clause is about, in words, for the report to quote.
    pub because: String,
}

impl Clause {
    /// A clause satisfied by any one of `any_of`, applying only where
    /// `when` holds.
    pub fn new<P>(when: Option<Guard>, any_of: P, because: &str) -> Clause
    where
        P: IntoIterator,
        P::Item: AsRef<str>,
    {
        Clause {
            when,
            any_of: globs(any_of),
            because: because.to_owned(),
        }
    }

    /// A clause that always applies, phrased as a single pattern.
    fn plain(pattern: &str, because: &str) -> Clause {
        Clause::new(None, [pattern], because)
    }

    /// Whether the clause has anything to say about these arguments.
    fn applies(&self, args: &[String]) -> bool {
        self.when.as_ref().is_none_or(|guard| guard.holds(args))
    }

    /// The arguments matching any of the clause's patterns.
    fn matched(&self, args: &[String]) -> BTreeSet<String> {
        args.iter()
            .filter(|arg| self.any_of.iter().any(|glob| glob.matches(arg)))
            .cloned()
            .collect()
    }

    /// The patterns themselves, for a report that has no argument to name.
    fn patterns(&self) -> BTreeSet<String> {
        self.any_of.iter().map(ToString::to_string).collect()
    }
}

/// A clause an invocation failed to meet.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
pub struct Unmet {
    /// What the clause was about, in the words the spec gave it.
    pub because: String,
    /// For a requirement, the patterns any one of which would have met it.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub any_of: BTreeSet<String>,
    /// For a prohibition, the arguments that breached it.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub present: BTreeSet<String>,
}

/// A description of one program's reproducibility and the conditions
/// affecting it.
#[derive(Clone)]
pub struct ReproducibilitySpec {
    /// The baseline reproducibility of the program.
    pub reproducibility: Reproducibility,
    /// Clauses an invocation must satisfy for the program to be
    /// reproducible.
    pub requirements: Vec<Clause>,
    /// Clauses an invocation must not satisfy.
    pub prohibitions: Vec<Clause>,
    /// Flags whose value is the argument that follows them, rather than
    /// part of the same one.
    pub takes_value: BTreeSet<Glob>,
    /// Options in which an absolute path does not represent an input.
    pub declared_paths: BTreeSet<Glob>,
    /// Map a raw argument to the canonical option it represents, or `None`
    /// if it is not recognized as an option of this program.
    pub recognize: Recognize,
}

impl fmt::Debug for ReproducibilitySpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReproducibilitySpec")
            .field("reproducibility", &self.reproducibility)
            .field("requirements", &self.requirements)
            .field("prohibitions", &self.prohibitions)
            .field("takes_value", &self.takes_value)
            .field("declared_paths", &self.declared_paths)
            .field("recognize", &"<function>")
            .finish()
    }
}

impl PartialEq for ReproducibilitySpec {
    /// Compares what a spec says, not how it reads arguments: the
    /// recognizer is excluded, comparing functions by identity making every
    /// independently-built spec unequal to every other.
    fn eq(&self, other: &Self) -> bool {
        self.reproducibility == other.reproducibility
            && self.requirements == other.requirements
            && self.prohibitions == other.prohibitions
            && self.takes_value == other.takes_value
            && self.declared_paths == other.declared_paths
    }
}

impl Eq for ReproducibilitySpec {}

impl ReproducibilitySpec {
    /// A spec that is its disposition and nothing else, for a program no
    /// flag can help or hurt.
    pub fn of(reproducibility: Reproducibility) -> ReproducibilitySpec {
        ReproducibilitySpec::new(
            reproducibility,
            [] as [&str; 0],
            [] as [&str; 0],
        )
    }

    /// Construct a spec from a baseline disposition and the unconditional
    /// flags, each becoming a clause of its own that always applies. A
    /// condition or a choice needs [`Self::with_clauses`]. The recognizer
    /// defaults to the identity.
    pub fn new<R, B>(
        reproducibility: Reproducibility,
        required_flags: R,
        breaking_flags: B,
    ) -> Self
    where
        R: IntoIterator,
        R::Item: Into<String>,
        B: IntoIterator,
        B::Item: Into<String>,
    {
        ReproducibilitySpec {
            reproducibility,
            requirements: required_flags
                .into_iter()
                .map(|flag| {
                    Clause::plain(
                        &flag.into(),
                        "it needs an option it was not given",
                    )
                })
                .collect(),
            prohibitions: breaking_flags
                .into_iter()
                .map(|flag| {
                    Clause::plain(
                        &flag.into(),
                        "it was given an option that breaks it",
                    )
                })
                .collect(),
            takes_value: BTreeSet::new(),
            declared_paths: BTreeSet::new(),
            recognize: Arc::new(|arg: &str| Some(arg.to_owned())),
        }
    }

    /// Declare the flags whose value is the next argument, returning the
    /// updated spec.
    pub fn with_valued_flags<F>(mut self, flags: F) -> Self
    where
        F: IntoIterator,
        F::Item: AsRef<str>,
    {
        self.takes_value = globs(flags);
        self
    }

    /// Declare the options in which an absolute path is part of what the
    /// program was asked to produce, returning the updated spec. Patterns
    /// match whole options, value folded on, so one covers both spellings.
    pub fn with_declared_paths<P>(mut self, patterns: P) -> Self
    where
        P: IntoIterator,
        P::Item: AsRef<str>,
    {
        self.declared_paths = globs(patterns);
        self
    }

    /// Fold each declared flag together with the argument after it, keeping
    /// the number of arguments each option was written as. A flag at the
    /// very end is left alone; one followed by another flag still takes it,
    /// because that is what the tool would do.
    fn join_values(&self, args: &[&str]) -> Vec<(String, usize)> {
        let mut joined = Vec::with_capacity(args.len());
        let mut at = 0;
        while at < args.len() {
            let arg = args[at];
            let takes =
                self.takes_value.iter().any(|flag| flag.matches(arg));
            if takes && at + 1 < args.len() {
                joined.push((format!("{arg}={}", args[at + 1]), 2));
                at += 2;
            } else {
                joined.push((arg.to_owned(), 1));
                at += 1;
            }
        }
        joined
    }

    /// The arguments in which this program declares a path inside the
    /// artifact it produces, rather than naming one it reads. Flag and value
    /// are both returned, so a caller scanning the raw command line passes
    /// over the option however it was spelled.
    pub fn declared_path_args<'a>(&self, args: &[&'a str]) -> Vec<&'a str> {
        if self.declared_paths.is_empty() {
            return Vec::new();
        }

        let mut declared = Vec::new();
        let mut at = 0;
        for (option, width) in self.join_values(args) {
            if self
                .declared_paths
                .iter()
                .any(|pattern| pattern.matches(&option))
            {
                declared.extend_from_slice(&args[at..at + width]);
            }
            at += width;
        }
        declared
    }

    /// Add clauses that say more than a bare flag can: the ones carrying a
    /// condition or a choice. Counterpart to [`Self::new`]'s flag lists.
    pub fn with_clauses<R, P>(
        mut self,
        requirements: R,
        prohibitions: P,
    ) -> Self
    where
        R: IntoIterator<Item = Clause>,
        P: IntoIterator<Item = Clause>,
    {
        self.requirements.extend(requirements);
        self.prohibitions.extend(prohibitions);
        self
    }

    /// Set the recognizer, returning the updated spec.
    pub fn with_recognizer(
        mut self,
        recognize: fn(&str) -> Option<String>,
    ) -> Self {
        self.recognize = Arc::new(recognize);
        self
    }

    /// Lift a translation map into a recognizer, returning the updated spec.
    pub fn with_translations(
        mut self,
        translations: BTreeMap<String, String>,
    ) -> Self {
        self.recognize = Arc::new(move |arg: &str| {
            Some(
                translations
                    .get(arg)
                    .cloned()
                    .unwrap_or_else(|| arg.to_owned()),
            )
        });
        self
    }
}

impl ReproducibilitySpec {
    /// The canonical option `arg` stands for, if it is recognized at all.
    pub fn recognize(&self, arg: &str) -> Option<String> {
        (self.recognize)(arg)
    }

    /// Assess whether a concrete invocation conforms to this spec.
    pub fn assess<'a, I>(&self, args: I) -> Conformance
    where
        I: IntoIterator<Item = &'a str>,
    {
        match self.reproducibility {
            Reproducibility::Always => Conformance::Reproducible,
            Reproducibility::Never => Conformance::NeverReproducible,
            Reproducibility::HostDerived => Conformance::HostDerived,
            Reproducibility::Sometimes => {
                // In order and with duplicates: a guard decides by the
                // last argument that speaks to it. Values are folded onto
                // their flags so every pattern sees whole options; a spec
                // declaring none keeps the shorter path, this running over
                // every argument of every action.
                let present: Vec<String> = if self.takes_value.is_empty() {
                    args.into_iter()
                        .filter_map(|arg| self.recognize(arg))
                        .collect()
                } else {
                    let raw: Vec<&str> = args.into_iter().collect();
                    self.join_values(&raw)
                        .into_iter()
                        .filter_map(|(option, _)| self.recognize(&option))
                        .collect()
                };

                let mut unmet: Vec<Unmet> = Vec::new();

                for clause in &self.requirements {
                    if clause.applies(&present)
                        && clause.matched(&present).is_empty()
                    {
                        unmet.push(Unmet {
                            because: clause.because.clone(),
                            any_of: clause.patterns(),
                            present: BTreeSet::new(),
                        });
                    }
                }

                for clause in &self.prohibitions {
                    if !clause.applies(&present) {
                        continue;
                    }
                    let matched = clause.matched(&present);
                    if !matched.is_empty() {
                        unmet.push(Unmet {
                            because: clause.because.clone(),
                            any_of: BTreeSet::new(),
                            present: matched,
                        });
                    }
                }

                if unmet.is_empty() {
                    Conformance::Reproducible
                } else {
                    unmet.sort();
                    unmet.dedup();
                    Conformance::Conditional { unmet }
                }
            }
        }
    }
}

/// The verdict of assessing an invocation against a [`ReproducibilitySpec`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Conformance {
    /// The invocation is reproducible.
    Reproducible,
    /// The program is never reproducible, whatever the flags.
    NeverReproducible,
    /// The program was written by inspecting the machine.
    HostDerived,
    /// The program is conditionally reproducible and this invocation does
    /// not meet the conditions. Never empty.
    Conditional {
        /// The clauses it failed, each with the spec's words for why.
        unmet: Vec<Unmet>,
    },
}

/// Ways of asking a verdict what went wrong, flattened across clauses. The
/// report reads the clauses themselves; these are for tests.
#[cfg(test)]
impl Conformance {
    /// Every pattern that would have satisfied a requirement left unmet.
    pub fn missing_required(&self) -> BTreeSet<String> {
        match self {
            Conformance::Conditional { unmet } => unmet
                .iter()
                .flat_map(|clause| clause.any_of.iter().cloned())
                .collect(),
            _ => BTreeSet::new(),
        }
    }

    /// Every argument that breached a prohibition.
    pub fn present_breaking(&self) -> BTreeSet<String> {
        match self {
            Conformance::Conditional { unmet } => unmet
                .iter()
                .flat_map(|clause| clause.present.iter().cloned())
                .collect(),
            _ => BTreeSet::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assert a verdict is conditional, and on exactly these grounds.
    #[track_caller]
    fn assert_conditional(
        verdict: Conformance,
        missing: BTreeSet<String>,
        breaking: BTreeSet<String>,
    ) {
        assert!(
            matches!(verdict, Conformance::Conditional { .. }),
            "expected a conditional verdict, got {verdict:?}",
        );
        assert_eq!(verdict.missing_required(), missing, "missing");
        assert_eq!(verdict.present_breaking(), breaking, "breaking");
    }

    #[test]
    fn new_collects_flag_sets_and_dedups() {
        let spec = ReproducibilitySpec::new(
            Reproducibility::Sometimes,
            ["--deterministic", "--deterministic", "-frandom-seed"],
            ["--timestamp"],
        );
        assert_eq!(spec.reproducibility, Reproducibility::Sometimes);
        let patterns: BTreeSet<String> = spec
            .requirements
            .iter()
            .flat_map(|clause| clause.patterns())
            .collect();
        assert!(patterns.contains("--deterministic"));
        assert!(patterns.contains("-frandom-seed"));
        assert_eq!(patterns.len(), 2);
        assert!(
            spec.prohibitions
                .iter()
                .any(|clause| clause.any_of.contains("--timestamp"))
        );
    }

    #[test]
    fn a_value_in_the_next_argument_is_folded_onto_its_flag() {
        let spec = ReproducibilitySpec::new(
            Reproducibility::Sometimes,
            ["--mode=*hash*"],
            [] as [&str; 0],
        )
        .with_valued_flags(["--mode"]);

        assert_eq!(
            spec.assess(["--mode", "unchecked_hash", "--src", "x.py"]),
            Conformance::Reproducible,
        );
        assert_conditional(
            spec.assess(["--mode", "timestamp"]),
            set(&["--mode=*hash*"]),
            set(&[]),
        );
    }

    #[test]
    fn both_spellings_of_a_value_come_out_the_same() {
        let spec = ReproducibilitySpec::new(
            Reproducibility::Sometimes,
            ["-t=*"],
            [] as [&str; 0],
        )
        .with_valued_flags(["-t"]);
        for form in [vec!["-t", "5"], vec!["-t=5"]] {
            assert_eq!(spec.assess(form), Conformance::Reproducible);
        }
    }

    #[test]
    fn a_value_already_joined_is_not_folded_again() {
        let spec = ReproducibilitySpec::new(
            Reproducibility::Sometimes,
            ["--mode=*hash*", "--src"],
            [] as [&str; 0],
        )
        .with_valued_flags(["--mode"]);
        assert_eq!(
            spec.assess(["--mode=unchecked_hash", "--src", "x.py"]),
            Conformance::Reproducible,
        );
    }

    #[test]
    fn a_valued_flag_with_nothing_after_it_is_left_alone() {
        let spec = ReproducibilitySpec::new(
            Reproducibility::Sometimes,
            [] as [&str; 0],
            ["-t=*"],
        )
        .with_valued_flags(["-t"]);
        assert_eq!(
            spec.assess(["-o", "out", "-t"]),
            Conformance::Reproducible
        );
    }

    #[test]
    fn a_valued_flag_takes_the_next_argument_even_if_it_looks_like_a_flag()
    {
        let spec = ReproducibilitySpec::new(
            Reproducibility::Sometimes,
            ["--verbose"],
            [] as [&str; 0],
        )
        .with_valued_flags(["-t"]);
        assert_conditional(
            spec.assess(["-t", "--verbose"]),
            set(&["--verbose"]),
            set(&[]),
        );
    }

    #[test]
    fn a_repeated_valued_flag_folds_each_occurrence() {
        let spec = ReproducibilitySpec::new(
            Reproducibility::Sometimes,
            ["--src=b.py"],
            [] as [&str; 0],
        )
        .with_valued_flags(["--src"]);
        assert_eq!(
            spec.assess(["--src", "a.py", "--src", "b.py"]),
            Conformance::Reproducible,
        );
    }

    #[test]
    fn default_recognizer_takes_arguments_at_face_value() {
        let spec = ReproducibilitySpec::new(
            Reproducibility::Always,
            [] as [String; 0],
            [] as [String; 0],
        );
        assert_eq!(
            spec.recognize("--anything"),
            Some("--anything".to_owned())
        );
        assert_eq!(spec.recognize("input.c"), Some("input.c".to_owned()));
    }

    #[test]
    fn the_default_recognizer_matches_flag_sets_literally() {
        let spec = ReproducibilitySpec::new(
            Reproducibility::Sometimes,
            ["--deterministic"],
            ["--timestamp"],
        );
        assert_eq!(
            spec.assess(["--deterministic", "input.c"]),
            Conformance::Reproducible
        );
        assert_conditional(
            spec.assess(["--deterministic", "--timestamp"]),
            set(&[]),
            set(&["--timestamp"]),
        );
        assert_conditional(
            spec.assess(["input.c"]),
            set(&["--deterministic"]),
            set(&[]),
        );
    }

    #[test]
    fn a_translation_maps_an_argument_to_another_option() {
        let spec = ReproducibilitySpec::new(
            Reproducibility::Sometimes,
            [] as [&str; 0],
            ["-O"],
        )
        .with_translations(translations([
            ("-O1", "-O"),
            ("-O2", "-O"),
            ("-O3", "-O"),
        ]));

        assert_eq!(spec.recognize("-O2"), Some("-O".to_owned()));
        assert_eq!(spec.recognize("input.c"), Some("input.c".to_owned()));
    }

    #[test]
    fn translations_decide_whether_a_flag_counts_as_present() {
        let spec = ReproducibilitySpec::new(
            Reproducibility::Sometimes,
            [] as [&str; 0],
            ["-O"],
        )
        .with_translations(translations([("-O2", "-O")]));

        assert_conditional(
            spec.assess(["-O2", "input.c"]),
            set(&[]),
            set(&["-O"]),
        );
        assert_eq!(spec.assess(["-O9"]), Conformance::Reproducible);
    }

    #[test]
    fn specs_compare_by_value() {
        let a = ReproducibilitySpec::new(
            Reproducibility::Never,
            ["--x"],
            ["--y"],
        );
        let b = ReproducibilitySpec::new(
            Reproducibility::Never,
            ["--x"],
            ["--y"],
        );
        assert_eq!(a, b);
    }

    fn translations<const N: usize>(
        pairs: [(&str, &str); N],
    ) -> BTreeMap<String, String> {
        pairs
            .into_iter()
            .map(|(from, to)| (from.to_owned(), to.to_owned()))
            .collect()
    }

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn always_conforms_regardless_of_args() {
        let spec = ReproducibilitySpec::new(
            Reproducibility::Always,
            ["--x"],
            ["--y"],
        );
        assert_eq!(spec.assess(["--y"]), Conformance::Reproducible);
        assert_eq!(spec.assess([] as [&str; 0]), Conformance::Reproducible);
    }

    #[test]
    fn never_is_always_non_reproducible() {
        let spec = ReproducibilitySpec::new(
            Reproducibility::Never,
            [] as [&str; 0],
            [] as [&str; 0],
        );
        assert_eq!(
            spec.assess(["--anything"]),
            Conformance::NeverReproducible
        );
    }

    #[test]
    fn sometimes_conforms_when_required_present_and_no_breaking() {
        let spec = ReproducibilitySpec::new(
            Reproducibility::Sometimes,
            ["--deterministic"],
            ["-O"],
        );
        assert_eq!(
            spec.assess(["--deterministic", "input.c"]),
            Conformance::Reproducible
        );
    }

    #[test]
    fn sometimes_reports_missing_required_flags() {
        let spec = ReproducibilitySpec::new(
            Reproducibility::Sometimes,
            ["--deterministic", "--sorted"],
            [] as [&str; 0],
        );
        assert_conditional(
            spec.assess(["--sorted"]),
            set(&["--deterministic"]),
            set(&[]),
        );
    }

    #[test]
    fn sometimes_reports_present_breaking_flags() {
        let spec = ReproducibilitySpec::new(
            Reproducibility::Sometimes,
            [] as [&str; 0],
            ["-O", "--timestamp"],
        )
        .with_translations(translations([("-O2", "-O")]));
        assert_conditional(
            spec.assess(["-O2", "input.c"]),
            set(&[]),
            set(&["-O"]),
        );
    }

    #[test]
    fn sometimes_reports_both_kinds_at_once() {
        let spec = ReproducibilitySpec::new(
            Reproducibility::Sometimes,
            ["--deterministic"],
            ["--timestamp"],
        );
        assert_conditional(
            spec.assess(["--timestamp"]),
            set(&["--deterministic"]),
            set(&["--timestamp"]),
        );
    }
}
