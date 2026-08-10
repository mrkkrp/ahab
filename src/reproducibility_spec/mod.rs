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

/// When a program behaves reproducibly.
///
/// This is the baseline disposition of the program, before considering
/// the specific flags it was invoked with (see [`ReproducibilitySpec`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reproducibility {
    /// The program is always reproducible, regardless of how it is invoked.
    Always,
    /// The program is never reproducible; no set of flags can make it so.
    Never,
    /// The program was written by inspecting the machine in ways that make
    /// it non-hermetic.
    HostDerived,
    /// The program is reproducible only under some conditions—see the
    /// required and breaking flags of the [`ReproducibilitySpec`].
    Sometimes,
}

/// How a program's raw arguments are read as canonical options.
pub type Recognize = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// A condition on an invocation, by which a [`Clause`] applies or does not.
///
/// Written as a family of flags that turn something on and the flags of the
/// same family that turn it back off.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Guard {
    /// Flags that turn the condition on.
    pub family: BTreeSet<Glob>,
    /// Flags of the same family that turn it off again.
    pub off: BTreeSet<Glob>,
}

impl Guard {
    /// Whether the condition holds, decided by the last argument that
    /// speaks to it.
    ///
    /// Compilers read their flags last-wins: `-g -g0` leaves debugging off
    /// and `-g0 -g` leaves it on, and a rule that only asked whether `-g0`
    /// appeared anywhere would get the second one wrong. Arguments that
    /// belong to neither set say nothing and are passed over.
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

/// One thing that has to be true of an invocation, and why.
///
/// A requirement is met and a prohibition is breached when any one of
/// `any_of` matches. Either way the clause only speaks when its guard
/// holds, so a rule about compiling says nothing about linking.
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
    /// A clause that always applies, phrased as a single pattern.
    fn plain(pattern: &str, because: &str) -> Self {
        Clause {
            when: None,
            any_of: [Glob::new(pattern)].into_iter().collect(),
            because: because.to_owned(),
        }
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
    /// Map a raw argument to the canonical option it represents, or `None`
    /// if it is not recognized as an option of this program.
    pub recognize: Recognize,
}

impl fmt::Debug for ReproducibilitySpec {
    /// A function cannot be shown, so it is named rather than printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReproducibilitySpec")
            .field("reproducibility", &self.reproducibility)
            .field("requirements", &self.requirements)
            .field("prohibitions", &self.prohibitions)
            .field("recognize", &"<function>")
            .finish()
    }
}

impl PartialEq for ReproducibilitySpec {
    /// Compares what a spec says, not how it reads arguments.
    ///
    /// Two functions cannot be compared, and comparing them by identity
    /// would make every independently-built spec unequal to every other,
    /// which is useless. So the recognizer is excluded: specs that agree on
    /// disposition and flags are equal even if they read arguments
    /// differently.
    fn eq(&self, other: &Self) -> bool {
        self.reproducibility == other.reproducibility
            && self.requirements == other.requirements
            && self.prohibitions == other.prohibitions
    }
}

impl Eq for ReproducibilitySpec {}

impl ReproducibilitySpec {
    /// Construct a spec from a baseline disposition and the two flag sets,
    /// taking any iterables of strings.
    ///
    /// The recognizer defaults to the identity—every argument stands for
    /// itself.
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
                    let flag = flag.into();
                    Clause::plain(&flag, &format!("{flag} is required"))
                })
                .collect(),
            prohibitions: breaking_flags
                .into_iter()
                .map(|flag| {
                    let flag = flag.into();
                    Clause::plain(&flag, &format!("{flag} breaks it"))
                })
                .collect(),
            recognize: Arc::new(|arg: &str| Some(arg.to_owned())),
        }
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
                // In order, and with duplicates: a guard decides by the
                // last argument that speaks to it, so neither position nor
                // repetition can be thrown away here.
                let present: Vec<String> = args
                    .into_iter()
                    .filter_map(|arg| self.recognize(arg))
                    .collect();

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
    /// The program was written by inspecting the machine in ways that make
    /// it non-hermetic.
    HostDerived,
    /// The program is conditionally reproducible and this invocation does
    /// not meet the conditions. Never empty.
    Conditional {
        /// The clauses it failed, each with the spec's words for why.
        unmet: Vec<Unmet>,
    },
}

/// Ways of asking a verdict what went wrong, flattened across clauses.
///
/// The report reads the clauses themselves, because it has room to say why
/// each one mattered; these are for tests, which mostly want to know which
/// patterns went unmet and which arguments offended.
#[cfg(test)]
impl Conformance {
    /// Every pattern that would have satisfied a requirement left unmet.
    ///
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
    ///
    /// Stated through the accessors rather than by rebuilding the clauses:
    /// what a test of `assess` cares about is which patterns went unmet and
    /// which arguments offended, not the sentence attached to each.
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
        // A clause per pattern, deduplicated on the way in.
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
        // Including arguments that are not options at all; they simply
        // never match a flag set.
        assert_eq!(spec.recognize("input.c"), Some("input.c".to_owned()));
    }

    #[test]
    fn the_default_recognizer_matches_flag_sets_literally() {
        // The point of the default: a spec whose options are plain words
        // needs no recognizer of its own.
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
        // A compiler whose optimization levels all count as one option.
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
        // Anything untranslated still stands for itself.
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

        // `-O2` is the breaking flag `-O` under another name.
        assert_conditional(
            spec.assess(["-O2", "input.c"]),
            set(&[]),
            set(&["-O"]),
        );
        // `-O9` was not translated, so it is not `-O`.
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

    /// Build a translation map from string pairs, for terse assertions.
    fn translations<const N: usize>(
        pairs: [(&str, &str); N],
    ) -> BTreeMap<String, String> {
        pairs
            .into_iter()
            .map(|(from, to)| (from.to_owned(), to.to_owned()))
            .collect()
    }

    /// Build a set from string literals, for terse assertions.
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
        // Required flag present, breaking flag absent.
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
        // -O2 translates to -O, a breaking flag; --timestamp is absent, so
        // only the one that is present is reported.
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
