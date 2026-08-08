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
    /// The program is reproducible only under some conditions—see the
    /// required and breaking flags of the [`ReproducibilitySpec`].
    Sometimes,
}

/// How a program's raw arguments are read as canonical options.
pub type Recognize = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// A description of one program's reproducibility and the conditions
/// affecting it.
#[derive(Clone)]
pub struct ReproducibilitySpec {
    /// The baseline reproducibility of the program.
    pub reproducibility: Reproducibility,
    /// Patterns an invocation must match for the program to be
    /// reproducible.
    pub required_flags: BTreeSet<Glob>,
    /// Patterns whose match breaks the program's reproducibility.
    pub breaking_flags: BTreeSet<Glob>,
    /// Map a raw argument to the canonical option it represents, or `None`
    /// if it is not recognized as an option of this program.
    pub recognize: Recognize,
}

impl fmt::Debug for ReproducibilitySpec {
    /// A function cannot be shown, so it is named rather than printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReproducibilitySpec")
            .field("reproducibility", &self.reproducibility)
            .field("required_flags", &self.required_flags)
            .field("breaking_flags", &self.breaking_flags)
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
            && self.required_flags == other.required_flags
            && self.breaking_flags == other.breaking_flags
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
            required_flags: required_flags
                .into_iter()
                .map(|flag| Glob::new(&flag.into()))
                .collect(),
            breaking_flags: breaking_flags
                .into_iter()
                .map(|flag| Glob::new(&flag.into()))
                .collect(),
            recognize: Arc::new(|arg: &str| Some(arg.to_owned())),
        }
    }

    /// Set the recognizer, returning the updated spec.
    #[allow(dead_code)]
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
            Reproducibility::Sometimes => {
                let present: BTreeSet<String> = args
                    .into_iter()
                    .filter_map(|arg| self.recognize(arg))
                    .collect();

                let missing_required: BTreeSet<String> = self
                    .required_flags
                    .iter()
                    .filter(|required| {
                        !present.iter().any(|arg| required.matches(arg))
                    })
                    .map(ToString::to_string)
                    .collect();

                let present_breaking: BTreeSet<String> = present
                    .iter()
                    .filter(|arg| {
                        self.breaking_flags
                            .iter()
                            .any(|breaking| breaking.matches(arg))
                    })
                    .cloned()
                    .collect();

                if missing_required.is_empty()
                    && present_breaking.is_empty()
                {
                    Conformance::Reproducible
                } else {
                    Conformance::Conditional {
                        missing_required,
                        present_breaking,
                    }
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
    /// The program is conditionally reproducible and this invocation does
    /// not meet the conditions: some required flags are absent and/or some
    /// breaking flags are present. At least one of the two sets is
    /// non-empty.
    Conditional {
        /// Required flags that are absent from the invocation.
        missing_required: BTreeSet<String>,
        /// Breaking flags that are present in the invocation.
        present_breaking: BTreeSet<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_collects_flag_sets_and_dedups() {
        let spec = ReproducibilitySpec::new(
            Reproducibility::Sometimes,
            ["--deterministic", "--deterministic", "-frandom-seed"],
            ["--timestamp"],
        );
        assert_eq!(spec.reproducibility, Reproducibility::Sometimes);
        // The set dedups and orders the required flags.
        assert!(spec.required_flags.contains("--deterministic"));
        assert!(spec.required_flags.contains("-frandom-seed"));
        assert_eq!(spec.required_flags.len(), 2);
        assert!(spec.breaking_flags.contains("--timestamp"));
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
        assert_eq!(
            spec.assess(["--deterministic", "--timestamp"]),
            Conformance::Conditional {
                missing_required: set(&[]),
                present_breaking: set(&["--timestamp"]),
            }
        );
        assert_eq!(
            spec.assess(["input.c"]),
            Conformance::Conditional {
                missing_required: set(&["--deterministic"]),
                present_breaking: set(&[]),
            }
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
        assert_eq!(
            spec.assess(["-O2", "input.c"]),
            Conformance::Conditional {
                missing_required: set(&[]),
                present_breaking: set(&["-O"]),
            }
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
        assert_eq!(
            spec.assess(["--sorted"]),
            Conformance::Conditional {
                missing_required: set(&["--deterministic"]),
                present_breaking: set(&[]),
            }
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
        assert_eq!(
            spec.assess(["-O2", "input.c"]),
            Conformance::Conditional {
                missing_required: set(&[]),
                present_breaking: set(&["-O"]),
            }
        );
    }

    #[test]
    fn sometimes_reports_both_kinds_at_once() {
        let spec = ReproducibilitySpec::new(
            Reproducibility::Sometimes,
            ["--deterministic"],
            ["--timestamp"],
        );
        assert_eq!(
            spec.assess(["--timestamp"]),
            Conformance::Conditional {
                missing_required: set(&["--deterministic"]),
                present_breaking: set(&["--timestamp"]),
            }
        );
    }
}
