//! Modelling *reproducibility*: whether a program (a tool invoked by a build
//! action) behaves deterministically, and the exact conditions that affect it.
//!
//! The centrepiece is [`ReproducibilitySpec`], a description of one program's
//! reproducibility. A *library* of such specs — one per known tool — lets Ahab
//! reason about actions more precisely than the syntactic checks in
//! [`crate::checks`]: rather than only spotting suspicious strings, it can ask
//! "given this program and these arguments, is the action reproducible?".

use std::collections::BTreeSet;

pub mod hardcoded;

/// When a program behaves reproducibly.
///
/// This is the *baseline* disposition of the program, before considering the
/// specific flags it was invoked with (see [`ReproducibilitySpec`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reproducibility {
    /// The program is always reproducible, regardless of how it is invoked.
    Always,
    /// The program is never reproducible; no set of flags can make it so.
    Never,
    /// The program is reproducible only under some conditions — see the
    /// required and breaking flags of the [`ReproducibilitySpec`].
    Sometimes,
}

/// A description of one program's reproducibility and the conditions affecting
/// it. A product of:
///
/// * a baseline [`Reproducibility`] disposition,
/// * the set of flags that are *required* for the program to be reproducible,
/// * the set of flags that *break* reproducibility, and
/// * a `recognize` predicate that maps a raw argument to the canonical option
///   it represents (or `None` if the argument is not a recognized option).
///
/// The `recognize` predicate is what connects raw action arguments — which may
/// be glued or abbreviated, e.g. `--sysroot=/x` or `-O2` — to the canonical
/// option names used in `required_flags` / `breaking_flags`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReproducibilitySpec {
    /// The baseline reproducibility of the program.
    pub reproducibility: Reproducibility,
    /// Flags that are required for the program to be reproducible.
    pub required_flags: BTreeSet<String>,
    /// Flags that break the program's reproducibility.
    pub breaking_flags: BTreeSet<String>,
    /// Map a raw argument to the canonical option it represents, or `None` if it
    /// is not recognized as an option of this program.
    pub recognize: fn(&str) -> Option<String>,
}

impl ReproducibilitySpec {
    /// Construct a spec from a baseline disposition and the two flag sets,
    /// taking any iterables of strings. The `recognize` predicate is supplied
    /// separately with [`with_recognizer`](Self::with_recognizer); by default it
    /// recognizes nothing.
    pub fn new<R, B>(reproducibility: Reproducibility, required_flags: R, breaking_flags: B) -> Self
    where
        R: IntoIterator,
        R::Item: Into<String>,
        B: IntoIterator,
        B::Item: Into<String>,
    {
        ReproducibilitySpec {
            reproducibility,
            required_flags: required_flags.into_iter().map(Into::into).collect(),
            breaking_flags: breaking_flags.into_iter().map(Into::into).collect(),
            recognize: |_| None,
        }
    }

    /// Set the `recognize` predicate, returning the updated spec.
    pub fn with_recognizer(mut self, recognize: fn(&str) -> Option<String>) -> Self {
        self.recognize = recognize;
        self
    }

    /// Apply the `recognize` predicate to `arg`, yielding the canonical option
    /// it represents, if any.
    pub fn recognize(&self, arg: &str) -> Option<String> {
        (self.recognize)(arg)
    }

    /// Assess whether a concrete invocation conforms to this spec.
    ///
    /// `args` are the arguments passed to the program (its `argv[1..]`, i.e.
    /// *not* including the program itself). Each is mapped through
    /// [`recognize`](Self::recognize) to the canonical option it represents;
    /// unrecognized arguments are ignored. The verdict then follows the baseline
    /// [`Reproducibility`]:
    ///
    /// * [`Always`](Reproducibility::Always) — always [`Conformance::Reproducible`].
    /// * [`Never`](Reproducibility::Never) — always [`Conformance::NeverReproducible`].
    /// * [`Sometimes`](Reproducibility::Sometimes) — reproducible iff every
    ///   required flag is present and no breaking flag is; otherwise
    ///   [`Conformance::Conditional`] naming the missing required and the
    ///   present breaking flags.
    pub fn assess<'a, I>(&self, args: I) -> Conformance
    where
        I: IntoIterator<Item = &'a str>,
    {
        match self.reproducibility {
            Reproducibility::Always => Conformance::Reproducible,
            Reproducibility::Never => Conformance::NeverReproducible,
            Reproducibility::Sometimes => {
                let present: BTreeSet<String> =
                    args.into_iter().filter_map(|arg| self.recognize(arg)).collect();

                let missing_required: BTreeSet<String> = self
                    .required_flags
                    .difference(&present)
                    .cloned()
                    .collect();
                let present_breaking: BTreeSet<String> = self
                    .breaking_flags
                    .intersection(&present)
                    .cloned()
                    .collect();

                if missing_required.is_empty() && present_breaking.is_empty() {
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
    /// The program is conditionally reproducible and this invocation does not
    /// meet the conditions: some required flags are absent and/or some breaking
    /// flags are present. At least one of the two sets is non-empty.
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

    /// A tiny recognizer for exercising the predicate: strips any `=value` and
    /// normalizes `-O<n>` to `-O`.
    fn recognize_sample(arg: &str) -> Option<String> {
        let head = arg.split('=').next().unwrap_or(arg);
        if let Some(rest) = head.strip_prefix("-O") {
            if rest.chars().all(|c| c.is_ascii_digit()) {
                return Some("-O".to_owned());
            }
        }
        if head.starts_with("--") {
            return Some(head.to_owned());
        }
        None
    }

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
    fn default_recognizer_recognizes_nothing() {
        let spec = ReproducibilitySpec::new(Reproducibility::Always, [] as [String; 0], [] as [String; 0]);
        assert_eq!(spec.recognize("--anything"), None);
    }

    #[test]
    fn custom_recognizer_normalizes_arguments() {
        let spec = ReproducibilitySpec::new(
            Reproducibility::Sometimes,
            ["--deterministic"],
            ["-O"],
        )
        .with_recognizer(recognize_sample);

        // `=value` is stripped down to the canonical option.
        assert_eq!(
            spec.recognize("--sysroot=/opt/x"),
            Some("--sysroot".to_owned())
        );
        // `-O2` normalizes to `-O`.
        assert_eq!(spec.recognize("-O2"), Some("-O".to_owned()));
        // Unrecognized arguments yield None.
        assert_eq!(spec.recognize("input.c"), None);
    }

    #[test]
    fn specs_compare_by_value() {
        let a = ReproducibilitySpec::new(Reproducibility::Never, ["--x"], ["--y"]);
        let b = ReproducibilitySpec::new(Reproducibility::Never, ["--x"], ["--y"]);
        assert_eq!(a, b);
    }

    /// Build a set from string literals, for terse assertions.
    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn always_conforms_regardless_of_args() {
        let spec = ReproducibilitySpec::new(Reproducibility::Always, ["--x"], ["--y"]);
        assert_eq!(spec.assess(["--y"]), Conformance::Reproducible);
        assert_eq!(spec.assess([] as [&str; 0]), Conformance::Reproducible);
    }

    #[test]
    fn never_is_always_non_reproducible() {
        let spec = ReproducibilitySpec::new(Reproducibility::Never, [] as [&str; 0], [] as [&str; 0]);
        assert_eq!(spec.assess(["--anything"]), Conformance::NeverReproducible);
    }

    #[test]
    fn sometimes_conforms_when_required_present_and_no_breaking() {
        let spec = ReproducibilitySpec::new(
            Reproducibility::Sometimes,
            ["--deterministic"],
            ["-O"],
        )
        .with_recognizer(recognize_sample);
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
        )
        .with_recognizer(recognize_sample);
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
        .with_recognizer(recognize_sample);
        // -O2 is recognized as -O (a breaking flag); --timestamp is absent.
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
        )
        .with_recognizer(recognize_sample);
        assert_eq!(
            spec.assess(["--timestamp"]),
            Conformance::Conditional {
                missing_required: set(&["--deterministic"]),
                present_breaking: set(&["--timestamp"]),
            }
        );
    }
}
