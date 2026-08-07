//! The hardcoded library of known [`ReproducibilitySpec`]s, keyed by
//! program.

use std::collections::HashMap;
use std::sync::OnceLock;

use super::ReproducibilitySpec;
use super::program_id::{Origin, ProgramId};

/// What the library knows about one program.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// The program has its own spec.
    Spec(ReproducibilitySpec),
    /// The program is reproducible under exactly the same conditions as
    /// this other program. Look that one up instead.
    SameAs(ProgramId),
    /// The program is a wrapper: it runs another program named in its own
    /// arguments, and its reproducibility is that of the wrapped command.
    /// The [`Transition`] says where in the arguments to find it.
    Wraps(Transition),
}

/// How to find the wrapped command inside a wrapper's arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    /// The wrapped command begins immediately after the first argument
    /// equal to `separator`: the next argument is its program and the rest
    /// are its arguments.
    AfterSeparator { separator: String },
}

impl Transition {
    /// Extract the wrapped command from `args`, the wrapper's `argv[1..]`.
    ///
    /// `None` when the arguments do not match the rule—a wrapper invoked
    /// without its separator, or with nothing following it. A transition
    /// that does not fire leaves the wrapper itself as the program, which
    /// then has no spec and is reported as unknown rather than passed.
    fn apply<'a>(
        &self,
        args: &[&'a str],
    ) -> Option<(&'a str, Vec<&'a str>)> {
        match self {
            Transition::AfterSeparator { separator } => {
                let at = args
                    .iter()
                    .position(|arg| *arg == separator.as_str())?;
                let (program, rest) = args[at + 1..].split_first()?;
                Some((program, rest.to_vec()))
            }
        }
    }
}

/// How many entries to follow before giving up, counting synonyms and
/// wrapper transitions alike. Bounds a library that accidentally loops.
const MAX_RESOLUTION_STEPS: usize = 16;

/// The library as authored, in source order.
fn entries() -> Vec<(ProgramId, Entry)> {
    vec![
        (
            ProgramId::module(
                "rules_rust",
                "util/process_wrapper/process_wrapper",
            ),
            Entry::Wraps(Transition::AfterSeparator {
                separator: "--".to_owned(),
            }),
        ),
        (
            ProgramId::module(
                "rules_rust",
                "util/process_wrapper/bootstrap_process_wrapper.sh",
            ),
            Entry::Wraps(Transition::AfterSeparator {
                separator: "--".to_owned(),
            }),
        ),
    ]
}

/// The library, indexed by program. Built from [`entries`] on first use.
fn library() -> &'static HashMap<ProgramId, Entry> {
    static LIBRARY: OnceLock<HashMap<ProgramId, Entry>> = OnceLock::new();
    LIBRARY.get_or_init(|| entries().into_iter().collect())
}

/// What an action's command line turned out to be, once wrappers have been
/// unwrapped and synonyms followed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution<'a> {
    /// The program whose reproducibility actually decides the action's: the
    /// innermost command after unwrapping. Equal to the program asked about
    /// when nothing wrapped it.
    pub program: ProgramId,
    /// That program's arguments, i.e. its `argv[1..]`.
    pub args: Vec<&'a str>,
    /// The wrappers passed through to reach it, outermost first. Empty when
    /// the action ran the program directly.
    pub wrappers: Vec<ProgramId>,
    /// The spec answering for [`program`](Self::program), with the program
    /// that carried it—the same one unless a synonym was followed. `None`
    /// when the library knows nothing about it.
    pub spec: Option<(&'static ProgramId, &'static ReproducibilitySpec)>,
}

impl Resolution<'_> {
    /// The program whose spec judged [`program`](Self::program), when that
    /// is a different one—i.e. when a synonym was followed. `None` when the
    /// program answered for itself, or when there is no spec at all.
    ///
    /// The distinction is worth reporting: a verdict reached through a
    /// synonym is only as good as the claim that the two behave alike.
    pub fn synonym(&self) -> Option<&'static ProgramId> {
        self.spec
            .map(|(carrier, _)| carrier)
            .filter(|carrier| **carrier != self.program)
    }
}

/// Resolve what an action really runs, from its program and `argv[1..]`.
pub fn resolve(program: ProgramId, args: Vec<&str>) -> Resolution<'_> {
    resolve_in(library(), program, args)
}

/// Resolve against a given library, so tests can inject synthetic ones.
fn resolve_in<'a>(
    library: &'static HashMap<ProgramId, Entry>,
    program: ProgramId,
    args: Vec<&'a str>,
) -> Resolution<'a> {
    let mut program = program;
    let mut key = program.clone();
    let mut args = args;
    let mut wrappers = Vec::new();

    for _ in 0..MAX_RESOLUTION_STEPS {
        // A program from outside the build is a verdict in itself, and
        // unwrapping it would be pretending we know what it does: `bash -c`
        // runs a whole script, not a single command.
        if program.origin == Origin::System {
            break;
        }

        let Some((found, entry)) = library.get_key_value(&key) else {
            break;
        };

        match entry {
            Entry::Spec(spec) => {
                return Resolution {
                    program,
                    args,
                    wrappers,
                    spec: Some((found, spec)),
                };
            }
            Entry::SameAs(target) => key = target.clone(),
            Entry::Wraps(transition) => {
                let Some((wrapped, rest)) = transition.apply(&args) else {
                    // The rule did not fire, so we cannot say what ran.
                    // Leaving the wrapper in place reports it as unknown.
                    break;
                };
                wrappers.push(program);
                program = ProgramId::of(wrapped);
                key = program.clone();
                args = rest;
            }
        }
    }

    Resolution {
        program,
        args,
        wrappers,
        spec: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reproducibility_spec::Reproducibility;

    fn always() -> ReproducibilitySpec {
        ReproducibilitySpec::new(
            Reproducibility::Always,
            [] as [&str; 0],
            [] as [&str; 0],
        )
    }

    fn never() -> ReproducibilitySpec {
        ReproducibilitySpec::new(
            Reproducibility::Never,
            [] as [&str; 0],
            [] as [&str; 0],
        )
    }

    /// Index entries into a library with the `'static` lifetime the real one
    /// has. Leaks, which costs nothing in a test binary.
    fn index(
        entries: Vec<(ProgramId, Entry)>,
    ) -> &'static HashMap<ProgramId, Entry> {
        Box::leak(Box::new(entries.into_iter().collect()))
    }

    /// Resolve with no arguments, for tests that only care about programs.
    fn resolve_bare<'a>(
        library: &'static HashMap<ProgramId, Entry>,
        program: &ProgramId,
    ) -> Resolution<'a> {
        resolve_in(library, program.clone(), Vec::new())
    }

    /// The spec a synthetic library gives `program`, if any.
    fn spec_for(
        library: &'static HashMap<ProgramId, Entry>,
        program: &ProgramId,
    ) -> Option<ReproducibilitySpec> {
        resolve_bare(library, program).spec.map(|(_, s)| s.clone())
    }

    // Stand-in programs for the resolution tests.
    fn a() -> ProgramId {
        ProgramId::module("a", "bin/a")
    }

    fn b() -> ProgramId {
        ProgramId::module("b", "bin/b")
    }

    fn c() -> ProgramId {
        ProgramId::module("c", "bin/c")
    }

    /// A `--`-separated wrapper, the shape Bazel's own wrappers use.
    fn wraps_after_dashdash() -> Entry {
        Entry::Wraps(Transition::AfterSeparator {
            separator: "--".to_owned(),
        })
    }

    // ---- the real library ----

    #[test]
    fn library_is_empty_so_everything_is_unknown() {
        assert!(
            resolve(ProgramId::of("/usr/bin/gcc"), vec![])
                .spec
                .is_none()
        );
        assert!(
            resolve(ProgramId::of("external/llvm+/bin/clang"), vec![])
                .spec
                .is_none()
        );
    }

    #[test]
    fn every_synonym_in_the_library_points_at_a_real_entry() {
        // Guards the library as it grows: a dangling or cyclic synonym would
        // make a program silently unknown rather than fail loudly.
        //
        // Only synonyms can be checked this way. Where a wrapper resolves to
        // depends on the arguments it was handed, so a `Wraps` entry has no
        // static destination to validate.
        let library: HashMap<_, _> = entries().into_iter().collect();
        for (program, _) in entries() {
            let mut seen = vec![program.clone()];
            let mut at = &program;
            for _ in 0..MAX_RESOLUTION_STEPS {
                let Some(Entry::SameAs(target)) = library.get(at) else {
                    break;
                };
                assert!(
                    library.contains_key(target),
                    "{program}: synonym points at {target}, \
                     which is not in the library",
                );
                assert!(
                    !seen.contains(target),
                    "{program}: synonym chain cycles at {target}",
                );
                seen.push(target.clone());
                at = target;
            }
        }
    }

    #[test]
    fn no_key_appears_twice_in_the_library() {
        // Indexing keeps the last of a repeated key and drops the rest, so a
        // duplicate would silently discard an entry someone wrote.
        let authored = entries();
        let indexed: HashMap<_, _> = entries().into_iter().collect();
        assert_eq!(
            authored.len(),
            indexed.len(),
            "the library contains a duplicate key",
        );
    }

    // ---- synonyms ----

    #[test]
    fn a_program_with_its_own_spec_resolves_to_it() {
        let library = index(vec![(a(), Entry::Spec(always()))]);
        assert_eq!(spec_for(library, &a()), Some(always()));
    }

    #[test]
    fn an_unknown_program_resolves_to_no_spec() {
        let library = index(vec![(a(), Entry::Spec(always()))]);
        assert_eq!(spec_for(library, &b()), None);
    }

    #[test]
    fn a_synonym_resolves_to_its_targets_spec() {
        let library = index(vec![
            (a(), Entry::Spec(never())),
            (b(), Entry::SameAs(a())),
        ]);
        assert_eq!(spec_for(library, &b()), Some(never()));
        // And the alias did not disturb the program it points at.
        assert_eq!(spec_for(library, &a()), Some(never()));
    }

    #[test]
    fn synonyms_may_chain() {
        let library = index(vec![
            (a(), Entry::Spec(always())),
            (b(), Entry::SameAs(a())),
            (c(), Entry::SameAs(b())),
        ]);
        assert_eq!(spec_for(library, &c()), Some(always()));
    }

    #[test]
    fn a_synonym_pointing_nowhere_resolves_to_no_spec() {
        let library = index(vec![(b(), Entry::SameAs(a()))]);
        assert_eq!(spec_for(library, &b()), None);
    }

    #[test]
    fn a_synonym_cycle_terminates() {
        let library = index(vec![
            (a(), Entry::SameAs(b())),
            (b(), Entry::SameAs(a())),
        ]);
        assert_eq!(spec_for(library, &a()), None);
    }

    #[test]
    fn a_synonym_does_not_change_the_program_the_action_ran() {
        // A synonym says "judge it by these rules", not "it ran something
        // else". Reporting the target as the program would misname what the
        // action actually invoked, and would hide that a synonym was used
        // at all, since the carrier would then always equal the program.
        let library = index(vec![
            (a(), Entry::Spec(always())),
            (b(), Entry::SameAs(a())),
        ]);
        let resolved = resolve_bare(library, &b());
        assert_eq!(resolved.program, b());
        assert_eq!(resolved.spec.map(|(carrier, _)| carrier), Some(&a()));
        assert_eq!(resolved.synonym(), Some(&a()));
    }

    #[test]
    fn a_program_with_its_own_spec_reports_no_synonym() {
        let library = index(vec![(a(), Entry::Spec(always()))]);
        assert_eq!(resolve_bare(library, &a()).synonym(), None);
    }

    #[test]
    fn an_unknown_program_reports_no_synonym() {
        let library = index(vec![(b(), Entry::SameAs(a()))]);
        assert_eq!(resolve_bare(library, &b()).synonym(), None);
    }

    // ---- wrappers ----

    #[test]
    fn a_wrapper_resolves_to_the_command_it_runs() {
        // The motivating case: process_wrapper's own flags say nothing about
        // reproducibility, so the question is re-asked of what follows `--`.
        let library = index(vec![
            (a(), wraps_after_dashdash()),
            (b(), Entry::Spec(never())),
        ]);
        let resolved = resolve_in(
            library,
            a(),
            vec!["--arg-file", "x", "--", "external/b+/bin/b", "--opt"],
        );
        assert_eq!(resolved.program, ProgramId::of("external/b+/bin/b"));
        assert_eq!(resolved.args, vec!["--opt"]);
        assert_eq!(resolved.wrappers, vec![a()]);
        assert_eq!(resolved.spec.map(|(_, s)| s.clone()), Some(never()));
    }

    #[test]
    fn a_wrappers_own_flags_are_not_assessed() {
        // Everything before the separator belongs to the wrapper, and must
        // not be mistaken for a flag of the wrapped program.
        let library = index(vec![(a(), wraps_after_dashdash())]);
        let resolved = resolve_in(
            library,
            a(),
            vec!["--subst", "pwd=x", "--", "external/b+/bin/b"],
        );
        assert_eq!(resolved.args, Vec::<&str>::new());
    }

    #[test]
    fn wrappers_may_nest() {
        // bootstrap_process_wrapper runs process_wrapper runs the real tool.
        let library = index(vec![
            (a(), wraps_after_dashdash()),
            (b(), wraps_after_dashdash()),
            (c(), Entry::Spec(always())),
        ]);
        let resolved = resolve_in(
            library,
            a(),
            vec![
                "--",
                "external/b+/bin/b",
                "--",
                "external/c+/bin/c",
                "-O2",
            ],
        );
        assert_eq!(resolved.program, c());
        assert_eq!(resolved.args, vec!["-O2"]);
        assert_eq!(resolved.wrappers, vec![a(), b()]);
    }

    #[test]
    fn a_wrapper_can_unwrap_onto_a_system_program() {
        // The reason this matters: without unwrapping, a wrapper hides the
        // fact that the action ultimately shells out to a host tool.
        let library = index(vec![(a(), wraps_after_dashdash())]);
        let resolved = resolve_in(library, a(), vec!["--", "/usr/bin/gcc"]);
        assert_eq!(resolved.program.origin, Origin::System);
        assert_eq!(resolved.wrappers, vec![a()]);
        assert!(resolved.spec.is_none());
    }

    #[test]
    fn a_transition_that_does_not_fire_leaves_the_wrapper_in_place() {
        // No separator: we cannot say what ran, so the wrapper stays and is
        // reported as unknown rather than waved through.
        let library = index(vec![(a(), wraps_after_dashdash())]);
        let resolved = resolve_in(library, a(), vec!["--arg-file", "x"]);
        assert_eq!(resolved.program, a());
        assert!(resolved.wrappers.is_empty());
        assert!(resolved.spec.is_none());
    }

    #[test]
    fn a_separator_with_nothing_after_it_does_not_fire() {
        let library = index(vec![(a(), wraps_after_dashdash())]);
        let resolved = resolve_in(library, a(), vec!["--"]);
        assert_eq!(resolved.program, a());
        assert!(resolved.spec.is_none());
    }

    #[test]
    fn only_the_first_separator_splits_the_command() {
        // A `--` among the wrapped program's own arguments is its business.
        let library = index(vec![
            (a(), wraps_after_dashdash()),
            (b(), Entry::Spec(always())),
        ]);
        let resolved = resolve_in(
            library,
            a(),
            vec!["--", "external/b+/bin/b", "--", "tail"],
        );
        assert_eq!(resolved.program, ProgramId::of("external/b+/bin/b"));
        assert_eq!(resolved.args, vec!["--", "tail"]);
    }

    #[test]
    fn a_wrapper_cycle_terminates() {
        // Each hop consumes a separator, so a self-wrapping entry runs out
        // of arguments; the step bound catches the case where it does not.
        let library = index(vec![(a(), wraps_after_dashdash())]);
        let args: Vec<&str> =
            std::iter::repeat_n(["--", "external/a+/bin/a"], 40)
                .flatten()
                .collect();
        let resolved = resolve_in(library, a(), args);
        assert!(resolved.spec.is_none());
    }
}
