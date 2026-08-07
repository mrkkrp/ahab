//! The hardcoded library of known [`ReproducibilitySpec`]s, keyed by
//! program.

use std::collections::HashMap;
use std::sync::OnceLock;

use super::ReproducibilitySpec;
use super::program_id::ProgramId;

/// What the library knows about one program.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// The program has its own spec.
    Spec(ReproducibilitySpec),
    /// The program is reproducible under exactly the same conditions as
    /// this other program. Look that one up instead.
    SameAs(ProgramId),
}

/// How many [`Entry::SameAs`] hops to follow before giving up.
const MAX_SYNONYM_HOPS: usize = 16;

/// The library as authored, in source order.
fn entries() -> Vec<(ProgramId, Entry)> {
    Vec::new()
}

/// The library, indexed by program. Built from [`entries`] on first use.
fn library() -> &'static HashMap<ProgramId, Entry> {
    static LIBRARY: OnceLock<HashMap<ProgramId, Entry>> = OnceLock::new();
    LIBRARY.get_or_init(|| entries().into_iter().collect())
}

/// Look up the reproducibility spec for `program`, following any synonyms.
///
/// Returns the program that actually carried the spec together with the
/// spec itself. That program is `program` when it has its own entry, and
/// the far end of its synonym chain otherwise—so comparing the two tells a
/// caller whether a synonym was resolved, and which one answered.
///
/// Returns `None` when we have no spec for that program.
pub fn lookup(
    program: &ProgramId,
) -> Option<(&'static ProgramId, &'static ReproducibilitySpec)> {
    resolve(library(), program)
}

/// Follow [`Entry::SameAs`] links from `program` until reaching one that
/// carries its own spec, returning that program and its spec.
fn resolve<'a>(
    library: &'a HashMap<ProgramId, Entry>,
    program: &ProgramId,
) -> Option<(&'a ProgramId, &'a ReproducibilitySpec)> {
    let mut key = program;
    let mut hops = 0;

    loop {
        let (found, entry) = library.get_key_value(key)?;
        match entry {
            Entry::Spec(spec) => return Some((found, spec)),
            Entry::SameAs(target) => {
                hops += 1;
                if hops > MAX_SYNONYM_HOPS {
                    return None;
                }
                key = target;
            }
        }
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

    /// Index a list of entries the way [`library`] does.
    fn index(
        entries: Vec<(ProgramId, Entry)>,
    ) -> HashMap<ProgramId, Entry> {
        entries.into_iter().collect()
    }

    /// Resolve `program` in a synthetic `library` to the spec that answers for it.
    fn lookup_in(
        library: &HashMap<ProgramId, Entry>,
        program: &ProgramId,
    ) -> Option<ReproducibilitySpec> {
        resolve(library, program).map(|(_, spec)| spec.clone())
    }

    /// Resolve `program` in a synthetic `library` to the program that answered.
    fn canonical_in<'a>(
        library: &'a HashMap<ProgramId, Entry>,
        program: &ProgramId,
    ) -> Option<&'a ProgramId> {
        resolve(library, program).map(|(canonical, _)| canonical)
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

    // ---- the real library ----

    #[test]
    fn library_is_empty_so_everything_is_unknown() {
        assert!(lookup(&ProgramId::of("/usr/bin/gcc")).is_none());
        assert!(
            lookup(&ProgramId::of("external/llvm+/bin/clang")).is_none()
        );
        assert!(lookup(&ProgramId::of("")).is_none());
    }

    #[test]
    fn every_synonym_in_the_library_reaches_a_spec() {
        // Guards the library as it grows: a dangling or cyclic synonym would
        // otherwise make a program silently unknown rather than fail loudly.
        for (program, _) in entries() {
            assert!(
                lookup(&program).is_some(),
                "{program} does not resolve to a spec: its synonym chain is \
                 dangling or cyclic",
            );
        }
    }

    #[test]
    fn no_key_appears_twice_in_the_library() {
        // Indexing keeps the last of a repeated key and drops the rest, so a
        // duplicate would silently discard an entry someone wrote.
        let authored = entries();
        assert_eq!(
            authored.len(),
            index(entries()).len(),
            "the library contains a duplicate key",
        );
        // Name it, so the failure above is actionable.
        for (i, (program, _)) in authored.iter().enumerate() {
            let duplicate = authored
                .iter()
                .skip(i + 1)
                .any(|(other, _)| other == program);
            assert!(
                !duplicate,
                "{program} appears more than once in the library"
            );
        }
    }

    // ---- resolution, against synthetic libraries ----

    #[test]
    fn a_program_with_its_own_spec_resolves_to_it() {
        let library = index(vec![(a(), Entry::Spec(always()))]);
        assert_eq!(lookup_in(&library, &a()), Some(always()));
    }

    #[test]
    fn an_unknown_program_resolves_to_nothing() {
        let library = index(vec![(a(), Entry::Spec(always()))]);
        assert_eq!(lookup_in(&library, &b()), None);
    }

    #[test]
    fn a_synonym_resolves_to_its_targets_spec() {
        // The motivating case: a wrapper sharing its compiler's conditions.
        let clang = ProgramId::extension(
            "llvm",
            "llvm_toolchain_minimal",
            "bin/clang",
        );
        let clangxx = ProgramId::extension(
            "llvm",
            "llvm_toolchain_minimal",
            "bin/clang++",
        );
        let library = index(vec![
            (clang.clone(), Entry::Spec(never())),
            (clangxx.clone(), Entry::SameAs(clang.clone())),
        ]);
        assert_eq!(lookup_in(&library, &clangxx), Some(never()));
        // And the alias did not disturb the program it points at.
        assert_eq!(lookup_in(&library, &clang), Some(never()));
    }

    #[test]
    fn synonyms_may_chain() {
        let library = index(vec![
            (a(), Entry::Spec(always())),
            (b(), Entry::SameAs(a())),
            (c(), Entry::SameAs(b())),
        ]);
        assert_eq!(lookup_in(&library, &c()), Some(always()));
    }

    #[test]
    fn several_synonyms_may_share_one_target() {
        let library = index(vec![
            (a(), Entry::Spec(always())),
            (b(), Entry::SameAs(a())),
            (c(), Entry::SameAs(a())),
        ]);
        assert_eq!(lookup_in(&library, &b()), Some(always()));
        assert_eq!(lookup_in(&library, &c()), Some(always()));
    }

    #[test]
    fn a_synonym_pointing_nowhere_resolves_to_nothing() {
        // Conservative: an unknown program is reported, not silently passed.
        let library = index(vec![(b(), Entry::SameAs(a()))]);
        assert_eq!(lookup_in(&library, &b()), None);
    }

    #[test]
    fn a_synonym_cycle_terminates() {
        let library = index(vec![
            (a(), Entry::SameAs(b())),
            (b(), Entry::SameAs(a())),
        ]);
        assert_eq!(lookup_in(&library, &a()), None);
    }

    #[test]
    fn a_self_referential_synonym_terminates() {
        let library = index(vec![(a(), Entry::SameAs(a()))]);
        assert_eq!(lookup_in(&library, &a()), None);
    }

    #[test]
    fn resolution_reports_the_program_that_carried_the_spec() {
        let library = index(vec![
            (a(), Entry::Spec(always())),
            (b(), Entry::SameAs(a())),
            (c(), Entry::SameAs(b())),
        ]);
        // A program with its own spec answers for itself.
        assert_eq!(canonical_in(&library, &a()), Some(&a()));
        // A synonym reports its target, not itself.
        assert_eq!(canonical_in(&library, &b()), Some(&a()));
        // And a chain reports the far end, not the next link.
        assert_eq!(canonical_in(&library, &c()), Some(&a()));
    }

    #[test]
    fn a_chain_longer_than_the_hop_limit_gives_up() {
        // A chain of links numbered 0..=n, with the spec at the far end.
        let chain = |links: usize| {
            let hop =
                |i: usize| ProgramId::module("m", &format!("bin/{i}"));
            let mut entries: Vec<(ProgramId, Entry)> = (0..links)
                .map(|i| (hop(i), Entry::SameAs(hop(i + 1))))
                .collect();
            entries.push((hop(links), Entry::Spec(always())));
            (index(entries), hop(0))
        };

        // Exactly at the bound it resolves; one link further it gives up.
        let (library, start) = chain(MAX_SYNONYM_HOPS);
        assert_eq!(lookup_in(&library, &start), Some(always()));

        let (library, start) = chain(MAX_SYNONYM_HOPS + 1);
        assert_eq!(lookup_in(&library, &start), None);
    }
}
