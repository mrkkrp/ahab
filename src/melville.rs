//! A little literary flourish: lines from Herman Melville's *Moby-Dick*
//! (1851) appended to Ahab's error output when violations are found.
//!
//! These are not the captain's abstract musings aimed at the whale, but
//! lines aimed at people—commands, rebukes, and expressions of
//! displeasure—so they read as dissatisfaction with the offending,
//! non-reproducible build. We don't track who originally spoke each line
//! (Ahab, Peleg, …): we take a little artistic license and just use the
//! words.
//!
//! Which line is chosen is decided deterministically from a hash of the
//! violations, so the same set of problems always yields the same quote.

use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};

use crate::checks::Violation;

/// Crew- and person-directed lines of command, impatience, and displeasure,
/// drawn from the novel. Suitable as an expression of the captain's
/// dissatisfaction.
///
/// Each is paired with the words in it that name what he is cross about, or
/// `None` where he is simply cross. The named fragment includes its
/// article, so that whatever replaces it can bring its own—"the nix store"
/// reads correctly where a bare program name would not.
const QUOTES: &[(&str, Option<&str>)] = &[
    (
        "Hard down out of that! Mind what I said about the marchant service—don't aggravate me—I won't have it.",
        Some("the marchant service"),
    ),
    (
        "Merchant service be damned. Talk not that lingo to me.",
        Some("Merchant service"),
    ),
    (
        "I'll take that leg away from thy stern, if ever thou talkest of the marchant service to me again.",
        Some("the marchant service"),
    ),
    (
        "Fiery pit! fiery pit! ye insult me, man; past all natural bearing, ye insult me.",
        None,
    ),
    (
        "It's an all-fired outrage to tell any human creature that he's bound to hell.",
        None,
    ),
    (
        "Out of the cabin, ye canting, drab-coloured son of a wooden gun—a straight wake with ye!",
        None,
    ),
    (
        "Below to thy nightly grave; where such as ye sleep between shrouds, to use ye to the filling one at last.",
        None,
    ),
    (
        "But what's this long face about, Mr. Starbuck; wilt thou not chase the white whale?",
        Some("the white whale"),
    ),
    (
        "Take off thine eye! more intolerable than fiends' glarings is a doltish stare!",
        None,
    ),
    (
        "So, so; thou reddenest and palest; my heat has melted thee to anger-glow.",
        None,
    ),
    (
        "Hark ye yet again—the little lower layer. All visible objects, man, are but as pasteboard masks.",
        None,
    ),
    ("Ha! boy, come back? bad pennies come not sooner.", None),
    (
        "Stab me not with that keen steel! Cant them; cant them over! know ye not the goblet end?",
        None,
    ),
    (
        "Swerve me? ye cannot swerve me, else ye swerve yourselves! man has ye there.",
        None,
    ),
    (
        "Swerve me? The path to my fixed purpose is laid with iron rails, whereon my soul is grooved to run.",
        Some("my fixed purpose"),
    ),
    ("Why don't ye spring, I say, all of ye—spring!", None),
];

const _: () = assert!(!QUOTES.is_empty());

/// Roots of the filesystem whose name says more about a build than the path
/// does. Longest-lived habits first: a `/nix/store` path is about the nix
/// store, however much of `/usr` it also happens to mention.
const FAMILIAR_PLACES: &[(&str, &str)] = &[
    ("/nix/store", "the nix store"),
    ("/home/", "somebody's home directory"),
    ("/Users/", "somebody's home directory"),
    ("/tmp/", "the temp directory"),
    ("/opt/", "the opt directory"),
    ("/var/", "the var directory"),
    ("/usr/", "the host"),
];

/// What the report is mostly about, phrased so that it can stand where a
/// whale used to.
///
/// Three questions in turn, the first that answers winning: is the build
/// reaching into somewhere recognizable, is there a program it keeps
/// running, and failing both, what sort of trouble is this? Ties are
/// broken by name so that the same report always names the same offender.
fn subject(violations: &BTreeMap<Violation, usize>) -> String {
    let mut places: BTreeMap<&str, usize> = BTreeMap::new();
    let mut programs: BTreeMap<&str, usize> = BTreeMap::new();
    let mut kinds: BTreeMap<&str, usize> = BTreeMap::new();

    for (violation, count) in violations {
        let facets = violation.facets();
        *kinds.entry(facets.kind).or_insert(0) += count;

        let program = facets.program.map(|program| program.path.as_str());
        for path in facets.path.into_iter().chain(program) {
            if let Some((_, place)) = FAMILIAR_PLACES
                .iter()
                .find(|(root, _)| path.starts_with(root))
            {
                *places.entry(place).or_insert(0) += count;
            }
        }

        if let Some(path) = program {
            let name = path.rsplit('/').next().unwrap_or(path);
            *programs.entry(name).or_insert(0) += count;
        }
    }

    if let Some(place) = most_common(&places) {
        return place;
    }
    if let Some(program) = most_common(&programs) {
        return program;
    }

    match most_common(&kinds).as_deref() {
        Some("environment_leak") => "the name of whoever built it",
        Some("bad_path") => "that wayward PATH",
        Some("execution_requirement") => "thy sandbox-shunning ways",
        Some("absolute_path") => "these absolute paths",
        _ => "this build",
    }
    .to_owned()
}

/// The most frequent entry, ties broken by name so the answer does not
/// depend on iteration order.
fn most_common(counts: &BTreeMap<&str, usize>) -> Option<String> {
    counts
        .iter()
        .max_by(|(a_name, a_count), (b_name, b_count)| {
            a_count.cmp(b_count).then(b_name.cmp(a_name))
        })
        .map(|(name, _)| (*name).to_owned())
}

/// Put `subject` where the quote named its own grievance.
fn render(quote: (&str, Option<&str>), subject: &str) -> String {
    let (text, Some(fragment)) = quote else {
        return quote.0.to_owned();
    };
    let Some(at) = text.find(fragment) else {
        return text.to_owned();
    };

    // A phrase opening a sentence takes a capital; a program name is left
    // spelled the way its author spelled it, which is what the space tells
    // us apart—`the nix store` has one, `cc_wrapper.sh` does not.
    let subject = if at == 0 && subject.contains(' ') {
        let mut chars = subject.chars();
        match chars.next() {
            Some(first) => {
                first.to_uppercase().collect::<String>() + chars.as_str()
            }
            None => String::new(),
        }
    } else {
        subject.to_owned()
    };

    text.replacen(fragment, &subject, 1)
}

/// Select a quote deterministically from the violations, and point it at
/// whatever they are mostly about.
pub fn quote_for(violations: &BTreeMap<Violation, usize>) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    violations.hash(&mut hasher);
    let index = (hasher.finish() % QUOTES.len() as u64) as usize;
    render(QUOTES[index], &subject(violations))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::{ActionRef, LeakSite};
    use crate::reproducibility_spec::program_id::ProgramId;

    fn action() -> ActionRef {
        ActionRef {
            mnemonic: "Test".to_owned(),
            target: "//test:t".to_owned(),
        }
    }

    fn unknown_program(path: &str) -> Violation {
        Violation::UnknownProgram {
            action: action(),
            program: ProgramId::of(path),
            wrappers: Vec::new(),
        }
    }

    fn absolute_path(path: &str) -> Violation {
        Violation::AbsolutePath {
            action: action(),
            path: path.to_owned(),
            site: LeakSite::Argument {
                value: path.to_owned(),
            },
        }
    }

    fn bad_path() -> Violation {
        Violation::BadPath {
            action: action(),
            actual: "/opt/bin".to_owned(),
        }
    }

    fn report(violations: Vec<Violation>) -> BTreeMap<Violation, usize> {
        violations.into_iter().map(|v| (v, 1)).collect()
    }

    #[test]
    fn every_quote_is_non_empty() {
        // That the collection itself is non-empty is guaranteed at compile
        // time by the `const` assertion above.
        assert!(QUOTES.iter().all(|(text, _)| !text.is_empty()));
    }

    #[test]
    fn every_named_fragment_occurs_in_its_line() {
        // A fragment that has drifted out of its line would silently stop
        // being replaced, leaving the captain shouting about whaling.
        for (text, fragment) in QUOTES {
            if let Some(fragment) = fragment {
                assert!(
                    text.contains(fragment),
                    "{fragment:?} is not in {text:?}",
                );
            }
        }
    }

    #[test]
    fn a_recognizable_place_is_what_gets_named() {
        let report = report(vec![
            absolute_path("/nix/store/abc-gcc-15/bin/gcc"),
            unknown_program("/nix/store/abc-gcc-15/bin/gcc"),
        ]);
        assert_eq!(subject(&report), "the nix store");
    }

    #[test]
    fn a_program_is_named_when_no_place_is() {
        let report = report(vec![unknown_program(
            "external/rules_cc+x+local_config_cc/cc_wrapper.sh",
        )]);
        // Its file name only: the path it sits at is nobody's business.
        assert_eq!(subject(&report), "cc_wrapper.sh");
    }

    #[test]
    fn the_complaint_is_named_when_nothing_else_is() {
        assert_eq!(subject(&report(vec![bad_path()])), "that wayward PATH");
        assert_eq!(subject(&BTreeMap::new()), "this build");
    }

    #[test]
    fn the_subject_replaces_the_grievance_the_line_came_with() {
        let named =
            ("Talk not of the white whale.", Some("the white whale"));
        assert_eq!(
            render(named, "cc_wrapper.sh"),
            "Talk not of cc_wrapper.sh.",
        );
        // A line that names nothing is left alone.
        let unnamed = ("Down, dog, and kennel!", None);
        assert_eq!(
            render(unnamed, "the nix store"),
            "Down, dog, and kennel!"
        );
    }

    #[test]
    fn a_phrase_opening_a_sentence_takes_a_capital() {
        let opener =
            ("Merchant service be damned.", Some("Merchant service"));
        assert_eq!(
            render(opener, "the nix store"),
            "The nix store be damned.",
        );
        // But a program name keeps the spelling it was given.
        assert_eq!(
            render(opener, "cc_wrapper.sh"),
            "cc_wrapper.sh be damned.",
        );
    }

    #[test]
    fn selection_is_deterministic_for_a_given_report() {
        let report = report(vec![unknown_program("/usr/bin/gcc")]);
        assert_eq!(quote_for(&report), quote_for(&report));
    }
}
