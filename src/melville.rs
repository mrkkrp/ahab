//! A little literary flourish: lines from Herman Melville's *Moby-Dick* (1851)
//! appended to Ahab's error output when violations are found.
//!
//! These are not the captain's abstract musings aimed at the whale, but lines
//! aimed at *people* — commands, rebukes, and expressions of displeasure — so
//! they read as dissatisfaction with the offending, non-reproducible build. We
//! don't track who originally spoke each line (Ahab, Peleg, …): we take a little
//! artistic license and just use the words.
//!
//! Which line is chosen is decided deterministically from a hash of the
//! violations, so the same set of problems always yields the same quote.

use std::hash::{Hash, Hasher};

/// Crew- and person-directed lines of command, impatience, and displeasure,
/// drawn from the novel. Suitable as an expression of the captain's
/// dissatisfaction.
const QUOTES: &[&str] = &[
    "Don't aggravate me—I won't have it.",
    "Process wrapper be damned. Talk not that lingo to me.",
    "I'll take that leg away from thy stern, if ever thou talkest of the nix store to me again.",
    "Fiery pit! fiery pit! ye insult me, man; past all natural bearing, ye insult me.",
    "Out of the cabin, ye canting, drab-colored son of a wooden gun—a straight wake with ye!",
    "Down, dog, and kennel!",
    "Thou art but too good a fellow, Starbuck. But what's this long face about?",
    "Take off thine eye! more intolerable than fiends' glarings is a doltish stare!",
    "Look ye, Starbuck, all visible objects are but as pasteboard masks—stand not between me and my purpose.",
    "Ha! boy, come back? bad pennies come not sooner.",
    "Stab me not with that keen steel! cant them; cant them over!",
    "Swerve me? ye cannot swerve me, else ye swerve yourselves! man has ye there.",
    "Are you a man that would take a whole month to think out a thing so simple?",
];

/// Select a quote deterministically from the hash of `key`.
///
/// The same `key` (for us, the collection of violations) always maps to the same
/// quote; different keys spread across the collection. Uses the standard
/// library's default hasher, which is deterministic for a given value within a
/// build.
pub fn quote_for<K: Hash>(key: &K) -> &'static str {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut hasher);
    let index = (hasher.finish() % QUOTES.len() as u64) as usize;
    QUOTES[index]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_collection_is_non_empty_and_well_formed() {
        assert!(!QUOTES.is_empty());
        assert!(QUOTES.iter().all(|q| !q.is_empty()));
    }

    #[test]
    fn selection_is_deterministic_for_a_given_key() {
        let key = vec!["a".to_owned(), "b".to_owned()];
        assert_eq!(quote_for(&key), quote_for(&key));
    }

    #[test]
    fn different_keys_can_select_different_quotes() {
        // Not guaranteed for any two keys, but across a spread of inputs we
        // should see more than one distinct quote chosen.
        let distinct: std::collections::BTreeSet<_> =
            (0..100).map(|i| quote_for(&i)).collect();
        assert!(distinct.len() > 1, "selection never varied across 100 keys");
    }

    #[test]
    fn selected_quote_is_from_the_collection() {
        let q = quote_for(&"anything");
        assert!(QUOTES.contains(&q));
    }
}
