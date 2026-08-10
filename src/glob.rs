//! Globs: the pattern language Ahab matches strings with.

use std::fmt;

/// A glob: a pattern of literal text, `*` (any run of characters, `/`
/// included) and `?` (exactly one character).
///
/// `*` spans `/` on purpose. The alternative—`*` stopping at a separator,
/// with `**` to cross one—is more expressive, but the expressiveness buys
/// little here and the failure mode is bad: `//third_party/*` would quietly
/// match nothing rather than the subtree the author plainly meant. One
/// wildcard that always does the obvious thing is worth more than two that
/// need a rule to tell apart.
///
/// There is no escape syntax, so a pattern cannot match a literal `*` or
/// `?`. Neither occurs in a Bazel label, a mnemonic, or any path we have
/// seen leak into an action.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Glob {
    /// The pattern as written. First field, so the derived ordering is the
    /// ordering of the pattern—everything after it is a function of it.
    pattern: String,
    /// What the pattern turned out to be, decided once.
    shape: Shape,
}

/// The shape of a pattern, worked out when it is compiled.
///
/// Matching is on the hot path—every argument of every action, against
/// every pattern of every clause—and the general algorithm has to index
/// both sides, which means walking the characters of each. Almost every
/// pattern anyone writes is one of the first four shapes, and those are
/// answerable by a substring test that touches no memory at all.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Shape {
    /// No wildcards: the text must equal the pattern.
    Literal,
    /// `abc*`: the text must start with this.
    Prefix(String),
    /// `*abc`: the text must end with this.
    Suffix(String),
    /// `*abc*`: the text must contain this.
    Contains(String),
    /// Anything else, matched by the general algorithm over these
    /// characters.
    General(Vec<char>),
}

impl Glob {
    /// Compile a pattern. Every string is a valid glob—there is no syntax
    /// to get wrong—so this cannot fail.
    pub fn new(pattern: &str) -> Glob {
        let stars = pattern.matches('*').count();
        let inner = pattern.trim_start_matches('*').trim_end_matches('*');
        let simple = !inner.contains(['*', '?']);

        let shape = match (stars, simple) {
            (0, _) if !pattern.contains('?') => Shape::Literal,
            (1, true) if pattern.ends_with('*') => {
                Shape::Prefix(inner.to_owned())
            }
            (1, true) if pattern.starts_with('*') => {
                Shape::Suffix(inner.to_owned())
            }
            (2, true)
                if pattern.starts_with('*') && pattern.ends_with('*') =>
            {
                Shape::Contains(inner.to_owned())
            }
            _ => Shape::General(pattern.chars().collect()),
        };

        Glob {
            pattern: pattern.to_owned(),
            shape,
        }
    }

    /// Whether the whole of `text` matches.
    pub fn matches(&self, text: &str) -> bool {
        let pattern = match &self.shape {
            Shape::Literal => return self.pattern == text,
            Shape::Prefix(what) => return text.starts_with(what.as_str()),
            Shape::Suffix(what) => return text.ends_with(what.as_str()),
            Shape::Contains(what) => return text.contains(what.as_str()),
            Shape::General(chars) => chars,
        };
        let text: Vec<char> = text.chars().collect();

        let (mut p, mut t) = (0, 0);
        // Where to resume from if the pattern runs aground: the `*` we last
        // passed, and how much of the text it had consumed by then.
        let mut star: Option<(usize, usize)> = None;

        while t < text.len() {
            if p < pattern.len()
                && (pattern[p] == '?' || pattern[p] == text[t])
            {
                p += 1;
                t += 1;
            } else if p < pattern.len() && pattern[p] == '*' {
                star = Some((p, t));
                p += 1;
            } else if let Some((at, consumed)) = star {
                p = at + 1;
                t = consumed + 1;
                star = Some((at, consumed + 1));
            } else {
                return false;
            }
        }

        // Trailing `*`s may still match the empty remainder; anything else
        // left over is text the pattern demanded and did not get.
        pattern[p..].iter().all(|c| *c == '*')
    }
}

impl std::borrow::Borrow<str> for Glob {
    fn borrow(&self) -> &str {
        &self.pattern
    }
}

impl fmt::Display for Glob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_glob_without_wildcards_is_exact() {
        let glob = Glob::new("CppCompile");
        assert!(glob.matches("CppCompile"));
        assert!(!glob.matches("CppCompiler"));
        assert!(!glob.matches("MyCppCompile"));
        assert!(!glob.matches(""));
    }

    #[test]
    fn a_star_spans_slashes() {
        let glob = Glob::new("/usr/include/*");
        assert!(glob.matches("/usr/include/stdio.h"));
        assert!(glob.matches("/usr/include/sys/types.h"));
        assert!(glob.matches("/usr/include/"));
        assert!(!glob.matches("/usr/local/include/stdio.h"));
    }

    #[test]
    fn a_star_matches_the_empty_string() {
        assert!(Glob::new("*").matches(""));
        assert!(Glob::new("**").matches(""));
        assert!(Glob::new("a*").matches("a"));
        assert!(Glob::new("*a").matches("a"));
    }

    #[test]
    fn a_question_mark_matches_exactly_one_character() {
        let glob = Glob::new("gcc-?");
        assert!(glob.matches("gcc-9"));
        assert!(!glob.matches("gcc-"));
        assert!(!glob.matches("gcc-11"));
    }

    #[test]
    fn a_glob_is_anchored_at_both_ends() {
        let glob = Glob::new("*/bin/*");
        assert!(glob.matches("@llvm//bin/clang"));
        assert!(!glob.matches("bin/clang"));
    }

    #[test]
    fn a_glob_backtracks_past_a_false_start() {
        // The first `ab` is a dead end: the pattern only fits if the star
        // gives it back and consumes further.
        assert!(Glob::new("*abc").matches("abxabc"));
        assert!(Glob::new("a*b*c").matches("axxbxxc"));
        assert!(!Glob::new("*abc").matches("abxab"));
    }

    #[test]
    fn a_glob_compares_whole_characters() {
        // Multi-byte input must not be sliced mid-character.
        assert!(Glob::new("caf?").matches("café"));
        assert!(Glob::new("*é").matches("café"));
    }
}
