//! Terminal color for Ahab's output.
//!
//! Color is decided once, at the edge, and carried as a [`Palette`] rather
//! than read from the environment wherever text is built. That keeps the
//! rendering functions pure and testable: a test asks for
//! [`Palette::plain`] and compares strings, without the result depending on
//! whether the test runner happened to have a terminal attached.
//!
//! The vocabulary is deliberately about meaning rather than
//! color—`action`, `finding`, `caution`—so the choice of magenta or cyan
//! lives here alone, and the call sites say what a piece of text is.

use std::io::IsTerminal;

/// Whether output to stderr should be colored.
///
/// Ahab's reports and diffs go to stderr, so that is what is tested. Color
/// only when it is a terminal, so redirected output stays plain text; and
/// never when `NO_COLOR` is set, which is the convention for turning color
/// off regardless.
pub(crate) fn stderr_supports_color() -> bool {
    std::env::var_os("NO_COLOR").is_none()
        && std::io::stderr().is_terminal()
}

/// Whether output to stdout should be colored, on the same terms.
///
/// Only the "checks passed" line goes to stdout, so this is asked far less
/// often than [`stderr_supports_color`]—but it has to be asked separately,
/// since a pipeline that captures one stream and not the other is ordinary.
pub(crate) fn stdout_supports_color() -> bool {
    std::env::var_os("NO_COLOR").is_none()
        && std::io::stdout().is_terminal()
}

/// How to style a piece of output, or that it should not be styled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Palette {
    enabled: bool,
}

impl Palette {
    /// A palette that emits ANSI escapes.
    pub(crate) fn color() -> Palette {
        Palette { enabled: true }
    }

    /// A palette that emits nothing, leaving text exactly as given.
    pub(crate) fn plain() -> Palette {
        Palette { enabled: false }
    }

    /// A palette that colors only if stderr can show it.
    pub(crate) fn for_stderr() -> Palette {
        if stderr_supports_color() {
            Palette::color()
        } else {
            Palette::plain()
        }
    }

    /// A palette that colors only if stdout can show it.
    pub(crate) fn for_stdout() -> Palette {
        if stdout_supports_color() {
            Palette::color()
        } else {
            Palette::plain()
        }
    }

    /// Wrap `text` in `code`, or return it untouched when disabled.
    fn paint(self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }

    /// A heading, such as the count of violations found.
    pub(crate) fn heading(self, text: &str) -> String {
        self.paint("1", text)
    }

    /// A quantity worth weighing: how many times a violation occurred.
    pub(crate) fn caution(self, text: &str) -> String {
        self.paint("33", text)
    }

    /// The action a violation belongs to.
    pub(crate) fn action(self, text: &str) -> String {
        self.paint("35", text)
    }

    /// The specific thing found: a path, a program, a flag. A hue rather
    /// than bold, because hue catches the eye where weight does not, and
    /// because bold is the one attribute terminals disagree about.
    pub(crate) fn finding(self, text: &str) -> String {
        self.paint("36", text)
    }

    /// Framing that should recede: list numbers, the sign-off.
    pub(crate) fn faint(self, text: &str) -> String {
        self.paint("2", text)
    }

    /// A line of a diff, by its leading marker.
    pub(crate) fn diff_line(self, line: &str) -> String {
        match line.chars().next() {
            Some('-') => self.paint("31", line),
            Some('+') => self.paint("32", line),
            Some('@') => self.paint("36", line),
            _ => line.to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_palette_leaves_text_alone() {
        let plain = Palette::plain();
        assert_eq!(plain.action("x"), "x");
        assert_eq!(plain.heading("x"), "x");
        assert_eq!(plain.diff_line("-x"), "-x");
    }

    #[test]
    fn a_color_palette_wraps_and_always_resets() {
        // A missing reset leaves the terminal tinted for everything after.
        let color = Palette::color();
        for painted in [
            color.heading("x"),
            color.caution("x"),
            color.action("x"),
            color.finding("x"),
            color.faint("x"),
            color.diff_line("+x"),
        ] {
            assert!(painted.starts_with('\x1b'), "{painted:?}");
            assert!(painted.ends_with("\x1b[0m"), "{painted:?}");
        }
    }

    #[test]
    fn diff_lines_are_colored_by_their_marker() {
        let color = Palette::color();
        assert!(color.diff_line("-gone").starts_with("\x1b[31m"));
        assert!(color.diff_line("+new").starts_with("\x1b[32m"));
        assert!(color.diff_line("@@ -1 +1 @@").starts_with("\x1b[36m"));
        // Context lines carry no marker and are left as they are.
        assert_eq!(color.diff_line(" same"), " same");
    }
}
