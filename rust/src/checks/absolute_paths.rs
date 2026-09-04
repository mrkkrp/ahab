//! Finding the absolute paths an action references.

use std::collections::HashSet;

use analysis_v2_proto::analysis::{Action, ActionGraphContainer};

use super::{ActionRef, LeakSite, Violation, target_labels};
use crate::param_files::{analyzable_strings, expanded_command_line};
use crate::reproducibility_spec::{
    library::Library, program_id::ProgramId,
};

/// Whether `byte` may be the first character of a name, i.e. may follow the
/// `/` that roots a path: the usual filename characters plus the ones that
/// show up in real paths (`.`, `-`, `_`, `+`, `~`, `@`, `%`), and anything
/// outside ASCII, since a filename may be in any language.
///
/// Glob metacharacters are deliberately absent even though
/// [`continues_path_run`] admits them. A pattern may hold one, but nothing
/// that *begins* with one is a path: `/*` opens a C comment far more often
/// than it names the root's children.
fn starts_path_run(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || !byte.is_ascii()
        || matches!(byte, b'.' | b'-' | b'_' | b'+' | b'~' | b'@' | b'%')
}

/// Whether `byte` may appear *within* a path run once one has begun:
/// anything [`starts_path_run`] admits, plus `/` itself and the glob
/// metacharacters, so that `/usr/lib/*` is reported as it is written rather
/// than truncated to the last separator it holds.
///
/// Brackets are not here, and are not an omission. They are legal in a
/// filename, so they cannot simply end a run; but `[` also opens a list, so
/// a `]` closing one ends the path inside it. That is a question about a
/// span rather than about one character, and [`path_run`] answers it by
/// balancing.
///
/// Every byte outside ASCII is admitted, which is what lets a run be sliced
/// out of the text it sits in: a run ends only at an ASCII byte or at the
/// end of the text, and never in the middle of a character.
fn continues_path_run(byte: u8) -> bool {
    starts_path_run(byte) || matches!(byte, b'/' | b'*' | b'?')
}

/// Whether `byte` is one a pattern language escapes with a backslash.
///
/// A run holding `\` before one of these is not a path but a regular
/// expression or a glob: the `/R\.class` of a filter names no directory
/// called `R`. A backslash before anything else belongs to the text around
/// the path rather than to a pattern—`\n` ends a line `printf` is about to
/// write, `\"` quotes a value, `\ ` stands for a space—so there the path
/// simply ends and is still reported.
fn escapes_a_metacharacter(byte: u8) -> bool {
    matches!(
        byte,
        b'.' | b'*'
            | b'?'
            | b'+'
            | b'['
            | b']'
            | b'('
            | b')'
            | b'{'
            | b'}'
            | b'|'
            | b'^'
            | b'$'
            | b'\\'
            | b'/'
    )
}

/// Compiler/linker flag prefixes that take a path glued directly after
/// them, with no `=` or space separator (e.g. `-I/usr/include`,
/// `-L/opt/lib`, `-isystem/usr/include`). A candidate `/` glued right onto
/// one of these is treated as the start of an absolute path.
const GLUED_FLAG_PREFIXES: &[&str] =
    &["-I", "-L", "-isystem", "-iquote", "-idirafter"];

/// Whether the candidate `/` at `slash` sits immediately after one of the
/// [`GLUED_FLAG_PREFIXES`], i.e. the text `prefix` occupies
/// `bytes[..slash]` ending exactly at the `/` and begins at a separator
/// boundary. This is what lets `-I/usr/include` be recognised while a
/// relative value like `-Irelative/include` (where the `/` does not sit
/// right after the flag) is left alone.
fn glued_onto_flag(bytes: &[u8], slash: usize) -> bool {
    GLUED_FLAG_PREFIXES.iter().any(|flag| {
        let flag = flag.as_bytes();
        slash >= flag.len()
            && &bytes[slash - flag.len()..slash] == flag
            // The flag itself must start at a boundary (start of string or
            // a non-path char before it), so we don't match a `-I` buried
            // inside some longer token.
            && (slash == flag.len()
                || !continues_path_run(bytes[slash - flag.len() - 1]))
    })
}

/// What kind of text a scanned string is, which decides what may put a path
/// in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SiteKind {
    /// Text a program receives as it stands: a command-line argument, a line
    /// of a param file, an environment variable value.
    Plain,
    /// A script a shell is about to run—the operand of `sh -c`, which for a
    /// genrule is the whole `cmd`.
    Shell,
}

/// The end of the path run beginning at the `/` at `start`, and whether that
/// run is a path at all.
fn path_run(bytes: &[u8], start: usize) -> (usize, bool) {
    let mut at = start + 1;
    let mut depth = 0usize;

    while at < bytes.len() {
        match bytes[at] {
            b'[' => depth += 1,
            b']' if depth > 0 => depth -= 1,
            b']' => break,
            b'\\' => {
                let pattern = bytes
                    .get(at + 1)
                    .is_some_and(|&next| escapes_a_metacharacter(next));
                return (at, !pattern);
            }
            byte if continues_path_run(byte) => {}
            _ => break,
        }
        at += 1;
    }

    (at, true)
}

/// Extract every absolute path embedded in `text`, read as a `kind` of site.
fn absolute_paths(text: &str, kind: SiteKind) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut paths = Vec::new();

    // The quote character of the section we are inside, if any.
    let mut quote: Option<u8> = None;
    // Whether a path may begin at the byte about to be read. The start of
    // the text is such a place.
    let mut may_start = true;
    let mut at = 0;

    while at < bytes.len() {
        let byte = bytes[at];

        // A `/` followed by a name, where a value may begin. A second `/`
        // is not a name, so a Bazel label like `//foo:bar` never starts one.
        if byte == b'/'
            && bytes.get(at + 1).is_some_and(|&next| starts_path_run(next))
            && (may_start || glued_onto_flag(bytes, at))
        {
            let (end, is_path) = path_run(bytes, at);
            if is_path {
                paths.push(text[at..end].to_owned());
            }
            at = end;
            may_start = false;
            continue;
        }

        match byte {
            // A backslash is transparent: neither a word character nor a
            // separator, so `\"` opens a value exactly as `"` does. Bazel
            // records a genrule's `cmd` as the shell will read it, and the
            // shell is about to take the escape off.
            b'\\' => {}
            b'\'' | b'"' => {
                may_start = match quote {
                    Some(open) if open == byte => {
                        quote = None;
                        false
                    }
                    Some(_) => false,
                    None => {
                        quote = Some(byte);
                        true
                    }
                };
            }
            // `=` assigns, `:` and `,` separate the elements of a list, `[`
            // opens one, and whitespace separates words. Each of them puts a
            // value after it.
            b'=' | b':' | b',' | b'[' => may_start = true,
            byte if byte.is_ascii_whitespace() => may_start = true,
            // The operators of a shell, which separate its words as surely
            // as a space does—but only where no quote makes them data.
            b'<' | b'>' | b'|' | b';' | b'&'
                if kind == SiteKind::Shell && quote.is_none() =>
            {
                may_start = true;
            }
            _ => may_start = false,
        }

        at += 1;
    }

    paths
}

/// Absolute paths that are allowed to appear in an action and must not be
/// reported as hermeticity violations.
///
/// `/dev/null` and `/proc/self/cwd` are special files that name the same
/// thing on every machine. The other two are placeholders that well-known
/// rule sets write into their actions on purpose:
///
/// * `/PLACEHOLDER_DEVELOPER_DIR` is what `apple_support` and `rules_swift`
///   map the Xcode developer directory onto, passing
///   `__BAZEL_XCODE_DEVELOPER_DIR__=/PLACEHOLDER_DEVELOPER_DIR` to
///   `-fdebug-prefix-map` and `-file-prefix-map`. It is the replacement
///   side of the map: the string that stands in the output *instead of*
///   wherever Xcode happens to be installed. Reporting it would be
///   reporting the very mechanism that keeps the developer directory out
///   of the artifact.
///
/// * `/bazel_rules_apple/fakepath` is the `--binary-file` argument
///   `rules_apple` hands to `appintentsmetadataprocessor`. Compile-time
///   extraction reads no binary, but the tool insists on the flag having a
///   value, so the rule invents one that cannot exist.
///
/// The list is closed on purpose: a project's own placeholder is a project
/// exception, not a default.
const ALLOWED_ABSOLUTE_PATHS: &[&str] = &[
    "/dev/null",
    "/proc/self/cwd",
    "/PLACEHOLDER_DEVELOPER_DIR",
    "/bazel_rules_apple/fakepath",
];

/// Whether an extracted absolute path is exempt from the absolute-path
/// check.
fn is_allowed_absolute_path(path: &str) -> bool {
    ALLOWED_ABSOLUTE_PATHS.contains(&path)
}

/// The shells whose `-c` operand is a script rather than an argument.
const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh"];

/// The script this action hands a shell to run, if that is what it does.
fn shell_script_operand(action: &Action) -> Option<&str> {
    let (executable, args) = action.arguments.split_first()?;
    let shell = executable.rsplit('/').next()?;
    if !SHELLS.contains(&shell) {
        return None;
    }
    let at = args.iter().position(|arg| arg == "-c")?;
    args.get(at + 1).map(String::as_str)
}

/// The strings with which this action's program declares a path inside the
/// artifact it produces, as the library describes that program.
///
/// Matched by value rather than by position, because the scan runs over the
/// raw command line followed by every param file, which is not the sequence
/// the program itself receives.
fn declared_path_strings<'a>(
    action: &'a Action,
    library: &Library,
) -> HashSet<&'a str> {
    let command_line = expanded_command_line(action);
    let Some((executable, args)) = command_line.split_first() else {
        return HashSet::new();
    };
    let resolved = library.resolve(
        ProgramId::of(executable.value),
        args.iter().map(|sourced| sourced.value).collect(),
    );
    let Some((_, spec)) = &resolved.spec else {
        return HashSet::new();
    };
    spec.declared_path_args(&resolved.args)
        .into_iter()
        .collect()
}

/// Find every absolute path (a `/`-rooted run) referenced in an action's
/// command line, in one of its param files, or in the value of any of its
/// `environment_variables`, and return one [`Violation`] per path found.
///
/// The environment variable literally named `PATH` is skipped: it is
/// expected to hold absolute paths and is governed separately by
/// [`super::check_path`]. Paths in [`ALLOWED_ABSOLUTE_PATHS`] (such as
/// `/dev/null`) are also skipped.
pub(super) fn check(
    container: &ActionGraphContainer,
    library: &Library,
) -> Vec<Violation> {
    let mut violations = Vec::new();
    let targets = target_labels(container);

    for action in &container.actions {
        // Worked out at the first path we would otherwise report, so that
        // the great majority of actions—which have no absolute path in them
        // at all—never pay for resolving their program a second time.
        let mut declared: Option<HashSet<&str>> = None;
        let shell_script = shell_script_operand(action);

        // Spilling a command line into a param file must not launder an
        // absolute path out of the report, so both are scanned.
        let program = usize::from(!action.arguments.is_empty());
        for sourced in analyzable_strings(action).into_iter().skip(program)
        {
            let kind = if shell_script == Some(sourced.value) {
                SiteKind::Shell
            } else {
                SiteKind::Plain
            };
            let paths = absolute_paths(sourced.value, kind);
            if paths.is_empty() {
                continue;
            }
            if declared
                .get_or_insert_with(|| {
                    declared_path_strings(action, library)
                })
                .contains(sourced.value)
            {
                continue;
            }
            for path in paths {
                if is_allowed_absolute_path(&path) {
                    continue;
                }
                violations.push(Violation::AbsolutePath {
                    action: ActionRef::of(action, &targets),
                    path,
                    site: LeakSite::of(sourced),
                });
            }
        }

        for kv in &action.environment_variables {
            if kv.key == "PATH" {
                continue;
            }
            for path in absolute_paths(&kv.value, SiteKind::Plain) {
                if is_allowed_absolute_path(&path) {
                    continue;
                }
                violations.push(Violation::AbsolutePath {
                    action: ActionRef::of(action, &targets),
                    path,
                    site: LeakSite::EnvVar {
                        key: kv.key.clone(),
                        value: kv.value.clone(),
                    },
                });
            }
        }
    }

    violations
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::EXPECTED_PATH;
    use crate::checks::tests::{
        action_with_args, action_with_env, assert_abs_path, container,
    };

    // ---- absolute_paths (the extractor): unit tests ----

    /// The paths in a string read as text handed to a program as it stands.
    fn plain(text: &str) -> Vec<String> {
        absolute_paths(text, SiteKind::Plain)
    }

    /// The paths in a string read as a script a shell is about to run.
    fn shell(text: &str) -> Vec<String> {
        absolute_paths(text, SiteKind::Shell)
    }

    #[test]
    fn extracts_a_bare_absolute_path() {
        assert_eq!(plain("/usr/bin"), vec!["/usr/bin".to_owned()]);
    }

    #[test]
    fn extracts_path_glued_after_a_flag_without_separator() {
        // -I/usr/include: the path starts mid-token, glued to the flag.
        assert_eq!(
            plain("-I/usr/include"),
            vec!["/usr/include".to_owned()]
        );
    }

    #[test]
    fn extracts_path_glued_after_isystem_flag() {
        assert_eq!(
            plain("-isystem/usr/include"),
            vec!["/usr/include".to_owned()]
        );
    }

    #[test]
    fn relative_value_after_a_flag_is_not_absolute() {
        // -Irelative/include: the `/` does not sit right after the flag, so the
        // value is relative and must not be flagged.
        assert!(plain("-Irelative/include").is_empty());
    }

    #[test]
    fn a_bracketed_segment_does_not_start_an_absolute_path() {
        // A SvelteKit rest-parameter route puts `[...id]` in a directory
        // name. The whole path is relative, so nothing absolute is in it.
        assert!(plain("src/routes/axes/[...id]/+page.svelte").is_empty());
    }

    #[test]
    fn a_bracketed_segment_is_part_of_the_path_it_sits_in() {
        // The group is a directory name, so the path runs through it
        // rather than stopping at the bracket—a truncated path would be
        // reported as a path that does not exist.
        assert_eq!(
            plain("/usr/lib/[abi]/libfoo.so"),
            vec!["/usr/lib/[abi]/libfoo.so"],
        );
    }

    #[test]
    fn a_bracket_opening_a_list_still_starts_a_path() {
        // The other reading of a bracket: not part of a name, but the
        // start of a list of them. Both paths are absolute and both are
        // reported, neither carrying the bracket that wraps them.
        assert_eq!(
            plain("--paths=[/usr/lib,/opt/lib]"),
            vec!["/usr/lib", "/opt/lib"],
        );
        assert_eq!(plain("[/usr/lib]"), vec!["/usr/lib"]);
    }

    #[test]
    fn extracts_path_glued_with_equals() {
        assert_eq!(
            plain("--sysroot=/opt/toolchain/sysroot"),
            vec!["/opt/toolchain/sysroot".to_owned()]
        );
    }

    #[test]
    fn extracts_each_path_in_a_colon_list() {
        assert_eq!(
            plain("/bin:/usr/bin:/usr/local/bin"),
            vec![
                "/bin".to_owned(),
                "/usr/bin".to_owned(),
                "/usr/local/bin".to_owned(),
            ]
        );
    }

    #[test]
    fn stops_a_run_at_separators() {
        // A comma and whitespace both terminate the run.
        assert_eq!(
            plain("/a/b,/c/d /e"),
            vec!["/a/b".to_owned(), "/c/d".to_owned(), "/e".to_owned()]
        );
    }

    #[test]
    fn keeps_dotted_and_dashed_path_characters() {
        assert_eq!(
            plain("/opt/gcc-12.2/lib/libfoo.so.1"),
            vec!["/opt/gcc-12.2/lib/libfoo.so.1".to_owned()]
        );
    }

    #[test]
    fn ignores_bare_slash_and_relative_paths() {
        assert!(plain("/").is_empty());
        assert!(plain("foo/bar").is_empty());
        assert!(plain("./rel/path").is_empty());
        assert!(plain("no paths here").is_empty());
    }

    #[test]
    fn ignores_double_slash_bazel_labels() {
        // //foo:bar is a Bazel label, not an absolute filesystem path.
        assert!(plain("//foo:bar").is_empty());
        // ...but a real path elsewhere in the same string is still found.
        assert_eq!(
            plain("//foo=/real/path"),
            vec!["/real/path".to_owned()]
        );
    }

    #[test]
    fn an_opening_quote_starts_a_path_and_a_closing_one_does_not() {
        // The quote before `/opt/x` opens the value. The one before
        // `/version` closes a field of a sed script, and what follows it
        // belongs to that script.
        assert_eq!(plain("-DFOO=\"/opt/x\""), vec!["/opt/x"]);
        assert!(
            plain(r#"sed -e 's/version = ""/version = "1.2.0"/' x"#)
                .is_empty()
        );
    }

    #[test]
    fn a_glob_does_not_start_a_path_but_belongs_to_one() {
        // `**/.svn/**` excludes a directory wherever it turns up; the `/`
        // after the stars separates the pattern's segments and roots
        // nothing. A cron expression reads the same way.
        assert!(plain("**/.svn/**").is_empty());
        assert!(plain("--exclude=**/*.o").is_empty());
        assert!(plain("*/5 * * * *").is_empty());
        // A glob that really is rooted counts, and is reported whole: a path
        // cut short at the `*` would be a path nothing has.
        assert_eq!(plain("/usr/lib/*"), vec!["/usr/lib/*"]);
        assert_eq!(plain("--include=/usr/lib/*.so"), vec!["/usr/lib/*.so"]);
        // A run may hold a `*` but may not begin with one, which is what
        // keeps a C comment from reading as the root's children.
        assert!(shell("echo '/* generated */' > x.c").is_empty());
    }

    #[test]
    fn ignores_a_character_class_that_excludes_the_separator() {
        // rules_js rewrites a launcher with `sed -E`, and the class in the
        // expression excludes `/` and `~`. Neither is a path.
        assert!(plain(r"s|([+][+][^/~]+)~([^/~]+)|\1+\2|g").is_empty());
        // A bracket that opens a list is not a class, and the paths in it
        // are still reported.
        assert_eq!(
            plain("[/usr/lib,/opt/lib]"),
            vec!["/usr/lib", "/opt/lib"],
        );
    }

    #[test]
    fn ignores_a_run_whose_backslash_escapes_a_metacharacter() {
        // `\.` escapes a dot for a matcher, so the run is that matcher's
        // text rather than a directory called `R`.
        assert!(plain(r"/R\.class,/BR\.class").is_empty());
        assert!(plain(r"s/a\/b/c/").is_empty());
    }

    #[test]
    fn a_backslash_around_a_path_still_leaves_a_path() {
        // The escapes a genrule writes belong to the text around the path,
        // not to a pattern: `\"` quotes the value, `\n` ends the line it is
        // written on, `\ ` stands for a space. The path ends at the
        // backslash and is reported.
        assert_eq!(
            shell(r#"echo \"/opt/toolchain/bin/cc\" > $@"#),
            vec!["/opt/toolchain/bin/cc"],
        );
        assert_eq!(
            shell(r#"printf "prefix=/opt/toolchain\n" > $@"#),
            vec!["/opt/toolchain"],
        );
        assert_eq!(plain(r"--sysroot=/opt/my\ toolchain"), vec!["/opt/my"]);
    }

    #[test]
    fn a_closing_markup_tag_is_not_a_directory() {
        // A genrule that writes XML holds `</manifest>`, which is a tag and
        // not a directory named `manifest`. Nothing quoted opens a value,
        // so the `<` leaves the tag name where it is.
        assert!(shell("echo '</manifest>' > $@").is_empty());
        assert!(shell("echo \"</ns:tag>\" > $@").is_empty());
        assert!(plain("</manifest>").is_empty());
        // The angle bracket of a redirection is an operator, not a tag: what
        // follows it is read, and where it is read from matters.
        assert_eq!(shell("cat < /etc/passwd"), vec!["/etc/passwd"]);
        assert_eq!(shell("cat </etc/passwd"), vec!["/etc/passwd"]);
        assert_eq!(shell("cat >/opt/out"), vec!["/opt/out"]);
    }

    #[test]
    fn a_path_rooted_at_an_expansion_is_not_absolute() {
        // `${pwd}` and `$(dirname x)` stand for wherever the build puts
        // them, so the `/` after the closing bracket separates the segments
        // of a path relative to that—it roots nothing. The same goes for a
        // template placeholder, wherever in the value it sits.
        assert!(plain("${pwd}/external/crate/lib.rs").is_empty());
        assert!(plain("${JAVA_HOME}/bin/javac").is_empty());
        assert!(shell("KEYTOOL=$(dirname ${BINS[1]})/keytool").is_empty());
        assert!(plain("{pkg}/com.example").is_empty());
        assert!(shell("sed 's/{pkg}/com.example/g' x").is_empty());
    }

    #[test]
    fn a_shebang_roots_nothing() {
        // A shebang is a thing a *file* begins with, and what is read here
        // is an argument. The `#!/bin/bash` of a script a genrule generates
        // is file content passing through one, and the `/bin/bash` that
        // genrule runs is reported as a program from outside the build
        // rather than twice over as a path.
        assert!(shell("cat <<'eof'\n#!/bin/bash\n").is_empty());
        assert!(plain("#!/usr/bin/env bash").is_empty());
        assert!(shell("echo '#!/bin/sh' > $@").is_empty());
        // What roots a path in such a script is what roots one anywhere.
        assert_eq!(shell("cat <<'eof'\ncp /opt/x .\n"), vec!["/opt/x"]);
    }

    #[test]
    fn a_shell_operator_separates_words() {
        assert_eq!(
            shell("source setup.sh; cp /opt/a /opt/b"),
            vec!["/opt/a", "/opt/b"],
        );
        assert_eq!(shell("cat x |/opt/tool"), vec!["/opt/tool"]);
        // Quoted, the same characters are data.
        assert!(shell("grep '^/usr/bin' x").is_empty());
        assert!(shell("awk '{print $1\"/\"$2}' x").is_empty());
    }

    // ---- absolute_paths: the closed list, checked byte by byte ----

    /// Every ASCII byte that roots a path when it sits just before the `/`.
    ///
    /// This is the whole rule restated as data, so that widening it takes
    /// editing this list and saying why. The bytes are, in order: tab, line
    /// feed, form feed, carriage return, space, the two quotes, `,`, `:`,
    /// `=` and `[`.
    const ROOTING_BYTES: &[u8] = b"\t\n\x0C\r \"',:=[";

    /// The operators a shell adds to [`ROOTING_BYTES`], which separate its
    /// words as surely as a space does.
    const ROOTING_IN_A_SHELL: &[u8] = b"&;<>|";

    /// The bytes that root a path in `kind` of site, found by trying each
    /// one in turn rather than by consulting the rule under test.
    fn rooting_bytes(kind: SiteKind) -> Vec<u8> {
        (0u8..=127)
            .filter(|byte| {
                // `x` before it, so nothing is rooted by the start of the
                // text and the byte alone has to do the work.
                let text = format!("x{}/usr/lib", *byte as char);
                !absolute_paths(&text, kind).is_empty()
            })
            .collect()
    }

    #[test]
    fn exactly_the_listed_bytes_root_a_path() {
        assert_eq!(rooting_bytes(SiteKind::Plain), ROOTING_BYTES);
    }

    #[test]
    fn a_script_adds_its_operators_and_nothing_else() {
        let mut expected: Vec<u8> =
            [ROOTING_BYTES, ROOTING_IN_A_SHELL].concat();
        expected.sort_unstable();
        assert_eq!(rooting_bytes(SiteKind::Shell), expected);
    }

    #[test]
    fn the_bytes_that_used_to_root_a_path_no_longer_do() {
        // Each of these was a "separator" under the old reading, which
        // asked whether the byte before the `/` merely looked like one.
        // They are the false positives of issue #12 and their kin, and the
        // test above is what keeps them out: none is on the list.
        for byte in b"*?\\^}){#!$" {
            let text = format!("x{}/usr/lib", *byte as char);
            assert!(
                absolute_paths(&text, SiteKind::Plain).is_empty(),
                "{text:?} should hold no path",
            );
        }
    }

    #[test]
    fn every_glued_flag_prefix_is_recognized_and_only_at_a_boundary() {
        for flag in GLUED_FLAG_PREFIXES {
            let text = format!("{flag}/usr/include");
            assert_eq!(
                plain(&text),
                vec!["/usr/include"],
                "{text:?} should hold a path",
            );
            // Glued onto the end of a longer word, a flag is not a flag:
            // the `-I` of `x-I/usr/include` is two characters that happen
            // to sit next to each other.
            let buried = format!("x{flag}/usr/include");
            assert!(
                plain(&buried).is_empty(),
                "{buried:?} should hold no path",
            );
        }
        // A flag that begins at a separator is still a flag.
        assert_eq!(plain("-Wl,-L/usr/lib"), vec!["/usr/lib"]);
    }

    // ---- absolute_paths: where a run ends ----

    #[test]
    fn a_run_ends_at_the_first_byte_a_path_may_not_hold() {
        for byte in b" \t\n\"'=:,;|&<>()^$#!" {
            let text = format!("/usr/lib{}x", *byte as char);
            assert_eq!(
                absolute_paths(&text, SiteKind::Shell),
                vec!["/usr/lib"],
                "{text:?} should end the run at the separator",
            );
        }
    }

    #[test]
    fn a_run_carries_on_through_the_characters_a_name_may_hold() {
        assert_eq!(
            plain("/opt/gcc-12.2+x_y~z@w%v/lib"),
            vec!["/opt/gcc-12.2+x_y~z@w%v/lib"],
        );
    }

    #[test]
    fn a_run_balances_the_brackets_it_passes_through() {
        assert_eq!(plain("/usr/[a[b]c]/lib"), vec!["/usr/[a[b]c]/lib"]);
        // An unbalanced `]` ends the run; an unbalanced `[` does not, since
        // a name may hold one.
        assert_eq!(plain("[/usr/lib]x"), vec!["/usr/lib"]);
        assert_eq!(plain("/usr/lib[a"), vec!["/usr/lib[a"]);
    }

    #[test]
    fn a_path_may_hold_characters_outside_ascii() {
        // A filename is in whatever language its author wrote it in, and a
        // path cut short at the first such character would be a path
        // nothing has.
        assert_eq!(
            plain("--flag=/opt/caf\u{e9}/bin"),
            vec!["/opt/caf\u{e9}/bin"]
        );
        assert_eq!(plain("/\u{e4}rger/x"), vec!["/\u{e4}rger/x"]);
        // Such a character is not a separator, so it roots nothing.
        assert!(plain("caf\u{e9}/usr/lib").is_empty());
        // ...but an ordinary separator after one still does.
        assert_eq!(plain("caf\u{e9} /usr/lib"), vec!["/usr/lib"]);
    }

    // ---- absolute_paths: quotes ----

    #[test]
    fn a_quote_is_read_as_opening_or_closing_by_what_came_before() {
        assert_eq!(plain("'/usr/lib'"), vec!["/usr/lib"]);
        assert_eq!(plain("--flag=\"/usr/lib\""), vec!["/usr/lib"]);
        // Closing, then opening again: only the second roots anything.
        assert_eq!(plain("\"a\"/b\"/usr/lib\""), vec!["/usr/lib"]);
        // An escaped quote counts, because the shell is about to take the
        // backslash off and what is left opens the value.
        assert_eq!(shell("echo \\\"/usr/lib\\\""), vec!["/usr/lib"]);
    }

    #[test]
    fn an_unbalanced_quote_does_not_hide_the_rest_of_the_text() {
        // The buildtools genrule writes a heredoc holding the words
        // "Bazel's Bash runfiles library", and that apostrophe opens a
        // quoted section that never closes. Whitespace separates words
        // either way, so a path after it is still found.
        assert_eq!(
            shell("# from Bazel's library\ncp /opt/x .\n"),
            vec!["/opt/x"],
        );
    }

    #[test]
    fn a_quote_of_the_other_kind_inside_one_is_data() {
        // The `'` here does not close the `"` section, so the `/` after it
        // roots nothing.
        assert!(shell("echo \"it's/usr/lib\"").is_empty());
    }

    // ---- absolute_paths: shell sites against plain ones ----

    #[test]
    fn only_a_script_reads_its_operators_as_separators() {
        for text in ["cat </etc/passwd", "x >/opt/out", "x |/opt/t"] {
            assert_eq!(shell(text).len(), 1, "{text:?} in a script");
            assert!(plain(text).is_empty(), "{text:?} as an argument");
        }
        // Quoted, they are data in a script too.
        assert!(shell("echo '</manifest>' >$@").is_empty());
    }

    // ---- absolute_paths: what comes out is always a path ----

    /// The bytes whose interactions decide every rule above.
    const PROBE_ALPHABET: &[u8] = b"/a.\\\"'[]}$<*= ";

    /// Call `check` with every string of `length` bytes over
    /// [`PROBE_ALPHABET`].
    fn every_probe_string(length: u32, mut check: impl FnMut(&str)) {
        let base = PROBE_ALPHABET.len() as u32;
        let mut buffer = Vec::with_capacity(length as usize);
        for mut code in 0..base.pow(length) {
            buffer.clear();
            for _ in 0..length {
                buffer.push(PROBE_ALPHABET[(code % base) as usize]);
                code /= base;
            }
            check(std::str::from_utf8(&buffer).expect("ASCII is UTF-8"));
        }
    }

    #[test]
    fn whatever_is_returned_is_a_rooted_substring_of_the_text() {
        // Exhaustive over the short strings made of the characters the
        // rules turn on: roughly forty thousand of them, in both kinds of
        // site. What is asserted is not which paths come out—the tests
        // above say that—but that nothing comes out which could not be a
        // path, and that the extractor has no input it cannot read.
        let mut with_a_path = 0;
        for kind in [SiteKind::Plain, SiteKind::Shell] {
            for length in 1..=4 {
                every_probe_string(length, |text| {
                    let mut cursor = 0;
                    let found = absolute_paths(text, kind);
                    with_a_path += usize::from(!found.is_empty());
                    for path in found {
                        assert!(
                            path.starts_with('/') && path.len() >= 2,
                            "{path:?} from {text:?} is not rooted",
                        );
                        for byte in path.bytes() {
                            assert!(
                                continues_path_run(byte)
                                    || byte == b'['
                                    || byte == b']',
                                "{path:?} from {text:?} holds {byte:?}",
                            );
                        }
                        // In order, and never overlapping what came before.
                        let at = text[cursor..].find(&path).unwrap_or_else(
                            || panic!("{path:?} is not in {text:?}"),
                        );
                        cursor += at + path.len();
                    }
                });
            }
        }
        // A positive control: a sweep that found nothing would satisfy
        // every assertion above while testing none of them.
        assert_eq!(with_a_path, 1516);
    }

    // ---- shell_script_operand ----

    #[test]
    fn the_operand_of_a_shell_is_the_script() {
        for program in
            ["/bin/bash", "bash", "external/x/bin/sh", "/bin/zsh", "ksh"]
        {
            let action =
                action_with_args("A", 1, &[program, "-c", "echo hi"]);
            assert_eq!(
                shell_script_operand(&action),
                Some("echo hi"),
                "{program} should be a shell",
            );
        }
    }

    #[test]
    fn nothing_else_has_a_script_to_read() {
        // Not a shell; a shell with no `-c`; a `-c` with nothing after it;
        // and an action with no command line at all.
        for arguments in [
            &["gcc", "-c", "foo.c"][..],
            &["/bin/bash", "script.sh"][..],
            &["/bin/bash", "-c"][..],
            &[][..],
        ] {
            let action = action_with_args("A", 1, arguments);
            assert_eq!(
                shell_script_operand(&action),
                None,
                "{arguments:?} names no script",
            );
        }
    }

    // ---- check: pathological cases (expect violations) ----

    #[test]
    fn absolute_path_in_argument_is_a_violation() {
        let c = container(vec![action_with_args(
            "CppCompile",
            1,
            &["tool", "-I/usr/include"],
        )]);
        let found = check(&c, &Library::default());
        assert_eq!(found.len(), 1);
        assert_abs_path(
            &found[0],
            "CppCompile",
            1,
            "/usr/include",
            LeakSite::Argument {
                value: "-I/usr/include".to_owned(),
            },
        );
    }

    #[test]
    fn absolute_path_in_env_value_is_a_violation() {
        let c = container(vec![action_with_env(
            "Genrule",
            2,
            &[("CC", "/usr/bin/gcc")],
        )]);
        let found = check(&c, &Library::default());
        assert_eq!(found.len(), 1);
        assert_abs_path(
            &found[0],
            "Genrule",
            2,
            "/usr/bin/gcc",
            LeakSite::EnvVar {
                key: "CC".to_owned(),
                value: "/usr/bin/gcc".to_owned(),
            },
        );
    }

    #[test]
    fn colon_list_argument_reports_each_path() {
        let c = container(vec![action_with_args(
            "A",
            1,
            &["tool", "/bin:/usr/bin"],
        )]);
        let found = check(&c, &Library::default());
        assert_eq!(found.len(), 2);
        assert_abs_path(
            &found[0],
            "A",
            1,
            "/bin",
            LeakSite::Argument {
                value: "/bin:/usr/bin".to_owned(),
            },
        );
        assert_abs_path(
            &found[1],
            "A",
            1,
            "/usr/bin",
            LeakSite::Argument {
                value: "/bin:/usr/bin".to_owned(),
            },
        );
    }

    #[test]
    fn path_env_var_is_skipped_by_absolute_path_check() {
        // PATH is expected to hold absolute paths and is governed by check_path;
        // the absolute-path check must not double-report it.
        let c = container(vec![action_with_env(
            "A",
            1,
            &[("PATH", EXPECTED_PATH)],
        )]);
        assert!(check(&c, &Library::default()).is_empty());
    }

    #[test]
    fn other_absolute_path_env_vars_are_still_flagged() {
        // Only the var literally named PATH is skipped; LD_LIBRARY_PATH is not.
        let c = container(vec![action_with_env(
            "A",
            1,
            &[("LD_LIBRARY_PATH", "/opt/lib")],
        )]);
        let found = check(&c, &Library::default());
        assert_eq!(found.len(), 1);
        assert_abs_path(
            &found[0],
            "A",
            1,
            "/opt/lib",
            LeakSite::EnvVar {
                key: "LD_LIBRARY_PATH".to_owned(),
                value: "/opt/lib".to_owned(),
            },
        );
    }

    // ---- check: paths the program declares ----

    /// An `img manifest` command line, as rules_img writes it: an in-image
    /// working directory, and a real output under `bazel-out`.
    fn image_manifest_action() -> Action {
        action_with_args(
            "ImageManifest",
            1,
            &[
                "bazel-out/k8-opt-exec/bin/external/rules_img_tool+/cmd/img\
                 /img_linux_amd64_/img_linux_amd64",
                "manifest",
                "--working-dir",
                "/app",
                "--manifest",
                "bazel-out/k8-fastbuild/bin/img/base/scratch_manifest.json",
            ],
        )
    }

    #[test]
    fn a_path_the_program_declares_in_its_output_is_not_reported() {
        // `/app` does not exist on this machine and is not supposed to: it
        // is where the image will put things once someone runs it.
        let c = container(vec![image_manifest_action()]);
        assert!(check(&c, &Library::builtin()).is_empty());
    }

    #[test]
    fn the_same_path_is_reported_when_the_library_says_nothing() {
        // The whole difference is the library. Without an entry for the
        // program there is nothing to say the path describes an image, and
        // Ahab reports it—which is what it should do for a tool it has
        // never heard of.
        let c = container(vec![image_manifest_action()]);
        let found = check(&c, &Library::default());
        assert_eq!(found.len(), 1);
        assert_abs_path(
            &found[0],
            "ImageManifest",
            1,
            "/app",
            LeakSite::Argument {
                value: "/app".to_owned(),
            },
        );
    }

    #[test]
    fn declaring_paths_does_not_excuse_the_rest_of_the_action() {
        // An entry naming some of a program's options must not turn into a
        // blanket pardon for the program: an absolute path anywhere else on
        // the same command line is still a finding.
        let mut action = image_manifest_action();
        action.arguments.push("--annotations-file".to_owned());
        action
            .arguments
            .push("/home/someone/annotations.json".to_owned());
        let c = container(vec![action]);
        let found = check(&c, &Library::builtin());
        assert_eq!(found.len(), 1);
        assert_abs_path(
            &found[0],
            "ImageManifest",
            1,
            "/home/someone/annotations.json",
            LeakSite::Argument {
                value: "/home/someone/annotations.json".to_owned(),
            },
        );
    }

    // ---- check: benign cases (expect no violations) ----

    #[test]
    fn relative_paths_and_labels_pass_absolute_path_check() {
        let c = container(vec![action_with_args(
            "A",
            1,
            &["-Irelative/include", "//pkg:target", "foo.o"],
        )]);
        assert!(check(&c, &Library::default()).is_empty());
    }

    #[test]
    fn a_path_under_a_variable_expansion_is_not_absolute() {
        // rules_rust writes exactly these. `${pwd}` becomes the execution
        // root at run time, so nothing machine-specific is recorded.
        let c = container(vec![action_with_env(
            "Clippy",
            1,
            &[
                (
                    "CLIPPY_CONF_DIR",
                    "${pwd}/external/rules_rust+/rust/settings",
                ),
                ("CARGO_MANIFEST_DIR", "${pwd}/proto"),
            ],
        )]);
        assert!(check(&c, &Library::default()).is_empty());
    }

    #[test]
    fn no_expansion_roots_a_path_whatever_it_names() {
        // The name inside the brackets is not consulted, because the shape
        // already says everything: whatever the expansion becomes, the `/`
        // after it separates the segments of a path relative to that. The
        // old reading needed a list of blessed names and reported
        // `${JAVA_HOME}/bin/javac` as a directory called `bin` at the root.
        let c = container(vec![action_with_args(
            "A",
            1,
            &[
                "tool",
                "--remap-path-prefix=${pwd}=.",
                "-I${output_base}/include",
                "$(exec_root)/gen",
                "${JAVA_HOME}/bin/javac",
                "$(realpath x)/y",
                "{pkg}/com.example",
                // A bare `$name` was never picked up, since the `/` sits
                // right after a path character; pinned so it stays that way.
                "$pwd/external/thing",
            ],
        )]);
        let found = check(&c, &Library::default());
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn a_group_closing_before_a_slash_continues_the_name_it_ends() {
        // A bracket is a filename character, so `[...id]/page` is one
        // relative path. A brace reads the same way, which is why a
        // template placeholder roots nothing wherever in a value it sits.
        let c = container(vec![action_with_args(
            "A",
            1,
            &["tool", "[pwd]/usr/lib", "{pwd}/opt/tool"],
        )]);
        let found = check(&c, &Library::default());
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn an_absolute_path_after_an_expansion_is_still_reported() {
        // The expansion excuses the path glued to it, not the whole
        // argument: a genuine absolute path later on still counts.
        let c = container(vec![action_with_args(
            "A",
            1,
            &["tool", "${pwd}/external/ok:/usr/lib"],
        )]);
        let found = check(&c, &Library::default());
        assert_eq!(found.len(), 1, "{found:?}");
        assert_abs_path(
            &found[0],
            "A",
            1,
            "/usr/lib",
            LeakSite::Argument {
                value: "${pwd}/external/ok:/usr/lib".to_owned(),
            },
        );
    }

    #[test]
    fn proc_self_cwd_is_allowed() {
        // What Bazel sets on every C++ action so that a compiler embedding
        // `$PWD` records the same bytes on every machine. It names the
        // working directory without saying where it is.
        let c = container(vec![action_with_env(
            "CppCompile",
            1,
            &[("PWD", "/proc/self/cwd")],
        )]);
        assert!(check(&c, &Library::default()).is_empty());
    }

    #[test]
    fn a_path_below_proc_self_cwd_is_still_reported() {
        // Only the bare directory is exempt. Anything reaching further is
        // an ordinary path that happens to start there, and the allow-list
        // matches the whole run rather than a prefix.
        let c = container(vec![action_with_args(
            "A",
            1,
            &["tool", "/proc/self/cwd/foo", "/proc/self/root"],
        )]);
        let found = check(&c, &Library::default());
        assert_eq!(found.len(), 2, "{found:?}");
    }

    #[test]
    fn dev_null_is_allowed_in_argument() {
        // /dev/null is a portable special file, not a hermeticity leak.
        let c =
            container(vec![action_with_args("A", 1, &["-o", "/dev/null"])]);
        assert!(check(&c, &Library::default()).is_empty());
    }

    #[test]
    fn dev_null_exemption_does_not_suppress_other_paths() {
        // Only the exact /dev/null run is exempt; a real path in the same list
        // is still reported. /dev/urandom is not on the allow-list.
        let c = container(vec![action_with_args(
            "A",
            1,
            &["tool", "/dev/null:/opt/bin"],
        )]);
        let found = check(&c, &Library::default());
        assert_eq!(found.len(), 1);
        assert_abs_path(
            &found[0],
            "A",
            1,
            "/opt/bin",
            LeakSite::Argument {
                value: "/dev/null:/opt/bin".to_owned(),
            },
        );
    }

    #[test]
    fn the_operand_of_a_shell_is_read_as_a_script() {
        // A genrule's `cmd` arrives as the `-c` operand of `/bin/bash`, and
        // only in a script does an unquoted `<` separate words. So the tag
        // stays a tag and the redirection names a path—one finding, not two
        // and not none.
        let c = container(vec![action_with_args(
            "Genrule",
            1,
            &[
                "/bin/bash",
                "-c",
                "echo '</manifest>' >$@; cat </etc/passwd",
            ],
        )]);
        let found = check(&c, &Library::default());
        assert_eq!(found.len(), 1, "{found:?}");
        assert_abs_path(
            &found[0],
            "Genrule",
            1,
            "/etc/passwd",
            LeakSite::Argument {
                value: "echo '</manifest>' >$@; cat </etc/passwd"
                    .to_owned(),
            },
        );
    }

    #[test]
    fn an_argument_that_is_not_a_script_is_not_read_as_one() {
        // The same text as an ordinary argument: nothing here is about to
        // be run by a shell, so `<` is not an operator and the tag is not a
        // path. Only the script gets the script reading.
        let c = container(vec![action_with_args(
            "A",
            1,
            &["tool", "--template=</manifest>"],
        )]);
        assert!(check(&c, &Library::default()).is_empty());
    }
}
