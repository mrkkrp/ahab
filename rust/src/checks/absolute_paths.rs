//! Finding the absolute paths an action references.

use std::collections::{HashMap, HashSet};

use analysis_v2_proto::analysis::Action;

use super::{ActionRef, LeakSite, ResolvedAction, Violation};
use crate::reproducibility_spec::library::Resolution;

/// How the system the actions run on roots a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathStyle {
    /// At `/`.
    Unix,
    /// At a drive, `C:\` or `C:/`. A `/` begins a switch there, as in
    /// `/nologo`, and `\` separates names rather than escaping.
    Windows,
}

impl PathStyle {
    /// The style of the system Ahab was built for, which is the one it
    /// queries Bazel on.
    pub(crate) const HOST: PathStyle = if cfg!(windows) {
        PathStyle::Windows
    } else {
        PathStyle::Unix
    };

    /// The length of the root beginning at `at`, if one does. A drive may
    /// be followed by several separators, as the escaped `C:\\` is.
    pub(super) fn root(self, bytes: &[u8], at: usize) -> Option<usize> {
        match self {
            PathStyle::Unix => (bytes[at] == b'/').then_some(1),
            PathStyle::Windows => {
                let [drive, b':', rest @ ..] = &bytes[at..] else {
                    return None;
                };
                let separators = rest
                    .iter()
                    .take_while(|&&byte| byte == b'\\' || byte == b'/')
                    .count();
                (drive.is_ascii_alphabetic() && separators > 0)
                    .then_some(2 + separators)
            }
        }
    }
}

/// Whether `byte` may follow the root of a path. Glob metacharacters are
/// absent, though [`continues_path_run`] admits them: `/*` is usually a C
/// comment, not the root's children.
fn starts_path_run(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || !byte.is_ascii()
        || matches!(byte, b'.' | b'-' | b'_' | b'+' | b'~' | b'@' | b'%')
}

/// Whether `byte` may appear within a run already begun.
///
/// Brackets are absent because a `]` may close a list the path sits in;
/// [`path_run`] balances them instead. Admitting every non-ASCII byte keeps
/// a run's end on a character boundary.
fn continues_path_run(byte: u8) -> bool {
    starts_path_run(byte) || matches!(byte, b'/' | b'*' | b'?')
}

/// Whether `byte` is one a pattern language escapes.
///
/// A run holding `\` before one is a regex or a glob: `/R\.class` names no
/// directory `R`. A `\` before anything else merely ends the path.
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

/// Flag prefixes that take a path glued straight on, with no `=` or space.
const GLUED_FLAG_PREFIXES: &[&str] =
    &["-I", "-L", "-isystem", "-iquote", "-idirafter"];

/// Whether the root at `root` is glued onto one of the
/// [`GLUED_FLAG_PREFIXES`] that itself begins at a boundary, which tells
/// `-I/usr/include` from `-Irelative/include` and from a `-I` inside a
/// longer word.
fn glued_onto_flag(bytes: &[u8], root: usize) -> bool {
    GLUED_FLAG_PREFIXES.iter().any(|flag| {
        let flag = flag.as_bytes();
        root >= flag.len()
            && &bytes[root - flag.len()..root] == flag
            && (root == flag.len()
                || !continues_path_run(bytes[root - flag.len() - 1]))
    })
}

/// What kind of text a scanned string is, which decides what roots a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SiteKind {
    /// Text a program receives as it stands.
    Plain,
    /// The operand of `sh -c`, which for a genrule is the whole `cmd`.
    Shell,
}

/// The end of the run whose root ends at `start`, and whether it is a path.
fn path_run(bytes: &[u8], start: usize, style: PathStyle) -> (usize, bool) {
    let mut at = start;
    let mut depth = 0usize;

    while at < bytes.len() {
        match bytes[at] {
            b'[' => depth += 1,
            b']' if depth > 0 => depth -= 1,
            b']' => break,
            b'\\' if style == PathStyle::Windows => {}
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

/// Whether a value may begin after `byte` in text read as it stands.
fn opens_a_value(byte: u8, style: PathStyle) -> bool {
    matches!(byte, b'\'' | b'"' | b'=' | b':' | b',' | b'[')
        || byte.is_ascii_whitespace()
        || byte == b';' && style == PathStyle::Windows
}

/// Whether a script's `\` within `quote` escapes the byte after it: any
/// byte outside quotes, within double quotes only those they interpret.
fn shell_escapes(quote: Option<u8>, next: Option<&u8>) -> bool {
    match quote {
        None => true,
        Some(b'"') => {
            matches!(next, Some(b'"' | b'\\' | b'$' | b'`' | b'\n'))
        }
        Some(_) => false,
    }
}

/// The end marker of the heredoc whose `<<` ends just before `at`, whether
/// its lines lose their leading tabs, and where the marker ends. Quoting
/// the marker only keeps the body from being expanded.
fn heredoc_marker(bytes: &[u8], mut at: usize) -> (Vec<u8>, bool, usize) {
    let strip_tabs = bytes.get(at) == Some(&b'-');
    at += usize::from(strip_tabs);
    while matches!(bytes.get(at), Some(b' ' | b'\t')) {
        at += 1;
    }
    let mut marker = Vec::new();
    while let Some(&byte) = bytes.get(at) {
        if byte.is_ascii_whitespace() || b";&|<>()".contains(&byte) {
            break;
        }
        if !matches!(byte, b'\'' | b'"' | b'\\') {
            marker.push(byte);
        }
        at += 1;
    }
    (marker, strip_tabs, at)
}

/// The body of a heredoc beginning at `at`, up to the line holding only
/// `marker`, and where the line after that begins. With no such line it
/// runs to the end of `text`.
fn heredoc_body<'a>(
    text: &'a str,
    at: usize,
    marker: &[u8],
    strip_tabs: bool,
) -> (&'a str, usize) {
    let mut line = at;
    while line < text.len() {
        let end = text[line..].find('\n').map_or(text.len(), |n| line + n);
        let mut content = &text[line..end];
        if strip_tabs {
            content = content.trim_start_matches('\t');
        }
        if content.as_bytes() == marker {
            return (&text[at..line], (end + 1).min(text.len()));
        }
        line = end + 1;
    }
    (&text[at..], text.len())
}

/// Extract every absolute path in `text`, read as a `kind` of site written
/// in `style`.
///
/// A root counts only at a separator—start of text, whitespace, an opening
/// quote, `=`, `:`, `,`, `[`, a shell operator, and on Windows the `;` that
/// separates a list—or glued onto a [`GLUED_FLAG_PREFIXES`] flag. That the
/// list is closed is what leaves globs, regexes, expansions and markup
/// alone. A script's quotes join the parts of a word instead, `(`, `$(` and
/// backticks begin one, `\` escapes, comments are skipped, and a heredoc's
/// body is read as plain text.
fn absolute_paths(
    text: &str,
    kind: SiteKind,
    style: PathStyle,
) -> Vec<String> {
    let bytes = text.as_bytes();
    let shell = kind == SiteKind::Shell;
    let mut paths = Vec::new();

    let mut quote: Option<u8> = None;
    let mut may_start = true;
    // Only a script's: whether a word begins here, so that `#` opens a
    // comment, whether a `\` escapes this byte, whether a backtick is open,
    // and the heredocs whose bodies begin on the next line.
    let mut word_begins = true;
    let mut escape = false;
    let mut backtick = false;
    let mut heredocs: Vec<(Vec<u8>, bool)> = Vec::new();
    let mut at = 0;

    while at < bytes.len() {
        let byte = bytes[at];
        let begins_word = std::mem::replace(&mut word_begins, false);
        let escaped = std::mem::replace(&mut escape, false);
        let unquoted = quote.is_none();

        // A second `/` is not a name, so the label `//foo:bar` roots nothing.
        if let Some(root) = style.root(bytes, at)
            && bytes
                .get(at + root)
                .is_some_and(|&next| starts_path_run(next))
            && (may_start || glued_onto_flag(bytes, at))
        {
            let (end, is_path) = path_run(bytes, at + root, style);
            // A run naming nothing, as `/.-` in `[/.-]`, is a pattern's.
            if is_path
                && bytes[at + root..end]
                    .iter()
                    .any(|&b| b.is_ascii_alphanumeric() || !b.is_ascii())
            {
                paths.push(text[at..end].to_owned());
            }
            at = end;
            may_start = false;
            continue;
        }

        match byte {
            // An escaped byte is data, so `\/x` still roots a path, but `\<`
            // redirects nothing and `\"` closes nothing, though like any
            // byte it may begin a value in what the script writes.
            b'\n' if escaped => {}
            _ if escaped => may_start = opens_a_value(byte, style),
            b'\\' if shell && shell_escapes(quote, bytes.get(at + 1)) => {
                escape = true;
            }
            // Transparent, so `\"` opens a value as `"` does: the shell
            // these strings are written for will take the escape off.
            b'\\' => {}
            b'#' if shell && begins_word => {
                at = text[at..].find('\n').map_or(bytes.len(), |n| at + n);
                continue;
            }
            b'<' if shell
                && unquoted
                && bytes.get(at + 1) == Some(&b'<')
                && bytes.get(at + 2) != Some(&b'<')
                && (at == 0 || bytes[at - 1] != b'<') =>
            {
                let (marker, strip_tabs, end) =
                    heredoc_marker(bytes, at + 2);
                if !marker.is_empty() {
                    heredocs.push((marker, strip_tabs));
                }
                at = end;
                may_start = false;
                continue;
            }
            b'\n' if shell && unquoted && !heredocs.is_empty() => {
                at += 1;
                for (marker, strip_tabs) in heredocs.drain(..) {
                    let (body, next) =
                        heredoc_body(text, at, &marker, strip_tabs);
                    paths.extend(absolute_paths(
                        body,
                        SiteKind::Plain,
                        style,
                    ));
                    at = next;
                }
                may_start = true;
                word_begins = true;
                continue;
            }
            // `$'…'` and `$"…"` are quotes too.
            b'$' if shell
                && unquoted
                && matches!(bytes.get(at + 1), Some(b'\'' | b'"')) => {}
            b'\'' | b'"' => {
                may_start = match quote {
                    Some(open) if open == byte => {
                        quote = None;
                        false
                    }
                    Some(_) => false,
                    None => {
                        quote = Some(byte);
                        may_start || !shell
                    }
                };
            }
            b'`' if shell && quote != Some(b'\'') => {
                backtick = !backtick;
                may_start = backtick;
                word_begins = backtick;
            }
            b'(' if shell
                && (unquoted
                    || quote == Some(b'"')
                        && at > 0
                        && bytes[at - 1] == b'$') =>
            {
                may_start = true;
                word_begins = true;
            }
            b'<' | b'>' | b'|' | b';' | b'&' if shell && unquoted => {
                may_start = true;
                word_begins = true;
            }
            byte => {
                may_start = opens_a_value(byte, style);
                word_begins =
                    shell && unquoted && byte.is_ascii_whitespace();
            }
        }

        at += 1;
    }

    paths
}

/// Paths that are not violations: two special files that name the same
/// thing everywhere, what `apple_support` maps the Xcode developer
/// directory onto, and a `--binary-file` value
/// `appintentsmetadataprocessor` demands but never reads.
///
/// Closed on purpose: a project's own placeholder is a project exception.
const ALLOWED_ABSOLUTE_PATHS: &[&str] = &[
    "/dev/null",
    "/proc/self/cwd",
    "/PLACEHOLDER_DEVELOPER_DIR",
    "/bazel_rules_apple/fakepath",
];

fn is_allowed_absolute_path(path: &str) -> bool {
    ALLOWED_ABSOLUTE_PATHS.contains(&path)
}

/// The shells whose `-c` operand is a script rather than an argument.
const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh"];

/// The script this action hands a shell to run, if that is what it does.
/// The shell is known by its file name, which on Windows ends in `.exe`.
fn shell_script_operand(action: &Action) -> Option<&str> {
    let (executable, args) = action.arguments.split_first()?;
    let name = executable.rsplit(['/', '\\']).next().unwrap_or_default();
    let shell = name.strip_suffix(".exe").unwrap_or(name);
    if !SHELLS.contains(&shell) {
        return None;
    }
    let at = args.iter().position(|arg| arg == "-c")?;
    args.get(at + 1).map(String::as_str)
}

/// The strings with which a program declares a path inside the artifact it
/// produces. Matched by value, not position: the scan order is not the
/// sequence the program sees.
fn declared_path_strings<'a>(
    resolved: Option<&Resolution<'a>>,
) -> HashSet<&'a str> {
    let Some(Resolution {
        args,
        spec: Some((_, spec)),
        ..
    }) = resolved
    else {
        return HashSet::new();
    };
    spec.declared_path_args(args).into_iter().collect()
}

/// One [`Violation`] per absolute path in an action's command line, param
/// files, the arguments a template substituted for its program and its
/// environment values. `PATH` is skipped—[`super::check_path`] governs it—as are
/// the [`ALLOWED_ABSOLUTE_PATHS`].
pub(super) fn check(
    resolved: &[ResolvedAction<'_>],
    targets: &HashMap<u32, &str>,
    style: PathStyle,
) -> Vec<Violation> {
    let mut violations = Vec::new();

    for resolved in resolved {
        let action = resolved.action;
        // Built at the first path we would report, so that the actions with
        // none never pay for it.
        let mut declared: Option<HashSet<&str>> = None;
        let shell_script = shell_script_operand(action);

        // argv[0] is the program, which the reproducibility check reports.
        let program = usize::from(!action.arguments.is_empty());
        for sourced in
            resolved.analyzable_strings().into_iter().skip(program)
        {
            let kind = if shell_script == Some(sourced.value) {
                SiteKind::Shell
            } else {
                SiteKind::Plain
            };
            let paths = absolute_paths(sourced.value, kind, style);
            if paths.is_empty() {
                continue;
            }
            if declared
                .get_or_insert_with(|| {
                    declared_path_strings(resolved.resolution.as_ref())
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
                    action: ActionRef::of(action, targets),
                    path,
                    site: LeakSite::of(sourced),
                });
            }
        }

        for kv in &action.environment_variables {
            if kv.key == "PATH" {
                continue;
            }
            for path in absolute_paths(&kv.value, SiteKind::Plain, style) {
                if is_allowed_absolute_path(&path) {
                    continue;
                }
                violations.push(Violation::AbsolutePath {
                    action: ActionRef::of(action, targets),
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
    use crate::checks::tests::{
        action_with_args, action_with_env, assert_abs_path,
        check_absolute_paths as check, container,
    };
    use crate::reproducibility_spec::library::Library;

    fn plain(text: &str) -> Vec<String> {
        absolute_paths(text, SiteKind::Plain, PathStyle::Unix)
    }

    fn shell(text: &str) -> Vec<String> {
        absolute_paths(text, SiteKind::Shell, PathStyle::Unix)
    }

    fn windows(text: &str) -> Vec<String> {
        absolute_paths(text, SiteKind::Plain, PathStyle::Windows)
    }

    #[test]
    fn extracts_a_bare_absolute_path() {
        assert_eq!(plain("/usr/bin"), vec!["/usr/bin".to_owned()]);
    }

    #[test]
    fn relative_value_after_a_flag_is_not_absolute() {
        assert!(plain("-Irelative/include").is_empty());
    }

    #[test]
    fn a_bracketed_segment_does_not_start_an_absolute_path() {
        assert!(plain("src/routes/axes/[...id]/+page.svelte").is_empty());
    }

    #[test]
    fn a_bracketed_segment_is_part_of_the_path_it_sits_in() {
        assert_eq!(
            plain("/usr/lib/[abi]/libfoo.so"),
            vec!["/usr/lib/[abi]/libfoo.so"],
        );
    }

    #[test]
    fn a_bracket_opening_a_list_still_starts_a_path() {
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
        assert_eq!(
            plain("/a/b,/c/d /e"),
            vec!["/a/b".to_owned(), "/c/d".to_owned(), "/e".to_owned()]
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
        assert!(plain("//foo:bar").is_empty());
        assert_eq!(
            plain("//foo=/real/path"),
            vec!["/real/path".to_owned()]
        );
    }

    #[test]
    fn an_opening_quote_starts_a_path_and_a_closing_one_does_not() {
        assert_eq!(plain("-DFOO=\"/opt/x\""), vec!["/opt/x"]);
        assert!(
            plain(r#"sed -e 's/version = ""/version = "1.2.0"/' x"#)
                .is_empty()
        );
    }

    #[test]
    fn a_glob_does_not_start_a_path_but_belongs_to_one() {
        assert!(plain("**/.svn/**").is_empty());
        assert!(plain("--exclude=**/*.o").is_empty());
        assert!(plain("*/5 * * * *").is_empty());
        assert_eq!(plain("/usr/lib/*"), vec!["/usr/lib/*"]);
        assert_eq!(plain("--include=/usr/lib/*.so"), vec!["/usr/lib/*.so"]);
        assert!(shell("echo '/* generated */' > x.c").is_empty());
    }

    #[test]
    fn ignores_a_character_class_that_excludes_the_separator() {
        assert!(plain(r"s|([+][+][^/~]+)~([^/~]+)|\1+\2|g").is_empty());
        assert_eq!(
            plain("[/usr/lib,/opt/lib]"),
            vec!["/usr/lib", "/opt/lib"],
        );
    }

    #[test]
    fn ignores_a_run_whose_backslash_escapes_a_metacharacter() {
        assert!(plain(r"/R\.class,/BR\.class").is_empty());
        assert!(plain(r"s/a\/b/c/").is_empty());
    }

    #[test]
    fn a_backslash_around_a_path_still_leaves_a_path() {
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
        assert!(shell("echo '</manifest>' > $@").is_empty());
        assert!(shell("echo \"</ns:tag>\" > $@").is_empty());
        assert!(plain("</manifest>").is_empty());
        assert_eq!(shell("cat < /etc/passwd"), vec!["/etc/passwd"]);
        assert_eq!(shell("cat </etc/passwd"), vec!["/etc/passwd"]);
        assert_eq!(shell("cat >/opt/out"), vec!["/opt/out"]);
    }

    #[test]
    fn a_path_rooted_at_an_expansion_is_not_absolute() {
        assert!(plain("${pwd}/external/crate/lib.rs").is_empty());
        assert!(plain("${JAVA_HOME}/bin/javac").is_empty());
        assert!(shell("KEYTOOL=$(dirname ${BINS[1]})/keytool").is_empty());
        assert!(plain("{pkg}/com.example").is_empty());
        assert!(shell("sed 's/{pkg}/com.example/g' x").is_empty());
    }

    #[test]
    fn a_shebang_roots_nothing() {
        assert!(shell("cat <<'eof'\n#!/bin/bash\n").is_empty());
        assert!(plain("#!/usr/bin/env bash").is_empty());
        assert!(shell("echo '#!/bin/sh' > $@").is_empty());
        assert_eq!(shell("cat <<'eof'\ncp /opt/x .\n"), vec!["/opt/x"]);
    }

    #[test]
    fn a_shell_operator_separates_words() {
        assert_eq!(
            shell("source setup.sh; cp /opt/a /opt/b"),
            vec!["/opt/a", "/opt/b"],
        );
        assert_eq!(shell("cat x |/opt/tool"), vec!["/opt/tool"]);
        assert!(shell("grep '^/usr/bin' x").is_empty());
        assert!(shell("awk '{print $1\"/\"$2}' x").is_empty());
    }

    #[test]
    fn a_heredoc_body_is_read_as_plain_text() {
        assert!(
            shell(
                "cat > out/Info.plist <<EOF\n<plist version=\"1.0\"><dict>\
                 <key>Name</key></dict></plist>\nEOF\n"
            )
            .is_empty()
        );
        assert_eq!(
            shell("cat <<-'EOF' >/opt/out\n\t</a>\n\tEOF\ncat x |/opt/y\n"),
            vec!["/opt/out", "/opt/y"],
        );
        assert_eq!(
            shell("cat <<A - <<B\n</a>\nA\n</b> /opt/b\nB\n"),
            vec!["/opt/b"],
        );
        assert_eq!(shell("cat <<<'</a>' >/opt/x"), vec!["/opt/x"]);
    }

    #[test]
    fn a_comment_is_skipped_and_its_quotes_with_it() {
        assert!(shell("# copied from /opt/x\ntrue").is_empty());
        assert!(shell("true # it's\necho '</a>' >$@").is_empty());
        assert_eq!(shell("echo $# x#/opt/y /opt/z"), vec!["/opt/z"]);
    }

    #[test]
    fn a_backslash_makes_the_next_byte_data_in_a_script() {
        assert!(shell(r#"echo "a\"b </c>""#).is_empty());
        assert!(shell(r"echo \</dict\>").is_empty());
        assert_eq!(shell(r"cp \/opt/x ."), vec!["/opt/x"]);
    }

    #[test]
    fn a_command_substitution_begins_a_word() {
        assert_eq!(shell("x=$(/bin/date)"), vec!["/bin/date"]);
        assert_eq!(shell("echo \"$(/bin/date)\""), vec!["/bin/date"]);
        assert_eq!(shell("x=`/bin/date`"), vec!["/bin/date"]);
        assert!(shell("x=`dirname y`/keytool").is_empty());
    }

    #[test]
    fn a_quote_in_a_script_begins_a_path_only_where_a_word_may() {
        assert!(shell("cp ${pwd}\"/external/x\" .").is_empty());
        assert_eq!(shell("cp \"/opt/x\" ."), vec!["/opt/x"]);
        assert_eq!(shell("cc -DX=\"/opt/x\" x.c"), vec!["/opt/x"]);
        assert_eq!(shell("echo $'/opt/x'"), vec!["/opt/x"]);
        assert!(shell("echo x$'/opt/x'").is_empty());
    }

    #[test]
    fn a_run_naming_nothing_is_not_a_path() {
        assert!(shell("sed 's/[/.-]/_/g' x").is_empty());
        assert!(plain("[/.-]").is_empty());
        assert_eq!(plain("[/.x-]"), vec!["/.x-"]);
    }

    #[test]
    fn a_drive_roots_a_path_on_windows() {
        assert_eq!(windows(r"C:\Users\me\x.h"), [r"C:\Users\me\x.h"]);
        assert_eq!(windows("d:/tools/bin"), ["d:/tools/bin"]);
        assert_eq!(windows(r#"-DDIR="C:\\VC\\bin""#), [r"C:\\VC\\bin"]);
    }

    #[test]
    fn a_slash_roots_nothing_on_windows() {
        assert!(windows("/nologo").is_empty());
        assert!(
            windows("/Fobazel-out/x64_windows-opt/bin/a.obj").is_empty()
        );
        assert!(windows("--sysroot=/opt/toolchain").is_empty());
    }

    #[test]
    fn a_drive_roots_nothing_unless_a_name_follows_it() {
        assert!(windows(r"C:\").is_empty());
        assert!(windows("C:relative").is_empty());
        assert!(windows("https://example.com").is_empty());
    }

    #[test]
    fn a_drive_inside_a_word_roots_nothing() {
        assert!(windows(r"ab:\x").is_empty());
        assert!(windows(r"x\C:\x").is_empty());
        assert_eq!(windows(r"-IC:\include"), [r"C:\include"]);
        assert!(windows(r"x-IC:\include").is_empty());
    }

    #[test]
    fn each_entry_of_a_list_is_found_on_windows() {
        assert_eq!(
            windows(r"C:\VC\include;D:\SDK\include"),
            [r"C:\VC\include", r"D:\SDK\include"],
        );
        assert_eq!(windows("/LIBPATH:C:/lib"), ["C:/lib"]);
    }

    #[test]
    fn a_backslash_separates_names_on_windows() {
        assert_eq!(windows(r"C:\R\.class"), [r"C:\R\.class"]);
        assert!(plain(r"/R\.class").is_empty());
    }

    #[test]
    fn whitespace_ends_a_run_on_windows_too() {
        assert_eq!(windows(r"C:\Program Files\VC"), [r"C:\Program"]);
    }

    /// The rule restated as data, so that widening it takes editing this
    /// list and saying why.
    const ROOTING_BYTES: &[u8] = b"\t\n\x0C\r \"',:=[";

    /// What a shell adds to [`ROOTING_BYTES`]: its operators and what
    /// begins a command.
    const ROOTING_IN_A_SHELL: &[u8] = b"&(;<>`|";

    /// What a shell takes from [`ROOTING_BYTES`]: the quotes, which join
    /// the parts of a word there rather than begin a value.
    const JOINING_IN_A_SHELL: &[u8] = b"\"'";

    /// [`ROOTING_BYTES`] as a script has them.
    fn rooting_in_a_script() -> Vec<u8> {
        let mut bytes: Vec<u8> = ROOTING_BYTES
            .iter()
            .copied()
            .filter(|byte| !JOINING_IN_A_SHELL.contains(byte))
            .collect();
        bytes.extend(ROOTING_IN_A_SHELL);
        bytes.sort_unstable();
        bytes
    }

    /// What Windows adds to [`ROOTING_BYTES`]: its list separator.
    const ROOTING_ON_WINDOWS: &[u8] = b";";

    /// Found by trying each byte rather than by consulting the rule under
    /// test.
    fn rooting_bytes(kind: SiteKind, style: PathStyle) -> Vec<u8> {
        let path = match style {
            PathStyle::Unix => "/usr/lib",
            PathStyle::Windows => r"C:\lib",
        };
        (0u8..=127)
            .filter(|byte| {
                let text = format!("x{}{path}", *byte as char);
                !absolute_paths(&text, kind, style).is_empty()
            })
            .collect()
    }

    fn sorted(parts: &[&[u8]]) -> Vec<u8> {
        let mut bytes = parts.concat();
        bytes.sort_unstable();
        bytes
    }

    #[test]
    fn exactly_the_listed_bytes_root_a_path() {
        assert_eq!(
            rooting_bytes(SiteKind::Plain, PathStyle::Unix),
            ROOTING_BYTES,
        );
    }

    #[test]
    fn a_script_adds_its_operators_and_takes_its_quotes() {
        assert_eq!(
            rooting_bytes(SiteKind::Shell, PathStyle::Unix),
            rooting_in_a_script(),
        );
    }

    #[test]
    fn windows_adds_its_list_separator_and_nothing_else() {
        assert_eq!(
            rooting_bytes(SiteKind::Plain, PathStyle::Windows),
            sorted(&[ROOTING_BYTES, ROOTING_ON_WINDOWS]),
        );
        assert_eq!(
            rooting_bytes(SiteKind::Shell, PathStyle::Windows),
            rooting_in_a_script(),
        );
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
            let buried = format!("x{flag}/usr/include");
            assert!(
                plain(&buried).is_empty(),
                "{buried:?} should hold no path",
            );
        }
        assert_eq!(plain("-Wl,-L/usr/lib"), vec!["/usr/lib"]);
    }

    #[test]
    fn a_run_ends_at_the_first_byte_a_path_may_not_hold() {
        for byte in b" \t\n\"'=:,;|&<>()^$#!" {
            let text = format!("/usr/lib{}x", *byte as char);
            assert_eq!(
                shell(&text),
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
        assert_eq!(plain("[/usr/lib]x"), vec!["/usr/lib"]);
        assert_eq!(plain("/usr/lib[a"), vec!["/usr/lib[a"]);
    }

    #[test]
    fn a_path_may_hold_characters_outside_ascii() {
        assert_eq!(
            plain("--flag=/opt/caf\u{e9}/bin"),
            vec!["/opt/caf\u{e9}/bin"]
        );
        assert_eq!(plain("/\u{e4}rger/x"), vec!["/\u{e4}rger/x"]);
        assert!(plain("caf\u{e9}/usr/lib").is_empty());
        assert_eq!(plain("caf\u{e9} /usr/lib"), vec!["/usr/lib"]);
    }

    #[test]
    fn a_quote_is_read_as_opening_or_closing_by_what_came_before() {
        assert_eq!(plain("'/usr/lib'"), vec!["/usr/lib"]);
        assert_eq!(plain("--flag=\"/usr/lib\""), vec!["/usr/lib"]);
        assert_eq!(plain("\"a\"/b\"/usr/lib\""), vec!["/usr/lib"]);
        assert_eq!(shell("echo \\\"/usr/lib\\\""), vec!["/usr/lib"]);
    }

    #[test]
    fn an_unbalanced_quote_does_not_hide_the_rest_of_the_text() {
        assert_eq!(
            shell("# from Bazel's library\ncp /opt/x .\n"),
            vec!["/opt/x"],
        );
    }

    #[test]
    fn a_quote_of_the_other_kind_inside_one_is_data() {
        assert!(shell("echo \"it's/usr/lib\"").is_empty());
    }

    #[test]
    fn only_a_script_reads_its_operators_as_separators() {
        for text in ["cat </etc/passwd", "x >/opt/out", "x |/opt/t"] {
            assert_eq!(shell(text).len(), 1, "{text:?} in a script");
            assert!(plain(text).is_empty(), "{text:?} as an argument");
        }
        assert!(shell("echo '</manifest>' >$@").is_empty());
    }

    /// The bytes whose interactions decide every rule above.
    const PROBE_ALPHABET: &[u8] = b"/a.\\\"'[]}$<*= ";

    /// [`PROBE_ALPHABET`] for Windows, whose `a:` is a drive.
    const PROBE_ALPHABET_ON_WINDOWS: &[u8] = b"/a.\\\"'[]:*=; ";

    /// Call `check` with every string of `length` bytes over `alphabet`.
    fn every_probe_string(
        alphabet: &[u8],
        length: u32,
        mut check: impl FnMut(&str),
    ) {
        let base = alphabet.len() as u32;
        let mut buffer = Vec::with_capacity(length as usize);
        for mut code in 0..base.pow(length) {
            buffer.clear();
            for _ in 0..length {
                buffer.push(alphabet[(code % base) as usize]);
                code /= base;
            }
            check(std::str::from_utf8(&buffer).expect("ASCII is UTF-8"));
        }
    }

    /// How many probe strings over `alphabet` hold a path in `style`,
    /// asserting that every path found is a rooted substring of its text.
    fn probe(style: PathStyle, alphabet: &[u8], length: u32) -> usize {
        let mut with_a_path = 0;
        for kind in [SiteKind::Plain, SiteKind::Shell] {
            for length in 1..=length {
                every_probe_string(alphabet, length, |text| {
                    let mut cursor = 0;
                    let found = absolute_paths(text, kind, style);
                    with_a_path += usize::from(!found.is_empty());
                    for path in found {
                        let root = style
                            .root(path.as_bytes(), 0)
                            .filter(|&root| path.len() > root)
                            .unwrap_or_else(|| {
                                panic!(
                                    "{path:?} from {text:?} is not rooted"
                                )
                            });
                        for byte in path.bytes().skip(root) {
                            assert!(
                                continues_path_run(byte)
                                    || byte == b'['
                                    || byte == b']'
                                    || byte == b'\\'
                                        && style == PathStyle::Windows,
                                "{path:?} from {text:?} holds {byte:?}",
                            );
                        }
                        let at = text[cursor..].find(&path).unwrap_or_else(
                            || panic!("{path:?} is not in {text:?}"),
                        );
                        cursor += at + path.len();
                    }
                });
            }
        }
        with_a_path
    }

    #[test]
    fn whatever_is_returned_is_a_rooted_substring_of_the_text() {
        assert_eq!(probe(PathStyle::Unix, PROBE_ALPHABET, 4), 794);
        assert_eq!(
            probe(PathStyle::Windows, PROBE_ALPHABET_ON_WINDOWS, 5),
            100,
        );
    }

    #[test]
    fn the_operand_of_a_shell_is_the_script() {
        for program in [
            "/bin/bash",
            "bash",
            "external/x/bin/sh",
            "/bin/zsh",
            "ksh",
            "C:/msys64/usr/bin/bash.exe",
            r"C:\msys64\usr\bin\bash.exe",
        ] {
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
        let c = container(vec![action_with_env(
            "A",
            1,
            &[("PATH", "/bin:/usr/bin:/usr/local/bin")],
        )]);
        assert!(check(&c, &Library::default()).is_empty());
    }

    /// An `img manifest` command line, as rules_img writes it.
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
        let c = container(vec![image_manifest_action()]);
        assert!(check(&c, &Library::builtin(None)).is_empty());
    }

    #[test]
    fn the_same_path_is_reported_when_the_library_says_nothing() {
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
        let mut action = image_manifest_action();
        action.arguments.push("--annotations-file".to_owned());
        action
            .arguments
            .push("/home/someone/annotations.json".to_owned());
        let c = container(vec![action]);
        let found = check(&c, &Library::builtin(None));
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
                "$pwd/external/thing",
            ],
        )]);
        let found = check(&c, &Library::default());
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn a_group_closing_before_a_slash_continues_the_name_it_ends() {
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
        let c = container(vec![action_with_env(
            "CppCompile",
            1,
            &[("PWD", "/proc/self/cwd")],
        )]);
        assert!(check(&c, &Library::default()).is_empty());
    }

    #[test]
    fn a_path_below_proc_self_cwd_is_still_reported() {
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
        let c =
            container(vec![action_with_args("A", 1, &["-o", "/dev/null"])]);
        assert!(check(&c, &Library::default()).is_empty());
    }

    #[test]
    fn dev_null_exemption_does_not_suppress_other_paths() {
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
    fn windows_paths_are_found_and_switches_are_not() {
        let c = container(vec![
            action_with_args(
                "CppCompile",
                1,
                &["cl.exe", "/nologo", "/Ibazel-out/bin", "/c", "a.c"],
            ),
            action_with_env(
                "CppCompile",
                1,
                &[("INCLUDE", r"C:\VC\include;C:\SDK\include")],
            ),
        ]);
        let found = super::check(
            &ResolvedAction::all(&c, &Library::default()),
            &crate::checks::target_labels(&c),
            PathStyle::Windows,
        );
        let paths: Vec<&str> = found
            .iter()
            .map(|violation| match violation {
                Violation::AbsolutePath { path, .. } => path.as_str(),
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(paths, [r"C:\VC\include", r"C:\SDK\include"]);
    }

    #[test]
    fn an_argument_that_is_not_a_script_is_not_read_as_one() {
        let c = container(vec![action_with_args(
            "A",
            1,
            &["tool", "--template=</manifest>"],
        )]);
        assert!(check(&c, &Library::default()).is_empty());
    }
}
