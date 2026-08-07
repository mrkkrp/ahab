//! Reconstructing what an action's command line actually contains.
//!
//! Bazel spills long command lines into *param files*: the action's
//! `arguments` keep only a short reference such as
//! `@bazel-out/k8-fastbuild/bin/foo-2.params` and the real arguments live
//! in that file. A check that reads only `arguments` therefore sees a
//! truncated command line and silently misses whatever the param file
//! holds—an absolute path, a leaked user name, a flag that breaks
//! reproducibility. Worse, it misses it *quietly*: the action looks clean
//! precisely because it is the large, interesting one.
//!
//! So param files are treated as first-class sources of information, on equal
//! footing with `arguments`, and every string they contribute is tagged with
//! [`ArgSource`] so a violation can say where it really came from.
//!
//! # They must be requested
//!
//! `analysis_v2.proto` notes that `param_files` "will be only set if
//! explicitly requested". Without `--include_param_files` the field is
//! silently empty and everything here is dead code, so
//! [`crate::aquery::run_aquery`] always passes that flag.
//!
//! # Two kinds of param file
//!
//! `param_files` mixes two things that look alike but are not:
//!
//! * **Argument files** — referenced from the command line, holding
//!   arguments the program parses. These belong spliced into the command
//!   line.
//! * **Content files**—attached to the action but never referenced as an
//!   argument, holding data the program reads as a *file*. C++ module maps
//!   are the common case: a `.cppmap` is passed by path via
//!   `-fmodule-map-file=`, and its contents are a module graph, not a list
//!   of flags. In this project's own build every single param file is of
//!   this kind.
//!
//! Hence the two views below. [`expanded_command_line`] is what the program
//! receives as `argv` and is what a reproducibility spec should judge;
//! feeding it module-map text would invite a recognizer to mistake a line
//! of a module graph for a flag. [`analyzable_strings`] is everything worth
//! scanning for leaked paths and sentinels, where content files matter just
//! as much.
//!
//! # Recognizing a reference
//!

//! There is no single spelling to match. The reference format is chosen by
//! whoever wrote the rule, via the `param_file_arg` argument of Starlark's
//! `Args.use_param_file`, which is a format string: native C++ and Java
//! actions use `@%s`, while others use `--flagfile=%s` and similar.
//! [`references`] therefore keys off the one part that cannot vary—the exec
//! path itself must appear verbatim at the end of the argument—and accepts
//! only the separators those formats can put in front of it.
//!
//! Some legal formats are still rejected, because the two kinds of param
//! file above are not always distinguishable by shape:
//! `-fmodule-map-file=out/m.cppmap` names a content file but is spelled
//! exactly like `--flagfile=out/x.params`. [`references`] documents where
//! that line is drawn and why it errs towards not splicing.
//!
//! Expansion is deliberately not recursive: Bazel does not nest param
//! files, and refusing to follow references found *inside* a param file
//! means a malformed or hostile graph cannot send us into a cycle.

use analysis_v2_proto::analysis::Action;

/// Where within an action a string Ahab analyzed came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ArgSource<'a> {
    /// Directly on the action's command line (its `arguments`).
    CommandLine,
    /// A line of the param file at this exec path.
    ParamFile(&'a str),
}

/// One analyzed string together with its provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Sourced<'a> {
    /// The string itself: a command-line argument or one line of a param file.
    pub value: &'a str,
    /// Where it came from.
    pub source: ArgSource<'a>,
}

/// Whether `arg` is a reference to the param file at `exec_path`.
///
/// The exec path must appear verbatim at the end of `arg`, preceded by either:
///
/// * something ending in `@`—covering `@path`, `@@path` and `-Wl,@path`; or
/// * a flag ending in `flagfile=`—covering `--flagfile=path` and
///   `-flagfile=path`.
///
/// Deliberately *not* accepted are a bare path and a general
/// `<flag>=<path>`, even though both are legal `param_file_arg` formats,
/// because neither can be told apart by shape from an ordinary path-valued
/// argument. `-Xclang out/m.cppmap` looks exactly like a bare reference,
/// and `-fmodule-map-file=out/m.cppmap` looks exactly like
/// `--flagfile=out/x.params` — and both of those are real arguments naming
/// C++ module maps, which this project's own build attaches to
/// `param_files` as content.
///
/// The asymmetry is deliberate: mistaking a content file for a reference
/// splices module-graph text into the command line *and* drops the real
/// argument, corrupting what a reproducibility spec judges, whereas failing
/// to recognize a reference only means those arguments are not assessed
/// against a spec—[`analyzable_strings`] still scans them for leaked paths
/// and sentinels either way. So when in doubt, do not splice.
///
/// An empty `exec_path` never matches, so a param file with no path cannot
/// swallow every argument.
fn references(arg: &str, exec_path: &str) -> bool {
    if exec_path.is_empty() {
        return false;
    }
    let Some(prefix) = arg.strip_suffix(exec_path) else {
        return false;
    };
    prefix.ends_with('@') || prefix.ends_with("flagfile=")
}

/// The action's command line as the program actually receives it: `arguments`,
/// with every reference to a param file replaced, in place, by that file's
/// lines.
pub(crate) fn expanded_command_line(action: &Action) -> Vec<Sourced<'_>> {
    let mut expanded = Vec::with_capacity(action.arguments.len());

    for arg in &action.arguments {
        let referenced = action
            .param_files
            .iter()
            .find(|param_file| references(arg, &param_file.exec_path));

        match referenced {
            Some(param_file) => {
                expanded.extend(param_file.arguments.iter().map(|line| {
                    Sourced {
                        value: line,
                        source: ArgSource::ParamFile(&param_file.exec_path),
                    }
                }))
            }
            None => expanded.push(Sourced {
                value: arg,
                source: ArgSource::CommandLine,
            }),
        }
    }

    expanded
}

/// Every string in the action worth scanning for leaked sentinels and
/// absolute paths: the raw command line followed by the contents of *every*
/// param file, referenced or not.
///
/// The command line is taken raw rather than expanded, so each param file's
/// lines appear exactly once however many arguments reference the file.
pub(crate) fn analyzable_strings(action: &Action) -> Vec<Sourced<'_>> {
    let command_line = action.arguments.iter().map(|arg| Sourced {
        value: arg,
        source: ArgSource::CommandLine,
    });

    let param_file_lines =
        action.param_files.iter().flat_map(|param_file| {
            param_file.arguments.iter().map(move |line| Sourced {
                value: line,
                source: ArgSource::ParamFile(&param_file.exec_path),
            })
        });

    command_line.chain(param_file_lines).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use analysis_v2_proto::analysis::ParamFile;

    /// An action with the given command line and param files.
    fn action(
        arguments: &[&str],
        param_files: &[(&str, &[&str])],
    ) -> Action {
        Action {
            mnemonic: "Test".to_owned(),
            target_id: 1,
            arguments: arguments.iter().map(|a| (*a).to_owned()).collect(),
            param_files: param_files
                .iter()
                .map(|(exec_path, lines)| ParamFile {
                    exec_path: (*exec_path).to_owned(),
                    arguments: lines
                        .iter()
                        .map(|l| (*l).to_owned())
                        .collect(),
                })
                .collect(),
            ..Default::default()
        }
    }

    /// The values of a sourced list, dropping provenance.
    fn values<'a>(sourced: &[Sourced<'a>]) -> Vec<&'a str> {
        sourced.iter().map(|s| s.value).collect()
    }

    // ---- references ----

    #[test]
    fn the_at_prefix_is_a_reference() {
        assert!(references(
            "@bazel-out/k8-fastbuild/bin/foo-2.params",
            "bazel-out/k8-fastbuild/bin/foo-2.params"
        ));
    }

    #[test]
    fn a_flagfile_prefix_is_a_reference() {
        // Rules choose their own `param_file_arg` format string.
        assert!(references("--flagfile=out/foo.params", "out/foo.params"));
        assert!(references("-flagfile=out/foo.params", "out/foo.params"));
    }

    #[test]
    fn an_embedded_at_is_a_reference() {
        // Linker-style pass-through, e.g. `-Wl,@file`, and the doubled `@@`.
        assert!(references("-Wl,@out/foo.params", "out/foo.params"));
        assert!(references("@@out/foo.params", "out/foo.params"));
    }

    #[test]
    fn a_path_valued_flag_is_not_a_reference() {
        // The motivating false positive: a C++ module map is named by a flag that
        // has exactly the shape of `--flagfile=`, but its contents are a module
        // graph, not arguments. Splicing it would corrupt the command line.
        assert!(!references(
            "-fmodule-map-file=out/m.cppmap",
            "out/m.cppmap"
        ));
    }

    #[test]
    fn a_bare_path_is_not_a_reference() {
        // Legal as a `param_file_arg` format, but indistinguishable from an
        // ordinary path argument such as the operand of `-Xclang`. Not splicing
        // costs only spec assessment; `analyzable_strings` still scans the file.
        assert!(!references("out/foo.params", "out/foo.params"));
    }

    #[test]
    fn an_unrelated_argument_is_not_a_reference() {
        assert!(!references("-c", "out/foo.params"));
        assert!(!references("@out/other.params", "out/foo.params"));
        // The path must end the argument, not merely appear in it.
        assert!(!references("@out/foo.params.bak", "out/foo.params"));
        // A path that merely shares a suffix is not a reference: `xout/foo.params`
        // ends with the path but `x` is not a separator.
        assert!(!references("xout/foo.params", "out/foo.params"));
    }

    #[test]
    fn an_empty_exec_path_never_matches() {
        // Otherwise every argument would strip an empty suffix and "reference" it.
        assert!(!references("-c", ""));
        assert!(!references("", ""));
    }

    // ---- expanded_command_line ----

    #[test]
    fn a_command_line_without_param_files_is_unchanged() {
        let a = action(&["/usr/bin/gcc", "-c", "foo.c"], &[]);
        let expanded = expanded_command_line(&a);
        assert_eq!(values(&expanded), ["/usr/bin/gcc", "-c", "foo.c"]);
        assert!(
            expanded.iter().all(|s| s.source == ArgSource::CommandLine)
        );
    }

    #[test]
    fn a_referenced_param_file_is_spliced_in_place() {
        let a = action(
            &["gcc", "@out/foo.params", "-o", "foo.o"],
            &[("out/foo.params", &["-O2", "-DNDEBUG"])],
        );
        // The reference is replaced by its lines, in position.
        assert_eq!(
            values(&expanded_command_line(&a)),
            ["gcc", "-O2", "-DNDEBUG", "-o", "foo.o"]
        );
    }

    #[test]
    fn spliced_lines_are_attributed_to_their_param_file() {
        let a = action(
            &["gcc", "@out/foo.params"],
            &[("out/foo.params", &["-O2"])],
        );
        let expanded = expanded_command_line(&a);
        assert_eq!(expanded[0].source, ArgSource::CommandLine);
        assert_eq!(
            expanded[1].source,
            ArgSource::ParamFile("out/foo.params")
        );
    }

    #[test]
    fn an_unreferenced_param_file_is_not_spliced() {
        // C++ module maps: attached to the action, read as a file, never an
        // argument. Splicing them would feed module-graph text to a recognizer.
        let a = action(
            &["clang", "-fmodule-map-file=out/m.cppmap"],
            &[("out/m.cppmap", &["module \"crosstool\" [system] {"])],
        );
        assert_eq!(
            values(&expanded_command_line(&a)),
            ["clang", "-fmodule-map-file=out/m.cppmap"]
        );
    }

    #[test]
    fn an_empty_param_file_removes_the_reference() {
        let a =
            action(&["gcc", "@out/foo.params"], &[("out/foo.params", &[])]);
        assert_eq!(values(&expanded_command_line(&a)), ["gcc"]);
    }

    #[test]
    fn several_param_files_expand_independently() {
        let a = action(
            &["gcc", "@out/a.params", "-x", "@out/b.params"],
            &[("out/a.params", &["-O2"]), ("out/b.params", &["-DFOO"])],
        );
        assert_eq!(
            values(&expanded_command_line(&a)),
            ["gcc", "-O2", "-x", "-DFOO"]
        );
    }

    #[test]
    fn expansion_does_not_recurse() {
        // A reference *inside* a param file is left as a plain string, so a
        // self-referential graph cannot loop.
        let a = action(
            &["gcc", "@out/a.params"],
            &[
                ("out/a.params", &["@out/a.params", "-O2"]),
                ("out/b.params", &["-DNESTED"]),
            ],
        );
        assert_eq!(
            values(&expanded_command_line(&a)),
            ["gcc", "@out/a.params", "-O2"]
        );
    }

    #[test]
    fn a_command_line_with_no_arguments_expands_to_nothing() {
        let a = action(&[], &[("out/foo.params", &["-O2"])]);
        assert!(expanded_command_line(&a).is_empty());
    }

    // ---- analyzable_strings ----

    #[test]
    fn analyzable_strings_cover_the_command_line_and_every_param_file() {
        let a = action(
            &["clang", "@out/foo.params", "-fmodule-map-file=out/m.cppmap"],
            &[
                ("out/foo.params", &["-O2"]),
                ("out/m.cppmap", &["module \"crosstool\" {"]),
            ],
        );
        // Referenced and unreferenced param files alike are scanned, and the raw
        // command line is kept so nothing is dropped.
        assert_eq!(
            values(&analyzable_strings(&a)),
            [
                "clang",
                "@out/foo.params",
                "-fmodule-map-file=out/m.cppmap",
                "-O2",
                "module \"crosstool\" {",
            ]
        );
    }

    #[test]
    fn a_param_file_referenced_twice_is_scanned_once() {
        // The command line is taken raw, so the number of references does not
        // multiply the file's lines into duplicate violations.
        let a = action(
            &["gcc", "@out/foo.params", "@out/foo.params"],
            &[("out/foo.params", &["-O2"])],
        );
        let scanned = values(&analyzable_strings(&a));
        assert_eq!(scanned.iter().filter(|v| **v == "-O2").count(), 1);
    }

    #[test]
    fn param_file_lines_are_attributed_to_their_file() {
        let a = action(&["gcc"], &[("out/foo.params", &["-O2"])]);
        let scanned = analyzable_strings(&a);
        assert_eq!(
            scanned[1].source,
            ArgSource::ParamFile("out/foo.params")
        );
    }
}
