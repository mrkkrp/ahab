//! Reconstructing what an action's command line actually contains.
//!
//! Bazel spills long command lines into *param files*, leaving `arguments`
//! holding only a reference such as `@bazel-out/…/foo-2.params`. A check
//! reading only `arguments` misses whatever the file holds, and misses it
//! quietly: the action looks clean precisely because it is the large one.
//! So param files are first-class here, every string tagged with
//! [`ArgSource`] so a violation can say where it came from.
//!
//! `param_files` "will be only set if explicitly requested", per
//! `analysis_v2.proto`, so [`crate::aquery::run_aquery`] always passes
//! `--include_param_files`.
//!
//! # Two kinds of param file
//!
//! * **Argument files** — referenced from the command line, holding
//!   arguments the program parses. These belong spliced into it.
//! * **Content files** — attached but never referenced, holding data the
//!   program reads as a *file*. C++ module maps are the common case.
//!
//! Hence the two views below. [`expanded_command_line`] is `argv`, and what
//! a reproducibility spec should judge; feeding it module-map text would
//! invite a recognizer to read a module graph as flags. [`analyzable_strings`]
//! is everything worth scanning for leaked paths, content files included.
//!
//! There is no single spelling of a reference: the format comes from the
//! rule's `param_file_arg`, `@%s` for native C++ and Java actions and
//! `--flagfile=%s` elsewhere. [`references`] keys off the one invariant part
//! and documents which legal formats it still rejects.
//!
//! Expansion is not recursive: Bazel does not nest param files, and
//! refusing to follow a reference found inside one rules out a cycle.

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
    pub value: &'a str,
    pub source: ArgSource<'a>,
}

/// Whether `arg` is a reference to the param file at `exec_path`: the path
/// verbatim at the end, preceded by something ending in `@` (`@path`,
/// `@@path`, `-Wl,@path`) or in `flagfile=`.
///
/// A bare path and a general `<flag>=<path>` are legal `param_file_arg`
/// formats and still rejected, neither being distinguishable by shape from
/// an ordinary path-valued argument: `-fmodule-map-file=out/m.cppmap` is
/// spelled exactly like `--flagfile=out/x.params`.
///
/// The asymmetry is deliberate. Splicing a content file corrupts what a
/// spec judges; missing a reference only leaves those arguments unassessed,
/// since [`analyzable_strings`] scans them either way.
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

/// The command line as the program receives it: `arguments`, with every
/// reference to a param file replaced in place by that file's lines.
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

/// Every string worth scanning for leaked sentinels and absolute paths: the
/// raw command line followed by *every* param file, referenced or not. Raw
/// rather than expanded, so each file's lines appear exactly once however
/// many arguments reference it.
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

    fn values<'a>(sourced: &[Sourced<'a>]) -> Vec<&'a str> {
        sourced.iter().map(|s| s.value).collect()
    }

    #[test]
    fn the_at_prefix_is_a_reference() {
        assert!(references(
            "@bazel-out/k8-fastbuild/bin/foo-2.params",
            "bazel-out/k8-fastbuild/bin/foo-2.params"
        ));
    }

    #[test]
    fn a_flagfile_prefix_is_a_reference() {
        assert!(references("--flagfile=out/foo.params", "out/foo.params"));
        assert!(references("-flagfile=out/foo.params", "out/foo.params"));
    }

    #[test]
    fn an_embedded_at_is_a_reference() {
        assert!(references("-Wl,@out/foo.params", "out/foo.params"));
        assert!(references("@@out/foo.params", "out/foo.params"));
    }

    #[test]
    fn a_path_valued_flag_is_not_a_reference() {
        assert!(!references(
            "-fmodule-map-file=out/m.cppmap",
            "out/m.cppmap"
        ));
    }

    #[test]
    fn a_bare_path_is_not_a_reference() {
        assert!(!references("out/foo.params", "out/foo.params"));
    }

    #[test]
    fn an_unrelated_argument_is_not_a_reference() {
        assert!(!references("-c", "out/foo.params"));
        assert!(!references("@out/other.params", "out/foo.params"));
        assert!(!references("@out/foo.params.bak", "out/foo.params"));
        assert!(!references("xout/foo.params", "out/foo.params"));
    }

    #[test]
    fn an_empty_exec_path_never_matches() {
        assert!(!references("-c", ""));
        assert!(!references("", ""));
    }

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
    fn analyzable_strings_cover_the_command_line_and_every_param_file() {
        let a = action(
            &["clang", "@out/foo.params", "-fmodule-map-file=out/m.cppmap"],
            &[
                ("out/foo.params", &["-O2"]),
                ("out/m.cppmap", &["module \"crosstool\" {"]),
            ],
        );
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
