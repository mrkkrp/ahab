//! Reconstructing what an action's command line actually contains.
//!
//! Bazel spills long command lines into *param files*, leaving `arguments`
//! holding only a reference such as `@bazel-out/…/foo-2.params`. A check
//! reading only `arguments` misses whatever the file holds, and misses it
//! quietly: the action looks clean precisely because it is the large one.
//! So the command line is rebuilt here with its param files spliced in.
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
//! Hence [`expanded_command_line`] splices only the former. It is `argv`,
//! and what a reproducibility spec should judge; feeding it module-map text
//! would invite a recognizer to read a module graph as flags. The leak
//! checks scan every param file instead, content files included.
//!
//! There is no single spelling of a reference: the format comes from the
//! rule's `param_file_arg`, `@%s` for native C++ and Java actions and
//! `--flagfile=%s` elsewhere. [`references`] keys off the one invariant part
//! and documents which legal formats it still rejects.
//!
//! Expansion is not recursive: Bazel does not nest param files, and
//! refusing to follow a reference found inside one rules out a cycle.

use analysis_v2_proto::analysis::Action;

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
/// since the leak checks scan them either way.
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
///
/// A reference to an empty param file is left as it stands, because aquery
/// reports such a file on some runs and leaves it out on others, and the
/// verdict must not depend on which.
pub(crate) fn expanded_command_line(action: &Action) -> Vec<&str> {
    let mut expanded = Vec::with_capacity(action.arguments.len());

    for arg in &action.arguments {
        let referenced = action.param_files.iter().find(|param_file| {
            !param_file.arguments.is_empty()
                && references(arg, &param_file.exec_path)
        });

        match referenced {
            Some(param_file) => expanded
                .extend(param_file.arguments.iter().map(String::as_str)),
            None => expanded.push(arg.as_str()),
        }
    }

    expanded
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
        assert_eq!(
            expanded_command_line(&a),
            ["/usr/bin/gcc", "-c", "foo.c"]
        );
    }

    #[test]
    fn a_reference_to_an_empty_param_file_is_left_in_place() {
        let a = action(
            &["tar", "--create", "@out/empty_mtree.txt"],
            &[("out/empty_mtree.txt", &[])],
        );
        assert_eq!(
            expanded_command_line(&a),
            ["tar", "--create", "@out/empty_mtree.txt"],
        );
    }

    #[test]
    fn a_referenced_param_file_is_spliced_in_place() {
        let a = action(
            &["gcc", "@out/foo.params", "-o", "foo.o"],
            &[("out/foo.params", &["-O2", "-DNDEBUG"])],
        );
        assert_eq!(
            expanded_command_line(&a),
            ["gcc", "-O2", "-DNDEBUG", "-o", "foo.o"]
        );
    }

    #[test]
    fn an_unreferenced_param_file_is_not_spliced() {
        let a = action(
            &["clang", "-fmodule-map-file=out/m.cppmap"],
            &[("out/m.cppmap", &["module \"crosstool\" [system] {"])],
        );
        assert_eq!(
            expanded_command_line(&a),
            ["clang", "-fmodule-map-file=out/m.cppmap"]
        );
    }

    #[test]
    fn several_param_files_expand_independently() {
        let a = action(
            &["gcc", "@out/a.params", "-x", "@out/b.params"],
            &[("out/a.params", &["-O2"]), ("out/b.params", &["-DFOO"])],
        );
        assert_eq!(
            expanded_command_line(&a),
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
            expanded_command_line(&a),
            ["gcc", "@out/a.params", "-O2"]
        );
    }
}
