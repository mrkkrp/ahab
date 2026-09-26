//! The strings of an action the leak checks scan, each with where it came
//! from, so a violation can say where it was found.

use analysis_v2_proto::analysis::Action;

use crate::reproducibility_spec::library::{
    SubstitutedArgs, substituted_words,
};
use crate::reproducibility_spec::program_id::ProgramId;

/// Where within an action a string Ahab analyzed came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum ArgSource<'a> {
    /// Directly on the action's command line (its `arguments`).
    CommandLine,
    /// A line of the param file at this exec path.
    ParamFile(&'a str),
    /// An argument `template` substituted for `key` ahead of the ones the
    /// action passes.
    Substitution {
        template: &'a ProgramId,
        key: &'a str,
    },
}

/// One analyzed string together with its provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct Sourced<'a> {
    pub value: &'a str,
    pub source: ArgSource<'a>,
}

/// Every string worth scanning for leaked sentinels and absolute paths: the
/// raw command line followed by *every* param file, referenced or not, and
/// then the arguments `substituted`. Raw rather than expanded, so each
/// file's lines appear exactly once however many arguments reference it.
pub(super) fn analyzable_strings<'a>(
    action: &'a Action,
    substituted: Option<&'a SubstitutedArgs<'_>>,
) -> Vec<Sourced<'a>> {
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

    let substituted_words = substituted.into_iter().flat_map(|args| {
        substituted_words(args.value).map(|word| Sourced {
            value: word,
            source: ArgSource::Substitution {
                template: &args.template,
                key: args.key,
            },
        })
    });

    command_line
        .chain(param_file_lines)
        .chain(substituted_words)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::tests::action_with_param_files;

    fn action(
        arguments: &[&str],
        param_files: &[(&str, &[&str])],
    ) -> Action {
        action_with_param_files("Test", 1, arguments, param_files)
    }

    fn values<'a>(sourced: &[Sourced<'a>]) -> Vec<&'a str> {
        sourced.iter().map(|s| s.value).collect()
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
            values(&analyzable_strings(&a, None)),
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
        let scanned = values(&analyzable_strings(&a, None));
        assert_eq!(scanned.iter().filter(|v| **v == "-O2").count(), 1);
    }

    #[test]
    fn param_file_lines_are_attributed_to_their_file() {
        let a = action(&["gcc"], &[("out/foo.params", &["-O2"])]);
        let scanned = analyzable_strings(&a, None);
        assert_eq!(
            scanned[1].source,
            ArgSource::ParamFile("out/foo.params")
        );
    }

    #[test]
    fn substituted_words_come_last_and_are_attributed_to_the_template() {
        let template = ProgramId::module("rules_acme", "acme/run.sh.tpl");
        let substituted = SubstitutedArgs {
            template: template.clone(),
            key: "{{args}}",
            value: "--quiet  --out=x",
        };
        let a = action(&["run"], &[("out/foo.params", &["-O2"])]);
        let scanned = analyzable_strings(&a, Some(&substituted));
        assert_eq!(values(&scanned), ["run", "-O2", "--quiet", "--out=x"]);
        assert_eq!(
            scanned[2].source,
            ArgSource::Substitution {
                template: &template,
                key: "{{args}}",
            }
        );
    }
}
