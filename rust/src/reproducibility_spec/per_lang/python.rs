use super::super::library::{Entry, Transition, always};
use super::super::program_id::ProgramId;
use super::super::{Reproducibility, ReproducibilitySpec};

/// A program rules_python builds or downloads.
fn rules_python(path: &str) -> ProgramId {
    ProgramId::module("rules_python", path)
}

/// Everything Ahab knows about Python builds, in source order.
pub(in crate::reproducibility_spec) fn entries() -> Vec<(ProgramId, Entry)>
{
    vec![
        // As with the JVM, answering for the interpreter would be answering
        // for whatever script anyone hands it. There is no `-jar` to hand
        // over at—the script is simply the first argument—so the transition
        // is positional and declines for `python3 -c` and `python3 -m`.
        (
            rules_python("python/private/python3"),
            Entry::Wraps(Transition::FirstArgument),
        ),
        // In `timestamp` mode—Python's default—a `.pyc` stores the source's
        // modification time and size. The two hash modes store a digest
        // instead, and either will do, hence the pattern on the word. The
        // mode is a separate argument, so the flag is declared as valued.
        (
            rules_python("tools/precompiler/precompiler"),
            Entry::Spec(
                ReproducibilitySpec::new(
                    Reproducibility::Sometimes,
                    ["--invalidation_mode=*hash*"],
                    [] as [&str; 0],
                )
                .with_valued_flags(["--invalidation_mode"]),
            ),
        ),
        // The same precompiler under the name a later rules_python gives it.
        (
            rules_python("tools/precompiler/precompiler_.py"),
            Entry::SameAs(rules_python("tools/precompiler/precompiler")),
        ),
        // Writes what a `py_binary` reports about how it was built: label,
        // compilation mode, whether it was stamped—all from the target's own
        // attributes. Stamping also copies in Bazel's status files, which is
        // an input rather than a flag and the workspace status check's
        // business; saying it here too would report one problem as two.
        (
            rules_python("python/private/build_data_writer.sh"),
            Entry::Spec(always()),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reproducibility_spec::Conformance;
    use crate::reproducibility_spec::library::Library;
    use crate::reproducibility_spec::per_lang::testing::assess;

    /// A `PyCompile` command line, from the interpreter onwards.
    fn pycompile() -> Vec<&'static str> {
        vec![
            "bazel-out/k8-opt-exec/bin/external/rules_python+/tools\
             /precompiler/precompiler",
            "--invalidation_mode",
            "unchecked_hash",
            "--src",
            "doc_build/merge.py",
            "--pyc",
            "bazel-out/k8-opt-exec/bin/doc_build/__pycache__/merge.pyc",
        ]
    }

    #[test]
    fn the_interpreter_hands_the_question_to_the_script() {
        let resolution = Library::builtin()
            .resolve(rules_python("python/private/python3"), pycompile());
        assert_eq!(
            resolution.program,
            rules_python("tools/precompiler/precompiler"),
        );
        assert_eq!(resolution.args.first(), Some(&"--invalidation_mode"));
        let (_, spec) = resolution.spec.clone().expect("a spec");
        assert_eq!(spec.assess(resolution.args), Conformance::Reproducible);
    }

    #[test]
    fn an_interpreter_given_no_script_is_not_vouched_for() {
        for form in [vec!["-c", "print(1)"], vec!["-m", "compileall"]] {
            let resolution = Library::builtin()
                .resolve(rules_python("python/private/python3"), form);
            assert_eq!(
                resolution.program,
                rules_python("python/private/python3"),
            );
            assert!(resolution.spec.is_none());
        }
    }

    #[test]
    fn precompiling_against_the_clock_is_reported() {
        let precompiler = rules_python("tools/precompiler/precompiler");
        let mode = |mode: &'static str| {
            let mut flags = vec!["--invalidation_mode", mode];
            flags.extend(["--src", "x.py", "--pyc", "x.pyc"]);
            assess(precompiler.clone(), flags)
        };
        for good in ["unchecked_hash", "checked_hash"] {
            assert_eq!(mode(good), Conformance::Reproducible, "{good}");
        }
        assert!(matches!(
            mode("timestamp"),
            Conformance::Conditional { .. }
        ));
    }

    #[test]
    fn the_precompiler_answers_under_either_of_its_file_names() {
        let resolution = Library::builtin().resolve(
            rules_python("tools/precompiler/precompiler_.py"),
            vec!["--invalidation_mode", "timestamp", "--src", "x.py"],
        );
        assert_eq!(
            resolution.synonym(),
            Some(&rules_python("tools/precompiler/precompiler")),
        );
        let (_, spec) = resolution.spec.clone().expect("a spec");
        assert!(matches!(
            spec.assess(resolution.args),
            Conformance::Conditional { .. }
        ));
    }

    #[test]
    fn writing_build_data_is_vouched_for() {
        assert_eq!(
            assess(
                rules_python("python/private/build_data_writer.sh"),
                vec![],
            ),
            Conformance::Reproducible,
        );
    }

    #[test]
    fn precompiling_without_choosing_a_mode_is_reported() {
        let flags: Vec<&str> = pycompile()
            .into_iter()
            .skip(1)
            .filter(|arg| {
                *arg != "--invalidation_mode" && *arg != "unchecked_hash"
            })
            .collect();
        assert!(matches!(
            assess(rules_python("tools/precompiler/precompiler"), flags),
            Conformance::Conditional { .. }
        ));
    }
}
