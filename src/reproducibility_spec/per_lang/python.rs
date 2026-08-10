use super::super::library::{Entry, Transition};
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
        // The interpreter is not a tool, it is how the tools are started,
        // and the same argument applies to it as to the JVM: answering for
        // `python3` would be answering for whatever script anyone hands it.
        // Unlike `java` there is no `-jar` to hand over at—the script is
        // simply the first argument—so the transition is positional, and
        // declines to fire for `python3 -c` and `python3 -m`, which name no
        // program to judge.
        (
            rules_python("python/private/python3"),
            Entry::Wraps(Transition::FirstArgument),
        ),
        // Compiling `.py` to `.pyc` is where Python decides what to record
        // about the source it came from. In `timestamp` mode—Python's own
        // default—a `.pyc` stores the source's modification time and size,
        // which makes it a function of when the tree was checked out. The
        // two hash modes store a digest of the source instead, and either
        // will do, which is why the pattern asks for the word rather than
        // naming both.
        //
        // The mode arrives as a separate argument, so the flag is declared
        // as taking a value and the pair is folded before the pattern sees
        // it.
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
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reproducibility_spec::Conformance;
    use crate::reproducibility_spec::library::Library;
    use crate::reproducibility_spec::per_lang::testing::assess;

    /// A `PyCompile` command line as rules_python writes it, from the
    /// interpreter onwards.
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
        // The verdict belongs to the precompiler, and the script's own
        // path is not mistaken for one of its arguments.
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
        // `python3 -c` runs code from the command line and `python3 -m` a
        // module resolved at runtime. Neither names a program, so the
        // transition declines and the interpreter—which has no spec—is
        // what gets reported.
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
        // Either hash mode records a digest of the source...
        for good in ["unchecked_hash", "checked_hash"] {
            assert_eq!(mode(good), Conformance::Reproducible, "{good}");
        }
        // ...while the timestamp mode records when the tree was checked
        // out. Distinguishing these is the whole reason the value has to
        // be reachable.
        assert!(matches!(
            mode("timestamp"),
            Conformance::Conditional { .. }
        ));
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
