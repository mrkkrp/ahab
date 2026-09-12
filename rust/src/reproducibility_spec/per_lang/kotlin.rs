use super::super::library::{Entry, always};
use super::super::program_id::ProgramId;

/// A program rules_kotlin builds and runs as part of a Kotlin action.
fn kotlin_tool(path: &str) -> ProgramId {
    ProgramId::module("rules_kotlin", path)
}

/// Everything Ahab knows about Kotlin builds, in source order.
pub(in crate::reproducibility_spec) fn entries() -> Vec<(ProgramId, Entry)>
{
    vec![
        // One launcher stands behind every action: compiling Kotlin and
        // running annotation processors over it are the same binary given
        // different arguments. Sources, classpath, output and target
        // versions are all named, and nothing is left to differ about.
        (kotlin_tool("src/main/kotlin/build"), Entry::Spec(always())),
        // Merges the dependency files a Kotlin and a Java compilation each
        // produced for one target: reads `--inputs`, writes `--output`.
        (
            kotlin_tool("src/main/kotlin/jdeps_merger"),
            Entry::Spec(always()),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reproducibility_spec::Conformance;
    use crate::reproducibility_spec::per_lang::testing::assess;

    #[test]
    fn the_builder_is_reproducible_compiling_and_processing_alike() {
        let compiling = vec![
            "--target_label",
            "//x:x",
            "--rule_kind",
            "kt_jvm_library",
            "--kotlin_jvm_target",
            "1.8",
            "--output",
            "bazel-out/k8-fastbuild/bin/x/x-kt.jar",
        ];
        assert_eq!(
            assess(kotlin_tool("src/main/kotlin/build"), compiling),
            Conformance::Reproducible,
        );

        let processing = vec![
            "--target_label",
            "//x:x",
            "--kapt_generated_class_jar",
            "bazel-out/k8-fastbuild/bin/x/x-kapt-generated-class.jar",
        ];
        assert_eq!(
            assess(kotlin_tool("src/main/kotlin/build"), processing),
            Conformance::Reproducible,
        );
    }

    #[test]
    fn the_jdeps_merger_is_reproducible() {
        assert_eq!(
            assess(
                kotlin_tool("src/main/kotlin/jdeps_merger"),
                vec!["--output", "x.jdeps", "--inputs", "x-kt.jdeps"],
            ),
            Conformance::Reproducible,
        );
    }

    #[test]
    fn the_tools_are_reached_through_the_module_that_builds_them() {
        assert_eq!(
            ProgramId::of(
                "bazel-out/k8-opt-exec-ST-d57f/bin/external/rules_kotlin+\
                 /src/main/kotlin/build",
            ),
            kotlin_tool("src/main/kotlin/build"),
        );
    }
}
