use super::super::library::{Entry, Transition, always};
use super::super::program_id::ProgramId;
use super::super::{Reproducibility, ReproducibilitySpec};

/// A program in Stardoc, the generator of Starlark documentation.
fn stardoc(path: &str) -> ProgramId {
    ProgramId::module("stardoc", path)
}

/// A program the `toolchains` extension of rules_java brings in. Which JDK
/// and which platform are part of the repository name rather than this one,
/// so one entry answers for `remotejdk25_linux` and its successors.
fn java_tool(path: &str) -> ProgramId {
    ProgramId::extension("rules_java", "toolchains", path)
}

/// The flags without which `singlejar` does not produce the same jar twice.
const SINGLEJAR_REQUIRED: [&str; 2] =
    ["--normalize", "--exclude_build_data"];

/// Turbine, which rules_java ships twice over.
const TURBINE_JAR: &str = "java_tools/turbine_direct_binary_deploy.jar";

/// Everything Ahab knows about JVM programs, in source order.
pub(in crate::reproducibility_spec) fn entries() -> Vec<(ProgramId, Entry)>
{
    vec![
        // Every input is named on the command line and built by the same
        // build: `--input` is a proto an earlier action extracted from the
        // Starlark, and the templates ship inside Stardoc. Filling them in
        // and writing markdown reads nothing from the environment.
        (
            stardoc(
                "src/main/java/com/google/devtools/build/stardoc/renderer\
                 /renderer",
            ),
            Entry::Spec(always()),
        ),
        // Every Java action runs `java <options> -jar <tool>`, so what runs
        // is the jar and answering for `java` would answer for whatever
        // follows it. A `java` invoked otherwise—classpath and main
        // class—matches nothing here and is reported rather than waved past.
        (
            java_tool("bin/java"),
            Entry::Wraps(Transition::AfterSeparator {
                separator: "-jar".to_owned(),
            }),
        ),
        // javac with Bazel's arguments around it, writing the class files
        // into a jar it normalizes itself.
        (
            java_tool("java_tools/JavaBuilder_deploy.jar"),
            Entry::Spec(always()),
        ),
        // GenClass reads the class files a compilation produced and writes
        // the ones belonging to generated sources into a jar of their own.
        (
            java_tool("java_tools/GenClass_deploy.jar"),
            Entry::Spec(always()),
        ),
        // Produces a header jar—signatures alone—from the sources and
        // classpath named in the action.
        (java_tool(TURBINE_JAR), Entry::Spec(always())),
        // The same compiler AOT-compiled into a native binary, so a header
        // compilation need not start a JVM.
        (
            java_tool("java_tools/turbine_direct_graal"),
            Entry::SameAs(java_tool(TURBINE_JAR)),
        ),
        // Strips a jar to its interface, normalizing what it writes.
        (java_tool("java_tools/ijar/ijar"), Entry::Spec(always())),
        // `--normalize` fixes the timestamp on every entry, which would
        // otherwise be the moment the action ran; `--exclude_build_data`
        // leaves out `build-data.properties`, which records the user and
        // machine. rules_java passes both every time.
        (
            java_tool("java_tools/src/tools/singlejar/singlejar_local"),
            Entry::Spec(ReproducibilitySpec::new(
                Reproducibility::Sometimes,
                SINGLEJAR_REQUIRED,
                [] as [&str; 0],
            )),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reproducibility_spec::Conformance;
    use crate::reproducibility_spec::library::Library;
    use crate::reproducibility_spec::per_lang::testing::assess;

    /// A `singlejar` command line as rules_java writes it.
    fn singlejar_args() -> Vec<&'static str> {
        vec![
            "--output",
            "bazel-out/k8-fastbuild/bin/x/libx-src.jar",
            "--compression",
            "--normalize",
            "--exclude_build_data",
            "--warn_duplicate_resources",
        ]
    }

    fn singlejar() -> ProgramId {
        java_tool("java_tools/src/tools/singlejar/singlejar_local")
    }

    #[test]
    fn java_hands_the_question_to_the_jar_it_runs() {
        let resolution = Library::builtin().resolve(
            java_tool("bin/java"),
            vec![
                "--add-opens=java.base/java.lang=ALL-UNNAMED",
                "-Xlog:disable",
                "-jar",
                "external/rules_java++toolchains+remote_java_tools\
                 /java_tools/JavaBuilder_deploy.jar",
                "--output",
                "libx.jar",
            ],
        );
        assert_eq!(
            resolution.program,
            java_tool("java_tools/JavaBuilder_deploy.jar"),
        );
        assert_eq!(resolution.args, vec!["--output", "libx.jar"]);
        let (_, spec) = resolution.spec.clone().expect("a spec");
        assert_eq!(spec.assess(resolution.args), Conformance::Reproducible);
    }

    #[test]
    fn a_java_invoked_without_a_jar_is_not_vouched_for() {
        let resolution = Library::builtin().resolve(
            java_tool("bin/java"),
            vec!["-cp", "x.jar:y.jar", "com.example.Main"],
        );
        assert_eq!(resolution.program, java_tool("bin/java"));
        assert!(resolution.spec.is_none());
    }

    #[test]
    fn singlejar_as_rules_java_invokes_it_is_reproducible() {
        assert_eq!(
            assess(singlejar(), singlejar_args()),
            Conformance::Reproducible,
        );
    }

    #[test]
    fn singlejar_without_its_normalizing_flags_is_not() {
        for dropped in SINGLEJAR_REQUIRED {
            let kept: Vec<&str> = singlejar_args()
                .into_iter()
                .filter(|arg| *arg != dropped)
                .collect();
            let verdict = assess(singlejar(), kept);
            assert!(
                matches!(verdict, Conformance::Conditional { .. }),
                "expected {dropped} to matter, got {verdict:?}",
            );
            assert_eq!(
                verdict.missing_required().iter().collect::<Vec<_>>(),
                vec![dropped],
                "dropping {dropped}",
            );
        }
    }

    #[test]
    fn both_turbines_are_judged_by_one_entry() {
        let native = Library::builtin().resolve(
            java_tool("java_tools/turbine_direct_graal"),
            vec!["--output", "libx-hjar.jar"],
        );
        assert_eq!(
            native.program,
            java_tool("java_tools/turbine_direct_graal"),
        );
        assert_eq!(native.synonym(), Some(&java_tool(TURBINE_JAR)));
    }

    #[test]
    fn the_jdk_is_reached_without_naming_a_version_or_a_platform() {
        assert_eq!(
            ProgramId::of(
                "external/rules_java++toolchains+remotejdk25_linux/bin/java",
            ),
            java_tool("bin/java"),
        );
        assert_eq!(
            ProgramId::of(
                "external/rules_java++toolchains+remote_java_tools_linux\
                 /java_tools/ijar/ijar",
            ),
            java_tool("java_tools/ijar/ijar"),
        );
    }
}
