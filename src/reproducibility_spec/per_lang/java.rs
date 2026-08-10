use super::super::library::{Entry, Transition, always};
use super::super::program_id::ProgramId;
use super::super::{Reproducibility, ReproducibilitySpec};

/// A program in Stardoc, the generator of Starlark documentation.
fn stardoc(path: &str) -> ProgramId {
    ProgramId::module("stardoc", path)
}

/// A program the `toolchains` extension of rules_java brings in: the JDK
/// itself, and the tools Bazel builds Java with. Which JDK and which
/// platform are part of the repository name rather than this one, so the
/// same entry answers for `remotejdk25_linux` and whatever succeeds it.
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
        // Every input the renderer has is named on the command line and
        // built by the same build: `--input` is a serialized proto that an
        // earlier action extracted from the Starlark, and the seven
        // templates are Velocity files shipped inside Stardoc. It reads
        // those, fills them in, and writes one markdown file. Nothing is
        // read from the environment and no path is absolute, so two runs
        // over the same proto have nothing to disagree about.
        //
        // The JVM underneath is not part of this claim, and does not need
        // to be: filling in a template is not the sort of work whose answer
        // depends on which Java is running it.
        (
            stardoc(
                "src/main/java/com/google/devtools/build/stardoc/renderer\
                 /renderer",
            ),
            Entry::Spec(always()),
        ),
        // The JVM is not a tool, it is how the tools are started. Every Java
        // action in a Bazel build runs `java <options> -jar <tool>`, so what
        // the action really runs is the jar, and answering for `java` would
        // be answering for whatever anyone puts after it. Handing over at
        // `-jar` puts the question where it can be decided: the jars below
        // carry the verdicts, and a `java` invoked some other way—with a
        // classpath and a main class—matches nothing here and is reported
        // rather than waved through.
        (
            java_tool("bin/java"),
            Entry::Wraps(Transition::AfterSeparator {
                separator: "-jar".to_owned(),
            }),
        ),
        // JavaBuilder is javac with Bazel's arguments around it. Compiling
        // the same sources against the same classpath yields the same class
        // files, and it writes them into a jar it normalizes itself.
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
        // Turbine reads sources and produces a header jar: the signatures
        // alone, with no method bodies. It is a function of the sources and
        // the classpath it is given, both named in the action.
        (java_tool(TURBINE_JAR), Entry::Spec(always())),
        // The same compiler ahead-of-time compiled into a native binary, so
        // that a header compilation need not start a JVM. Declared a synonym
        // rather than described again: it is the same program, and the two
        // could not be allowed to disagree.
        (
            java_tool("java_tools/turbine_direct_graal"),
            Entry::SameAs(java_tool(TURBINE_JAR)),
        ),
        // ijar strips a jar to its interface, dropping method bodies and
        // the debugging information that would otherwise make a header jar
        // change whenever an implementation did. It normalizes what it
        // writes, which is the whole point of it.
        (java_tool("java_tools/ijar/ijar"), Entry::Spec(always())),
        // singlejar merges jars, and the two ways a jar stops being a
        // function of its contents are both things it is told not to do.
        // `--normalize` fixes the timestamp on every entry, which would
        // otherwise be the moment the action ran. `--exclude_build_data`
        // leaves out `build-data.properties`, which records the user and
        // the machine that built it. rules_java passes both every time; a
        // build that does not is not merging jars reproducibly.
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
        // The shape of every Java action: JVM options, `-jar`, the tool.
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
        // The verdict belongs to JavaBuilder, and the JVM's own options are
        // not mistaken for the tool's.
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
        // A classpath and a main class instead. The transition does not
        // fire, so the JVM stays the program—and the JVM has no spec, which
        // is what makes this report rather than pass.
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
        // Each is load-bearing on its own: one silences the clock, the
        // other the name of whoever ran it, and neither implies the other.
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
        // The action still reports the binary it ran...
        assert_eq!(
            native.program,
            java_tool("java_tools/turbine_direct_graal"),
        );
        // ...while the verdict is credited to the jar.
        assert_eq!(native.synonym(), Some(&java_tool(TURBINE_JAR)));
    }

    #[test]
    fn the_jdk_is_reached_without_naming_a_version_or_a_platform() {
        // The repository is `remotejdk25_linux` today and something else
        // tomorrow; the entry has to survive that.
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
