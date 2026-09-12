//! JavaScript and TypeScript builds.
//!
//! An npm package may carry scripts the package manager runs on
//! installation, and that is where a JavaScript build stops being a
//! function of its inputs. TypeScript shares this module because its
//! compiler is an npm package reached the same way.

use super::super::library::{Entry, always, never, under_both_names};
use super::super::program_id::ProgramId;
use super::super::{Reproducibility, ReproducibilitySpec};

/// One of rules_js's own tools, under both names it answers to.
fn rules_js_tool(path: &str) -> Vec<(ProgramId, Entry)> {
    under_both_names("aspect_rules_js", path, Entry::Spec(never()))
}

/// A program in the repository rules_ts's `typescript` extension builds.
/// The extension is named for where it is defined, so every project
/// following rules_ts's own instructions reaches these under this identity.
/// A project that gets the extension through an intermediate module does
/// not match.
fn npm_typescript(path: &str) -> ProgramId {
    ProgramId::main_extension("typescript", path)
}

/// A program shipped by J2CL.
fn j2cl(path: &str) -> ProgramId {
    ProgramId::module("j2cl", path)
}

/// The worker shared by rules_closure's compiler and validators.
fn closure_worker() -> ProgramId {
    ProgramId::module(
        "rules_closure",
        "java/io/bazel/rules/closure/ClosureWorker",
    )
}

/// Everything Ahab knows about JavaScript builds, in source order.
pub(in crate::reproducibility_spec) fn entries() -> Vec<(ProgramId, Entry)>
{
    // The runner for npm lifecycle hooks, which executes whatever a
    // third-party `package.json` says—or `node-gyp rebuild` against the
    // machine's C++ toolchain when a package ships a `binding.gyp` and no
    // install script. `never` rather than unknown: no flag could redeem it,
    // because the code it runs is not in the build at all.
    let mut entries = rules_js_tool("npm/private/lifecycle/min/bin_/bin");

    // Dispatches the Closure compiler, its library checker and the webfiles
    // validator, each reading the sources, manifests and options named by
    // the action. The webfiles archive writer fixes every ZIP timestamp.
    entries.push((closure_worker(), Entry::Spec(always())));

    // Writes its source jar through J2CL's Bazel output helper, which
    // resets every timestamp to the epoch.
    entries.push((
        j2cl(
            "tools/java/com/google/j2cl/tools/gwtincompatible\
             /GwtIncompatibleStripper_worker",
        ),
        Entry::Spec(always()),
    ));

    // The same output helper, plus a per-target temporary directory cleared
    // before each worker request, so nothing carries over between them.
    entries.push((
        j2cl("transpiler/java/com/google/j2cl/transpiler/BazelJ2clBuilder"),
        Entry::Spec(always()),
    ));

    // The TypeScript compiler: what it emits follows from the sources and
    // the `tsconfig.json`, and rules_ts hands it relative paths throughout.
    //
    // Except `--generateTrace`, which writes a Chrome tracing file whose
    // every event is stamped from the performance counter or `Date.now`.
    // rules_ts declares the trace directory as an output, so those timings
    // are part of what the build produces.
    //
    // Deliberately not conditions: `--diagnostics`, `--extendedDiagnostics`,
    // `--listFiles`, `--listEmittedFiles` and `--traceResolution` report
    // timings too, but to standard output, which is not an artifact.
    entries.push((
        npm_typescript("tsc_/tsc"),
        Entry::Spec(ReproducibilitySpec::new(
            Reproducibility::Sometimes,
            [] as [&str; 0],
            ["--generateTrace"],
        )),
    ));

    // rules_ts's own checker: reads the `tsconfig.json`, compares it against
    // the rule's attributes and writes them back out as a marker. Where tsc
    // reports an absolute path it relativizes first, since sandbox paths
    // differ across builds.
    entries.push((
        npm_typescript("validator_/validator"),
        Entry::Spec(always()),
    ));

    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reproducibility_spec::Conformance;
    use crate::reproducibility_spec::library::Library;
    use crate::reproducibility_spec::per_lang::testing::assess;

    /// The lifecycle runner's path, as both rule set and project see it.
    const LIFECYCLE: &str = "npm/private/lifecycle/min/bin_/bin";

    #[test]
    fn running_a_packages_install_scripts_is_never_reproducible() {
        assert_eq!(
            assess(
                ProgramId::module("aspect_rules_js", LIFECYCLE),
                vec![
                    "--bazel-bindir",
                    "bazel-out/k8-fastbuild/bin",
                    "pngjs",
                    "../../../external/+npm+npm__pngjs__5.0.0/package",
                    "--platform=linux",
                    "--arch=x64",
                ],
            ),
            Conformance::NeverReproducible,
        );
    }

    #[test]
    fn compiling_typescript_is_reproducible() {
        for args in [
            vec![
                "--project",
                "ts/test/tsconfig.json",
                "--rootDir",
                "ts/test",
            ],
            vec![
                "--outDir",
                "ts/test/out-dir",
                "--declarationDir",
                "ts/test/out-dir",
                "--project",
                "ts/test/tsconfig_dirty_out_dir.json",
                "--rootDir",
                "ts/test",
            ],
        ] {
            assert_eq!(
                assess(npm_typescript("tsc_/tsc"), args.clone()),
                Conformance::Reproducible,
                "{args:?}",
            );
        }
    }

    #[test]
    fn asking_the_compiler_for_a_trace_records_the_clock() {
        assert!(matches!(
            assess(
                npm_typescript("tsc_/tsc"),
                vec![
                    "--project",
                    "ts/test/tsconfig.json",
                    "--generateTrace",
                    "ts/test/traced_ts_trace",
                ],
            ),
            Conformance::Conditional { .. }
        ));
        assert_eq!(
            assess(
                npm_typescript("tsc_/tsc"),
                vec![
                    "--project",
                    "ts/test/tsconfig.json",
                    "--diagnostics",
                    "--extendedDiagnostics",
                    "--listFiles",
                    "--listEmittedFiles",
                    "--traceResolution",
                ],
            ),
            Conformance::Reproducible,
        );
    }

    #[test]
    fn the_options_validator_is_vouched_for() {
        assert_eq!(
            assess(
                npm_typescript("validator_/validator"),
                vec![
                    "ts/test/tsconfig.json",
                    "ts/test/dir_params.validation",
                    "@@//ts/test:dir",
                    "ts/test",
                ],
            ),
            Conformance::Reproducible,
        );
    }

    #[test]
    fn closure_compilation_and_validation_are_reproducible() {
        for args in [
            vec!["JsChecker", "--src", "lib.js", "--output", "lib.pbtxt"],
            vec![
                "JsCompiler",
                "--js",
                "lib.js",
                "--js_output_file",
                "app.js",
            ],
            vec![
                "WebfilesValidator",
                "--target",
                "app.pb",
                "--output",
                "validated",
            ],
        ] {
            assert_eq!(
                assess(closure_worker(), args.clone()),
                Conformance::Reproducible,
                "{args:?}",
            );
        }
    }

    #[test]
    fn j2cl_tools_are_reproducible() {
        for (program, args) in [
            (
                j2cl(
                    "tools/java/com/google/j2cl/tools/gwtincompatible\
                     /GwtIncompatibleStripper_worker",
                ),
                vec!["-d", "stripped-src.jar", "Example.java"],
            ),
            (
                j2cl(
                    "transpiler/java/com/google/j2cl/transpiler\
                     /BazelJ2clBuilder",
                ),
                vec![
                    "-classpath",
                    "deps.jar",
                    "-output",
                    "example.js",
                    "Example.java",
                ],
            ),
        ] {
            assert_eq!(
                assess(program, args.clone()),
                Conformance::Reproducible,
                "{args:?}",
            );
        }
    }

    #[test]
    fn the_runner_answers_to_both_of_its_names() {
        let from_main =
            Library::builtin().resolve(ProgramId::main(LIFECYCLE), vec![]);
        assert_eq!(
            from_main.synonym(),
            Some(&ProgramId::module("aspect_rules_js", LIFECYCLE)),
        );
    }
}
