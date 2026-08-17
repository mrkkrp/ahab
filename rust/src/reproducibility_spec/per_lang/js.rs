//! JavaScript and TypeScript builds.
//!
//! The npm ecosystem's unit of distribution is a package that may carry
//! scripts the package manager is expected to run on installation, and that
//! is where a JavaScript build stops being a function of its inputs.
//!
//! TypeScript shares this module rather than getting its own. Its compiler
//! is an npm package, reached through the same `node_modules` machinery and
//! launched by the same rules_js `js_binary`, so what Ahab has to know to
//! name a program is the same knowledge in both cases.

use super::super::library::{Entry, always, never};
use super::super::program_id::ProgramId;
use super::super::{Reproducibility, ReproducibilitySpec};

/// One of rules_js's own tools, under both names it answers to.
///
/// Depend on rules_js and its tools arrive from the module; analyze rules_js
/// itself and the same tools are in the main one. The same loose end as
/// rules_pkg's: the second form matches on path alone, so a project building
/// something at the same path inherits a verdict meant for rules_js.
fn rules_js_tool(path: &str) -> Vec<(ProgramId, Entry)> {
    let module = ProgramId::module("aspect_rules_js", path);
    vec![
        (module.clone(), Entry::Spec(never())),
        (ProgramId::main(path), Entry::SameAs(module)),
    ]
}

/// A program in the repository rules_ts's `typescript` extension builds.
///
/// The extension takes its name from where it is defined, not from where it
/// is called, so every project that follows rules_ts's own instructions—
/// `use_extension("@aspect_rules_ts//ts:extensions.bzl", "typescript")`—
/// reaches these under this same identity. The loose end is a project that
/// gets the extension through some intermediate module instead: then the
/// repository is that module's and this does not match.
fn npm_typescript(path: &str) -> ProgramId {
    ProgramId::main_extension("typescript", path)
}

/// Everything Ahab knows about JavaScript builds, in source order.
pub(in crate::reproducibility_spec) fn entries() -> Vec<(ProgramId, Entry)>
{
    // The runner for npm lifecycle hooks: `preinstall`, `install`,
    // `postinstall`. What it executes is whatever the `scripts` of a
    // third-party `package.json` say, through `@pnpm/lifecycle`, and when a
    // package ships a `binding.gyp` and no install script of its own the
    // runner supplies `node-gyp rebuild`—which compiles C++ against
    // whatever toolchain the machine has.
    //
    // So this is `never` rather than unknown. Unknown would say nobody has
    // described it yet; the truth is that no flag could redeem it, because
    // the code it runs is not in the build at all. rules_js says as much
    // itself: of the seven such actions in its own tree, four declare
    // `requires-network` and five `no-sandbox`.
    let mut entries = rules_js_tool("npm/private/lifecycle/min/bin_/bin");

    // The TypeScript compiler. What it emits is decided by the sources and
    // the `tsconfig.json` it is pointed at—there is no clock on the path
    // that writes JavaScript, declarations, source maps or a
    // `.tsbuildinfo`, and rules_ts hands it relative paths for `--rootDir`,
    // `--outDir` and the rest.
    //
    // Except when asked for a trace. `--generateTrace` writes a Chrome
    // tracing file, and every event in it is stamped: in the compiler
    // shipped with the version analyzed here, `writeEvent` defaults its
    // time to `1e3 * timestamp()`, where `timestamp` is the performance
    // counter or `Date.now`. rules_ts declares the trace directory as an
    // output of the action, so those timings are part of what the build
    // produces rather than something written to a log.
    //
    // Deliberately not conditions: `--diagnostics`, `--extendedDiagnostics`,
    // `--listFiles`, `--listEmittedFiles` and `--traceResolution` also
    // report timings and machine detail, but to standard output, which is
    // not an artifact. All five appear in rules_ts's own tests.
    entries.push((
        npm_typescript("tsc_/tsc"),
        Entry::Spec(ReproducibilitySpec::new(
            Reproducibility::Sometimes,
            [] as [&str; 0],
            ["--generateTrace"],
        )),
    ));

    // rules_ts's own checker: it reads the `tsconfig.json`, compares what
    // it finds against the attributes the rule was given, and writes those
    // attributes back out as a marker so that Bazel has an output to hang
    // the action on. No clock, no environment, nothing read that was not
    // handed to it—and where tsc reports a path as absolute it turns it
    // back into a relative one first, because, as its own comment says,
    // sandbox paths differ across builds.
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
        // The arguments name the package and where to put it, and none of
        // them says anything about what its scripts will do.
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
        // A `TsProject` command line as rules_ts writes it, in the two
        // shapes its own tests produce most.
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
        // The trace is a declared output, and every event in it carries a
        // timestamp. Reporting timings to standard output is a different
        // matter, and the flags that do that are left alone.
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
    fn the_runner_answers_to_both_of_its_names() {
        // rules_js is the rare rule set that runs its own tools on itself,
        // so the fishery sees the main-repository spelling.
        let from_main =
            Library::builtin().resolve(ProgramId::main(LIFECYCLE), vec![]);
        assert_eq!(
            from_main.synonym(),
            Some(&ProgramId::module("aspect_rules_js", LIFECYCLE)),
        );
    }
}
