//! JavaScript builds.
//!
//! The npm ecosystem's unit of distribution is a package that may carry
//! scripts the package manager is expected to run on installation, and that
//! is where a JavaScript build stops being a function of its inputs.

use super::super::library::{Entry, never};
use super::super::program_id::ProgramId;

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
    rules_js_tool("npm/private/lifecycle/min/bin_/bin")
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
