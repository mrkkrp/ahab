use super::super::library::{Entry, always};
use super::super::program_id::ProgramId;

/// A program the `go_sdk` extension downloads and unpacks.
fn go_sdk(path: &str) -> ProgramId {
    ProgramId::extension("rules_go", "go_sdk", path)
}

/// A program inside Gazelle, which declares itself as the module `gazelle`
/// however its dependents spell the repository.
fn gazelle(path: &str) -> ProgramId {
    ProgramId::module("gazelle", path)
}

/// One of Gazelle's own generators, under both names it answers to.
///
/// Depend on Gazelle and its programs arrive from the module; analyze
/// Gazelle itself and the same programs are in the main one, where nothing
/// records whose they are. The second form is the loose end: a path is all
/// there is to go on, so a project that happens to build something at the
/// same path inherits a verdict meant for Gazelle. The paths are long and
/// particular enough to make that unlikely, and the alternative is every
/// Go project's report carrying entries for a tool half of them use.
fn gazelle_generator(path: &str) -> Vec<(ProgramId, Entry)> {
    vec![
        (gazelle(path), Entry::Spec(always())),
        (ProgramId::main(path), Entry::SameAs(gazelle(path))),
    ]
}

/// Everything Ahab knows about Go builds, in source order.
pub(in crate::reproducibility_spec) fn entries() -> Vec<(ProgramId, Entry)>
{
    vec![
        // One program stands behind nearly every Go action. rules_go does
        // not invoke the Go tools directly: it builds a helper from the SDK
        // and gives it a subcommand—`compilepkg` to compile a package,
        // `link` to produce a binary, `gentestmain` to write the generated
        // main of a test. Each one is a deterministic function of the
        // sources and archives named on the command line, and the arguments
        // are workspace-relative, so nothing about where the build happens
        // reaches the output. What Go would otherwise bake in, rules_go
        // takes out: it trims paths on its way to the compiler, and hands
        // the linker `-buildid=redacted` rather than let it embed one.
        //
        // Linking is the exception worth naming, and it is not modelled
        // here. `link` finishes by handing off to a C linker and archiver
        // named absolutely—`-extld /usr/bin/gcc`, `-extar /usr/bin/ar`—so a
        // linked Go binary is only as reproducible as whatever compiler the
        // machine turned out to have. That does not belong in this spec,
        // because those paths are already in the action for the absolute
        // path check to find, and restating it here would report the same
        // machine twice. The judgement is the same one made about `rustc`,
        // which also links through a compiler it does not vouch for.
        (go_sdk("builder_reset/builder"), Entry::Spec(always())),
    ]
    .into_iter()
    // Gazelle generates the BUILD files of a large share of the Go projects
    // built with Bazel, and building Gazelle runs three generators of its
    // own. They are not part of rules_go and Ahab has no special claim on
    // them; they are here because the alternative is that everyone who uses
    // Gazelle writes the same three specs. Each reads a file the build
    // handed it—a CSV of proto imports, the SDK's package list—and writes a
    // Go source file from it, with no input but what is named on the
    // command line.
    .chain(gazelle_generator(
        "language/proto/gen/gen_known_imports_/gen_known_imports",
    ))
    .chain(gazelle_generator(
        "language/go/gen_std_package_list/gen_std_package_list_\
         /gen_std_package_list",
    ))
    .chain(gazelle_generator(
        "language/go/platform_info_generator/platform_info_generator_\
         /platform_info_generator",
    ))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reproducibility_spec::Conformance;
    use crate::reproducibility_spec::library::Library;

    /// The head of a `compilepkg` command line as rules_go writes it,
    /// trimmed to the shape rather than the full list of sources.
    fn compilepkg() -> Vec<&'static str> {
        vec![
            "compilepkg",
            "-sdk",
            "external/rules_go++go_sdk+main___download_0",
            "-goroot",
            "bazel-out/k8-fastbuild/bin/external/rules_go+/stdlib_",
            "-installsuffix",
            "linux_amd64",
            "-src",
            "language/go/gen_std_package_list/gen_std_package_list.go",
            "-importpath",
            "github.com/bazelbuild/bazel-gazelle/language/go",
            "-gcflags",
            "",
        ]
    }

    /// A `link` command line, including the external linker rules_go names
    /// after the separator.
    fn link() -> Vec<&'static str> {
        vec![
            "link",
            "-sdk",
            "external/rules_go++go_sdk+main___download_0",
            "-main",
            "bazel-out/k8-fastbuild/bin/language/go/thing.a",
            "--",
            "-extar",
            "/usr/bin/ar",
            "-extld",
            "/usr/bin/gcc",
            "-buildid=redacted",
        ]
    }

    fn assess(args: Vec<&str>) -> Conformance {
        let resolution = Library::builtin()
            .resolve(go_sdk("builder_reset/builder"), args);
        let (_, spec) = resolution.spec.expect("a spec for the builder");
        spec.assess(resolution.args)
    }

    #[test]
    fn the_builder_is_reproducible_whichever_subcommand_it_is_given() {
        // The three that rules_go actually uses. None of them carries a
        // condition, so none of them can come out conditional.
        assert_eq!(assess(compilepkg()), Conformance::Reproducible);
        assert_eq!(assess(link()), Conformance::Reproducible);
        assert_eq!(
            assess(vec!["gentestmain", "-pkgname", "language/go"]),
            Conformance::Reproducible,
        );
    }

    #[test]
    fn the_external_linker_is_left_to_the_other_checks() {
        // Deliberate: `link` names a compiler from the machine and is still
        // judged reproducible here, because the absolute path check reads
        // the same argument and reports it. This test exists so that
        // changing that becomes a decision rather than an accident.
        assert!(link().contains(&"/usr/bin/gcc"));
        assert_eq!(assess(link()), Conformance::Reproducible);
    }

    /// The generator whose path is spelled across two source lines, so that
    /// a stray space in the continuation would fail here rather than
    /// silently stop matching anything.
    const STD_PACKAGE_LIST: &str = "language/go/gen_std_package_list\
         /gen_std_package_list_/gen_std_package_list";

    #[test]
    fn gazelles_generators_answer_to_both_of_their_names() {
        for path in [
            "language/proto/gen/gen_known_imports_/gen_known_imports",
            STD_PACKAGE_LIST,
            "language/go/platform_info_generator\
             /platform_info_generator_/platform_info_generator",
        ] {
            // As a dependency, which is how everyone but Gazelle sees them.
            let from_module =
                Library::builtin().resolve(gazelle(path), vec![]);
            assert!(from_module.spec.is_some(), "{path} from the module");

            // And inside Gazelle's own build, where the verdict is credited
            // to the module entry rather than restated.
            let from_main =
                Library::builtin().resolve(ProgramId::main(path), vec![]);
            let (_, spec) =
                from_main.spec.clone().expect("a spec in the main module");
            assert_eq!(from_main.synonym(), Some(&gazelle(path)), "{path}");
            assert_eq!(
                spec.assess(from_main.args),
                Conformance::Reproducible,
                "{path}",
            );
        }
    }

    #[test]
    fn the_builder_is_named_by_the_extension_that_downloads_it() {
        // rules_go builds it per SDK, so it is reached through `go_sdk`
        // rather than sitting at a path in the module.
        let resolution = Library::builtin()
            .resolve(go_sdk("builder_reset/builder"), vec!["compilepkg"]);
        assert!(resolution.spec.is_some());
        // A program of the same name in the module itself is somebody
        // else's, and has no spec here.
        let elsewhere = Library::builtin().resolve(
            ProgramId::module("rules_go", "builder_reset/builder"),
            vec!["compilepkg"],
        );
        assert!(elsewhere.spec.is_none());
    }
}
