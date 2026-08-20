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

/// The metadata merger shipped by rules_webtesting.
fn metadata_merger(platform: &str) -> ProgramId {
    let extension = if platform == "windows_x64" {
        ".exe"
    } else {
        ""
    };
    ProgramId::module(
        "rules_webtesting",
        &format!("go/metadata/main/main_{platform}{extension}"),
    )
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
        // rules_go's protoc driver, which is not a plain wrapper: it runs
        // the real protoc named by `-protoc`, with the Go plugin named by
        // `-plugin`, and then moves what came out into place. Modelling it
        // as `Wraps` would answer for protoc alone and drop the plugin,
        // which is the same call made about rules_rust's protoc wrapper.
        //
        // A spec of its own holds because the driver adds nothing of its
        // own: its source reads no clock, no environment and no randomness
        // —the one thing it asks the machine is `runtime.GOOS`, to decide
        // how to spell a Windows path. It stages output through a temporary
        // directory, but only the files move out of it, not its name.
        (
            ProgramId::module(
                "rules_go",
                "go/tools/builders/go-protoc/go-protoc-bin",
            ),
            Entry::Spec(always()),
        ),
    ]
    .into_iter()
    // rules_webtesting's metadata merger reads the JSON files named on its
    // command line, merges them in order, and writes indented JSON. It does
    // not consult the clock, environment or host. The executable name varies
    // by platform because rules_webtesting packages all four binaries in a
    // release, but the source and behavior are the same.
    .chain(
        ["linux_x64", "darwin_x64", "darwin_arm64", "windows_x64"].map(
            |platform| (metadata_merger(platform), Entry::Spec(always())),
        ),
    )
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
    // The yacc of the Go world, which projects with a grammar to compile
    // reach through Gazelle's `go_deps`. A parser generator is a pure
    // function of its grammar, and this one is written to stay that way:
    // its source reads no clock and no environment, and the single map it
    // keeps is only ever indexed, never ranged over—which is where a Go
    // program of this shape would otherwise pick up the randomized
    // iteration order that makes output vary between runs.
    //
    // One oddity worth recording, because it looks alarming and is not. The
    // header it writes is `// Code generated by goyacc <its own argv>`, so
    // the generated file contains the path it was told to write to. That
    // path is workspace-relative and stated by the action, so it is a
    // function of the build rather than of the machine—but it does mean the
    // file changes when the output path does.
    //
    // Its identity is the `go_deps` extension rather than the Go module it
    // came from, since the repository name is dropped as unstable. Two
    // different Go modules shipping `cmd/goyacc` would be one program here.
    .chain([(
        ProgramId::extension(
            "gazelle",
            "go_deps",
            "cmd/goyacc/goyacc_/goyacc",
        ),
        Entry::Spec(always()),
    )])
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reproducibility_spec::Conformance;
    use crate::reproducibility_spec::library::Library;
    use crate::reproducibility_spec::per_lang::testing;

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
        testing::assess(go_sdk("builder_reset/builder"), args)
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
    fn web_test_metadata_merging_is_reproducible_on_every_platform() {
        for platform in
            ["linux_x64", "darwin_x64", "darwin_arm64", "windows_x64"]
        {
            assert_eq!(
                testing::assess(
                    metadata_merger(platform),
                    vec![
                        "--output",
                        "bazel-out/k8-fastbuild/bin/test.gen.json",
                        "browser.gen.json",
                        "test.tmp.json",
                    ],
                ),
                Conformance::Reproducible,
                "{platform}",
            );
        }
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

    #[test]
    fn generating_go_from_protos_is_vouched_for() {
        // A `GoProtocGen` command line, which names both the protoc it
        // drives and the plugin it drives it with.
        assert_eq!(
            testing::assess(
                ProgramId::module(
                    "rules_go",
                    "go/tools/builders/go-protoc/go-protoc-bin",
                ),
                vec![
                    "-protoc",
                    "external/protobuf+/protoc",
                    "-importpath",
                    "github.com/bazelbuild/buildtools/api_proto",
                    "-plugin",
                    "external/rules_go+/proto/go_proto_reset_plugin_\
                     /protoc-gen-go",
                    "-descriptor_set",
                    "api_proto/api_proto-descriptor-set.proto.bin",
                    "api_proto/api.proto",
                ],
            ),
            Conformance::Reproducible,
        );
    }

    #[test]
    fn the_parser_generator_is_vouched_for() {
        assert_eq!(
            testing::assess(
                ProgramId::extension(
                    "gazelle",
                    "go_deps",
                    "cmd/goyacc/goyacc_/goyacc",
                ),
                vec!["-o", "bin/build/parse.y.baz.go", "build/parse.y"],
            ),
            Conformance::Reproducible,
        );
    }
}
