use super::super::library::{Entry, Transition, always};
use super::super::program_id::ProgramId;
use super::super::{Reproducibility, ReproducibilitySpec};

/// The Rust toolchain, as rules_rust's `rust` extension lays it out.
fn rust_tool(name: &str) -> ProgramId {
    ProgramId::extension(
        "rules_rust",
        "rust",
        &format!("rust_toolchain/bin/{name}"),
    )
}

/// The path prefixes an invocation of `rustc` has to be told to rewrite.
const REQUIRED_REMAPS: [&str; 3] = [
    "--remap-path-prefix=${pwd}=*",
    "--remap-path-prefix=${output_base}=*",
    "--remap-path-prefix=${exec_root}=*",
];

/// Normalize how one of `rustc`'s arguments is spelled.
fn rustc_option(arg: &str) -> Option<String> {
    match arg.strip_prefix("--codegen=") {
        Some(rest) => Some(format!("-C{rest}")),
        None => Some(arg.to_owned()),
    }
}

/// Everything Ahab knows about Rust builds, in source order.
pub(in crate::reproducibility_spec) fn entries() -> Vec<(ProgramId, Entry)>
{
    vec![
        (
            ProgramId::module(
                "rules_rust",
                "util/process_wrapper/process_wrapper",
            ),
            Entry::Wraps(Transition::AfterSeparator {
                separator: "--".to_owned(),
            }),
        ),
        (
            ProgramId::module(
                "rules_rust",
                "util/process_wrapper/bootstrap_process_wrapper.sh",
            ),
            Entry::Wraps(Transition::AfterSeparator {
                separator: "--".to_owned(),
            }),
        ),
        // The same two programs reached the other way: rules_rs fetches a
        // patched copy through an extension of its own. The patches are to
        // Windows linking and rust-analyzer integration, so what the wrapper
        // does with its arguments—the claim `SameAs` makes—is unchanged.
        (
            ProgramId::extension(
                "rules_rs",
                "rules_rust",
                "util/process_wrapper/process_wrapper",
            ),
            Entry::SameAs(ProgramId::module(
                "rules_rust",
                "util/process_wrapper/process_wrapper",
            )),
        ),
        (
            ProgramId::extension(
                "rules_rs",
                "rules_rust",
                "util/process_wrapper/bootstrap_process_wrapper.sh",
            ),
            Entry::SameAs(ProgramId::module(
                "rules_rust",
                "util/process_wrapper/bootstrap_process_wrapper.sh",
            )),
        ),
        // rustc bakes the paths it was given into debug info and panic
        // messages, and those are absolute at execution time even when the
        // action recorded no absolute path, so `--remap-path-prefix` is not
        // optional. Incremental compilation reuses cached fragments and
        // breaks the deal however the flag is spelled.
        (
            rust_tool("rustc"),
            Entry::Spec(
                ReproducibilitySpec::new(
                    Reproducibility::Sometimes,
                    REQUIRED_REMAPS,
                    ["-Cincremental=*"],
                )
                .with_recognizer(rustc_option),
            ),
        ),
        // rustc with extra lints: same flags, same code, same terms.
        (
            rust_tool("clippy-driver"),
            Entry::SameAs(rust_tool("rustc")),
        ),
        // Not a plain wrapper: it drives protoc, the prost and tonic codegen
        // plugins, and rustfmt. `Wraps` would answer for protoc alone and
        // drop the three tools that also shape the output, so it carries a
        // spec of its own—which holds, each of those steps being
        // deterministic.
        (
            ProgramId::module("rules_rust_prost", "private/protoc_wrapper"),
            Entry::Spec(always()),
        ),
        // The same toolchain as rules_rs registers it. rules_rust puts the
        // version and platform in the repository name, which normalization
        // drops; rules_rs puts them in the path
        // (`rustc/default_linux_x86_64_1_86_0_rust_toolchain/bin/rustc`),
        // so the path is a pattern and does not name them.
        (
            ProgramId::extension("rules_rs", "toolchains", "*/bin/rustc"),
            Entry::SameAs(rust_tool("rustc")),
        ),
        (
            ProgramId::extension(
                "rules_rs",
                "toolchains",
                "*/bin/clippy-driver",
            ),
            Entry::SameAs(rust_tool("clippy-driver")),
        ),
        // rustfmt needs no pattern: rules_rs, like rules_rust, keeps it
        // outside the toolchain directory.
        (
            ProgramId::extension("rules_rs", "toolchains", "bin/rustfmt"),
            Entry::SameAs(ProgramId::extension(
                "rules_rust",
                "rust",
                "bin/rustfmt",
            )),
        ),
        // rules_rs builds its prost wrapper from rules_rust's own source
        // file, in a package of its own: same program, different address.
        (
            ProgramId::module(
                "rules_rs",
                "rs/private/prost/protoc_wrapper",
            ),
            Entry::SameAs(ProgramId::module(
                "rules_rust_prost",
                "private/protoc_wrapper",
            )),
        ),
        // rustdoc takes rustc's flags and is emphatically *not* its synonym:
        // a stable rustdoc cannot be given `--remap-path-prefix` at all
        // ("only supports `--remap-path-prefix` behind `-Zunstable-options`",
        // per rules_rust), so requiring the remaps would demand something no
        // user could provide. Nor does it need them—measured on 1.93.1,
        // documenting a crate from two working directories produced 55
        // byte-identical files, source-view pages included.
        (rust_tool("rustdoc"), Entry::Spec(always())),
        // rules_rust runs rustfmt only in `--check` mode, where it writes
        // nothing and reports by exit status; the action's sole output is
        // the empty file `process_wrapper --touch-file` creates.
        //
        // Not under `rust_toolchain/bin` like the rest: rustfmt has a
        // repository of its own, pinnable to another channel.
        (
            ProgramId::extension("rules_rust", "rust", "bin/rustfmt"),
            Entry::Spec(always()),
        ),
        // Packs a rustdoc directory into a zip, running no zip logic of its
        // own: the first argument is the tool it spawns, in practice
        // Bazel's zipper. The arguments carried across are not literally
        // the ones it passes on, but they are not consulted—what matters is
        // which program answers.
        (
            ProgramId::module(
                "rules_rust",
                "rust/private/rustdoc/dir_zipper/dir_zipper",
            ),
            Entry::Wraps(Transition::FirstArgument),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reproducibility_spec::Conformance;
    use crate::reproducibility_spec::library::Library;
    use crate::reproducibility_spec::per_lang::testing::{assess, missing};

    /// The flags rules_rust hands rustc.
    fn rules_rust_flags() -> Vec<&'static str> {
        vec![
            "--crate-name=ahab",
            "--codegen=opt-level=0",
            "--codegen=debuginfo=0",
            "--remap-path-prefix=${output_base}=.",
            "--remap-path-prefix=${pwd}=.",
            "--remap-path-prefix=${exec_root}=.",
            "--edition=2021",
            "-Cembed-bitcode=no",
        ]
    }

    #[test]
    fn rustdoc_is_not_held_to_rustcs_remapping() {
        assert_eq!(
            assess(rust_tool("rustdoc"), without_remappings()),
            Conformance::Reproducible,
        );
        assert!(matches!(
            assess(rust_tool("rustc"), without_remappings()),
            Conformance::Conditional { .. }
        ));
    }

    #[test]
    fn rustfmt_only_checks_and_so_writes_a_constant() {
        assert_eq!(
            assess(
                ProgramId::extension("rules_rust", "rust", "bin/rustfmt"),
                vec![
                    "--config-path",
                    "external/rules_rust+/rust/settings/.rustfmt.toml",
                    "--edition",
                    "2024",
                    "--config",
                    "skip_children=true",
                    "--check",
                    "nativelink-config/src/lib.rs",
                ],
            ),
            Conformance::Reproducible,
        );
    }

    #[test]
    fn the_rustdoc_zipper_answers_for_the_tool_it_is_handed() {
        let zipper =
            ProgramId::module("bazel_tools", "tools/zip/zipper/zipper");
        let resolution = Library::builtin().resolve(
            ProgramId::module(
                "rules_rust",
                "rust/private/rustdoc/dir_zipper/dir_zipper",
            ),
            vec![
                "external/bazel_tools/tools/zip/zipper/zipper",
                "bazel-out/k8-fastbuild/bin/nativelink-macro/docs.zip",
                "bazel-out/k8-fastbuild/bin",
                "bazel-out/k8-fastbuild/bin/nativelink-macro/docs.rustdoc",
            ],
        );
        assert_eq!(resolution.program, zipper);
        assert_eq!(resolution.wrappers.len(), 1);
        let (_, spec) = resolution.spec.clone().expect("a spec");
        assert_eq!(spec.assess(resolution.args), Conformance::Reproducible,);
    }

    #[test]
    fn rustc_as_rules_rust_invokes_it_is_reproducible() {
        assert_eq!(
            assess(rust_tool("rustc"), rules_rust_flags()),
            Conformance::Reproducible,
        );
    }

    fn without_remappings() -> Vec<&'static str> {
        rules_rust_flags()
            .into_iter()
            .filter(|flag| !flag.starts_with("--remap-path-prefix"))
            .collect()
    }

    #[test]
    fn rustc_without_path_remapping_is_not() {
        let missing = missing(rust_tool("rustc"), without_remappings());
        for required in REQUIRED_REMAPS {
            assert!(missing.contains(required), "{missing:?}");
        }
    }

    #[test]
    fn each_required_remapping_is_load_bearing() {
        for dropped in REQUIRED_REMAPS {
            let kept: Vec<String> = REQUIRED_REMAPS
                .iter()
                .filter(|required| **required != dropped)
                .map(|required| required.replace('*', "."))
                .collect();
            let mut flags = without_remappings();
            flags.extend(kept.iter().map(String::as_str));

            let missing = missing(rust_tool("rustc"), flags);
            assert_eq!(
                missing.iter().map(String::as_str).collect::<Vec<_>>(),
                vec![dropped],
                "dropping {dropped}",
            );
        }
    }

    #[test]
    fn remapping_some_other_prefix_does_not_satisfy_the_requirement() {
        let mut flags = without_remappings();
        flags.push("--remap-path-prefix=/nowhere=.");
        let missing = missing(rust_tool("rustc"), flags);
        for required in REQUIRED_REMAPS {
            assert!(missing.contains(required), "{missing:?}");
        }
    }

    #[test]
    fn incremental_compilation_breaks_rustc_however_it_is_written() {
        for spelling in
            ["-Cincremental=/tmp/inc", "--codegen=incremental=x"]
        {
            let mut flags = rules_rust_flags();
            flags.push(spelling);
            let verdict = assess(rust_tool("rustc"), flags);
            match &verdict {
                Conformance::Conditional { .. } => {
                    let present_breaking = verdict.present_breaking();
                    assert_eq!(present_breaking.len(), 1, "{spelling}");
                    let reported =
                        present_breaking.iter().next().expect("one");
                    assert!(
                        reported.starts_with("-Cincremental"),
                        "{spelling}: {reported}",
                    );
                }
                other => {
                    panic!("expected {spelling} to break it, got {other:?}")
                }
            }
        }
    }

    #[test]
    fn a_merely_similar_option_does_not_break_rustc() {
        let mut flags = rules_rust_flags();
        flags.push("-Cincrementalish=1");
        assert_eq!(
            assess(rust_tool("rustc"), flags),
            Conformance::Reproducible,
        );
    }

    #[test]
    fn clippy_driver_is_judged_by_rustcs_spec() {
        let resolution = Library::builtin()
            .resolve(rust_tool("clippy-driver"), rules_rust_flags());
        assert_eq!(resolution.program, rust_tool("clippy-driver"));
        assert_eq!(resolution.synonym(), Some(&rust_tool("rustc")));
        let (_, spec) = resolution.spec.clone().expect("a spec");
        assert_eq!(spec.assess(resolution.args), Conformance::Reproducible);
    }

    #[test]
    fn the_rustc_recognizer_folds_both_codegen_spellings() {
        assert_eq!(
            rustc_option("--codegen=debuginfo=0"),
            rustc_option("-Cdebuginfo=0"),
        );
        assert_eq!(
            rustc_option("-Cdebuginfo=0"),
            Some("-Cdebuginfo=0".into()),
        );
        assert_eq!(
            rustc_option("--remap-path-prefix=${pwd}=."),
            Some("--remap-path-prefix=${pwd}=.".into()),
        );
        assert_eq!(rustc_option("--test"), Some("--test".into()));
    }
}
