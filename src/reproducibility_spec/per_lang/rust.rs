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
        // rustc compiles deterministically from the same sources and flags,
        // with one standing exception: it bakes the paths it was given into
        // debug info and panic messages, and those paths are absolute at
        // execution time even when the action recorded no absolute path.
        // `--remap-path-prefix` is what rewrites them back to something
        // machine-independent, so it is not optional.
        //
        // Incremental compilation reuses cached fragments and is not
        // expected to yield byte-identical output, so it breaks the deal
        // however the flag is spelled or wherever its cache is pointed.
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
        // clippy-driver is rustc with extra lints: it takes the same flags,
        // compiles through the same code, and is reproducible on the same
        // terms. Declared a synonym rather than copied so the two cannot
        // drift apart.
        (
            rust_tool("clippy-driver"),
            Entry::SameAs(rust_tool("rustc")),
        ),
        // The prost wrapper is not a plain wrapper: it drives protoc, the
        // prost and tonic codegen plugins, and rustfmt over the result.
        // Modelling it as `Wraps` would answer for protoc alone and quietly
        // drop the three tools that also shape the output, so it carries a
        // spec of its own—which holds because every one of those steps is
        // itself deterministic.
        (
            ProgramId::module("rules_rust_prost", "private/protoc_wrapper"),
            Entry::Spec(always()),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reproducibility_spec::Conformance;
    use crate::reproducibility_spec::library::Library;
    use std::collections::BTreeSet;

    /// The flags rules_rust actually hands rustc, trimmed to the ones that
    /// bear on reproducibility.
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

    fn assess(program: &ProgramId, args: &[&str]) -> Conformance {
        let resolution =
            Library::builtin().resolve(program.clone(), args.to_vec());
        let (_, spec) = resolution.spec.expect("a spec for the program");
        spec.assess(resolution.args)
    }

    #[test]
    fn rustc_as_rules_rust_invokes_it_is_reproducible() {
        assert_eq!(
            assess(&rust_tool("rustc"), &rules_rust_flags()),
            Conformance::Reproducible,
        );
    }

    /// The missing requirements of a conditional verdict, or a panic if the
    /// invocation was judged reproducible after all.
    fn missing(program: &ProgramId, flags: &[&str]) -> BTreeSet<String> {
        match assess(program, flags) {
            Conformance::Conditional {
                missing_required, ..
            } => missing_required,
            other => {
                panic!("expected a conditional verdict, got {other:?}")
            }
        }
    }

    /// `rules_rust_flags` with every path remapping stripped out.
    fn without_remappings() -> Vec<&'static str> {
        rules_rust_flags()
            .into_iter()
            .filter(|flag| !flag.starts_with("--remap-path-prefix"))
            .collect()
    }

    #[test]
    fn rustc_without_path_remapping_is_not() {
        // A requirement that went unmet is named by its pattern: there is
        // no argument to point at. With none of them supplied, all three
        // are reported rather than just the first.
        let missing = missing(&rust_tool("rustc"), &without_remappings());
        for required in REQUIRED_REMAPS {
            assert!(missing.contains(required), "{missing:?}");
        }
    }

    #[test]
    fn each_required_remapping_is_load_bearing() {
        // Drop exactly one at a time. Each covers a different family of
        // path, so none of the three is implied by the other two.
        for dropped in REQUIRED_REMAPS {
            let kept: Vec<String> = REQUIRED_REMAPS
                .iter()
                .filter(|required| **required != dropped)
                // The patterns end in `*`; a real invocation remaps to `.`.
                .map(|required| required.replace('*', "."))
                .collect();
            let mut flags = without_remappings();
            flags.extend(kept.iter().map(String::as_str));

            let missing = missing(&rust_tool("rustc"), &flags);
            assert_eq!(
                missing.iter().map(String::as_str).collect::<Vec<_>>(),
                vec![dropped],
                "dropping {dropped}",
            );
        }
    }

    #[test]
    fn remapping_some_other_prefix_does_not_satisfy_the_requirement() {
        // The point of matching values rather than flag names. Remapping
        // is present, and under a name-only rule that would have been
        // enough—but none of the prefixes that vary by machine is what
        // gets rewritten.
        let mut flags = without_remappings();
        flags.push("--remap-path-prefix=/nowhere=.");
        let missing = missing(&rust_tool("rustc"), &flags);
        for required in REQUIRED_REMAPS {
            assert!(missing.contains(required), "{missing:?}");
        }
    }

    #[test]
    fn incremental_compilation_breaks_rustc_however_it_is_written() {
        // Both spellings. There is no valueless form to test: rustc
        // rejects `-Cincremental` outright, since the option names the
        // cache directory.
        for spelling in
            ["-Cincremental=/tmp/inc", "--codegen=incremental=x"]
        {
            let mut flags = rules_rust_flags();
            flags.push(spelling);
            match assess(&rust_tool("rustc"), &flags) {
                Conformance::Conditional {
                    present_breaking, ..
                } => {
                    // Reported by the argument that matched, not by the
                    // pattern: here there is something concrete to name.
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
        // The pattern is anchored at the `=`, so it names one option
        // rather than everything that starts with its name.
        let mut flags = rules_rust_flags();
        flags.push("-Cincrementalish=1");
        assert_eq!(
            assess(&rust_tool("rustc"), &flags),
            Conformance::Reproducible,
        );
    }

    #[test]
    fn clippy_driver_is_judged_by_rustcs_spec() {
        let resolution = Library::builtin()
            .resolve(rust_tool("clippy-driver"), rules_rust_flags());
        // The action still reports what it ran...
        assert_eq!(resolution.program, rust_tool("clippy-driver"));
        // ...while the verdict is credited to rustc.
        assert_eq!(resolution.synonym(), Some(&rust_tool("rustc")));
        let (_, spec) = resolution.spec.clone().expect("a spec");
        assert_eq!(spec.assess(resolution.args), Conformance::Reproducible);
    }

    #[test]
    fn the_rustc_recognizer_folds_both_codegen_spellings() {
        // The two spellings agree...
        assert_eq!(
            rustc_option("--codegen=debuginfo=0"),
            rustc_option("-Cdebuginfo=0"),
        );
        // ...on the short one, value intact. Keeping the value is what
        // lets a pattern constrain it.
        assert_eq!(
            rustc_option("-Cdebuginfo=0"),
            Some("-Cdebuginfo=0".into()),
        );
        // Anything that is not a codegen option passes through whole,
        // however many `=` its value contains.
        assert_eq!(
            rustc_option("--remap-path-prefix=${pwd}=."),
            Some("--remap-path-prefix=${pwd}=.".into()),
        );
        // A bare flag stands for itself.
        assert_eq!(rustc_option("--test"), Some("--test".into()));
    }
}
