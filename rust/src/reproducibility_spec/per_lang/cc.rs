use std::collections::BTreeSet;

use super::super::library::{Entry, host_derived};
use super::super::program_id::ProgramId;
use super::super::{Clause, Guard, Reproducibility, ReproducibilitySpec};
use crate::glob::Glob;

/// A program in the repository `cc_configure` generates from the host.
fn local_config_cc(path: &str) -> ProgramId {
    ProgramId::extension("rules_cc", "cc_configure_extension", path)
}

/// A program in the LLVM that `toolchains_llvm` downloads and unpacks.
/// Unlike the one configuration finds on the machine, this compiler is a
/// pinned artifact of the build, which is what makes it answerable at all.
fn llvm_toolchain(path: &str) -> ProgramId {
    ProgramId::module("llvm_toolchain", path)
}

/// The flag clang needs however it is invoked.
const CLANG_REQUIRED: [&str; 1] = ["-no-canonical-prefixes"];

/// The macros a compilation has to define away, and the flags that would
/// otherwise let each of them record the clock.
const DATE_MACROS: [&str; 3] = ["__DATE__", "__TIME__", "__TIMESTAMP__"];

/// The clauses that only apply to some of what clang does. One program
/// compiles, links and preprocesses, so both are guarded: the first on `-c`,
/// the second on the family of flags that emits debugging information.
fn clang_clauses() -> Vec<Clause> {
    let mut clauses: Vec<Clause> = DATE_MACROS
        .iter()
        .map(|macro_name| Clause {
            when: Some(Guard {
                family: [Glob::new("-c")].into_iter().collect(),
                off: BTreeSet::new(),
            }),
            any_of: [Glob::new(&format!("-D{macro_name}=*"))]
                .into_iter()
                .collect(),
            because: format!(
                "a source mentioning {macro_name} records when it was \
                 compiled unless the macro is defined away",
            ),
        })
        .collect();

    clauses.push(Clause {
        when: Some(Guard {
            family: [
                "-g",
                "-g1",
                "-g2",
                "-g3",
                "-gdwarf*",
                "-gline-tables-only",
                "-gsplit-dwarf",
                "-gz*",
            ]
            .into_iter()
            .map(Glob::new)
            .collect(),
            off: [Glob::new("-g0")].into_iter().collect(),
        }),
        // `-ffile-prefix-map` implies the debug mapping, and naming the
        // compilation directory outright addresses the same field.
        any_of: [
            "-ffile-prefix-map=*",
            "-fdebug-prefix-map=*",
            "-fdebug-compilation-dir=*",
        ]
        .into_iter()
        .map(Glob::new)
        .collect(),
        because: "debugging information records the directory it was \
                  compiled in, which is the execution root"
            .to_owned(),
    });

    clauses
}

/// The letters `ar` accepts as its operation and modifiers.
const AR_MODIFIERS: &str = "abcDdfhiLlNOoPpqrSsTtUuVvxX";

/// Normalize how `ar`'s operation is spelled. Its letters may come in any
/// order, so folding them to a sorted token under a name of its own lets a
/// pattern require one without also matching a file that contains it.
fn ar_operation(arg: &str) -> Option<String> {
    if !arg.is_empty() && arg.chars().all(|c| AR_MODIFIERS.contains(c)) {
        let mut letters: Vec<char> = arg.chars().collect();
        letters.sort_unstable();
        letters.dedup();
        let letters: String = letters.into_iter().collect();
        return Some(format!("modifiers:{letters}"));
    }
    Some(arg.to_owned())
}

/// Everything Ahab knows about C++ builds, in source order.
pub(in crate::reproducibility_spec) fn entries() -> Vec<(ProgramId, Entry)>
{
    vec![
        // The compiler, one step removed. Its last line execs the `gcc` or
        // `clang` that configuration found, by absolute path.
        (
            local_config_cc("cc_wrapper.sh"),
            Entry::Spec(host_derived()),
        ),
        // Runs the host's `nm` and `c++filt` over an archive.
        (
            local_config_cc("validate_static_library.sh"),
            Entry::Spec(host_derived()),
        ),
        // The header-dependency scanner, likewise wrapping a host tool.
        (
            local_config_cc("deps_scanner_wrapper.sh"),
            Entry::Spec(host_derived()),
        ),
        // The same shape of wrapper, opposite verdict: the clang it execs
        // was downloaded rather than found, so it is as pinned as any other
        // input and the question becomes what it is asked to do. One
        // requirement holds regardless—stop canonicalizing paths, which
        // would put the execution root into the output.
        (
            llvm_toolchain("bin/cc_wrapper.sh"),
            Entry::Spec(
                ReproducibilitySpec::new(
                    Reproducibility::Sometimes,
                    CLANG_REQUIRED,
                    [] as [&str; 0],
                )
                .with_clauses(clang_clauses(), []),
            ),
        ),
        // An archiver stores each member's modification time, user and
        // group, none of which is a property of the code. `D` zeroes all
        // three; Bazel asks for it as `rcsD`.
        (
            llvm_toolchain("bin/llvm-ar"),
            Entry::Spec(
                ReproducibilitySpec::new(
                    Reproducibility::Sometimes,
                    ["modifiers:*D*"],
                    [] as [&str; 0],
                )
                .with_recognizer(ar_operation),
            ),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reproducibility_spec::Conformance;
    use crate::reproducibility_spec::library::Library;
    use crate::reproducibility_spec::per_lang::testing::{assess, missing};
    use std::collections::BTreeSet;

    /// A compile command line as Bazel's llvm toolchain writes it.
    fn clang_args() -> Vec<&'static str> {
        vec![
            "-MD",
            "-no-canonical-prefixes",
            "-D__DATE__=\"redacted\"",
            "-D__TIMESTAMP__=\"redacted\"",
            "-D__TIME__=\"redacted\"",
            "--sysroot=external/sysroot_linux_amd64/",
            "-frandom-seed=bazel-out/k8-fastbuild/bin/x/_objs/y/z.pic.o",
            "-c",
            "source/common/common/assert.cc",
        ]
    }

    #[test]
    fn clang_as_the_llvm_toolchain_invokes_it_is_reproducible() {
        assert_eq!(
            assess(llvm_toolchain("bin/cc_wrapper.sh"), clang_args()),
            Conformance::Reproducible,
        );
    }

    #[test]
    fn each_clang_requirement_is_load_bearing() {
        for dropped in CLANG_REQUIRED {
            let prefix = dropped.trim_end_matches('*');
            let kept: Vec<&str> = clang_args()
                .into_iter()
                .filter(|arg| !arg.starts_with(prefix))
                .collect();
            assert_eq!(
                missing(llvm_toolchain("bin/cc_wrapper.sh"), kept)
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                vec![dropped],
                "dropping {dropped}",
            );
        }
    }

    fn remedies() -> BTreeSet<String> {
        [
            "-fdebug-compilation-dir=*",
            "-fdebug-prefix-map=*",
            "-ffile-prefix-map=*",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    fn clang_without(prefix: &str) -> Vec<&'static str> {
        clang_args()
            .into_iter()
            .filter(|arg| !arg.starts_with(prefix))
            .collect()
    }

    #[test]
    fn a_compilation_must_define_the_date_macros_away() {
        assert_eq!(
            assess(llvm_toolchain("bin/cc_wrapper.sh"), clang_args()),
            Conformance::Reproducible,
        );
        for macro_name in DATE_MACROS {
            let flags = clang_without(&format!("-D{macro_name}="));
            assert_eq!(
                missing(llvm_toolchain("bin/cc_wrapper.sh"), flags)
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                vec![format!("-D{macro_name}=*")],
                "{macro_name}",
            );
        }
    }

    #[test]
    fn the_date_macros_are_only_asked_of_a_compilation() {
        let mut flags = clang_without("-D__");
        flags.retain(|arg| *arg != "-c");
        assert_eq!(
            assess(llvm_toolchain("bin/cc_wrapper.sh"), flags),
            Conformance::Reproducible,
        );
    }

    #[test]
    fn debugging_information_must_have_its_paths_remapped() {
        let mut flags = clang_args();
        flags.extend(["-g", "-gsplit-dwarf"]);
        assert_eq!(
            missing(llvm_toolchain("bin/cc_wrapper.sh"), flags),
            remedies(),
        );

        for remedy in [
            "-ffile-prefix-map=/execroot=.",
            "-fdebug-prefix-map=/execroot=.",
            "-fdebug-compilation-dir=.",
        ] {
            let mut flags = clang_args();
            flags.extend(["-g", remedy]);
            assert_eq!(
                assess(llvm_toolchain("bin/cc_wrapper.sh"), flags),
                Conformance::Reproducible,
                "{remedy}",
            );
        }
    }

    #[test]
    fn a_guard_is_decided_by_the_last_flag_that_speaks_to_it() {
        let mut off = clang_args();
        off.extend(["-g", "-g0"]);
        assert_eq!(
            assess(llvm_toolchain("bin/cc_wrapper.sh"), off),
            Conformance::Reproducible,
        );

        let mut on = clang_args();
        on.extend(["-g0", "-g"]);
        assert_eq!(
            missing(llvm_toolchain("bin/cc_wrapper.sh"), on),
            remedies(),
        );
    }

    #[test]
    fn linking_is_not_asked_for_a_preprocessors_flags() {
        let linking = vec![
            "-no-canonical-prefixes",
            "-o",
            "bazel-out/k8-fastbuild/bin/source/exe/envoy-static",
            "-Wl,-S",
            "bazel-out/k8-fastbuild/bin/source/exe/libmain.a",
        ];
        assert!(linking.iter().all(|arg| !arg.starts_with("-D__")));
        assert_eq!(
            assess(llvm_toolchain("bin/cc_wrapper.sh"), linking),
            Conformance::Reproducible,
        );
    }

    #[test]
    fn the_host_compiler_and_the_downloaded_one_are_judged_apart() {
        let host = Library::builtin()
            .resolve(local_config_cc("cc_wrapper.sh"), clang_args());
        let (_, spec) = host.spec.expect("a spec for the host wrapper");
        assert_eq!(spec.reproducibility, Reproducibility::HostDerived);
    }

    #[test]
    fn ar_is_reproducible_only_in_deterministic_mode() {
        let archive = ["bazel-out/k8-fastbuild/bin/x/libx.lo", "y.o"];

        let mut deterministic = vec!["rcsD"];
        deterministic.extend(archive.iter());
        assert_eq!(
            assess(llvm_toolchain("bin/llvm-ar"), deterministic),
            Conformance::Reproducible,
        );

        let mut plain = vec!["rcs"];
        plain.extend(archive.iter());
        assert_eq!(
            missing(llvm_toolchain("bin/llvm-ar"), plain)
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["modifiers:*D*"],
        );
    }

    #[test]
    fn the_order_of_ars_modifiers_does_not_matter() {
        for spelling in ["rcsD", "rDcs", "Drcs", "rcsDD"] {
            assert_eq!(
                assess(
                    llvm_toolchain("bin/llvm-ar"),
                    vec![spelling, "libx.lo", "y.o"],
                ),
                Conformance::Reproducible,
                "{spelling}",
            );
        }
    }

    #[test]
    fn a_file_name_is_not_mistaken_for_ars_modifiers() {
        assert_eq!(
            ar_operation("bazel-out/x/D.o"),
            Some("bazel-out/x/D.o".into())
        );
        assert_eq!(
            missing(
                llvm_toolchain("bin/llvm-ar"),
                vec!["rcs", "bazel-out/x/D.o"],
            )
            .len(),
            1,
        );
    }
}
