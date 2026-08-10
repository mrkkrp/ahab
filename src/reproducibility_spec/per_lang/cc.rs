use super::super::library::{Entry, host_derived};
use super::super::program_id::ProgramId;
use super::super::{Reproducibility, ReproducibilitySpec};

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

/// The flags without which clang is not a function of its inputs.
///
/// Only the one, and not for want of candidates. A compilation also needs
/// `__DATE__`, `__TIME__` and `__TIMESTAMP__` defined away, or a source
/// that mentions them records the moment it was built—but the same program
/// links as well as compiles, and a link has no preprocessor to define them
/// for. Requiring them would report every C++ link ever run. Saying
/// "required when `-c` is present" is not something a spec can express
/// today, so the check that would need it is left undone rather than made
/// noisy.
const CLANG_REQUIRED: [&str; 1] = ["-no-canonical-prefixes"];

/// The letters `ar` accepts as its operation and modifiers.
const AR_MODIFIERS: &str = "abcDdfhiLlNOoPpqrSsTtUuVvxX";

/// Normalize how `ar`'s operation is spelled.
///
/// It arrives as a single argument whose letters may come in any order, so
/// `rcsD` and `rDcs` ask for the same thing. Folding it to a sorted token
/// under a name of its own lets a pattern require one of those letters
/// without also matching a file that happens to contain it.
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
        // The same shape of wrapper, and the opposite verdict. This one
        // execs a clang that was downloaded and unpacked rather than found,
        // so the compiler is as pinned as any other input and the question
        // becomes what it is asked to do.
        //
        // What it is required to do is stop canonicalizing the paths it was
        // given, which would otherwise put the execution root—a directory
        // whose name is nobody else's—into the output. Bazel passes that on
        // compilations and links alike, which is what makes it safe to ask
        // for; see `CLANG_REQUIRED` for the checks that are not.
        //
        // Nor is a `-fdebug-prefix-map` required. It would be, for a build
        // compiling with debug information, since the compilation directory
        // is absolute and lands in the DWARF. Bazel's default configuration
        // does not pass `-g`, and requiring a remapping of paths that are
        // not being recorded would report every C++ action in the world.
        (
            llvm_toolchain("bin/cc_wrapper.sh"),
            Entry::Spec(ReproducibilitySpec::new(
                Reproducibility::Sometimes,
                CLANG_REQUIRED,
                [] as [&str; 0],
            )),
        ),
        // An archiver writes the modification time, user and group of every
        // member it stores, none of which is a property of the code. `D`
        // asks for all three to be zeroed—the same bargain `singlejar`
        // strikes with `--normalize`, and Bazel asks for it as `rcsD`.
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
    use std::collections::BTreeSet;

    /// A compile command line as Bazel's llvm toolchain writes it, trimmed
    /// to the arguments that bear on reproducibility.
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

    fn assess(program: ProgramId, args: Vec<&str>) -> Conformance {
        let resolution = Library::builtin().resolve(program, args);
        let (_, spec) = resolution.spec.expect("a spec");
        spec.assess(resolution.args)
    }

    fn missing(program: ProgramId, args: Vec<&str>) -> BTreeSet<String> {
        match assess(program, args) {
            Conformance::Conditional {
                missing_required, ..
            } => missing_required,
            other => {
                panic!("expected a conditional verdict, got {other:?}")
            }
        }
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

    #[test]
    fn linking_is_not_asked_for_a_preprocessors_flags() {
        // The same wrapper links, with no `-c` and no defines, because
        // there is nothing to preprocess. Requiring the date macros of
        // every invocation would make this—an ordinary link, and the
        // commonest C++ action there is—a violation.
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
        // Same file name, same job, and the reason they differ is not what
        // they do but where they came from.
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
        // They are a set, not a sequence, so every spelling of the same set
        // has to answer the same.
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
        // The point of folding the operation under a name of its own: this
        // path is made only of letters `ar` would accept, and must not be
        // allowed to satisfy the requirement on its own.
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
