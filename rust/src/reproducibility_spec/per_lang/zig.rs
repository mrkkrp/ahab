use super::super::library::Entry;
use super::super::program_id::ProgramId;
use super::super::{Clause, Reproducibility, ReproducibilitySpec, Switch};

/// The Zig compiler, as rules_zig's `zig` extension lays it out. The
/// release and the platform are in the repository name, which normalization
/// drops, so the exact path is enough.
fn zig() -> ProgramId {
    ProgramId::extension("rules_zig", "zig", "zig")
}

/// The invocations that emit machine code. One binary does every job, and
/// the rules below are about what a code generator writes: documentation
/// (`zig test … -femit-docs=… -fno-emit-bin`) and `zig translate-c` produce
/// no object code and are unaffected—measured on 0.16.0, a documentation
/// directory built from two working directories came out byte-identical.
/// `test-obj` compiles a test into an object for a later link, and a
/// `-femit-bin=` after `-fno-emit-bin` asks for the binary again.
fn emits_machine_code() -> Switch {
    Switch::new(
        [
            "build-exe",
            "build-lib",
            "build-obj",
            "test",
            "test-obj",
            "-femit-bin=*",
        ],
        ["-fno-emit-bin"],
    )
}

/// What a Zig compilation has to be told before its output is a function of
/// its inputs.
///
/// The language reference lists "Reproducible build" among what the three
/// release modes promise, and "No reproducible build requirement" under
/// `Debug`. Measured on both compilers rules_zig offers: eight `Debug` runs
/// produced eight binaries, eight runs in each release mode produced one.
///
/// `Debug` is also the one mode reaching for Zig's own code generator
/// rather than LLVM, and that generator emits from every core at once.
/// `-fllvm` is therefore the other remedy—eight `Debug` runs under it
/// produced one binary—for a project that cannot leave `Debug`.
///
/// Debugging information is unconditional: Zig records the compilation
/// directory and has no `--remap-path-prefix`, so the only invocation that
/// does not carry it is one that keeps no debugging information at all.
///
/// Zig heeds the last of each pair, and the last `-O`, so `-fno-llvm`,
/// `-fno-strip` and `-O Debug` take back what came before them.
fn zig_requirements() -> Vec<Clause> {
    vec![
        Clause::new(
            Some(emits_machine_code()),
            [
                Switch::new(["-fllvm"], ["-fno-llvm"]),
                Switch::new(
                    ["-O=ReleaseFast", "-O=ReleaseSafe", "-O=ReleaseSmall"],
                    ["-O=*"],
                ),
            ],
            "Zig promises a reproducible build in its release modes and \
             disclaims one in Debug, whose code generator emits from every \
             core at once and writes out whichever thread finished first",
        ),
        Clause::new(
            Some(emits_machine_code()),
            [Switch::new(["-fstrip"], ["-fno-strip"])],
            "debugging information records the directory the compilation \
             ran in, which Zig has no option to rewrite",
        ),
    ]
}

/// What no set of the other flags can repair.
///
/// A static archive stays different however it is invoked: Zig assembles
/// the object in a temporary directory under the cache and stores that name
/// in the archive's member header. Two archives of the same code differ in
/// those fifteen bytes and in nothing else. A release mode does not help—it
/// promises reproducibility of the code, and a member header is not code.
/// Executables, shared libraries and objects carry no member headers and
/// are unaffected.
///
/// `--build-id=uuid` is the other way to ask for a random number; Zig's
/// other styles hash the code, and `none` is the default.
///
/// Nothing is said about `-fincremental`: 0.16.0 refuses to link one at
/// all—`TODO implement saving linker state`.
///
/// A later `-femit-bin=` or `-fno-emit-bin`, and a later `--build-id`,
/// override what came before.
fn zig_prohibitions() -> Vec<Clause> {
    vec![
        Clause::new(
            None,
            [Switch::new(
                ["-femit-bin=*.a", "-femit-bin=*.lib"],
                ["-femit-bin=*", "-fno-emit-bin"],
            )],
            "a static archive stores the name of the temporary directory \
             its object was assembled in, which is drawn afresh for every \
             invocation",
        ),
        Clause::new(
            None,
            [Switch::new(
                ["--build-id=uuid"],
                ["--build-id", "--build-id=*"],
            )],
            "a uuid build id is a random number rather than a function of \
             the code",
        ),
    ]
}

/// Everything Ahab knows about Zig builds, in source order.
///
/// `-O` is declared as valued, so `-O ReleaseFast` reads as the one option
/// `-O=ReleaseFast` that a clause can name, and a bare `ReleaseFast` on its
/// own is not mistaken for it.
pub(in crate::reproducibility_spec) fn entries() -> Vec<(ProgramId, Entry)>
{
    vec![(
        zig(),
        Entry::Spec(
            ReproducibilitySpec::of(Reproducibility::Sometimes)
                .with_valued_flags(["-O"])
                .with_clauses(zig_requirements(), zig_prohibitions()),
        ),
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reproducibility_spec::Conformance;
    use crate::reproducibility_spec::per_lang::testing::{assess, missing};
    use std::collections::BTreeSet;

    /// The command line rules_zig writes for an executable.
    fn build_exe_args() -> Vec<&'static str> {
        vec![
            "build-exe",
            "--zig-lib-dir",
            "external/rules_zig++zig+zig_0.16.0_x86_64-linux/lib",
            "--cache-dir",
            "/tmp/zig-cache",
            "--global-cache-dir",
            "/tmp/zig-cache",
            "-O",
            "Debug",
            "-fno-single-threaded",
            "-fstrip",
            "-target",
            "x86_64-linux-gnu.2.17",
            "-Msimple-binary_Cbinary=simple-binary/main.zig",
            "-femit-bin=bazel-out/k8-fastbuild/bin/simple-binary/binary",
        ]
    }

    /// The same arguments with the code generator settled.
    fn with_llvm() -> Vec<&'static str> {
        let mut args = build_exe_args();
        args.push("-fllvm");
        args
    }

    /// Everything that would settle a `Debug` compilation, as reported.
    fn remedies() -> BTreeSet<String> {
        [
            "-fllvm",
            "-O=ReleaseFast",
            "-O=ReleaseSafe",
            "-O=ReleaseSmall",
        ]
        .map(str::to_owned)
        .into_iter()
        .collect()
    }

    #[test]
    fn zig_as_rules_zig_invokes_it_is_not_reproducible() {
        assert_eq!(missing(zig(), build_exe_args()), remedies());
    }

    #[test]
    fn llvm_settles_the_code_generator() {
        assert_eq!(assess(zig(), with_llvm()), Conformance::Reproducible);
    }

    #[test]
    fn one_job_does_not_settle_it() {
        let mut one_job = build_exe_args();
        one_job.push("-j1");
        assert_eq!(missing(zig(), one_job), remedies());
    }

    #[test]
    fn a_release_mode_is_promised_reproducible_and_needs_nothing_else() {
        for mode in ["ReleaseFast", "ReleaseSafe", "ReleaseSmall"] {
            let args: Vec<&str> = build_exe_args()
                .into_iter()
                .map(|arg| if arg == "Debug" { mode } else { arg })
                .collect();
            assert_eq!(
                assess(zig(), args),
                Conformance::Reproducible,
                "-O {mode}",
            );
        }
    }

    #[test]
    fn a_mode_is_read_as_the_value_of_the_flag_before_it() {
        let mut args = build_exe_args();
        args.push("ReleaseFast");
        assert_eq!(missing(zig(), args), remedies());
    }

    #[test]
    fn a_compilation_that_keeps_debugging_information_records_where_it_ran()
    {
        let by_llvm = with_llvm();
        let by_mode: Vec<&str> = build_exe_args()
            .into_iter()
            .map(|arg| if arg == "Debug" { "ReleaseFast" } else { arg })
            .collect();
        for settled in [by_llvm, by_mode] {
            let unstripped: Vec<&str> = settled
                .iter()
                .copied()
                .filter(|arg| *arg != "-fstrip")
                .collect();
            assert_eq!(
                missing(zig(), unstripped),
                ["-fstrip"].map(str::to_owned).into_iter().collect(),
                "{settled:?}",
            );
        }
    }

    #[test]
    fn documentation_is_not_held_to_the_code_generator_s_rules() {
        let args = vec![
            "test",
            "--test-no-exec",
            "--cache-dir",
            "/tmp/zig-cache",
            "-femit-docs=bazel-out/k8-fastbuild/bin/bazel_builtin/test.docs",
            "-fno-emit-bin",
            "-fno-emit-implib",
            "-O",
            "Debug",
            "-Mbazel_Ubuiltin_Ctest=bazel_builtin/test.zig",
        ];
        assert_eq!(assess(zig(), args), Conformance::Reproducible);
    }

    #[test]
    fn a_test_binary_is_held_to_them() {
        let args = vec![
            "test",
            "--test-no-exec",
            "-O",
            "Debug",
            "-fstrip",
            "-Mbazel_Ubuiltin_Ctest=bazel_builtin/test.zig",
            "-femit-bin=bazel-out/k8-fastbuild/bin/bazel_builtin/test",
        ];
        assert_eq!(missing(zig(), args), remedies());
    }

    #[test]
    fn a_test_compiled_into_an_object_is_held_to_them() {
        let args = vec![
            "test-obj",
            "--test-no-exec",
            "-O",
            "Debug",
            "-fstrip",
            "-Mbazel_Ubuiltin_Ctest=bazel_builtin/test.zig",
        ];
        assert_eq!(missing(zig(), args), remedies());
    }

    #[test]
    fn a_static_archive_breaks_it_whatever_else_was_asked_for() {
        let by_mode: Vec<&str> = build_exe_args()
            .into_iter()
            .map(|arg| if arg == "Debug" { "ReleaseFast" } else { arg })
            .collect();
        for settled in [with_llvm(), by_mode] {
            let mut args = settled;
            args.retain(|arg| !arg.starts_with("-femit-bin="));
            args.push("-femit-bin=bazel-out/k8-opt/bin/c/liblibrary.a");
            let verdict = assess(zig(), args);
            assert_eq!(
                verdict.present_breaking(),
                ["-femit-bin=bazel-out/k8-opt/bin/c/liblibrary.a"]
                    .map(str::to_owned)
                    .into_iter()
                    .collect(),
            );
        }
    }

    #[test]
    fn a_shared_library_is_not_an_archive() {
        let mut args = with_llvm();
        args.retain(|arg| !arg.starts_with("-femit-bin="));
        args.extend([
            "-dynamic",
            "-femit-bin=bazel-out/k8-fastbuild/bin/cc/libadd.so",
        ]);
        assert_eq!(assess(zig(), args), Conformance::Reproducible);
    }

    #[test]
    fn a_random_build_id_breaks_it() {
        let mut args = with_llvm();
        args.push("--build-id=uuid");
        assert_eq!(
            assess(zig(), args).present_breaking(),
            ["--build-id=uuid"].map(str::to_owned).into_iter().collect(),
        );
        let mut hashed = with_llvm();
        hashed.push("--build-id=tree");
        assert_eq!(assess(zig(), hashed), Conformance::Reproducible);
    }

    /// `base` and then `extra`.
    fn with(
        base: &[&'static str],
        extra: &[&'static str],
    ) -> Vec<&'static str> {
        [base, extra].concat()
    }

    #[test]
    fn zig_heeds_the_last_of_each_pair_and_of_each_option() {
        let released: Vec<&str> = build_exe_args()
            .into_iter()
            .map(|arg| if arg == "Debug" { "ReleaseFast" } else { arg })
            .collect();

        assert_eq!(
            missing(zig(), with(&with_llvm(), &["-fno-strip"])),
            ["-fstrip"].map(str::to_owned).into_iter().collect(),
        );
        assert_eq!(
            missing(zig(), with(&with_llvm(), &["-fno-llvm"])),
            remedies(),
        );
        assert_eq!(
            assess(zig(), with(&released, &["-fllvm", "-fno-llvm"])),
            Conformance::Reproducible,
        );
        assert_eq!(
            missing(zig(), with(&released, &["-O", "Debug"])),
            remedies(),
        );
        assert_eq!(
            assess(zig(), with(&build_exe_args(), &["-O", "ReleaseFast"])),
            Conformance::Reproducible,
        );
        assert_eq!(
            assess(
                zig(),
                with(&with_llvm(), &["--build-id=uuid", "--build-id=tree"]),
            ),
            Conformance::Reproducible,
        );
        assert_eq!(
            assess(
                zig(),
                with(&with_llvm(), &["--build-id=tree", "--build-id=uuid"]),
            )
            .present_breaking(),
            ["--build-id=uuid"].map(str::to_owned).into_iter().collect(),
        );
    }

    #[test]
    fn only_the_last_emit_bin_says_what_is_written() {
        let archive = "-femit-bin=bazel-out/k8-opt/bin/c/liblibrary.a";
        assert_eq!(
            assess(
                zig(),
                with(&with_llvm(), &[archive, "-femit-bin=out/library.o"]),
            ),
            Conformance::Reproducible,
        );
        let debug = with(&build_exe_args(), &[archive, "-fno-emit-bin"]);
        assert_eq!(assess(zig(), debug), Conformance::Reproducible);

        let documentation = vec![
            "test",
            "-O",
            "Debug",
            "-fstrip",
            "-fno-emit-bin",
            "-femit-bin=bazel-out/k8-fastbuild/bin/bazel_builtin/test",
        ];
        assert_eq!(missing(zig(), documentation), remedies());
    }
}
