use super::super::library::Entry;
use super::super::program_id::ProgramId;
use super::super::{Clause, Guard, Reproducibility, ReproducibilitySpec};
use crate::glob::Glob;

/// The Zig compiler, as rules_zig's `zig` extension lays it out.
///
/// The release and the platform are in the repository name—
/// `zig_0.16.0_x86_64-linux`—which normalization drops, so the exact path
/// is enough and no pattern is needed. One binary does every job: the first
/// argument decides whether this invocation compiles, documents, or
/// translates a C header, which is why the rules about code generation are
/// guarded rather than stated over every invocation.
fn zig() -> ProgramId {
    ProgramId::extension("rules_zig", "zig", "zig")
}

/// The invocations that emit machine code.
///
/// Both rules below are about what a code generator writes, and the same
/// binary is regularly asked for something else. rules_zig builds
/// documentation with `zig test … -femit-docs=… -fno-emit-bin`, and
/// translates C headers with `zig translate-c`; neither produces object
/// code, and neither is affected by anything the rules require. Measured on
/// the 0.16.0 compiler analyzed here: a documentation directory built from
/// two different working directories came out byte-identical, HTML, wasm
/// and source tarball alike.
///
/// `-fno-emit-bin` is an `off` flag rather than a separate clause because
/// it always follows the subcommand, and the guard is decided by the last
/// argument that speaks to it.
fn emits_machine_code() -> Guard {
    Guard {
        family: ["build-exe", "build-lib", "build-obj", "test"]
            .into_iter()
            .map(Glob::new)
            .collect(),
        off: [Glob::new("-fno-emit-bin")].into_iter().collect(),
    }
}

/// What a Zig compilation has to be told before its output is a function of
/// its inputs.
///
/// The first condition is one the language reference states outright.
/// Zig's four optimization modes are listed there with what each one
/// promises, and reproducibility is among the promises: `ReleaseFast`,
/// `ReleaseSafe` and `ReleaseSmall` each say "Reproducible build", while
/// `Debug`, the default, says "No reproducible build requirement". It is
/// not a formality. Measured on the two compilers rules_zig offers,
/// compiling one program with identical arguments in one directory: eight
/// runs in `Debug` produced eight different binaries, and eight runs in
/// each of the three release modes produced one. 0.16.0 and 0.15.2 agree.
///
/// `Debug` is also the one mode that reaches for the code generator Zig
/// ships rather than for LLVM, at least on the x86-64 Linux compilers
/// measured here, and that generator emits from every core at once, so
/// what it writes depends on which thread got there first. `-fllvm` is
/// therefore the other remedy, and eight `Debug` runs under it produced
/// one binary on both releases. It is named alongside the modes because a
/// project that cannot leave `Debug` can still leave the code generator.
///
/// Debugging information is the second condition and is not conditional on
/// anything: Zig records the directory it compiled in, and the same program
/// built in two directories differs in `ReleaseFast` as surely as in
/// `Debug` under LLVM. rustc answers this with `--remap-path-prefix`; Zig
/// has no such option, so the only invocation that does not carry the
/// directory is one that keeps no debugging information at all.
fn zig_requirements() -> Vec<Clause> {
    vec![
        Clause {
            when: Some(emits_machine_code()),
            any_of: [
                "-fllvm",
                "-O=ReleaseFast",
                "-O=ReleaseSafe",
                "-O=ReleaseSmall",
            ]
            .into_iter()
            .map(Glob::new)
            .collect(),
            because: "Zig promises a reproducible build in its release \
                      modes and disclaims one in Debug, whose code \
                      generator emits from every core at once and writes \
                      out whichever thread finished first"
                .to_owned(),
        },
        Clause {
            when: Some(emits_machine_code()),
            any_of: [Glob::new("-fstrip")].into_iter().collect(),
            because: "debugging information records the directory the \
                      compilation ran in, which Zig has no option to \
                      rewrite"
                .to_owned(),
        },
    ]
}

/// What no set of the other flags can repair.
///
/// A static archive is the one output that stays different however the
/// compilation is invoked. Zig assembles the object in a temporary
/// directory under the cache—`tmp/83e43963f9d73f76` on the run measured—and
/// stores that name in the archive's member header. It is drawn afresh
/// every time, so two archives of the same code differ in it and in nothing
/// else: fifteen bytes, all of them the temporary directory. The same is
/// true of 0.15.2, and of `-O ReleaseFast`—the mode that promises a
/// reproducible build promises it of the code, and the name in the member
/// header is not code. Executables, shared libraries and objects are
/// unaffected—they carry no member headers—and came out byte-identical
/// under `-fllvm -fstrip` and under `-O ReleaseFast -fstrip` alike.
///
/// `--build-id=uuid` is the other way to ask for a random number. Zig's
/// other styles are hashes of the code and reproduce; `none` is the
/// default.
///
/// Not said here: anything about `-fincremental`. Incremental compilation
/// would continue from what the cache directory already holds rather than
/// from the inputs, but 0.16.0 refuses to link one at all—`TODO implement
/// saving linker state`—so there is no such build to report on yet.
fn zig_prohibitions() -> Vec<Clause> {
    vec![
        Clause {
            when: None,
            any_of: ["-femit-bin=*.a", "-femit-bin=*.lib"]
                .into_iter()
                .map(Glob::new)
                .collect(),
            because: "a static archive stores the name of the temporary \
                      directory its object was assembled in, which is drawn \
                      afresh for every invocation"
                .to_owned(),
        },
        Clause {
            when: None,
            any_of: [Glob::new("--build-id=uuid")].into_iter().collect(),
            because: "a uuid build id is a random number rather than a \
                      function of the code"
                .to_owned(),
        },
    ]
}

/// Everything Ahab knows about Zig builds, in source order.
///
/// `-O` is declared as taking its value from the argument after it, which
/// is how the optimization mode becomes something a clause can name: the
/// two arguments `-O` and `ReleaseFast` are read as the one option
/// `-O=ReleaseFast`, and a bare `ReleaseFast` sitting in the command line
/// on its own is not mistaken for it.
pub(in crate::reproducibility_spec) fn entries() -> Vec<(ProgramId, Entry)>
{
    vec![(
        zig(),
        Entry::Spec(
            ReproducibilitySpec::new(
                Reproducibility::Sometimes,
                [] as [&str; 0],
                [] as [&str; 0],
            )
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

    /// The command line rules_zig writes for an executable, trimmed to the
    /// arguments that bear on reproducibility.
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
        // The whole point of the target in the fishery: under Bazel's
        // fastbuild rules_zig asks for `Debug`, which is the one mode Zig
        // declines to promise anything about, so every compilation it runs
        // is at the mercy of thread scheduling.
        assert_eq!(missing(zig(), build_exe_args()), remedies());
    }

    #[test]
    fn llvm_settles_the_code_generator() {
        assert_eq!(assess(zig(), with_llvm()), Conformance::Reproducible);
    }

    #[test]
    fn one_job_does_not_settle_it() {
        // It settles 0.16.0 and not 0.15.2, and the spec cannot see which
        // of the two it is looking at, so it settles nothing.
        let mut one_job = build_exe_args();
        one_job.push("-j1");
        assert_eq!(missing(zig(), one_job), remedies());
    }

    #[test]
    fn a_release_mode_is_promised_reproducible_and_needs_nothing_else() {
        // The remedy that costs nothing: no backend flag, no job limit,
        // just the mode the language reference vouches for. `Debug` is
        // what rules_zig writes for fastbuild, so each mode is swapped in
        // where that one stood.
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
        // Which is what keeps the word from standing on its own: an
        // argument that merely spells `ReleaseFast` was not asked of `-O`
        // and settles nothing.
        let mut args = build_exe_args();
        args.push("ReleaseFast");
        assert_eq!(missing(zig(), args), remedies());
    }

    #[test]
    fn a_compilation_that_keeps_debugging_information_records_where_it_ran()
    {
        // Everything else settled, and the directory still comes along.
        // Settled by LLVM in `Debug`, and settled by asking for a release
        // mode: neither is any help here, because what a release mode
        // promises is that the code is a function of the code, and the
        // compilation directory was never that.
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
        // A documentation build runs `zig test` and then turns the binary
        // off again, which is where the guard reads its answer. Neither
        // rule applies, and the invocation that would have been reported
        // twice over is reported not at all.
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
        // The same subcommand, emitting a binary after all.
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
    fn a_static_archive_breaks_it_whatever_else_was_asked_for() {
        // Including a release mode, whose promise stops at the code.
        let by_mode: Vec<&str> = build_exe_args()
            .into_iter()
            .map(|arg| if arg == "Debug" { "ReleaseFast" } else { arg })
            .collect();
        for settled in [with_llvm(), by_mode] {
            let mut args = settled;
            args.retain(|arg| !arg.starts_with("-femit-bin="));
            args.push("-femit-bin=bazel-out/k8-opt/bin/c/liblibrary.a");
            let verdict = assess(zig(), args);
            // Reported by the argument that matched, since there is
            // something concrete to name.
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
        // Same subcommand, same rule set, and nothing to report: what the
        // archive prohibition names is the archive, not the library rule
        // that happened to produce one.
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
        // The styles that hash the code do not.
        let mut hashed = with_llvm();
        hashed.push("--build-id=tree");
        assert_eq!(assess(zig(), hashed), Conformance::Reproducible);
    }
}
