use super::super::library::{Entry, Transition, host_derived};
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

/// The prebuilt tools the newer `llvm` module's extension provides.
fn minimal_llvm(path: &str) -> ProgramId {
    ProgramId::extension("llvm", "llvm_toolchain_minimal", path)
}

/// Read deterministic-archive switches even in short-option groups such
/// as `-pU`. A value-taking option ends the group; `-oU` names an output.
fn strip_mode(arg: &str) -> String {
    let Some(short) = arg.strip_prefix('-').filter(|s| !s.starts_with('-'))
    else {
        return arg.to_owned();
    };
    let mut mode = None;
    for option in short.chars() {
        match option {
            'D' => mode = Some("--enable-deterministic-archives"),
            'U' => mode = Some("--disable-deterministic-archives"),
            'o' | 'R' | 'N' | 'K' => break,
            _ => {}
        }
    }
    mode.unwrap_or(arg).to_owned()
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
    let compiling = Guard::on(["-c"]);
    let emits_debug_info = Guard::toggled(
        [
            "-g",
            "-g1",
            "-g2",
            "-g3",
            "-gdwarf*",
            "-gline-tables-only",
            "-gsplit-dwarf",
            "-gz*",
        ],
        ["-g0"],
    );

    let mut clauses: Vec<Clause> = DATE_MACROS
        .iter()
        .map(|macro_name| {
            Clause::new(
                Some(compiling.clone()),
                [format!("-D{macro_name}=*")],
                &format!(
                    "a source mentioning {macro_name} records when it was \
                     compiled unless the macro is defined away",
                ),
            )
        })
        .collect();

    // `-ffile-prefix-map` implies the debug mapping, and naming the
    // compilation directory outright addresses the same field.
    clauses.push(Clause::new(
        Some(emits_debug_info),
        [
            "-ffile-prefix-map=*",
            "-fdebug-prefix-map=*",
            "-fdebug-compilation-dir=*",
        ],
        "debugging information records the directory it was compiled in, \
         which is the execution root",
    ));

    clauses
}

/// The letters `ar` accepts as its operation and modifiers.
const AR_MODIFIERS: &str = "abcDdfhiLlNOoPpqrSsTtUuVvxX";

/// Normalize how `ar`'s operation is spelled. Its letters may come in any
/// order, so folding them to a sorted token under a name of its own lets a
/// pattern require one without also matching a file that contains it.
fn ar_operation(arg: &str) -> String {
    if !arg.is_empty() && arg.chars().all(|c| AR_MODIFIERS.contains(c)) {
        let mut letters: Vec<char> = arg.chars().collect();
        letters.sort_unstable();
        letters.dedup();
        let letters: String = letters.into_iter().collect();
        return format!("modifiers:{letters}");
    }
    arg.to_owned()
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
        (
            minimal_llvm("bin/clang"),
            Entry::SameAs(llvm_toolchain("bin/cc_wrapper.sh")),
        ),
        (
            minimal_llvm("bin/clang++"),
            Entry::SameAs(minimal_llvm("bin/clang")),
        ),
        // This wrapper forwards to LLVM_CLANGXX, but can also produce a
        // dSYM or interface library. Those modes need their own specs.
        (
            ProgramId::module(
                "llvm",
                "tools/internal/link-wrapper-clang++/link-wrapper-clang++",
            ),
            Entry::Wraps(Transition::FromEnvironment {
                program: "LLVM_CLANGXX".to_owned(),
                unless: [
                    ("LLVM_DSYM_PATH", "?*"),
                    ("LLVM_GENERATE_INTERFACE_LIBRARY", "yes"),
                ]
                .into_iter()
                .map(|(key, pattern)| (key.to_owned(), Glob::new(pattern)))
                .collect(),
            }),
        ),
        // llvm-strip zeroes archive header IDs and times by default.
        // -U opts out; a later -D restores deterministic mode.
        (
            minimal_llvm("bin/llvm-strip"),
            Entry::Spec(
                ReproducibilitySpec::of(Reproducibility::Sometimes)
                    .with_clauses(
                        [],
                        [Clause::new(
                            Some(Guard::toggled(
                                ["--disable-deterministic-archives"],
                                ["--enable-deterministic-archives"],
                            )),
                            ["--disable-deterministic-archives"],
                            "archive headers retain user IDs, group IDs \
                             and timestamps",
                        )],
                    )
                    .with_valued_flags([
                        "-o",
                        "-R",
                        "-N",
                        "-K",
                        "--remove-section",
                        "--strip-symbol",
                        "--keep-section",
                        "--keep-symbol",
                        "--extract-section",
                    ])
                    .with_recognizer(strip_mode),
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
    use crate::checks::Violation;
    use crate::checks::tests::{
        action_with_env, action_with_param_files, check_reproducibility,
        container,
    };
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
    fn each_clang_requirement_is_load_bearing() {
        for dropped in CLANG_REQUIRED {
            let kept = clang_without(dropped.trim_end_matches('*'));
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
        let host = Library::builtin(None)
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
        assert_eq!(ar_operation("bazel-out/x/D.o"), "bazel-out/x/D.o");
        assert_eq!(
            missing(
                llvm_toolchain("bin/llvm-ar"),
                vec!["rcs", "bazel-out/x/D.o"],
            )
            .len(),
            1,
        );
    }

    #[test]
    fn the_minimal_compilers_keep_every_clang_requirement() {
        for tool in ["bin/clang", "bin/clang++"] {
            let program = minimal_llvm(tool);
            assert_eq!(
                assess(program.clone(), clang_args()),
                Conformance::Reproducible,
            );
            for flag in [
                "-no-canonical-prefixes",
                "-D__DATE__=",
                "-D__TIME__=",
                "-D__TIMESTAMP__=",
            ] {
                assert_eq!(
                    missing(program.clone(), clang_without(flag)).len(),
                    1,
                    "{tool}: {flag}",
                );
            }
            let mut debug = clang_args();
            debug.push("-g");
            assert_eq!(missing(program, debug), remedies());
        }
    }

    #[test]
    fn minimal_compiler_names_do_not_depend_on_platform_or_bazel_version() {
        for path in [
            "external/llvm++llvm_toolchain_minimal+llvm-toolchain-minimal-linux-amd64/bin/clang",
            "external/llvm++llvm_toolchain_minimal+llvm-toolchain-minimal-macos-arm64/bin/clang++",
            "external/llvm~0.8.19~llvm_toolchain_minimal~llvm-toolchain-minimal-linux-amd64/bin/clang",
        ] {
            assert_eq!(
                assess(ProgramId::of(path), clang_args()),
                Conformance::Reproducible,
                "{path}",
            );
        }
    }

    #[test]
    fn strip_defaults_to_deterministic_archives_and_the_last_switch_wins() {
        for flags in [
            vec![],
            vec!["-S", "out/program"],
            vec!["-D"],
            vec!["--enable-deterministic-archives"],
            vec!["-U", "-D"],
            vec!["-UD"],
            vec!["--disable-deterministic-archives", "-D"],
            vec!["-o", "-Uoutput", "out/input"],
            vec!["-RUserSection", "out/input"],
            vec!["--strip-symbol", "-U", "out/input"],
            vec!["out/UsesD.o"],
        ] {
            assert_eq!(
                assess(minimal_llvm("bin/llvm-strip"), flags.clone()),
                Conformance::Reproducible,
                "{flags:?}",
            );
        }
        for flags in [
            vec!["-U"],
            vec!["--disable-deterministic-archives"],
            vec!["-pU"],
            vec!["-DU"],
            vec!["-D", "-U"],
            vec!["--enable-deterministic-archives", "-U"],
        ] {
            let verdict =
                assess(minimal_llvm("bin/llvm-strip"), flags.clone());
            let Conformance::Conditional { unmet } = verdict else {
                panic!("{flags:?}: {verdict:?}");
            };
            assert_eq!(unmet.len(), 1);
            assert_eq!(
                unmet[0].present,
                BTreeSet::from([
                    "--disable-deterministic-archives".to_owned()
                ]),
            );
        }
    }

    const LINK_WRAPPER: &str = "bazel-out/darwin_arm64-fastbuild/bin/external/llvm+/tools/internal/link-wrapper-clang++/link-wrapper-clang++";
    const CLANGXX: &str = "external/llvm++llvm_toolchain_minimal+llvm-toolchain-minimal-linux-amd64/bin/clang++";

    fn link_action(
        environment: &[(&str, &str)],
    ) -> analysis_v2_proto::analysis::Action {
        let mut action = action_with_env("CppLink", 1, environment);
        action.arguments = [LINK_WRAPPER, "-no-canonical-prefixes", "a.o"]
            .map(str::to_owned)
            .into();
        action
    }

    #[test]
    fn the_link_wrapper_uses_the_declared_compiler_and_param_file_flags() {
        let mut action = action_with_param_files(
            "CppLink",
            1,
            &[LINK_WRAPPER, "@out/link.params"],
            &[("out/link.params", &["-no-canonical-prefixes", "a.o"])],
        );
        action.environment_variables =
            link_action(&[("LLVM_CLANGXX", CLANGXX)]).environment_variables;
        let c = container(vec![action]);
        assert!(
            check_reproducibility(&c, &Library::builtin(None)).is_empty()
        );

        let mut c = c;
        c.actions[0].param_files[0].arguments.remove(0);
        let found = check_reproducibility(&c, &Library::builtin(None));
        let [
            Violation::ConditionalReproducibility {
                program,
                wrappers,
                unmet,
                ..
            },
        ] = found.as_slice()
        else {
            panic!("{found:?}");
        };
        assert_eq!(*program, minimal_llvm("bin/clang++"));
        assert_eq!(*wrappers, [ProgramId::of(LINK_WRAPPER)]);
        assert_eq!(
            unmet[0].any_of,
            BTreeSet::from(["-no-canonical-prefixes".to_owned()])
        );
    }

    #[test]
    fn optional_link_wrapper_tools_are_not_silently_accepted() {
        for (key, value, unknown) in [
            ("LLVM_DSYM_PATH", "out/program.dSYM", true),
            ("LLVM_DSYM_PATH", "", false),
            ("LLVM_GENERATE_INTERFACE_LIBRARY", "yes", true),
            ("LLVM_GENERATE_INTERFACE_LIBRARY", "no", false),
            ("LLVM_STRIP_DEBUG_SYMBOLS", "yes", false),
        ] {
            let c = container(vec![link_action(&[
                ("LLVM_CLANGXX", CLANGXX),
                (key, value),
            ])]);
            let found = check_reproducibility(&c, &Library::builtin(None));
            if unknown {
                assert!(
                    matches!(
                        found.as_slice(),
                        [Violation::UnknownProgram { program, .. }]
                            if *program == ProgramId::of(LINK_WRAPPER)
                    ),
                    "{key}={value}: {found:?}"
                );
            } else {
                assert!(found.is_empty(), "{key}={value}: {found:?}");
            }
        }
    }

    #[test]
    fn a_missing_or_host_linker_does_not_inherit_the_clang_spec() {
        for environment in [vec![], vec![("LLVM_CLANGXX", "")]] {
            let c = container(vec![link_action(&environment)]);
            let found = check_reproducibility(&c, &Library::builtin(None));
            assert!(
                matches!(
                    found.as_slice(),
                    [Violation::UnknownProgram { .. }]
                ),
                "{found:?}"
            );
        }
        let c = container(vec![link_action(&[(
            "LLVM_CLANGXX",
            "/usr/bin/clang++",
        )])]);
        let found = check_reproducibility(&c, &Library::builtin(None));
        assert!(
            matches!(
                found.as_slice(),
                [Violation::SystemProgram { program, wrappers, .. }]
                    if *program == ProgramId::of("/usr/bin/clang++")
                        && *wrappers == [ProgramId::of(LINK_WRAPPER)]
            ),
            "{found:?}"
        );
    }
}
