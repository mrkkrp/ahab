use super::super::library::{Entry, always, host_derived};
use super::super::program_id::ProgramId;
use super::super::{Clause, Guard, Reproducibility, ReproducibilitySpec};

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

/// A prebuilt tool from the `llvm` module's `llvm_toolchain_minimal`.
fn minimal_llvm(path: &str) -> ProgramId {
    ProgramId::extension("llvm", "llvm_toolchain_minimal", path)
}

/// A helper the `llvm` module builds from its `tools/internal`.
fn llvm_internal(tool: &str) -> ProgramId {
    ProgramId::module("llvm", &format!("tools/internal/{tool}/{tool}"))
}

/// Why an archiver must zero the metadata it stores for each member.
const ARCHIVE_METADATA: &str =
    "archive headers retain user IDs, group IDs and timestamps";

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

/// The macros a compilation has to define away, and the flags that would
/// otherwise let each of them record the clock.
const DATE_MACROS: [&str; 3] = ["__DATE__", "__TIME__", "__TIMESTAMP__"];

/// The names Bazel gives C-family sources and headers, plus C++20 module
/// interfaces: any of them among clang's arguments means it reads headers.
const SOURCES_AND_HEADERS: &[&str] = &[
    "*.c", "*.cc", "*.cpp", "*.cxx", "*.c++", "*.C", "*.cu", "*.cl", "*.m",
    "*.mm", "*.S", "*.cppm", "*.ixx", "*.h", "*.hh", "*.hpp", "*.ipp",
    "*.hxx", "*.h++", "*.inc", "*.inl", "*.tlh", "*.tli", "*.H", "*.tcc",
];

/// The clauses for what clang does. One program compiles, links and
/// preprocesses, so most are guarded: the date macros on `-c`, the stricter
/// canonicalization clause on a source or header among the arguments, and
/// the last on the family of flags that emits debugging information.
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

    // With the resource directory named, what a link still resolves through
    // clang's location only finds the linker, its plugin and library
    // directories, none of which the output records.
    clauses.push(Clause::new(
        None,
        ["-no-canonical-prefixes", "-resource-dir", "-resource-dir=*"],
        "paths clang derives from its own location, such as a sanitizer \
         runtime's rpath, are absolute",
    ));
    clauses.push(Clause::new(
        Some(Guard::on(SOURCES_AND_HEADERS)),
        ["-no-canonical-prefixes"],
        "headers found next to the compiler are named by the absolute path \
         its symlinks resolve to",
    ));

    // `-ffile-prefix-map` implies the debug mapping, and naming the
    // compilation directory outright addresses the same field, which
    // `-ffile-compilation-dir` names for coverage mapping as well.
    clauses.push(Clause::new(
        Some(emits_debug_info),
        [
            "-ffile-prefix-map=*",
            "-fdebug-prefix-map=*",
            "-fdebug-compilation-dir=*",
            "-ffile-compilation-dir=*",
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
        // input and the question becomes what it is asked to do.
        (
            llvm_toolchain("bin/cc_wrapper.sh"),
            Entry::Spec(
                ReproducibilitySpec::of(Reproducibility::Sometimes)
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
        // Execs the toolchain's own clang++ with its arguments. The dSYM and
        // interface library it can go on to produce are switched on through
        // the environment alone, so dsymutil, llvm-ifs and the rest that
        // they run are not examined.
        (
            llvm_internal("link-wrapper-clang++"),
            Entry::SameAs(minimal_llvm("bin/clang++")),
        ),
        // Touches the stamp Bazel expects, then execs the toolchain's own
        // clang++ with its arguments, which check syntax and write a
        // dependency file.
        (
            llvm_internal("header-parser"),
            Entry::SameAs(minimal_llvm("bin/clang++")),
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
                            ARCHIVE_METADATA,
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
        (
            minimal_llvm("bin/llvm-ar"),
            Entry::SameAs(llvm_toolchain("bin/llvm-ar")),
        ),
        // The archiver for Apple platforms zeroes the same fields unless
        // given -U, which it refuses to combine with -D.
        (
            minimal_llvm("bin/llvm-libtool-darwin"),
            Entry::Spec(
                ReproducibilitySpec::of(Reproducibility::Sometimes)
                    .with_clauses(
                        [],
                        [Clause::new(None, ["-U"], ARCHIVE_METADATA)],
                    ),
            ),
        ),
        // Packs split DWARF objects into one file, adding index tables but
        // nothing from the machine or the clock.
        (minimal_llvm("bin/llvm-dwp"), Entry::Spec(always())),
        // Looks for duplicate symbols in an archive with the llvm-nm and
        // c++filt its environment names, and writes only an empty stamp.
        (
            llvm_internal("static-library-validator"),
            Entry::Spec(always()),
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
    fn a_source_or_header_needs_no_canonical_prefixes_not_a_resource_dir() {
        for invocation in [
            vec!["-c", "x.cc"],
            vec!["-S", "x.c"],
            vec!["-E", "x.m"],
            vec!["-M", "x.c"],
            vec!["-fsyntax-only", "-xc++-header", "x.h"],
            vec!["--precompile", "x.cppm"],
            vec!["x.cc", "-o", "x"],
        ] {
            let mut flags = clang_without("-no-canonical-prefixes");
            flags.retain(|arg| *arg != "-c" && !arg.ends_with(".cc"));
            flags.extend(["-resource-dir", "rel/res"]);
            flags.extend(invocation.iter());
            assert_eq!(
                missing(llvm_toolchain("bin/cc_wrapper.sh"), flags)
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                vec!["-no-canonical-prefixes"],
                "{invocation:?}",
            );
        }
    }

    fn remedies() -> BTreeSet<String> {
        [
            "-fdebug-compilation-dir=*",
            "-fdebug-prefix-map=*",
            "-ffile-compilation-dir=*",
            "-ffile-prefix-map=*",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    fn canonicalization_remedies() -> BTreeSet<String> {
        ["-no-canonical-prefixes", "-resource-dir", "-resource-dir=*"]
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
            "-ffile-compilation-dir=.",
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
    fn a_link_needs_no_canonical_prefixes_or_its_resource_directory() {
        let linking = [
            "-o",
            "bazel-out/k8-fastbuild/bin/source/exe/envoy-static",
            "-Wl,-S",
            "-Xlinker",
            "-E",
            "bazel-out/k8-fastbuild/bin/source/exe/libmain.a",
        ];
        assert_eq!(
            missing(llvm_toolchain("bin/cc_wrapper.sh"), linking.to_vec()),
            canonicalization_remedies(),
        );
        for named in [
            &["-no-canonical-prefixes"][..],
            &["-resource-dir", "rel/res"],
            &["-resource-dir=rel/res"],
        ] {
            assert_eq!(
                assess(
                    llvm_toolchain("bin/cc_wrapper.sh"),
                    [named, &linking].concat(),
                ),
                Conformance::Reproducible,
                "{named:?}",
            );
        }
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
                let unmet = missing(program.clone(), clang_without(flag));
                assert!(
                    unmet.iter().any(|pattern| pattern.starts_with(flag)),
                    "{tool}: {flag}: {unmet:?}",
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

    #[test]
    fn libtool_is_reproducible_unless_told_to_keep_member_metadata() {
        let libtool = minimal_llvm("bin/llvm-libtool-darwin");
        let archive = ["-static", "-o", "out/libx.a", "x.o"];
        for mode in [&[][..], &["-D"]] {
            let flags = [mode, &archive].concat();
            assert_eq!(
                assess(libtool.clone(), flags.clone()),
                Conformance::Reproducible,
                "{flags:?}",
            );
        }
        assert_eq!(
            assess(libtool, [&["-U"][..], &archive].concat())
                .present_breaking(),
            BTreeSet::from(["-U".to_owned()]),
        );
    }

    #[test]
    fn the_minimal_archiver_and_debug_tools_resolve_from_action_paths() {
        let minimal = "external/llvm++llvm_toolchain_minimal+llvm-toolchain-minimal-linux-amd64";
        for (path, args) in [
            (format!("{minimal}/bin/llvm-ar"), vec!["rcsD", "libx.a", "x.o"]),
            (format!("{minimal}/bin/llvm-dwp"), vec!["x.dwo", "-o", "x.dwp"]),
            (
                "bazel-out/k8-fastbuild/bin/external/llvm+/tools/internal/static-library-validator/static-library-validator".to_owned(),
                vec!["libx.a", "x_validation_output.txt"],
            ),
        ] {
            assert_eq!(
                assess(ProgramId::of(&path), args),
                Conformance::Reproducible,
                "{path}",
            );
        }
        assert_eq!(
            missing(
                ProgramId::of(&format!("{minimal}/bin/llvm-ar")),
                vec!["rcs", "libx.a", "x.o"],
            )
            .len(),
            1,
        );
    }

    const LINK_WRAPPER: &str = "bazel-out/darwin_arm64-fastbuild/bin/external/llvm+/tools/internal/link-wrapper-clang++/link-wrapper-clang++";
    const HEADER_PARSER: &str = "bazel-out/k8-fastbuild/bin/external/llvm+/tools/internal/header-parser/header-parser";

    #[test]
    fn the_header_parser_is_judged_as_the_clang_it_runs() {
        let parse = |flags: &[&str]| {
            let mut action = action_with_env("CppCompile", 1, &[]);
            let tail = ["-resource-dir", "rel/res", "-fsyntax-only", "x.h"];
            action.arguments = [&[HEADER_PARSER], flags, &tail]
                .concat()
                .into_iter()
                .map(str::to_owned)
                .collect();
            check_reproducibility(
                &container(vec![action]),
                &Library::builtin(None),
            )
        };
        assert!(parse(&["-no-canonical-prefixes"]).is_empty());

        let found = parse(&[]);
        let [
            Violation::ConditionalReproducibility {
                program,
                synonym,
                unmet,
                ..
            },
        ] = found.as_slice()
        else {
            panic!("{found:?}");
        };
        assert_eq!(*program, llvm_internal("header-parser"));
        assert_eq!(*synonym, Some(llvm_toolchain("bin/cc_wrapper.sh")));
        assert_eq!(unmet.len(), 1);
        assert_eq!(
            unmet[0].any_of,
            BTreeSet::from(["-no-canonical-prefixes".to_owned()])
        );
    }

    #[test]
    fn the_link_wrapper_is_judged_as_clang_by_its_param_file_flags() {
        let link = |params: &[&str]| {
            check_reproducibility(
                &container(vec![action_with_param_files(
                    "CppLink",
                    1,
                    &[LINK_WRAPPER, "@out/link.params"],
                    &[("out/link.params", params)],
                )]),
                &Library::builtin(None),
            )
        };
        assert!(link(&["-resource-dir", "rel/res", "a.o"]).is_empty());

        let found = link(&["a.o"]);
        let [
            Violation::ConditionalReproducibility {
                program,
                synonym,
                unmet,
                ..
            },
        ] = found.as_slice()
        else {
            panic!("{found:?}");
        };
        assert_eq!(*program, llvm_internal("link-wrapper-clang++"));
        assert_eq!(*synonym, Some(llvm_toolchain("bin/cc_wrapper.sh")));
        assert_eq!(unmet[0].any_of, canonicalization_remedies());
    }
}
