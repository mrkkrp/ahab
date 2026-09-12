use std::collections::BTreeSet;

use super::super::library::{Entry, always, aspect_bazel_lib, bazel_lib};
use super::super::program_id::ProgramId;
use super::super::{Clause, Guard, Reproducibility, ReproducibilitySpec};
use crate::glob::Glob;

/// One of rules_pkg's packaging tools, under both names it answers to: from
/// the module for a consumer, from the main repository when rules_pkg
/// itself is analyzed. The second form matches on path alone—the same loose
/// end as Gazelle's generators.
fn pkg_tool(path: &str, spec: Entry) -> Vec<(ProgramId, Entry)> {
    let module = ProgramId::module("rules_pkg", path);
    vec![
        (module.clone(), spec),
        (ProgramId::main(path), Entry::SameAs(module)),
    ]
}

/// The command-line compressor shipped by the Brotli module.
fn brotli() -> ProgramId {
    ProgramId::module("brotli", "brotli")
}

/// The `bsdtar` a toolchain hands the build, named by the module that
/// registered the toolchain rather than by the platform-specific repository
/// it was unpacked into—so one entry answers on every platform.
fn bsdtar(module: &str) -> ProgramId {
    ProgramId::extension(module, "toolchains", "tar")
}

/// A guard that holds when any of `flags` is on the command line.
fn given(flags: [&str; 2]) -> Option<Guard> {
    Some(Guard {
        family: flags.into_iter().map(Glob::new).collect(),
        off: BTreeSet::new(),
    })
}

/// What libarchive's tar does with time, which is the only thing about it
/// that is not a function of what it was given. Both clauses were measured
/// against bsdtar 3.8.1 rather than reasoned about.
///
/// Neither sees a bundled short option: `-czf` is one argument and the
/// patterns are whole ones. Every rule set that reaches for this tool spells
/// its flags out, so the gap costs a missed finding rather than a false one.
fn bsdtar_spec() -> ReproducibilitySpec {
    ReproducibilitySpec::new(
        Reproducibility::Sometimes,
        [] as [&str; 0],
        [] as [&str; 0],
    )
    // Both are written joined as well as separated; folding brings the two
    // spellings to one shape.
    .with_valued_flags(["--mtime", "--options"])
    .with_clauses(
        [
            Clause {
                when: given(["--create", "-c"]),
                // Three ways to state the times rather than read them off
                // the filesystem: `--mtime`, entries taken from another
                // archive or a specification (the `@` form), or an mtree
                // line that sets `time=` itself.
                //
                // The last is not the same claim twice: a specification is
                // written with `use_param_file("@%s")`, so Bazel splices it
                // and what arrives is its lines. It is also the stronger
                // claim—a specification naming no times leaves them to the
                // filesystem after all. The loose end is that one such line
                // vouches for the rest.
                any_of: ["--mtime=*", "@*", "* time=*"]
                    .into_iter()
                    .map(Glob::new)
                    .collect(),
                because: "the times an archive records are the \
                          filesystem's unless it is told otherwise"
                    .to_owned(),
            },
            Clause {
                when: given(["--gzip", "-z"]),
                any_of: [Glob::new("--options=*gzip:!timestamp*")]
                    .into_iter()
                    .collect(),
                because: "gzip records the moment it compressed".to_owned(),
            },
        ],
        [] as [Clause; 0],
    )
}

/// Everything Ahab knows about packaging, in source order.
pub(in crate::reproducibility_spec) fn entries() -> Vec<(ProgramId, Entry)>
{
    // rules_pkg hands in each entry's time, owner and mode. `--mtime` is
    // the one with no default: leave it out and the timestamp comes from
    // whatever the tree said. `--preserve_mtime` asks for the opposite.
    //
    // Not stated here: `--stamp_from`, which is a dependency rather than a
    // flag and which the workspace status check already reads off the
    // action's inputs.
    let tar = Entry::Spec(ReproducibilitySpec::new(
        Reproducibility::Sometimes,
        ["--mtime=*"],
        ["--preserve_mtime"],
    ));

    let mut entries = pkg_tool("pkg/private/tar/build_tar", tar);

    // The zip tool needs nothing asked of it: `-t` defaults to the zip
    // epoch, so an archive told no time still gets a fixed one.
    entries.extend(pkg_tool(
        "pkg/private/zip/build_zip",
        Entry::Spec(always()),
    ));

    // A Brotli stream carries no filename, timestamp or ownership metadata.
    // Its clock is used only for verbose progress, on stderr.
    entries.push((brotli(), Entry::Spec(always())));

    // A Debian package is an `ar` archive of two tarballs, and make_deb
    // writes zero into every field that would otherwise carry a clock: the
    // member timestamps, the gzip header, and the control file's `Date`.
    entries.extend(pkg_tool(
        "pkg/private/deb/make_deb",
        Entry::Spec(always()),
    ));

    // Renames and drops files on their way into a package. A function of
    // the manifest it is given.
    entries.extend(pkg_tool("pkg/filter_directory", Entry::Spec(always())));

    // rules_tar's one tool, which every one of its rules dispatches to by
    // flag rather than by subcommand. It never builds an archive out of
    // loose files, only out of other archives, so there is no moment at
    // which it could ask the time: every entry keeps the metadata it had.
    entries.push((
        ProgramId::module("rules_tar", "tar/tool/tool_/tool"),
        Entry::Spec(always()),
    ));

    // libarchive's tar, which two modules register a toolchain for. Unlike
    // the tools above it is not written for a build system and has no
    // opinion about reproducibility, so what it does depends on how it is
    // asked—hence conditions rather than a verdict.
    entries.push((bsdtar("tar.bzl"), Entry::Spec(bsdtar_spec())));
    for other in [bazel_lib("tar"), aspect_bazel_lib("tar")] {
        entries.push((other, Entry::SameAs(bsdtar("tar.bzl"))));
    }

    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reproducibility_spec::Conformance;
    use crate::reproducibility_spec::library::Library;
    use crate::reproducibility_spec::per_lang::testing::{assess, missing};

    fn build_tar() -> ProgramId {
        ProgramId::module("rules_pkg", "pkg/private/tar/build_tar")
    }

    /// A `PackageTar` command line as rules_pkg writes it.
    fn tar_args() -> Vec<&'static str> {
        vec![
            "--output=bazel-out/k8-fastbuild/bin/distro/rules_pkg.tar.gz",
            "--mode=0444",
            "--owner=0.0",
            "--owner_name=.",
            "--directory=.",
            "--compression=gz",
            "--mtime=portable",
            "--manifest=bazel-out/k8-fastbuild/bin/distro/rules_pkg.manifest",
        ]
    }

    #[test]
    fn a_tar_told_when_to_say_it_was_written_is_reproducible() {
        assert_eq!(
            assess(build_tar(), tar_args()),
            Conformance::Reproducible
        );
    }

    #[test]
    fn a_tar_with_no_mtime_is_reported() {
        let flags: Vec<&str> = tar_args()
            .into_iter()
            .filter(|arg| !arg.starts_with("--mtime="))
            .collect();
        assert_eq!(
            missing(build_tar(), flags).iter().collect::<Vec<_>>(),
            vec!["--mtime=*"],
        );
    }

    #[test]
    fn preserving_the_sources_mtime_breaks_it() {
        let mut flags = tar_args();
        flags.push("--preserve_mtime");
        match assess(build_tar(), flags) {
            Conformance::Conditional { unmet } => assert_eq!(
                unmet.iter().flat_map(|c| c.present.iter()).count(),
                1,
            ),
            other => panic!("expected it to break, got {other:?}"),
        }
    }

    #[test]
    fn the_zip_tool_needs_no_timestamp_because_it_has_a_default() {
        assert_eq!(
            assess(
                ProgramId::module("rules_pkg", "pkg/private/zip/build_zip"),
                vec!["-o", "out.zip", "--manifest", "m"],
            ),
            Conformance::Reproducible,
        );
    }

    #[test]
    fn brotli_compression_is_reproducible() {
        assert_eq!(
            assess(
                brotli(),
                vec![
                    "-q",
                    "11",
                    "-f",
                    "-o",
                    "bazel-out/k8-fastbuild/bin/index.html.br",
                    "server/src/main/webapp/index.html",
                ],
            ),
            Conformance::Reproducible,
        );
    }

    #[test]
    fn the_tar_tool_is_reproducible_whichever_rule_dispatched_to_it() {
        let tool = ProgramId::module("rules_tar", "tar/tool/tool_/tool");
        for args in [
            vec![
                "--output",
                "bazel-out/k8-fastbuild/bin/concatenate/out.tar.xz",
                "--duplicate",
                "error",
                "fixture/txt.tar.xz",
            ],
            vec![
                "--output",
                "bazel-out/k8-fastbuild/bin/filter/out.tar.xz",
                "--filter=fixture/nested/*.txt",
                "fixture/fixture.tar.xz",
            ],
        ] {
            assert_eq!(
                assess(tool.clone(), args),
                Conformance::Reproducible,
            );
        }
    }

    #[test]
    fn tar_writing_from_a_specification_is_reproducible() {
        for args in [
            vec![
                "--create",
                "--format",
                "gnutar",
                "--gzip",
                "--options=gzip:!timestamp",
                "--file",
                "group.tar.gz",
                "@group_mtree.txt",
            ],
            vec![
                "--create",
                "--xz",
                "--file",
                "source.tar.xz",
                "@source_mtree.txt",
            ],
        ] {
            assert_eq!(
                assess(bsdtar("tar.bzl"), args.clone()),
                Conformance::Reproducible,
                "{args:?}",
            );
        }
    }

    #[test]
    fn gzip_without_the_option_records_when_it_ran() {
        assert_eq!(
            missing(
                bsdtar("tar.bzl"),
                vec!["--create", "--gzip", "--file", "o.tgz", "@spec"],
            )
            .iter()
            .collect::<Vec<_>>(),
            vec!["--options=*gzip:!timestamp*"],
        );
    }

    #[test]
    fn a_spliced_specification_still_shows_that_it_states_the_times() {
        for spec in [
            vec!["#mtree", "./etc uid=0 gid=0 time=0.0 mode=0755 type=dir"],
            vec!["flatten/ uid=0 gid=0 time=1672560000 type=dir nlink=1"],
        ] {
            let mut args = vec!["--create", "--xz", "--file", "out.tar.xz"];
            args.extend(spec.clone());
            assert_eq!(
                assess(bsdtar("tar.bzl"), args),
                Conformance::Reproducible,
                "{spec:?}",
            );
        }
        assert!(matches!(
            assess(
                bsdtar("tar.bzl"),
                vec![
                    "--create",
                    "--file",
                    "out.tar",
                    "#mtree",
                    "./etc uid=0 gid=0 mode=0755 type=dir",
                ],
            ),
            Conformance::Conditional { .. }
        ));
        assert_eq!(
            assess(
                bsdtar("tar.bzl"),
                vec!["--create", "--file", "o.tar", "@spec"],
            ),
            Conformance::Reproducible,
        );
    }

    #[test]
    fn tar_creating_from_loose_files_records_their_timestamps() {
        let from_files =
            vec!["--create", "--file", "o.tar", "usr/share/doc"];
        assert!(matches!(
            assess(bsdtar("tar.bzl"), from_files.clone()),
            Conformance::Conditional { .. }
        ));
        for mtime in [vec!["--mtime", "0"], vec!["--mtime=0"]] {
            let mut args = from_files.clone();
            args.extend(mtime.clone());
            assert_eq!(
                assess(bsdtar("tar.bzl"), args),
                Conformance::Reproducible,
                "{mtime:?}",
            );
        }
        assert_eq!(
            assess(
                bsdtar("tar.bzl"),
                vec!["-x", "-f", "pkg.deb", "-C", "tmp"],
            ),
            Conformance::Reproducible,
        );
    }

    #[test]
    fn both_toolchains_answer_with_the_same_tar() {
        let resolution =
            Library::builtin().resolve(bsdtar("aspect_bazel_lib"), vec![]);
        assert_eq!(resolution.synonym(), Some(&bsdtar("tar.bzl")));
    }

    #[test]
    fn the_tools_answer_to_both_of_their_names() {
        for path in [
            "pkg/private/tar/build_tar",
            "pkg/private/zip/build_zip",
            "pkg/private/deb/make_deb",
            "pkg/filter_directory",
        ] {
            let from_main =
                Library::builtin().resolve(ProgramId::main(path), vec![]);
            assert_eq!(
                from_main.synonym(),
                Some(&ProgramId::module("rules_pkg", path)),
                "{path}",
            );
        }
    }
}
