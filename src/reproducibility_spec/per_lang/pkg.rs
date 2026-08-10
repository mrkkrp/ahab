use super::super::library::{Entry, always};
use super::super::program_id::ProgramId;
use super::super::{Reproducibility, ReproducibilitySpec};

/// One of rules_pkg's packaging tools, under both names it answers to.
///
/// Depend on rules_pkg and its tools arrive from the module; analyze
/// rules_pkg itself and the same tools are in the main one. The same loose
/// end as Gazelle's generators: the second form matches on path alone, so a
/// project building something at the same path inherits a verdict meant for
/// rules_pkg.
fn pkg_tool(path: &str, spec: Entry) -> Vec<(ProgramId, Entry)> {
    let module = ProgramId::module("rules_pkg", path);
    vec![
        (module.clone(), spec),
        (ProgramId::main(path), Entry::SameAs(module)),
    ]
}

/// Everything Ahab knows about packaging, in source order.
pub(in crate::reproducibility_spec) fn entries() -> Vec<(ProgramId, Entry)>
{
    // A tar records, for every entry, three things that are not properties
    // of the file: when it was last written, who owned it, and what mode it
    // had. rules_pkg hands all three in on the command line, and `--mtime`
    // is the one with no default—leave it out and the timestamp comes from
    // whatever the tree happened to say.
    //
    // `--preserve_mtime` asks for the opposite: take the source file's own
    // modification time, which is a property of the checkout rather than of
    // the content.
    //
    // Not stated here: `--stamp_from`, which points the tool at a workspace
    // status file. That is a dependency rather than a flag, and the
    // workspace status check reads it off the action's inputs already.
    let tar = Entry::Spec(ReproducibilitySpec::new(
        Reproducibility::Sometimes,
        ["--mtime=*"],
        ["--preserve_mtime"],
    ));

    let mut entries = pkg_tool("pkg/private/tar/build_tar", tar);

    // The zip tool needs nothing asked of it: `-t` defaults to the zip
    // epoch, so an archive built without being told a time still gets a
    // fixed one. Only the contents and the order they are given in decide
    // what comes out.
    entries.extend(pkg_tool(
        "pkg/private/zip/build_zip",
        Entry::Spec(always()),
    ));

    // A Debian package is an `ar` archive of two tarballs, and make_deb
    // writes zero into every field that would otherwise carry a clock—the
    // member timestamps, the gzip header, and the `Date` of the control
    // file, which it derives from the same zero.
    entries.extend(pkg_tool(
        "pkg/private/deb/make_deb",
        Entry::Spec(always()),
    ));

    // Renames and drops files on their way into a package. A function of
    // the manifest it is given.
    entries.extend(pkg_tool("pkg/filter_directory", Entry::Spec(always())));

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
        // Passed bare, as rules_pkg passes it—the false case simply omits
        // the flag rather than spelling it out.
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
        // Deliberately not `Sometimes`: `-t` defaults to the zip epoch, so
        // requiring it would report every archive built without one.
        assert_eq!(
            assess(
                ProgramId::module("rules_pkg", "pkg/private/zip/build_zip"),
                vec!["-o", "out.zip", "--manifest", "m"],
            ),
            Conformance::Reproducible,
        );
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
