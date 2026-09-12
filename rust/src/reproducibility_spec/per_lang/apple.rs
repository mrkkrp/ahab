use super::super::library::{Entry, always, host_derived};
use super::super::program_id::ProgramId;

/// A program in `apple_support`'s crosstool. Every one ends up at
/// `/usr/bin/xcrun`: the Apple toolchain borrows the compiler inside
/// whichever Xcode the machine has, and no flag changes that.
fn crosstool(path: &str) -> ProgramId {
    ProgramId::module("apple_support", &format!("crosstool/{path}"))
}

/// One of `rules_apple`'s tools, under both names it answers to: from the
/// module for a consumer, from the main repository when `rules_apple`
/// itself is analyzed. The same loose end as rules_pkg's packaging tools—
/// the second form matches on path alone.
fn apple_tool(path: &str, spec: Entry) -> Vec<(ProgramId, Entry)> {
    let module = ProgramId::module("rules_apple", path);
    vec![
        (module.clone(), spec),
        (ProgramId::main(path), Entry::SameAs(module)),
    ]
}

/// Everything Ahab knows about Apple builds, in source order.
///
/// Nearly all of it is one verdict, and it is not about flags: an Apple
/// build compiles, bundles and signs with the Xcode and keychain on the
/// machine. Two machines with different Xcodes are two different builds and
/// no command line says otherwise, hence host-derived rather than
/// conditional. The bundler is the exception—it runs no Xcode tool at all.
pub(in crate::reproducibility_spec) fn entries() -> Vec<(ProgramId, Entry)>
{
    // `wrapped_clang.cc` reads `DEVELOPER_DIR` and `SDKROOT` from the
    // environment, substitutes them into `__BAZEL_XCODE_*` placeholders and
    // spawns `/usr/bin/xcrun`. The `_pp` half asks for `clang++`.
    let mut entries = vec![
        (crosstool("wrapped_clang"), Entry::Spec(host_derived())),
        (crosstool("wrapped_clang_pp"), Entry::Spec(host_derived())),
        // `libtool.cc`, which writes its arguments into a response file
        // and then runs `/usr/bin/xcrun libtool` over it.
        (crosstool("libtool"), Entry::Spec(host_derived())),
        // The link wrapper from `osx_cc_wrapper.sh.tpl`: runs
        // `wrapped_clang`, then `/usr/bin/xcrun install_name_tool`.
        (crosstool("cc_wrapper.sh"), Entry::Spec(host_derived())),
    ];

    // "Wrapper for 'xcrun' tools": `actool`, `ibtool` and the rest of
    // Xcode's asset compilers.
    entries.extend(apple_tool(
        "tools/xctoolrunner/xctoolrunner",
        Entry::Spec(host_derived()),
    ));

    // Runs `xcrun swift-stdlib-tool --copy`, so which Swift runtime
    // libraries land in the bundle is a fact about the installed Xcode.
    entries.extend(apple_tool(
        "tools/swift_stdlib_tool/swift_stdlib_tool",
        Entry::Spec(host_derived()),
    ));

    // Writes what `xcrun xcodebuild -version` reports—Xcode build number,
    // SDK version, platform build—into a plist: a description of the
    // machine.
    entries.extend(apple_tool(
        "tools/environment_plist/environment_plist",
        Entry::Spec(host_derived()),
    ));

    // Reads a bundle's identity and entitlements back out with `codesign`,
    // so its dossier is shaped by the signing tool and keychain at hand.
    entries.extend(apple_tool(
        "tools/dossier_codesigningtool/dossier_codesigningtool",
        Entry::Spec(host_derived()),
    ));

    // `plistlib.dump` sorts the keys, but the tool reaches for the
    // machine's `plutil` at both ends: `-convert xml1` on input that does
    // not begin `<?xml`, `-convert binary1` on a binary result. Its own
    // source: "plutil is invoked to convert the file to binary, and that
    // again makes no promises."
    //
    // Which mode an action asked for is invisible here—the sole argument
    // is a JSON control file and the `binary` key lives inside it—so the
    // verdict is about the tool, and it is the pessimistic one.
    entries.extend(apple_tool(
        "tools/plisttool/plisttool",
        Entry::Spec(host_derived()),
    ));

    // Merges files, directories and archives into one uncompressed zip,
    // running no Xcode tool. Everything that usually makes an archive a
    // function of when and where it was written is pinned instead of read:
    // dateless `zipfile.ZipInfo` entries stamped 1980-01-01, permission
    // bits assigned outright, no compression unless asked, and merge order
    // taken from the control struct `rules_apple` builds from depsets.
    //
    // Except one thing: a tree artifact is walked with `os.walk`, which
    // sorts nothing, so its entries land in filesystem order. APFS hashes
    // the normalized name with CRC-32C and no per-volume seed, so two Macs
    // agree—and macOS is the only place these actions run. It would not
    // hold elsewhere: ext4 mixes in a seed drawn at mkfs time.
    entries.extend(apple_tool(
        "tools/bundletool/bundletool",
        Entry::Spec(always()),
    ));

    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reproducibility_spec::Conformance;
    use crate::reproducibility_spec::library::Library;
    use crate::reproducibility_spec::per_lang::testing::assess;

    /// The one entry here that is not host-derived.
    const BUNDLER: &str = "tools/bundletool/bundletool";

    /// Every program this file names, by the id a consumer's build uses,
    /// minus the bundler.
    fn programs() -> Vec<ProgramId> {
        let programs: Vec<ProgramId> = entries()
            .into_iter()
            .filter(|(program, entry)| {
                matches!(entry, Entry::Spec(_))
                    && !program.to_string().ends_with(BUNDLER)
            })
            .map(|(program, _)| program)
            .collect();
        assert!(!programs.is_empty());
        programs
    }

    #[test]
    fn the_apple_toolchain_is_host_derived_whatever_it_is_asked() {
        for program in programs() {
            assert_eq!(
                assess(program.clone(), vec![]),
                Conformance::HostDerived,
                "{program}",
            );
            assert_eq!(
                assess(
                    program.clone(),
                    vec!["-c", "hello.m", "-o", "hello.o"],
                ),
                Conformance::HostDerived,
                "{program}",
            );
        }
    }

    #[test]
    fn the_bundler_is_reproducible_however_it_is_invoked() {
        assert_eq!(
            assess(
                ProgramId::module("rules_apple", BUNDLER),
                vec![
                    "bazel-out/k8-fastbuild/bin/x/bundletool_control.json"
                ],
            ),
            Conformance::Reproducible,
        );
    }

    #[test]
    fn a_rules_apple_tool_answers_under_its_own_repositorys_name() {
        let program = ProgramId::main("tools/xctoolrunner/xctoolrunner");
        let resolved = Library::builtin().resolve(program, vec![]);
        let synonym = resolved.synonym().cloned();
        let (_, spec) = resolved.spec.expect("a spec for the program");
        assert_eq!(spec.assess([]), Conformance::HostDerived);
        assert_eq!(
            synonym,
            Some(ProgramId::module(
                "rules_apple",
                "tools/xctoolrunner/xctoolrunner",
            )),
        );
    }
}
