use super::super::library::{Entry, always, host_derived};
use super::super::program_id::ProgramId;

/// A program in `apple_support`'s crosstool.
///
/// Every one of them ends up at `/usr/bin/xcrun`, which is what makes this
/// file short: the Apple toolchain does not ship a compiler, it borrows the
/// one inside whichever Xcode the machine has, and no flag changes that.
fn crosstool(path: &str) -> ProgramId {
    ProgramId::module("apple_support", &format!("crosstool/{path}"))
}

/// One of `rules_apple`'s tools, under both names it answers to.
///
/// Depend on `rules_apple` and its tools arrive from the module; analyze
/// `rules_apple` itself and the same tools are in the main one. The same
/// loose end as rules_pkg's packaging tools: the second form matches on
/// path alone, so a project building something at the same path inherits a
/// verdict meant for `rules_apple`.
fn apple_tool(path: &str, spec: Entry) -> Vec<(ProgramId, Entry)> {
    let module = ProgramId::module("rules_apple", path);
    vec![
        (module.clone(), spec),
        (ProgramId::main(path), Entry::SameAs(module)),
    ]
}

/// Everything Ahab knows about Apple builds, in source order.
///
/// Nearly all of it is one verdict, and the verdict is not about flags. An
/// Apple build compiles with the Xcode on the machine, bundles with the
/// Xcode on the machine and signs with the identity in its keychain:
/// `wrapped_clang` reads `DEVELOPER_DIR` and `SDKROOT` out of the
/// environment before spawning `/usr/bin/xcrun clang`, and most of the
/// tools below reach the same place by the same route. Two machines with
/// different Xcodes are two different builds, and nothing on a command line
/// says otherwise—which is why these are host-derived rather than
/// conditionally reproducible.
///
/// The bundler is the exception, and it is the one program here that had to
/// be read rather than recognized: it runs no Xcode tool at all.
pub(in crate::reproducibility_spec) fn entries() -> Vec<(ProgramId, Entry)>
{
    // `wrapped_clang.cc`: "Pass args to 'xcrun clang'". It reads
    // `DEVELOPER_DIR` and `SDKROOT` as mandatory environment variables,
    // substitutes them into `__BAZEL_XCODE_*` placeholders, and spawns
    // `/usr/bin/xcrun` with the tool name. The `_pp` half is the same
    // binary asking for `clang++`.
    let mut entries = vec![
        (crosstool("wrapped_clang"), Entry::Spec(host_derived())),
        (crosstool("wrapped_clang_pp"), Entry::Spec(host_derived())),
        // `libtool.cc`, which writes its arguments into a response file
        // and then runs `/usr/bin/xcrun libtool` over it.
        (crosstool("libtool"), Entry::Spec(host_derived())),
        // The link wrapper generated from `osx_cc_wrapper.sh.tpl`. It runs
        // `wrapped_clang`—host-derived already—and then rewrites the
        // binary's load paths with `/usr/bin/xcrun install_name_tool`.
        (crosstool("cc_wrapper.sh"), Entry::Spec(host_derived())),
    ];

    // "Wrapper for 'xcrun' tools", by its own docstring: `actool`,
    // `ibtool` and the rest of the asset compilers, which are Xcode's.
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

    // The plainest case in the file: it runs `/usr/bin/xcrun xcodebuild
    // -version` and writes what came back—the Xcode build number, the SDK
    // version, the platform build—into the plist it produces. The output
    // is a description of the machine.
    entries.extend(apple_tool(
        "tools/environment_plist/environment_plist",
        Entry::Spec(host_derived()),
    ));

    // Runs the `codesign` it is handed to read a bundle's identity and
    // entitlements back out, so the dossier it writes is shaped by the
    // signing tool and keychain of whoever ran it.
    entries.extend(apple_tool(
        "tools/dossier_codesigningtool/dossier_codesigningtool",
        Entry::Spec(host_derived()),
    ));

    // Python that mostly does its own work—`plistlib.dump` sorts the keys,
    // so the XML it writes is settled by what went in—but it reaches for
    // the machine's `plutil` at both ends. Reading, any input that does
    // not begin `<?xml` is piped through `plutil -convert xml1`; writing,
    // a binary result is `plutil -convert binary1` over the finished file,
    // which is what `rules_apple` asks for whenever the bundle wants a
    // binary Info.plist. Its own source says where that leaves things:
    // "plutil is invoked to convert the file to binary, and that again
    // makes no promises. So even if feed a stable input, the output might
    // not be deterministic when run on different machines and/or different
    // macOS versions."
    //
    // Which of the two modes an action asked for is not visible from here:
    // the tool takes one argument, the path of a JSON control file, and
    // the `binary` key lives inside it. So the verdict is about the tool
    // rather than about the invocation, and it is the pessimistic one.
    entries.extend(apple_tool(
        "tools/plisttool/plisttool",
        Entry::Spec(host_derived()),
    ));

    // The bundler, which merges files, directories and other archives into
    // one uncompressed zip, and runs no Xcode tool doing it. Everything
    // that usually makes an archive a function of when and where it was
    // written is pinned instead of read: every entry goes in through a
    // `zipfile.ZipInfo` built without a date, which stamps 1980-01-01
    // rather than the file's modification time; the permission bits are
    // assigned outright—0644, plus the executable bits where the control
    // struct or the source file asks for them—rather than copied off the
    // file; nothing is compressed unless the control struct says so; and
    // files and archives are merged in the order that struct lists them,
    // which `rules_apple` builds from depsets.
    //
    // One thing is not the action's to state. A source that is a
    // directory—a tree artifact: a Core Data model, an app intents bundle,
    // a DocC archive—is walked with `os.walk`, which sorts nothing, so
    // those entries land in whatever order the filesystem lists them. That
    // order is a function of the names on the filesystems these actions
    // run on: APFS returns directory entries in hash order, the hash being
    // a CRC-32C of the normalized name with no per-volume seed, so two
    // Macs agree—and macOS is the only place an Apple bundling action
    // executes, the toolchains being `exec_compatible_with` it. The caveat
    // is written down because it does not hold everywhere: ext4 hashes the
    // name too but mixes in a seed drawn when the filesystem was made, and
    // two Linux machines would order such a bundle differently.
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

    /// The bundler, which is the one entry here that is not host-derived.
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
        // A filter that quietly matched nothing would leave the test below
        // asserting about an empty list.
        assert!(!programs.is_empty());
        programs
    }

    #[test]
    fn the_apple_toolchain_is_host_derived_whatever_it_is_asked() {
        // No flag makes any of these hermetic, so the assessment is taken
        // twice—once bare, once with a plausible command line—to pin that
        // the verdict does not depend on the arguments.
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
        // The whole invocation is the path of a control file, so there is
        // nothing here to be conditional on: the entry either vouches for
        // the tool or it does not.
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
        // What the fishery analyzes: rules_apple's own build, where the
        // tools are in the main repository rather than in a module.
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
