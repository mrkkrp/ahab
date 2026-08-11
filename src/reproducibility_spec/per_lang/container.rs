use super::super::library::{Entry, always};
use super::super::program_id::ProgramId;

/// The platforms rules_img cross-compiles its tool for, as its `BUILD`
/// file lists them.
///
/// The tool is named after the platform it was built for, so a spec that
/// knew only one of these would quietly stop recognizing the tool on a
/// developer's machine that happens not to be the one it was written on.
const IMG_PLATFORMS: [(&str, &str); 7] = [
    ("linux", "amd64"),
    ("linux", "arm64"),
    ("linux", "s390x"),
    ("darwin", "amd64"),
    ("darwin", "arm64"),
    ("windows", "amd64"),
    ("windows", "arm64"),
];

/// Where rules_go puts a `go_binary`: a directory named after the target
/// with a trailing underscore, and the binary inside it.
fn go_binary(package: &str, name: &str) -> String {
    format!("{package}/{name}_/{name}")
}

/// The tool rules_img builds, under the name the host platform gives it.
fn img_tool(path: &str) -> ProgramId {
    ProgramId::module("rules_img_tool", path)
}

/// The one entry the platform-specific names all defer to.
fn canonical_img() -> ProgramId {
    img_tool(&go_binary("cmd/img", "img"))
}

/// Everything Ahab knows about building container images, in source order.
pub(in crate::reproducibility_spec) fn entries() -> Vec<(ProgramId, Entry)>
{
    // One binary behind every image action, dispatched by subcommand:
    // `layer` and `mtree` to assemble a layer, `manifest` and `ocilayout`
    // to describe the result, `push` and `pull` to move it. The same shape
    // as the Go and Kotlin builders.
    //
    // It never asks what time it is. Its clock does appear—in serving,
    // registry authentication and blob download—but nowhere on the path
    // that builds a layer. What a tar entry records is taken from the
    // metadata the build declares, an RFC3339 string parsed from the
    // action's own inputs, so an image is a function of what went into it.
    let mut entries = vec![(canonical_img(), Entry::Spec(always()))];

    // The cross-compiled copies are the same program under another name,
    // so they defer rather than repeat: the report still says which one
    // ran, and the claim is stated once.
    for (os, arch) in IMG_PLATFORMS {
        let name = format!("img_{os}_{arch}");
        entries.push((
            img_tool(&go_binary("cmd/img", &name)),
            Entry::SameAs(canonical_img()),
        ));
        // rules_go gives a Windows binary the suffix the platform expects.
        if os == "windows" {
            entries.push((
                img_tool(&format!("cmd/img/{name}_/{name}.exe")),
                Entry::SameAs(canonical_img()),
            ));
        }
    }

    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reproducibility_spec::Conformance;
    use crate::reproducibility_spec::library::Library;
    use crate::reproducibility_spec::per_lang::testing::assess;

    #[test]
    fn the_tool_is_vouched_for_on_every_platform_it_is_built_for() {
        // The point of the list: a Mac developer runs `img_darwin_arm64`
        // and must get the same answer as the Linux CI that recorded the
        // expectation.
        for (os, arch) in IMG_PLATFORMS {
            let name = format!("img_{os}_{arch}");
            let program = img_tool(&go_binary("cmd/img", &name));
            let resolution =
                Library::builtin().resolve(program.clone(), vec![]);
            assert_eq!(
                resolution.synonym(),
                Some(&canonical_img()),
                "{name}",
            );
            assert_eq!(
                assess(program, vec!["layer", "--output", "l.tar"]),
                Conformance::Reproducible,
                "{name}",
            );
        }
    }

    #[test]
    fn the_windows_builds_are_known_by_their_suffix_too() {
        for arch in ["amd64", "arm64"] {
            let name = format!("img_windows_{arch}");
            let program = img_tool(&format!("cmd/img/{name}_/{name}.exe"));
            assert!(
                Library::builtin().resolve(program, vec![]).spec.is_some(),
                "{name}.exe",
            );
        }
    }

    #[test]
    fn the_name_the_fishery_saw_is_one_of_them() {
        // The path rules_img actually produced, recorded here so that a
        // change to the naming convention fails a test rather than
        // quietly costing three hundred findings their spec.
        assert_eq!(
            ProgramId::of(
                "bazel-out/k8-opt-exec/bin/external/rules_img_tool+/cmd/img\
                 /img_linux_amd64_/img_linux_amd64",
            ),
            img_tool("cmd/img/img_linux_amd64_/img_linux_amd64"),
        );
    }
}
