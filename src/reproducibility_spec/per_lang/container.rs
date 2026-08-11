use super::super::ReproducibilitySpec;
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

/// The flags with which `img` is told where something sits *inside* the
/// image it is assembling.
///
/// Not inferred from their names: the tool's own help says "inside the
/// image" for each of them, and the ones with defaults default to
/// `/etc/passwd`, `/etc/ssl/certs` and their like—places in a Linux
/// filesystem the image is going to have, which the build machine merely
/// happens to have too.
///
/// The last five are the image's configuration rather than its files: what
/// it runs, from where, and with what environment. `--env` carries the
/// image's own `PATH`, which is why one of these is unavoidable in every
/// image built from a base.
const IMAGE_PATH_FLAGS: [&str; 21] = [
    // Where a file, a directory or an executable lands.
    "--executable",
    "--directory",
    "--file-metadata",
    "--path",
    "--lib-dir",
    // The files the `base` subcommand synthesizes, each of which has a
    // conventional place in the image.
    "--passwd-path",
    "--group-path",
    "--shadow-path",
    "--bundle-path",
    "--exploded-dir",
    "--java-keystore-path",
    "--os-release-path",
    "--usr-lib-path",
    "--lsb-release-path",
    "--ld-so-conf-path",
    "--ld-so-cache-path",
    // What the image does when it is run.
    "--env",
    "--user",
    "--entrypoint",
    "--cmd",
    "--working-dir",
];

/// A record of a param file `img` was given, in which some field is an
/// absolute path.
///
/// The layer subcommand takes its file list through `--add-from-file`,
/// `--symlinks-from-file` and `--symlink-pairs-from-file`, each a file of
/// NUL-separated records naming where things go in the image. Bazel writes
/// those files with `use_param_file(use_always = True)`, and an aquery
/// hands us their lines with no flag attached, so the record has to be
/// recognized by its shape: a NUL immediately followed by `/` is a field
/// that is an absolute path, and every field of these records is an
/// in-image one.
///
/// What this gives up: a record whose *first* field were absolute would not
/// match, and a build path that ever appeared in one of these fields would
/// be passed over. Both are the safe direction—narrower than the flags
/// above, at the cost of a finding we would want.
const IMAGE_PATH_RECORD: &str = "*\0/*";

/// What `img` is, plus which of its options describe the image rather than
/// the machine.
fn img_spec() -> ReproducibilitySpec {
    always()
        .with_valued_flags(IMAGE_PATH_FLAGS)
        .with_declared_paths(
            IMAGE_PATH_FLAGS
                .iter()
                .map(|flag| format!("{flag}=*"))
                .chain([IMAGE_PATH_RECORD.to_owned()]),
        )
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
    //
    // Where it does name absolute paths is in describing the image, and
    // those are not paths on this machine at all—see [`IMAGE_PATH_FLAGS`].
    let mut entries = vec![(canonical_img(), Entry::Spec(img_spec()))];

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

    /// What `declared_path_args` makes of a command line, as the strings it
    /// passes over.
    fn declared(args: &[&str]) -> Vec<String> {
        img_spec()
            .declared_path_args(args)
            .into_iter()
            .map(ToOwned::to_owned)
            .collect()
    }

    #[test]
    fn a_path_in_the_image_is_declared_however_the_flag_is_spelled() {
        // rules_img writes the value as a separate argument; a person
        // reading the report and trying it by hand would write it joined.
        // Both have to reach the same answer or the list is a trap—and
        // either way it is the argument holding `/app` that gets passed
        // over, which is the one the scan would have reported.
        assert_eq!(
            declared(&["manifest", "--working-dir", "/app"]),
            vec!["--working-dir".to_owned(), "/app".to_owned()],
        );
        assert_eq!(
            declared(&["manifest", "--working-dir=/app"]),
            vec!["--working-dir=/app".to_owned()],
        );
    }

    #[test]
    fn a_path_on_the_build_machine_is_not_declared() {
        // The flags that name real inputs and outputs are deliberately not
        // in the list: a toolchain leaking `/usr/bin/gcc` into an `--output`
        // must still be reported, and it is the same tool and the same
        // action that would carry it.
        assert!(
            declared(&[
                "layer",
                "--output",
                "/tmp/scratch/layer.tar",
                "--metadata",
                "/home/someone/meta.json",
            ])
            .is_empty(),
        );
    }

    #[test]
    fn every_flag_in_the_list_declares_its_value() {
        // Each entry is a claim about one flag, so each is exercised rather
        // than trusting that the loop that builds the patterns is right.
        for flag in IMAGE_PATH_FLAGS {
            let args = vec!["base", flag, "/etc/somewhere"];
            assert_eq!(
                declared(&args),
                vec![flag.to_owned(), "/etc/somewhere".to_owned()],
                "{flag}",
            );
        }
    }

    #[test]
    fn a_param_file_record_is_declared_by_its_shape() {
        // A symlink record: where the link goes in the image, and what it
        // points at there. Bazel hands us the line with no flag on it.
        assert_eq!(
            declared(&[
                "layer",
                "etc/app/current.txt\0/etc/app/config.txt"
            ]),
            vec!["etc/app/current.txt\0/etc/app/config.txt".to_owned()],
        );
        // A record whose fields are all relative has nothing to excuse, and
        // an ordinary argument is not a record at all.
        for ordinary in [
            "package_relative\0etc/app/config.txt\0_main/tests\0",
            "/usr/lib/x86_64-linux-gnu",
        ] {
            assert!(
                declared(&["layer", ordinary]).is_empty(),
                "{ordinary}"
            );
        }
    }

    #[test]
    fn declaring_paths_does_not_make_the_tool_conditional() {
        // The flags are named so that `takes_value` can fold them, which is
        // a statement about the tool's interface and must not be mistaken
        // for a condition on its reproducibility.
        assert_eq!(
            assess(
                canonical_img(),
                vec!["manifest", "--working-dir", "/app"],
            ),
            Conformance::Reproducible,
        );
    }
}
