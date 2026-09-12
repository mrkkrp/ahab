use super::super::ReproducibilitySpec;
use super::super::library::{Entry, always};
use super::super::program_id::ProgramId;

/// The platforms rules_img cross-compiles its tool for. The tool is named
/// after the platform it was built for, so a spec knowing only one of these
/// would stop recognizing it on everyone else's machine.
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
/// image it is assembling. Not inferred from their names: the tool's own
/// help says "inside the image" for each, and the defaults are `/etc/passwd`
/// and the like—places the image will have, which the build machine merely
/// happens to have too.
const IMAGE_PATH_FLAGS: [&str; 21] = [
    // Where a file, a directory or an executable lands.
    "--executable",
    "--directory",
    "--file-metadata",
    "--path",
    "--lib-dir",
    // The files `base` synthesizes, each with a conventional place.
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
    // The image's configuration rather than its files: what it runs, from
    // where, with what environment. `--env` carries the image's own `PATH`.
    "--env",
    "--user",
    "--entrypoint",
    "--cmd",
    "--working-dir",
];

/// A record of a param file `img` was given, in which some field is an
/// absolute path.
///
/// The layer subcommand's file lists are NUL-separated records naming where
/// things go in the image, and aquery hands us their lines with no flag
/// attached, so the record is recognized by its shape. A record whose
/// *first* field were absolute would not match; that is the safe direction.
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

/// The scripts rules_distroless runs to assemble a layer. They share a
/// shape: bsdtar, gawk and coreutils are handed in as arguments rather than
/// found on the machine, and entry times are either carried over from the
/// package or written out as a constant.
fn distroless_tools() -> Vec<(ProgramId, Entry)> {
    [
        // Concatenates a `ca-certificates` package's certificates in glob
        // order, which a sandboxed action carries no locale to vary.
        "distroless/private/cacerts.sh",
        // Writes the rule's declared time onto every mtree entry, then
        // compresses with `gzip:!timestamp`.
        "distroless/private/locale.sh",
        // Merges archives, optionally keeping the last entry per path.
        "distroless/private/flatten.sh",
        // Both write a `/var/lib/dpkg/status.d` entry from a control file.
        // `dpkg_status.sh` hard-codes `time=1672560000` into its mtree;
        // `dpkg_statusd.sh` carries the control archive's times over.
        "apt/private/dpkg_status.sh",
        "apt/private/dpkg_statusd.sh",
        // A `keytool` reimplementation that writes each certificate's own
        // `notBefore` where the stock one stamps the moment of addition.
        // Its digest password and salt are constants in the source.
        "distroless/private/keystore_binary",
    ]
    .into_iter()
    .map(|path| {
        (
            ProgramId::module("rules_distroless", path),
            Entry::Spec(always()),
        )
    })
    .collect()
}

/// Everything Ahab knows about building container images, in source order.
pub(in crate::reproducibility_spec) fn entries() -> Vec<(ProgramId, Entry)>
{
    // One binary behind every image action, dispatched by subcommand.
    // Its clock appears in serving, registry authentication and blob
    // download, but nowhere on the path that builds a layer: a tar entry's
    // time comes from an RFC3339 string in the action's own inputs.
    //
    // The absolute paths it names describe the image rather than this
    // machine—see [`IMAGE_PATH_FLAGS`].
    let mut entries = vec![(canonical_img(), Entry::Spec(img_spec()))];

    // The cross-compiled copies defer so the claim is stated once, while
    // the report still says which one ran.
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

    entries.extend(distroless_tools());

    // Measures a layer—digest, size, compression—off the archive itself.
    // The one field that could have come from a clock does not: the script
    // writes `created: "1970-01-01T00:00:00Z"` literally.
    entries.push((
        ProgramId::module("rules_oci", "oci/private/descriptor.sh"),
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

    #[test]
    fn the_tool_is_vouched_for_on_every_platform_it_is_built_for() {
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
        assert_eq!(
            ProgramId::of(
                "bazel-out/k8-opt-exec/bin/external/rules_img_tool+/cmd/img\
                 /img_linux_amd64_/img_linux_amd64",
            ),
            img_tool("cmd/img/img_linux_amd64_/img_linux_amd64"),
        );
    }

    #[test]
    fn the_distroless_layer_tools_are_vouched_for() {
        let tools = [
            ("distroless/private/cacerts.sh", vec!["tar", "pkg.deb"]),
            (
                "distroless/private/locale.sh",
                vec!["tar", "out.tgz", "data.tar.xz", "123"],
            ),
            ("distroless/private/flatten.sh", vec!["tar", "False"]),
            ("apt/private/dpkg_status.sh", vec!["tar", "out.tar"]),
            (
                "apt/private/dpkg_statusd.sh",
                vec!["tar", "out.tar", "control.tar.xz", "ca-certificates"],
            ),
            (
                "distroless/private/keystore_binary",
                vec!["out.jks", "amazon.crt"],
            ),
        ];
        for (path, args) in tools {
            assert_eq!(
                assess(ProgramId::module("rules_distroless", path), args),
                Conformance::Reproducible,
                "{path}",
            );
        }
    }

    #[test]
    fn the_oci_descriptor_is_vouched_for() {
        assert_eq!(
            assess(
                ProgramId::module("rules_oci", "oci/private/descriptor.sh"),
                vec!["flat.tar", "image.0.descriptor.json", "@base//:flat"],
            ),
            Conformance::Reproducible,
        );
    }

    /// What `declared_path_args` passes over in a command line.
    fn declared(args: &[&str]) -> Vec<String> {
        img_spec()
            .declared_path_args(args)
            .into_iter()
            .map(ToOwned::to_owned)
            .collect()
    }

    #[test]
    fn a_path_in_the_image_is_declared_however_the_flag_is_spelled() {
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
        assert_eq!(
            declared(&[
                "layer",
                "etc/app/current.txt\0/etc/app/config.txt"
            ]),
            vec!["etc/app/current.txt\0/etc/app/config.txt".to_owned()],
        );
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
        assert_eq!(
            assess(
                canonical_img(),
                vec!["manifest", "--working-dir", "/app"],
            ),
            Conformance::Reproducible,
        );
    }
}
