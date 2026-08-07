//! Stable identification of the programs that build actions run.
//!
//! A [`ReproducibilitySpec`](super::ReproducibilitySpec) describes one
//! program, so specs must be keyed by something that names a program and
//! only that program, consistently across builds. [`ProgramId`] is that
//! key: an action's `argv[0]` with everything unstable normalized away,
//! leaving only what the tool's own author controls.
//!
//! The rest of these docs record *why* it is built this way. The reasoning
//! rests on empirical facts about Bazel that are easy to get wrong and that
//! shift between releases, so they are written down here rather than
//! rediscovered.
//!
//! # Why not the obvious keys
//!
//! * **The executable's base name** (`process_wrapper`) is not unique. Two
//!   rulesets can ship unrelated tools under the same file name, so
//!   `foo/bar/process_wrapper` and `baz/quux/process_wrapper` would collide.
//! * **The full exec path** is unique but wildly unstable — see the gradient
//!   below.
//! * **The owning target's label**, e.g.
//!   `@@rules_rust++crate+crates__anyhow-1.0.104//:anyhow`, looks
//!   attractive but is strictly worse. `analysis_v2.proto`'s `Artifact`
//!   carries only `id`, `path_fragment_id` and `is_tree_artifact`—no
//!   owner—so recovering a label means finding the action that generates
//!   the executable and reading its `target_id`. That fails for prebuilt
//!   and system tools, and the label embeds the same canonical repository
//!   name, so it would need exactly the normalization below anyway. Path
//!   normalization is the better primitive.
//!
//! # The stability gradient
//!
//! Reading a path such as
//! `bazel-out/k8-opt-exec/bin/external/rules_rust++crate+crates__anyhow-1.0.104/foo`
//! left to right, stability *increases*:
//!
//! 1. **`bazel-out/<configuration>/<root>`**—least stable. Varies with CPU,
//!    compilation mode and exec-vs-target, and Bazel 8+ can append a
//!    `-ST-<hash>` suffix for output-directory diffs. Only the three-segment
//!    *shape* is fixed, so that is all [`strip_output_prefix`] relies on.
//! 2. **The separator and version fields**—unstable across Bazel releases;
//!    see the table below.
//! 3. **The generated repository name** (`crates__anyhow-1.0.104`,
//!    `llvm_toolchain_llvm`)—chosen by the project being analyzed, and
//!    version- and platform-bearing. Dropped entirely.
//! 4. **Module and extension names** (`rules_rust`, `crate`)—fixed by the
//!    tool's author. Kept.
//! 5. **The package and target tail**
//!    (`util/process_wrapper/process_wrapper`)—most stable: it is the
//!    ruleset's own source layout, which moves only when the ruleset
//!    reorganizes, which is exactly when a spec should be revisited anyway.
//!    Kept.
//!
//! # Canonical repository names
//!
//! The delicate part is decoding the repository segment. Bazel's canonical
//! repository names have changed shape repeatedly:
//!
//! | Bazel      | module repository | extension repository                        |
//! |------------|-------------------|---------------------------------------------|
//! | WORKSPACE  | `rules_rust`      | n/a                                         |
//! | 6.x – 7.0  | `rules_rust~0.40.0` | `rules_rust~0.40.0~crate~crates__anyhow-1.0.104` |
//! | 7.1 – 7.x  | `rules_rust~`     | `rules_rust~~crate~crates__anyhow-1.0.104`  |
//! | 8.x – 9.x  | `rules_rust+`     | `rules_rust++crate+crates__anyhow-1.0.104`  |
//!
//! Within a single Bazel version the names still vary by field count. Of the 336
//! repositories surveyed:
//!
//! | fields | count | shape                                   | example                                    |
//! |--------|-------|-----------------------------------------|--------------------------------------------|
//! | 1      | 3     | `<module>`                              | `bazel_tools`, `platforms`, `_main`        |
//! | 2      | 20    | `<module>+<version>`                    | `llvm+`, `rules_rust+`                     |
//! | 3      | 2     | `<module>+<extension>+<repo>`           | `platforms+host_platform+host_platform`    |
//! | 4      | 247   | `<module>+<version>+<extension>+<repo>` | `rules_rust++crate+crates__anyhow-1.0.104` |
//!
//! The three-field shape exists because built-in repositories (`bazel_tools`,
//! `platforms`) carry no version suffix, which shifts every later field left; a
//! fixed four-field split would misread them. Rather than special-case them,
//! [`decode_repo`] relies on the invariant that holds across all four shapes:
//! the *first* field is always the module and, when there are three or more
//! fields, the *last two* are always the extension and the repository it
//! generated. Whatever sits in between is a version.
//!
//! Splitting is unambiguous because Bazel repository names are restricted to
//! `[A-Za-z0-9._-]`, so `+` and `~` can only ever be separators.
//!
//! # What survives normalization
//!
//! Only the module and extension names, because only they are outside the
//! analyzed project's control:
//!
//! * **Module name**—comes from `module(name = …)` in the dependency's
//!   *own* `MODULE.bazel`, i.e. its registry identity. Notably it is not
//!   affected by `bazel_dep(name = "rules_rust", repo_name = "rr")`, which
//!   rebinds only the apparent name used inside the consumer's files.
//! * **Extension name**—the exported symbol in the defining `.bzl`, e.g.
//!   `crate = module_extension(…)` in
//!   `@rules_rust//crate_universe:extensions.bzl`. The variable a consumer
//!   binds at the `use_extension` call site never appears. Evidenced by
//!   `bazel_lib++toolchains+coreutils_linux_amd64`, where `toolchains` is
//!   aspect_bazel_lib's export name even though this project never mentions
//!   aspect_bazel_lib, and by `rules_rust++i2+rrc__autocfg-1.5.0`, where
//!   `i2` is one of rules_rust's terse internal extensions.
//!
//! The other two fields are dropped:
//!
//! * **Module version**—empty in all 247 four-field names surveyed, since
//!   it is populated only under `multiple_version_override`. It is pure
//!   churn, and it can never be what distinguishes two programs: if two
//!   versions of a tool behave differently that is a question about flags,
//!   not identity.
//! * **Generated repository name**—braids together three separate unstable
//!   things, all three visible in the survey: names the consuming project
//!   chose (the `crates` in `crates__anyhow-1.0.104` is its
//!   `use_repo(crate, "crates")`), dependency versions (`-1.0.104`), and
//!   host or target platforms (`llvm-toolchain-minimal-22.1.8-linux-amd64`,
//!   `rust_linux_x86_64__x86_64-unknown-linux-gnu__stable_tools`). None of
//!   it is knowable to whoever writes a spec.
//!
//! The payoff is that a spec never names a version, a platform triple, a
//! separator, or anything the analyzed project picked—which in turn means
//! exact matching is enough, and no glob or pattern machinery is needed.
//!
//! # Known consequence: extension granularity
//!
//! Dropping the repository name means every repository generated by one
//! extension shares an identity. Each crate_universe build script
//! normalizes to `@rules_rust+crate//…` regardless of which crate it
//! belongs to, folding roughly 90 of the surveyed repositories into a
//! single key.
//!
//! This is deliberate: "a Cargo build script" is the unit we have
//! reproducibility knowledge about, not "anyhow 1.0.104's build script". It
//! does foreclose saying "openssl-sys's build script specifically is
//! non-hermetic". If that becomes necessary, the extension point is an
//! optional discriminator on [`Origin`] — adding one is backwards
//! compatible with specs written against the coarser key.
//!
//! # Related concern, deliberately out of scope
//!
//! `process_wrapper` and friends are *wrappers*: their reproducibility is
//! really that of whatever follows `--` in their argument list. Keying them
//! like any other program is a simplification. Handling it properly means
//! letting a spec say "I am a wrapper, re-dispatch on `argv[n..]`", which
//! is a question about the shape of [`super::ReproducibilitySpec`], not
//! about identity.

use serde::{Deserialize, Serialize};

use std::fmt;

/// Where a program comes from, with unstable naming normalized away.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// The main repository—the workspace being analyzed. `extension` is set
    /// when the program lives in a repository generated by an extension
    /// that the main repository itself defines.
    Main {
        /// The module extension that generated the repository, if any.
        extension: Option<String>,
    },
    /// An external Bazel module, named as it is in the registry
    /// (`rules_rust`, `llvm`)—never by the apparent name a `bazel_dep` may
    /// have bound it to.
    Module {
        /// The module name, i.e. its `module(name = …)`.
        name: String,
        /// The module extension that generated the repository, if any.
        extension: Option<String>,
    },
    /// Outside the execution root: an absolute path to a tool on the host,
    /// or a bare command name resolved through `PATH`. Either way the
    /// program is not part of the build, which is itself a hermeticity
    /// signal.
    System,
}

/// A stable key identifying the program an action runs.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
pub struct ProgramId {
    /// The repository the program comes from.
    pub origin: Origin,
    /// The program's path within that repository, e.g.
    /// `util/process_wrapper/process_wrapper`. For [`Origin::System`] this
    /// is the path or command name as it appeared in `argv[0]`.
    pub path: String,
}

/// Constructors for *naming* a program in source, as [`super::hardcoded`] does
/// when a spec or a synonym is written against one.
#[allow(dead_code)]
impl ProgramId {
    /// A program in a Bazel module's own repository, e.g.
    /// `@rules_rust//util/process_wrapper/process_wrapper`. `module` is the
    /// module's registry name—never an apparent name a `bazel_dep` bound it
    /// to.
    pub fn module(module: &str, path: &str) -> ProgramId {
        ProgramId {
            origin: Origin::Module {
                name: module.to_owned(),
                extension: None,
            },
            path: path.to_owned(),
        }
    }

    /// A program in a repository generated by one of a module's extensions,
    /// e.g. `@llvm+llvm_toolchain_minimal//bin/clang`. `extension` is the
    /// extension's exported symbol name in the module that defines it.
    pub fn extension(
        module: &str,
        extension: &str,
        path: &str,
    ) -> ProgramId {
        ProgramId {
            origin: Origin::Module {
                name: module.to_owned(),
                extension: Some(extension.to_owned()),
            },
            path: path.to_owned(),
        }
    }
}

impl ProgramId {
    /// Identify the program an action runs from its executable path (`argv[0]`).
    pub fn of(executable: &str) -> ProgramId {
        if executable.starts_with('/') || !executable.contains('/') {
            return ProgramId {
                origin: Origin::System,
                path: executable.to_owned(),
            };
        }

        let path = strip_output_prefix(executable);

        // In a runfiles tree the repository name is a plain path segment
        // rather than something under `external/`, so it has to be split
        // off first.
        if let Some(rest) = strip_runfiles_prefix(path) {
            if let Some((repo, tail)) = rest.split_once('/') {
                return ProgramId {
                    origin: decode_repo(repo),
                    path: tail.to_owned(),
                };
            }
        }

        if let Some((repo, tail)) = split_external(path) {
            return ProgramId {
                origin: decode_repo(repo),
                path: tail.to_owned(),
            };
        }

        ProgramId {
            origin: Origin::Main { extension: None },
            path: path.to_owned(),
        }
    }
}

/// Render an id in a Bazel-like label form: `@rules_rust//util/process_wrapper`,
/// `@rules_rust+crate//_bs.out_dir`, `//src/tools/gen`, `/usr/bin/gcc`.
///
/// The `@<module>+<extension>` spelling mirrors Bazel's own encoding, minus the
/// version and repository fields we drop. A main-repository extension therefore
/// renders with an empty module (`@+myext//…`), just as Bazel writes it.
impl fmt::Display for ProgramId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.origin {
            Origin::System => write!(f, "{}", self.path),
            Origin::Main { extension: None } => {
                write!(f, "//{}", self.path)
            }
            Origin::Main {
                extension: Some(extension),
            } => write!(f, "@+{extension}//{}", self.path),
            Origin::Module {
                name,
                extension: None,
            } => write!(f, "@{name}//{}", self.path),
            Origin::Module {
                name,
                extension: Some(extension),
            } => write!(f, "@{name}+{extension}//{}", self.path),
        }
    }
}

/// Strip a leading `bazel-out/<configuration>/<root>/`, e.g.
/// `bazel-out/k8-opt-exec/bin/`.
fn strip_output_prefix(path: &str) -> &str {
    let Some(rest) = path.strip_prefix("bazel-out/") else {
        return path;
    };
    let mut segments = rest.splitn(3, '/');
    match (segments.next(), segments.next(), segments.next()) {
        (Some(_configuration), Some(_root), Some(tail)) => tail,
        _ => path,
    }
}

/// Strip everything up to and including a `<binary>.runfiles/` segment,
/// returning `None` when the path does not run through a runfiles tree. The
/// last occurrence wins, so a runfiles tree nested inside another resolves
/// to the innermost one.
fn strip_runfiles_prefix(path: &str) -> Option<&str> {
    const MARKER: &str = ".runfiles/";
    let start = path.rmatch_indices(MARKER).next()?.0;
    Some(&path[start + MARKER.len()..])
}

/// Split a repository-qualified path into `(repository, tail)`. External
/// paths appear as `external/<repo>/…` in the execution root and as
/// `../<repo>/…` when written relative to a runfiles directory.
fn split_external(path: &str) -> Option<(&str, &str)> {
    let rest = path
        .strip_prefix("external/")
        .or_else(|| path.strip_prefix("../"))?;
    let (repo, tail) = rest.split_once('/')?;
    if tail.is_empty() {
        return None;
    }
    Some((repo, tail))
}

/// Decode a canonical repository name into an [`Origin`], discarding the
/// module version and the generated repository name. See the module docs
/// for the grammar; both the Bazel 8+ `+` separator and the older `~` are
/// accepted.
fn decode_repo(repo: &str) -> Origin {
    let separator = if repo.contains('+') { '+' } else { '~' };
    let fields: Vec<&str> = repo.split(separator).collect();

    // With three or more fields the last two are always the module
    // extension and the repository it generated. Fewer fields means a
    // module repository, whose trailing field (if present) is the version.
    let extension = if fields.len() >= 3 {
        Some(fields[fields.len() - 2].to_owned())
    } else {
        None
    };

    // Bazel spells the main repository `_main`; an extension defined by the
    // main module leaves the module field empty. Accept both.
    let module = fields[0];
    if module.is_empty() || module == "_main" {
        Origin::Main { extension }
    } else {
        Origin::Module {
            name: module.to_owned(),
            extension,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `Module` origin without an extension, for terse assertions.
    fn module(name: &str) -> Origin {
        Origin::Module {
            name: name.to_owned(),
            extension: None,
        }
    }

    /// Build a `Module` origin reached through an extension.
    fn module_ext(name: &str, extension: &str) -> Origin {
        Origin::Module {
            name: name.to_owned(),
            extension: Some(extension.to_owned()),
        }
    }

    #[test]
    fn absolute_paths_are_system_tools() {
        let id = ProgramId::of("/usr/bin/gcc");
        assert_eq!(id.origin, Origin::System);
        // The whole path is kept: /usr/bin/gcc and /opt/bin/gcc are different.
        assert_eq!(id.path, "/usr/bin/gcc");
        assert_eq!(id.to_string(), "/usr/bin/gcc");
    }

    #[test]
    fn bare_command_names_are_system_tools() {
        // No separator at all means PATH resolution, i.e. not part of the build.
        let id = ProgramId::of("clang");
        assert_eq!(id.origin, Origin::System);
        assert_eq!(id.path, "clang");
    }

    #[test]
    fn empty_input_is_a_system_tool() {
        assert_eq!(
            ProgramId::of(""),
            ProgramId {
                origin: Origin::System,
                path: String::new(),
            }
        );
    }

    #[test]
    fn output_prefix_is_stripped_for_main_repository_paths() {
        let id = ProgramId::of("bazel-out/k8-fastbuild/bin/src/tools/gen");
        assert_eq!(id.origin, Origin::Main { extension: None });
        assert_eq!(id.path, "src/tools/gen");
        assert_eq!(id.to_string(), "//src/tools/gen");
    }

    #[test]
    fn the_configuration_segment_is_not_inspected() {
        // Compilation mode, exec-vs-target and the Bazel 8 `-ST-<hash>` suffix
        // all vary; only the three-segment shape is relied upon.
        for configuration in
            ["k8-fastbuild", "k8-opt-exec", "k8-opt-exec-ST-1a2b3c4d"]
        {
            let path = format!(
                "bazel-out/{configuration}/bin/external/rules_rust+/util/x"
            );
            let id = ProgramId::of(&path);
            assert_eq!(id.origin, module("rules_rust"), "{configuration}");
            assert_eq!(id.path, "util/x", "{configuration}");
        }
    }

    #[test]
    fn a_short_bazel_out_path_is_left_alone() {
        // Too few segments to be an output prefix; do not mangle it.
        let id = ProgramId::of("bazel-out/k8-fastbuild");
        assert_eq!(id.origin, Origin::Main { extension: None });
        assert_eq!(id.path, "bazel-out/k8-fastbuild");
    }

    #[test]
    fn module_repository_normalizes_to_its_module_name() {
        // The motivating case: the process_wrapper path from the module docs.
        let id = ProgramId::of(
            "bazel-out/k8-opt-exec/bin/external/rules_rust+/util/process_wrapper/process_wrapper",
        );
        assert_eq!(id.origin, module("rules_rust"));
        assert_eq!(id.path, "util/process_wrapper/process_wrapper");
        assert_eq!(
            id.to_string(),
            "@rules_rust//util/process_wrapper/process_wrapper"
        );
    }

    #[test]
    fn programs_differing_only_in_repository_path_are_distinct() {
        // The whole point of not keying on the base name.
        let a = ProgramId::of(
            "bazel-out/k8-fastbuild/bin/external/rules_rust+/util/process_wrapper/process_wrapper",
        );
        let b = ProgramId::of(
            "bazel-out/k8-fastbuild/bin/external/some_module+/baz/quux/process_wrapper",
        );
        assert_ne!(a, b);
    }

    #[test]
    fn extension_repository_keeps_module_and_extension_but_drops_the_repository()
     {
        let id = ProgramId::of(
            "bazel-out/k8-fastbuild/bin/external/rules_rust++crate+crates__anyhow-1.0.104/_bs.out_dir",
        );
        assert_eq!(id.origin, module_ext("rules_rust", "crate"));
        assert_eq!(id.path, "_bs.out_dir");
        assert_eq!(id.to_string(), "@rules_rust+crate//_bs.out_dir");
    }

    #[test]
    fn crate_universe_repositories_collapse_across_crates_and_versions() {
        // Dropping the repository field is what makes these equal; the repository
        // name carries both a project-chosen prefix and a dependency version.
        let anyhow = ProgramId::of(
            "bazel-out/k8-fastbuild/bin/external/rules_rust++crate+crates__anyhow-1.0.104/_bs.out_dir",
        );
        let libc = ProgramId::of(
            "bazel-out/k8-fastbuild/bin/external/rules_rust++crate+crates__libc-0.2.189/_bs.out_dir",
        );
        assert_eq!(anyhow, libc);
    }

    #[test]
    fn builtin_repositories_have_no_version_field() {
        // `bazel_tools` and `platforms` carry no `+` suffix, so their extension
        // repositories have three fields rather than four.
        assert_eq!(
            ProgramId::of("external/bazel_tools+winsdk_configure+local_config_winsdk/bin/x").origin,
            module_ext("bazel_tools", "winsdk_configure")
        );
        assert_eq!(
            ProgramId::of(
                "external/platforms+host_platform+host_platform/bin/x"
            )
            .origin,
            module_ext("platforms", "host_platform")
        );
        assert_eq!(
            ProgramId::of("external/bazel_tools/tools/cpp/x").origin,
            module("bazel_tools")
        );
    }

    #[test]
    fn module_version_field_is_dropped() {
        // multiple_version_override populates the version; two versions of one
        // module must not be two different programs.
        let unversioned = ProgramId::of("external/rules_rust+/util/x");
        let versioned = ProgramId::of("external/rules_rust+1.2.3/util/x");
        assert_eq!(unversioned, versioned);
        assert_eq!(versioned.origin, module("rules_rust"));
    }

    #[test]
    fn the_older_tilde_separator_is_understood() {
        // Bazel 6/7.0 spelling, version included.
        assert_eq!(
            ProgramId::of("external/rules_rust~0.40.0/util/x").origin,
            module("rules_rust")
        );
        // Bazel 7.1 spelling, version dropped.
        assert_eq!(
            ProgramId::of("external/rules_rust~/util/x").origin,
            module("rules_rust")
        );
        // Bazel 7 extension repository.
        assert_eq!(
            ProgramId::of("external/rules_rust~~crate~crates__anyhow-1.0.104/_bs.out_dir").origin,
            module_ext("rules_rust", "crate")
        );
    }

    #[test]
    fn the_same_program_matches_across_bazel_versions() {
        // The property that motivates the whole module.
        let ids = [
            "external/rules_rust~0.40.0/util/process_wrapper/process_wrapper",
            "external/rules_rust~/util/process_wrapper/process_wrapper",
            "external/rules_rust+/util/process_wrapper/process_wrapper",
            "external/rules_rust/util/process_wrapper/process_wrapper", // WORKSPACE
        ]
        .map(ProgramId::of);
        assert!(ids.iter().all(|id| *id == ids[0]), "{ids:?}");
    }

    #[test]
    fn main_repository_is_recognized_by_both_spellings() {
        assert_eq!(
            ProgramId::of("external/_main/src/tools/gen").origin,
            Origin::Main { extension: None }
        );
        // An extension defined by the main module leaves the module field empty.
        assert_eq!(
            ProgramId::of("external/_main+myext+myrepo/bin/tool").origin,
            Origin::Main {
                extension: Some("myext".to_owned()),
            }
        );
        assert_eq!(
            ProgramId::of("external/+myext+myrepo/bin/tool").origin,
            Origin::Main {
                extension: Some("myext".to_owned()),
            }
        );
    }

    #[test]
    fn main_repository_extension_renders_with_an_empty_module() {
        let id = ProgramId::of("external/+myext+myrepo/bin/tool");
        assert_eq!(id.to_string(), "@+myext//bin/tool");
    }

    #[test]
    fn runfiles_paths_resolve_through_the_repository_segment() {
        let id = ProgramId::of(
            "bazel-out/k8-fastbuild/bin/ahab.runfiles/_main/ahab",
        );
        assert_eq!(id.origin, Origin::Main { extension: None });
        assert_eq!(id.path, "ahab");

        let id = ProgramId::of(
            "ahab.runfiles/rules_rust+/util/process_wrapper/process_wrapper",
        );
        assert_eq!(id.origin, module("rules_rust"));
        assert_eq!(id.path, "util/process_wrapper/process_wrapper");
    }

    #[test]
    fn the_innermost_runfiles_tree_wins() {
        let id =
            ProgramId::of("a.runfiles/_main/b.runfiles/rules_rust+/util/x");
        assert_eq!(id.origin, module("rules_rust"));
        assert_eq!(id.path, "util/x");
    }

    #[test]
    fn a_segment_merely_containing_runfiles_is_not_a_runfiles_tree() {
        // `.runfiles` must end the segment.
        let id = ProgramId::of(
            "bazel-out/k8-fastbuild/bin/x.runfilesy/_main/tool",
        );
        assert_eq!(id.origin, Origin::Main { extension: None });
        assert_eq!(id.path, "x.runfilesy/_main/tool");
    }

    #[test]
    fn runfiles_relative_external_paths_are_understood() {
        // Written relative to a runfiles directory rather than the execroot.
        let id = ProgramId::of(
            "../rules_rust+/util/process_wrapper/process_wrapper",
        );
        assert_eq!(id.origin, module("rules_rust"));
        assert_eq!(id.path, "util/process_wrapper/process_wrapper");
    }

    #[test]
    fn a_repository_with_no_tail_is_not_split() {
        // `external/<repo>` alone names no program; leave it in the main repo
        // rather than inventing an empty path.
        let id = ProgramId::of("external/rules_rust+");
        assert_eq!(id.origin, Origin::Main { extension: None });
        assert_eq!(id.path, "external/rules_rust+");
    }

    // ---- naming a program in source ----

    #[test]
    fn ids_are_usable_as_map_keys() {
        use std::collections::HashMap;
        let mut specs = HashMap::new();
        specs.insert(
            ProgramId::of(
                "external/rules_rust+/util/process_wrapper/process_wrapper",
            ),
            "wrapper",
        );
        // A different configuration and Bazel version, same program.
        let looked_up = specs.get(&ProgramId::of(
            "bazel-out/k8-opt-exec/bin/external/rules_rust~/util/process_wrapper/process_wrapper",
        ));
        assert_eq!(looked_up, Some(&"wrapper"));
    }
}
