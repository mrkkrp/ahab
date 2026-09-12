//! Stable identification of the programs that build actions run.
//!
//! A [`ReproducibilitySpec`](super::ReproducibilitySpec) describes one
//! program, so specs must be keyed by something that names a program and
//! only that program, consistently across builds. [`ProgramId`] is that
//! key: an action's `argv[0]` with everything unstable normalized away,
//! leaving only what the tool's own author controls.
//!
//! The rest of these docs record empirical facts about Bazel that are easy
//! to get wrong and that shift between releases.
//!
//! # Why not the obvious keys
//!
//! * **The executable's base name** is not unique: two rulesets can ship
//!   unrelated tools called `process_wrapper`.
//! * **The full exec path** is unique but wildly unstable.
//! * **The owning target's label** is not reachable—`analysis_v2.proto`'s
//!   `Artifact` carries no owner, so recovering one means finding the action
//!   that generates the executable, which fails for prebuilt and system
//!   tools. It also embeds the same canonical repository name, so it would
//!   need exactly the normalization below anyway.
//!
//! # The stability gradient
//!
//! Reading a path such as
//! `bazel-out/k8-opt-exec/bin/external/rules_rust++crate+crates__anyhow-1.0.104/foo`
//! left to right, stability *increases*:
//!
//! 1. **`bazel-out/<configuration>/<root>`**—varies with CPU, compilation
//!    mode and exec-vs-target, and Bazel 8+ may append `-ST-<hash>`. Only
//!    the three-segment shape is fixed, so that is all
//!    [`strip_output_prefix`] relies on.
//! 2. **The separator and version fields**—see the table below.
//! 3. **The generated repository name** (`crates__anyhow-1.0.104`)—chosen by
//!    the analyzed project, version- and platform-bearing. Dropped.
//! 4. **Module and extension names**—fixed by the tool's author. Kept.
//! 5. **The package and target tail**—the ruleset's own source layout, which
//!    moves only when a spec should be revisited anyway. Kept.
//!
//! # Canonical repository names
//!
//! Bazel's canonical repository names have changed shape repeatedly:
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
//! The three-field shape exists because built-in repositories carry no
//! version suffix, which shifts every later field left. Rather than
//! special-case them, [`decode_repo`] relies on the invariant holding across
//! all four shapes: the first field is the module, the last two (when there
//! are three or more) are the extension and the repository it generated, and
//! whatever sits between is a version. Splitting is unambiguous because
//! repository names are restricted to `[A-Za-z0-9._-]`.
//!
//! # What survives normalization
//!
//! Only the module and extension names, being the only fields outside the
//! analyzed project's control:
//!
//! * **Module name**—from `module(name = …)` in the dependency's own
//!   `MODULE.bazel`, unaffected by a `bazel_dep`'s `repo_name`.
//! * **Extension name**—the exported symbol in the defining `.bzl`, not the
//!   variable a consumer binds at the `use_extension` call site. Witness
//!   `bazel_lib++toolchains+coreutils_linux_amd64`, where `toolchains` is
//!   aspect_bazel_lib's export name though this project never mentions it.
//!
//! The other two are dropped:
//!
//! * **Module version**—empty in all 247 four-field names surveyed, being
//!   populated only under `multiple_version_override`. Two versions of a
//!   tool behaving differently is a question about flags, not identity.
//! * **Generated repository name**—braids together names the consuming
//!   project chose, dependency versions and platform triples, none of them
//!   knowable to whoever writes a spec.
//!
//! So a spec never names a version, a platform triple or a separator, which
//! is what makes exact matching enough.
//!
//! # Known consequence: extension granularity
//!
//! Every repository one extension generated shares an identity: each
//! crate_universe build script normalizes to `@rules_rust+crate//…`, folding
//! ~90 surveyed repositories into one key. Deliberate—"a Cargo build script"
//! is the unit we have knowledge about—but it forecloses singling one out.
//! The extension point would be an optional discriminator on [`Origin`],
//! backwards compatible with specs written against the coarser key.

use serde::{Deserialize, Serialize};

use std::fmt;
use std::str::FromStr;

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
    /// An external Bazel module, named as in the registry—never by the
    /// apparent name a `bazel_dep` may have bound it to.
    Module {
        /// The module name, i.e. its `module(name = …)`.
        name: String,
        /// The module extension that generated the repository, if any.
        extension: Option<String>,
    },
    /// Outside the execution root: an absolute path to a host tool, or a
    /// bare command name resolved through `PATH`. Either way the program is
    /// not part of the build, which is itself a hermeticity signal.
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

/// Constructors for *naming* a program in source, as [`super::library`] does.
impl ProgramId {
    /// A program in the main repository, e.g. `//src/tools/gen`.
    pub fn main(path: &str) -> ProgramId {
        ProgramId {
            origin: Origin::Main { extension: None },
            path: path.to_owned(),
        }
    }

    /// A program in a Bazel module's own repository, e.g.
    /// `@rules_rust//util/process_wrapper/process_wrapper`, named by the
    /// module's registry name.
    pub fn module(module: &str, path: &str) -> ProgramId {
        ProgramId {
            origin: Origin::Module {
                name: module.to_owned(),
                extension: None,
            },
            path: path.to_owned(),
        }
    }

    /// A program in a repository generated by an extension the main
    /// repository itself uses, e.g. `@+typescript//tsc_/tsc`.
    pub fn main_extension(extension: &str, path: &str) -> ProgramId {
        ProgramId {
            origin: Origin::Main {
                extension: Some(extension.to_owned()),
            },
            path: path.to_owned(),
        }
    }

    /// A program in a repository generated by one of a module's extensions,
    /// e.g. `@llvm+llvm_toolchain_minimal//bin/clang`, named by the
    /// extension's exported symbol in the module that defines it.
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
    /// Identify the program an action runs from its `argv[0]`.
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

/// Parse the form [`Display`](fmt::Display) produces, so a program can be
/// named in a configuration file the way it is named in a report.
impl FromStr for ProgramId {
    type Err = String;

    fn from_str(text: &str) -> Result<ProgramId, String> {
        let Some(rest) = text.strip_prefix('@') else {
            return Ok(match text.strip_prefix("//") {
                Some(path) => ProgramId::main(path),
                None => ProgramId::of(text),
            });
        };

        let Some((repo, path)) = rest.split_once("//") else {
            return Err(format!(
                "{text:?} names a repository but no program: expected \
                 `@repository//path`"
            ));
        };
        if path.is_empty() {
            return Err(format!("{text:?} has no program after `//`"));
        }

        let (module, extension) = match repo.split_once('+') {
            Some((module, extension)) => (module, Some(extension)),
            None => (repo, None),
        };
        if extension.is_some_and(str::is_empty) {
            return Err(format!("{text:?} has an empty extension name"));
        }

        Ok(ProgramId {
            origin: match (module.is_empty(), extension) {
                (true, extension) => Origin::Main {
                    extension: extension.map(ToOwned::to_owned),
                },
                (false, extension) => Origin::Module {
                    name: module.to_owned(),
                    extension: extension.map(ToOwned::to_owned),
                },
            },
            path: path.to_owned(),
        })
    }
}

/// Render an id in a Bazel-like label form: `@rules_rust//util/process_wrapper`,
/// `@rules_rust+crate//_bs.out_dir`, `//src/tools/gen`, `/usr/bin/gcc`.
///
/// The spelling mirrors Bazel's own encoding minus the dropped fields, so a
/// main-repository extension renders with an empty module (`@+myext//…`).
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
/// module version and the generated repository name. Both the Bazel 8+ `+`
/// separator and the older `~` are accepted; see the module docs.
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

    fn module(name: &str) -> Origin {
        Origin::Module {
            name: name.to_owned(),
            extension: None,
        }
    }

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
        assert_eq!(id.path, "/usr/bin/gcc");
        assert_eq!(id.to_string(), "/usr/bin/gcc");
    }

    #[test]
    fn bare_command_names_are_system_tools() {
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
        let id = ProgramId::of("bazel-out/k8-fastbuild");
        assert_eq!(id.origin, Origin::Main { extension: None });
        assert_eq!(id.path, "bazel-out/k8-fastbuild");
    }

    #[test]
    fn module_repository_normalizes_to_its_module_name() {
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
        let unversioned = ProgramId::of("external/rules_rust+/util/x");
        let versioned = ProgramId::of("external/rules_rust+1.2.3/util/x");
        assert_eq!(unversioned, versioned);
        assert_eq!(versioned.origin, module("rules_rust"));
    }

    #[test]
    fn the_older_tilde_separator_is_understood() {
        assert_eq!(
            ProgramId::of("external/rules_rust~0.40.0/util/x").origin,
            module("rules_rust")
        );
        assert_eq!(
            ProgramId::of("external/rules_rust~/util/x").origin,
            module("rules_rust")
        );
        assert_eq!(
            ProgramId::of("external/rules_rust~~crate~crates__anyhow-1.0.104/_bs.out_dir").origin,
            module_ext("rules_rust", "crate")
        );
    }

    #[test]
    fn the_same_program_matches_across_bazel_versions() {
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
        let id = ProgramId::of(
            "bazel-out/k8-fastbuild/bin/x.runfilesy/_main/tool",
        );
        assert_eq!(id.origin, Origin::Main { extension: None });
        assert_eq!(id.path, "x.runfilesy/_main/tool");
    }

    #[test]
    fn runfiles_relative_external_paths_are_understood() {
        let id = ProgramId::of(
            "../rules_rust+/util/process_wrapper/process_wrapper",
        );
        assert_eq!(id.origin, module("rules_rust"));
        assert_eq!(id.path, "util/process_wrapper/process_wrapper");
    }

    #[test]
    fn a_repository_with_no_tail_is_not_split() {
        let id = ProgramId::of("external/rules_rust+");
        assert_eq!(id.origin, Origin::Main { extension: None });
        assert_eq!(id.path, "external/rules_rust+");
    }

    #[test]
    fn parsing_inverts_rendering() {
        for id in [
            ProgramId::module("rules_rust", "util/process_wrapper/pw"),
            ProgramId::extension(
                "llvm",
                "llvm_toolchain_minimal",
                "bin/cc",
            ),
            ProgramId::main("src/tools/gen"),
            ProgramId::of("external/+myext+myrepo/bin/tool"),
            ProgramId::of("/usr/bin/gcc"),
            ProgramId::of("gcc"),
        ] {
            let rendered = id.to_string();
            assert_eq!(
                rendered.parse::<ProgramId>().as_ref(),
                Ok(&id),
                "{rendered}",
            );
        }
    }

    #[test]
    fn a_repository_without_a_program_is_rejected() {
        for bad in ["@rules_rust", "@rules_rust//", "@rules_rust+//x"] {
            assert!(bad.parse::<ProgramId>().is_err(), "{bad}");
        }
    }

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
        let looked_up = specs.get(&ProgramId::of(
            "bazel-out/k8-opt-exec/bin/external/rules_rust~/util/process_wrapper/process_wrapper",
        ));
        assert_eq!(looked_up, Some(&"wrapper"));
    }
}
