//! Pure hermeticity checks over a decoded `analysis.ActionGraphContainer`.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use analysis_v2_proto::analysis::{
    Action, ActionGraphContainer, DepSetOfFiles, PathFragment,
};
use serde::{Deserialize, Serialize};

use crate::param_files::{
    ArgSource, Sourced, analyzable_strings, expanded_command_line,
};
use crate::reproducibility_spec::{
    Conformance, Unmet,
    library::Library,
    program_id::{Origin, ProgramId},
};
use crate::terminal_color::Palette;

mod absolute_paths;

/// The `PATH` every action is required to use.
const EXPECTED_PATH: &str = "/bin:/usr/bin:/usr/local/bin";

/// The action responsible for a violation.
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
pub(crate) struct ActionRef {
    /// E.g. `CppCompile`; may be empty.
    pub mnemonic: String,
    /// E.g. `//foo:bar`.
    pub target: String,
}

impl ActionRef {
    /// An id the dump does not describe yields a placeholder rather than a
    /// meaningless number.
    fn of(action: &Action, targets: &HashMap<u32, &str>) -> Self {
        ActionRef {
            mnemonic: action.mnemonic.clone(),
            target: targets.get(&action.target_id).map_or_else(
                || "<unknown target>".to_owned(),
                |label| (*label).to_owned(),
            ),
        }
    }
}

impl std::fmt::Display for ActionRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.mnemonic.is_empty() {
            write!(f, "action for target {}", self.target)
        } else {
            write!(f, "{} action for target {}", self.mnemonic, self.target)
        }
    }
}

/// Index a container's targets by id. Valid only for this container, so it
/// must be applied before a violation leaves the analysis.
fn target_labels(container: &ActionGraphContainer) -> HashMap<u32, &str> {
    container
        .targets
        .iter()
        .map(|target| (target.id, target.label.as_str()))
        .collect()
}

/// Which piece of the invoking environment a leaked sentinel stood in for.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EnvSource {
    User,
    Hostname,
}

impl EnvSource {
    fn as_str(self) -> &'static str {
        match self {
            EnvSource::User => "USER",
            EnvSource::Hostname => "HOSTNAME",
        }
    }
}

/// Where in an action something Ahab flagged was found.
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
#[serde(tag = "location", rename_all = "snake_case")]
pub(crate) enum LeakSite {
    Argument {
        value: String,
    },
    /// Inside a param file line, reported separately because the argument
    /// is only a reference and quoting it would not show the text.
    ParamFile {
        exec_path: String,
        /// The line the finding was in.
        value: String,
    },
    EnvVar {
        key: String,
        value: String,
    },
}

impl LeakSite {
    /// The site for a scanned string, from its provenance.
    fn of(sourced: Sourced<'_>) -> LeakSite {
        match sourced.source {
            ArgSource::CommandLine => LeakSite::Argument {
                value: sourced.value.to_owned(),
            },
            ArgSource::ParamFile(exec_path) => LeakSite::ParamFile {
                exec_path: exec_path.to_owned(),
                value: sourced.value.to_owned(),
            },
        }
    }

    /// How a report names the place, and the text found there.
    fn describe(&self) -> (String, &str) {
        match self {
            LeakSite::Argument { value } => {
                ("an argument".to_owned(), value.as_str())
            }
            LeakSite::ParamFile { exec_path, value } => {
                (format!("param file {exec_path:?}"), value.as_str())
            }
            LeakSite::EnvVar { key, value } => {
                (format!("environment variable {key:?}"), value.as_str())
            }
        }
    }
}

/// How the analysis reached the program it judged: the wrappers it sat
/// behind, outermost first, and the synonym whose spec answered for it.
/// Without them a verdict would read as a claim about `argv[0]`.
fn provenance(
    wrappers: &[ProgramId],
    synonym: Option<&ProgramId>,
    palette: Palette,
) -> String {
    let mut parts = Vec::new();
    if !wrappers.is_empty() {
        let names: Vec<String> = wrappers
            .iter()
            .map(|w| palette.finding(&format!("{w:?}", w = w.to_string())))
            .collect();
        parts.push(format!("wrapped by {}", names.join(", then ")));
    }
    if let Some(synonym) = synonym {
        parts.push(format!(
            "spec from synonym {}",
            palette.finding(&format!("{:?}", synonym.to_string())),
        ));
    }
    if parts.is_empty() {
        return String::new();
    }
    format!(" ({})", parts.join(", "))
}

/// A single violation, recording everything the check observed. See
/// [`Violation::render`].
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
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Violation {
    /// A sentinel leaked into an action.
    EnvironmentLeak {
        action: ActionRef,
        source: EnvSource,
        sentinel: String,
        site: LeakSite,
    },
    /// An action set `PATH` to something other than [`EXPECTED_PATH`].
    BadPath { action: ActionRef, actual: String },
    /// An action declares it cannot run like an ordinary hermetic one.
    ExecutionRequirement {
        action: ActionRef,
        /// As declared: `no-sandbox`, `requires-network`, and so on.
        requirement: String,
    },
    /// An action referenced a `/`-rooted run.
    AbsolutePath {
        action: ActionRef,
        path: String,
        /// Where it appeared, with the surrounding text.
        site: LeakSite,
    },
    /// An action runs a program from outside the build, named by an
    /// absolute path or by a bare name left to `PATH`.
    SystemProgram {
        action: ActionRef,
        program: ProgramId,
        wrappers: Vec<ProgramId>,
    },
    /// An action runs a program that is part of the build, but that Bazel
    /// produced by inspecting the machine.
    HostDerivedProgram {
        action: ActionRef,
        program: ProgramId,
        wrappers: Vec<ProgramId>,
    },
    /// An action runs a program with no reproducibility spec. Reported
    /// rather than passed over: silence is not approval.
    UnknownProgram {
        action: ActionRef,
        program: ProgramId,
        wrappers: Vec<ProgramId>,
    },
    /// An action runs a program that is never reproducible.
    NeverReproducible {
        action: ActionRef,
        program: ProgramId,
        wrappers: Vec<ProgramId>,
        synonym: Option<ProgramId>,
    },
    /// An action reads one of Bazel's workspace status files, so its output
    /// depends on values gathered about the build. The contents are up to
    /// the project, so only the file is named.
    WorkspaceStatus { action: ActionRef, path: String },
    /// An action runs a conditionally-reproducible program, and this
    /// invocation does not meet the conditions.
    ConditionalReproducibility {
        action: ActionRef,
        program: ProgramId,
        wrappers: Vec<ProgramId>,
        synonym: Option<ProgramId>,
        /// The clauses it failed, in the spec's own words.
        unmet: Vec<Unmet>,
    },
}

/// A violation flattened into the dimensions an exception can match, with
/// absent fields left as `None`. Producing it is one exhaustive `match`, so
/// a variant added later cannot be quietly left out.
pub(crate) struct Facets<'a> {
    /// The variant's serialization tag, e.g. `absolute_path`.
    pub kind: &'static str,
    pub action: &'a ActionRef,
    /// The program judged, for the variants that judge one.
    pub program: Option<&'a ProgramId>,
    /// The absolute path found, for [`Violation::AbsolutePath`].
    pub path: Option<&'a str>,
    /// The offending `PATH`, for [`Violation::BadPath`].
    pub actual: Option<&'a str>,
    /// The declared requirement, for [`Violation::ExecutionRequirement`].
    pub requirement: Option<&'a str>,
    /// The environment source, for [`Violation::EnvironmentLeak`].
    pub source: Option<EnvSource>,
    /// Where in the action it was found, for the variants that record it.
    pub site: Option<&'a LeakSite>,
}

impl Violation {
    pub(crate) fn facets(&self) -> Facets<'_> {
        let bare = |kind, action| Facets {
            kind,
            action,
            program: None,
            path: None,
            actual: None,
            requirement: None,
            source: None,
            site: None,
        };

        match self {
            Violation::EnvironmentLeak {
                action,
                source,
                sentinel: _,
                site,
            } => Facets {
                source: Some(*source),
                site: Some(site),
                ..bare("environment_leak", action)
            },
            Violation::BadPath { action, actual } => Facets {
                actual: Some(actual),
                ..bare("bad_path", action)
            },
            Violation::ExecutionRequirement {
                action,
                requirement,
            } => Facets {
                requirement: Some(requirement),
                ..bare("execution_requirement", action)
            },
            Violation::WorkspaceStatus { action, path } => Facets {
                path: Some(path),
                ..bare("workspace_status", action)
            },
            Violation::AbsolutePath { action, path, site } => Facets {
                path: Some(path),
                site: Some(site),
                ..bare("absolute_path", action)
            },
            Violation::SystemProgram {
                action,
                program,
                wrappers: _,
            } => Facets {
                program: Some(program),
                ..bare("system_program", action)
            },
            Violation::HostDerivedProgram {
                action,
                program,
                wrappers: _,
            } => Facets {
                program: Some(program),
                ..bare("host_derived_program", action)
            },
            Violation::UnknownProgram {
                action,
                program,
                wrappers: _,
            } => Facets {
                program: Some(program),
                ..bare("unknown_program", action)
            },
            Violation::NeverReproducible {
                action,
                program,
                wrappers: _,
                synonym: _,
            } => Facets {
                program: Some(program),
                ..bare("never_reproducible", action)
            },
            Violation::ConditionalReproducibility {
                action,
                program,
                wrappers: _,
                synonym: _,
                unmet: _,
            } => Facets {
                program: Some(program),
                ..bare("conditional_reproducibility", action)
            },
        }
    }

    /// Render as one human-readable line.
    pub(crate) fn render(&self, palette: Palette) -> String {
        let hermeticity = "hermeticity violation";
        let reproducibility = "reproducibility violation";
        let unknown = "reproducibility unknown";
        let at = |action: &ActionRef| palette.action(&action.to_string());
        let found = |text: &str| palette.finding(text);

        match self {
            Violation::EnvironmentLeak {
                action,
                source,
                sentinel: _,
                site,
            } => {
                let (where_, text) = site.describe();
                format!(
                    "{hermeticity}: {} leaked into {where_} of {}: {text}",
                    found(source.as_str()),
                    at(action),
                )
            }
            Violation::BadPath { action, actual } => format!(
                "{hermeticity}: {} sets PATH to {}, expected {EXPECTED_PATH:?}",
                at(action),
                found(&format!("{actual:?}")),
            ),
            Violation::ExecutionRequirement {
                action,
                requirement,
            } => format!(
                "{hermeticity}: {} declares {}, so the build itself says \
                 it cannot run like an ordinary action",
                at(action),
                found(&format!("{requirement:?}")),
            ),
            Violation::WorkspaceStatus { action, path } => {
                let why = if path.ends_with(VOLATILE_STATUS) {
                    "which carries generated and potentially volatile data \
                    which Bazel deliberately does not invalidate on"
                } else {
                    "which carries generated and potentially volatile data"
                };
                format!(
                    "{hermeticity}: {} reads {}, {why}",
                    at(action),
                    found(&format!("{path:?}")),
                )
            }
            Violation::AbsolutePath { action, path, site } => {
                let (where_, text) = site.describe();
                format!(
                    "{hermeticity}: {} references absolute path {} in \
                     {where_}: {text}",
                    at(action),
                    found(&format!("{path:?}")),
                )
            }
            Violation::SystemProgram {
                action,
                program,
                wrappers,
            } => format!(
                "{hermeticity}: {} runs program {}{}, which comes from \
                 outside the build",
                at(action),
                found(&format!("{:?}", program.to_string())),
                provenance(wrappers, None, palette),
            ),
            Violation::HostDerivedProgram {
                action,
                program,
                wrappers,
            } => format!(
                "{hermeticity}: {} runs program {}{}, which does its \
                 work with tools this machine provides rather than ones \
                 the build declares",
                at(action),
                found(&format!("{:?}", program.to_string())),
                provenance(wrappers, None, palette),
            ),
            Violation::UnknownProgram {
                action,
                program,
                wrappers,
            } => format!(
                "{unknown}: {} runs program {}{}, which has no known \
                 reproducibility spec",
                at(action),
                found(&format!("{:?}", program.to_string())),
                provenance(wrappers, None, palette),
            ),
            Violation::NeverReproducible {
                action,
                program,
                wrappers,
                synonym,
            } => format!(
                "{reproducibility}: {} runs program {}{}, which is never \
                 reproducible",
                at(action),
                found(&format!("{:?}", program.to_string())),
                provenance(wrappers, synonym.as_ref(), palette),
            ),
            Violation::ConditionalReproducibility {
                action,
                program,
                wrappers,
                synonym,
                unmet,
            } => {
                let reasons: Vec<String> = unmet
                    .iter()
                    .map(|clause| {
                        let names = |set: &BTreeSet<String>| {
                            set.iter()
                                .map(String::as_str)
                                .collect::<Vec<_>>()
                                .join(" ")
                        };
                        let evidence = if clause.present.is_empty() {
                            format!(
                                "but none of {} was passed",
                                names(&clause.any_of)
                            )
                        } else {
                            names(&clause.present)
                        };
                        format!("{}, {}", clause.because, evidence)
                    })
                    .collect();
                format!(
                    "{reproducibility}: {} runs program {}{} \
                     non-reproducibly: {}",
                    at(action),
                    found(&format!("{:?}", program.to_string())),
                    provenance(wrappers, synonym.as_ref(), palette),
                    reasons.join("; "),
                )
            }
        }
    }
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.render(Palette::plain()))
    }
}

/// Every distinct violation in `container` with its number of occurrences,
/// in a deterministic order.
pub(crate) fn check_all(
    container: &ActionGraphContainer,
    user: &str,
    hostname: &str,
    library: &Library,
) -> BTreeMap<Violation, usize> {
    let mut violations = check_environment_leaks(container, user, hostname);
    violations.extend(check_path(container));
    violations.extend(absolute_paths::check(container, library));
    violations.extend(check_execution_requirements(container));
    violations.extend(check_workspace_status(container));
    violations.extend(check_reproducibility(container, library));

    let mut counted = BTreeMap::new();
    for violation in violations {
        *counted.entry(violation).or_insert(0) += 1;
    }
    counted
}

/// The workspace status files, relative to the output path.
const STABLE_STATUS: &str = "stable-status.txt";
const VOLATILE_STATUS: &str = "volatile-status.txt";

/// Reconstruct an artifact's execution-root-relative path. The proto stores
/// paths as a tree of segments, so this walks up to the root and reverses,
/// bounded by the fragment count in case the graph describes a cycle.
fn artifact_path(
    id: u32,
    fragments: &HashMap<u32, &PathFragment>,
) -> Option<String> {
    let mut segments = Vec::new();
    let mut at = Some(id);
    while let Some(current) = at {
        let fragment = fragments.get(&current)?;
        segments.push(fragment.label.as_str());
        at = (fragment.parent_id != 0).then_some(fragment.parent_id);
        if segments.len() > fragments.len() {
            return None;
        }
    }
    segments.reverse();
    Some(segments.join("/"))
}

/// For every dep set, which of `wanted` it reaches. Answered once for the
/// whole graph: dep sets are shared and deeply nested, so walking them per
/// action re-treads the same ground thousands of times.
fn reachable_from_each(
    sets: &HashMap<u32, &DepSetOfFiles>,
    wanted: &HashMap<u32, String>,
) -> HashMap<u32, BTreeSet<u32>> {
    let mut found: HashMap<u32, BTreeSet<u32>> = HashMap::new();

    for &root in sets.keys() {
        // An explicit stack rather than recursion: these nest as deeply as
        // the build does. `open` holds the sets on the current path, so a
        // cycle contributes nothing instead of looping forever.
        let mut open: BTreeSet<u32> = BTreeSet::new();
        let mut stack = vec![(root, false)];

        while let Some((id, ready)) = stack.pop() {
            if found.contains_key(&id) {
                continue;
            }
            let Some(set) = sets.get(&id) else {
                found.insert(id, BTreeSet::new());
                continue;
            };
            if ready {
                let mut reached: BTreeSet<u32> = set
                    .direct_artifact_ids
                    .iter()
                    .filter(|artifact| wanted.contains_key(artifact))
                    .copied()
                    .collect();
                for child in &set.transitive_dep_set_ids {
                    if let Some(sub) = found.get(child) {
                        reached.extend(sub.iter().copied());
                    }
                }
                open.remove(&id);
                found.insert(id, reached);
            } else {
                open.insert(id);
                stack.push((id, true));
                for &child in &set.transitive_dep_set_ids {
                    if !found.contains_key(&child) && !open.contains(&child)
                    {
                        stack.push((child, false));
                    }
                }
            }
        }
    }

    found
}

/// Every action that reads Bazel's workspace status files.
fn check_workspace_status(
    container: &ActionGraphContainer,
) -> Vec<Violation> {
    let mut violations = Vec::new();
    let targets = target_labels(container);

    let fragments: HashMap<u32, &PathFragment> = container
        .path_fragments
        .iter()
        .map(|fragment| (fragment.id, fragment))
        .collect();
    let sets: HashMap<u32, &DepSetOfFiles> = container
        .dep_set_of_files
        .iter()
        .map(|set| (set.id, set))
        .collect();
    let paths: HashMap<u32, String> = container
        .artifacts
        .iter()
        .filter(|artifact| {
            fragments
                .get(&artifact.path_fragment_id)
                .is_some_and(|leaf| {
                    leaf.label == STABLE_STATUS
                        || leaf.label == VOLATILE_STATUS
                })
        })
        .filter_map(|artifact| {
            let path =
                artifact_path(artifact.path_fragment_id, &fragments)?;
            Some((artifact.id, path))
        })
        .collect();

    if paths.is_empty() {
        return violations;
    }

    let reached = reachable_from_each(&sets, &paths);

    for action in &container.actions {
        let found: BTreeSet<u32> = action
            .input_dep_set_ids
            .iter()
            .filter_map(|id| reached.get(id))
            .flat_map(|ids| ids.iter().copied())
            .collect();
        for id in found {
            if let Some(path) = paths.get(&id) {
                violations.push(Violation::WorkspaceStatus {
                    action: ActionRef::of(action, &targets),
                    path: path.clone(),
                });
            }
        }
    }

    violations
}

/// Execution requirements that say an action is not an ordinary hermetic
/// one.
const NON_HERMETIC_REQUIREMENTS: &[(&str, &str)] = &[
    (
        "requires-network",
        "the action reaches the network, so its output can depend on \
         anything out there",
    ),
    (
        "no-sandbox",
        "the action sees the whole filesystem, so it can read inputs it \
         never declared",
    ),
    (
        "local",
        "the action sees the whole filesystem, so it can read inputs it \
         never declared",
    ),
];

/// Whether a declared execution requirement is one Ahab reports.
fn is_non_hermetic_requirement(key: &str) -> bool {
    NON_HERMETIC_REQUIREMENTS
        .iter()
        .any(|(requirement, _)| *requirement == key)
}

/// One [`Violation`] per execution requirement meaning an action cannot run
/// like an ordinary hermetic one.
fn check_execution_requirements(
    container: &ActionGraphContainer,
) -> Vec<Violation> {
    let mut violations = Vec::new();
    let targets = target_labels(container);

    for action in &container.actions {
        for kv in &action.execution_info {
            if is_non_hermetic_requirement(&kv.key) {
                violations.push(Violation::ExecutionRequirement {
                    action: ActionRef::of(action, &targets),
                    requirement: kv.key.clone(),
                });
            }
        }
    }

    violations
}

/// One [`Violation`] per sentinel leaked into an action's command line, its
/// param files or its environment values.
fn check_environment_leaks(
    container: &ActionGraphContainer,
    user: &str,
    hostname: &str,
) -> Vec<Violation> {
    let mut violations = Vec::new();
    let targets = target_labels(container);

    for action in &container.actions {
        let scanned = analyzable_strings(action);

        for (sentinel, source) in
            [(user, EnvSource::User), (hostname, EnvSource::Hostname)]
        {
            for sourced in &scanned {
                if sourced.value.contains(sentinel) {
                    violations.push(Violation::EnvironmentLeak {
                        action: ActionRef::of(action, &targets),
                        source,
                        sentinel: sentinel.to_owned(),
                        site: LeakSite::of(*sourced),
                    });
                }
            }

            for kv in &action.environment_variables {
                if kv.value.contains(sentinel) {
                    violations.push(Violation::EnvironmentLeak {
                        action: ActionRef::of(action, &targets),
                        source,
                        sentinel: sentinel.to_owned(),
                        site: LeakSite::EnvVar {
                            key: kv.key.clone(),
                            value: kv.value.clone(),
                        },
                    });
                }
            }
        }
    }

    violations
}

/// One [`Violation`] per action setting `PATH` to anything but
/// [`EXPECTED_PATH`].
fn check_path(container: &ActionGraphContainer) -> Vec<Violation> {
    let mut violations = Vec::new();
    let targets = target_labels(container);

    for action in &container.actions {
        for kv in &action.environment_variables {
            if kv.key == "PATH" && kv.value != EXPECTED_PATH {
                violations.push(Violation::BadPath {
                    action: ActionRef::of(action, &targets),
                    actual: kv.value.clone(),
                });
            }
        }
    }

    violations
}

/// Each action's program against the library of specs.
fn check_reproducibility(
    container: &ActionGraphContainer,
    library: &Library,
) -> Vec<Violation> {
    let mut violations = Vec::new();
    let targets = target_labels(container);

    for action in &container.actions {
        let command_line = expanded_command_line(action);
        let Some((executable, args)) = command_line.split_first() else {
            continue;
        };

        let resolved = library.resolve(
            ProgramId::of(executable.value),
            args.iter().map(|sourced| sourced.value).collect(),
        );
        let action_ref = || ActionRef::of(action, &targets);
        let wrappers = resolved.wrappers.clone();

        // Reported as a hermeticity failure rather than as a program we
        // lack a spec for: no spec could make it acceptable.
        if resolved.program.origin == Origin::System {
            violations.push(Violation::SystemProgram {
                action: action_ref(),
                program: resolved.program,
                wrappers,
            });
            continue;
        }

        let synonym = resolved.synonym().cloned();
        let Some((_, spec)) = resolved.spec else {
            violations.push(Violation::UnknownProgram {
                action: action_ref(),
                program: resolved.program,
                wrappers,
            });
            continue;
        };
        match spec.assess(resolved.args.iter().copied()) {
            Conformance::Reproducible => {}
            Conformance::HostDerived => {
                violations.push(Violation::HostDerivedProgram {
                    action: action_ref(),
                    program: resolved.program,
                    wrappers,
                });
            }
            Conformance::NeverReproducible => {
                violations.push(Violation::NeverReproducible {
                    action: action_ref(),
                    program: resolved.program,
                    wrappers,
                    synonym,
                });
            }
            Conformance::Conditional { unmet } => {
                violations.push(Violation::ConditionalReproducibility {
                    action: action_ref(),
                    program: resolved.program,
                    wrappers,
                    synonym,
                    unmet,
                });
            }
        }
    }

    violations
}

#[cfg(test)]
pub(crate) mod tests {

    use super::*;
    use crate::reproducibility_spec::program_id::Origin;
    use analysis_v2_proto::analysis::KeyValuePair;

    const USER_SENTINEL: &str = "ahab-user-SENTINEL";
    const HOST_SENTINEL: &str = "ahab-host-SENTINEL";

    /// Build an [`Action`] with the given mnemonic, target id, and environment
    /// variables (as `(key, value)` pairs).
    pub(crate) fn action_with_env(
        mnemonic: &str,
        target_id: u32,
        env: &[(&str, &str)],
    ) -> Action {
        Action {
            mnemonic: mnemonic.to_owned(),
            target_id,
            environment_variables: env
                .iter()
                .map(|(k, v)| KeyValuePair {
                    key: (*k).to_owned(),
                    value: (*v).to_owned(),
                })
                .collect(),
            ..Default::default()
        }
    }

    /// Build an [`Action`] with the given mnemonic, target id, and command-line
    /// arguments.
    pub(crate) fn action_with_args(
        mnemonic: &str,
        target_id: u32,
        args: &[&str],
    ) -> Action {
        Action {
            mnemonic: mnemonic.to_owned(),
            target_id,
            arguments: args.iter().map(|a| (*a).to_owned()).collect(),
            ..Default::default()
        }
    }

    /// Build an [`Action`] with command-line arguments and param files, each
    /// given as `(exec_path, lines)`.
    pub(crate) fn action_with_param_files(
        mnemonic: &str,
        target_id: u32,
        args: &[&str],
        param_files: &[(&str, &[&str])],
    ) -> Action {
        Action {
            param_files: param_files
                .iter()
                .map(|(exec_path, lines)| {
                    analysis_v2_proto::analysis::ParamFile {
                        exec_path: (*exec_path).to_owned(),
                        arguments: lines
                            .iter()
                            .map(|l| (*l).to_owned())
                            .collect(),
                    }
                })
                .collect(),
            ..action_with_args(mnemonic, target_id, args)
        }
    }

    /// Wrap a list of actions in an [`ActionGraphContainer`].
    /// Assert that `v` is a [`Violation::AbsolutePath`] with the given fields.
    #[track_caller]
    pub(crate) fn assert_abs_path(
        v: &Violation,
        mnemonic: &str,
        target_id: u32,
        path: &str,
        site: LeakSite,
    ) {
        match v {
            Violation::AbsolutePath {
                action,
                path: got_path,
                site: got_site,
            } => {
                assert_eq!(action.mnemonic, mnemonic);
                assert_eq!(action.target, test_label(target_id));
                assert_eq!(got_path, path);
                assert_eq!(*got_site, site);
            }
            other => panic!("expected AbsolutePath, got {other:?}"),
        }
    }

    pub(crate) fn container(actions: Vec<Action>) -> ActionGraphContainer {
        let mut ids: Vec<u32> =
            actions.iter().map(|a| a.target_id).collect();
        ids.sort_unstable();
        ids.dedup();
        let targets = ids
            .into_iter()
            .map(|id| analysis_v2_proto::analysis::Target {
                id,
                label: test_label(id),
                ..Default::default()
            })
            .collect();

        ActionGraphContainer {
            actions,
            targets,
            ..Default::default()
        }
    }

    /// A container whose one action takes `inputs` (exec-root-relative
    /// paths) as its inputs, described the way a real dump describes
    /// them—as a tree of path fragments behind a dep set.
    fn container_with_inputs(inputs: &[&str]) -> ActionGraphContainer {
        let mut fragments: Vec<PathFragment> = Vec::new();
        let mut artifacts: Vec<analysis_v2_proto::analysis::Artifact> =
            Vec::new();

        for (index, path) in inputs.iter().enumerate() {
            let mut parent = 0;
            for segment in path.split('/') {
                let id = fragments.len() as u32 + 1;
                fragments.push(PathFragment {
                    id,
                    label: segment.to_owned(),
                    parent_id: parent,
                });
                parent = id;
            }
            artifacts.push(analysis_v2_proto::analysis::Artifact {
                id: index as u32 + 1,
                path_fragment_id: parent,
                ..Default::default()
            });
        }

        let mut action = action_with_args("Tool", 1, &["/bin/tool"]);
        action.input_dep_set_ids = vec![1];

        ActionGraphContainer {
            dep_set_of_files: vec![DepSetOfFiles {
                id: 1,
                direct_artifact_ids: artifacts
                    .iter()
                    .map(|artifact| artifact.id)
                    .collect(),
                ..Default::default()
            }],
            artifacts,
            path_fragments: fragments,
            ..container(vec![action])
        }
    }

    #[test]
    fn reading_the_status_files_is_reported_once_for_each() {
        let c = container_with_inputs(&[
            "bazel-out/stable-status.txt",
            "bazel-out/volatile-status.txt",
            "src/main.cc",
        ]);
        let found = check_workspace_status(&c);
        let paths: Vec<&str> = found
            .iter()
            .map(|violation| match violation {
                Violation::WorkspaceStatus { path, .. } => path.as_str(),
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        assert_eq!(
            paths,
            vec![
                "bazel-out/stable-status.txt",
                "bazel-out/volatile-status.txt",
            ],
        );
    }

    #[test]
    fn an_action_that_reads_neither_is_not_reported() {
        let c = container_with_inputs(&["src/main.cc", "src/main.h"]);
        assert!(check_workspace_status(&c).is_empty());
    }

    #[test]
    fn the_two_status_files_are_told_apart_in_the_report() {
        let c = container_with_inputs(&[
            "bazel-out/stable-status.txt",
            "bazel-out/volatile-status.txt",
        ]);
        let rendered: Vec<String> = check_workspace_status(&c)
            .iter()
            .map(|violation| violation.render(Palette::plain()))
            .collect();
        for line in &rendered {
            for guess in ["BUILD_USER", "BUILD_HOST", "BUILD_TIMESTAMP"] {
                assert!(!line.contains(guess), "{line}");
            }
        }
        assert!(
            !rendered[0].contains("does not invalidate"),
            "{rendered:?}",
        );
        assert!(
            rendered[1].contains("does not invalidate"),
            "{rendered:?}",
        );
    }

    #[test]
    fn a_status_file_reached_only_transitively_is_still_found() {
        let mut c = container_with_inputs(&["bazel-out/stable-status.txt"]);
        c.dep_set_of_files = vec![
            DepSetOfFiles {
                id: 1,
                transitive_dep_set_ids: vec![2],
                ..Default::default()
            },
            DepSetOfFiles {
                id: 2,
                transitive_dep_set_ids: vec![3],
                ..Default::default()
            },
            DepSetOfFiles {
                id: 3,
                direct_artifact_ids: vec![1],
                ..Default::default()
            },
        ];
        assert_eq!(check_workspace_status(&c).len(), 1);
    }

    #[test]
    fn a_cycle_among_dep_sets_does_not_hang_the_walk() {
        let mut c = container_with_inputs(&["bazel-out/stable-status.txt"]);
        c.dep_set_of_files = vec![
            DepSetOfFiles {
                id: 1,
                transitive_dep_set_ids: vec![2],
                direct_artifact_ids: vec![1],
            },
            DepSetOfFiles {
                id: 2,
                transitive_dep_set_ids: vec![1],
                ..Default::default()
            },
        ];
        assert_eq!(check_workspace_status(&c).len(), 1);
    }

    /// One [`Violation`] of every variant, for tests that have to cover
    /// all of them.
    ///
    /// Written out rather than generated, because the point is that a new
    /// variant is not covered until somebody adds it here—and the test
    /// below fails until they do.
    pub(crate) fn one_of_each_kind() -> Vec<Violation> {
        let at = || ActionRef {
            mnemonic: "A".to_owned(),
            target: "//test:t".to_owned(),
        };
        let site = || LeakSite::Argument {
            value: "x".to_owned(),
        };
        let program = || ProgramId::of("/usr/bin/cc");

        vec![
            Violation::EnvironmentLeak {
                action: at(),
                source: EnvSource::User,
                sentinel: USER_SENTINEL.to_owned(),
                site: site(),
            },
            Violation::BadPath {
                action: at(),
                actual: "/opt/bin".to_owned(),
            },
            Violation::ExecutionRequirement {
                action: at(),
                requirement: "local".to_owned(),
            },
            Violation::AbsolutePath {
                action: at(),
                path: "/usr/bin/cc".to_owned(),
                site: site(),
            },
            Violation::SystemProgram {
                action: at(),
                program: program(),
                wrappers: Vec::new(),
            },
            Violation::HostDerivedProgram {
                action: at(),
                program: program(),
                wrappers: Vec::new(),
            },
            Violation::UnknownProgram {
                action: at(),
                program: program(),
                wrappers: Vec::new(),
            },
            Violation::NeverReproducible {
                action: at(),
                program: program(),
                wrappers: Vec::new(),
                synonym: None,
            },
            Violation::WorkspaceStatus {
                action: at(),
                path: "bazel-out/stable-status.txt".to_owned(),
            },
            Violation::ConditionalReproducibility {
                action: at(),
                program: program(),
                wrappers: Vec::new(),
                synonym: None,
                unmet: Vec::new(),
            },
        ]
    }

    #[test]
    fn the_sample_covers_every_variant() {
        let kinds: BTreeSet<&str> = one_of_each_kind()
            .iter()
            .map(|violation| violation.facets().kind)
            .collect();
        assert_eq!(kinds.len(), one_of_each_kind().len());
    }

    /// The label [`container`] gives the target with this id.
    fn test_label(target_id: u32) -> String {
        format!("//test:t{target_id}")
    }

    /// Run [`check_environment_leaks`] with both real sentinels.
    fn leaks(c: &ActionGraphContainer) -> Vec<Violation> {
        check_environment_leaks(c, USER_SENTINEL, HOST_SENTINEL)
    }

    /// Assert that `v` is the single expected [`Violation::EnvironmentLeak`],
    /// unwrapping and comparing its structured fields.
    #[track_caller]
    fn assert_env_leak(
        v: &Violation,
        expected: (&str, u32, EnvSource, &str, LeakSite),
    ) {
        let (mnemonic, target_id, source, sentinel, site) = expected;
        match v {
            Violation::EnvironmentLeak {
                action,
                source: got_source,
                sentinel: got_sentinel,
                site: got_site,
            } => {
                assert_eq!(action.mnemonic, mnemonic);
                assert_eq!(action.target, test_label(target_id));
                assert_eq!(*got_source, source);
                assert_eq!(got_sentinel, sentinel);
                assert_eq!(*got_site, site);
            }
            other => panic!("expected EnvironmentLeak, got {other:?}"),
        }
    }

    /// Assert that `v` is a [`Violation::BadPath`] for the given action with the
    /// given actual PATH value.
    #[track_caller]
    fn assert_bad_path(
        v: &Violation,
        mnemonic: &str,
        target_id: u32,
        actual: &str,
    ) {
        match v {
            Violation::BadPath {
                action,
                actual: got_actual,
            } => {
                assert_eq!(action.mnemonic, mnemonic);
                assert_eq!(action.target, test_label(target_id));
                assert_eq!(got_actual, actual);
            }
            other => panic!("expected BadPath, got {other:?}"),
        }
    }

    #[test]
    fn user_sentinel_in_argument_is_a_violation() {
        let c = container(vec![action_with_args(
            "CppCompile",
            1,
            &["-DUSER", USER_SENTINEL],
        )]);
        let found = leaks(&c);
        assert_eq!(found.len(), 1);
        assert_env_leak(
            &found[0],
            (
                "CppCompile",
                1,
                EnvSource::User,
                USER_SENTINEL,
                LeakSite::Argument {
                    value: USER_SENTINEL.to_owned(),
                },
            ),
        );
    }

    #[test]
    fn user_sentinel_in_env_value_is_a_violation() {
        let c = container(vec![action_with_env(
            "CppCompile",
            1,
            &[("BUILD_USER", USER_SENTINEL)],
        )]);
        let found = leaks(&c);
        assert_eq!(found.len(), 1);
        assert_env_leak(
            &found[0],
            (
                "CppCompile",
                1,
                EnvSource::User,
                USER_SENTINEL,
                LeakSite::EnvVar {
                    key: "BUILD_USER".to_owned(),
                    value: USER_SENTINEL.to_owned(),
                },
            ),
        );
    }

    #[test]
    fn sentinel_as_substring_still_trips() {
        let embedded = format!("--define=builder={USER_SENTINEL}-extra");
        let c =
            container(vec![action_with_args("Action", 1, &[&embedded])]);
        let found = leaks(&c);
        assert_eq!(found.len(), 1);
        assert_env_leak(
            &found[0],
            (
                "Action",
                1,
                EnvSource::User,
                USER_SENTINEL,
                LeakSite::Argument { value: embedded },
            ),
        );
    }

    #[test]
    fn all_leaks_are_collected_not_just_the_first() {
        let c = container(vec![
            action_with_args("A", 1, &[USER_SENTINEL]),
            action_with_env("B", 2, &[("HOST", HOST_SENTINEL)]),
        ]);
        let found = leaks(&c);
        assert_eq!(found.len(), 2);
        assert_env_leak(
            &found[0],
            (
                "A",
                1,
                EnvSource::User,
                USER_SENTINEL,
                LeakSite::Argument {
                    value: USER_SENTINEL.to_owned(),
                },
            ),
        );
        assert_env_leak(
            &found[1],
            (
                "B",
                2,
                EnvSource::Hostname,
                HOST_SENTINEL,
                LeakSite::EnvVar {
                    key: "HOST".to_owned(),
                    value: HOST_SENTINEL.to_owned(),
                },
            ),
        );
    }

    #[test]
    fn sentinel_only_in_env_key_is_not_a_leak() {
        let c = container(vec![action_with_env(
            "CppCompile",
            1,
            &[(USER_SENTINEL, "harmless")],
        )]);
        assert!(leaks(&c).is_empty());
    }

    #[test]
    fn each_sentinel_is_checked_independently() {
        let user_only =
            container(vec![action_with_args("A", 1, &[USER_SENTINEL])]);
        assert!(
            !check_environment_leaks(
                &user_only,
                USER_SENTINEL,
                "no-such-host"
            )
            .is_empty()
        );

        let host_only =
            container(vec![action_with_args("A", 1, &[HOST_SENTINEL])]);
        assert!(
            !check_environment_leaks(
                &host_only,
                "no-such-user",
                HOST_SENTINEL
            )
            .is_empty()
        );

        let clean = container(vec![action_with_args("A", 1, &["--ok"])]);
        assert!(
            check_environment_leaks(&clean, USER_SENTINEL, HOST_SENTINEL)
                .is_empty()
        );
    }

    #[test]
    fn an_action_without_a_mnemonic_renders_as_its_target_alone() {
        let action = ActionRef {
            mnemonic: String::new(),
            target: test_label(1),
        };
        assert_eq!(action.to_string(), "action for target //test:t1");
    }

    /// An [`Action`] declaring the given execution requirements.
    fn action_with_requirements(
        mnemonic: &str,
        target_id: u32,
        requirements: &[&str],
    ) -> Action {
        Action {
            mnemonic: mnemonic.to_owned(),
            target_id,
            execution_info: requirements
                .iter()
                .map(|key| KeyValuePair {
                    key: (*key).to_owned(),
                    value: String::new(),
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn every_declared_non_hermetic_requirement_is_reported() {
        let c = container(vec![action_with_requirements(
            "Genrule",
            1,
            &["requires-network", "no-sandbox"],
        )]);
        let found = check_execution_requirements(&c);
        assert_eq!(found.len(), 2, "{found:?}");
        let declared: Vec<&str> = found
            .iter()
            .map(|v| match v {
                Violation::ExecutionRequirement { requirement, .. } => {
                    requirement.as_str()
                }
                other => panic!("{other:?}"),
            })
            .collect();
        assert!(declared.contains(&"requires-network"), "{declared:?}");
        assert!(declared.contains(&"no-sandbox"), "{declared:?}");
    }

    #[test]
    fn scheduling_advice_is_not_a_hermeticity_finding() {
        let c = container(vec![action_with_requirements(
            "Rustc",
            1,
            &[
                "supports-path-mapping",
                "supports-workers",
                "cpu:4",
                "resources:memory:512",
                "some-tag-invented-next-year",
            ],
        )]);
        assert!(check_execution_requirements(&c).is_empty());
    }

    #[test]
    fn an_action_declaring_nothing_is_not_reported() {
        let c = container(vec![action_with_env("Rustc", 1, &[])]);
        assert!(check_execution_requirements(&c).is_empty());
    }

    #[test]
    fn a_declared_requirement_says_so_in_the_report() {
        let c = container(vec![action_with_requirements(
            "Genrule",
            1,
            &["requires-network"],
        )]);
        let rendered =
            check_execution_requirements(&c)[0].render(Palette::plain());
        assert!(rendered.contains("\"requires-network\""), "{rendered}");
        assert!(rendered.contains("the build itself says"), "{rendered}");
    }

    #[test]
    fn arbitrary_wrong_path_is_a_violation() {
        let c = container(vec![action_with_env(
            "CppCompile",
            1,
            &[("PATH", "/usr/local/sbin:/usr/bin")],
        )]);
        let found = check_path(&c);
        assert_eq!(found.len(), 1);
        assert_bad_path(
            &found[0],
            "CppCompile",
            1,
            "/usr/local/sbin:/usr/bin",
        );
    }

    #[test]
    fn render_pretty_prints_expected_path() {
        let v = Violation::BadPath {
            action: ActionRef {
                mnemonic: "CppCompile".to_owned(),
                target: test_label(3),
            },
            actual: "/bin".to_owned(),
        };
        let rendered = v.render(Palette::plain());
        assert!(
            rendered.contains("CppCompile action for target //test:t3"),
            "{rendered}"
        );
        assert!(rendered.contains(r#"sets PATH to "/bin""#), "{rendered}");
        assert!(rendered.contains(EXPECTED_PATH), "{rendered}");
    }

    #[test]
    fn path_superstring_is_a_violation() {
        let too_long = format!("{EXPECTED_PATH}:/opt/bin");
        let c = container(vec![action_with_env(
            "A",
            1,
            &[("PATH", &too_long)],
        )]);
        let found = check_path(&c);
        assert_eq!(found.len(), 1);
        assert_bad_path(&found[0], "A", 1, &too_long);
    }

    #[test]
    fn exact_expected_path_passes() {
        let c = container(vec![action_with_env(
            "A",
            1,
            &[("PATH", EXPECTED_PATH)],
        )]);
        assert!(check_path(&c).is_empty());
    }

    #[test]
    fn action_without_path_passes() {
        let c = container(vec![action_with_env(
            "A",
            1,
            &[("HOME", "/home/nobody"), ("LANG", "C")],
        )]);
        assert!(check_path(&c).is_empty());
    }

    /// Assert that `v` is a [`Violation::UnknownProgram`] for the given action
    /// and program. The program is compared structurally, not by its rendering.
    #[track_caller]
    fn assert_unknown_program(
        v: &Violation,
        mnemonic: &str,
        target_id: u32,
        program: &ProgramId,
    ) {
        match v {
            Violation::UnknownProgram {
                action,
                program: got_program,
                ..
            } => {
                assert_eq!(action.mnemonic, mnemonic);
                assert_eq!(action.target, test_label(target_id));
                assert_eq!(got_program, program);
            }
            other => panic!("expected UnknownProgram, got {other:?}"),
        }
    }

    #[test]
    fn a_host_derived_program_reads_differently_from_a_system_one() {
        let system = container(vec![action_with_args(
            "CppCompile",
            1,
            &["/usr/bin/gcc", "a.c"],
        )]);
        let derived = container(vec![action_with_args(
            "CppCompile",
            1,
            &[
                "external/rules_cc++cc_configure_extension+local_config_cc/cc_wrapper.sh",
                "a.c",
            ],
        )]);
        let library = Library::builtin();

        let system = check_reproducibility(&system, &library);
        let derived = check_reproducibility(&derived, &library);
        assert!(
            matches!(system[0], Violation::SystemProgram { .. }),
            "{system:?}",
        );
        assert!(
            matches!(derived[0], Violation::HostDerivedProgram { .. }),
            "{derived:?}",
        );

        let system = system[0].render(Palette::plain());
        let derived = derived[0].render(Palette::plain());
        assert!(
            system.contains("comes from outside the build"),
            "{system}"
        );
        assert!(
            derived.contains("tools this machine provides"),
            "{derived}",
        );
        assert!(
            derived.contains(
                "@rules_cc+cc_configure_extension//cc_wrapper.sh"
            ),
            "{derived}",
        );
    }

    #[test]
    fn unknown_program_is_flagged_by_its_normalized_identity() {
        let c = container(vec![action_with_args(
            "CppCompile",
            1,
            &["external/llvm+/bin/clang", "-c", "foo.c"],
        )]);
        let found = check_reproducibility(&c, &Library::builtin());
        assert_eq!(found.len(), 1);
        assert_unknown_program(
            &found[0],
            "CppCompile",
            1,
            &ProgramId::of("external/llvm+/bin/clang"),
        );
    }

    #[test]
    fn a_program_named_by_an_absolute_path_is_a_system_program() {
        let c = container(vec![action_with_args(
            "Genrule",
            1,
            &["/bin/bash", "-c", "true"],
        )]);
        let found = check_reproducibility(&c, &Library::builtin());
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0],
            Violation::SystemProgram {
                action: ActionRef {
                    mnemonic: "Genrule".to_owned(),
                    target: test_label(1),
                },
                program: ProgramId::of("/bin/bash"),
                wrappers: Vec::new(),
            }
        );
    }

    #[test]
    fn renders_the_wrappers_a_program_was_reached_through() {
        let v = Violation::UnknownProgram {
            action: ActionRef {
                mnemonic: "Rustc".to_owned(),
                target: test_label(1),
            },
            program: ProgramId::extension(
                "rules_rust",
                "rust",
                "rust_toolchain/bin/rustc",
            ),
            wrappers: vec![ProgramId::module(
                "rules_rust",
                "util/process_wrapper/process_wrapper",
            )],
        };
        let r = v.render(Palette::plain());
        assert!(
            r.contains(
                r#"program "@rules_rust+rust//rust_toolchain/bin/rustc""#
            ),
            "{r}"
        );
        assert!(
            r.contains(
                r#"wrapped by "@rules_rust//util/process_wrapper/process_wrapper""#
            ),
            "{r}"
        );
    }

    #[test]
    fn a_sentinel_in_the_program_path_is_still_a_leak() {
        let program = format!("/home/{USER_SENTINEL}/toolchains/bin/gcc");
        let c =
            container(vec![action_with_args("CppCompile", 1, &[&program])]);
        let found = leaks(&c);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_env_leak(
            &found[0],
            (
                "CppCompile",
                1,
                EnvSource::User,
                USER_SENTINEL,
                LeakSite::Argument {
                    value: program.clone(),
                },
            ),
        );
    }

    #[test]
    fn the_program_itself_is_not_reported_as_an_absolute_path() {
        let c = container(vec![action_with_args(
            "Genrule",
            1,
            &["/bin/bash", "-c", "true"],
        )]);
        assert!(absolute_paths::check(&c, &Library::default()).is_empty());
        assert_eq!(check_reproducibility(&c, &Library::builtin()).len(), 1);
    }

    #[test]
    fn skipping_the_program_does_not_hide_later_arguments() {
        let c = container(vec![action_with_args(
            "Genrule",
            1,
            &["/bin/bash", "-I/usr/include"],
        )]);
        let found = absolute_paths::check(&c, &Library::default());
        assert_eq!(found.len(), 1);
        assert_abs_path(
            &found[0],
            "Genrule",
            1,
            "/usr/include",
            LeakSite::Argument {
                value: "-I/usr/include".to_owned(),
            },
        );
    }

    #[test]
    fn a_bare_command_name_is_a_system_program() {
        let c =
            container(vec![action_with_args("CppCompile", 1, &["gcc"])]);
        let found = check_reproducibility(&c, &Library::builtin());
        assert_eq!(found.len(), 1);
        assert!(matches!(found[0], Violation::SystemProgram { .. }));
        assert!(absolute_paths::check(&c, &Library::default()).is_empty());
    }

    #[test]
    fn renders_a_system_program_as_coming_from_outside_the_build() {
        let v = Violation::SystemProgram {
            action: ActionRef {
                mnemonic: "Genrule".to_owned(),
                target: test_label(1),
            },
            program: ProgramId::of("/bin/bash"),
            wrappers: Vec::new(),
        };
        let r = v.render(Palette::plain());
        assert!(r.contains(r#"program "/bin/bash""#), "{r}");
        assert!(r.contains("outside the build"), "{r}");
        assert!(!r.contains("spec"), "{r}");
    }

    #[test]
    fn violations_retain_the_programs_structure() {
        let c = container(vec![action_with_args(
            "Rustc",
            1,
            &[
                "external/rules_rust++crate+crates__anyhow-1.0.104/_bs.out_dir",
            ],
        )]);
        let found = check_reproducibility(&c, &Library::builtin());
        match &found[0] {
            Violation::UnknownProgram { program, .. } => {
                assert_eq!(
                    program.origin,
                    Origin::Module {
                        name: "rules_rust".to_owned(),
                        extension: Some("crate".to_owned()),
                    }
                );
                assert_eq!(program.path, "_bs.out_dir");
            }
            other => panic!("expected UnknownProgram, got {other:?}"),
        }
    }

    #[test]
    fn actions_without_arguments_have_no_program_to_check() {
        let c =
            container(vec![action_with_env("A", 1, &[("HOME", "/tmp")])]);
        assert!(check_reproducibility(&c, &Library::builtin()).is_empty());
    }

    #[test]
    fn each_action_with_an_unknown_program_is_reported() {
        let c = container(vec![
            action_with_args("A", 1, &["external/llvm+/bin/clang"]),
            action_with_args("B", 2, &["external/rules_rust+/util/x"]),
        ]);
        let found = check_reproducibility(&c, &Library::builtin());
        assert_eq!(found.len(), 2);
        assert_unknown_program(
            &found[0],
            "A",
            1,
            &ProgramId::of("external/llvm+/bin/clang"),
        );
        assert_unknown_program(
            &found[1],
            "B",
            2,
            &ProgramId::of("external/rules_rust+/util/x"),
        );
    }

    /// A container exercising every check at once, with enough actions for the
    /// order they arrive in to matter.
    fn mixed_actions() -> Vec<Action> {
        vec![
            action_with_args(
                "CppCompile",
                3,
                &["/usr/bin/gcc", "-I/opt/include"],
            ),
            action_with_env(
                "Genrule",
                1,
                &[("HOME", &format!("/home/{USER_SENTINEL}"))],
            ),
            action_with_args("Rustc", 2, &["rustc", "--sysroot=/opt/rust"]),
            action_with_env("Genrule", 5, &[("PATH", "/usr/local/bin")]),
            action_with_args("CppLink", 4, &["/usr/bin/ld", "-L/opt/lib"]),
            action_with_env("Rustc", 2, &[("HOSTNAME", HOST_SENTINEL)]),
            action_with_param_files(
                "CppCompile",
                6,
                &["clang", "@out/foo.params"],
                &[("out/foo.params", &["-L/opt/other"])],
            ),
        ]
    }

    #[test]
    fn violation_order_is_stable_across_every_rotation_of_the_actions() {
        let expected = check_all(
            &container(mixed_actions()),
            USER_SENTINEL,
            HOST_SENTINEL,
            &Library::builtin(),
        );

        let actions = mixed_actions();
        for split in 0..actions.len() {
            let mut rotated = actions.clone();
            rotated.rotate_left(split);
            assert_eq!(
                check_all(
                    &container(rotated),
                    USER_SENTINEL,
                    HOST_SENTINEL,
                    &Library::builtin()
                ),
                expected,
                "rotating the actions by {split} changed the report",
            );
        }
    }

    #[test]
    fn check_all_accounts_for_everything_the_individual_checks_find() {
        let c = container(mixed_actions());
        let mut individually =
            check_environment_leaks(&c, USER_SENTINEL, HOST_SENTINEL);
        individually.extend(check_path(&c));
        individually.extend(absolute_paths::check(&c, &Library::default()));
        individually.extend(check_reproducibility(&c, &Library::builtin()));

        let combined = check_all(
            &c,
            USER_SENTINEL,
            HOST_SENTINEL,
            &Library::builtin(),
        );
        assert_eq!(
            combined.values().sum::<usize>(),
            individually.len(),
            "occurrences do not add up to what the checks found",
        );

        individually.sort();
        individually.dedup();
        let keys: Vec<Violation> = combined.keys().cloned().collect();
        assert_eq!(keys, individually);
    }

    /// Two actions of one target, same mnemonic, with the same flaw — the shape
    /// that makes a real report 60% repeats.
    fn sibling_actions() -> Vec<Action> {
        vec![
            action_with_args(
                "CppCompile",
                1,
                &["external/llvm+/bin/clang", "-I/opt/include", "a.c"],
            ),
            action_with_args(
                "CppCompile",
                1,
                &["external/llvm+/bin/clang", "-I/opt/include", "b.c"],
            ),
            action_with_args(
                "CppCompile",
                1,
                &["external/llvm+/bin/clang", "-I/opt/include", "c.c"],
            ),
        ]
    }

    #[test]
    fn identical_violations_are_counted_rather_than_repeated() {
        let violations = check_all(
            &container(sibling_actions()),
            USER_SENTINEL,
            HOST_SENTINEL,
            &Library::builtin(),
        );

        let absolute = violations
            .iter()
            .find(|(v, _)| matches!(v, Violation::AbsolutePath { .. }))
            .expect("the fixture must produce an absolute-path violation");
        assert_eq!(*absolute.1, 3);

        let unknown = violations
            .iter()
            .find(|(v, _)| matches!(v, Violation::UnknownProgram { .. }))
            .expect(
                "the fixture must produce an unknown-program violation",
            );
        assert_eq!(*unknown.1, 3);

        assert_eq!(violations.len(), 2);
        assert_eq!(violations.values().sum::<usize>(), 6);
    }

    #[test]
    fn counts_distinguish_otherwise_identical_results() {
        let one = check_all(
            &container(sibling_actions()[..1].to_vec()),
            USER_SENTINEL,
            HOST_SENTINEL,
            &Library::builtin(),
        );
        let three = check_all(
            &container(sibling_actions()),
            USER_SENTINEL,
            HOST_SENTINEL,
            &Library::builtin(),
        );

        assert_eq!(
            one.keys().collect::<Vec<_>>(),
            three.keys().collect::<Vec<_>>(),
            "the fixtures must differ only in multiplicity",
        );
        assert_ne!(one, three);
    }

    #[test]
    fn sentinels_leaking_into_a_param_file_are_found() {
        let c = container(vec![action_with_param_files(
            "CppLink",
            1,
            &["clang", "@out/foo.params"],
            &[(
                "out/foo.params",
                &["-o", &format!("/home/{USER_SENTINEL}/out.o")],
            )],
        )]);
        let found = leaks(&c);
        assert_eq!(found.len(), 1, "{found:?}");
        match &found[0] {
            Violation::EnvironmentLeak { site, source, .. } => {
                assert_eq!(*source, EnvSource::User);
                assert_eq!(
                    *site,
                    LeakSite::ParamFile {
                        exec_path: "out/foo.params".to_owned(),
                        value: format!("/home/{USER_SENTINEL}/out.o"),
                    }
                );
            }
            other => panic!("expected EnvironmentLeak, got {other:?}"),
        }
    }

    #[test]
    fn absolute_paths_inside_a_param_file_are_found() {
        let c = container(vec![action_with_param_files(
            "CppLink",
            1,
            &["clang", "@out/foo.params"],
            &[("out/foo.params", &["-L/opt/lib"])],
        )]);
        let found = absolute_paths::check(&c, &Library::default());
        assert_eq!(found.len(), 1, "{found:?}");
        match &found[0] {
            Violation::AbsolutePath { path, site, .. } => {
                assert_eq!(path, "/opt/lib");
                assert_eq!(
                    *site,
                    LeakSite::ParamFile {
                        exec_path: "out/foo.params".to_owned(),
                        value: "-L/opt/lib".to_owned(),
                    }
                );
            }
            other => panic!("expected AbsolutePath, got {other:?}"),
        }
    }

    #[test]
    fn unreferenced_param_files_are_still_scanned() {
        let c = container(vec![action_with_param_files(
            "CppCompile",
            1,
            &["clang", "-fmodule-map-file=out/m.cppmap"],
            &[("out/m.cppmap", &["umbrella \"/usr/include\""])],
        )]);
        let found = absolute_paths::check(&c, &Library::default());
        assert_eq!(found.len(), 1, "{found:?}");
    }

    #[test]
    fn a_param_file_is_scanned_once_per_action() {
        let c = container(vec![action_with_param_files(
            "CppLink",
            1,
            &["clang", "@out/foo.params", "@out/foo.params"],
            &[("out/foo.params", &["-L/opt/lib"])],
        )]);
        assert_eq!(absolute_paths::check(&c, &Library::default()).len(), 1);
    }

    #[test]
    fn the_program_is_identified_through_an_expanded_command_line() {
        let c = container(vec![action_with_param_files(
            "CppLink",
            1,
            &["external/llvm+/bin/clang", "@out/foo.params"],
            &[("out/foo.params", &["-O2"])],
        )]);
        let found = check_reproducibility(&c, &Library::builtin());
        assert_eq!(found.len(), 1);
        assert_unknown_program(
            &found[0],
            "CppLink",
            1,
            &ProgramId::of("external/llvm+/bin/clang"),
        );
    }

    #[test]
    fn renders_a_leak_sited_in_a_param_file() {
        let v = Violation::AbsolutePath {
            action: ActionRef {
                mnemonic: "CppLink".to_owned(),
                target: test_label(1),
            },
            path: "/opt/lib".to_owned(),
            site: LeakSite::ParamFile {
                exec_path: "out/foo.params".to_owned(),
                value: "-L/opt/lib".to_owned(),
            },
        };
        let r = v.render(Palette::plain());
        assert!(r.contains(r#"param file "out/foo.params""#), "{r}");
        assert!(r.ends_with(": -L/opt/lib"), "{r}");
    }

    #[test]
    fn renders_never_reproducible() {
        let v = Violation::NeverReproducible {
            action: ActionRef {
                mnemonic: "Genrule".to_owned(),
                target: test_label(4),
            },
            program: ProgramId::of("date"),
            wrappers: Vec::new(),
            synonym: None,
        };
        let r = v.render(Palette::plain());
        assert!(r.contains("Genrule action for target //test:t4"), "{r}");
        assert!(r.contains(r#"program "date""#), "{r}");
        assert!(r.contains("never"), "{r}");
        assert!(!r.contains("synonym"), "{r}");
    }

    #[test]
    fn renders_the_synonym_that_provided_the_spec() {
        let clang = ProgramId::extension(
            "llvm",
            "llvm_toolchain_minimal",
            "bin/clang",
        );
        let v = Violation::NeverReproducible {
            action: ActionRef {
                mnemonic: "CppCompile".to_owned(),
                target: test_label(1),
            },
            program: ProgramId::extension(
                "llvm",
                "llvm_toolchain_minimal",
                "bin/clang++",
            ),
            wrappers: Vec::new(),
            synonym: Some(clang),
        };
        let r = v.render(Palette::plain());
        assert!(
            r.contains(
                r#"program "@llvm+llvm_toolchain_minimal//bin/clang++""#
            ),
            "{r}"
        );
        assert!(
            r.contains(r#"spec from synonym "@llvm+llvm_toolchain_minimal//bin/clang""#),
            "{r}"
        );
    }

    #[test]
    fn renders_the_program_through_display_not_debug() {
        let v = Violation::UnknownProgram {
            action: ActionRef {
                mnemonic: "Rustc".to_owned(),
                target: test_label(1),
            },
            program: ProgramId::of(
                "bazel-out/k8-opt-exec/bin/external/rules_rust+/util/process_wrapper/process_wrapper",
            ),
            wrappers: Vec::new(),
        };
        let r = v.render(Palette::plain());
        assert!(
            r.contains(r#"program "@rules_rust//util/process_wrapper/process_wrapper""#),
            "{r}"
        );
        assert!(!r.contains("Origin"), "{r}");
    }

    #[test]
    fn renders_conditional_with_both_reasons() {
        let v = Violation::ConditionalReproducibility {
            action: ActionRef {
                mnemonic: "CppCompile".to_owned(),
                target: test_label(1),
            },
            program: ProgramId::of("gcc"),
            wrappers: Vec::new(),
            synonym: None,
            unmet: vec![
                Unmet {
                    because: "it needs an option it was not given"
                        .to_owned(),
                    any_of: ["--deterministic".to_owned()].into(),
                    present: Default::default(),
                },
                Unmet {
                    because: "it was given an option that breaks it"
                        .to_owned(),
                    any_of: Default::default(),
                    present: ["--timestamp".to_owned()].into(),
                },
            ],
        };
        let r = v.render(Palette::plain());
        assert!(r.contains(r#"program "gcc""#), "{r}");
        assert!(r.contains("it needs an option it was not given"), "{r}");
        assert!(
            r.contains("but none of --deterministic was passed"),
            "{r}"
        );
        assert!(r.contains("it was given an option that breaks it"), "{r}");
        assert!(r.contains("breaks it, --timestamp"), "{r}");
    }

    #[test]
    fn renders_conditional_with_only_missing_required() {
        let v = Violation::ConditionalReproducibility {
            action: ActionRef {
                mnemonic: "A".to_owned(),
                target: test_label(1),
            },
            program: ProgramId::of("gcc"),
            wrappers: Vec::new(),
            synonym: None,
            unmet: vec![Unmet {
                because: "it needs an option it was not given".to_owned(),
                any_of: ["--sorted".to_owned()].into(),
                present: Default::default(),
            }],
        };
        let r = v.render(Palette::plain());
        assert!(r.contains("it needs an option it was not given"), "{r}");
        assert!(r.contains("but none of --sorted was passed"), "{r}");
        assert!(!r.contains('['), "{r}");
        assert!(!r.contains(r#"""--sorted"#), "{r}");
        assert!(!r.contains("breaks it"), "{r}");
    }
}
