//! Pure hermeticity checks over a decoded `analysis.ActionGraphContainer`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

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

/// The exact value of `PATH` that every action is required to use.
const EXPECTED_PATH: &str = "/bin:/usr/bin:/usr/local/bin";

/// The identity of the action responsible for a violation.
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
    /// The action's mnemonic (e.g. `CppCompile`). May be empty.
    pub mnemonic: String,
    /// The label of the target responsible for the action, e.g. `//foo:bar`.
    pub target: String,
}

impl ActionRef {
    /// Capture the action's identity, resolving its `target_id` through
    /// `targets`. An id the dump does not describe yields a placeholder
    /// rather than a number that would be meaningless outside this run.
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
    /// Render the action using its mnemonic when present, falling back to
    /// just the target otherwise.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.mnemonic.is_empty() {
            write!(f, "action for target {}", self.target)
        } else {
            write!(f, "{} action for target {}", self.mnemonic, self.target)
        }
    }
}

/// Index a container's targets by the id its actions refer to them by.
///
/// The mapping is valid only for this container, which is the whole reason
/// it has to be applied before a violation leaves the analysis.
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
    /// The environment variable name this source corresponds to.
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
    /// Inside a command-line argument.
    Argument { value: String },
    /// Inside a line of one of the action's param files. Reported
    /// separately from [`LeakSite::Argument`] because the argument the
    /// action actually carries is only a reference to the file, so quoting
    /// it would not show the offending text.
    ParamFile {
        /// The exec path of the param file.
        exec_path: String,
        /// The line of the file the finding was in.
        value: String,
    },
    /// Inside the value of an environment variable.
    EnvVar { key: String, value: String },
}

impl LeakSite {
    /// Build the site for a string the checks scanned, from its provenance.
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

    /// How a report names where something was found, and the text it was
    /// found in.
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

/// A parenthetical describing how the analysis reached the program it
/// judged: the wrappers it was found behind, outermost first, and the
/// synonym whose spec answered for it. Empty when the action ran the
/// program directly and it had a spec of its own.
///
/// Without the wrappers a verdict about a wrapped command would read as a
/// claim about the action's own `argv[0]`, which is not what ran. Without
/// the synonym a verdict would not say that it rests on two programs being
/// declared alike.
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

/// A single hermeticity violation, as a structured value recording
/// everything the check observed. Use [`Violation::render`] to pretty-print
/// it.
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
        /// Which environment source the sentinel stood in for.
        source: EnvSource,
        /// The sentinel value that leaked.
        sentinel: String,
        /// Where in the action it was found.
        site: LeakSite,
    },
    /// An action set `PATH` to something other than [`EXPECTED_PATH`].
    BadPath {
        action: ActionRef,
        /// The `PATH` value the action actually set.
        actual: String,
    },
    /// An action declares an execution requirement that says it cannot be
    /// run like an ordinary hermetic action.
    ExecutionRequirement {
        action: ActionRef,
        /// The requirement, as the action declares it: `no-sandbox`,
        /// `requires-network`, and so on.
        requirement: String,
    },
    /// An action referenced an absolute path (a `/`-rooted run) in one of
    /// its arguments or environment-variable values.
    AbsolutePath {
        action: ActionRef,
        /// The absolute path that was found (the extracted `/`-rooted run).
        path: String,
        /// Where in the action it appeared, including the full surrounding
        /// text.
        site: LeakSite,
    },
    /// An action runs a program from outside the build: named by an
    /// absolute path, or by a bare command name left to `PATH`. Either way
    /// the tool is whatever the machine happens to have, so the action
    /// cannot be hermetic and no reproducibility spec could redeem it.
    SystemProgram {
        action: ActionRef,
        /// The program the action runs.
        program: ProgramId,
        /// Wrappers passed through to reach it, outermost first. Empty when
        /// the action ran the program directly.
        wrappers: Vec<ProgramId>,
    },
    /// An action runs a program that *is* part of the build—it sits inside
    /// the execution root and Bazel produced it—but that Bazel produced by
    /// inspecting the machine.
    HostDerivedProgram {
        action: ActionRef,
        /// The program the action runs.
        program: ProgramId,
        /// Wrappers passed through to reach it, outermost first. Empty when
        /// the action ran the program directly.
        wrappers: Vec<ProgramId>,
    },
    /// An action runs a program for which we have no reproducibility spec,
    /// so we cannot vouch for the action's reproducibility. Reported
    /// conservatively—an unknown program is treated as a problem, not a
    /// pass.
    UnknownProgram {
        action: ActionRef,
        /// The program the action runs.
        program: ProgramId,
        /// Wrappers passed through to reach it, outermost first. Empty when
        /// the action ran the program directly.
        wrappers: Vec<ProgramId>,
    },
    /// An action runs a program that is never reproducible, whatever its
    /// flags.
    NeverReproducible {
        action: ActionRef,
        /// The program the action runs.
        program: ProgramId,
        /// Wrappers passed through to reach it, outermost first. Empty when
        /// the action ran the program directly.
        wrappers: Vec<ProgramId>,
        /// The synonym whose spec produced this verdict, if it was not the
        /// program's own.
        synonym: Option<ProgramId>,
    },
    /// An action reads one of Bazel's workspace status files, so what it
    /// produces depends on values gathered about the build rather than on
    /// the action's declared inputs. What those values are is up to the
    /// project's `--workspace_status_command`, so the violation names the
    /// file and does not guess at its contents.
    WorkspaceStatus {
        action: ActionRef,
        /// The status file the action reads.
        path: String,
    },
    /// An action runs a conditionally-reproducible program, but this
    /// invocation does not meet the conditions: required flags are missing
    /// and/or breaking flags are present. At least one of the two lists is
    /// non-empty.
    ConditionalReproducibility {
        action: ActionRef,
        /// The program the action runs.
        program: ProgramId,
        /// Wrappers passed through to reach it, outermost first. Empty when
        /// the action ran the program directly.
        wrappers: Vec<ProgramId>,
        /// The synonym whose spec produced this verdict, if it was not the
        /// program's own.
        synonym: Option<ProgramId>,
        /// The clauses the invocation failed, with the spec's own words for
        /// what each was about.
        unmet: Vec<Unmet>,
    },
}

/// A violation flattened into the handful of dimensions something outside
/// the checks might want to ask about, with the fields a given kind does
/// not have left as `None`.
///
/// This exists so that [`crate::exceptions`] can match on a violation
/// without restating the shape of every variant. Producing it is one
/// exhaustive `match`, so a variant added later cannot be quietly left out
/// of the answer—the compiler asks what its facets are.
pub(crate) struct Facets<'a> {
    /// The variant's serialization tag, e.g. `absolute_path`.
    pub kind: &'static str,
    /// The action responsible.
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
    /// Flatten the violation into the dimensions an exception can match.
    pub(crate) fn facets(&self) -> Facets<'_> {
        // A base value so each arm states only what makes it different.
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

    /// Pretty-print the violation into a single human-readable line.
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
            // Programs render through their `Display`
            // (`@rules_rust//util/…`) rather than their `Debug`, then quote
            // that as a whole.
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
                "{hermeticity}: {} runs program {}{}, which Bazel \
                 generated by inspecting this machine",
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

/// Run every check over `container` and return the distinct violations
/// found, each with the number of times it occurred, in a deterministic
/// order.
pub(crate) fn check_all(
    container: &ActionGraphContainer,
    user: &str,
    hostname: &str,
    library: &Library,
) -> BTreeMap<Violation, usize> {
    let mut violations = check_environment_leaks(container, user, hostname);
    violations.extend(check_path(container));
    violations.extend(check_absolute_paths(container, library));
    violations.extend(check_execution_requirements(container));
    violations.extend(check_workspace_status(container));
    violations.extend(check_reproducibility(container, library));

    let mut counted = BTreeMap::new();
    for violation in violations {
        *counted.entry(violation).or_insert(0) += 1;
    }
    counted
}

/// The two files Bazel writes the workspace status into, relative to the
/// output path.
const STABLE_STATUS: &str = "stable-status.txt";
const VOLATILE_STATUS: &str = "volatile-status.txt";

/// Reconstruct an artifact's execution-root-relative path.
///
/// The proto stores paths as a tree of segments—each fragment naming one
/// and pointing at its parent—so a path is read by walking up to the root
/// and reversing. The walk is bounded by the number of fragments, since a
/// malformed graph could otherwise describe a cycle.
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

/// For every dep set, which of `wanted` it reaches—directly or through
/// another set.
///
/// Answered once for the whole graph rather than once per action. Dep sets
/// are shared, deeply nested and numerous, so walking each action's inputs
/// separately re-treads the same ground thousands of times; this walks each
/// set once and lets every action that names it read the answer off.
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

/// Find every action that reads Bazel's workspace status files.
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
/// one, with why each is worth reporting.
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

/// Find every action that declares an execution requirement meaning it
/// cannot run like an ordinary hermetic action, and return one
/// [`Violation`] per declaration.
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

/// Find every place where a sentinel leaks into an action's command line,
/// into one of its param files, or into the value of any of its
/// `environment_variables`, and return one [`Violation`] per leak.
fn check_environment_leaks(
    container: &ActionGraphContainer,
    user: &str,
    hostname: &str,
) -> Vec<Violation> {
    let mut violations = Vec::new();
    let targets = target_labels(container);

    for action in &container.actions {
        // Param files are scanned alongside the command line: a sentinel is
        // just as leaked when it sits in a spilled argument list.
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

/// Find every action that sets `PATH` to anything other than
/// [`EXPECTED_PATH`], and return one [`Violation`] per deviation.
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

/// Whether `c` may appear *inside* an absolute path run. Deliberately
/// broad: the usual filename characters plus the separators that show up in
/// real paths (`.`, `-`, `_`, `+`, `~`, `@`, `%`) and `/` itself.
/// Characters *not* in this set—whitespace, `=`, `:`, `,`, quotes,
/// etc.—terminate a run, which is how paths "glued" to other text via those
/// separators get split out.
fn is_path_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(c, '/' | '.' | '-' | '_' | '+' | '~' | '@' | '%')
}

/// Compiler/linker flag prefixes that take a path glued directly after
/// them, with no `=` or space separator (e.g. `-I/usr/include`,
/// `-L/opt/lib`, `-isystem/usr/include`). A candidate `/` glued right onto
/// one of these is treated as the start of an absolute path.
const GLUED_FLAG_PREFIXES: &[&str] =
    &["-I", "-L", "-isystem", "-iquote", "-idirafter"];

/// Whether the candidate `/` at `slash` sits immediately after one of the
/// [`GLUED_FLAG_PREFIXES`], i.e. the text `prefix` occupies
/// `bytes[..slash]` ending exactly at the `/` and begins at a separator
/// boundary. This is what lets `-I/usr/include` be recognised while a
/// relative value like `-Irelative/include` (where the `/` does not sit
/// right after the flag) is left alone.
fn glued_onto_flag(bytes: &[u8], slash: usize) -> bool {
    GLUED_FLAG_PREFIXES.iter().any(|flag| {
        let flag = flag.as_bytes();
        slash >= flag.len()
            && &bytes[slash - flag.len()..slash] == flag
            // The flag itself must start at a boundary (start of string or
            // a non-path char before it), so we don't match a `-I` buried
            // inside some longer token.
            && (slash == flag.len() || !is_path_char(bytes[slash - flag.len() - 1] as char))
    })
}

/// Placeholders that stand for a location inside the build, and that
/// therefore say nothing about the machine the build runs on.
///
/// All three are substituted by rules_rust's `process_wrapper` (see the
/// `--subst pwd=${pwd}` arguments it is handed) and name the execution
/// root, the source root under it, and the output base. A path written
/// against one of these is as machine-independent as a relative path.
///
/// The list is closed on purpose.
const BUILD_PLACEHOLDERS: &[&str] = &["pwd", "exec_root", "output_base"];

/// Whether the character just before `slash` closes a `${…}` or `$(…)`
/// naming one of [`BUILD_PLACEHOLDERS`].
///
/// rules_rust sets `CLIPPY_CONF_DIR=${pwd}/external/…` and
/// `CARGO_MANIFEST_DIR=${pwd}/proto`. The `/` after the closing brace is
/// not the root of anything: it separates segments of a path relative to
/// wherever the placeholder lands at execution time. The action records the
/// placeholder rather than the directory it will become, so nothing about
/// the machine is baked in.
fn closes_build_placeholder(bytes: &[u8], slash: usize) -> bool {
    let open = match bytes.get(slash.wrapping_sub(1)) {
        Some(b'}') => b'{',
        Some(b')') => b'(',
        _ => return false,
    };

    // A placeholder name is a plain identifier, so the opening bracket is
    // however far back the identifier characters run. Scanning for that
    // rather than balancing brackets also rejects a command substitution
    // like `$(realpath x)`, whose contents are not an identifier at all.
    let close_at = slash - 1;
    let mut start = close_at;
    while start > 0 {
        let byte = bytes[start - 1];
        if byte.is_ascii_alphanumeric() || byte == b'_' {
            start -= 1;
        } else {
            break;
        }
    }

    // `start < 2` leaves no room for the `$` and the bracket that must
    // precede the name.
    if start < 2 || bytes[start - 1] != open || bytes[start - 2] != b'$' {
        return false;
    }

    let name = &bytes[start..close_at];
    BUILD_PLACEHOLDERS
        .iter()
        .any(|known| known.as_bytes() == name)
}

/// Extract every absolute path embedded in `text`. A run begins at a `/` that
///
/// * is followed by at least one path character,
/// * is not the start of a `//` sequence (so Bazel labels like `//foo:bar` are
///   skipped), and
/// * sits at an absolute-path boundary—either the `/` is at the start of
///   the string / preceded by a separator (whitespace, `=`, `:`, `,`, a
///   quote, …), or it is glued directly onto a flag prefix like
///   `-I`/`-L`/`-isystem`.
///
/// It then continues over path characters. This catches standalone paths,
/// colon-lists (`/bin:/usr/bin`), `--sysroot=/opt/x`, and `-I/usr/include`,
/// while leaving relative paths such as `foo/bar` untouched. Runs are
/// returned in order of appearance.
fn absolute_paths(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut paths = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'/' {
            let next = bytes.get(i + 1).copied();
            let followed_by_path_char =
                next.is_some_and(|b| is_path_char(b as char));
            let not_double_slash = next != Some(b'/');

            // A `/` is an absolute-path start if it's at a separator
            // boundary (start of string or preceded by a non-path char) or
            // glued onto a flag prefix—unless what precedes it is a
            // build-internal placeholder, which makes the path relative to
            // that placeholder however separator-like the `}` looks.
            let boundary = if i == 0 {
                true
            } else if closes_build_placeholder(bytes, i) {
                false
            } else {
                !is_path_char(bytes[i - 1] as char)
                    || glued_onto_flag(bytes, i)
            };

            if followed_by_path_char && not_double_slash && boundary {
                let start = i;
                i += 1;
                while i < bytes.len() && is_path_char(bytes[i] as char) {
                    i += 1;
                }
                paths.push(text[start..i].to_owned());
                continue;
            }
        }
        i += 1;
    }

    paths
}

/// Absolute paths that are allowed to appear in an action and must not be
/// reported as hermeticity violations.
const ALLOWED_ABSOLUTE_PATHS: &[&str] = &["/dev/null", "/proc/self/cwd"];

/// Whether an extracted absolute path is exempt from the absolute-path
/// check.
fn is_allowed_absolute_path(path: &str) -> bool {
    ALLOWED_ABSOLUTE_PATHS.contains(&path)
}

/// The strings with which this action's program declares a path inside the
/// artifact it produces, as the library describes that program.
///
/// Matched by value rather than by position, because the scan runs over the
/// raw command line followed by every param file, which is not the sequence
/// the program itself receives.
fn declared_path_strings<'a>(
    action: &'a Action,
    library: &Library,
) -> HashSet<&'a str> {
    let command_line = expanded_command_line(action);
    let Some((executable, args)) = command_line.split_first() else {
        return HashSet::new();
    };
    let resolved = library.resolve(
        ProgramId::of(executable.value),
        args.iter().map(|sourced| sourced.value).collect(),
    );
    let Some((_, spec)) = &resolved.spec else {
        return HashSet::new();
    };
    spec.declared_path_args(&resolved.args)
        .into_iter()
        .collect()
}

/// Find every absolute path (a `/`-rooted run) referenced in an action's
/// command line, in one of its param files, or in the value of any of its
/// `environment_variables`, and return one [`Violation`] per path found.
///
/// The environment variable literally named `PATH` is skipped: it is
/// expected to hold absolute paths and is governed separately by
/// [`check_path`]. Paths in [`ALLOWED_ABSOLUTE_PATHS`] (such as
/// `/dev/null`) are also skipped.
fn check_absolute_paths(
    container: &ActionGraphContainer,
    library: &Library,
) -> Vec<Violation> {
    let mut violations = Vec::new();
    let targets = target_labels(container);

    for action in &container.actions {
        // Worked out at the first path we would otherwise report, so that
        // the great majority of actions—which have no absolute path in them
        // at all—never pay for resolving their program a second time.
        let mut declared: Option<HashSet<&str>> = None;

        // Spilling a command line into a param file must not launder an
        // absolute path out of the report, so both are scanned.
        let program = usize::from(!action.arguments.is_empty());
        for sourced in analyzable_strings(action).into_iter().skip(program)
        {
            let paths = absolute_paths(sourced.value);
            if paths.is_empty() {
                continue;
            }
            if declared
                .get_or_insert_with(|| {
                    declared_path_strings(action, library)
                })
                .contains(sourced.value)
            {
                continue;
            }
            for path in paths {
                if is_allowed_absolute_path(&path) {
                    continue;
                }
                violations.push(Violation::AbsolutePath {
                    action: ActionRef::of(action, &targets),
                    path,
                    site: LeakSite::of(sourced),
                });
            }
        }

        for kv in &action.environment_variables {
            if kv.key == "PATH" {
                continue;
            }
            for path in absolute_paths(&kv.value) {
                if is_allowed_absolute_path(&path) {
                    continue;
                }
                violations.push(Violation::AbsolutePath {
                    action: ActionRef::of(action, &targets),
                    path,
                    site: LeakSite::EnvVar {
                        key: kv.key.clone(),
                        value: kv.value.clone(),
                    },
                });
            }
        }
    }

    violations
}

/// Check each action's program against the library of reproducibility
/// specs.
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

        // A tool from outside the build is a hermeticity failure outright,
        // so it is reported as such rather than as a program we happen to
        // lack a spec for. No spec could make it acceptable.
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

    // Short, human-readable stand-ins for the values Ahab injects as USER
    // and HOSTNAME.
    const USER_SENTINEL: &str = "ahab-user-SENTINEL";
    const HOST_SENTINEL: &str = "ahab-host-SENTINEL";

    /// Build an [`Action`] with the given mnemonic, target id, and environment
    /// variables (as `(key, value)` pairs).
    fn action_with_env(
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
    fn action_with_args(
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
    fn action_with_param_files(
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
    fn container(actions: Vec<Action>) -> ActionGraphContainer {
        // Describe every target the actions refer to, as a real dump would, so
        // the fixtures exercise label resolution rather than sidestep it.
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
            // Ids start at 1: the proto spells "no parent" as 0, so a
            // fragment with that id could not be pointed at.
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
        // The overwhelming majority: nothing stamped, nothing to say.
        let c = container_with_inputs(&["src/main.cc", "src/main.h"]);
        assert!(check_workspace_status(&c).is_empty());
    }

    #[test]
    fn the_two_status_files_are_told_apart_in_the_report() {
        // What separates them is not what they hold—that is the project's
        // to decide—but that Bazel refuses to invalidate on one of them.
        // Only the volatile line should say so.
        let c = container_with_inputs(&[
            "bazel-out/stable-status.txt",
            "bazel-out/volatile-status.txt",
        ]);
        let rendered: Vec<String> = check_workspace_status(&c)
            .iter()
            .map(|violation| violation.render(Palette::plain()))
            .collect();
        // Neither names a key, since neither can know one.
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
        // Dep sets nest, and an input three sets deep is as much an input
        // as a direct one.
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
        // Nothing Bazel emits is cyclic, but a walk over ids from a file
        // should not be the thing that finds out.
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
        // The list above is hand-written, so something has to notice when
        // a variant is added and not listed. Kinds are unique per variant,
        // so counting the distinct ones is enough.
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
        // The check uses `.contains()`, so a sentinel embedded in a larger
        // string is still a leak — and the recorded value is the *whole*
        // enclosing argument, not just the sentinel.
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
        // Two independent leaks across two actions: each carries its own
        // structured detail.
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
        // Only env-var *values* are checked, never keys. A sentinel appearing
        // as a key is deliberately allowed.
        let c = container(vec![action_with_env(
            "CppCompile",
            1,
            &[(USER_SENTINEL, "harmless")],
        )]);
        assert!(leaks(&c).is_empty());
    }

    #[test]
    fn each_sentinel_is_checked_independently() {
        // Only USER leaks: passing a non-matching hostname must still catch it.
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

        // Only HOSTNAME leaks: passing a non-matching user must still catch it.
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

        // Neither sentinel present -> no violations even with real sentinels.
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

    // ---- check_execution_requirements ----

    #[test]
    fn every_declared_non_hermetic_requirement_is_reported() {
        // One violation each, so that an action declaring two problems is
        // not reported as one.
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
        // Everything here is a capability or a resource hint. A tag
        // nobody has classified stays silent, which is the direction to
        // fail in: a deny-list that misses something is quiet, an
        // allow-list that misses something is noise.
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
        // The wording matters: this is the one finding Ahab does not
        // infer, and the message should say the build stated it.
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

    // ---- check_path: pathological cases (expect violations) ----

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
        // The pretty-printer names both the offending and the expected PATH.
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
        // Exact match is required: EXPECTED_PATH plus a trailing dir must fail,
        // and the recorded actual value is the full superstring.
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

    // ---- check_path: benign cases (expect no violations) ----

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

    // ---- absolute_paths (the extractor): unit tests ----

    #[test]
    fn extracts_a_bare_absolute_path() {
        assert_eq!(absolute_paths("/usr/bin"), vec!["/usr/bin".to_owned()]);
    }

    #[test]
    fn extracts_path_glued_after_a_flag_without_separator() {
        // -I/usr/include: the path starts mid-token, glued to the flag.
        assert_eq!(
            absolute_paths("-I/usr/include"),
            vec!["/usr/include".to_owned()]
        );
    }

    #[test]
    fn extracts_path_glued_after_isystem_flag() {
        assert_eq!(
            absolute_paths("-isystem/usr/include"),
            vec!["/usr/include".to_owned()]
        );
    }

    #[test]
    fn relative_value_after_a_flag_is_not_absolute() {
        // -Irelative/include: the `/` does not sit right after the flag, so the
        // value is relative and must not be flagged.
        assert!(absolute_paths("-Irelative/include").is_empty());
    }

    #[test]
    fn extracts_path_glued_with_equals() {
        assert_eq!(
            absolute_paths("--sysroot=/opt/toolchain/sysroot"),
            vec!["/opt/toolchain/sysroot".to_owned()]
        );
    }

    #[test]
    fn extracts_each_path_in_a_colon_list() {
        assert_eq!(
            absolute_paths("/bin:/usr/bin:/usr/local/bin"),
            vec![
                "/bin".to_owned(),
                "/usr/bin".to_owned(),
                "/usr/local/bin".to_owned(),
            ]
        );
    }

    #[test]
    fn stops_a_run_at_separators() {
        // A comma and whitespace both terminate the run.
        assert_eq!(
            absolute_paths("/a/b,/c/d /e"),
            vec!["/a/b".to_owned(), "/c/d".to_owned(), "/e".to_owned()]
        );
    }

    #[test]
    fn keeps_dotted_and_dashed_path_characters() {
        assert_eq!(
            absolute_paths("/opt/gcc-12.2/lib/libfoo.so.1"),
            vec!["/opt/gcc-12.2/lib/libfoo.so.1".to_owned()]
        );
    }

    #[test]
    fn ignores_bare_slash_and_relative_paths() {
        assert!(absolute_paths("/").is_empty());
        assert!(absolute_paths("foo/bar").is_empty());
        assert!(absolute_paths("./rel/path").is_empty());
        assert!(absolute_paths("no paths here").is_empty());
    }

    #[test]
    fn ignores_double_slash_bazel_labels() {
        // //foo:bar is a Bazel label, not an absolute filesystem path.
        assert!(absolute_paths("//foo:bar").is_empty());
        // ...but a real path elsewhere in the same string is still found.
        assert_eq!(
            absolute_paths("//foo=/real/path"),
            vec!["/real/path".to_owned()]
        );
    }

    // ---- check_absolute_paths: pathological cases (expect violations) ----

    /// Assert that `v` is a [`Violation::AbsolutePath`] with the given fields.
    #[track_caller]
    fn assert_abs_path(
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

    #[test]
    fn absolute_path_in_argument_is_a_violation() {
        let c = container(vec![action_with_args(
            "CppCompile",
            1,
            &["tool", "-I/usr/include"],
        )]);
        let found = check_absolute_paths(&c, &Library::default());
        assert_eq!(found.len(), 1);
        assert_abs_path(
            &found[0],
            "CppCompile",
            1,
            "/usr/include",
            LeakSite::Argument {
                value: "-I/usr/include".to_owned(),
            },
        );
    }

    #[test]
    fn absolute_path_in_env_value_is_a_violation() {
        let c = container(vec![action_with_env(
            "Genrule",
            2,
            &[("CC", "/usr/bin/gcc")],
        )]);
        let found = check_absolute_paths(&c, &Library::default());
        assert_eq!(found.len(), 1);
        assert_abs_path(
            &found[0],
            "Genrule",
            2,
            "/usr/bin/gcc",
            LeakSite::EnvVar {
                key: "CC".to_owned(),
                value: "/usr/bin/gcc".to_owned(),
            },
        );
    }

    #[test]
    fn colon_list_argument_reports_each_path() {
        let c = container(vec![action_with_args(
            "A",
            1,
            &["tool", "/bin:/usr/bin"],
        )]);
        let found = check_absolute_paths(&c, &Library::default());
        assert_eq!(found.len(), 2);
        assert_abs_path(
            &found[0],
            "A",
            1,
            "/bin",
            LeakSite::Argument {
                value: "/bin:/usr/bin".to_owned(),
            },
        );
        assert_abs_path(
            &found[1],
            "A",
            1,
            "/usr/bin",
            LeakSite::Argument {
                value: "/bin:/usr/bin".to_owned(),
            },
        );
    }

    #[test]
    fn path_env_var_is_skipped_by_absolute_path_check() {
        // PATH is expected to hold absolute paths and is governed by check_path;
        // the absolute-path check must not double-report it.
        let c = container(vec![action_with_env(
            "A",
            1,
            &[("PATH", EXPECTED_PATH)],
        )]);
        assert!(check_absolute_paths(&c, &Library::default()).is_empty());
    }

    #[test]
    fn other_absolute_path_env_vars_are_still_flagged() {
        // Only the var literally named PATH is skipped; LD_LIBRARY_PATH is not.
        let c = container(vec![action_with_env(
            "A",
            1,
            &[("LD_LIBRARY_PATH", "/opt/lib")],
        )]);
        let found = check_absolute_paths(&c, &Library::default());
        assert_eq!(found.len(), 1);
        assert_abs_path(
            &found[0],
            "A",
            1,
            "/opt/lib",
            LeakSite::EnvVar {
                key: "LD_LIBRARY_PATH".to_owned(),
                value: "/opt/lib".to_owned(),
            },
        );
    }

    // ---- check_absolute_paths: paths the program declares ----

    /// An `img manifest` command line, as rules_img writes it: an in-image
    /// working directory, and a real output under `bazel-out`.
    fn image_manifest_action() -> Action {
        action_with_args(
            "ImageManifest",
            1,
            &[
                "bazel-out/k8-opt-exec/bin/external/rules_img_tool+/cmd/img\
                 /img_linux_amd64_/img_linux_amd64",
                "manifest",
                "--working-dir",
                "/app",
                "--manifest",
                "bazel-out/k8-fastbuild/bin/img/base/scratch_manifest.json",
            ],
        )
    }

    #[test]
    fn a_path_the_program_declares_in_its_output_is_not_reported() {
        // `/app` does not exist on this machine and is not supposed to: it
        // is where the image will put things once someone runs it.
        let c = container(vec![image_manifest_action()]);
        assert!(check_absolute_paths(&c, &Library::builtin()).is_empty());
    }

    #[test]
    fn the_same_path_is_reported_when_the_library_says_nothing() {
        // The whole difference is the library. Without an entry for the
        // program there is nothing to say the path describes an image, and
        // Ahab reports it—which is what it should do for a tool it has
        // never heard of.
        let c = container(vec![image_manifest_action()]);
        let found = check_absolute_paths(&c, &Library::default());
        assert_eq!(found.len(), 1);
        assert_abs_path(
            &found[0],
            "ImageManifest",
            1,
            "/app",
            LeakSite::Argument {
                value: "/app".to_owned(),
            },
        );
    }

    #[test]
    fn declaring_paths_does_not_excuse_the_rest_of_the_action() {
        // An entry naming some of a program's options must not turn into a
        // blanket pardon for the program: an absolute path anywhere else on
        // the same command line is still a finding.
        let mut action = image_manifest_action();
        action.arguments.push("--annotations-file".to_owned());
        action
            .arguments
            .push("/home/someone/annotations.json".to_owned());
        let c = container(vec![action]);
        let found = check_absolute_paths(&c, &Library::builtin());
        assert_eq!(found.len(), 1);
        assert_abs_path(
            &found[0],
            "ImageManifest",
            1,
            "/home/someone/annotations.json",
            LeakSite::Argument {
                value: "/home/someone/annotations.json".to_owned(),
            },
        );
    }

    // ---- check_absolute_paths: benign cases (expect no violations) ----

    #[test]
    fn relative_paths_and_labels_pass_absolute_path_check() {
        let c = container(vec![action_with_args(
            "A",
            1,
            &["-Irelative/include", "//pkg:target", "foo.o"],
        )]);
        assert!(check_absolute_paths(&c, &Library::default()).is_empty());
    }

    #[test]
    fn a_path_under_a_variable_expansion_is_not_absolute() {
        // rules_rust writes exactly these. `${pwd}` becomes the execution
        // root at run time, so nothing machine-specific is recorded.
        let c = container(vec![action_with_env(
            "Clippy",
            1,
            &[
                (
                    "CLIPPY_CONF_DIR",
                    "${pwd}/external/rules_rust+/rust/settings",
                ),
                ("CARGO_MANIFEST_DIR", "${pwd}/proto"),
            ],
        )]);
        assert!(check_absolute_paths(&c, &Library::default()).is_empty());
    }

    #[test]
    fn every_build_placeholder_is_understood() {
        let c = container(vec![action_with_args(
            "A",
            1,
            &[
                "tool",
                "--remap-path-prefix=${pwd}=.",
                "-I${output_base}/include",
                "$(exec_root)/gen",
                // A bare `$name` was never picked up, since the `/` sits
                // right after a path character; pinned so it stays that way.
                "$pwd/external/thing",
            ],
        )]);
        let found = check_absolute_paths(&c, &Library::default());
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn an_unrecognized_expansion_is_not_trusted() {
        // The whole point of the allow-list. `${HOME}` expands to a
        // host-specific absolute path, and a project's own placeholder
        // could expand to anything at all, so neither is excused: an
        // unknown name has to be reported rather than assumed harmless.
        let c = container(vec![action_with_args(
            "A",
            1,
            &[
                "tool",
                "${HOME}/lib",
                "${foobar}/usr/lib",
                "$(realpath x)/y",
            ],
        )]);
        let found = check_absolute_paths(&c, &Library::default());
        assert_eq!(found.len(), 3, "{found:?}");
    }

    #[test]
    fn a_closing_brace_alone_does_not_excuse_an_absolute_path() {
        // Even a known name needs the `$`: brackets that merely happen to
        // precede a `/` are just brackets.
        let c = container(vec![action_with_args(
            "A",
            1,
            &["tool", "[pwd]/usr/lib", "{pwd}/opt/tool"],
        )]);
        let found = check_absolute_paths(&c, &Library::default());
        assert_eq!(found.len(), 2, "{found:?}");
    }

    #[test]
    fn an_absolute_path_after_an_expansion_is_still_reported() {
        // The expansion excuses the path glued to it, not the whole
        // argument: a genuine absolute path later on still counts.
        let c = container(vec![action_with_args(
            "A",
            1,
            &["tool", "${pwd}/external/ok:/usr/lib"],
        )]);
        let found = check_absolute_paths(&c, &Library::default());
        assert_eq!(found.len(), 1, "{found:?}");
        assert_abs_path(
            &found[0],
            "A",
            1,
            "/usr/lib",
            LeakSite::Argument {
                value: "${pwd}/external/ok:/usr/lib".to_owned(),
            },
        );
    }

    #[test]
    fn proc_self_cwd_is_allowed() {
        // What Bazel sets on every C++ action so that a compiler embedding
        // `$PWD` records the same bytes on every machine. It names the
        // working directory without saying where it is.
        let c = container(vec![action_with_env(
            "CppCompile",
            1,
            &[("PWD", "/proc/self/cwd")],
        )]);
        assert!(check_absolute_paths(&c, &Library::default()).is_empty());
    }

    #[test]
    fn a_path_below_proc_self_cwd_is_still_reported() {
        // Only the bare directory is exempt. Anything reaching further is
        // an ordinary path that happens to start there, and the allow-list
        // matches the whole run rather than a prefix.
        let c = container(vec![action_with_args(
            "A",
            1,
            &["tool", "/proc/self/cwd/foo", "/proc/self/root"],
        )]);
        let found = check_absolute_paths(&c, &Library::default());
        assert_eq!(found.len(), 2, "{found:?}");
    }

    #[test]
    fn dev_null_is_allowed_in_argument() {
        // /dev/null is a portable special file, not a hermeticity leak.
        let c =
            container(vec![action_with_args("A", 1, &["-o", "/dev/null"])]);
        assert!(check_absolute_paths(&c, &Library::default()).is_empty());
    }

    #[test]
    fn dev_null_exemption_does_not_suppress_other_paths() {
        // Only the exact /dev/null run is exempt; a real path in the same list
        // is still reported. /dev/urandom is not on the allow-list.
        let c = container(vec![action_with_args(
            "A",
            1,
            &["tool", "/dev/null:/opt/bin"],
        )]);
        let found = check_absolute_paths(&c, &Library::default());
        assert_eq!(found.len(), 1);
        assert_abs_path(
            &found[0],
            "A",
            1,
            "/opt/bin",
            LeakSite::Argument {
                value: "/dev/null:/opt/bin".to_owned(),
            },
        );
    }

    // ---- check_reproducibility ----

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
        // The two are both hermeticity failures and both about the host,
        // but a reader has to be able to tell which: one was seen in
        // argv[0], the other is Ahab's own claim about a generated file.
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
            derived.contains("generated by inspecting this machine"),
            "{derived}",
        );
        // The generated one still says where in the build it sits.
        assert!(
            derived.contains(
                "@rules_cc+cc_configure_extension//cc_wrapper.sh"
            ),
            "{derived}",
        );
    }

    #[test]
    fn unknown_program_is_flagged_by_its_normalized_identity() {
        // With an empty spec library every program in the build is unknown,
        // and the reported program is argv[0] as a rendered ProgramId.
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
        // No spec could redeem it, so it is not reported as merely unknown.
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
        // The verdict is about the wrapped command, and says so.
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
        // Why the argv[0] skip belongs to `check_absolute_paths` and not to
        // `analyzable_strings`: a toolchain configured under the invoking
        // user's home bakes their name into argv[0], and that is exactly the
        // leak Ahab hunts. Nothing else would report it — the accompanying
        // SystemProgram violation says the tool is external, not that a
        // username is embedded in its path.
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
        // Reported once, by the check that can say what is actually wrong.
        // Flagging it here too would only repeat it, less clearly: the
        // extracted path and the argument holding it are the same string.
        let c = container(vec![action_with_args(
            "Genrule",
            1,
            &["/bin/bash", "-c", "true"],
        )]);
        assert!(check_absolute_paths(&c, &Library::default()).is_empty());
        assert_eq!(check_reproducibility(&c, &Library::builtin()).len(), 1);
    }

    #[test]
    fn skipping_the_program_does_not_hide_later_arguments() {
        // Only argv[0] is exempt; an absolute path anywhere after it stands.
        let c = container(vec![action_with_args(
            "Genrule",
            1,
            &["/bin/bash", "-I/usr/include"],
        )]);
        let found = check_absolute_paths(&c, &Library::default());
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
        // Resolved through PATH, so it is whatever the machine has. This is
        // the case the absolute-path check cannot see: there is no `/` in it.
        let c =
            container(vec![action_with_args("CppCompile", 1, &["gcc"])]);
        let found = check_reproducibility(&c, &Library::builtin());
        assert_eq!(found.len(), 1);
        assert!(matches!(found[0], Violation::SystemProgram { .. }));
        assert!(check_absolute_paths(&c, &Library::default()).is_empty());
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
        // Not framed as a missing spec.
        assert!(!r.contains("spec"), "{r}");
    }

    #[test]
    fn violations_retain_the_programs_structure() {
        // Violations keep a ProgramId, so later analysis can interrogate the
        // origin instead of re-parsing a rendered string.
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
        // No argv[0] -> nothing to attribute a program to -> skipped.
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

    // ---- deterministic ordering ----

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
        // Reversing alone could pass by luck; every rotation must agree too.
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
        // Collapsing must lose nothing: the counts have to add back up.
        let c = container(mixed_actions());
        let mut individually =
            check_environment_leaks(&c, USER_SENTINEL, HOST_SENTINEL);
        individually.extend(check_path(&c));
        individually.extend(check_absolute_paths(&c, &Library::default()));
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

        // And every distinct violation is present, exactly once as a key.
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

        // `-I/opt/include` is byte-identical across the three actions, and an
        // ActionRef names a target and mnemonic, not an individual action.
        let absolute = violations
            .iter()
            .find(|(v, _)| matches!(v, Violation::AbsolutePath { .. }))
            .expect("the fixture must produce an absolute-path violation");
        assert_eq!(*absolute.1, 3);

        // Same for the program, which all three actions share.
        let unknown = violations
            .iter()
            .find(|(v, _)| matches!(v, Violation::UnknownProgram { .. }))
            .expect(
                "the fixture must produce an unknown-program violation",
            );
        assert_eq!(*unknown.1, 3);

        // Three actions, three violations each, but only two distinct ones.
        assert_eq!(violations.len(), 2);
        assert_eq!(violations.values().sum::<usize>(), 6);
    }

    #[test]
    fn counts_distinguish_otherwise_identical_results() {
        // The reason multiplicity is kept: the same flaw on one action and on
        // three is not the same finding, and the results must not compare equal.
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

    // ---- param files as first-class sources ----

    #[test]
    fn sentinels_leaking_into_a_param_file_are_found() {
        // The command line holds only a reference, so a check reading `arguments`
        // alone would see nothing wrong here.
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
        let found = check_absolute_paths(&c, &Library::default());
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
        // A C++ module map is never spliced into the command line, but an
        // absolute path inside it is still a leak.
        let c = container(vec![action_with_param_files(
            "CppCompile",
            1,
            &["clang", "-fmodule-map-file=out/m.cppmap"],
            &[("out/m.cppmap", &["umbrella \"/usr/include\""])],
        )]);
        let found = check_absolute_paths(&c, &Library::default());
        assert_eq!(found.len(), 1, "{found:?}");
    }

    #[test]
    fn a_param_file_is_scanned_once_per_action() {
        // Two references to one file must not double-report its contents.
        let c = container(vec![action_with_param_files(
            "CppLink",
            1,
            &["clang", "@out/foo.params", "@out/foo.params"],
            &[("out/foo.params", &["-L/opt/lib"])],
        )]);
        assert_eq!(check_absolute_paths(&c, &Library::default()).len(), 1);
    }

    #[test]
    fn the_program_is_identified_through_an_expanded_command_line() {
        // argv[0] is never itself a param file reference, but expansion must not
        // disturb it.
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
        // The line itself ends the report and is quoted by nothing: it is
        // the thing to look at, not a parenthetical about it.
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
        // A program judged by its own spec says nothing about synonyms.
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
        // Both the program that ran and the one whose spec judged it.
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
        // The variants hold a structured ProgramId; rendering must go through
        // its Display, not dump the struct.
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
        // Each clause speaks in the words its spec gave it, and shows the
        // patterns that would have met it or the arguments that broke it.
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
        // Plainly: the options are bare, with no brackets or quotes of
        // their own. The program name is quoted; that is a different
        // thing and stays.
        assert!(!r.contains('['), "{r}");
        assert!(!r.contains(r#"""--sorted"#), "{r}");
        // Nothing is said about a clause the invocation did not fail.
        assert!(!r.contains("breaks it"), "{r}");
    }
}
