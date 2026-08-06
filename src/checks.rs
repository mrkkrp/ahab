//! Pure hermeticity checks over a decoded `analysis.ActionGraphContainer`.
//!
//! Each check is a pure function: it takes the container (plus whatever
//! parameters it needs) and returns the list of [`Violation`]s it found, never
//! aborting and never touching the environment. The caller decides what a
//! non-empty result means (for Ahab, a non-zero exit). Collecting *all*
//! violations rather than bailing on the first gives callers a complete report.

use std::collections::{BTreeMap, HashMap};

use analysis_v2_proto::analysis::{Action, ActionGraphContainer};

use crate::param_files::{analyzable_strings, expanded_command_line, ArgSource, Sourced};
use crate::reproducibility_spec::{hardcoded, program_id::ProgramId, Conformance};

/// The exact value of `PATH` that every action is required to use.
pub(crate) const EXPECTED_PATH: &str = "/bin:/usr/bin:/usr/local/bin";

/// The identity of the action responsible for a violation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ActionRef {
    /// The action's mnemonic (e.g. `CppCompile`). May be empty.
    pub mnemonic: String,
    /// The label of the target responsible for the action, e.g. `//foo:bar`.
    pub target: String,
}

impl ActionRef {
    /// Capture the action's identity, resolving its `target_id` through
    /// `targets`. An id the dump does not describe yields a placeholder rather
    /// than a number that would be meaningless outside this run.
    fn of(action: &Action, targets: &HashMap<u32, &str>) -> Self {
        ActionRef {
            mnemonic: action.mnemonic.clone(),
            target: targets
                .get(&action.target_id)
                .map_or_else(|| "<unknown target>".to_owned(), |label| (*label).to_owned()),
        }
    }
}

impl std::fmt::Display for ActionRef {
    /// Render the action using its mnemonic when present, falling back to just
    /// the target otherwise.
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
/// The mapping is valid only for this container, which is the whole reason it
/// has to be applied before a violation leaves the analysis — see [`ActionRef`].
fn target_labels(container: &ActionGraphContainer) -> HashMap<u32, &str> {
    container
        .targets
        .iter()
        .map(|target| (target.id, target.label.as_str()))
        .collect()
}

/// Which piece of the invoking environment a leaked sentinel stood in for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum LeakSite {
    /// Inside a command-line argument.
    Argument { value: String },
    /// Inside a line of one of the action's param files. Reported separately
    /// from [`LeakSite::Argument`] because the argument the action actually
    /// carries is only a reference to the file, so quoting it would not show the
    /// offending text.
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
}

/// Which program's spec judged an action.
///
/// The library lets one program declare that it is reproducible under exactly
/// another's conditions, so the spec applied to an action is not always the one
/// written against the program it runs. Recording which it was keeps a
/// reproducibility verdict traceable to the entry that produced it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum SpecSource {
    /// The program the action runs has a spec of its own.
    Own,
    /// The program has no spec of its own; this one answered for it, reached by
    /// following synonyms through the library.
    Synonym(ProgramId),
}

impl SpecSource {
    /// Classify the program that carried the spec against the one that was
    /// looked up. Equal ids mean the program answered for itself.
    fn of(program: &ProgramId, carrier: &ProgramId) -> SpecSource {
        if program == carrier {
            SpecSource::Own
        } else {
            SpecSource::Synonym(carrier.clone())
        }
    }

    /// A parenthetical naming the program whose spec was applied, empty when
    /// that is the program itself — repeating it would only add noise.
    fn attribution(&self) -> String {
        match self {
            SpecSource::Own => String::new(),
            SpecSource::Synonym(carrier) => {
                format!(" (spec from synonym {:?})", carrier.to_string())
            }
        }
    }
}

/// A single hermeticity violation, as a structured value recording everything
/// the check observed. Use [`Violation::render`] to pretty-print it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Violation {
    /// A sentinel (the value Ahab injected for USER or HOSTNAME) leaked into an
    /// action.
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
    /// An action referenced an absolute path (a `/`-rooted run) in one of its
    /// arguments or environment-variable values.
    AbsolutePath {
        action: ActionRef,
        /// The absolute path that was found (the extracted `/`-rooted run).
        path: String,
        /// Where in the action it appeared, including the full surrounding text.
        site: LeakSite,
    },
    /// An action runs a program for which we have no reproducibility spec, so we
    /// cannot vouch for the action's reproducibility. Reported conservatively —
    /// an unknown program is treated as a problem, not a pass.
    UnknownProgram {
        action: ActionRef,
        /// The program the action runs, normalized from its `argv[0]`.
        program: ProgramId,
    },
    /// An action runs a program that is never reproducible, whatever its flags.
    NeverReproducible {
        action: ActionRef,
        /// The program the action runs.
        program: ProgramId,
        /// Which program's spec produced this verdict.
        spec_source: SpecSource,
    },
    /// An action runs a conditionally-reproducible program, but this invocation
    /// does not meet the conditions: required flags are missing and/or breaking
    /// flags are present. At least one of the two lists is non-empty.
    ConditionalReproducibility {
        action: ActionRef,
        /// The program the action runs.
        program: ProgramId,
        /// Which program's spec produced this verdict.
        spec_source: SpecSource,
        /// Required flags absent from the invocation.
        missing_required: Vec<String>,
        /// Breaking flags present in the invocation.
        present_breaking: Vec<String>,
    },
}

impl Violation {
    /// Pretty-print the violation into a single human-readable line.
    pub(crate) fn render(&self) -> String {
        match self {
            Violation::EnvironmentLeak {
                action,
                source,
                sentinel,
                site,
            } => match site {
                LeakSite::Argument { value } => format!(
                    "hermeticity violation: {source} leaked into an argument of {action} \
                     (found sentinel {sentinel:?} in argument {value:?})",
                    source = source.as_str(),
                ),
                LeakSite::ParamFile { exec_path, value } => format!(
                    "hermeticity violation: {source} leaked into param file {exec_path:?} \
                     of {action} (found sentinel {sentinel:?} in line {value:?})",
                    source = source.as_str(),
                ),
                LeakSite::EnvVar { key, value } => format!(
                    "hermeticity violation: {source} leaked into environment variable \
                     {key:?} of {action} (found sentinel {sentinel:?} in value {value:?})",
                    source = source.as_str(),
                ),
            },
            Violation::BadPath { action, actual } => format!(
                "hermeticity violation: {action} sets PATH to {actual:?}, expected {EXPECTED_PATH:?}",
            ),
            Violation::AbsolutePath { action, path, site } => match site {
                LeakSite::Argument { value } => format!(
                    "hermeticity violation: {action} references absolute path {path:?} \
                     in argument {value:?}",
                ),
                LeakSite::ParamFile { exec_path, value } => format!(
                    "hermeticity violation: {action} references absolute path {path:?} \
                     in param file {exec_path:?} (line {value:?})",
                ),
                LeakSite::EnvVar { key, value } => format!(
                    "hermeticity violation: {action} references absolute path {path:?} \
                     in environment variable {key:?} (value {value:?})",
                ),
            },
            // Programs render through their `Display` (`@rules_rust//util/…`)
            // rather than their `Debug`, then quote that as a whole.
            Violation::UnknownProgram { action, program } => format!(
                "reproducibility unknown: {action} runs program {:?}, which has no \
                 known reproducibility spec",
                program.to_string(),
            ),
            Violation::NeverReproducible {
                action,
                program,
                spec_source,
            } => format!(
                "reproducibility violation: {action} runs program {:?}{}, which is never \
                 reproducible",
                program.to_string(),
                spec_source.attribution(),
            ),
            Violation::ConditionalReproducibility {
                action,
                program,
                spec_source,
                missing_required,
                present_breaking,
            } => {
                let mut reasons = Vec::new();
                if !missing_required.is_empty() {
                    reasons.push(format!("missing required flag(s) {missing_required:?}"));
                }
                if !present_breaking.is_empty() {
                    reasons.push(format!("present breaking flag(s) {present_breaking:?}"));
                }
                format!(
                    "reproducibility violation: {action} runs program {:?}{} \
                     non-reproducibly: {}",
                    program.to_string(),
                    spec_source.attribution(),
                    reasons.join("; "),
                )
            }
        }
    }
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.render())
    }
}

/// Run every check over `container` and return the distinct violations found,
/// each with the number of times it occurred, in a deterministic order.
pub(crate) fn check_all(
    container: &ActionGraphContainer,
    user: &str,
    hostname: &str,
) -> BTreeMap<Violation, usize> {
    let mut violations = check_environment_leaks(container, user, hostname);
    violations.extend(check_path(container));
    violations.extend(check_absolute_paths(container));
    violations.extend(check_reproducibility(container));

    let mut counted = BTreeMap::new();
    for violation in violations {
        *counted.entry(violation).or_insert(0) += 1;
    }
    counted
}

/// Find every place where a sentinel (the values Ahab passed as USER and
/// HOSTNAME) leaks into an action's command line, into one of its param files,
/// or into the value of any of its `environment_variables`, and return one
/// [`Violation`] per leak.
pub(crate) fn check_environment_leaks(
    container: &ActionGraphContainer,
    user: &str,
    hostname: &str,
) -> Vec<Violation> {
    let mut violations = Vec::new();
    let targets = target_labels(container);

    for action in &container.actions {
        // Param files are scanned alongside the command line: a sentinel is just
        // as leaked when it sits in a spilled argument list.
        let scanned = analyzable_strings(action);

        for (sentinel, source) in [(user, EnvSource::User), (hostname, EnvSource::Hostname)] {
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

/// Find every action that sets `PATH` to anything other than [`EXPECTED_PATH`],
/// and return one [`Violation`] per deviation.
pub(crate) fn check_path(container: &ActionGraphContainer) -> Vec<Violation> {
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

/// Whether `c` may appear *inside* an absolute path run. Deliberately broad: the
/// usual filename characters plus the separators that show up in real paths
/// (`.`, `-`, `_`, `+`, `~`, `@`, `%`) and `/` itself. Characters *not* in this
/// set — whitespace, `=`, `:`, `,`, quotes, etc. — terminate a run, which is how
/// paths "glued" to other text via those separators get split out.
fn is_path_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '-' | '_' | '+' | '~' | '@' | '%')
}

/// Compiler/linker flag prefixes that take a path glued directly after them,
/// with no `=` or space separator (e.g. `-I/usr/include`, `-L/opt/lib`,
/// `-isystem/usr/include`). A candidate `/` glued right onto one of these is
/// treated as the start of an absolute path.
const GLUED_FLAG_PREFIXES: &[&str] = &["-I", "-L", "-isystem", "-iquote", "-idirafter"];

/// Whether the candidate `/` at `slash` sits immediately after one of the
/// [`GLUED_FLAG_PREFIXES`], i.e. the text `prefix` occupies `bytes[..slash]`
/// ending exactly at the `/` and begins at a separator boundary. This is what
/// lets `-I/usr/include` be recognised while a relative value like
/// `-Irelative/include` (where the `/` does not sit right after the flag) is
/// left alone.
fn glued_onto_flag(bytes: &[u8], slash: usize) -> bool {
    GLUED_FLAG_PREFIXES.iter().any(|flag| {
        let flag = flag.as_bytes();
        slash >= flag.len()
            && &bytes[slash - flag.len()..slash] == flag
            // The flag itself must start at a boundary (start of string or a
            // non-path char before it), so we don't match a `-I` buried inside
            // some longer token.
            && (slash == flag.len() || !is_path_char(bytes[slash - flag.len() - 1] as char))
    })
}

/// Extract every absolute path embedded in `text`. A run begins at a `/` that
///
/// * is followed by at least one path character,
/// * is not the start of a `//` sequence (so Bazel labels like `//foo:bar` are
///   skipped), and
/// * sits at an absolute-path boundary — either the `/` is at the start of the
///   string / preceded by a separator (whitespace, `=`, `:`, `,`, a quote, …),
///   or it is glued directly onto a flag prefix like `-I`/`-L`/`-isystem`.
///
/// It then continues over path characters. This catches standalone paths,
/// colon-lists (`/bin:/usr/bin`), `--sysroot=/opt/x`, and `-I/usr/include`,
/// while leaving relative paths such as `foo/bar` untouched. Runs are returned
/// in order of appearance.
fn absolute_paths(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut paths = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'/' {
            let next = bytes.get(i + 1).copied();
            let followed_by_path_char = next.is_some_and(|b| is_path_char(b as char));
            let not_double_slash = next != Some(b'/');

            // A `/` is an absolute-path start if it's at a separator boundary
            // (start of string or preceded by a non-path char) or glued onto a
            // flag prefix.
            let boundary = i == 0
                || !is_path_char(bytes[i - 1] as char)
                || glued_onto_flag(bytes, i);

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
/// reported as hermeticity violations. `/dev/null` is a portable, always-present
/// special file (used as a sink or an empty input); referencing it does not make
/// a build non-hermetic.
const ALLOWED_ABSOLUTE_PATHS: &[&str] = &["/dev/null"];

/// Whether an extracted absolute path is exempt from the absolute-path check.
fn is_allowed_absolute_path(path: &str) -> bool {
    ALLOWED_ABSOLUTE_PATHS.contains(&path)
}

/// Find every absolute path (a `/`-rooted run) referenced in an action's command
/// line, in one of its param files, or in the value of any of its
/// `environment_variables`, and return one [`Violation`] per path found.
///
/// The environment variable literally named `PATH` is skipped: it is expected to
/// hold absolute paths and is governed separately by [`check_path`]. Paths in
/// [`ALLOWED_ABSOLUTE_PATHS`] (such as `/dev/null`) are also skipped.
pub(crate) fn check_absolute_paths(container: &ActionGraphContainer) -> Vec<Violation> {
    let mut violations = Vec::new();
    let targets = target_labels(container);

    for action in &container.actions {
        // Spilling a command line into a param file must not launder an absolute
        // path out of the report, so both are scanned.
        for sourced in analyzable_strings(action) {
            for path in absolute_paths(sourced.value) {
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

/// Check each action's program against the hardcoded library of reproducibility
/// specs.
///
/// The program is identified from the action's `argv[0]` by
/// [`ProgramId::of`], which normalizes away the parts of an exec path that vary
/// between builds. Actions with no arguments have no program to attribute and
/// are skipped. For each program:
///
/// * with no known spec, we report [`Violation::UnknownProgram`] — we cannot
///   vouch for its reproducibility, so we err on the side of flagging; otherwise
/// * we assess the actual invocation (`argv[1..]`) against the spec and, if it
///   does not conform, report the corresponding reproducibility violation,
///   noting via [`SpecSource`] whether the spec was the program's own or reached
///   through a synonym.
///
/// The invocation is assessed against the *expanded* command line, so a flag
/// that breaks reproducibility is caught whether it sits on the command line or
/// in a param file the command line references.
pub(crate) fn check_reproducibility(container: &ActionGraphContainer) -> Vec<Violation> {
    let mut violations = Vec::new();
    let targets = target_labels(container);

    for action in &container.actions {
        let command_line = expanded_command_line(action);
        let Some(executable) = command_line.first() else {
            continue;
        };
        let program = ProgramId::of(executable.value);

        let Some((carrier, spec)) = hardcoded::lookup(&program) else {
            violations.push(Violation::UnknownProgram {
                action: ActionRef::of(action, &targets),
                program,
            });
            continue;
        };
        // The spec may have come from a synonym rather than the program itself;
        // record which, so the verdict stays traceable to the entry behind it.
        let spec_source = SpecSource::of(&program, carrier);

        // Assess the invocation against the spec: everything after argv[0].
        let args = command_line.iter().skip(1).map(|sourced| sourced.value);
        match spec.assess(args) {
            Conformance::Reproducible => {}
            Conformance::NeverReproducible => {
                violations.push(Violation::NeverReproducible {
                    action: ActionRef::of(action, &targets),
                    program,
                    spec_source,
                });
            }
            Conformance::Conditional {
                missing_required,
                present_breaking,
            } => {
                violations.push(Violation::ConditionalReproducibility {
                    action: ActionRef::of(action, &targets),
                    program,
                    spec_source,
                    missing_required: missing_required.into_iter().collect(),
                    present_breaking: present_breaking.into_iter().collect(),
                });
            }
        }
    }

    violations
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reproducibility_spec::program_id::Origin;
    use analysis_v2_proto::analysis::KeyValuePair;

    // Fixed, human-readable stand-ins for the values Ahab injects as USER and
    // HOSTNAME. Using literals (rather than `random_token`) keeps every test
    // fully deterministic.
    const USER_SENTINEL: &str = "ahab-user-SENTINEL";
    const HOST_SENTINEL: &str = "ahab-host-SENTINEL";

    /// Build an [`Action`] with the given mnemonic, target id, and environment
    /// variables (as `(key, value)` pairs).
    fn action_with_env(mnemonic: &str, target_id: u32, env: &[(&str, &str)]) -> Action {
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
    fn action_with_args(mnemonic: &str, target_id: u32, args: &[&str]) -> Action {
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
                .map(|(exec_path, lines)| analysis_v2_proto::analysis::ParamFile {
                    exec_path: (*exec_path).to_owned(),
                    arguments: lines.iter().map(|l| (*l).to_owned()).collect(),
                })
                .collect(),
            ..action_with_args(mnemonic, target_id, args)
        }
    }

    /// Wrap a list of actions in an [`ActionGraphContainer`].
    fn container(actions: Vec<Action>) -> ActionGraphContainer {
        // Describe every target the actions refer to, as a real dump would, so
        // the fixtures exercise label resolution rather than sidestep it.
        let mut ids: Vec<u32> = actions.iter().map(|a| a.target_id).collect();
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
    fn assert_env_leak(v: &Violation, expected: (&str, u32, EnvSource, &str, LeakSite)) {
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
    fn assert_bad_path(v: &Violation, mnemonic: &str, target_id: u32, actual: &str) {
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
    fn hostname_sentinel_in_argument_is_a_violation() {
        let c = container(vec![action_with_args("Genrule", 2, &[HOST_SENTINEL])]);
        let found = leaks(&c);
        assert_eq!(found.len(), 1);
        assert_env_leak(
            &found[0],
            (
                "Genrule",
                2,
                EnvSource::Hostname,
                HOST_SENTINEL,
                LeakSite::Argument {
                    value: HOST_SENTINEL.to_owned(),
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
    fn hostname_sentinel_in_env_value_is_a_violation() {
        let c = container(vec![action_with_env(
            "CppCompile",
            1,
            &[("BUILD_HOST", HOST_SENTINEL)],
        )]);
        let found = leaks(&c);
        assert_eq!(found.len(), 1);
        assert_env_leak(
            &found[0],
            (
                "CppCompile",
                1,
                EnvSource::Hostname,
                HOST_SENTINEL,
                LeakSite::EnvVar {
                    key: "BUILD_HOST".to_owned(),
                    value: HOST_SENTINEL.to_owned(),
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
        let c = container(vec![action_with_args("Action", 1, &[&embedded])]);
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
    fn leak_in_second_action_is_found() {
        // First action is clean; the leak lives in the second, so all actions
        // must be scanned.
        let c = container(vec![
            action_with_args("Clean", 1, &["--foo"]),
            action_with_env("Dirty", 2, &[("USER", USER_SENTINEL)]),
        ]);
        let found = leaks(&c);
        assert_eq!(found.len(), 1);
        assert_env_leak(
            &found[0],
            (
                "Dirty",
                2,
                EnvSource::User,
                USER_SENTINEL,
                LeakSite::EnvVar {
                    key: "USER".to_owned(),
                    value: USER_SENTINEL.to_owned(),
                },
            ),
        );
    }

    #[test]
    fn leak_in_action_without_mnemonic_is_found() {
        // An empty mnemonic is recorded faithfully; the `ActionRef` Display (and
        // the target_id) carry the fallback.
        let c = container(vec![action_with_args("", 7, &[USER_SENTINEL])]);
        let found = leaks(&c);
        assert_eq!(found.len(), 1);
        assert_env_leak(
            &found[0],
            (
                "",
                7,
                EnvSource::User,
                USER_SENTINEL,
                LeakSite::Argument {
                    value: USER_SENTINEL.to_owned(),
                },
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
    fn empty_container_has_no_leaks() {
        assert!(leaks(&container(vec![])).is_empty());
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
    fn actions_without_sentinels_pass() {
        let c = container(vec![
            action_with_args("CppCompile", 1, &["-c", "foo.cc", "-o", "foo.o"]),
            action_with_env("Genrule", 2, &[("PATH", EXPECTED_PATH)]),
        ]);
        assert!(leaks(&c).is_empty());
    }

    #[test]
    fn each_sentinel_is_checked_independently() {
        // Only USER leaks: passing a non-matching hostname must still catch it.
        let user_only = container(vec![action_with_args("A", 1, &[USER_SENTINEL])]);
        assert!(!check_environment_leaks(&user_only, USER_SENTINEL, "no-such-host").is_empty());

        // Only HOSTNAME leaks: passing a non-matching user must still catch it.
        let host_only = container(vec![action_with_args("A", 1, &[HOST_SENTINEL])]);
        assert!(!check_environment_leaks(&host_only, "no-such-user", HOST_SENTINEL).is_empty());

        // Neither sentinel present -> no violations even with real sentinels.
        let clean = container(vec![action_with_args("A", 1, &["--ok"])]);
        assert!(check_environment_leaks(&clean, USER_SENTINEL, HOST_SENTINEL).is_empty());
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
        assert_bad_path(&found[0], "CppCompile", 1, "/usr/local/sbin:/usr/bin");
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
        let rendered = v.render();
        assert!(rendered.contains("CppCompile action for target //test:t3"), "{rendered}");
        assert!(rendered.contains(r#"sets PATH to "/bin""#), "{rendered}");
        assert!(rendered.contains(EXPECTED_PATH), "{rendered}");
    }

    #[test]
    fn path_superstring_is_a_violation() {
        // Exact match is required: EXPECTED_PATH plus a trailing dir must fail,
        // and the recorded actual value is the full superstring.
        let too_long = format!("{EXPECTED_PATH}:/opt/bin");
        let c = container(vec![action_with_env("A", 1, &[("PATH", &too_long)])]);
        let found = check_path(&c);
        assert_eq!(found.len(), 1);
        assert_bad_path(&found[0], "A", 1, &too_long);
    }

    #[test]
    fn wrong_path_in_second_action_is_found() {
        let c = container(vec![
            action_with_env("Good", 1, &[("PATH", EXPECTED_PATH)]),
            action_with_env("Bad", 2, &[("PATH", "/bin")]),
        ]);
        let found = check_path(&c);
        assert_eq!(found.len(), 1);
        assert_bad_path(&found[0], "Bad", 2, "/bin");
    }

    #[test]
    fn wrong_path_in_action_without_mnemonic_is_found() {
        let c = container(vec![action_with_env("", 9, &[("PATH", "/bin")])]);
        let found = check_path(&c);
        assert_eq!(found.len(), 1);
        assert_bad_path(&found[0], "", 9, "/bin");
    }

    // ---- check_path: benign cases (expect no violations) ----

    #[test]
    fn exact_expected_path_passes() {
        let c = container(vec![action_with_env("A", 1, &[("PATH", EXPECTED_PATH)])]);
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

    #[test]
    fn empty_container_passes_path_check() {
        assert!(check_path(&container(vec![])).is_empty());
    }

    #[test]
    fn multiple_actions_with_correct_path_pass() {
        let c = container(vec![
            action_with_env("A", 1, &[("PATH", EXPECTED_PATH)]),
            action_with_env("B", 2, &[("PATH", EXPECTED_PATH), ("HOME", "/tmp")]),
            action_with_args("C", 3, &["--no-env"]),
        ]);
        assert!(check_path(&c).is_empty());
    }

    // ---- absolute_paths (the extractor): unit tests ----

    #[test]
    fn extracts_a_bare_absolute_path() {
        assert_eq!(absolute_paths("/usr/bin"), vec!["/usr/bin".to_owned()]);
    }

    #[test]
    fn extracts_a_single_segment_path() {
        // "Any /-rooted run" — a lone /bin counts.
        assert_eq!(absolute_paths("/bin"), vec!["/bin".to_owned()]);
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
    fn assert_abs_path(v: &Violation, mnemonic: &str, target_id: u32, path: &str, site: LeakSite) {
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
            &["-I/usr/include"],
        )]);
        let found = check_absolute_paths(&c);
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
        let found = check_absolute_paths(&c);
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
        let c = container(vec![action_with_args("A", 1, &["/bin:/usr/bin"])]);
        let found = check_absolute_paths(&c);
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
        assert!(check_absolute_paths(&c).is_empty());
    }

    #[test]
    fn other_absolute_path_env_vars_are_still_flagged() {
        // Only the var literally named PATH is skipped; LD_LIBRARY_PATH is not.
        let c = container(vec![action_with_env(
            "A",
            1,
            &[("LD_LIBRARY_PATH", "/opt/lib")],
        )]);
        let found = check_absolute_paths(&c);
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

    // ---- check_absolute_paths: benign cases (expect no violations) ----

    #[test]
    fn relative_paths_and_labels_pass_absolute_path_check() {
        let c = container(vec![action_with_args(
            "A",
            1,
            &["-Irelative/include", "//pkg:target", "foo.o"],
        )]);
        assert!(check_absolute_paths(&c).is_empty());
    }

    #[test]
    fn empty_container_passes_absolute_path_check() {
        assert!(check_absolute_paths(&container(vec![])).is_empty());
    }

    #[test]
    fn dev_null_is_allowed_in_argument() {
        // /dev/null is a portable special file, not a hermeticity leak.
        let c = container(vec![action_with_args("A", 1, &["-o", "/dev/null"])]);
        assert!(check_absolute_paths(&c).is_empty());
    }

    #[test]
    fn dev_null_is_allowed_in_env_value() {
        let c = container(vec![action_with_env("A", 1, &[("OUT", "/dev/null")])]);
        assert!(check_absolute_paths(&c).is_empty());
    }

    #[test]
    fn dev_null_exemption_does_not_suppress_other_paths() {
        // Only the exact /dev/null run is exempt; a real path in the same list
        // is still reported. /dev/urandom is not on the allow-list.
        let c = container(vec![action_with_args("A", 1, &["/dev/null:/opt/bin"])]);
        let found = check_absolute_paths(&c);
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
    fn assert_unknown_program(v: &Violation, mnemonic: &str, target_id: u32, program: &ProgramId) {
        match v {
            Violation::UnknownProgram {
                action,
                program: got_program,
            } => {
                assert_eq!(action.mnemonic, mnemonic);
                assert_eq!(action.target, test_label(target_id));
                assert_eq!(got_program, program);
            }
            other => panic!("expected UnknownProgram, got {other:?}"),
        }
    }

    #[test]
    fn unknown_program_is_flagged_by_its_normalized_identity() {
        // With an empty spec library every program is unknown, and the reported
        // program is argv[0] as a rendered ProgramId. An absolute path is a
        // system tool, so it is reported verbatim.
        let c = container(vec![action_with_args(
            "CppCompile",
            1,
            &["/usr/bin/gcc", "-c", "foo.c"],
        )]);
        let found = check_reproducibility(&c);
        assert_eq!(found.len(), 1);
        assert_unknown_program(&found[0], "CppCompile", 1, &ProgramId::of("/usr/bin/gcc"));
    }

    #[test]
    fn unknown_program_identity_is_normalized_for_build_outputs() {
        // The configuration prefix and the canonical repository name are
        // stripped, so the violation carries the program's identity rather than
        // the exec path it happened to be invoked by.
        let c = container(vec![action_with_args(
            "Rustc",
            1,
            &["bazel-out/k8-opt-exec/bin/external/rules_rust+/util/process_wrapper/process_wrapper"],
        )]);
        let found = check_reproducibility(&c);
        assert_eq!(found.len(), 1);
        assert_unknown_program(
            &found[0],
            "Rustc",
            1,
            &ProgramId {
                origin: Origin::Module {
                    name: "rules_rust".to_owned(),
                    extension: None,
                },
                path: "util/process_wrapper/process_wrapper".to_owned(),
            },
        );
    }

    #[test]
    fn violations_retain_the_programs_structure() {
        // Violations keep a ProgramId, so later analysis can interrogate the
        // origin instead of re-parsing a rendered string.
        let c = container(vec![action_with_args(
            "Rustc",
            1,
            &["external/rules_rust++crate+crates__anyhow-1.0.104/_bs.out_dir"],
        )]);
        let found = check_reproducibility(&c);
        match &found[0] {
            Violation::UnknownProgram { program, .. } => {
                assert_eq!(program.origin.module(), Some("rules_rust"));
                assert_eq!(program.origin.extension(), Some("crate"));
                assert_eq!(program.path, "_bs.out_dir");
            }
            other => panic!("expected UnknownProgram, got {other:?}"),
        }
    }

    #[test]
    fn actions_without_arguments_have_no_program_to_check() {
        // No argv[0] -> nothing to attribute a program to -> skipped.
        let c = container(vec![action_with_env("A", 1, &[("HOME", "/tmp")])]);
        assert!(check_reproducibility(&c).is_empty());
    }

    #[test]
    fn each_action_with_an_unknown_program_is_reported() {
        let c = container(vec![
            action_with_args("A", 1, &["/usr/bin/gcc"]),
            action_with_args("B", 2, &["clang"]),
        ]);
        let found = check_reproducibility(&c);
        assert_eq!(found.len(), 2);
        assert_unknown_program(&found[0], "A", 1, &ProgramId::of("/usr/bin/gcc"));
        assert_unknown_program(&found[1], "B", 2, &ProgramId::of("clang"));
    }

    #[test]
    fn empty_container_passes_reproducibility_check() {
        assert!(check_reproducibility(&container(vec![])).is_empty());
    }

    // ---- deterministic ordering ----

    /// A container exercising every check at once, with enough actions for the
    /// order they arrive in to matter.
    fn mixed_actions() -> Vec<Action> {
        vec![
            action_with_args("CppCompile", 3, &["/usr/bin/gcc", "-I/opt/include"]),
            action_with_env("Genrule", 1, &[("HOME", &format!("/home/{USER_SENTINEL}"))]),
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
    fn violation_order_does_not_depend_on_action_order() {
        // The property that matters: Bazel may enumerate the action graph in any
        // order, and the report must not change because of it.
        let forward = check_all(&container(mixed_actions()), USER_SENTINEL, HOST_SENTINEL);

        let mut reversed = mixed_actions();
        reversed.reverse();
        let reversed = check_all(&container(reversed), USER_SENTINEL, HOST_SENTINEL);

        assert!(!forward.is_empty(), "the fixture must produce violations");
        assert_eq!(forward, reversed);
    }

    #[test]
    fn violation_order_is_stable_across_every_rotation_of_the_actions() {
        // Reversing alone could pass by luck; every rotation must agree too.
        let expected = check_all(&container(mixed_actions()), USER_SENTINEL, HOST_SENTINEL);

        let actions = mixed_actions();
        for split in 0..actions.len() {
            let mut rotated = actions.clone();
            rotated.rotate_left(split);
            assert_eq!(
                check_all(&container(rotated), USER_SENTINEL, HOST_SENTINEL),
                expected,
                "rotating the actions by {split} changed the report",
            );
        }
    }

    #[test]
    fn the_report_groups_violations_by_kind() {
        // Keying by content orders by variant, so the report keeps the shape it
        // had when the checks were simply run in sequence.
        let violations = check_all(&container(mixed_actions()), USER_SENTINEL, HOST_SENTINEL);
        let kind = |v: &Violation| match v {
            Violation::EnvironmentLeak { .. } => 0,
            Violation::BadPath { .. } => 1,
            Violation::AbsolutePath { .. } => 2,
            Violation::UnknownProgram { .. } => 3,
            Violation::NeverReproducible { .. } => 4,
            Violation::ConditionalReproducibility { .. } => 5,
        };
        let kinds: Vec<u8> = violations.keys().map(kind).collect();
        let mut sorted = kinds.clone();
        sorted.sort_unstable();
        assert_eq!(kinds, sorted, "violations are not grouped by kind");
    }

    #[test]
    fn check_all_accounts_for_everything_the_individual_checks_find() {
        // Collapsing must lose nothing: the counts have to add back up.
        let c = container(mixed_actions());
        let mut individually = check_environment_leaks(&c, USER_SENTINEL, HOST_SENTINEL);
        individually.extend(check_path(&c));
        individually.extend(check_absolute_paths(&c));
        individually.extend(check_reproducibility(&c));

        let combined = check_all(&c, USER_SENTINEL, HOST_SENTINEL);
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
            action_with_args("CppCompile", 1, &["clang", "-I/opt/include", "a.c"]),
            action_with_args("CppCompile", 1, &["clang", "-I/opt/include", "b.c"]),
            action_with_args("CppCompile", 1, &["clang", "-I/opt/include", "c.c"]),
        ]
    }

    #[test]
    fn identical_violations_are_counted_rather_than_repeated() {
        let violations = check_all(&container(sibling_actions()), USER_SENTINEL, HOST_SENTINEL);

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
            .expect("the fixture must produce an unknown-program violation");
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
        );
        let three = check_all(&container(sibling_actions()), USER_SENTINEL, HOST_SENTINEL);

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
        let found = check_absolute_paths(&c);
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
        let found = check_absolute_paths(&c);
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
        assert_eq!(check_absolute_paths(&c).len(), 1);
    }

    #[test]
    fn the_program_is_identified_through_an_expanded_command_line() {
        // argv[0] is never itself a param file reference, but expansion must not
        // disturb it.
        let c = container(vec![action_with_param_files(
            "CppLink",
            1,
            &["/usr/bin/clang", "@out/foo.params"],
            &[("out/foo.params", &["-O2"])],
        )]);
        let found = check_reproducibility(&c);
        assert_eq!(found.len(), 1);
        assert_unknown_program(&found[0], "CppLink", 1, &ProgramId::of("/usr/bin/clang"));
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
        let r = v.render();
        assert!(r.contains(r#"param file "out/foo.params""#), "{r}");
        assert!(r.contains(r#"line "-L/opt/lib""#), "{r}");
    }

    // Rendering of the conformance-failure variants. (The end-to-end path
    // through `check_reproducibility` for a *known* program is exercised once the
    // hardcoded library gains specs; the conformance logic itself is covered by
    // the `reproducibility_spec` tests. Here we pin the rendered diagnostics.)

    #[test]
    fn renders_never_reproducible() {
        let v = Violation::NeverReproducible {
            action: ActionRef {
                mnemonic: "Genrule".to_owned(),
                target: test_label(4),
            },
            program: ProgramId::of("date"),
            spec_source: SpecSource::Own,
        };
        let r = v.render();
        assert!(r.contains("Genrule action for target //test:t4"), "{r}");
        assert!(r.contains(r#"program "date""#), "{r}");
        assert!(r.contains("never"), "{r}");
        // A program judged by its own spec says nothing about synonyms.
        assert!(!r.contains("synonym"), "{r}");
    }

    #[test]
    fn renders_the_synonym_that_provided_the_spec() {
        let clang = ProgramId::extension("llvm", "llvm_toolchain_minimal", "bin/clang");
        let v = Violation::NeverReproducible {
            action: ActionRef {
                mnemonic: "CppCompile".to_owned(),
                target: test_label(1),
            },
            program: ProgramId::extension("llvm", "llvm_toolchain_minimal", "bin/clang++"),
            spec_source: SpecSource::Synonym(clang),
        };
        let r = v.render();
        // Both the program that ran and the one whose spec judged it.
        assert!(
            r.contains(r#"program "@llvm+llvm_toolchain_minimal//bin/clang++""#),
            "{r}"
        );
        assert!(
            r.contains(r#"spec from synonym "@llvm+llvm_toolchain_minimal//bin/clang""#),
            "{r}"
        );
    }

    #[test]
    fn spec_source_distinguishes_own_from_synonym() {
        let clang = ProgramId::extension("llvm", "llvm_toolchain_minimal", "bin/clang");
        let clangxx = ProgramId::extension("llvm", "llvm_toolchain_minimal", "bin/clang++");
        assert_eq!(SpecSource::of(&clang, &clang), SpecSource::Own);
        assert_eq!(
            SpecSource::of(&clangxx, &clang),
            SpecSource::Synonym(clang.clone())
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
        };
        let r = v.render();
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
            spec_source: SpecSource::Own,
            missing_required: vec!["--deterministic".to_owned()],
            present_breaking: vec!["--timestamp".to_owned()],
        };
        let r = v.render();
        assert!(r.contains(r#"program "gcc""#), "{r}");
        assert!(r.contains("missing required flag(s)"), "{r}");
        assert!(r.contains("--deterministic"), "{r}");
        assert!(r.contains("present breaking flag(s)"), "{r}");
        assert!(r.contains("--timestamp"), "{r}");
    }

    #[test]
    fn renders_conditional_with_only_missing_required() {
        let v = Violation::ConditionalReproducibility {
            action: ActionRef {
                mnemonic: "A".to_owned(),
                target: test_label(1),
            },
            program: ProgramId::of("gcc"),
            spec_source: SpecSource::Own,
            missing_required: vec!["--sorted".to_owned()],
            present_breaking: vec![],
        };
        let r = v.render();
        assert!(r.contains("missing required flag(s)"), "{r}");
        // No breaking reason when the list is empty.
        assert!(!r.contains("breaking"), "{r}");
    }
}
