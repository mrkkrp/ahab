//! Pure hermeticity checks over a decoded `analysis.ActionGraphContainer`.
//!
//! Each check is a pure function: it takes the container (plus whatever
//! parameters it needs) and returns the list of [`Violation`]s it found, never
//! aborting and never touching the environment. The caller decides what a
//! non-empty result means (for Ahab, a non-zero exit). Collecting *all*
//! violations rather than bailing on the first gives callers a complete report.

use analysis_v2_proto::analysis::{Action, ActionGraphContainer};

/// The exact value of `PATH` that every action is required to use.
pub(crate) const EXPECTED_PATH: &str = "/bin:/usr/bin:/usr/local/bin";

/// The identity of the action responsible for a violation, captured so a
/// violation is self-contained and can be reported without the original
/// container. Corresponds to an [`Action`]'s `mnemonic` and `target_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActionRef {
    /// The action's mnemonic (e.g. `CppCompile`). May be empty.
    pub mnemonic: String,
    /// The id of the target responsible for the action.
    pub target_id: u32,
}

impl ActionRef {
    fn of(action: &Action) -> Self {
        ActionRef {
            mnemonic: action.mnemonic.clone(),
            target_id: action.target_id,
        }
    }
}

impl std::fmt::Display for ActionRef {
    /// Render the action using its mnemonic when present, falling back to just
    /// the target id otherwise.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.mnemonic.is_empty() {
            write!(f, "action for target_id {}", self.target_id)
        } else {
            write!(f, "{} action for target_id {}", self.mnemonic, self.target_id)
        }
    }
}

/// Which piece of the invoking environment a leaked sentinel stood in for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Where in an action a leaked sentinel was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LeakSite {
    /// The sentinel appeared inside a command-line argument.
    Argument { value: String },
    /// The sentinel appeared inside the value of an environment variable.
    EnvVar { key: String, value: String },
}

/// A single hermeticity violation, as a structured value recording everything
/// the check observed. Use [`Violation::render`] to pretty-print it.
#[derive(Debug, Clone, PartialEq, Eq)]
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
                LeakSite::EnvVar { key, value } => format!(
                    "hermeticity violation: {source} leaked into environment variable \
                     {key:?} of {action} (found sentinel {sentinel:?} in value {value:?})",
                    source = source.as_str(),
                ),
            },
            Violation::BadPath { action, actual } => format!(
                "hermeticity violation: {action} sets PATH to {actual:?}, expected {EXPECTED_PATH:?}",
            ),
        }
    }
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.render())
    }
}

/// Find every place where a sentinel (the values Ahab passed as USER and
/// HOSTNAME) leaks into an action's `arguments` or into the value of any of its
/// `environment_variables`, and return one [`Violation`] per leak.
pub(crate) fn check_environment_leaks(
    container: &ActionGraphContainer,
    user: &str,
    hostname: &str,
) -> Vec<Violation> {
    let mut violations = Vec::new();

    for action in &container.actions {
        for (sentinel, source) in [(user, EnvSource::User), (hostname, EnvSource::Hostname)] {
            for arg in &action.arguments {
                if arg.contains(sentinel) {
                    violations.push(Violation::EnvironmentLeak {
                        action: ActionRef::of(action),
                        source,
                        sentinel: sentinel.to_owned(),
                        site: LeakSite::Argument {
                            value: arg.clone(),
                        },
                    });
                }
            }

            for kv in &action.environment_variables {
                if kv.value.contains(sentinel) {
                    violations.push(Violation::EnvironmentLeak {
                        action: ActionRef::of(action),
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

    for action in &container.actions {
        for kv in &action.environment_variables {
            if kv.key == "PATH" && kv.value != EXPECTED_PATH {
                violations.push(Violation::BadPath {
                    action: ActionRef::of(action),
                    actual: kv.value.clone(),
                });
            }
        }
    }

    violations
}

#[cfg(test)]
mod tests {
    use super::*;
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

    /// Wrap a list of actions in an [`ActionGraphContainer`].
    fn container(actions: Vec<Action>) -> ActionGraphContainer {
        ActionGraphContainer {
            actions,
            ..Default::default()
        }
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
                assert_eq!(action.target_id, target_id);
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
                assert_eq!(action.target_id, target_id);
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
                target_id: 3,
            },
            actual: "/bin".to_owned(),
        };
        let rendered = v.render();
        assert!(rendered.contains("CppCompile action for target_id 3"), "{rendered}");
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
}
