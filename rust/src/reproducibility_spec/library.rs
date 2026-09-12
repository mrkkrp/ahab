//! What Ahab knows about reproducibility of the programs a build runs,
//! keyed by [`ProgramId`].

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::Deserialize;

use super::program_id::{Origin, ProgramId};
use super::{Clause, Guard, Reproducibility, ReproducibilitySpec};
use crate::glob::Glob;

/// What the library knows about one program: either the answer, or where to
/// ask it instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// The program's own reproducibility.
    Spec(ReproducibilitySpec),
    /// The program is reproducible under exactly the conditions of this
    /// other one. A claim about behavior, not identity: `clang++` may be
    /// declared the same as `clang` without being the same binary, and what
    /// the action ran is still what gets reported.
    SameAs(ProgramId),
    /// The program runs another, named in its own arguments, and is as
    /// reproducible as whatever that turns out to be.
    Wraps(Transition),
}

/// How to find the wrapped command inside a wrapper's arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    /// The wrapped command begins immediately after the first argument
    /// equal to `separator`: the next argument is its program and the rest
    /// are its arguments.
    AfterSeparator { separator: String },
    /// The wrapped command is the first argument: an interpreter handed a
    /// script, as `python3 precompiler --src …`. Does not fire on an option,
    /// `python3 -c` and `python3 -m` naming no program to judge.
    FirstArgument,
}

impl Transition {
    /// Extract the wrapped command from the wrapper's `argv[1..]`. `None`
    /// when the arguments do not match the rule, which leaves the wrapper
    /// itself as the program—reported unknown rather than passed.
    fn apply<'a>(
        &self,
        args: &[&'a str],
    ) -> Option<(&'a str, Vec<&'a str>)> {
        match self {
            Transition::AfterSeparator { separator } => {
                let at = args
                    .iter()
                    .position(|arg| *arg == separator.as_str())?;
                let (program, rest) = args[at + 1..].split_first()?;
                Some((program, rest.to_vec()))
            }
            Transition::FirstArgument => {
                let (program, rest) = args.split_first()?;
                if program.starts_with('-') {
                    return None;
                }
                Some((program, rest.to_vec()))
            }
        }
    }
}

/// How many entries to follow before giving up, counting synonyms and
/// wrapper transitions alike. Bounds a library that accidentally loops.
const MAX_RESOLUTION_STEPS: usize = 16;

/// Whether a path names one program or a set of them. Safe because [`Glob`]
/// has no escape syntax and neither character occurs in a path we have seen
/// an action run.
fn is_pattern(path: &str) -> bool {
    path.contains(['*', '?'])
}

/// A spec for a program whose output is a function of its inputs however it
/// is invoked.
pub(super) fn always() -> ReproducibilitySpec {
    ReproducibilitySpec::new(
        Reproducibility::Always,
        [] as [&str; 0],
        [] as [&str; 0],
    )
}

/// A spec for a program no set of flags can make reproducible.
pub(super) fn never() -> ReproducibilitySpec {
    ReproducibilitySpec::new(
        Reproducibility::Never,
        [] as [&str; 0],
        [] as [&str; 0],
    )
}

/// A spec for a program that works from what the machine has: one Bazel
/// wrote by inspecting it, or one that runs a tool installed on it.
pub(super) fn host_derived() -> ReproducibilitySpec {
    ReproducibilitySpec::new(
        Reproducibility::HostDerived,
        [] as [&str; 0],
        [] as [&str; 0],
    )
}

/// The library Ahab ships with.
fn entries() -> Vec<(ProgramId, Entry)> {
    let mut entries = super::per_lang::rust::entries();
    entries.extend(super::per_lang::apple::entries());
    entries.extend(super::per_lang::cc::entries());
    entries.extend(super::per_lang::container::entries());
    entries.extend(super::per_lang::go::entries());
    entries.extend(super::per_lang::java::entries());
    entries.extend(super::per_lang::js::entries());
    entries.extend(super::per_lang::kotlin::entries());
    entries.extend(super::per_lang::pkg::entries());
    entries.extend(super::per_lang::python::entries());
    entries.extend(super::per_lang::zig::entries());
    entries.extend(language_agnostic());
    entries
}

/// The `coreutils` subcommands that answer with something about the machine
/// rather than about the inputs. Matched against whole arguments, so a file
/// named `date` is reported too: a clause cannot ask about position, and
/// that is the safe direction.
const HOST_SUBCOMMANDS: [&str; 20] = [
    "arch", "date", "df", "env", "groups", "hostid", "hostname", "id",
    "logname", "mktemp", "nproc", "printenv", "pwd", "shuf", "stat",
    "stty", "touch", "tty", "uname", "whoami",
];

/// A tool from a toolchain the bazel_lib module registers. The module was
/// `aspect_bazel_lib` up to 2.x and `bazel_lib` from 3.0, and both are in
/// the wild, so each tool answers to both names.
pub(super) fn bazel_lib(tool: &str) -> ProgramId {
    ProgramId::extension("bazel_lib", "toolchains", tool)
}

/// The same tool under the name the 2.x module went by.
pub(super) fn aspect_bazel_lib(tool: &str) -> ProgramId {
    ProgramId::extension("aspect_bazel_lib", "toolchains", tool)
}

/// Entries for tools no one language owns.
fn language_agnostic() -> Vec<(ProgramId, Entry)> {
    vec![
        // One binary standing in for the whole of coreutils, which the
        // bazel_lib rules use wherever they would need a shell. It also
        // carries `date`, `hostname` and `uname`, which `always` would be
        // vouching for, so the clause names them instead.
        (
            bazel_lib("coreutils"),
            Entry::Spec(
                ReproducibilitySpec::new(
                    Reproducibility::Sometimes,
                    [] as [&str; 0],
                    [] as [&str; 0],
                )
                .with_clauses(
                    [] as [Clause; 0],
                    [Clause {
                        when: None,
                        any_of: HOST_SUBCOMMANDS
                            .into_iter()
                            .map(Glob::new)
                            .collect(),
                        because: "it was asked for something the machine \
                                  knows rather than something the build \
                                  gave it"
                            .to_owned(),
                    }],
                ),
            ),
        ),
        (
            aspect_bazel_lib("coreutils"),
            Entry::SameAs(bazel_lib("coreutils")),
        ),
        // The two copiers every rule set built on bazel_lib uses to
        // assemble a directory. Both write the same bytes out, with no
        // clock and nothing read that was not handed to them.
        //
        // The tree they leave has modification times that are a function of
        // nothing, deliberately not stated as a condition: Bazel compares a
        // tree by digests, so those times reach an artifact only if
        // something downstream turns them into content—and that tool
        // answers for it where it happens.
        (bazel_lib("copy_to_directory"), Entry::Spec(always())),
        (
            aspect_bazel_lib("copy_to_directory"),
            Entry::SameAs(bazel_lib("copy_to_directory")),
        ),
        (bazel_lib("copy_directory"), Entry::Spec(always())),
        (
            aspect_bazel_lib("copy_directory"),
            Entry::SameAs(bazel_lib("copy_directory")),
        ),
        // A pure function of the descriptors it is given, arriving either
        // prebuilt from the extension or as protobuf's own `cc_binary`.
        (
            ProgramId::extension("protobuf", "protoc", "bin/protoc"),
            Entry::Spec(always()),
        ),
        (
            ProgramId::module("protobuf", "protoc"),
            Entry::SameAs(ProgramId::extension(
                "protobuf",
                "protoc",
                "bin/protoc",
            )),
        ),
        // A third way: "the protobuf compiler without code generators",
        // which the proto rules run for a descriptor set.
        (
            ProgramId::module(
                "protobuf",
                "src/google/protobuf/compiler/protoc_minimal",
            ),
            Entry::SameAs(ProgramId::extension(
                "protobuf",
                "protoc",
                "bin/protoc",
            )),
        ),
        // Bazel's own zip tool. Where a zip normally records the moment
        // each entry was added, zipper writes one constant—2010-01-01,
        // observed across all 2237 entries of a real archive.
        (
            ProgramId::module("bazel_tools", "tools/zip/zipper/zipper"),
            Entry::Spec(always()),
        ),
        // The same binary under the path it is built at: `//tools/zip:zipper`
        // is an alias for `//third_party/ijar:zipper`.
        (
            ProgramId::module("bazel_tools", "third_party/ijar/zipper"),
            Entry::SameAs(ProgramId::module(
                "bazel_tools",
                "tools/zip/zipper/zipper",
            )),
        ),
        // Bazel's test shim. Its log and JUnit XML carry timings and are
        // never byte-identical, but they are terminal: no other action
        // consumes them, so that variation cannot reach an artifact.
        (
            ProgramId::module("bazel_tools", "tools/test/test-setup.sh"),
            Entry::Spec(always()),
        ),
    ]
}

/// What an action's command line turned out to be, once wrappers have been
/// unwrapped and synonyms followed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution<'a> {
    /// The program whose reproducibility actually decides the action's: the
    /// innermost command after unwrapping. Equal to the program asked about
    /// when nothing wrapped it.
    pub program: ProgramId,
    /// That program's arguments, i.e. its `argv[1..]`.
    pub args: Vec<&'a str>,
    /// The wrappers passed through to reach it, outermost first. Empty when
    /// the action ran the program directly.
    pub wrappers: Vec<ProgramId>,
    /// The spec answering for [`program`](Self::program), with the program
    /// that carried it—the same one unless a synonym was followed.
    pub spec: Option<(ProgramId, ReproducibilitySpec)>,
}

impl Resolution<'_> {
    /// The program whose spec judged [`program`](Self::program), when a
    /// synonym was followed or a pattern entry answered. `None` when the
    /// program answered for itself.
    pub fn synonym(&self) -> Option<&ProgramId> {
        self.spec
            .as_ref()
            .map(|(carrier, _)| carrier)
            .filter(|carrier| **carrier != self.program)
    }
}

/// An entry whose key names a set of programs rather than one.
#[derive(Debug, Clone)]
struct PatternEntry {
    /// The key as written, which is what gets reported when it answers.
    key: ProgramId,
    /// Its path, compiled.
    path: Glob,
    /// What it says.
    entry: Entry,
}

/// What Ahab knows about programs: the built-in entries, plus whatever a
/// project has added. A key's path may be a glob, for the rule sets that put
/// something unstable in the path itself.
#[derive(Debug, Clone, Default)]
pub struct Library {
    /// Entries whose path is literal, which is nearly all of them.
    exact: HashMap<ProgramId, Entry>,
    /// Entries whose path is a glob, oldest first.
    patterns: Vec<PatternEntry>,
}

impl Library {
    /// The library Ahab ships with.
    pub fn builtin() -> Library {
        let mut library = Library::default();
        library.extend(entries());
        library
    }

    /// Add entries, replacing any already present for the same program.
    /// Later entries win, and a pattern added again moves to the end so
    /// that holds for patterns too.
    pub fn extend(
        &mut self,
        entries: impl IntoIterator<Item = (ProgramId, Entry)>,
    ) {
        for (key, entry) in entries {
            if is_pattern(&key.path) {
                self.patterns.retain(|held| held.key != key);
                self.patterns.push(PatternEntry {
                    path: Glob::new(&key.path),
                    key,
                    entry,
                });
            } else {
                self.exact.insert(key, entry);
            }
        }
    }

    /// The entry answering for `key`, with the key that carried it. An
    /// exact key beats any pattern; between patterns, the last added wins.
    fn lookup(&self, key: &ProgramId) -> Option<(&ProgramId, &Entry)> {
        if let Some((found, entry)) = self.exact.get_key_value(key) {
            return Some((found, entry));
        }
        self.patterns
            .iter()
            .rev()
            .find(|held| {
                held.key.origin == key.origin
                    && held.path.matches(&key.path)
            })
            .map(|held| (&held.key, &held.entry))
    }

    /// Resolve what an action really runs, following [`Entry::Wraps`] and
    /// [`Entry::SameAs`] until a program carries a spec, is unknown, or
    /// comes from outside the build. An unknown program is a verdict for
    /// the caller to report, not a failure here.
    pub fn resolve<'a>(
        &self,
        program: ProgramId,
        args: Vec<&'a str>,
    ) -> Resolution<'a> {
        let mut program = program;
        let mut key = program.clone();
        let mut args = args;
        let mut wrappers = Vec::new();

        for _ in 0..MAX_RESOLUTION_STEPS {
            // Unwrapping one would be pretending we know what it does:
            // `bash -c` runs a whole script, not a single command.
            if program.origin == Origin::System {
                break;
            }

            let Some((found, entry)) = self.lookup(&key) else {
                break;
            };

            match entry {
                Entry::Spec(spec) => {
                    return Resolution {
                        program,
                        args,
                        wrappers,
                        spec: Some((found.clone(), spec.clone())),
                    };
                }
                Entry::SameAs(target) => key = target.clone(),
                Entry::Wraps(transition) => {
                    let Some((wrapped, rest)) = transition.apply(&args)
                    else {
                        break;
                    };
                    wrappers.push(program);
                    program = ProgramId::of(wrapped);
                    key = program.clone();
                    args = rest;
                }
            }
        }

        Resolution {
            program,
            args,
            wrappers,
            spec: None,
        }
    }
}

/// The JSON form of a `--repro-specs` file: an object keyed by program.
#[derive(Debug, Deserialize)]
struct SpecFile {
    /// What the file says about each program.
    programs: BTreeMap<String, EntryFile>,
}

/// The JSON form of an [`Entry`]. Separate from `Entry` so the format is
/// not hostage to the internal representation, and can be spelled the way a
/// person would write it.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EntryFile {
    /// The program's own reproducibility.
    Spec(SpecFields),
    /// The program is judged by another program's spec.
    SameAs(String),
    /// The program runs another named in its arguments.
    Wraps(TransitionFile),
}

/// The JSON form of a [`ReproducibilitySpec`].
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SpecFields {
    /// The baseline disposition.
    reproducibility: Reproducibility,
    /// Patterns an invocation must match for the program to be
    /// reproducible.
    #[serde(default)]
    required_flags: BTreeSet<String>,
    /// Patterns whose match breaks its reproducibility, written the same
    /// way.
    #[serde(default)]
    breaking_flags: BTreeSet<String>,
    /// Clauses an invocation must satisfy, each of which may be guarded and
    /// may offer alternatives. The long form of `required_flags`.
    #[serde(default)]
    requirements: Vec<ClauseFields>,
    /// Clauses an invocation must not satisfy. The long form of
    /// `breaking_flags`.
    #[serde(default)]
    prohibitions: Vec<ClauseFields>,
    /// Flags whose value is the argument that follows them.
    #[serde(default)]
    takes_value: BTreeSet<String>,
    /// Options in which an absolute path describes what the program
    /// produces rather than the machine producing it.
    #[serde(default)]
    declared_paths: BTreeSet<String>,
    /// Arguments that stand for a different option, as `argument -> option`.
    /// Anything unlisted stands for itself.
    #[serde(default)]
    recognize: BTreeMap<String, String>,
}

/// The JSON form of a [`Clause`].
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClauseFields {
    /// What the clause is about, quoted back in the report.
    because: String,
    /// The patterns, any one of which satisfies it.
    any_of: BTreeSet<String>,
    /// The condition under which it applies. Absent is always.
    #[serde(default)]
    when: Option<GuardFields>,
}

/// The JSON form of a [`Guard`].
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GuardFields {
    /// Flags that turn the condition on.
    family: BTreeSet<String>,
    /// Flags of the same family that turn it off again.
    #[serde(default)]
    off: BTreeSet<String>,
}

impl From<ClauseFields> for Clause {
    fn from(fields: ClauseFields) -> Clause {
        Clause {
            when: fields.when.map(|guard| Guard {
                family: guard.family.iter().map(|f| Glob::new(f)).collect(),
                off: guard.off.iter().map(|f| Glob::new(f)).collect(),
            }),
            any_of: fields.any_of.iter().map(|f| Glob::new(f)).collect(),
            because: fields.because,
        }
    }
}

/// The JSON form of a [`Transition`].
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TransitionFile {
    /// The wrapped command follows this separator.
    AfterSeparator(String),
    /// The wrapped command is the first argument.
    FirstArgument,
}

/// Parse the entries a `--repro-specs` file declares. Errors name the
/// program at fault, a serde error alone giving only a position.
pub fn parse_entries(
    json: &str,
) -> Result<Vec<(ProgramId, Entry)>, String> {
    let file: SpecFile =
        serde_json::from_str(json).map_err(|why| why.to_string())?;

    file.programs
        .into_iter()
        .map(|(program, entry)| {
            let named = |what: &str, text: &str| {
                text.parse::<ProgramId>()
                    .map_err(|why| format!("{program}: {what}: {why}"))
            };
            let id = named("program", &program)?;
            let entry = match entry {
                EntryFile::Spec(fields) => Entry::Spec(
                    ReproducibilitySpec::new(
                        fields.reproducibility,
                        fields.required_flags,
                        fields.breaking_flags,
                    )
                    .with_clauses(
                        fields.requirements.into_iter().map(Clause::from),
                        fields.prohibitions.into_iter().map(Clause::from),
                    )
                    .with_valued_flags(fields.takes_value)
                    .with_declared_paths(fields.declared_paths)
                    .with_translations(fields.recognize),
                ),
                EntryFile::SameAs(target) => {
                    Entry::SameAs(named("same_as", &target)?)
                }
                EntryFile::Wraps(TransitionFile::FirstArgument) => {
                    Entry::Wraps(Transition::FirstArgument)
                }
                EntryFile::Wraps(TransitionFile::AfterSeparator(
                    separator,
                )) => {
                    Entry::Wraps(Transition::AfterSeparator { separator })
                }
            };
            Ok((id, entry))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reproducibility_spec::program_id::Origin;

    #[test]
    fn the_zip_tool_is_vouched_for_however_it_is_asked_to_pack() {
        let resolution = Library::builtin().resolve(
            ProgramId::module("bazel_tools", "tools/zip/zipper/zipper"),
            vec![
                "cC",
                "bazel-out/k8-fastbuild/bin/tool.zip",
                "__main__.py=bazel-out/k8-fastbuild/bin/tool.temp",
                "runfiles/_main/__init__.py=",
            ],
        );
        let (_, spec) = resolution.spec.expect("a spec for zipper");
        assert_eq!(
            spec.assess(resolution.args),
            crate::reproducibility_spec::Conformance::Reproducible,
        );
    }

    /// A library holding exactly these entries and nothing built in.
    fn index(entries: Vec<(ProgramId, Entry)>) -> Library {
        let mut library = Library::default();
        library.extend(entries);
        library
    }

    fn resolve_bare<'a>(
        library: &Library,
        program: &ProgramId,
    ) -> Resolution<'a> {
        library.resolve(program.clone(), Vec::new())
    }

    fn spec_for(
        library: &Library,
        program: &ProgramId,
    ) -> Option<ReproducibilitySpec> {
        resolve_bare(library, program).spec.map(|(_, spec)| spec)
    }

    fn a() -> ProgramId {
        ProgramId::module("a", "bin/a")
    }

    fn b() -> ProgramId {
        ProgramId::module("b", "bin/b")
    }

    fn c() -> ProgramId {
        ProgramId::module("c", "bin/c")
    }

    fn wraps_after_dashdash() -> Entry {
        Entry::Wraps(Transition::AfterSeparator {
            separator: "--".to_owned(),
        })
    }

    #[test]
    fn a_program_the_library_does_not_name_has_no_spec() {
        assert!(
            Library::builtin()
                .resolve(ProgramId::of("/usr/bin/gcc"), vec![])
                .spec
                .is_none()
        );
        assert!(
            Library::builtin()
                .resolve(ProgramId::of("external/llvm+/bin/clang"), vec![])
                .spec
                .is_none()
        );
    }

    #[test]
    fn every_synonym_in_the_library_points_at_a_real_entry() {
        let library = Library::builtin();
        for (program, _) in entries() {
            let mut seen = vec![program.clone()];
            let mut at = program.clone();
            for _ in 0..MAX_RESOLUTION_STEPS {
                let Some((_, Entry::SameAs(target))) = library.lookup(&at)
                else {
                    break;
                };
                let target = target.clone();
                assert!(
                    !is_pattern(&target.path),
                    "{program}: synonym points at {target}, which is a \
                     pattern—a synonym has to name one program",
                );
                assert!(
                    library.lookup(&target).is_some(),
                    "{program}: synonym points at {target}, \
                     which is not in the library",
                );
                assert!(
                    !seen.contains(&target),
                    "{program}: synonym chain cycles at {target}",
                );
                seen.push(target.clone());
                at = target;
            }
        }
    }

    fn library_of(
        entries: impl IntoIterator<Item = (ProgramId, Entry)>,
    ) -> Library {
        let mut library = Library::default();
        library.extend(entries);
        library
    }

    #[test]
    fn a_pattern_answers_for_every_program_whose_path_it_matches() {
        let library = library_of([(
            ProgramId::extension("r", "toolchains", "*/bin/rustc"),
            Entry::Spec(always()),
        )]);
        for path in [
            "external/r++toolchains+tc/linux_x86_64_1_86_0/bin/rustc",
            "external/r++toolchains+tc/macos_arm64_1_99_0/bin/rustc",
        ] {
            let resolved = library.resolve(ProgramId::of(path), vec![]);
            assert!(
                resolved.spec.is_some(),
                "{path} was not matched by the pattern",
            );
        }
    }

    #[test]
    fn a_pattern_does_not_reach_across_repositories() {
        let library = library_of([(
            ProgramId::extension("r", "toolchains", "*/bin/rustc"),
            Entry::Spec(always()),
        )]);
        let elsewhere =
            ProgramId::of("external/other++toolchains+tc/x/bin/rustc");
        assert!(library.resolve(elsewhere, vec![]).spec.is_none());
    }

    #[test]
    fn naming_a_program_outright_beats_a_pattern_that_covers_it() {
        let exact = ProgramId::extension("r", "toolchains", "x/bin/rustc");
        let library = library_of([
            (exact.clone(), Entry::Spec(never())),
            (
                ProgramId::extension("r", "toolchains", "*/bin/rustc"),
                Entry::Spec(always()),
            ),
        ]);
        let resolved = library.resolve(exact.clone(), vec![]);
        let (carrier, spec) = resolved.spec.expect("no spec");
        assert_eq!(carrier, exact);
        assert_eq!(spec, never());
    }

    #[test]
    fn a_later_pattern_wins_over_an_earlier_one() {
        let library = library_of([
            (
                ProgramId::extension("r", "toolchains", "*/bin/rustc"),
                Entry::Spec(always()),
            ),
            (
                ProgramId::extension("r", "toolchains", "*/rustc"),
                Entry::Spec(never()),
            ),
        ]);
        let resolved = library.resolve(
            ProgramId::of("external/r++toolchains+tc/x/bin/rustc"),
            vec![],
        );
        assert_eq!(resolved.spec.expect("no spec").1, never());
    }

    #[test]
    fn a_pattern_reports_the_key_that_answered() {
        let pattern =
            ProgramId::extension("r", "toolchains", "*/bin/rustc");
        let library =
            library_of([(pattern.clone(), Entry::Spec(always()))]);
        let resolved = library.resolve(
            ProgramId::of("external/r++toolchains+tc/x/bin/rustc"),
            vec![],
        );
        assert_eq!(resolved.synonym(), Some(&pattern));
    }

    #[test]
    fn a_pattern_can_stand_in_for_a_synonym() {
        let target = ProgramId::module("rules_rust", "bin/rustc");
        let library = library_of([
            (target.clone(), Entry::Spec(always())),
            (
                ProgramId::extension("r", "toolchains", "*/bin/rustc"),
                Entry::SameAs(target.clone()),
            ),
        ]);
        let resolved = library.resolve(
            ProgramId::of("external/r++toolchains+tc/x/bin/rustc"),
            vec![],
        );
        assert_eq!(resolved.synonym(), Some(&target));
    }

    #[test]
    fn a_program_outside_the_execution_root_is_the_machines() {
        let resolved = Library::builtin()
            .resolve(ProgramId::of("/usr/bin/gcc"), vec![]);
        assert_eq!(resolved.program.origin, Origin::System);
        assert!(resolved.spec.is_none());
    }

    #[test]
    fn a_declared_program_is_the_machines_wherever_it_sits() {
        let wrapper = ProgramId::extension(
            "rules_cc",
            "cc_configure_extension",
            "cc_wrapper.sh",
        );
        let resolved = Library::builtin().resolve(wrapper.clone(), vec![]);
        assert_ne!(resolved.program.origin, Origin::System);
        assert_eq!(
            resolved.spec.map(|(_, spec)| spec.reproducibility),
            Some(Reproducibility::HostDerived),
        );
        assert_eq!(
            resolved.program.to_string(),
            "@rules_cc+cc_configure_extension//cc_wrapper.sh",
        );
    }

    #[test]
    fn its_neighbours_in_the_same_repository_are_not() {
        let static_file = ProgramId::extension(
            "rules_cc",
            "cc_configure_extension",
            "armeabi_cc_toolchain_config.bzl",
        );
        let resolved = Library::builtin().resolve(static_file, vec![]);
        assert!(resolved.spec.is_none());
    }

    #[test]
    fn a_synonym_may_point_at_a_host_derived_program() {
        let library = index(vec![
            (a(), Entry::Spec(host_derived())),
            (b(), Entry::SameAs(a())),
        ]);
        assert_eq!(
            spec_for(&library, &b()).map(|spec| spec.reproducibility),
            Some(Reproducibility::HostDerived),
        );
    }

    #[test]
    fn no_key_appears_twice_in_the_library() {
        let authored = entries();
        let indexed: HashMap<_, _> = entries().into_iter().collect();
        assert_eq!(
            authored.len(),
            indexed.len(),
            "the library contains a duplicate key",
        );
    }

    #[test]
    fn a_program_with_its_own_spec_resolves_to_it() {
        let library = index(vec![(a(), Entry::Spec(always()))]);
        assert_eq!(spec_for(&library, &a()), Some(always()));
    }

    #[test]
    fn an_unknown_program_resolves_to_no_spec() {
        let library = index(vec![(a(), Entry::Spec(always()))]);
        assert_eq!(spec_for(&library, &b()), None);
    }

    #[test]
    fn a_synonym_resolves_to_its_targets_spec() {
        let library = index(vec![
            (a(), Entry::Spec(never())),
            (b(), Entry::SameAs(a())),
        ]);
        assert_eq!(spec_for(&library, &b()), Some(never()));
        assert_eq!(spec_for(&library, &a()), Some(never()));
    }

    #[test]
    fn synonyms_may_chain() {
        let library = index(vec![
            (a(), Entry::Spec(always())),
            (b(), Entry::SameAs(a())),
            (c(), Entry::SameAs(b())),
        ]);
        assert_eq!(spec_for(&library, &c()), Some(always()));
    }

    #[test]
    fn a_synonym_pointing_nowhere_resolves_to_no_spec() {
        let library = index(vec![(b(), Entry::SameAs(a()))]);
        assert_eq!(spec_for(&library, &b()), None);
    }

    #[test]
    fn a_synonym_cycle_terminates() {
        let library = index(vec![
            (a(), Entry::SameAs(b())),
            (b(), Entry::SameAs(a())),
        ]);
        assert_eq!(spec_for(&library, &a()), None);
    }

    #[test]
    fn a_self_referential_synonym_terminates() {
        let library = index(vec![(a(), Entry::SameAs(a()))]);
        assert_eq!(spec_for(&library, &a()), None);
    }

    #[test]
    fn a_chain_longer_than_the_step_limit_gives_up() {
        let chain = |links: usize| {
            let hop =
                |i: usize| ProgramId::module("m", &format!("bin/{i}"));
            let mut entries: Vec<(ProgramId, Entry)> = (0..links)
                .map(|i| (hop(i), Entry::SameAs(hop(i + 1))))
                .collect();
            entries.push((hop(links), Entry::Spec(always())));
            (index(entries), hop(0))
        };

        let (library, start) = chain(MAX_RESOLUTION_STEPS - 1);
        assert_eq!(spec_for(&library, &start), Some(always()));

        let (library, start) = chain(MAX_RESOLUTION_STEPS);
        assert_eq!(spec_for(&library, &start), None);
    }

    #[test]
    fn a_synonym_does_not_change_the_program_the_action_ran() {
        let library = index(vec![
            (a(), Entry::Spec(always())),
            (b(), Entry::SameAs(a())),
        ]);
        let resolved = resolve_bare(&library, &b());
        assert_eq!(resolved.program, b());
        assert_eq!(resolved.synonym(), Some(&a()));
        assert_eq!(resolved.spec.map(|(carrier, _)| carrier), Some(a()));
    }

    #[test]
    fn a_program_with_its_own_spec_reports_no_synonym() {
        let library = index(vec![(a(), Entry::Spec(always()))]);
        assert_eq!(resolve_bare(&library, &a()).synonym(), None);
    }

    #[test]
    fn an_unknown_program_reports_no_synonym() {
        let library = index(vec![(b(), Entry::SameAs(a()))]);
        assert_eq!(resolve_bare(&library, &b()).synonym(), None);
    }

    #[test]
    fn a_wrapper_resolves_to_the_command_it_runs() {
        let library = index(vec![
            (a(), wraps_after_dashdash()),
            (b(), Entry::Spec(never())),
        ]);
        let resolved = library.resolve(
            a(),
            vec!["--arg-file", "x", "--", "external/b+/bin/b", "--opt"],
        );
        assert_eq!(resolved.program, ProgramId::of("external/b+/bin/b"));
        assert_eq!(resolved.args, vec!["--opt"]);
        assert_eq!(resolved.wrappers, vec![a()]);
        assert_eq!(resolved.spec.map(|(_, s)| s.clone()), Some(never()));
    }

    #[test]
    fn a_wrappers_own_flags_are_not_assessed() {
        let library = index(vec![(a(), wraps_after_dashdash())]);
        let resolved = library.resolve(
            a(),
            vec!["--subst", "pwd=x", "--", "external/b+/bin/b"],
        );
        assert_eq!(resolved.args, Vec::<&str>::new());
    }

    #[test]
    fn wrappers_may_nest() {
        let library = index(vec![
            (a(), wraps_after_dashdash()),
            (b(), wraps_after_dashdash()),
            (c(), Entry::Spec(always())),
        ]);
        let resolved = library.resolve(
            a(),
            vec![
                "--",
                "external/b+/bin/b",
                "--",
                "external/c+/bin/c",
                "-O2",
            ],
        );
        assert_eq!(resolved.program, c());
        assert_eq!(resolved.args, vec!["-O2"]);
        assert_eq!(resolved.wrappers, vec![a(), b()]);
    }

    #[test]
    fn a_wrapper_can_unwrap_onto_a_system_program() {
        let library = index(vec![(a(), wraps_after_dashdash())]);
        let resolved = library.resolve(a(), vec!["--", "/usr/bin/gcc"]);
        assert_eq!(resolved.program.origin, Origin::System);
        assert_eq!(resolved.wrappers, vec![a()]);
        assert!(resolved.spec.is_none());
    }

    #[test]
    fn a_transition_that_does_not_fire_leaves_the_wrapper_in_place() {
        let library = index(vec![(a(), wraps_after_dashdash())]);
        let resolved = library.resolve(a(), vec!["--arg-file", "x"]);
        assert_eq!(resolved.program, a());
        assert!(resolved.wrappers.is_empty());
        assert!(resolved.spec.is_none());
    }

    #[test]
    fn a_separator_with_nothing_after_it_does_not_fire() {
        let library = index(vec![(a(), wraps_after_dashdash())]);
        let resolved = library.resolve(a(), vec!["--"]);
        assert_eq!(resolved.program, a());
        assert!(resolved.spec.is_none());
    }

    #[test]
    fn only_the_first_separator_splits_the_command() {
        let library = index(vec![
            (a(), wraps_after_dashdash()),
            (b(), Entry::Spec(always())),
        ]);
        let resolved = library
            .resolve(a(), vec!["--", "external/b+/bin/b", "--", "tail"]);
        assert_eq!(resolved.program, ProgramId::of("external/b+/bin/b"));
        assert_eq!(resolved.args, vec!["--", "tail"]);
    }

    #[test]
    fn a_wrapper_cycle_terminates() {
        let library = index(vec![(a(), wraps_after_dashdash())]);
        let args: Vec<&str> =
            std::iter::repeat_n(["--", "external/a+/bin/a"], 40)
                .flatten()
                .collect();
        let resolved = library.resolve(a(), args);
        assert!(resolved.spec.is_none());
    }
}
