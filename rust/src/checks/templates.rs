//! Identifying a script by the template it was expanded from.

use std::collections::{BTreeSet, HashMap};

use analysis_v2_proto::analysis::{
    ActionGraphContainer, DepSetOfFiles, PathFragment,
};

use super::artifact_path;
use crate::reproducibility_spec::{
    library::{Library, Resolution, Substitutions},
    program_id::ProgramId,
};

/// The mnemonic of the action `ctx.actions.expand_template` registers.
const TEMPLATE_EXPAND: &str = "TemplateExpand";

/// How a file a `TemplateExpand` action writes came about.
#[derive(Debug)]
struct Expansion<'a> {
    /// The template, as an execution-root-relative path.
    template: String,
    /// What was substituted into it.
    substitutions: Substitutions<'a>,
}

/// The expansion behind each file a `TemplateExpand` action writes, keyed
/// by its execution-root-relative path.
#[derive(Debug, Default)]
pub(crate) struct Templates<'a>(HashMap<String, Expansion<'a>>);

impl<'a> Templates<'a> {
    /// Collect the expansions `container` describes.
    pub(crate) fn of(container: &'a ActionGraphContainer) -> Templates<'a> {
        let fragments: HashMap<u32, &PathFragment> = container
            .path_fragments
            .iter()
            .map(|fragment| (fragment.id, fragment))
            .collect();
        let artifacts: HashMap<u32, u32> = container
            .artifacts
            .iter()
            .map(|artifact| (artifact.id, artifact.path_fragment_id))
            .collect();
        let sets: HashMap<u32, &DepSetOfFiles> = container
            .dep_set_of_files
            .iter()
            .map(|set| (set.id, set))
            .collect();
        let path = |artifact: u32| {
            artifact_path(*artifacts.get(&artifact)?, &fragments)
        };

        let mut expanded = HashMap::new();
        for action in &container.actions {
            if action.mnemonic != TEMPLATE_EXPAND {
                continue;
            }
            let inputs =
                direct_and_transitive(&action.input_dep_set_ids, &sets);
            let ([template], [output]) =
                (inputs.as_slice(), action.output_ids.as_slice())
            else {
                continue;
            };
            if let (Some(template), Some(output)) =
                (path(*template), path(*output))
            {
                let substitutions = action
                    .substitutions
                    .iter()
                    .map(|pair| (pair.key.as_str(), pair.value.as_str()))
                    .collect();
                expanded.insert(
                    output,
                    Expansion {
                        template,
                        substitutions,
                    },
                );
            }
        }
        Templates(expanded)
    }

    /// What running `executable` with `args` resolves to in `library`.
    /// The executable is known by the template it was expanded from when
    /// `library` knows that template and not the executable itself.
    pub(crate) fn resolve(
        &self,
        executable: &str,
        args: Vec<&'a str>,
        library: &Library,
    ) -> Resolution<'a> {
        let program = ProgramId::of(executable);
        let known = self
            .0
            .get(executable)
            .filter(|_| !library.knows(&program))
            .map(|expansion| {
                (ProgramId::of(&expansion.template), expansion)
            })
            .filter(|(template, _)| library.knows(template));
        match known {
            Some((template, expansion)) => library.resolve_expanded(
                template,
                args,
                &expansion.substitutions,
            ),
            None => library.resolve(program, args),
        }
    }
}

/// The artifacts in `roots` and every dep set they reach, deduplicated.
fn direct_and_transitive(
    roots: &[u32],
    sets: &HashMap<u32, &DepSetOfFiles>,
) -> Vec<u32> {
    let mut seen = BTreeSet::new();
    let mut found = BTreeSet::new();
    let mut stack = roots.to_vec();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        if let Some(set) = sets.get(&id) {
            found.extend(set.direct_artifact_ids.iter().copied());
            stack.extend(set.transitive_dep_set_ids.iter().copied());
        }
    }
    found.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::LeakSite;
    use crate::checks::tests::{
        action_with_args, assert_abs_path, check_absolute_paths, container,
    };
    use analysis_v2_proto::analysis::{Action, Artifact, KeyValuePair};

    const SCRIPT: &str = "bazel-out/k8-fastbuild/bin/app/image_app.sh";

    const LAUNCHER: &str = "bazel-out/k8-fastbuild/bin/app/gen_/gen";

    const JS_BINARY: &str =
        "external/aspect_rules_js+/js/private/js_binary.sh.tpl";

    /// A container in which `template` is expanded into `script` with
    /// `substitutions`, and `run` is then run.
    fn expanded(
        template: &str,
        script: &str,
        substitutions: &[(&str, &str)],
        run: Action,
    ) -> ActionGraphContainer {
        let mut fragments = Vec::new();
        let mut artifacts = Vec::new();
        for path in [template, script] {
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
            artifacts.push(Artifact {
                id: artifacts.len() as u32 + 1,
                path_fragment_id: parent,
                ..Default::default()
            });
        }
        let expand = Action {
            mnemonic: TEMPLATE_EXPAND.to_owned(),
            target_id: 1,
            input_dep_set_ids: vec![1],
            output_ids: vec![2],
            substitutions: substitutions
                .iter()
                .map(|(key, value)| KeyValuePair {
                    key: (*key).to_owned(),
                    value: (*value).to_owned(),
                })
                .collect(),
            ..Default::default()
        };
        ActionGraphContainer {
            dep_set_of_files: vec![DepSetOfFiles {
                id: 1,
                direct_artifact_ids: vec![1],
                ..Default::default()
            }],
            artifacts,
            path_fragments: fragments,
            ..container(vec![expand, run])
        }
    }

    fn image(args: &[&str]) -> Action {
        let mut argv = vec![SCRIPT];
        argv.extend(args);
        action_with_args("OCIImage", 1, &argv)
    }

    /// What the second action in `c` resolves to.
    fn resolve<'a>(
        c: &'a ActionGraphContainer,
        library: &Library,
    ) -> Resolution<'a> {
        let (executable, args) = c.actions[1]
            .arguments
            .split_first()
            .expect("a command line");
        Templates::of(c).resolve(
            executable,
            args.iter().map(String::as_str).collect(),
            library,
        )
    }

    #[test]
    fn a_script_is_known_by_the_template_it_was_expanded_from() {
        let c = expanded(
            "external/rules_oci+/oci/private/image.sh",
            SCRIPT,
            &[],
            image(&[]),
        );
        assert_eq!(
            resolve(&c, &Library::builtin(None)).program,
            ProgramId::module("rules_oci", "oci/private/image.sh"),
        );
    }

    #[test]
    fn a_template_the_library_does_not_know_leaves_the_script_as_it_is() {
        let c = expanded(
            "external/rules_acme+/acme/private/image.sh.tpl",
            SCRIPT,
            &[],
            image(&[]),
        );
        assert_eq!(
            resolve(&c, &Library::builtin(None)).program,
            ProgramId::of(SCRIPT),
        );
    }

    #[test]
    fn a_script_the_library_knows_keeps_its_own_name() {
        let tsc = "bazel-out/k8-opt-exec/bin/external\
                   /aspect_rules_ts++typescript+npm_typescript/tsc_/tsc";
        let c = expanded(
            JS_BINARY,
            tsc,
            &[("{{entry_point_path}}", "../typescript/bin/tsc")],
            action_with_args("TsProject", 1, &[tsc, "--project", "x"]),
        );
        let resolved = resolve(&c, &Library::builtin(None));
        assert_eq!(
            resolved.program,
            ProgramId::extension(
                "aspect_rules_ts",
                "typescript",
                "tsc_/tsc"
            ),
        );
        assert!(resolved.wrappers.is_empty());
    }

    #[test]
    fn a_js_binary_launcher_runs_its_entry_point_with_the_fixed_args() {
        let c = expanded(
            JS_BINARY,
            LAUNCHER,
            &[
                ("{{entry_point_path}}", "app/gen.mjs"),
                ("{{fixed_args}}", "--config-file app/gen.json  --quiet"),
            ],
            action_with_args("JsRunBinary", 1, &[LAUNCHER, "out.txt"]),
        );
        let resolved = resolve(&c, &Library::builtin(None));
        assert_eq!(resolved.program, ProgramId::main("app/gen.mjs"));
        assert_eq!(
            resolved.args,
            vec!["--config-file", "app/gen.json", "--quiet", "out.txt"],
        );
        assert_eq!(
            resolved.wrappers,
            vec![ProgramId::module(
                "aspect_rules_js",
                "js/private/js_binary.sh.tpl",
            )],
        );
    }

    #[test]
    fn launchers_of_one_entry_point_are_one_program() {
        let entry_point = "../npm+/node_modules/rollup/dist/bin/rollup";
        let programs: Vec<ProgramId> = ["app/a_/a", "lib/b_/b"]
            .map(|launcher| {
                let launcher =
                    format!("bazel-out/k8-fastbuild/bin/{launcher}");
                let c = expanded(
                    JS_BINARY,
                    &launcher,
                    &[("{{entry_point_path}}", entry_point)],
                    action_with_args("Rollup", 1, &[&launcher]),
                );
                resolve(&c, &Library::builtin(None)).program
            })
            .into();
        assert_eq!(programs[0], programs[1]);
        assert_eq!(
            programs[0],
            ProgramId::module("npm", "node_modules/rollup/dist/bin/rollup"),
        );
    }

    #[test]
    fn a_launcher_with_no_entry_point_is_the_template() {
        let c = expanded(
            JS_BINARY,
            LAUNCHER,
            &[],
            action_with_args("JsRunBinary", 1, &[LAUNCHER]),
        );
        let resolved = resolve(&c, &Library::builtin(None));
        assert_eq!(
            resolved.program,
            ProgramId::module(
                "aspect_rules_js",
                "js/private/js_binary.sh.tpl"
            ),
        );
        assert!(resolved.spec.is_none());
    }

    #[test]
    fn the_working_directory_of_an_image_is_not_an_absolute_path() {
        let c = expanded(
            "external/rules_oci+/oci/private/image.sh",
            SCRIPT,
            &[],
            image(&["--workdir=/root", "--from=/tmp/base"]),
        );
        let found = check_absolute_paths(&c, &Library::builtin(None));
        assert_eq!(found.len(), 1, "{found:?}");
        assert_abs_path(
            &found[0],
            "OCIImage",
            1,
            "/tmp/base",
            LeakSite::Argument {
                value: "--from=/tmp/base".to_owned(),
            },
        );
    }
}
