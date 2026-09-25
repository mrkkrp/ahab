//! Identifying a script by the template it was expanded from.

use std::collections::{BTreeSet, HashMap};

use analysis_v2_proto::analysis::{
    ActionGraphContainer, DepSetOfFiles, PathFragment,
};

use super::artifact_path;
use crate::reproducibility_spec::{
    library::Library, program_id::ProgramId,
};

/// The mnemonic of the action `ctx.actions.expand_template` registers.
const TEMPLATE_EXPAND: &str = "TemplateExpand";

/// The template each file a `TemplateExpand` action writes was expanded
/// from, both as execution-root-relative paths.
#[derive(Debug, Default)]
pub(crate) struct Templates(HashMap<String, String>);

impl Templates {
    /// Collect the expansions `container` describes.
    pub(crate) fn of(container: &ActionGraphContainer) -> Templates {
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
                expanded.insert(output, template);
            }
        }
        Templates(expanded)
    }

    /// The program `executable` names: the template it was expanded from if
    /// `library` knows that template, otherwise the executable itself.
    pub(crate) fn program(
        &self,
        executable: &str,
        library: &Library,
    ) -> ProgramId {
        self.0
            .get(executable)
            .map(|template| ProgramId::of(template))
            .filter(|template| library.knows(template))
            .unwrap_or_else(|| ProgramId::of(executable))
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
    use analysis_v2_proto::analysis::{Action, Artifact};

    const SCRIPT: &str = "bazel-out/k8-fastbuild/bin/app/image_app.sh";

    /// A container in which `template` is expanded into [`SCRIPT`], which
    /// `run` then runs.
    fn expanded(template: &str, run: Action) -> ActionGraphContainer {
        let mut fragments = Vec::new();
        let mut artifacts = Vec::new();
        for path in [template, SCRIPT] {
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

    #[test]
    fn a_script_is_known_by_the_template_it_was_expanded_from() {
        let c = expanded(
            "external/rules_oci+/oci/private/image.sh",
            image(&[]),
        );
        assert_eq!(
            Templates::of(&c).program(SCRIPT, &Library::builtin(None)),
            ProgramId::module("rules_oci", "oci/private/image.sh"),
        );
    }

    #[test]
    fn a_template_the_library_does_not_know_leaves_the_script_as_it_is() {
        let c = expanded(
            "external/aspect_rules_js+/js/private/js_binary.sh.tpl",
            image(&[]),
        );
        assert_eq!(
            Templates::of(&c).program(SCRIPT, &Library::builtin(None)),
            ProgramId::of(SCRIPT),
        );
    }

    #[test]
    fn the_working_directory_of_an_image_is_not_an_absolute_path() {
        let c = expanded(
            "external/rules_oci+/oci/private/image.sh",
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
