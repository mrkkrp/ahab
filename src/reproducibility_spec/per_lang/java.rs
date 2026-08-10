use super::super::library::{Entry, always};
use super::super::program_id::ProgramId;

/// A program in Stardoc, the generator of Starlark documentation.
fn stardoc(path: &str) -> ProgramId {
    ProgramId::module("stardoc", path)
}

/// Stardoc's renderer, which turns an extracted description of a Starlark
/// file into markdown.
const RENDERER: &str =
    "src/main/java/com/google/devtools/build/stardoc/renderer/renderer";

/// Everything Ahab knows about JVM programs, in source order.
pub(in crate::reproducibility_spec) fn entries() -> Vec<(ProgramId, Entry)>
{
    vec![
        // Every input the renderer has is named on the command line and
        // built by the same build: `--input` is a serialized proto that an
        // earlier action extracted from the Starlark, and the seven
        // templates are Velocity files shipped inside Stardoc. It reads
        // those, fills them in, and writes one markdown file. Nothing is
        // read from the environment and no path is absolute, so two runs
        // over the same proto have nothing to disagree about.
        //
        // The JVM underneath is not part of this claim, and does not need
        // to be: filling in a template is not the sort of work whose answer
        // depends on which Java is running it.
        (stardoc(RENDERER), Entry::Spec(always())),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reproducibility_spec::Conformance;
    use crate::reproducibility_spec::library::Library;

    /// A Renderer command line as Stardoc's rule writes it, with the
    /// templates trimmed to two of the seven.
    fn renderer_args() -> Vec<&'static str> {
        vec![
            "--input=bazel-out/k8-fastbuild/bin/docs/x.extract.binaryproto",
            "--output=bazel-out/k8-fastbuild/bin/docs/extensions.md",
            "--header_template=external/stardoc+/stardoc/templates\
             /markdown_tables/header.vm",
            "--rule_template=external/stardoc+/stardoc/templates\
             /markdown_tables/rule.vm",
        ]
    }

    #[test]
    fn the_renderer_is_reproducible_as_stardoc_invokes_it() {
        let resolution =
            Library::builtin().resolve(stardoc(RENDERER), renderer_args());
        let (_, spec) = resolution.spec.expect("a spec for the renderer");
        assert_eq!(spec.assess(resolution.args), Conformance::Reproducible);
    }

    #[test]
    fn the_renderer_is_named_in_the_module_that_ships_it() {
        // Stardoc arrives as a plain module, so there is no extension in
        // the identity—unlike the Go builder, which is built per SDK.
        assert!(
            Library::builtin()
                .resolve(stardoc(RENDERER), vec![])
                .spec
                .is_some()
        );
        // The same path in the main module is somebody else's program.
        assert!(
            Library::builtin()
                .resolve(ProgramId::main(RENDERER), vec![])
                .spec
                .is_none()
        );
    }
}
