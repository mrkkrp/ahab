pub(super) mod cc;
pub(super) mod go;
pub(super) mod java;
pub(super) mod kotlin;
pub(super) mod rust;

/// Helpers every per-language test module needs.
#[cfg(test)]
pub(super) mod testing {
    use super::super::Conformance;
    use super::super::library::Library;
    use super::super::program_id::ProgramId;
    use std::collections::BTreeSet;

    /// The built-in library's verdict on this invocation.
    ///
    /// Panics when the program has no spec at all: a test that meant to ask
    /// about an unknown program should say so directly rather than read it
    /// out of a verdict that was never reached.
    pub(in crate::reproducibility_spec::per_lang) fn assess(
        program: ProgramId,
        args: Vec<&str>,
    ) -> Conformance {
        let resolution = Library::builtin().resolve(program, args);
        let (_, spec) = resolution.spec.expect("a spec for the program");
        spec.assess(resolution.args)
    }

    /// Assert that the given lookup returns a conditional conformance
    /// verdict, then return what would satisfy it.
    pub(in crate::reproducibility_spec::per_lang) fn missing(
        program: ProgramId,
        args: Vec<&str>,
    ) -> BTreeSet<String> {
        let verdict = assess(program, args);
        assert!(
            matches!(verdict, Conformance::Conditional { .. }),
            "expected a conditional verdict, got {verdict:?}",
        );
        verdict.missing_required()
    }
}
