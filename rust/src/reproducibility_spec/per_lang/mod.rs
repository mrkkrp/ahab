pub(super) mod apple;
pub(super) mod cc;
pub(super) mod container;
pub(super) mod go;
pub(super) mod java;
pub(super) mod js;
pub(super) mod kotlin;
pub(super) mod pkg;
pub(super) mod python;
pub(super) mod rust;
pub(super) mod zig;

/// Helpers every per-language test module needs.
#[cfg(test)]
pub(super) mod testing {
    use super::super::Conformance;
    use super::super::library::Library;
    use super::super::program_id::ProgramId;
    use std::collections::BTreeSet;

    /// The built-in library's verdict on this invocation. Panics when the
    /// program has no spec at all.
    pub(in crate::reproducibility_spec::per_lang) fn assess(
        program: ProgramId,
        args: Vec<&str>,
    ) -> Conformance {
        let resolution = Library::builtin().resolve(program, args);
        let (_, spec) = resolution.spec.expect("a spec for the program");
        spec.assess(resolution.args)
    }

    /// Assert a conditional verdict, then return what would satisfy it.
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
