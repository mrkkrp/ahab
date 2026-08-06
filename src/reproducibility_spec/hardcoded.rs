//! The hardcoded library of known [`ReproducibilitySpec`]s, keyed by program.
//!
//! Over time this will accumulate hundreds of entries — one per tool whose
//! reproducibility we understand (compilers, linkers, archivers, code
//! generators, …). It starts empty: until a program is added here, Ahab has no
//! reproducibility knowledge of it and [`lookup`] returns `None`, which the
//! reproducibility check treats conservatively as an error rather than a pass.
//!
//! Entries are keyed by [`ProgramId`], so a spec is written against a normalized
//! identity such as `@rules_rust//util/process_wrapper/process_wrapper` rather
//! than against a raw exec path. See [`super::program_id`] for what that
//! normalization removes and why; the practical consequence for spec authors is
//! that a key never mentions a compilation mode, a Bazel version, a dependency
//! version, a host platform, or a repository name the analyzed project chose.

use super::program_id::ProgramId;
use super::ReproducibilitySpec;

/// Look up the reproducibility spec for `program`.
///
/// Returns `None` when we have no spec for that program — callers must treat an
/// unknown program conservatively.
pub fn lookup(program: &ProgramId) -> Option<ReproducibilitySpec> {
    // The library is intentionally empty for now; specs are added here one tool
    // at a time, matching on the rendered identity, e.g.:
    //
    //     match program.to_string().as_str() {
    //         "@rules_rust//util/process_wrapper/process_wrapper" => Some(...),
    //         _ => None,
    //     }
    //
    // Until then every program is unknown.
    let _ = program;
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn library_is_empty_so_everything_is_unknown() {
        assert!(lookup(&ProgramId::of("/usr/bin/gcc")).is_none());
        assert!(lookup(&ProgramId::of("external/llvm+/bin/clang")).is_none());
        assert!(lookup(&ProgramId::of("")).is_none());
    }
}
