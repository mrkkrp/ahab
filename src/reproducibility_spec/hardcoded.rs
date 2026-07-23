//! The hardcoded library of known [`ReproducibilitySpec`]s, keyed by program.
//!
//! Over time this will accumulate hundreds of entries — one per tool whose
//! reproducibility we understand (compilers, linkers, archivers, code
//! generators, …). It starts empty: until a program is added here, Ahab has no
//! reproducibility knowledge of it and [`lookup`] returns `None`, which the
//! reproducibility check treats conservatively as an error rather than a pass.

use super::ReproducibilitySpec;

/// Look up the reproducibility spec for the program identified by `program`.
///
/// `program` is the *base name* of the executable an action runs (see
/// [`program_name`]), e.g. `gcc` or `clang`. Returns `None` when we have no spec
/// for that program — callers must treat an unknown program conservatively.
pub fn lookup(program: &str) -> Option<ReproducibilitySpec> {
    // The library is intentionally empty for now; specs are added here one tool
    // at a time, e.g.:
    //
    //     "gcc" => Some(ReproducibilitySpec::new(...)),
    //
    // Until then every program is unknown.
    let _ = program;
    None
}

/// Reduce an action's executable path (typically `argv[0]`) to the base name we
/// key specs by: the final path component, e.g. `/usr/bin/gcc` -> `gcc`,
/// `external/llvm/bin/clang` -> `clang`. An empty input yields an empty name.
pub fn program_name(executable: &str) -> &str {
    executable
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(executable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn library_is_empty_so_everything_is_unknown() {
        assert!(lookup("gcc").is_none());
        assert!(lookup("clang").is_none());
        assert!(lookup("").is_none());
    }

    #[test]
    fn program_name_takes_the_final_path_component() {
        assert_eq!(program_name("/usr/bin/gcc"), "gcc");
        assert_eq!(program_name("external/llvm/bin/clang"), "clang");
        assert_eq!(program_name("gcc"), "gcc");
        assert_eq!(program_name(""), "");
    }
}
