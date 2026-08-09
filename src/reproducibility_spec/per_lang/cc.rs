use super::super::library::{Entry, host_derived};
use super::super::program_id::ProgramId;

/// A program in the repository `cc_configure` generates from the host.
fn local_config_cc(path: &str) -> ProgramId {
    ProgramId::extension("rules_cc", "cc_configure_extension", path)
}

/// Everything Ahab knows about C++ builds, in source order.
pub(in crate::reproducibility_spec) fn entries() -> Vec<(ProgramId, Entry)>
{
    vec![
        // The compiler, one step removed. Its last line execs the `gcc` or
        // `clang` that configuration found, by absolute path.
        (
            local_config_cc("cc_wrapper.sh"),
            Entry::Spec(host_derived()),
        ),
        // Runs the host's `nm` and `c++filt` over an archive.
        (
            local_config_cc("validate_static_library.sh"),
            Entry::Spec(host_derived()),
        ),
        // The header-dependency scanner, likewise wrapping a host tool.
        (
            local_config_cc("deps_scanner_wrapper.sh"),
            Entry::Spec(host_derived()),
        ),
    ]
}
