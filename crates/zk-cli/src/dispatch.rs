//! CPU dispatch without making AVX2 mandatory: the portable `zk` hands the whole invocation to a
//! sibling `zk-avx2` binary (built by `scripts/build_optimized.py`) when the CPU supports AVX2 and
//! BMI2 and that binary is installed next to it. Both binaries run the same code and parameters;
//! only the compiled vector instructions differ, so proofs are interchangeable. Set
//! `ZK_PORTABLE=1` to stay on the portable build.

use std::path::PathBuf;
use std::process::{Command, ExitCode};

/// The optimized sibling's file name.
const OPTIMIZED: &str = if cfg!(windows) {
    "zk-avx2.exe"
} else {
    "zk-avx2"
};

/// The optimized sibling to run instead of this process, if any. A sibling older than this
/// executable was built from older sources (the portable build was redone since), so it is skipped
/// with a warning rather than run in this binary's place.
pub fn optimized_sibling() -> Option<PathBuf> {
    if cfg!(target_feature = "avx2") || std::env::var_os("ZK_PORTABLE").is_some() || !cpu_has_avx2()
    {
        return None;
    }
    let current = std::env::current_exe().ok()?;
    let sibling = current.with_file_name(OPTIMIZED);
    let built = |path: &PathBuf| path.metadata().and_then(|m| m.modified()).ok();
    let (sibling_built, current_built) = (built(&sibling)?, built(&current)?);
    if sibling_built < current_built {
        eprintln!(
            "warning: {} is older than this zk; run scripts/build_optimized.py (using the portable build)",
            sibling.display()
        );
        return None;
    }
    Some(sibling)
}

#[cfg(target_arch = "x86_64")]
fn cpu_has_avx2() -> bool {
    is_x86_feature_detected!("avx2") && is_x86_feature_detected!("bmi2")
}

#[cfg(not(target_arch = "x86_64"))]
fn cpu_has_avx2() -> bool {
    false
}

/// Run `binary` with `args`, inheriting stdio, and return its exit status.
pub fn delegate(binary: PathBuf, args: &[String]) -> ExitCode {
    match Command::new(&binary).args(args).status() {
        Ok(status) => ExitCode::from(status.code().map_or(1, |code| code as u8)),
        Err(error) => {
            eprintln!("error: cannot start {}: {error}", binary.display());
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_an_installed_sibling_the_portable_build_runs_itself() {
        // Test binaries live in target/*/deps, where no zk-avx2 is ever installed.
        assert_eq!(optimized_sibling(), None);
    }
}
