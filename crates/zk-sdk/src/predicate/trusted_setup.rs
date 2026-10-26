//! Finding what a Groth16 trusted setup needs on disk: the approved circuits' r1cs and sym, and a
//! published phase-1 (Powers of Tau) file. The ceremony itself (creating, contributing to and
//! verifying setups) is [`zk_groth16::Ceremony`]; a [`zk_groth16::Setup`] built from its key pack
//! goes to [`super::Predicates::with_groth16`].

use std::path::{Path, PathBuf};
use std::sync::Arc;

use zk_groth16::{phase1_file_name, phase1_powers, Ceremony, Directory, Phase1};

use crate::{Result, ZkError};

fn backend(error: zk_groth16::Groth16Error) -> ZkError {
    ZkError::Backend(format!("groth16: {error}"))
}

/// `given`, else the environment variable `variable`.
fn configured(given: Option<PathBuf>, variable: &str) -> Option<PathBuf> {
    given.or_else(|| std::env::var_os(variable).map(PathBuf::from))
}

/// `<name>` beside the executable when it exists, else `repository` under this repository's root.
fn beside_executable(name: &str, repository: &str) -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|exe| Some(exe.parent()?.join(name)))
        .filter(|dir| dir.exists())
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join(repository)
        })
}

/// The approved circuits' r1cs and sym: `dir`, else `$ZK_GROTH16_DIR`, else a `groth16` directory
/// beside the executable, else this repository's `testdata/groth16`.
pub fn groth16_directory(dir: Option<PathBuf>) -> PathBuf {
    configured(dir, "ZK_GROTH16_DIR")
        .unwrap_or_else(|| beside_executable("groth16", "testdata/groth16"))
}

/// The phase-1 file: `path`, else `$ZK_PTAU`, else the smallest published file (by power) in a
/// `ptau` directory beside the executable or in this repository's `target/ptau`.
pub fn phase1_path(path: Option<PathBuf>) -> PathBuf {
    configured(path, "ZK_PTAU").unwrap_or_else(|| {
        let dir = beside_executable("ptau", "target/ptau");
        phase1_powers()
            .map(|power| dir.join(phase1_file_name(power)))
            .find(|file| file.is_file())
            .unwrap_or_else(|| dir.join(phase1_file_name(16)))
    })
}

/// The ceremony over the approved circuits in `dir` and the phase-1 file at `ptau` (see
/// [`groth16_directory`] and [`phase1_path`]); the file must be one of the published ones.
pub fn load_ceremony(dir: Option<PathBuf>, ptau: Option<PathBuf>) -> Result<Ceremony> {
    let ptau = phase1_path(ptau);
    let bytes = std::fs::read(&ptau).map_err(|e| {
        ZkError::Backend(format!(
            "groth16: cannot read the phase-1 file {}: {e} (fetch it with \
             `python scripts/groth16_setup.py --fetch` or pass --ptau)",
            ptau.display()
        ))
    })?;
    let phase1 = Phase1::new(Arc::from(bytes)).map_err(backend)?;
    let circuits = Arc::new(Directory::new(groth16_directory(dir)));
    Ok(Ceremony::new(circuits, phase1))
}

/// Every approved Groth16 circuit.
pub fn groth16_circuits() -> Vec<String> {
    zk_groth16::circuits().map(str::to_owned).collect()
}
