//! Shared fixture: ephemeral trusted setups created from the published phase-1 file. No key is
//! stored in the repository; every test run makes its own.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use zk_groth16::{
    phase1_file_name, phase1_powers, Ceremony, Contribution, Directory, KeyPack, Phase1, Setup,
    Trust,
};

fn root() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
}

/// The bytes of `$ZK_PTAU`, else of the smallest published phase-1 file in `target/ptau`.
pub fn phase1_bytes() -> Vec<u8> {
    let file = std::env::var_os("ZK_PTAU")
        .map(PathBuf::from)
        .or_else(|| {
            let dir = root().join("target/ptau");
            phase1_powers()
                .map(|power| dir.join(phase1_file_name(power)))
                .find(|file| file.is_file())
        })
        .expect("no published phase-1 file: run `python scripts/groth16_setup.py --fetch`");
    std::fs::read(file).expect("read the phase-1 file")
}

/// The approved circuits in `testdata/groth16` over the published phase 1.
pub fn ceremony() -> &'static Ceremony {
    static CEREMONY: OnceLock<Ceremony> = OnceLock::new();
    CEREMONY.get_or_init(|| {
        let phase1 = Phase1::new(Arc::from(phase1_bytes())).expect("a published phase-1 file");
        Ceremony::new(
            Arc::new(Directory::new(root().join("testdata/groth16"))),
            phase1,
        )
    })
}

/// A new setup for `names` with one fresh contribution named `contributor`.
pub fn create(names: &[&str], contributor: &str) -> KeyPack {
    let names: Vec<String> = names.iter().map(|n| (*n).to_owned()).collect();
    let contribution = Contribution::Random {
        name: Some(contributor.to_owned()),
    };
    ceremony()
        .create(&names, &contribution, &mut |_, _, _| {})
        .expect("create a setup")
}

/// `pack` ready to prove, with its own setup id authorized for verification.
pub fn trusted(pack: KeyPack) -> Setup {
    let mut trust = Trust::default();
    trust.insert(pack.setup_id().expect("setup id"));
    Setup::new(ceremony().clone(), pack, trust).expect("setup")
}
