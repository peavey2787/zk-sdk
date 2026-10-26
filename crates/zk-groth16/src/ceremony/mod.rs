//! Trusted setups as a first-class feature: phase-2 keys derived from a published phase-1 file,
//! sequential contributions in snarkjs's format, and verification of a whole contribution chain.
//!
//! A [`Ceremony`] knows the approved circuits (their r1cs, pinned by hash) and a verified
//! [`Phase1`]. It can start a new setup for any subset of circuits ([`Ceremony::create`]), add a
//! contribution to an existing one ([`Ceremony::contribute`], which first verifies what it is
//! given) and verify a setup ([`Ceremony::verify`]), producing a report of every contribution.
//! The keys are byte-compatible with snarkjs: `snarkjs zkey verify` accepts keys made here, and
//! keys made by snarkjs from the same phase-1 file verify here.

mod contribute;
mod init;
mod mpc;
mod phase1;
mod rng;
mod verify;

use std::sync::Arc;

use ark_bn254::Fr;
use zk_witness::R1cs;

use crate::digest::hex;
use crate::keys::{KeyId, KeyPack};
use crate::setup::{approved, pinned};
use crate::{field::Bn254, Groth16Error, Result, Source};

pub use mpc::{Beacon, MAX_NAME_BYTES};
pub use phase1::{phase1_file_name, phase1_powers, Phase1};
pub use rng::{MAX_BEACON_EXPONENT, MIN_BEACON_EXPONENT};

/// How a new contribution draws its secret.
#[derive(Clone, Debug)]
pub enum Contribution {
    /// Fresh OS (or browser) entropy, discarded once the contribution is made.
    Random { name: Option<String> },
    /// Expanded from a public beacon value, so anyone can recompute it (normally the last one).
    Beacon {
        name: Option<String>,
        beacon: Beacon,
    },
}

/// One contribution's public record, as `snarkjs zkey verify` prints it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContributionRecord {
    pub name: Option<String>,
    /// BLAKE2b-512 of the contribution's public key, in hex.
    pub hash: String,
    pub beacon: Option<Beacon>,
}

/// One verified key: its identity and contribution history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyReport {
    pub circuit: String,
    pub key_id: KeyId,
    /// BLAKE2b-512 of the circuit and phase 1 (snarkjs's "circuit hash"), in hex.
    pub circuit_hash: String,
    pub contributions: Vec<ContributionRecord>,
}

/// A verified setup: one report per key, by circuit name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupReport {
    pub setup_id: KeyId,
    pub keys: Vec<KeyReport>,
}

/// Approved circuits and a verified phase 1.
#[derive(Clone)]
pub struct Ceremony {
    circuits: Arc<dyn Source>,
    phase1: Arc<Phase1>,
}

/// Progress callbacks receive `(circuit, done, total)` after each circuit.
pub type Progress<'a> = &'a mut dyn FnMut(&str, usize, usize);

impl Ceremony {
    /// `circuits` supplies each approved circuit's `<name>.r1cs` and `<name>.sym`.
    pub fn new(circuits: Arc<dyn Source>, phase1: Phase1) -> Self {
        Self {
            circuits,
            phase1: Arc::new(phase1),
        }
    }

    pub fn phase1(&self) -> &Phase1 {
        &self.phase1
    }

    /// The pinned bytes of `<name>.<extension>` (r1cs or sym).
    pub(crate) fn artifact(&self, name: &str, extension: &str) -> Result<Arc<[u8]>> {
        pinned(self.circuits.as_ref(), name, extension)
    }

    fn r1cs(&self, name: &str) -> Result<R1cs<Fr>> {
        Ok(zk_witness::parse_r1cs_raw::<Bn254>(
            &self.artifact(name, "r1cs")?,
        )?)
    }

    /// Circuit `name`'s phase-2 starting key (snarkjs `zkey new`): not usable before a
    /// contribution.
    pub fn initial_key(&self, name: &str) -> Result<Vec<u8>> {
        init::initialize(&self.r1cs(name)?, &self.phase1)
    }

    /// Check one key of circuit `name` against phase 1 and report its contributions.
    pub fn verify_key(&self, name: &str, zkey: &[u8]) -> Result<KeyReport> {
        let initial = self.initial_key(name)?;
        let mpc = verify::verify(&initial, zkey).map_err(|e| in_circuit(name, e))?;
        Ok(KeyReport {
            circuit: name.to_owned(),
            key_id: KeyId::of(name, zkey)?,
            circuit_hash: hex(&mpc.cs_hash),
            contributions: mpc
                .records
                .iter()
                .map(|r| ContributionRecord {
                    name: r.name.clone(),
                    hash: hex(&r.hash()),
                    beacon: r.beacon.clone(),
                })
                .collect(),
        })
    }

    /// Verify every key of `pack`.
    pub fn verify(&self, pack: &KeyPack, progress: Progress) -> Result<SetupReport> {
        let total = pack.len();
        let mut keys = Vec::with_capacity(total);
        for (done, (name, zkey)) in pack.iter().enumerate() {
            keys.push(self.verify_key(name, zkey)?);
            progress(name, done + 1, total);
        }
        Ok(SetupReport {
            setup_id: pack.setup_id()?,
            keys,
        })
    }

    /// Circuit `name`'s starting key with one contribution: the first key of a new setup.
    pub fn create_key(&self, name: &str, contribution: &Contribution) -> Result<Vec<u8>> {
        approved(name)?;
        apply(&self.initial_key(name)?, contribution)
    }

    /// `zkey` (a key of circuit `name`), verified, with one more contribution.
    pub fn contribute_key(
        &self,
        name: &str,
        zkey: &[u8],
        contribution: &Contribution,
    ) -> Result<Vec<u8>> {
        self.verify_key(name, zkey)?;
        apply(zkey, contribution)
    }

    /// A new setup for `names`: each circuit's starting key with one contribution.
    pub fn create(
        &self,
        names: &[String],
        contribution: &Contribution,
        progress: Progress,
    ) -> Result<KeyPack> {
        let mut pack = KeyPack::default();
        for (done, name) in names.iter().enumerate() {
            pack.insert(name, self.create_key(name, contribution)?)?;
            progress(name, done + 1, names.len());
        }
        Ok(pack)
    }

    /// `pack` with one more contribution to every key, each verified first.
    pub fn contribute(
        &self,
        pack: &KeyPack,
        contribution: &Contribution,
        progress: Progress,
    ) -> Result<KeyPack> {
        let mut out = KeyPack::default();
        for (done, (name, zkey)) in pack.iter().enumerate() {
            out.insert(name, self.contribute_key(name, zkey, contribution)?)?;
            progress(name, done + 1, pack.len());
        }
        Ok(out)
    }
}

fn in_circuit(name: &str, error: Groth16Error) -> Groth16Error {
    Groth16Error::Setup(format!("{name}: {error}"))
}

fn apply(zkey: &[u8], contribution: &Contribution) -> Result<Vec<u8>> {
    match contribution {
        Contribution::Random { name } => contribute::contribute(zkey, name.as_deref()),
        Contribution::Beacon { name, beacon } => contribute::beacon(zkey, name.as_deref(), beacon),
    }
}
