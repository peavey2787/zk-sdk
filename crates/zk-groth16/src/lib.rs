//! Groth16 over BN254 for the built-in predicate circuits (`testdata/groth16`).
//!
//! No proving keys ship with the crate: trusted setups are made with it. A [`Ceremony`] derives each
//! circuit's phase-2 starting key from a published Hermez Powers of Tau file ([`Phase1`]), adds
//! sequential contributions and verifies whole contribution chains, all in snarkjs's format. A
//! [`Setup`] proves with any valid [`KeyPack`] and verifies only under keys its [`Trust`] list
//! authorizes. Proofs are 128 bytes and verify in a few milliseconds, but Groth16 relies on that
//! trusted setup and on pairing hardness: it is **not** post-quantum, unlike the Spartan-WHIR
//! backend.
mod approved;
mod binfile;
mod ceremony;
mod circuit;
mod digest;
mod error;
mod field;
mod hash;
mod keys;
mod par;
mod points;
mod prover;
mod qap;
mod random;
mod setup;
mod source;
mod verifier;
mod zkey;

pub use ark_bn254::Fr;
pub use ceremony::{
    phase1_file_name, phase1_powers, Beacon, Ceremony, Contribution, ContributionRecord, KeyReport,
    Phase1, Progress, SetupReport, MAX_BEACON_EXPONENT, MAX_NAME_BYTES, MIN_BEACON_EXPONENT,
};
pub use circuit::{Circuit, ProveOutput};
pub use error::{Groth16Error, Result};
pub use field::Bn254;
pub use hash::{commit, compress, sponge};
pub use keys::{KeyId, KeyPack, Trust};
pub use random::random_scalar;
pub use setup::{circuits, Setup};
pub use source::{Directory, Memory, Source};
pub use verifier::{VerifyingKey, PROOF_BYTES};
pub use zk_witness::FieldInputs;
