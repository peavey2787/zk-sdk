//! Groth16 over BN254 for the built-in predicate circuits (`testdata/groth16`).
//!
//! The keys come from the public Hermez Powers of Tau plus one documented phase-2 contribution and
//! a public beacon (`scripts/groth16_setup.py`, docs/GROTH16_SETUP.md). Proofs are 128 bytes and
//! verify in a few milliseconds, but Groth16 relies on that trusted setup and on pairing hardness:
//! it is **not** post-quantum, unlike the Spartan-WHIR backend.
mod approved;
mod bundle;
mod circuit;
mod commit;
mod error;
mod field;
mod prover;
mod qap;
mod verifier;
mod zkey;

pub use ark_bn254::Fr;
pub use bundle::circuits;
pub use circuit::{Circuit, ProveOutput};
pub use commit::{commit, random_scalar};
pub use error::{Groth16Error, Result};
pub use field::Bn254;
pub use verifier::{VerifyingKey, PROOF_BYTES};
pub use zk_witness::FieldInputs;
