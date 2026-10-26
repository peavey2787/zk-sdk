//! Randomness for blindings, prover scalars and setup contributions.

use ark_bn254::Fr;
use ark_ff::PrimeField;

use crate::{Groth16Error, Result};

/// A uniformly random scalar (commitment blindings, prover randomness) from the OS (or browser)
/// CSPRNG. 64 bytes reduced modulo r leave a statistical distance below 2^-250 from uniform.
pub fn random_scalar() -> Result<Fr> {
    let mut bytes = [0u8; 64];
    getrandom::fill(&mut bytes).map_err(|e| Groth16Error::Randomness(e.to_string()))?;
    let scalar = Fr::from_le_bytes_mod_order(&bytes);
    zeroize::Zeroize::zeroize(&mut bytes);
    Ok(scalar)
}
