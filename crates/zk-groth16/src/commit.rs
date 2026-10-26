//! The BN254 value commitment, matching `circuits/lib/bn254/commit.circom`:
//! `Poseidon5(COMMIT_DOMAIN, signed, L, value, blinding)` with `value = sum(limb[i] * 2^(16 i))`.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use light_poseidon::{Poseidon, PoseidonHasher};

use crate::{Groth16Error, Result};

/// `commit_domain()` in the circuit.
const COMMIT_DOMAIN: u64 = 1_514_344_449;

/// The commitment to the 16-bit limbs of a value (little-endian) under `blinding`.
pub fn commit(signed: bool, limbs: &[u16], blinding: Fr) -> Fr {
    let value = limbs.iter().rev().fold(Fr::from(0u64), |acc, limb| {
        acc * Fr::from(1u64 << 16) + Fr::from(*limb)
    });
    let inputs = [
        Fr::from(COMMIT_DOMAIN),
        Fr::from(u64::from(signed)),
        Fr::from(limbs.len() as u64),
        value,
        blinding,
    ];
    Poseidon::<Fr>::new_circom(inputs.len())
        .and_then(|mut hasher| hasher.hash(&inputs))
        .expect("five inputs are within light-poseidon's circom widths")
}

/// A uniformly random scalar (commitment blindings, prover randomness) from the OS (or browser)
/// CSPRNG. 64 bytes reduced modulo r leave a statistical distance below 2^-250 from uniform.
pub fn random_scalar() -> Result<Fr> {
    let mut bytes = [0u8; 64];
    getrandom::fill(&mut bytes).map_err(|e| Groth16Error::Randomness(e.to_string()))?;
    let scalar = Fr::from_le_bytes_mod_order(&bytes);
    zeroize::Zeroize::zeroize(&mut bytes);
    Ok(scalar)
}
