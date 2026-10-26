//! The BN254 Poseidon hashes of the predicate circuits, every one a circom-compatible Poseidon over
//! five inputs (light-poseidon's parameters, as generated into `circuits/lib/bn254/poseidon.circom`):
//! the value commitment (`circuits/lib/bn254/commit.circom`) and the Merkle sponge and node
//! compression (`circuits/lib/bn254/merkle.circom`).

use ark_bn254::Fr;
use light_poseidon::{Poseidon, PoseidonHasher};

/// `commit_domain()` in the circuit.
const COMMIT_DOMAIN: u64 = 1_514_344_449;
/// `node_domain()` in the circuit.
const NODE_DOMAIN: u64 = 1_514_344_453;
/// Message elements absorbed per Poseidon call after the first.
const RATE: usize = 4;

fn poseidon5(inputs: [Fr; 5]) -> Fr {
    Poseidon::<Fr>::new_circom(inputs.len())
        .and_then(|mut hasher| hasher.hash(&inputs))
        .expect("five inputs are within light-poseidon's circom widths")
}

/// The commitment to the 16-bit limbs of a value (little-endian) under `blinding`:
/// `Poseidon5(COMMIT_DOMAIN, signed, L, value, blinding)` with `value = sum(limb[i] * 2^(16 i))`.
pub fn commit(signed: bool, limbs: &[u16], blinding: Fr) -> Fr {
    let value = limbs.iter().rev().fold(Fr::from(0u64), |acc, limb| {
        acc * Fr::from(1u64 << 16) + Fr::from(*limb)
    });
    poseidon5([
        Fr::from(COMMIT_DOMAIN),
        Fr::from(u64::from(signed)),
        Fr::from(limbs.len() as u64),
        value,
        blinding,
    ])
}

/// Fixed-length sponge under `domain`: `h = Poseidon5(domain, len, 0, 0, 0)`, then
/// `h = Poseidon5(h, m[4b..4b + 4])` per zero-padded block of four.
pub fn sponge(domain: u64, message: &[Fr]) -> Fr {
    let zero = Fr::from(0u64);
    let start = poseidon5([
        Fr::from(domain),
        Fr::from(message.len() as u64),
        zero,
        zero,
        zero,
    ]);
    message.chunks(RATE).fold(start, |state, block| {
        let mut inputs = [state, zero, zero, zero, zero];
        inputs[1..=block.len()].copy_from_slice(block);
        poseidon5(inputs)
    })
}

/// Merkle node: `Poseidon5(NODE_DOMAIN, left, right, 0, 0)`.
pub fn compress(left: Fr, right: Fr) -> Fr {
    let zero = Fr::from(0u64);
    poseidon5([Fr::from(NODE_DOMAIN), left, right, zero, zero])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sponge_binds_domain_length_and_every_element() {
        let message: Vec<Fr> = (1..=6u64).map(Fr::from).collect();
        let digest = sponge(7, &message);
        assert_ne!(digest, sponge(8, &message));
        assert_ne!(digest, sponge(7, &message[..5]));
        let mut padded = message.clone();
        padded.push(Fr::from(0u64));
        assert_ne!(digest, sponge(7, &padded), "length is bound");
        let mut changed = message;
        changed[5] += Fr::from(1u64);
        assert_ne!(digest, sponge(7, &changed));
    }

    #[test]
    fn compression_is_ordered() {
        let (a, b) = (Fr::from(1u64), Fr::from(2u64));
        assert_ne!(compress(a, b), compress(b, a));
    }
}
