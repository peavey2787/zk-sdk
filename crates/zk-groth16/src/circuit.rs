//! A bundled circuit ready to prove.

use ark_bn254::Fr;
use ark_serialize::CanonicalSerialize;
use zeroize::Zeroize;
use zk_witness::{FieldInputs, LinearCombination, WitnessCalculator};

use crate::{
    bundle,
    commit::random_scalar,
    field::Bn254,
    prover,
    qap::{Matrix, Qap},
    verifier::{VerifyingKey, PROOF_BYTES},
    zkey::{self, ProvingKey},
    Groth16Error, Result,
};

/// One of the bundled predicate circuits with its proving key.
pub struct Circuit {
    calculator: WitnessCalculator<Bn254>,
    proving_key: ProvingKey,
    qap: Qap,
}

/// A proof and the public signals (circom order) it was generated for.
pub struct ProveOutput {
    pub proof: Vec<u8>,
    pub public_signals: Vec<Fr>,
}

fn matrix(rows: impl Iterator<Item = LinearCombination<Fr>>) -> Matrix {
    rows.map(|lc| lc.iter().map(|t| (t.coef, t.wire as usize)).collect())
        .collect()
}

impl Circuit {
    /// Load an approved bundled circuit (see [`crate::circuits`]); fails if its r1cs and zkey do not
    /// describe the same system.
    pub fn bundled(name: &str) -> Result<Self> {
        let artifacts = bundle::approved(name)?;
        let calculator = WitnessCalculator::<Bn254>::in_field(artifacts.r1cs, artifacts.sym)?;
        let key = zkey::parse(artifacts.zkey)?;
        let r1cs = calculator.r1cs();
        let rows = || r1cs.constraints.iter();
        let qap = Qap::new(
            matrix(rows().map(|k| k.a.clone())),
            matrix(rows().map(|k| k.b.clone())),
            r1cs.n_public() + 1,
        );
        let mismatch = || Groth16Error::Format(format!("{name}: zkey does not match its r1cs"));
        let qap = qap.ok_or_else(mismatch)?;
        if (key.n_vars, key.n_public, key.domain_size)
            != (
                r1cs.n_wires as usize,
                r1cs.n_public(),
                qap.domain.size as usize,
            )
        {
            return Err(mismatch());
        }
        Ok(Self {
            calculator,
            proving_key: key.proving_key,
            qap,
        })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::new(&self.proving_key.vk)
    }

    pub fn constraints(&self) -> usize {
        self.qap.a.len()
    }

    /// Solve the witness (failing unless every constraint holds) and prove it with fresh randomness.
    pub fn prove(&self, inputs: &FieldInputs<Bn254>) -> Result<ProveOutput> {
        let mut witness = self.calculator.witness(inputs)?;
        let (mut r, mut s) = (random_scalar()?, random_scalar()?);
        let mut h = self.qap.quotient(&witness.assignment);
        let proof = prover::prove(
            &self.proving_key,
            &witness.assignment,
            self.qap.n_inputs,
            &h,
            r,
            s,
        );
        r.zeroize();
        s.zeroize();
        h.zeroize();
        witness.assignment.zeroize();
        let mut bytes = Vec::with_capacity(PROOF_BYTES);
        (proof.a, proof.b, proof.c)
            .serialize_compressed(&mut bytes)
            .map_err(|e| Groth16Error::Prove(e.to_string()))?;
        Ok(ProveOutput {
            proof: bytes,
            public_signals: witness.public_signals,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{G1Affine, G2Affine};
    use serde_json::Value;

    fn g1(p: &G1Affine) -> Value {
        serde_json::json!([p.x.to_string(), p.y.to_string(), "1"])
    }

    fn g2(p: &G2Affine) -> Value {
        serde_json::json!([
            [p.x.c0.to_string(), p.x.c1.to_string()],
            [p.y.c0.to_string(), p.y.c1.to_string()],
            ["1", "0"]
        ])
    }

    /// The zkey reader agrees with snarkjs's own export of every verification key.
    #[test]
    fn verifying_keys_match_the_snarkjs_exports() {
        let data = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/groth16");
        for name in crate::circuits() {
            let text = std::fs::read_to_string(data.join(format!("{name}.vkey.json"))).unwrap();
            let expected: Value = serde_json::from_str(&text).unwrap();
            let vk = &Circuit::bundled(name).unwrap().proving_key.vk;
            assert_eq!(expected["vk_alpha_1"], g1(&vk.alpha_g1), "{name}");
            assert_eq!(expected["vk_beta_2"], g2(&vk.beta_g2), "{name}");
            assert_eq!(expected["vk_gamma_2"], g2(&vk.gamma_g2), "{name}");
            assert_eq!(expected["vk_delta_2"], g2(&vk.delta_g2), "{name}");
            let ic: Vec<Value> = vk.ic.iter().map(g1).collect();
            assert_eq!(expected["IC"], Value::Array(ic), "{name}");
        }
    }
}
