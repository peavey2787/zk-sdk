//! An approved circuit with a verified proving key, ready to prove.

use ark_bn254::Fr;
use ark_serialize::CanonicalSerialize;
use zeroize::Zeroize;
use zk_witness::{FieldInputs, LinearCombination, WitnessCalculator};

use crate::{
    field::Bn254,
    prover,
    qap::{Matrix, Qap},
    random::random_scalar,
    verifier::{VerifyingKey, PROOF_BYTES},
    zkey::{self, ProvingKey},
    Groth16Error, Result,
};

/// One of the approved predicate circuits with its proving key (see [`crate::Setup`]).
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
    /// The circuit from artifacts [`crate::Setup`] has checked; fails if the r1cs and zkey do not
    /// describe the same system.
    pub(crate) fn new(name: &str, r1cs: &[u8], sym: &str, zkey: &[u8]) -> Result<Self> {
        let calculator = WitnessCalculator::<Bn254>::in_field(r1cs, sym)?;
        let key = zkey::parse(zkey)?;
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
