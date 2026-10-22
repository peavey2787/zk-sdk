//! The short path: load a circuit, set up, prove from JSON, verify. Everything here is a thin
//! layer over [`portable`](crate::portable); the security policy is the only knob.
//!
//! ```no_run
//! # fn demo(r1cs: Vec<u8>, sym: String) -> zk_sdk::Result<()> {
//! use zk_sdk::{Circuit, SecurityPolicy, Soundness};
//!
//! let circuit = Circuit::new(r1cs, sym);
//! let (prover, verifier) = circuit.setup()?; // 116-bit full ZK by default
//! let proof = prover.prove(r#"{"age":"20","threshold":"18"}"#)?;
//! verifier.verify(&[1, 18], &proof)?; // the statement YOU trust: outputs, then public inputs
//!
//! // Power users choose the policy explicitly; unsupported choices are rejected, never adjusted.
//! let policy = SecurityPolicy::default().with_bits(110).with_soundness(Soundness::CapacityBound);
//! let (_prover, _verifier) = circuit.setup_with(policy)?;
//! # Ok(()) }
//! ```

use crate::{portable, Result, SecurityPolicy, Zk};

/// A compiled circuit: the circom `.r1cs` bytes and the `.sym` text used to compute witnesses.
#[derive(Clone)]
pub struct Circuit {
    r1cs: Vec<u8>,
    sym: String,
}

/// Holds the secret proving key. Keep it private.
pub struct Prover {
    zk: Zk,
    r1cs: Vec<u8>,
    sym: String,
    proving_key: Vec<u8>,
}

/// Holds only public material, so it can be shared and stored freely.
pub struct Verifier {
    zk: Zk,
    verifying_key: Vec<u8>,
}

fn engine(policy: SecurityPolicy) -> Zk {
    Zk::spartan_whir().with_policy(policy)
}

impl Circuit {
    pub fn new(r1cs: Vec<u8>, sym: String) -> Self {
        Self { r1cs, sym }
    }

    /// Setup under the default policy (116 bits, full ZK).
    pub fn setup(&self) -> Result<(Prover, Verifier)> {
        self.setup_with(SecurityPolicy::default())
    }

    pub fn setup_with(&self, policy: SecurityPolicy) -> Result<(Prover, Verifier)> {
        let zk = engine(policy);
        let keys = portable::setup(&zk, self.r1cs.clone())?;
        let prover = Prover {
            zk: engine(policy),
            r1cs: self.r1cs.clone(),
            sym: self.sym.clone(),
            proving_key: keys.proving,
        };
        let verifier = Verifier::from_bytes(keys.verifying);
        Ok((prover, verifier))
    }
}

impl Prover {
    /// Restore a prover from a previously stored proving key.
    pub fn from_bytes(circuit: Circuit, proving_key: Vec<u8>) -> Self {
        Self {
            zk: Zk::spartan_whir(),
            r1cs: circuit.r1cs,
            sym: circuit.sym,
            proving_key,
        }
    }

    pub fn to_bytes(&self) -> &[u8] {
        &self.proving_key
    }

    /// Compute the witness from circom input JSON and prove it. Fails if the inputs do not
    /// satisfy the circuit.
    pub fn prove(&self, input_json: &str) -> Result<Vec<u8>> {
        let wtns = portable::witness(&self.zk, &self.r1cs, &self.sym, input_json)?;
        portable::prove(&self.zk, &self.proving_key, &wtns)
    }
}

impl Verifier {
    pub fn from_bytes(verifying_key: Vec<u8>) -> Self {
        Self {
            zk: Zk::spartan_whir(),
            verifying_key,
        }
    }

    pub fn to_bytes(&self) -> &[u8] {
        &self.verifying_key
    }

    /// `expected` is the public statement the verifier trusts (outputs first, then public
    /// inputs). Fails closed on any mismatch, corruption or wrong key.
    pub fn verify(&self, expected: &[u64], proof: &[u8]) -> Result<()> {
        portable::verify(&self.zk, &self.verifying_key, expected, proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Soundness;

    fn circuit() -> Circuit {
        Circuit::new(
            include_bytes!("../../../testdata/age_over/age_over.r1cs").to_vec(),
            include_str!("../../../testdata/age_over/age_over.sym").to_owned(),
        )
    }

    const INPUT: &str = r#"{"age":"20","threshold":"18"}"#;

    #[test]
    fn four_calls_and_restore() {
        let (prover, verifier) = circuit().setup().unwrap();
        let proof = prover.prove(INPUT).unwrap();
        verifier.verify(&[1, 18], &proof).unwrap();
        assert!(verifier.verify(&[0, 18], &proof).is_err());
        let restored = Verifier::from_bytes(verifier.to_bytes().to_vec());
        restored.verify(&[1, 18], &proof).unwrap();
    }

    #[test]
    fn power_user_policy_and_rejection() {
        let policy = SecurityPolicy::default()
            .with_bits(105)
            .with_soundness(Soundness::UniqueDecoding);
        let (prover, verifier) = circuit().setup_with(policy).unwrap();
        verifier
            .verify(&[1, 18], &prover.prove(INPUT).unwrap())
            .unwrap();
        assert!(circuit()
            .setup_with(SecurityPolicy::default().with_bits(128))
            .is_err());
    }
}
