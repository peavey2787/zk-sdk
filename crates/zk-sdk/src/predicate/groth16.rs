//! Groth16 proving and verification for the predicate engine. The approved BN254 circuits are
//! loaded on first use and cached with their prepared verifying keys. Proofs carry a tag so a
//! Groth16 proof is never parsed as a Spartan-WHIR artifact or the other way round.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use zk_groth16::{Bn254, Circuit, FieldInputs, Fr, VerifyingKey};

use crate::{Result, ZkError};

const TAG: &[u8; 8] = b"ZKG16v01";

struct Entry {
    circuit: Circuit,
    verifying_key: VerifyingKey,
}

#[derive(Default)]
pub(super) struct Groth16Circuits {
    entries: Mutex<HashMap<String, Arc<Entry>>>,
}

fn backend(error: zk_groth16::Groth16Error) -> ZkError {
    ZkError::Backend(format!("groth16: {error}"))
}

impl Groth16Circuits {
    fn entry(&self, name: &str) -> Result<Arc<Entry>> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| ZkError::Backend("groth16 cache poisoned".into()))?;
        if let Some(entry) = entries.get(name) {
            return Ok(Arc::clone(entry));
        }
        let circuit = Circuit::bundled(name).map_err(backend)?;
        let entry = Arc::new(Entry {
            verifying_key: circuit.verifying_key(),
            circuit,
        });
        entries.insert(name.to_owned(), Arc::clone(&entry));
        Ok(entry)
    }

    /// Prove circuit `name` on `signals`; the circuit's public signals must be exactly `public`,
    /// the inputs the verifier will derive from the claim.
    pub fn prove(
        &self,
        name: &str,
        signals: &FieldInputs<Bn254>,
        public: &[Fr],
    ) -> Result<Vec<u8>> {
        let output = self.entry(name)?.circuit.prove(signals).map_err(backend)?;
        if output.public_signals != public {
            return Err(ZkError::Backend(format!(
                "{name}: circuit public signals differ from the claim's"
            )));
        }
        Ok([TAG.as_slice(), &output.proof].concat())
    }

    pub fn verify(&self, name: &str, public: &[Fr], proof: &[u8]) -> Result<()> {
        let body = proof
            .strip_prefix(TAG.as_slice())
            .ok_or_else(|| ZkError::Format("not a groth16 predicate proof".into()))?;
        self.entry(name)?
            .verifying_key
            .verify(public, body)
            .map_err(|_| ZkError::StatementMismatch)
    }
}
