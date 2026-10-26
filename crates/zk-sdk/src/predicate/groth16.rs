//! Groth16 proving and verification for the predicate engine. Nothing is set up by default: a
//! [`Setup`] (a key pack checked against phase 1, and the verifier's trust list) must be configured
//! with [`super::Predicates::with_groth16`]. Circuits and verifying keys are loaded on first use and
//! cached. Proofs carry a tag so a Groth16 proof is never parsed as a Spartan-WHIR artifact or the
//! other way round.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use zk_groth16::{Bn254, Circuit, FieldInputs, Fr, Setup, VerifyingKey};

use crate::{Result, ZkError};

const TAG: &[u8; 8] = b"ZKG16v01";

#[derive(Default)]
pub(super) struct Groth16Circuits {
    setup: Option<Setup>,
    circuits: Mutex<HashMap<String, Arc<Circuit>>>,
    verifying_keys: Mutex<HashMap<String, Arc<VerifyingKey>>>,
}

fn backend(error: zk_groth16::Groth16Error) -> ZkError {
    ZkError::Backend(format!("groth16: {error}"))
}

/// The cached value of `name`, loaded with `load` on first use.
fn cached<T>(
    cache: &Mutex<HashMap<String, Arc<T>>>,
    name: &str,
    load: impl FnOnce() -> Result<T>,
) -> Result<Arc<T>> {
    let mut cache = cache
        .lock()
        .map_err(|_| ZkError::Backend("groth16 cache poisoned".into()))?;
    if let Some(value) = cache.get(name) {
        return Ok(Arc::clone(value));
    }
    let value = Arc::new(load()?);
    cache.insert(name.to_owned(), Arc::clone(&value));
    Ok(value)
}

impl Groth16Circuits {
    pub fn new(setup: Setup) -> Self {
        Self {
            setup: Some(setup),
            ..Self::default()
        }
    }

    fn setup(&self) -> Result<&Setup> {
        self.setup.as_ref().ok_or_else(|| {
            ZkError::Backend(
                "groth16 needs a trusted setup: create one (`zk groth16 new`) or import a key pack, \
                 then pass it with Predicates::with_groth16 (CLI: --groth16-keys)"
                    .into(),
            )
        })
    }

    /// Prove circuit `name` on `signals`; the circuit's public signals must be exactly `public`,
    /// the inputs the verifier will derive from the claim.
    pub fn prove(
        &self,
        name: &str,
        signals: &FieldInputs<Bn254>,
        public: &[Fr],
    ) -> Result<Vec<u8>> {
        let setup = self.setup()?;
        let circuit = cached(&self.circuits, name, || {
            setup.circuit(name).map_err(backend)
        })?;
        let output = circuit.prove(signals).map_err(backend)?;
        if output.public_signals != public {
            return Err(ZkError::Backend(format!(
                "{name}: circuit public signals differ from the claim's"
            )));
        }
        Ok([TAG.as_slice(), &output.proof].concat())
    }

    /// Verify under circuit `name`'s key, which the setup's trust list must authorize.
    pub fn verify(&self, name: &str, public: &[Fr], proof: &[u8]) -> Result<()> {
        let body = proof
            .strip_prefix(TAG.as_slice())
            .ok_or_else(|| ZkError::Format("not a groth16 predicate proof".into()))?;
        let setup = self.setup()?;
        cached(&self.verifying_keys, name, || {
            setup.verifying_key(name).map_err(backend)
        })?
        .verify(public, body)
        .map_err(|_| ZkError::StatementMismatch)
    }
}
