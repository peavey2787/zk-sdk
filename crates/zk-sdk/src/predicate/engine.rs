//! The predicate facade: `prove(&claim, witness)` and `verify(&claim, &proof)` with no compile or
//! setup step for the developer. Approved circuits are loaded and keyed on first use per circuit
//! and cached, then proved by the same backend and policy as the advanced six-operation facade.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::bundle;
use super::claim::{Predicate, Statement};
use super::commit::Opening;
use crate::{
    decode_artifact, encode_artifact, Inputs, KeyPair, Proof, Result, SecurityPolicy,
    WitnessCalculator, Zk, ZkError,
};

/// The openings the prover holds, in the order of the claim's commitments.
pub struct Witness(Vec<Opening>);

impl From<Opening> for Witness {
    fn from(opening: Opening) -> Self {
        Self(vec![opening])
    }
}

impl From<&Opening> for Witness {
    fn from(opening: &Opening) -> Self {
        Self(vec![opening.clone()])
    }
}

impl From<(Opening, Opening)> for Witness {
    fn from((left, right): (Opening, Opening)) -> Self {
        Self(vec![left, right])
    }
}

/// A proof that a [`Predicate`] holds. It carries no statement: the verifier supplies the claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PredicateProof(Vec<u8>);

impl PredicateProof {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

struct Entry {
    calculator: WitnessCalculator,
    keys: KeyPair,
}

pub struct Predicates {
    zk: Zk,
    entries: Mutex<HashMap<String, Arc<Entry>>>,
}

impl Default for Predicates {
    fn default() -> Self {
        Self::new()
    }
}

impl Predicates {
    /// Spartan-WHIR, full zero knowledge, the default 116-bit policy.
    pub fn new() -> Self {
        Self::with_policy(SecurityPolicy::default())
    }

    pub fn with_policy(policy: SecurityPolicy) -> Self {
        Self {
            zk: Zk::spartan_whir().with_policy(policy),
            entries: Mutex::default(),
        }
    }

    fn entry(&self, circuit: &str) -> Result<Arc<Entry>> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| ZkError::Backend("predicate cache poisoned".into()))?;
        if let Some(entry) = entries.get(circuit) {
            return Ok(Arc::clone(entry));
        }
        let bundled = bundle::lookup(circuit)?;
        let compiled = self.zk.compile(bundled.r1cs.to_vec())?;
        let entry = Arc::new(Entry {
            keys: self.zk.setup(&compiled)?,
            calculator: WitnessCalculator::new(bundled.r1cs, bundled.sym)
                .map_err(|e| ZkError::Format(e.to_string()))?,
        });
        entries.insert(circuit.to_owned(), Arc::clone(&entry));
        Ok(entry)
    }

    /// Prove `claim`. Fails, without producing a proof, when the witness does not open the
    /// claim's commitments or the claim is false.
    pub fn prove(&self, claim: &Predicate, witness: impl Into<Witness>) -> Result<PredicateProof> {
        let statement = claim.statement()?;
        let openings = witness.into().0;
        let inputs = inputs(&statement, claim, &openings)?;
        let entry = self.entry(statement.circuit())?;
        let private = self.zk.witness(&entry.calculator, &inputs)?;
        let output = self.zk.prove(&entry.keys.proving, &private)?;
        Ok(PredicateProof(encode_artifact(&output.proof)?))
    }

    /// Verify `proof` against `claim`, the statement the caller trusts. Any failure is an error.
    pub fn verify(&self, claim: &Predicate, proof: &PredicateProof) -> Result<()> {
        let statement = claim.statement()?;
        let entry = self.entry(statement.circuit())?;
        let proof: Proof = decode_artifact(&proof.0)?;
        let expected = self.zk.encode_public_inputs(&statement.public_inputs())?;
        self.zk.verify(&entry.keys.verifying, &expected, &proof)
    }
}

fn commitments(claim: &Predicate) -> Vec<&super::commit::Commitment> {
    match claim {
        Predicate::Opens { commitment }
        | Predicate::Compare { commitment, .. }
        | Predicate::Range { commitment, .. } => vec![commitment],
        Predicate::CompareCommitted { left, right, .. } => vec![left, right],
    }
}

/// Public inputs plus the private `limb`/`blinding` signals, after checking each opening matches.
fn inputs(statement: &Statement, claim: &Predicate, openings: &[Opening]) -> Result<Inputs> {
    let expected = commitments(claim);
    if openings.len() != expected.len() {
        return Err(ZkError::Predicate(format!(
            "claim needs {} opening(s), got {}",
            expected.len(),
            openings.len()
        )));
    }
    let mut inputs = Inputs::new();
    for field in statement.named() {
        if field.array {
            put_array(&mut inputs, field.name, &field.values);
        } else {
            inputs.insert(field.name.to_owned(), field.values[0]);
        }
    }
    for ((slot, opening), commitment) in statement.slots().iter().zip(openings).zip(expected) {
        if !opening.opens(commitment) {
            return Err(ZkError::Predicate(
                "opening does not match the commitment".into(),
            ));
        }
        put_array(
            &mut inputs,
            &format!("{slot}limb"),
            &statement.ty().limbs(opening.encoded()?),
        );
        put_array(
            &mut inputs,
            &format!("{slot}blinding"),
            &opening.blinding().map(u64::from),
        );
    }
    Ok(inputs)
}

fn put_array(inputs: &mut Inputs, name: &str, values: &[u64]) {
    for (i, value) in values.iter().enumerate() {
        inputs.insert(format!("{name}[{i}]"), *value);
    }
}
