//! The predicate facade: `prove(&claim, witness)` and `verify(&claim, &proof)` with no compile or
//! setup step for the developer. Approved circuits are loaded and keyed on first use per circuit
//! and cached, then proved by the same backend and policy as the advanced six-operation facade.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::bundle;
use super::claim::Predicate;
use super::commit::Opening;
use super::statement::Statement;
use crate::{
    decode_artifact, encode_artifact, CompiledCircuit, Inputs, KeyPair, Proof, Result,
    SecurityPolicy, WitnessCalculator, Zk, ZkError,
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

/// Every opening the claim needs, in claim order. One prover must hold all of them: a proof about
/// values held by different owners needs those owners to pool their openings with one prover
/// (revealing the values to it) or to run a multi-party computation, which this SDK does not
/// provide. A single party cannot prove knowledge of secrets it does not have.
impl From<Vec<Opening>> for Witness {
    fn from(openings: Vec<Opening>) -> Self {
        Self(openings)
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
    zk: Zk,
    bits: u16,
    calculator: WitnessCalculator,
    keys: KeyPair,
}

pub struct Predicates {
    policy: SecurityPolicy,
    entries: Mutex<HashMap<String, Arc<Entry>>>,
}

impl Default for Predicates {
    fn default() -> Self {
        Self::new()
    }
}

impl Predicates {
    /// Spartan-WHIR, full zero knowledge, targeting the default 116-bit policy. A circuit whose
    /// size upstream cannot support at that target is set up at the highest level it can attain
    /// instead (never below the backend minimum); [`Predicates::security_bits`] reports it.
    pub fn new() -> Self {
        Self::with_policy(SecurityPolicy::default())
    }

    pub fn with_policy(policy: SecurityPolicy) -> Self {
        Self {
            policy,
            entries: Mutex::default(),
        }
    }

    /// The target security level in bits that `circuit` is actually set up at: the policy's, or
    /// the most upstream attains for that circuit's size when that is lower. Soundness of the
    /// composed proof system remains unverified end to end.
    pub fn security_bits(&self, circuit: &str) -> Result<u16> {
        Ok(self.entry(circuit)?.bits)
    }

    /// Keys at the policy, or at the level upstream says this circuit can attain.
    fn setup(&self, compiled: &CompiledCircuit) -> Result<(Zk, KeyPair)> {
        let zk = Zk::spartan_whir().with_policy(self.policy);
        match zk.setup(compiled) {
            Err(ZkError::SecurityUnattainable { attainable, .. }) => {
                let zk = Zk::spartan_whir().with_policy(self.policy.with_bits(attainable));
                let keys = zk.setup(compiled)?;
                Ok((zk, keys))
            }
            keys => keys.map(|keys| (zk, keys)),
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
        let compiled = Zk::spartan_whir().compile(bundled.r1cs.to_vec())?;
        let (zk, keys) = self.setup(&compiled)?;
        let entry = Arc::new(Entry {
            bits: keys.proving.binding().policy.bits,
            zk,
            keys,
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
        let private = entry.zk.witness(&entry.calculator, &inputs)?;
        let output = entry.zk.prove(&entry.keys.proving, &private)?;
        Ok(PredicateProof(encode_artifact(&output.proof)?))
    }

    /// Verify `proof` against `claim`, the statement the caller trusts. Any failure is an error.
    pub fn verify(&self, claim: &Predicate, proof: &PredicateProof) -> Result<()> {
        let statement = claim.statement()?;
        let entry = self.entry(statement.circuit())?;
        let proof: Proof = decode_artifact(&proof.0)?;
        let expected = entry.zk.encode_public_inputs(&statement.public_inputs())?;
        entry.zk.verify(&entry.keys.verifying, &expected, &proof)
    }
}

/// Public inputs plus the private `limb`/`blinding` signals, after checking each opening matches.
fn inputs(statement: &Statement, claim: &Predicate, openings: &[Opening]) -> Result<Inputs> {
    let expected = statement.committed();
    if openings.len() != expected.len() {
        return Err(ZkError::Predicate(format!(
            "claim needs {} opening(s), got {}",
            expected.len(),
            openings.len()
        )));
    }
    for (index, (opening, commitment)) in openings.iter().zip(expected).enumerate() {
        if !opening.opens(commitment) {
            return Err(ZkError::Predicate(format!(
                "opening {index} does not match its commitment"
            )));
        }
    }
    let values: Vec<_> = openings.iter().map(Opening::value).collect();
    if let Some(reason) = claim.refusal(&values)? {
        return Err(ZkError::Predicate(format!(
            "the claim is false, so no proof exists: {reason}"
        )));
    }
    assignment(statement, openings)
}

/// Every circuit input for `openings`, without judging whether the claim is true. The circuit
/// itself decides: its witness exists exactly when the claim holds.
pub(super) fn assignment(statement: &Statement, openings: &[Opening]) -> Result<Inputs> {
    let mut inputs = Inputs::new();
    for field in statement.named() {
        if field.array {
            put_array(&mut inputs, field.name, &field.values);
        } else {
            inputs.insert(field.name.to_owned(), field.values[0]);
        }
    }
    let limbs = statement.ty().width.limbs();
    for slot in statement.slots() {
        let (limb, blinding) = match slot.source {
            Some(source) => (
                statement.ty().limbs(openings[source].encoded()?),
                openings[source].blinding().map(u64::from),
            ),
            None => (vec![0; limbs], [0; 8]),
        };
        put_array(&mut inputs, &slot.limb, &limb);
        put_array(&mut inputs, &slot.blinding, &blinding);
    }
    Ok(inputs)
}

fn put_array(inputs: &mut Inputs, name: &str, values: &[u64]) {
    for (i, value) in values.iter().enumerate() {
        inputs.insert(format!("{name}[{i}]"), *value);
    }
}
