//! Text-and-bytes entry points to the predicate engine: the single implementation behind the CLI
//! and the browser bindings. Claims and secrets are JSON; proofs are opaque bytes. Verification
//! takes only the trusted claim and the proof, never statement data from the proof itself.

use serde::Serialize;
use zeroize::Zeroize;

use super::claim::Predicate;
use super::commit::{Commitment, Opening};
use super::compose::{Claim, Conjunction, ConjunctionWitness};
use super::engine::{PredicateProof, Predicates, Witness};
use super::int::{IntType, Number};
use super::set::{SetPath, SetTree};
use crate::{Result, ZkError};

/// A fresh commitment: publish `commitment`, keep `secret` private. The secret text is
/// overwritten when this record is dropped.
#[derive(Serialize)]
pub struct Committed {
    pub commitment: String,
    pub secret: String,
}

impl Drop for Committed {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl Committed {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("a commitment record always serializes")
    }
}

pub fn commit(ty: &str, value: &str) -> Result<Committed> {
    let ty: IntType = ty.parse()?;
    let value: Number = value.parse()?;
    let (commitment, opening) = Commitment::commit(ty, value)?;
    Ok(Committed {
        commitment: commitment.to_text(),
        secret: opening.to_secret_json(),
    })
}

/// Parse the secrets, then overwrite their text whether or not parsing succeeded.
fn openings(mut secrets: Vec<String>) -> Result<Vec<Opening>> {
    let openings: Result<Vec<Opening>> = secrets
        .iter()
        .map(|s| Opening::from_secret_json(s))
        .collect();
    secrets.iter_mut().for_each(Zeroize::zeroize);
    if secrets.is_empty() {
        return Err(ZkError::Predicate(
            "provide one secret per committed value".into(),
        ));
    }
    openings
}

/// Prove the JSON claim with the given secrets (one per committed value, in claim order). A set
/// membership or absence claim takes its Merkle path as one more, final secret. The secret texts
/// are taken by value and overwritten once parsed.
pub fn prove(zk: &Predicates, claim_json: &str, secrets: Vec<String>) -> Result<Vec<u8>> {
    match Claim::from_json(claim_json)? {
        Claim::Single(claim) => prove_single(zk, &claim, secrets),
        Claim::All(claim) => prove_all(zk, &claim, secrets),
    }
}

fn prove_single(zk: &Predicates, claim: &Predicate, mut secrets: Vec<String>) -> Result<Vec<u8>> {
    let path = if claim.statement()?.path().is_some() {
        Some(take_path(&mut secrets))
    } else {
        None
    };
    let mut witness: Witness = openings(secrets)?.into();
    if let Some(path) = path {
        witness = witness.with_path(path?);
    }
    Ok(zk.prove(claim, witness)?.as_bytes().to_vec())
}

/// A conjunction takes one secret per distinct commitment (in order of first appearance across
/// its claims), then one Merkle path per set claim.
fn prove_all(zk: &Predicates, claim: &Conjunction, mut secrets: Vec<String>) -> Result<Vec<u8>> {
    let distinct = claim.commitments().len();
    if secrets.len() < distinct {
        secrets.iter_mut().for_each(Zeroize::zeroize);
        return Err(ZkError::Predicate(format!(
            "the conjunction needs {distinct} opening secret(s) before any set paths"
        )));
    }
    let mut paths = secrets.split_off(distinct);
    let parsed: Result<Vec<SetPath>> = paths.iter().map(|p| SetPath::from_json(p)).collect();
    paths.iter_mut().for_each(Zeroize::zeroize);
    let witness = ConjunctionWitness {
        openings: openings(secrets)?,
        paths: parsed?,
    };
    Ok(zk.prove_all(claim, witness)?.as_bytes().to_vec())
}

/// Remove the final secret and parse it as a set path, overwriting its text.
fn take_path(secrets: &mut Vec<String>) -> Result<SetPath> {
    let mut text = secrets.pop().ok_or_else(|| {
        ZkError::Predicate("a set claim needs its path as the last secret".into())
    })?;
    let path = SetPath::from_json(&text);
    text.zeroize();
    path
}

fn tree(int_type: &str, values_json: &str) -> Result<SetTree> {
    let values: Vec<Number> =
        serde_json::from_str(values_json).map_err(|e| ZkError::Format(e.to_string()))?;
    SetTree::new(int_type.parse()?, values)
}

/// The public commitment text of the set of decimal strings in the JSON array `values_json`.
pub fn set_commitment(int_type: &str, values_json: &str) -> Result<String> {
    Ok(tree(int_type, values_json)?.commitment().to_text())
}

/// The private Merkle path (JSON) showing `value` is in the set, or with `absent` that it is not.
pub fn set_path(int_type: &str, values_json: &str, value: &str, absent: bool) -> Result<String> {
    let tree = tree(int_type, values_json)?;
    let value: Number = value.parse()?;
    let path = if absent {
        tree.absence_path(value)?
    } else {
        tree.member_path(value)?
    };
    Ok(path.to_json())
}

pub fn verify(zk: &Predicates, claim_json: &str, proof: &[u8]) -> Result<()> {
    let proof = PredicateProof::from_bytes(proof.to_vec());
    match Claim::from_json(claim_json)? {
        Claim::Single(claim) => zk.verify(&claim, &proof),
        Claim::All(claim) => zk.verify_all(&claim, &proof),
    }
}

/// Circuit name, attained security level and public inputs of a claim, for display and
/// interoperability checks.
pub fn describe(zk: &Predicates, claim_json: &str) -> Result<String> {
    let describe_one = |claim: &Predicate| -> Result<String> {
        let statement = claim.statement()?;
        Ok(format!(
            "{} {}-bit {:?}",
            statement.circuit(),
            zk.security_bits(statement.circuit())?,
            statement.public_inputs()
        ))
    };
    match Claim::from_json(claim_json)? {
        Claim::Single(claim) => describe_one(&claim),
        Claim::All(all) => Ok(all
            .claims()
            .iter()
            .map(describe_one)
            .collect::<Result<Vec<_>>>()?
            .join(
                "
",
            )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_round_trip_proves_and_verifies() {
        let zk = Predicates::new();
        let made = commit("i64", "-4").unwrap();
        let claim = format!(
            r#"{{"kind":"compare","commitment":"{}","op":"lt","bound":"0"}}"#,
            made.commitment
        );
        let proof = prove(&zk, &claim, vec![made.secret.clone()]).unwrap();
        verify(&zk, &claim, &proof).unwrap();
        assert!(describe(&zk, &claim)
            .unwrap()
            .starts_with("compare_64 116-bit"));
        assert!(verify(&zk, &claim.replace("\"lt\"", "\"gt\""), &proof).is_err());
        assert!(prove(&zk, &claim, vec![]).is_err());
        assert!(prove(&zk, &claim, vec![made.secret.clone(); 3]).is_err());
        assert!(commit("u7", "1").is_err() && commit("u32", "-1").is_err());
    }
}
