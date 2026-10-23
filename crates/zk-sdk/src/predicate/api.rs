//! Text-and-bytes entry points to the predicate engine: the single implementation behind the CLI
//! and the browser bindings. Claims and secrets are JSON; proofs are opaque bytes. Verification
//! takes only the trusted claim and the proof, never statement data from the proof itself.

use serde::Serialize;
use zeroize::Zeroize;

use super::claim::Predicate;
use super::commit::{Commitment, Opening};
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
fn witness(mut secrets: Vec<String>) -> Result<Witness> {
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
    Ok(openings?.into())
}

/// Prove the JSON claim with the given secrets (one per committed value, in claim order). A set
/// membership or absence claim takes its Merkle path as one more, final secret. The secret texts
/// are taken by value and overwritten once parsed.
pub fn prove(zk: &Predicates, claim_json: &str, mut secrets: Vec<String>) -> Result<Vec<u8>> {
    let claim = Predicate::from_json(claim_json)?;
    let path = if claim.statement()?.path().is_some() {
        Some(take_path(&mut secrets))
    } else {
        None
    };
    let witness = witness(secrets);
    let mut witness = witness?;
    if let Some(path) = path {
        witness = witness.with_path(path?);
    }
    Ok(zk.prove(&claim, witness)?.as_bytes().to_vec())
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
    zk.verify(
        &Predicate::from_json(claim_json)?,
        &PredicateProof::from_bytes(proof.to_vec()),
    )
}

/// Circuit name, attained security level and public inputs of a claim, for display and
/// interoperability checks.
pub fn describe(zk: &Predicates, claim_json: &str) -> Result<String> {
    let statement = Predicate::from_json(claim_json)?.statement()?;
    Ok(format!(
        "{} {}-bit {:?}",
        statement.circuit(),
        zk.security_bits(statement.circuit())?,
        statement.public_inputs()
    ))
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
