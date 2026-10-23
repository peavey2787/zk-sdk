//! Text-and-bytes entry points to the predicate engine: the single implementation behind the CLI
//! and the browser bindings. Claims and secrets are JSON; proofs are opaque bytes. Verification
//! takes only the trusted claim and the proof, never statement data from the proof itself.

use serde::Serialize;

use super::claim::Predicate;
use super::commit::{Commitment, Opening};
use super::engine::{PredicateProof, Predicates, Witness};
use super::int::{IntType, Number};
use crate::{Result, ZkError};

/// A fresh commitment: publish `commitment`, keep `secret` private.
#[derive(Serialize)]
pub struct Committed {
    pub commitment: String,
    pub secret: String,
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

fn witness(secrets: &[String]) -> Result<Witness> {
    if secrets.is_empty() {
        return Err(ZkError::Predicate(
            "provide one secret per committed value".into(),
        ));
    }
    let openings: Result<Vec<Opening>> = secrets
        .iter()
        .map(|s| Opening::from_secret_json(s))
        .collect();
    Ok(openings?.into())
}

/// Prove the JSON claim with the given secrets (one per committed value, in claim order).
pub fn prove(zk: &Predicates, claim_json: &str, secrets: &[String]) -> Result<Vec<u8>> {
    let claim = Predicate::from_json(claim_json)?;
    Ok(zk.prove(&claim, witness(secrets)?)?.as_bytes().to_vec())
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
        let proof = prove(&zk, &claim, std::slice::from_ref(&made.secret)).unwrap();
        verify(&zk, &claim, &proof).unwrap();
        assert!(describe(&zk, &claim)
            .unwrap()
            .starts_with("compare_64 116-bit"));
        assert!(verify(&zk, &claim.replace("\"lt\"", "\"gt\""), &proof).is_err());
        assert!(prove(&zk, &claim, &[]).is_err());
        assert!(prove(&zk, &claim, &vec![made.secret.clone(); 3]).is_err());
        assert!(commit("u7", "1").is_err() && commit("u32", "-1").is_err());
    }
}
