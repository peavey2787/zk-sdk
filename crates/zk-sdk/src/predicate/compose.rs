//! Conjunctions: several claims proved together over shared commitments.
//!
//! A [`Conjunction`] holds up to [`MAX_CLAIMS`] ordinary claims. Its proof is one independent proof
//! per claim, framed together, and it verifies only when every one verifies against its own claim
//! as the verifier derived it. **Shared-witness binding** comes from the commitments themselves: a
//! commitment that appears in several claims is opened once by the prover, and every sub-proof is
//! verified against that same public digest, so all of them speak about the one value and blinding
//! it binds. Two *different* commitments to equal values are not linked by this; add a
//! `compare_committed(.., Eq, ..)` claim to say they are equal.
//!
//! This is composition by AND only. Disjunction across unrelated claims would have to hide which
//! branch holds, which separate proofs cannot do; the hidden-branch unions the library does offer
//! are single circuits (`in_any_range`, set membership).

use serde::{Deserialize, Serialize};

use super::claim::Predicate;
use super::commit::{Commitment, Opening};
use super::engine::{PredicateProof, Predicates, Witness};
use super::set::SetPath;
use crate::{Result, ZkError};

/// The most claims one conjunction combines.
pub const MAX_CLAIMS: usize = 8;

/// `claim_1 AND claim_2 AND ...`, JSON `{"kind":"all","claims":[...]}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conjunction {
    claims: Vec<Predicate>,
}

/// The wire form of a conjunction.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    kind: String,
    claims: Vec<Predicate>,
}

impl Conjunction {
    /// Combine `claims`; each must lower to a circuit on its own, and there are one to
    /// [`MAX_CLAIMS`] of them.
    pub fn new(claims: Vec<Predicate>) -> Result<Self> {
        if claims.is_empty() || claims.len() > MAX_CLAIMS {
            return Err(ZkError::Predicate(format!(
                "a conjunction combines 1 to {MAX_CLAIMS} claims, got {}",
                claims.len()
            )));
        }
        claims
            .iter()
            .try_for_each(|claim| claim.statement().map(drop))?;
        Ok(Self { claims })
    }

    pub fn claims(&self) -> &[Predicate] {
        &self.claims
    }

    /// The distinct commitments to open, in order of first appearance across the claims. The
    /// witness supplies one opening for each, however many claims share it.
    pub fn commitments(&self) -> Vec<Commitment> {
        let mut unique: Vec<Commitment> = Vec::new();
        for claim in &self.claims {
            for commitment in claim.statement().iter().flat_map(|s| s.committed()) {
                if !unique.contains(commitment) {
                    unique.push(*commitment);
                }
            }
        }
        unique
    }

    /// How many claims need a Merkle path (set claims), in claim order.
    pub fn path_count(&self) -> usize {
        self.claims
            .iter()
            .filter(|claim| claim.statement().is_ok_and(|s| s.path().is_some()))
            .count()
    }

    pub fn to_json(&self) -> String {
        let wire = Wire {
            kind: "all".into(),
            claims: self.claims.clone(),
        };
        serde_json::to_string(&wire).expect("claims always serialize")
    }

    fn from_wire(wire: Wire) -> Result<Self> {
        if wire.kind != "all" {
            return Err(ZkError::Format(format!(
                "not a conjunction: kind {}",
                wire.kind
            )));
        }
        Self::new(wire.claims)
    }

    /// One ordinary witness per claim: its openings picked out of the shared pool by commitment,
    /// and its path taken from `paths` in claim order.
    fn witnesses(&self, witness: ConjunctionWitness) -> Result<Vec<Witness>> {
        let shared = self.commitments();
        if witness.openings.len() != shared.len() {
            return Err(ZkError::Predicate(format!(
                "the conjunction needs {} distinct opening(s), got {}",
                shared.len(),
                witness.openings.len()
            )));
        }
        for (index, (opening, commitment)) in witness.openings.iter().zip(&shared).enumerate() {
            if !opening.opens(commitment) {
                return Err(ZkError::Predicate(format!(
                    "opening {index} does not match its commitment"
                )));
            }
        }
        if witness.paths.len() != self.path_count() {
            return Err(ZkError::Predicate(format!(
                "the conjunction needs {} set path(s), got {}",
                self.path_count(),
                witness.paths.len()
            )));
        }
        let mut paths = witness.paths.iter();
        self.claims
            .iter()
            .map(|claim| {
                let statement = claim.statement()?;
                let picked = statement
                    .committed()
                    .iter()
                    .filter_map(|c| shared.iter().position(|s| s == c))
                    .map(|index| witness.openings[index].clone())
                    .collect::<Vec<_>>();
                let sub = Witness::from(picked);
                Ok(match statement.path() {
                    Some(_) => sub.with_path(
                        paths
                            .next()
                            .cloned()
                            .ok_or_else(|| ZkError::Predicate("a set path is missing".into()))?,
                    ),
                    None => sub,
                })
            })
            .collect()
    }
}

/// The openings of a conjunction's distinct commitments (see [`Conjunction::commitments`]) and the
/// Merkle paths of its set claims (see [`Conjunction::path_count`]). One prover must hold them all.
pub struct ConjunctionWitness {
    pub openings: Vec<Opening>,
    pub paths: Vec<SetPath>,
}

/// Either a single claim or a conjunction: what the JSON entry points accept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Claim {
    Single(Box<Predicate>),
    All(Conjunction),
}

impl Claim {
    pub fn from_json(text: &str) -> Result<Self> {
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|e| ZkError::Format(e.to_string()))?;
        if value.get("kind").and_then(|k| k.as_str()) == Some("all") {
            let wire: Wire =
                serde_json::from_value(value).map_err(|e| ZkError::Format(e.to_string()))?;
            return Conjunction::from_wire(wire).map(Self::All);
        }
        Predicate::from_json(text).map(|claim| Self::Single(Box::new(claim)))
    }
}

fn frame(proofs: &[PredicateProof]) -> PredicateProof {
    let mut bytes = (proofs.len() as u32).to_le_bytes().to_vec();
    for proof in proofs {
        bytes.extend((proof.as_bytes().len() as u32).to_le_bytes());
        bytes.extend(proof.as_bytes());
    }
    PredicateProof::from_bytes(bytes)
}

fn take<'a>(bytes: &mut &'a [u8], count: usize) -> Result<&'a [u8]> {
    if bytes.len() < count {
        return Err(ZkError::Format("truncated conjunction proof".into()));
    }
    let (head, rest) = bytes.split_at(count);
    *bytes = rest;
    Ok(head)
}

fn take_length(bytes: &mut &[u8]) -> Result<usize> {
    let raw = take(bytes, 4)?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize)
}

fn unframe(proof: &PredicateProof, expected: usize) -> Result<Vec<PredicateProof>> {
    let mut bytes = proof.as_bytes();
    let count = take_length(&mut bytes)?;
    if count != expected {
        return Err(ZkError::Format(format!(
            "the proof has {count} part(s) but the conjunction has {expected} claim(s)"
        )));
    }
    let parts = (0..count)
        .map(|_| {
            let length = take_length(&mut bytes)?;
            take(&mut bytes, length).map(|part| PredicateProof::from_bytes(part.to_vec()))
        })
        .collect::<Result<Vec<_>>>()?;
    if bytes.is_empty() {
        Ok(parts)
    } else {
        Err(ZkError::Format("trailing bytes after the proof".into()))
    }
}

impl Predicates {
    /// Prove every claim of `claim`, sharing the openings. Fails, before any proof is attempted,
    /// when a claim is false for the witness.
    pub fn prove_all(
        &self,
        claim: &Conjunction,
        witness: ConjunctionWitness,
    ) -> Result<PredicateProof> {
        let witnesses = claim.witnesses(witness)?;
        for (index, (part, sub)) in claim.claims.iter().zip(&witnesses).enumerate() {
            if let Some(reason) = sub.refusal(part)? {
                return Err(ZkError::Predicate(format!(
                    "claim {index} of the conjunction is false, so no proof exists: {reason}"
                )));
            }
        }
        let proofs = claim
            .claims
            .iter()
            .zip(witnesses)
            .map(|(part, sub)| self.prove(part, sub))
            .collect::<Result<Vec<_>>>()?;
        Ok(frame(&proofs))
    }

    /// Verify a conjunction proof: every part must verify against its own claim.
    pub fn verify_all(&self, claim: &Conjunction, proof: &PredicateProof) -> Result<()> {
        let parts = unframe(proof, claim.claims.len())?;
        claim
            .claims
            .iter()
            .zip(&parts)
            .try_for_each(|(part, proof)| self.verify(part, proof))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::predicate::int::IntType;

    fn commit(value: u8) -> Commitment {
        Commitment::commit_with_blinding(IntType::U32, value, [9; 8])
            .unwrap()
            .0
    }

    #[test]
    fn shared_commitments_are_opened_once_in_order_of_appearance() {
        let (a, b) = (commit(1), commit(2));
        let all = Conjunction::new(vec![
            Predicate::at_least(a, 1u8),
            Predicate::compare_committed(a, crate::predicate::Op::Lt, b),
            Predicate::at_most(b, 9u8),
        ])
        .unwrap();
        assert_eq!(all.commitments(), vec![a, b]);
        assert_eq!(all.path_count(), 0);
    }

    #[test]
    fn size_and_shape_are_bounded() {
        let a = commit(1);
        assert!(Conjunction::new(Vec::new()).is_err());
        assert!(Conjunction::new(vec![Predicate::opens(a); MAX_CLAIMS + 1]).is_err());
        assert!(Conjunction::new(vec![Predicate::opens(a); MAX_CLAIMS]).is_ok());
        let wide = Commitment::commit_with_blinding(IntType::I64, 1u8, [1; 8])
            .unwrap()
            .0;
        let mismatch = Predicate::compare_committed(a, crate::predicate::Op::Eq, wide);
        assert!(Conjunction::new(vec![mismatch]).is_err());
    }

    #[test]
    fn json_round_trips_and_dispatches() {
        let a = commit(1);
        let all = Conjunction::new(vec![Predicate::opens(a), Predicate::at_least(a, 1u8)]).unwrap();
        assert_eq!(
            Claim::from_json(&all.to_json()).unwrap(),
            Claim::All(all.clone())
        );
        let single = Predicate::opens(a);
        assert_eq!(
            Claim::from_json(&single.to_json()).unwrap(),
            Claim::Single(Box::new(single))
        );
        assert!(Claim::from_json(r#"{"kind":"all","claims":[],"extra":1}"#).is_err());
        assert!(Claim::from_json(r#"{"kind":"all","claims":[]}"#).is_err());
    }

    #[test]
    fn proof_framing_rejects_every_malformed_shape() {
        let parts = [vec![1u8, 2], vec![3u8]].map(PredicateProof::from_bytes);
        let framed = frame(&parts);
        assert_eq!(unframe(&framed, 2).unwrap(), parts);
        assert!(unframe(&framed, 1).is_err(), "wrong part count");
        let bytes = framed.as_bytes();
        for cut in 0..bytes.len() {
            let truncated = PredicateProof::from_bytes(bytes[..cut].to_vec());
            assert!(unframe(&truncated, 2).is_err(), "cut at {cut}");
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(unframe(&PredicateProof::from_bytes(trailing), 2).is_err());
        let mut huge = bytes.to_vec();
        huge[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(unframe(&PredicateProof::from_bytes(huge), 2).is_err());
    }

    #[test]
    fn duplicate_claims_still_need_one_opening() {
        let a = commit(1);
        let all = Conjunction::new(vec![Predicate::opens(a), Predicate::opens(a)]).unwrap();
        let unique: HashSet<_> = all.commitments().into_iter().collect();
        assert_eq!(unique.len(), 1);
    }
}
