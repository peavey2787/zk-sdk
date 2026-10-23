//! Private state transitions with application-defined deterministic rules.
//!
//! A state is a list of committed fields. A [`Transition`] relates an `old` state to a `new` one
//! by a list of [`Rule`]s, each a deterministic relation over exact integers: a field changes by a
//! public delta, stays or moves monotonically, a guard holds on the old state, an invariant holds
//! on the new one, or a set of fields conserves its total. The rules lower to ordinary claims of a
//! [`Conjunction`], so the proof reveals only the two commitment lists and the rules, and each
//! commitment is opened once across every rule that mentions it.
//!
//! Chaining is by commitment identity: when a step's `new` commitments are the next step's `old`
//! commitments ([`Transition::follows`]), the two steps speak about the same hidden state.

use serde::{Deserialize, Serialize};

use super::claim::{Op, Predicate};
use super::commit::{Commitment, Opening};
use super::compose::{Conjunction, ConjunctionWitness};
use super::int::Number;
use crate::{Result, ZkError};

/// One deterministic relation between the old and new state; `field` indexes the state lists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Rule {
    /// `new[field] op old[field]`: `eq` leaves it unchanged, `ge` lets it only grow.
    Compare { field: usize, op: Op },
    /// `new[field] == old[field] + delta`.
    Add { field: usize, delta: Number },
    /// `new[field] == old[field] - delta`.
    Sub { field: usize, delta: Number },
    /// Guard on the old state: `old[field] op bound`.
    Require { field: usize, op: Op, bound: Number },
    /// Invariant on the new state: `new[field] op bound`.
    Ensure { field: usize, op: Op, bound: Number },
    /// `sum(old[fields]) == sum(new[fields]) + fee`: value moves between fields, none appears.
    Conserve { fields: Vec<usize>, fee: Number },
}

/// A claimed step from the `old` state to the `new` one under `rules`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transition {
    old: Vec<Commitment>,
    new: Vec<Commitment>,
    claim: Conjunction,
}

impl Transition {
    /// States of equal, non-zero size whose matching fields share a type, and one to
    /// [`MAX_CLAIMS`](super::MAX_CLAIMS) rules over valid fields.
    pub fn new(old: Vec<Commitment>, new: Vec<Commitment>, rules: &[Rule]) -> Result<Self> {
        if old.is_empty() || old.len() != new.len() {
            return Err(ZkError::Predicate(
                "the old and new states need the same, non-zero number of fields".into(),
            ));
        }
        if let Some(i) = (0..old.len()).find(|&i| old[i].ty() != new[i].ty()) {
            return Err(ZkError::Predicate(format!(
                "field {i} changes type between the old and new state"
            )));
        }
        let claims = rules
            .iter()
            .map(|rule| lower(rule, &old, &new))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            claim: Conjunction::new(claims)?,
            old,
            new,
        })
    }

    /// The conjunction to prove and verify (`prove_all` / `verify_all`).
    pub fn claim(&self) -> &Conjunction {
        &self.claim
    }

    pub fn old(&self) -> &[Commitment] {
        &self.old
    }

    pub fn new_state(&self) -> &[Commitment] {
        &self.new
    }

    /// Whether this step starts exactly where `previous` ended.
    pub fn follows(&self, previous: &Transition) -> bool {
        self.old == previous.new
    }

    /// The witness from the openings of the old and new fields, in any order.
    pub fn witness(&self, openings: Vec<Opening>) -> Result<ConjunctionWitness> {
        let ordered = self
            .claim
            .commitments()
            .iter()
            .map(|commitment| {
                openings
                    .iter()
                    .find(|opening| opening.opens(commitment))
                    .cloned()
                    .ok_or_else(|| {
                        ZkError::Predicate(
                            "no opening matches a commitment of the transition".into(),
                        )
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(ConjunctionWitness {
            openings: ordered,
            paths: Vec::new(),
        })
    }
}

fn field(state: &[Commitment], index: usize) -> Result<Commitment> {
    state.get(index).copied().ok_or_else(|| {
        ZkError::Predicate(format!(
            "rule names field {index} but the state has {}",
            state.len()
        ))
    })
}

fn fields(state: &[Commitment], indexes: &[usize]) -> Result<Vec<Commitment>> {
    indexes.iter().map(|&i| field(state, i)).collect()
}

fn lower(rule: &Rule, old: &[Commitment], new: &[Commitment]) -> Result<Predicate> {
    Ok(match rule {
        Rule::Compare { field: f, op } => {
            Predicate::compare_committed(field(new, *f)?, *op, field(old, *f)?)
        }
        Rule::Add { field: f, delta } => Predicate::sum(
            vec![field(old, *f)?],
            *delta,
            Op::Eq,
            vec![field(new, *f)?],
            0,
        ),
        Rule::Sub { field: f, delta } => Predicate::sum(
            vec![field(old, *f)?],
            0,
            Op::Eq,
            vec![field(new, *f)?],
            *delta,
        ),
        Rule::Require {
            field: f,
            op,
            bound,
        } => Predicate::compare(field(old, *f)?, *op, *bound),
        Rule::Ensure {
            field: f,
            op,
            bound,
        } => Predicate::compare(field(new, *f)?, *op, *bound),
        Rule::Conserve { fields: f, fee } => {
            Predicate::conserve(fields(old, f)?, fields(new, f)?, *fee)
        }
    })
}
