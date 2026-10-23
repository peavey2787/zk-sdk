//! Predicate-first proving: say what is true about a committed value and prove it, with no
//! circuit, compiler or setup in the developer's hands.
//!
//! ```no_run
//! # fn demo() -> zk_sdk::Result<()> {
//! use zk_sdk::predicate::{Commitment, IntType, Predicate, Predicates};
//!
//! let (commitment, opening) = Commitment::commit(IntType::U32, 20u32)?; // commitment is public
//! let zk = Predicates::new();
//! let claim = Predicate::at_least(commitment, 18);
//! let proof = zk.prove(&claim, opening)?;
//! zk.verify(&claim, &proof)?;
//! # Ok(()) }
//! ```

mod api;
mod approved;
mod arithmetic;
mod bundle;
mod claim;
mod commit;
mod compose;
mod credential;
#[cfg(test)]
mod differential;
mod distance;
mod engine;
mod exact;
mod hash;
mod int;
mod semantics;
mod set;
mod statement;
mod transition;

pub use api::{
    commit, credential_issue, credential_present, describe, prove, set_commitment, set_path,
    transition_claim, verify, Committed, LoweredTransition,
};
pub use arithmetic::MAX_TERMS;
pub use claim::{Op, Operand, Predicate};
pub use commit::{Commitment, Opening};
pub use compose::{Claim, Conjunction, ConjunctionWitness, MAX_CLAIMS};
pub use credential::{
    Credential, CredentialEntry, CredentialIssuer, IssuerCommitment, Presentation,
};
pub use engine::{PredicateProof, Predicates, Witness};
pub use int::{IntType, Number, Width};
pub use set::{SetCommitment, SetPath, SetTree, SET_DEPTHS};
pub use statement::Statement;
pub use transition::{Rule, Transition};
