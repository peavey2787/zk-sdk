use thiserror::Error;
use zk_witness::WitnessError;

pub type Result<T> = std::result::Result<T, Groth16Error>;

#[derive(Debug, Error)]
pub enum Groth16Error {
    #[error("malformed {0}")]
    Format(String),
    #[error("unknown or unapproved circuit `{0}`")]
    Unapproved(String),
    #[error("witness: {0}")]
    Witness(#[from] WitnessError),
    #[error("proving failed: {0}")]
    Prove(String),
    #[error("proof rejected")]
    Rejected,
    #[error("randomness unavailable: {0}")]
    Randomness(String),
}
