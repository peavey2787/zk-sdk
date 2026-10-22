use thiserror::Error;

pub type Result<T> = std::result::Result<T, WitnessError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WitnessError {
    #[error("malformed circuit or input file: {0}")]
    Format(String),
    #[error("unknown circuit input `{0}`")]
    UnknownInput(String),
    #[error("missing value for circuit input `{0}`")]
    MissingInput(String),
    #[error("input `{0}` is not a canonical field element")]
    NotCanonical(String),
    #[error("{0} intermediate signal(s) could not be determined from the inputs")]
    Unsolved(usize),
    #[error("inputs do not satisfy constraint {0}")]
    Unsatisfied(usize),
}
