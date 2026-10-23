use thiserror::Error;

pub type Result<T> = std::result::Result<T, ZkError>;

#[derive(Debug, Error)]
pub enum ZkError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid artifact or unsupported format: {0}")]
    Format(String),
    #[error("security configuration rejected: {0}")]
    Policy(String),
    #[error(
        "requested {requested} bits of security, but this circuit can attain at most {attainable}; \na lower level is used only if the caller explicitly lowers the minimum"
    )]
    SecurityUnattainable { requested: u16, attainable: u16 },
    #[error("backend unavailable: {0}")]
    Unavailable(String),
    #[error("backend operation failed: {0}")]
    Backend(String),
    #[error("invalid predicate: {0}")]
    Predicate(String),
    #[error("proof does not match the expected statement or verifying key")]
    StatementMismatch,
}
