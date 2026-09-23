use thiserror::Error;

#[derive(Error, Debug)]
pub enum DomainError {
    #[error("invalid observation: {0}")]
    InvalidObservation(String),

    #[error("invalid state transition: {0}")]
    InvalidStateTransition(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
