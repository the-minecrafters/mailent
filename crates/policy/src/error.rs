use thiserror::Error;

#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("failed to parse policy pack: {0}")]
    ParseError(String),

    #[error("unknown rule identifier: {0}")]
    UnknownRule(String),
}
