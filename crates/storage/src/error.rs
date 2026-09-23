use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("immutable evidence conflict: {0}")]
    Conflict(String),

    #[error("entity not found: {0}")]
    NotFound(String),

    #[error("storage backend error: {0}")]
    Backend(String),
}
