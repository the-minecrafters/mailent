#[derive(Debug, thiserror::Error)]
pub enum SensorError {
    #[error("capture I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid capture: {0}")]
    Input(String),
    #[error("Zeek analysis failed: {0}")]
    Zeek(String),
    #[error("Zeek normalization failed: {0}")]
    Normalize(String),
    #[error("serialization: {0}")]
    Json(#[from] serde_json::Error),
    #[error("core submission failed: {0}")]
    Submit(String),
}
