use thiserror::Error;

#[derive(Error, Debug)]
pub enum EventBusError {
    #[error("event bus channel closed")]
    ChannelClosed,

    #[error("channel buffer is full: {0}")]
    BufferFull(String),

    #[error("event serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("distributed bus unavailable: {0}")]
    Unavailable(String),
}
