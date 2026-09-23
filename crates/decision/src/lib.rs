use async_trait::async_trait;
use mailent_domain::{DecisionContext, DecisionResult};
use thiserror::Error;

pub mod circuit_breaker;
pub mod jev;

pub use circuit_breaker::CircuitBreaker;
pub use jev::{JevConfig, JevProvider};

#[derive(Error, Debug)]
pub enum DecisionError {
    #[error("decision provider is disabled")]
    Disabled,

    #[error("circuit breaker open: external provider is temporarily unavailable")]
    CircuitBreakerOpen,

    #[error("decision provider timeout after {0} ms")]
    Timeout(u64),

    #[error("provider error: {0}")]
    ProviderFailure(String),
}

#[async_trait]
pub trait DecisionProvider: Send + Sync {
    async fn assess(&self, context: DecisionContext) -> Result<DecisionResult, DecisionError>;
}

/// A provider that explicitly performs no decision assessment.
/// Used for air-gapped deployments or when external decisions are intentionally disabled.
#[derive(Debug, Default, Clone)]
pub struct DisabledProvider;

#[async_trait]
impl DecisionProvider for DisabledProvider {
    async fn assess(&self, _context: DecisionContext) -> Result<DecisionResult, DecisionError> {
        Err(DecisionError::Disabled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_disabled_provider_returns_disabled_error() {
        let provider = DisabledProvider;
        let ctx = DecisionContext {
            session_id: Uuid::new_v4(),
            findings: vec![],
            metadata: serde_json::json!({}),
        };
        let res = provider.assess(ctx).await;
        assert!(matches!(res, Err(DecisionError::Disabled)));
    }
}
