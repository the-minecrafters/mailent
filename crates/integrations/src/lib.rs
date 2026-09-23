use async_trait::async_trait;
use mailent_domain::Finding;
use thiserror::Error;

pub mod ct;
pub mod dane;
pub mod mta_sts;
pub mod resolver;
pub mod tls_rpt;

pub use ct::evaluate_ct_certificate_event;
pub use dane::{parse_tlsa_record, validate_dane, validate_tlsa};
pub use mta_sts::{
    MtaStsValidationResult, evaluate_session_against_mta_sts, matches_mx_pattern,
    parse_mta_sts_policy,
};
pub use resolver::{
    DomainIntelligenceResolver, LiveDomainIntelligenceResolver, MockDomainIntelligenceResolver,
    SrvRecord,
};
pub use tls_rpt::{parse_tls_rpt_json, parse_tls_rpt_policy};

#[derive(Error, Debug)]
pub enum IntegrationError {
    #[error("network connection failed: {0}")]
    Network(String),

    #[error("formatting failed: {0}")]
    Format(String),
}

#[async_trait]
pub trait AlertSink: Send + Sync {
    async fn send_alert(&self, finding: &Finding) -> Result<(), IntegrationError>;
}

/// Boundary configuration for webhook alert forwarding
#[derive(Debug, Clone)]
pub struct WebhookSinkConfig {
    pub endpoint_url: String,
    pub auth_header: Option<String>,
}

/// Boundary configuration for Syslog/CEF forwarding
#[derive(Debug, Clone)]
pub struct SyslogSinkConfig {
    pub host: String,
    pub port: u16,
    pub facility: u8,
}
