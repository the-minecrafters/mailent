use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Important security events emitted by Mailent control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationEventType {
    InvestigationCreated,
    FindingConfirmed,
    VerificationCompleted,
    RemediationVerified,
    VerificationFailed,
    InfrastructureDriftDetected,
    SecurityRegressionDetected,
}

impl std::fmt::Display for IntegrationEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvestigationCreated => write!(f, "investigation_created"),
            Self::FindingConfirmed => write!(f, "finding_confirmed"),
            Self::VerificationCompleted => write!(f, "verification_completed"),
            Self::RemediationVerified => write!(f, "remediation_verified"),
            Self::VerificationFailed => write!(f, "verification_failed"),
            Self::InfrastructureDriftDetected => write!(f, "infrastructure_drift_detected"),
            Self::SecurityRegressionDetected => write!(f, "security_regression_detected"),
        }
    }
}

/// Destination kind for an integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationKind {
    Webhook,
    Syslog,
}

impl std::fmt::Display for IntegrationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Webhook => write!(f, "Webhook"),
            Self::Syslog => write!(f, "Syslog (RFC 5424 / CEF)"),
        }
    }
}

/// Configuration of an outbound workflow integration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IntegrationConfig {
    pub id: Uuid,
    pub name: String,
    pub kind: IntegrationKind,
    /// Webhook URL (e.g. https://soc.corp.example/alerts) or Syslog address (udp://host:514 or tcp://host:514)
    pub destination: String,
    pub event_types: Vec<IntegrationEventType>,
    pub enabled: bool,
    /// Optional authorization header or shared secret
    pub auth_header: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_delivery_at: Option<OffsetDateTime>,
    pub last_status_code: Option<u16>,
    pub last_error: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// Request to create or update an integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertIntegrationRequest {
    pub name: String,
    pub kind: IntegrationKind,
    pub destination: String,
    pub event_types: Vec<IntegrationEventType>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub auth_header: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Structured payload dispatched to outbound integrations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IntegrationEventPayload {
    pub event_id: Uuid,
    pub event_type: IntegrationEventType,
    pub title: String,
    pub summary: String,
    pub asset_id: Option<Uuid>,
    pub asset_name: Option<String>,
    pub investigation_id: Option<Uuid>,
    pub finding_id: Option<Uuid>,
    pub probe_id: Option<Uuid>,
    pub details: serde_json::Value,
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
}

impl IntegrationEventPayload {
    /// Formats the event as a standard ArcSight Common Event Format (CEF) string
    /// suitable for enterprise SIEM ingestion (Splunk, Sentinel, QRadar, etc.).
    pub fn to_cef(&self) -> String {
        let severity = match self.event_type {
            IntegrationEventType::FindingConfirmed => "8",
            IntegrationEventType::SecurityRegressionDetected => "8",
            IntegrationEventType::VerificationFailed => "7",
            IntegrationEventType::InvestigationCreated => "6",
            IntegrationEventType::InfrastructureDriftDetected => "4",
            IntegrationEventType::VerificationCompleted => "3",
            IntegrationEventType::RemediationVerified => "1",
        };
        let escaped_title = self.title.replace('\\', "\\\\").replace('|', "\\|");
        format!(
            "CEF:0|Mailent|Mailent Core|1.0.0|{}|{}|{}|msg={} cs1Label=Asset cs1={} cs2Label=EventID cs2={}",
            self.event_type,
            escaped_title,
            severity,
            self.summary.replace('\\', "\\\\").replace('=', "\\="),
            self.asset_name.as_deref().unwrap_or("unknown"),
            self.event_id
        )
    }
}
