use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DriftKind {
    // Existing variants
    NewTlsVersion,
    NewCipherSuite,
    KeyExchangeChanged,
    ForwardSecrecyLost,
    CertificateChanged,
    NewCertificateIssuer,
    NewEndpoint,

    // Infrastructure drift variants
    MxAdded,
    MxRemoved,
    EndpointAdded,
    EndpointRemoved,
    StartTlsLost,
    StartTlsRestored,
    LegacyTlsEnabled,
    LegacyTlsDisabled,
    ForwardSecrecyRestored,
    CertificateExpired,
    CertificateRenewed,
    CertificateTrustChanged,
    MtaStsChanged,
    DaneChanged,
    TlsRptChanged,
    FindingIntroduced,
    FindingResolved,
    PostureChanged,
}

impl DriftKind {
    /// Returns true if this change represents a regression in security posture,
    /// rather than a benign, maintenance, or positive security improvement.
    pub fn is_security_regression(&self) -> bool {
        matches!(
            self,
            Self::StartTlsLost
                | Self::LegacyTlsEnabled
                | Self::ForwardSecrecyLost
                | Self::CertificateExpired
                | Self::CertificateTrustChanged
        )
    }

    /// Returns true if this change represents a confirmed security resolution or improvement.
    pub fn is_security_improvement(&self) -> bool {
        matches!(
            self,
            Self::StartTlsRestored
                | Self::LegacyTlsDisabled
                | Self::ForwardSecrecyRestored
                | Self::CertificateRenewed
                | Self::FindingResolved
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftEvent {
    pub id: Uuid,
    pub asset_id: Uuid,
    pub kind: DriftKind,
    pub title: String,
    pub description: String,
    pub previous_value: Option<String>,
    pub new_value: String,
    #[serde(with = "time::serde::rfc3339")]
    pub observed_at: OffsetDateTime,
    #[serde(default)]
    pub session_id: Option<Uuid>,
    #[serde(default)]
    pub assessment_id: Option<Uuid>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub organization_id: Option<Uuid>,
}

impl DriftEvent {
    pub fn is_security_regression(&self) -> bool {
        self.kind.is_security_regression()
    }
}
