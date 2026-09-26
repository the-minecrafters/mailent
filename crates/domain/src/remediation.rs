use crate::{
    EmailSession, Finding, GuidanceKind, ProbeOutcome, ProbeRun, ProbeStartTlsResult,
    RemediationGuidance, TlsVersion,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationState {
    InProgress,
    Applied,
    Verifying,
    VerifiedFixed,
    StillPresent,
    Inconclusive,
}

/// A condition tied to an existing policy finding, never inferred from best-practice advice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationCondition {
    LegacyTlsDisabled,
    StartTlsAvailable,
    CertificateValid,
    ForwardSecrecyOnly,
}
impl RemediationCondition {
    pub fn for_guidance(guidance: &RemediationGuidance) -> Option<Self> {
        if guidance.kind != GuidanceKind::Remediation || guidance.finding_id.is_none() {
            return None;
        }
        match guidance.rule_id.as_str() {
            "TLS_LEGACY_VERSION" => Some(Self::LegacyTlsDisabled),
            "STARTTLS_NOT_ADVERTISED" | "STARTTLS_MISSING" => Some(Self::StartTlsAvailable),
            "CERTIFICATE_EXPIRED" | "CERTIFICATE_SELF_SIGNED" | "CERTIFICATE_INVALID" => {
                Some(Self::CertificateValid)
            }
            "NO_FORWARD_SECRECY" => Some(Self::ForwardSecrecyOnly),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeOutcome {
    Accepted,
    Rejected,
    Unavailable,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TlsChallenge {
    pub version: TlsVersion,
    pub outcome: ChallengeOutcome,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemediationAttempt {
    pub request_id: Uuid,
    pub probe_id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub requested_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub completed_at: Option<OffsetDateTime>,
    pub outcome: Option<RemediationState>,
    pub explanation: String,
    /// Canonical active evidence, kept separately from the immutable before snapshot.
    pub after: Option<ProbeRun>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemediationRecord {
    pub id: Uuid,
    pub asset_id: Uuid,
    pub investigation_id: Option<Uuid>,
    pub finding: Finding,
    pub guidance: RemediationGuidance,
    pub before: EmailSession,
    pub condition: RemediationCondition,
    pub state: RemediationState,
    pub revision: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub applied_at: Option<OffsetDateTime>,
    pub analyst_note: Option<String>,
    pub attempts: Vec<RemediationAttempt>,
}

/// Final outcome labels augment training snapshots; they never replace analyst labels or features.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemediationTrainingOutcome {
    pub remediation_id: Uuid,
    pub request_id: Uuid,
    pub probe_id: Uuid,
    pub rule_id: String,
    pub outcome: RemediationState,
    #[serde(with = "time::serde::rfc3339")]
    pub verified_at: OffsetDateTime,
}

/// Pure issue-specific comparison. This cannot close an investigation or delete findings.
pub fn verify_remediation(
    record: &RemediationRecord,
    probe: &ProbeRun,
) -> (RemediationState, String) {
    use RemediationState::*;
    let inconclusive = |reason: &str| (Inconclusive, reason.to_owned());
    if probe.asset_id != record.asset_id
        || probe.protocol != record.before.protocol
        || probe.port != record.before.flow.dst_port
    {
        return inconclusive("The check does not match the original mail server connection.");
    }
    if probe.outcome != ProbeOutcome::Success || probe.finished_at.is_none() {
        return inconclusive("The check failed or is incomplete. The fix has not been verified.");
    }
    let Some(result) = &probe.result else {
        return inconclusive("No active evidence");
    };
    if let Some(err) = &result.error {
        let is_cert_issue = err.contains("certificate")
            || err.contains("unknown issuer")
            || err.contains("self-signed")
            || err.contains("expired");
        if !is_cert_issue || record.condition == RemediationCondition::CertificateValid {
            return inconclusive(&format!("Transport verification reported an error: {err}"));
        }
    }
    if result.resolved_ip.as_deref() != Some(record.before.flow.dst_ip.as_str()) {
        return inconclusive(
            "The check reached a different address. The original connection has not been verified.",
        );
    }
    let finished = probe.finished_at.expect("completed probe checked");
    match record.condition {
        RemediationCondition::LegacyTlsDisabled => {
            if result
                .tls_version
                .as_ref()
                .is_some_and(TlsVersion::is_legacy)
                || result
                    .tls_challenges
                    .iter()
                    .any(|c| c.outcome == ChallengeOutcome::Accepted)
            {
                return (
                    StillPresent,
                    "The affected endpoint still accepts a legacy TLS handshake".into(),
                );
            }
            if !result
                .tls_version
                .as_ref()
                .is_some_and(TlsVersion::is_modern)
            {
                return inconclusive("Modern TLS was not established");
            }
            if [TlsVersion::Tls10, TlsVersion::Tls11].iter().all(|v| {
                result
                    .tls_challenges
                    .iter()
                    .any(|c| &c.version == v && c.outcome == ChallengeOutcome::Rejected)
            }) {
                (VerifiedFixed, "Modern TLS established and the server explicitly rejected TLS 1.0 and TLS 1.1 at the affected endpoint".into())
            } else {
                inconclusive(
                    "Legacy protocol refusal was not conclusively observed for both TLS 1.0 and TLS 1.1",
                )
            }
        }
        RemediationCondition::StartTlsAvailable => match result.starttls {
            ProbeStartTlsResult::NotAdvertised | ProbeStartTlsResult::AdvertisedAndRejected => {
                (StillPresent, "STARTTLS remains unavailable".into())
            }
            ProbeStartTlsResult::AdvertisedAndAccepted if result.tls_version.is_some() => (
                VerifiedFixed,
                "STARTTLS advertised, accepted, and TLS established at the affected endpoint"
                    .into(),
            ),
            _ => inconclusive("No completed STARTTLS exchange"),
        },
        RemediationCondition::CertificateValid => {
            let Some(cert) = &result.certificate else {
                return inconclusive("Certificate unavailable");
            };
            if cert.validity.is_expired_at(finished)
                || cert.validity.is_not_yet_valid_at(finished)
                || result.certificate_hostname_valid == Some(false)
                || result.certificate_trusted == Some(false)
            {
                return (
                    StillPresent,
                    "Certificate validity, hostname, or trust validation still fails".into(),
                );
            }
            if result.certificate_hostname_valid != Some(true)
                || result.certificate_trusted != Some(true)
            {
                return inconclusive("Certificate validation evidence is incomplete");
            }
            (VerifiedFixed, "The affected endpoint presents a currently valid certificate with verified hostname and trust chain".into())
        }
        RemediationCondition::ForwardSecrecyOnly => inconclusive(
            "A preferred forward-secret handshake cannot prove static RSA is disabled; constrained cipher refusal verification is not available",
        ),
    }
}
