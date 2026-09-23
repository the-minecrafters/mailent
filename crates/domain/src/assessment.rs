use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Evidence for application-layer protocol identification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolEvidence {
    pub protocol: String,
    pub role: String,
    pub proof: String,
    pub verified_by: String,
}

/// Metadata specific to offline PCAP / packet capture assessments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureMetadata {
    pub capture_name: String,
    pub capture_hash: String,
    pub capture_size_bytes: u64,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub time_range_start: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub time_range_end: Option<OffsetDateTime>,
}

/// Discovered network endpoint for mail services.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredEndpoint {
    pub service: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub priority: Option<u16>,
    #[serde(default)]
    pub resolved_ips: Vec<String>,
}

/// Provenance trace for domain service and DNS record discovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryEvidence {
    pub record_type: String,
    pub query: String,
    pub details: String,
    pub dnssec_status: String,
}

/// Metadata specific to live domain mail-infrastructure assessments.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InfrastructureMetadata {
    pub target_domain: String,
    pub discovered_endpoints: Vec<DiscoveredEndpoint>,
    #[serde(with = "time::serde::rfc3339")]
    pub scan_start: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub scan_end: OffsetDateTime,
    pub discovery_evidence: Vec<DiscoveryEvidence>,
}

/// Origin source of an assessment: offline packet capture or live domain scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AssessmentSource {
    Capture(CaptureMetadata),
    Infrastructure(InfrastructureMetadata),
}

/// First-class persistent forensic assessment record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssessmentRecord {
    pub id: Uuid,
    pub title: String,
    pub source: AssessmentSource,

    // Backward-compatibility fields (derived from source or stored directly):
    pub capture_name: String,
    pub capture_hash: String,
    pub capture_size_bytes: u64,

    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub time_range_start: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub time_range_end: Option<OffsetDateTime>,
    pub protocols_identified: Vec<String>,
    pub protocol_evidence: Vec<ProtocolEvidence>,
    pub session_ids: Vec<Uuid>,
    pub asset_ids: Vec<Uuid>,
    pub finding_ids: Vec<Uuid>,
    pub posture_score: f32,
    pub posture_grade: String,
    pub evidence_gaps: Vec<String>,
    pub ai_risk_classification: String,
    pub ai_risk_rationale: String,
    pub ai_confidence: f32,
    #[serde(default)]
    pub metadata: serde_json::Value,
    #[serde(default)]
    pub organization_id: Option<Uuid>,
}

impl AssessmentRecord {
    pub fn with_organization(mut self, organization_id: Uuid) -> Self {
        self.organization_id = Some(organization_id);
        self
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_capture(
        id: Uuid,
        title: String,
        capture: CaptureMetadata,
        created_at: OffsetDateTime,
        protocols_identified: Vec<String>,
        protocol_evidence: Vec<ProtocolEvidence>,
        session_ids: Vec<Uuid>,
        asset_ids: Vec<Uuid>,
        finding_ids: Vec<Uuid>,
        posture_score: f32,
        posture_grade: String,
        evidence_gaps: Vec<String>,
        ai_risk_classification: String,
        ai_risk_rationale: String,
        ai_confidence: f32,
        metadata: serde_json::Value,
    ) -> Self {
        let capture_name = capture.capture_name.clone();
        let capture_hash = capture.capture_hash.clone();
        let capture_size_bytes = capture.capture_size_bytes;
        let time_range_start = capture.time_range_start;
        let time_range_end = capture.time_range_end;
        Self {
            id,
            title,
            source: AssessmentSource::Capture(capture),
            capture_name,
            capture_hash,
            capture_size_bytes,
            created_at,
            time_range_start,
            time_range_end,
            protocols_identified,
            protocol_evidence,
            session_ids,
            asset_ids,
            finding_ids,
            posture_score,
            posture_grade,
            evidence_gaps,
            ai_risk_classification,
            ai_risk_rationale,
            ai_confidence,
            metadata,
            organization_id: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_infrastructure(
        id: Uuid,
        title: String,
        infra: InfrastructureMetadata,
        created_at: OffsetDateTime,
        protocols_identified: Vec<String>,
        protocol_evidence: Vec<ProtocolEvidence>,
        session_ids: Vec<Uuid>,
        asset_ids: Vec<Uuid>,
        finding_ids: Vec<Uuid>,
        posture_score: f32,
        posture_grade: String,
        evidence_gaps: Vec<String>,
        ai_risk_classification: String,
        ai_risk_rationale: String,
        ai_confidence: f32,
        metadata: serde_json::Value,
    ) -> Self {
        let capture_name = format!("{} infrastructure", infra.target_domain);
        use sha2::{Digest, Sha256};
        let capture_hash = format!("{:x}", Sha256::digest(infra.target_domain.as_bytes()));
        let time_range_start = Some(infra.scan_start);
        let time_range_end = Some(infra.scan_end);
        Self {
            id,
            title,
            source: AssessmentSource::Infrastructure(infra),
            capture_name,
            capture_hash,
            capture_size_bytes: 0,
            created_at,
            time_range_start,
            time_range_end,
            protocols_identified,
            protocol_evidence,
            session_ids,
            asset_ids,
            finding_ids,
            posture_score,
            posture_grade,
            evidence_gaps,
            ai_risk_classification,
            ai_risk_rationale,
            ai_confidence,
            metadata,
            organization_id: None,
        }
    }

    pub fn source_type_str(&self) -> &'static str {
        match &self.source {
            AssessmentSource::Capture(_) => "capture",
            AssessmentSource::Infrastructure(_) => "infrastructure",
        }
    }

    pub fn target_domain(&self) -> Option<&str> {
        match &self.source {
            AssessmentSource::Infrastructure(infra) => Some(&infra.target_domain),
            AssessmentSource::Capture(_) => None,
        }
    }
}

/// Brief summary of an assessment for listings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssessmentSummary {
    pub id: Uuid,
    pub title: String,
    pub source_type: String,
    pub target: String,
    pub capture_name: String,
    pub capture_hash: String,
    pub capture_size_bytes: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub protocols_identified: Vec<String>,
    pub session_count: usize,
    pub finding_count: usize,
    pub posture_score: f32,
    pub posture_grade: String,
    pub ai_risk_classification: String,
    #[serde(default)]
    pub organization_id: Option<Uuid>,
}

impl From<&AssessmentRecord> for AssessmentSummary {
    fn from(r: &AssessmentRecord) -> Self {
        let (source_type, target) = match &r.source {
            AssessmentSource::Capture(c) => ("capture".to_string(), c.capture_name.clone()),
            AssessmentSource::Infrastructure(i) => {
                ("infrastructure".to_string(), i.target_domain.clone())
            }
        };
        Self {
            id: r.id,
            title: r.title.clone(),
            source_type,
            target,
            capture_name: r.capture_name.clone(),
            capture_hash: r.capture_hash.clone(),
            capture_size_bytes: r.capture_size_bytes,
            created_at: r.created_at,
            protocols_identified: r.protocols_identified.clone(),
            session_count: r.session_ids.len(),
            finding_count: r.finding_ids.len(),
            posture_score: r.posture_score,
            posture_grade: r.posture_grade.clone(),
            ai_risk_classification: r.ai_risk_classification.clone(),
            organization_id: r.organization_id,
        }
    }
}
