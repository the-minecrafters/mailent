use async_trait::async_trait;
use mailent_domain::{
    Asset, CertificateRecord, DriftEvent, EmailSession, Finding, NormalizedObservation,
    SensorHeartbeat, SensorRecord,
};
use uuid::Uuid;

use crate::error::StorageError;

#[async_trait]
pub trait AssetRepository: Send + Sync {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<Asset>, StorageError>;
    async fn find_by_address_or_identity(
        &self,
        identity: &str,
    ) -> Result<Option<Asset>, StorageError>;
    async fn upsert(&self, asset: Asset) -> Result<(), StorageError>;
    async fn list_all(&self) -> Result<Vec<Asset>, StorageError>;
    async fn save_drift_event(&self, event: DriftEvent) -> Result<(), StorageError>;
    async fn list_drift_events(
        &self,
        asset_id: Option<Uuid>,
        limit: usize,
    ) -> Result<Vec<DriftEvent>, StorageError>;
}

#[async_trait]
pub trait CertificateRepository: Send + Sync {
    async fn save(&self, cert: CertificateRecord) -> Result<(), StorageError>;
    async fn find_by_fingerprint(
        &self,
        fp: &str,
    ) -> Result<Option<CertificateRecord>, StorageError>;
    async fn list_all(&self) -> Result<Vec<CertificateRecord>, StorageError>;
    async fn list_for_asset(&self, asset_id: Uuid) -> Result<Vec<CertificateRecord>, StorageError>;
}

#[async_trait]
pub trait SensorRepository: Send + Sync {
    async fn record_heartbeat(&self, heartbeat: SensorHeartbeat) -> Result<(), StorageError>;
    async fn list_sensors(&self) -> Result<Vec<SensorRecord>, StorageError>;
    async fn get_sensor(&self, sensor_id: &str) -> Result<Option<SensorRecord>, StorageError>;
}

#[async_trait]
pub trait FindingRepository: Send + Sync {
    async fn link_asset(&self, finding_id: Uuid, asset_id: Uuid) -> Result<(), StorageError>;
    async fn save(&self, finding: Finding) -> Result<(), StorageError>;
    async fn list_all(&self) -> Result<Vec<Finding>, StorageError>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<Finding>, StorageError>;
    async fn list_for_session(&self, session_id: Uuid) -> Result<Vec<Finding>, StorageError>;
    async fn list_for_asset(&self, asset_id: Uuid) -> Result<Vec<Finding>, StorageError>;
}

#[async_trait]
pub trait SessionRepository: Send + Sync {
    async fn save(&self, session: EmailSession) -> Result<(), StorageError>;
    async fn list_recent(&self, limit: usize) -> Result<Vec<EmailSession>, StorageError>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<EmailSession>, StorageError>;
    async fn list_for_asset(
        &self,
        asset_ip: &str,
        limit: usize,
    ) -> Result<Vec<EmailSession>, StorageError>;
}

#[async_trait]
pub trait ObservationRepository: Send + Sync {
    async fn save(&self, observation: NormalizedObservation) -> Result<(), StorageError>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<NormalizedObservation>, StorageError>;
    async fn list_recent(&self, limit: usize) -> Result<Vec<NormalizedObservation>, StorageError>;
}

#[async_trait]
pub trait EvidenceStore: Send + Sync {
    async fn put(&self, key: &str, data: &[u8]) -> Result<(), StorageError>;
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError>;
}

#[async_trait]
pub trait IntelligenceRepository: Send + Sync {
    async fn save_mx_records(
        &self,
        domain: &str,
        records: &[mailent_domain::MxRecord],
    ) -> Result<(), StorageError>;
    async fn get_mx_records(
        &self,
        domain: &str,
    ) -> Result<Vec<mailent_domain::MxRecord>, StorageError>;

    async fn save_tlsa_records(
        &self,
        domain: &str,
        records: &[mailent_domain::TlsaRecord],
    ) -> Result<(), StorageError>;
    async fn get_tlsa_records(
        &self,
        domain: &str,
    ) -> Result<Vec<mailent_domain::TlsaRecord>, StorageError>;

    async fn save_mta_sts_policy(
        &self,
        policy: &mailent_domain::MtaStsPolicy,
    ) -> Result<(), StorageError>;
    async fn get_mta_sts_policy(
        &self,
        domain: &str,
    ) -> Result<Option<mailent_domain::MtaStsPolicy>, StorageError>;

    async fn save_tls_rpt_policy(
        &self,
        policy: &mailent_domain::TlsRptPolicy,
    ) -> Result<(), StorageError>;
    async fn get_tls_rpt_policy(
        &self,
        domain: &str,
    ) -> Result<Option<mailent_domain::TlsRptPolicy>, StorageError>;

    async fn save_tls_rpt_report(
        &self,
        report: &mailent_domain::TlsRptAggregateReport,
    ) -> Result<(), StorageError>;
    async fn list_tls_rpt_reports(
        &self,
        domain: Option<&str>,
        limit: usize,
    ) -> Result<Vec<mailent_domain::TlsRptAggregateReport>, StorageError>;

    async fn save_ct_certificates(
        &self,
        domain: &str,
        certs: &[mailent_domain::CtCertificateRecord],
    ) -> Result<(), StorageError>;
    async fn get_ct_certificates(
        &self,
        domain: &str,
    ) -> Result<Vec<mailent_domain::CtCertificateRecord>, StorageError>;

    async fn save_ct_event(
        &self,
        event: &mailent_domain::CtIntelligenceEvent,
    ) -> Result<(), StorageError>;
    async fn list_ct_events(
        &self,
        domain: Option<&str>,
        limit: usize,
    ) -> Result<Vec<mailent_domain::CtIntelligenceEvent>, StorageError>;

    async fn save_refresh_status(
        &self,
        status: &mailent_domain::IntelligenceRefreshStatus,
    ) -> Result<(), StorageError>;
    async fn get_refresh_status(
        &self,
        domain: &str,
    ) -> Result<Option<mailent_domain::IntelligenceRefreshStatus>, StorageError>;
    async fn list_due_refreshes(&self) -> Result<Vec<String>, StorageError>;
}

#[async_trait]
pub trait BaselineRepository: Send + Sync {
    async fn save_baseline(
        &self,
        baseline: &mailent_domain::AssetBaseline,
    ) -> Result<(), StorageError>;
    async fn get_baseline(
        &self,
        asset_id: Uuid,
    ) -> Result<Option<mailent_domain::AssetBaseline>, StorageError>;

    async fn save_anomaly(
        &self,
        anomaly: &mailent_domain::AnomalySignal,
    ) -> Result<(), StorageError>;
    async fn list_anomalies(
        &self,
        asset_id: Option<Uuid>,
        limit: usize,
    ) -> Result<Vec<mailent_domain::AnomalySignal>, StorageError>;
}

#[async_trait]
pub trait InvestigationRepository: Send + Sync {
    /// Merge evidence by probe id without overwriting analyst status or passive evidence.
    async fn attach_probe(&self, run: &mailent_domain::ProbeRun) -> Result<(), StorageError>;
    async fn save(&self, investigation: &mailent_domain::Investigation)
    -> Result<(), StorageError>;
    async fn find_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<mailent_domain::Investigation>, StorageError>;
    async fn list_all(
        &self,
        limit: usize,
    ) -> Result<Vec<mailent_domain::Investigation>, StorageError>;
    async fn list_for_asset(
        &self,
        asset_id: Uuid,
    ) -> Result<Vec<mailent_domain::Investigation>, StorageError>;
    async fn update_status(
        &self,
        id: Uuid,
        status: mailent_domain::InvestigationStatus,
    ) -> Result<(), StorageError>;
}

#[async_trait]
pub trait DecisionRepository: Send + Sync {
    async fn save_record(
        &self,
        record: &mailent_domain::DecisionRecord,
    ) -> Result<(), StorageError>;
    async fn list_recent(
        &self,
        limit: usize,
    ) -> Result<Vec<mailent_domain::DecisionRecord>, StorageError>;
}

#[async_trait]
pub trait ProbeRepository: Send + Sync {
    /// Atomically reserve a target, enforcing cooldown across simultaneous requests.
    async fn reserve(
        &self,
        run: &mailent_domain::ProbeRun,
        cooldown_seconds: u64,
    ) -> Result<bool, StorageError>;
    async fn unfinished(&self) -> Result<Vec<mailent_domain::ProbeRun>, StorageError>;
    async fn save(&self, run: &mailent_domain::ProbeRun) -> Result<(), StorageError>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<mailent_domain::ProbeRun>, StorageError>;
    async fn list_for_asset(
        &self,
        asset_id: Uuid,
        limit: usize,
    ) -> Result<Vec<mailent_domain::ProbeRun>, StorageError>;
    async fn list_recent(
        &self,
        limit: usize,
    ) -> Result<Vec<mailent_domain::ProbeRun>, StorageError>;
    /// Return the most recent probe run for a target domain (used for cooldown gating).
    async fn latest_for_target(
        &self,
        asset_id: Uuid,
        target: &str,
    ) -> Result<Option<mailent_domain::ProbeRun>, StorageError>;
    async fn update(&self, run: &mailent_domain::ProbeRun) -> Result<(), StorageError>;
}

#[async_trait]
pub trait TrainingRecordRepository: Send + Sync {
    async fn attach_remediation_outcome(
        &self,
        id: Uuid,
        outcome: &mailent_domain::RemediationTrainingOutcome,
    ) -> Result<(), StorageError>;
    async fn save(&self, record: &mailent_domain::TrainingRecord) -> Result<(), StorageError>;
    async fn list_recent(
        &self,
        investigation_id: Option<Uuid>,
        asset_id: Option<Uuid>,
        limit: usize,
    ) -> Result<Vec<mailent_domain::TrainingRecord>, StorageError>;
    async fn list_unlabeled(
        &self,
        limit: usize,
    ) -> Result<Vec<mailent_domain::TrainingRecord>, StorageError>;
    async fn find_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<mailent_domain::TrainingRecord>, StorageError>;
    /// Attach (or replace) the analyst/final outcome label.  `labeled_at` is set
    /// now; the original feature snapshot is never modified.
    async fn attach_analyst_label(
        &self,
        id: Uuid,
        label: &mailent_domain::AnalystLabel,
    ) -> Result<(), StorageError>;
}

#[async_trait]
pub trait RemediationRepository: Send + Sync {
    async fn create(
        &self,
        record: &mailent_domain::RemediationRecord,
    ) -> Result<mailent_domain::RemediationRecord, StorageError>;
    async fn find_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<mailent_domain::RemediationRecord>, StorageError>;
    async fn list_for_asset(
        &self,
        asset_id: Uuid,
    ) -> Result<Vec<mailent_domain::RemediationRecord>, StorageError>;
    async fn list_verifying(&self) -> Result<Vec<mailent_domain::RemediationRecord>, StorageError>;
    /// Compare-and-swap prevents duplicate network jobs and lost analyst updates.
    async fn update(
        &self,
        record: &mailent_domain::RemediationRecord,
        expected_revision: i64,
    ) -> Result<bool, StorageError>;
}

#[async_trait]
pub trait PostureRepository: Send + Sync {
    async fn save_snapshot(
        &self,
        snapshot: &mailent_domain::PostureSnapshot,
    ) -> Result<(), StorageError>;
    async fn list_for_asset(
        &self,
        asset_id: Uuid,
        limit: usize,
    ) -> Result<Vec<mailent_domain::PostureSnapshot>, StorageError>;
    async fn latest_for_asset(
        &self,
        asset_id: Uuid,
    ) -> Result<Option<mailent_domain::PostureSnapshot>, StorageError>;
}

#[async_trait]
pub trait IntegrationRepository: Send + Sync {
    async fn save(&self, config: &mailent_domain::IntegrationConfig) -> Result<(), StorageError>;
    async fn list_all(&self) -> Result<Vec<mailent_domain::IntegrationConfig>, StorageError>;
    async fn find_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<mailent_domain::IntegrationConfig>, StorageError>;
    async fn delete(&self, id: Uuid) -> Result<bool, StorageError>;
    async fn update_status(
        &self,
        id: Uuid,
        status_code: Option<u16>,
        error: Option<String>,
        at: time::OffsetDateTime,
    ) -> Result<(), StorageError>;
}

#[async_trait]
pub trait ArchivedReportRepository: Send + Sync {
    async fn archive(
        &self,
        report: &mailent_domain::ArchivedReportRecord,
    ) -> Result<(), StorageError>;
    async fn list_all(
        &self,
        limit: usize,
    ) -> Result<Vec<mailent_domain::ArchivedReportSummary>, StorageError>;
    async fn list_for_subject(
        &self,
        subject_id: Uuid,
    ) -> Result<Vec<mailent_domain::ArchivedReportSummary>, StorageError>;
    async fn find_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<mailent_domain::ArchivedReportRecord>, StorageError>;
}

#[async_trait]
pub trait AssessmentRepository: Send + Sync {
    async fn save(&self, assessment: &mailent_domain::AssessmentRecord)
    -> Result<(), StorageError>;
    async fn find_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<mailent_domain::AssessmentRecord>, StorageError>;
    async fn list_all(&self) -> Result<Vec<mailent_domain::AssessmentSummary>, StorageError>;
    async fn list_for_org(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<mailent_domain::AssessmentSummary>, StorageError>;
    async fn find_by_id_scoped(
        &self,
        id: Uuid,
        organization_id: Uuid,
    ) -> Result<Option<mailent_domain::AssessmentRecord>, StorageError>;
}

#[async_trait]
pub trait OrganizationRepository: Send + Sync {
    async fn find_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<mailent_domain::Organization>, StorageError>;
    async fn find_by_slug(
        &self,
        slug: &str,
    ) -> Result<Option<mailent_domain::Organization>, StorageError>;
    async fn list_for_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<mailent_domain::Organization>, StorageError>;
    async fn save(&self, org: &mailent_domain::Organization) -> Result<(), StorageError>;
    async fn add_member(
        &self,
        member: &mailent_domain::OrganizationMember,
    ) -> Result<(), StorageError>;
    async fn get_member(
        &self,
        organization_id: Uuid,
        user_id: &str,
    ) -> Result<Option<mailent_domain::OrganizationMember>, StorageError>;
}

#[async_trait]
pub trait DeviceRepository: Send + Sync {
    async fn save_device(&self, device: &mailent_domain::Device) -> Result<(), StorageError>;
    async fn find_device_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<mailent_domain::Device>, StorageError>;
    async fn list_devices_for_org(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<mailent_domain::Device>, StorageError>;
    async fn revoke_device(&self, id: Uuid) -> Result<(), StorageError>;
    async fn create_challenge(
        &self,
        challenge: &mailent_domain::DeviceAuthorizationChallenge,
    ) -> Result<(), StorageError>;
    async fn get_challenge(
        &self,
        code: &str,
    ) -> Result<Option<mailent_domain::DeviceAuthorizationChallenge>, StorageError>;
    async fn approve_challenge(
        &self,
        code: &str,
        user_id: &str,
        org_id: Uuid,
        device_token: &str,
        device_id: Uuid,
    ) -> Result<(), StorageError>;
    async fn save_device_token(
        &self,
        token_hash: &str,
        device_id: Uuid,
        org_id: Uuid,
    ) -> Result<(), StorageError>;
    async fn validate_device_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<(mailent_domain::Device, Uuid)>, StorageError>;
    async fn revoke_device_token(&self, token_hash: &str) -> Result<(), StorageError>;
    async fn heartbeat(
        &self,
        device_id: Uuid,
        version: Option<String>,
        capabilities: Vec<String>,
        status: String,
        now: time::OffsetDateTime,
    ) -> Result<(), StorageError>;
    async fn update_agent_status(
        &self,
        device_id: Uuid,
        status: Option<String>,
        current_job_id: Option<Uuid>,
        increment_completed: bool,
    ) -> Result<(), StorageError>;
}

#[async_trait]
pub trait JobRepository: Send + Sync {
    /// Cancel every active job for a device within its workspace in one operation.
    async fn cancel_active_for_device(
        &self,
        org_id: Uuid,
        device_id: Uuid,
        now: time::OffsetDateTime,
    ) -> Result<u64, StorageError>;
    async fn create_job(&self, job: &mailent_domain::AgentJob) -> Result<(), StorageError>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<mailent_domain::AgentJob>, StorageError>;
    async fn find_by_idempotency_key(
        &self,
        org_id: Uuid,
        key: &str,
    ) -> Result<Option<mailent_domain::AgentJob>, StorageError>;
    async fn lease_next_job(
        &self,
        agent_id: Uuid,
        org_id: Uuid,
        now: time::OffsetDateTime,
        lease_duration_secs: u64,
    ) -> Result<Option<mailent_domain::AgentJob>, StorageError>;
    async fn lease_next_cloud_job(
        &self,
        now: time::OffsetDateTime,
        lease_duration_secs: u64,
    ) -> Result<Option<mailent_domain::AgentJob>, StorageError>;
    async fn update_job(&self, job: &mailent_domain::AgentJob) -> Result<(), StorageError>;
    async fn recover_expired_leases(&self, now: time::OffsetDateTime) -> Result<u64, StorageError>;
    async fn list_for_org(
        &self,
        org_id: Uuid,
        limit: usize,
    ) -> Result<Vec<mailent_domain::AgentJob>, StorageError>;
    async fn count_active_for_org(&self, org_id: Uuid) -> Result<usize, StorageError>;
    async fn count_active_for_agent(&self, agent_id: Uuid) -> Result<usize, StorageError>;
}

#[async_trait]
pub trait MonitorRepository: Send + Sync {
    async fn save(
        &self,
        monitor: &mailent_domain::InfrastructureMonitor,
    ) -> Result<(), StorageError>;
    async fn find_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<mailent_domain::InfrastructureMonitor>, StorageError>;
    async fn find_by_domain(
        &self,
        org_id: Uuid,
        domain: &str,
    ) -> Result<Option<mailent_domain::InfrastructureMonitor>, StorageError>;
    async fn list_for_org(
        &self,
        org_id: Uuid,
    ) -> Result<Vec<mailent_domain::InfrastructureMonitor>, StorageError>;
    async fn find_due_monitors(
        &self,
        now: time::OffsetDateTime,
        limit: usize,
    ) -> Result<Vec<mailent_domain::InfrastructureMonitor>, StorageError>;
    async fn delete(&self, id: Uuid, org_id: Uuid) -> Result<bool, StorageError>;
}
