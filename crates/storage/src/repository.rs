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
