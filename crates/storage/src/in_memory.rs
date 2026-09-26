use async_trait::async_trait;
use mailent_domain::{
    AnomalySignal, AssessmentRecord, AssessmentSummary, Asset, AssetBaseline, CertificateRecord,
    CtCertificateRecord, CtIntelligenceEvent, DecisionRecord, DriftEvent, EmailSession, Finding,
    IntelligenceRefreshStatus, Investigation, InvestigationStatus, MtaStsPolicy, MxRecord,
    NormalizedObservation, ProbeRun, SensorHeartbeat, SensorRecord, SensorStatus,
    TlsRptAggregateReport, TlsRptPolicy, TlsaRecord, TrainingRecord,
};
use std::{collections::HashMap, sync::Arc};
use time::OffsetDateTime;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    error::StorageError,
    repository::{
        ArchivedReportRepository, AssessmentRepository, AssetRepository, BaselineRepository,
        CertificateRepository, DecisionRepository, DeviceRepository, EvidenceStore,
        FindingRepository, IntegrationRepository, IntelligenceRepository, InvestigationRepository,
        JobRepository, MonitorRepository, ObservationRepository, OrganizationRepository,
        PostureRepository, ProbeRepository, SensorRepository, SessionRepository,
        TrainingRecordRepository,
    },
};

/// In-memory storage implementation used exclusively for testing, local scaffolding,
/// and fast iteration during isolated unit tests.
#[derive(Debug, Clone)]
pub struct InMemoryStorage {
    remediations: Arc<RwLock<Vec<mailent_domain::RemediationRecord>>>,
    assets: Arc<RwLock<Vec<Asset>>>,
    drift_events: Arc<RwLock<Vec<DriftEvent>>>,
    findings: Arc<RwLock<Vec<Finding>>>,
    finding_assets: Arc<RwLock<std::collections::HashMap<Uuid, Uuid>>>,
    sessions: Arc<RwLock<Vec<EmailSession>>>,
    certificates: Arc<RwLock<Vec<CertificateRecord>>>,
    sensors: Arc<RwLock<Vec<SensorRecord>>>,
    observations: Arc<RwLock<Vec<NormalizedObservation>>>,
    evidence: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    mx_records: Arc<RwLock<HashMap<String, Vec<MxRecord>>>>,
    tlsa_records: Arc<RwLock<HashMap<String, Vec<TlsaRecord>>>>,
    mta_sts_policies: Arc<RwLock<HashMap<String, MtaStsPolicy>>>,
    tls_rpt_policies: Arc<RwLock<HashMap<String, TlsRptPolicy>>>,
    tls_rpt_reports: Arc<RwLock<Vec<TlsRptAggregateReport>>>,
    ct_certificates: Arc<RwLock<HashMap<String, Vec<CtCertificateRecord>>>>,
    ct_events: Arc<RwLock<Vec<CtIntelligenceEvent>>>,
    refresh_statuses: Arc<RwLock<HashMap<String, IntelligenceRefreshStatus>>>,
    baselines: Arc<RwLock<HashMap<Uuid, AssetBaseline>>>,
    anomalies: Arc<RwLock<Vec<AnomalySignal>>>,
    investigations: Arc<RwLock<Vec<Investigation>>>,
    decision_records: Arc<RwLock<Vec<DecisionRecord>>>,
    probe_runs: Arc<RwLock<Vec<ProbeRun>>>,
    training_records: Arc<RwLock<Vec<TrainingRecord>>>,
    posture_snapshots: Arc<RwLock<Vec<mailent_domain::PostureSnapshot>>>,
    integrations: Arc<RwLock<Vec<mailent_domain::IntegrationConfig>>>,
    archived_reports: Arc<RwLock<Vec<mailent_domain::ArchivedReportRecord>>>,
    assessments: Arc<RwLock<Vec<mailent_domain::AssessmentRecord>>>,
    organizations: Arc<RwLock<Vec<mailent_domain::Organization>>>,
    organization_members: Arc<RwLock<Vec<mailent_domain::OrganizationMember>>>,
    devices: Arc<RwLock<Vec<mailent_domain::Device>>>,
    device_challenges: Arc<RwLock<Vec<mailent_domain::DeviceAuthorizationChallenge>>>,
    device_tokens: Arc<RwLock<Vec<mailent_domain::DeviceTokenRecord>>>,
    agent_jobs: Arc<RwLock<Vec<mailent_domain::AgentJob>>>,
    infrastructure_monitors: Arc<RwLock<Vec<mailent_domain::InfrastructureMonitor>>>,
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        let default_org = mailent_domain::Organization::default();
        Self {
            remediations: Arc::default(),
            assets: Arc::default(),
            drift_events: Arc::default(),
            findings: Arc::default(),
            finding_assets: Arc::default(),
            sessions: Arc::default(),
            certificates: Arc::default(),
            sensors: Arc::default(),
            observations: Arc::default(),
            evidence: Arc::default(),
            mx_records: Arc::default(),
            tlsa_records: Arc::default(),
            mta_sts_policies: Arc::default(),
            tls_rpt_policies: Arc::default(),
            tls_rpt_reports: Arc::default(),
            ct_certificates: Arc::default(),
            ct_events: Arc::default(),
            refresh_statuses: Arc::default(),
            baselines: Arc::default(),
            anomalies: Arc::default(),
            investigations: Arc::default(),
            decision_records: Arc::default(),
            probe_runs: Arc::default(),
            training_records: Arc::default(),
            posture_snapshots: Arc::default(),
            integrations: Arc::default(),
            archived_reports: Arc::default(),
            assessments: Arc::default(),
            organizations: Arc::new(RwLock::new(vec![default_org])),
            organization_members: Arc::default(),
            devices: Arc::default(),
            device_challenges: Arc::default(),
            device_tokens: Arc::default(),
            agent_jobs: Arc::default(),
            infrastructure_monitors: Arc::default(),
        }
    }
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn reset_all_data(&self) {
        self.remediations.write().await.clear();
        self.assets.write().await.clear();
        self.drift_events.write().await.clear();
        self.findings.write().await.clear();
        self.finding_assets.write().await.clear();
        self.sessions.write().await.clear();
        self.certificates.write().await.clear();
        self.sensors.write().await.clear();
        self.observations.write().await.clear();
        self.evidence.write().await.clear();
        self.mx_records.write().await.clear();
        self.tlsa_records.write().await.clear();
        self.mta_sts_policies.write().await.clear();
        self.tls_rpt_policies.write().await.clear();
        self.tls_rpt_reports.write().await.clear();
        self.ct_certificates.write().await.clear();
        self.ct_events.write().await.clear();
        self.refresh_statuses.write().await.clear();
        self.baselines.write().await.clear();
        self.anomalies.write().await.clear();
        self.investigations.write().await.clear();
        self.decision_records.write().await.clear();
        self.probe_runs.write().await.clear();
        self.training_records.write().await.clear();
        self.posture_snapshots.write().await.clear();
        self.integrations.write().await.clear();
        self.archived_reports.write().await.clear();
        self.assessments.write().await.clear();
        *self.organizations.write().await = vec![mailent_domain::Organization::default()];
        self.organization_members.write().await.clear();
        self.devices.write().await.clear();
        self.device_challenges.write().await.clear();
        self.device_tokens.write().await.clear();
        self.agent_jobs.write().await.clear();
        self.infrastructure_monitors.write().await.clear();
    }
}

#[async_trait]
impl AssetRepository for InMemoryStorage {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<Asset>, StorageError> {
        let guard = self.assets.read().await;
        Ok(guard.iter().find(|a| a.id == id).cloned())
    }

    async fn find_by_address_or_identity(
        &self,
        identity: &str,
    ) -> Result<Option<Asset>, StorageError> {
        let guard = self.assets.read().await;
        Ok(guard
            .iter()
            .find(|a| {
                a.addresses.iter().any(|addr| addr == identity)
                    || a.hostnames.iter().any(|h| h == identity)
                    || a.identities.iter().any(|i| i.value == identity)
            })
            .cloned())
    }

    async fn upsert(&self, asset: Asset) -> Result<(), StorageError> {
        let mut guard = self.assets.write().await;
        if let Some(existing) = guard.iter_mut().find(|a| a.id == asset.id) {
            *existing = asset;
        } else {
            guard.push(asset);
        }
        Ok(())
    }

    async fn list_all(&self) -> Result<Vec<Asset>, StorageError> {
        let guard = self.assets.read().await;
        Ok(guard.clone())
    }

    async fn save_drift_event(&self, event: DriftEvent) -> Result<(), StorageError> {
        let mut guard = self.drift_events.write().await;
        guard.push(event);
        Ok(())
    }

    async fn list_drift_events(
        &self,
        asset_id: Option<Uuid>,
        limit: usize,
    ) -> Result<Vec<DriftEvent>, StorageError> {
        let guard = self.drift_events.read().await;
        let iter = guard
            .iter()
            .filter(|e| asset_id.is_none_or(|aid| e.asset_id == aid))
            .rev()
            .take(limit)
            .cloned();
        Ok(iter.collect())
    }
}

#[async_trait]
impl CertificateRepository for InMemoryStorage {
    async fn save(&self, cert: CertificateRecord) -> Result<(), StorageError> {
        let mut guard = self.certificates.write().await;
        if let Some(existing) = guard
            .iter_mut()
            .find(|c| c.sha256_fingerprint == cert.sha256_fingerprint)
        {
            existing.last_seen = cert.last_seen;
            for aid in cert.associated_asset_ids {
                if !existing.associated_asset_ids.contains(&aid) {
                    existing.associated_asset_ids.push(aid);
                }
            }
        } else {
            guard.push(cert);
        }
        Ok(())
    }

    async fn find_by_fingerprint(
        &self,
        fp: &str,
    ) -> Result<Option<CertificateRecord>, StorageError> {
        let guard = self.certificates.read().await;
        Ok(guard.iter().find(|c| c.sha256_fingerprint == fp).cloned())
    }

    async fn list_all(&self) -> Result<Vec<CertificateRecord>, StorageError> {
        let guard = self.certificates.read().await;
        Ok(guard.clone())
    }

    async fn list_for_asset(&self, asset_id: Uuid) -> Result<Vec<CertificateRecord>, StorageError> {
        let guard = self.certificates.read().await;
        Ok(guard
            .iter()
            .filter(|c| c.associated_asset_ids.contains(&asset_id))
            .cloned()
            .collect())
    }
}

#[async_trait]
impl SensorRepository for InMemoryStorage {
    async fn record_heartbeat(&self, heartbeat: SensorHeartbeat) -> Result<(), StorageError> {
        let mut guard = self.sensors.write().await;
        let now = time::OffsetDateTime::now_utc();
        if let Some(existing) = guard
            .iter_mut()
            .find(|s| s.sensor_id == heartbeat.sensor_id)
        {
            existing.site_id = heartbeat.site_id;
            existing.hostname = heartbeat.hostname;
            existing.version = heartbeat.version;
            existing.mode = heartbeat.mode;
            existing.interface = heartbeat.interface;
            existing.status = SensorStatus::Online;
            existing.last_seen = now;
        } else {
            guard.push(SensorRecord {
                sensor_id: heartbeat.sensor_id,
                site_id: heartbeat.site_id,
                hostname: heartbeat.hostname,
                version: heartbeat.version,
                mode: heartbeat.mode,
                interface: heartbeat.interface,
                status: SensorStatus::Online,
                last_seen: now,
                registered_at: now,
            });
        }
        Ok(())
    }

    async fn list_sensors(&self) -> Result<Vec<SensorRecord>, StorageError> {
        let guard = self.sensors.read().await;
        let now = time::OffsetDateTime::now_utc();
        // Update statuses dynamically based on last_seen
        let updated: Vec<SensorRecord> = guard
            .iter()
            .map(|s| {
                let mut copy = s.clone();
                let diff = (now - s.last_seen).whole_seconds();
                if diff > 120 {
                    copy.status = SensorStatus::Offline;
                } else if diff > 30 {
                    copy.status = SensorStatus::Stale;
                } else {
                    copy.status = SensorStatus::Online;
                }
                copy
            })
            .collect();
        Ok(updated)
    }

    async fn get_sensor(&self, sensor_id: &str) -> Result<Option<SensorRecord>, StorageError> {
        let sensors = self.list_sensors().await?;
        Ok(sensors.into_iter().find(|s| s.sensor_id == sensor_id))
    }
}

#[async_trait]
impl FindingRepository for InMemoryStorage {
    async fn link_asset(&self, finding_id: Uuid, asset_id: Uuid) -> Result<(), StorageError> {
        let mut links = self.finding_assets.write().await;
        if links.get(&finding_id).is_some_and(|id| *id != asset_id) {
            return Err(StorageError::Conflict(
                "finding already belongs to another asset".into(),
            ));
        }
        links.insert(finding_id, asset_id);
        Ok(())
    }
    async fn save(&self, finding: Finding) -> Result<(), StorageError> {
        let mut guard = self.findings.write().await;
        if let Some(existing) = guard.iter_mut().find(|f| f.id == finding.id) {
            if existing.rule_id != finding.rule_id {
                return Err(StorageError::Conflict(
                    "finding identity already has different evidence".into(),
                ));
            }
            existing.last_seen = finding.last_seen;
            existing.affected_count = finding.affected_count;
            for ev in finding.evidence {
                if !existing
                    .evidence
                    .iter()
                    .any(|e| e.session_id == ev.session_id && e.observation_id == ev.observation_id)
                {
                    existing.evidence.push(ev);
                }
            }
        } else {
            guard.push(finding);
        }
        Ok(())
    }

    async fn list_all(&self) -> Result<Vec<Finding>, StorageError> {
        let guard = self.findings.read().await;
        Ok(guard.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Finding>, StorageError> {
        let guard = self.findings.read().await;
        Ok(guard.iter().find(|f| f.id == id).cloned())
    }

    async fn list_for_session(&self, session_id: Uuid) -> Result<Vec<Finding>, StorageError> {
        let guard = self.findings.read().await;
        Ok(guard
            .iter()
            .filter(|f| f.evidence.iter().any(|e| e.session_id == Some(session_id)))
            .cloned()
            .collect())
    }

    async fn list_for_asset(&self, asset_id: Uuid) -> Result<Vec<Finding>, StorageError> {
        let links = self.finding_assets.read().await;
        let guard = self.findings.read().await;
        Ok(guard
            .iter()
            .filter(|f| links.get(&f.id) == Some(&asset_id))
            .cloned()
            .collect())
    }
}

#[async_trait]
impl SessionRepository for InMemoryStorage {
    async fn save(&self, session: EmailSession) -> Result<(), StorageError> {
        let mut guard = self.sessions.write().await;
        if let Some(existing) = guard
            .iter_mut()
            .find(|s| s.session_id == session.session_id)
        {
            if existing.protocol != session.protocol
                || existing.flow != session.flow
                || existing.tls_version != session.tls_version
                || existing.cipher_suite != session.cipher_suite
                || existing.starttls_state != session.starttls_state
            {
                return Err(StorageError::Conflict(
                    "observation ID already has different evidence".into(),
                ));
            }
            existing.last_seen = session.last_seen;
        } else {
            guard.push(session);
        }
        Ok(())
    }

    async fn list_recent(&self, limit: usize) -> Result<Vec<EmailSession>, StorageError> {
        let guard = self.sessions.read().await;
        Ok(guard.iter().rev().take(limit).cloned().collect())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<EmailSession>, StorageError> {
        let guard = self.sessions.read().await;
        Ok(guard.iter().find(|s| s.session_id == id).cloned())
    }

    async fn list_for_asset(
        &self,
        asset_ip: &str,
        limit: usize,
    ) -> Result<Vec<EmailSession>, StorageError> {
        let guard = self.sessions.read().await;
        Ok(guard
            .iter()
            .filter(|s| s.flow.src_ip == asset_ip || s.flow.dst_ip == asset_ip)
            .rev()
            .take(limit)
            .cloned()
            .collect())
    }
}

#[async_trait]
impl ObservationRepository for InMemoryStorage {
    async fn save(&self, observation: NormalizedObservation) -> Result<(), StorageError> {
        let mut guard = self.observations.write().await;
        if let Some(existing) = guard
            .iter()
            .find(|o| o.observation_id == observation.observation_id)
        {
            if existing.protocol != observation.protocol || existing.flow != observation.flow {
                return Err(StorageError::Conflict(
                    "observation ID conflict with different parameters".into(),
                ));
            }
        } else {
            guard.push(observation);
        }
        Ok(())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<NormalizedObservation>, StorageError> {
        let guard = self.observations.read().await;
        Ok(guard.iter().find(|o| o.observation_id == id).cloned())
    }

    async fn list_recent(&self, limit: usize) -> Result<Vec<NormalizedObservation>, StorageError> {
        let guard = self.observations.read().await;
        Ok(guard.iter().rev().take(limit).cloned().collect())
    }
}

#[async_trait]
impl EvidenceStore for InMemoryStorage {
    async fn put(&self, key: &str, data: &[u8]) -> Result<(), StorageError> {
        let mut guard = self.evidence.write().await;
        guard.insert(key.to_string(), data.to_vec());
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let guard = self.evidence.read().await;
        Ok(guard.get(key).cloned())
    }
}

#[async_trait]
impl IntelligenceRepository for InMemoryStorage {
    async fn save_mx_records(
        &self,
        domain: &str,
        records: &[MxRecord],
    ) -> Result<(), StorageError> {
        let mut guard = self.mx_records.write().await;
        guard.insert(domain.to_string(), records.to_vec());
        Ok(())
    }

    async fn get_mx_records(&self, domain: &str) -> Result<Vec<MxRecord>, StorageError> {
        let guard = self.mx_records.read().await;
        Ok(guard.get(domain).cloned().unwrap_or_default())
    }

    async fn save_tlsa_records(
        &self,
        domain: &str,
        records: &[TlsaRecord],
    ) -> Result<(), StorageError> {
        let mut guard = self.tlsa_records.write().await;
        guard.insert(domain.to_string(), records.to_vec());
        Ok(())
    }

    async fn get_tlsa_records(&self, domain: &str) -> Result<Vec<TlsaRecord>, StorageError> {
        let guard = self.tlsa_records.read().await;
        Ok(guard.get(domain).cloned().unwrap_or_default())
    }

    async fn save_mta_sts_policy(&self, policy: &MtaStsPolicy) -> Result<(), StorageError> {
        let mut guard = self.mta_sts_policies.write().await;
        guard.insert(policy.domain.clone(), policy.clone());
        Ok(())
    }

    async fn get_mta_sts_policy(&self, domain: &str) -> Result<Option<MtaStsPolicy>, StorageError> {
        let guard = self.mta_sts_policies.read().await;
        Ok(guard.get(domain).cloned())
    }

    async fn save_tls_rpt_policy(&self, policy: &TlsRptPolicy) -> Result<(), StorageError> {
        let mut guard = self.tls_rpt_policies.write().await;
        guard.insert(policy.domain.clone(), policy.clone());
        Ok(())
    }

    async fn get_tls_rpt_policy(&self, domain: &str) -> Result<Option<TlsRptPolicy>, StorageError> {
        let guard = self.tls_rpt_policies.read().await;
        Ok(guard.get(domain).cloned())
    }

    async fn save_tls_rpt_report(
        &self,
        report: &TlsRptAggregateReport,
    ) -> Result<(), StorageError> {
        let mut guard = self.tls_rpt_reports.write().await;
        guard.push(report.clone());
        Ok(())
    }

    async fn list_tls_rpt_reports(
        &self,
        domain: Option<&str>,
        limit: usize,
    ) -> Result<Vec<TlsRptAggregateReport>, StorageError> {
        let guard = self.tls_rpt_reports.read().await;
        let mut filtered: Vec<TlsRptAggregateReport> = guard
            .iter()
            .filter(|r| domain.is_none() || domain == Some(r.policy_domain.as_str()))
            .cloned()
            .collect();
        filtered.sort_by_key(|a| std::cmp::Reverse(a.imported_at));
        filtered.truncate(limit);
        Ok(filtered)
    }

    async fn save_ct_certificates(
        &self,
        domain: &str,
        certs: &[CtCertificateRecord],
    ) -> Result<(), StorageError> {
        let mut guard = self.ct_certificates.write().await;
        guard.insert(domain.to_string(), certs.to_vec());
        Ok(())
    }

    async fn get_ct_certificates(
        &self,
        domain: &str,
    ) -> Result<Vec<CtCertificateRecord>, StorageError> {
        let guard = self.ct_certificates.read().await;
        Ok(guard.get(domain).cloned().unwrap_or_default())
    }

    async fn save_ct_event(&self, event: &CtIntelligenceEvent) -> Result<(), StorageError> {
        let mut guard = self.ct_events.write().await;
        guard.push(event.clone());
        Ok(())
    }

    async fn list_ct_events(
        &self,
        domain: Option<&str>,
        limit: usize,
    ) -> Result<Vec<CtIntelligenceEvent>, StorageError> {
        let guard = self.ct_events.read().await;
        let mut filtered: Vec<CtIntelligenceEvent> = guard
            .iter()
            .filter(|e| domain.is_none() || domain == Some(e.domain.as_str()))
            .cloned()
            .collect();
        filtered.sort_by_key(|a| std::cmp::Reverse(a.observed_at));
        filtered.truncate(limit);
        Ok(filtered)
    }

    async fn save_refresh_status(
        &self,
        status: &IntelligenceRefreshStatus,
    ) -> Result<(), StorageError> {
        let mut guard = self.refresh_statuses.write().await;
        guard.insert(status.domain.clone(), status.clone());
        Ok(())
    }

    async fn get_refresh_status(
        &self,
        domain: &str,
    ) -> Result<Option<IntelligenceRefreshStatus>, StorageError> {
        let guard = self.refresh_statuses.read().await;
        Ok(guard.get(domain).cloned())
    }

    async fn list_due_refreshes(&self) -> Result<Vec<String>, StorageError> {
        let guard = self.refresh_statuses.read().await;
        let now = OffsetDateTime::now_utc();
        let due = guard
            .values()
            .filter(|s| s.next_check.map(|n| n <= now).unwrap_or(false))
            .map(|s| s.domain.clone())
            .collect();
        Ok(due)
    }
}

#[async_trait]
impl BaselineRepository for InMemoryStorage {
    async fn save_baseline(&self, baseline: &AssetBaseline) -> Result<(), StorageError> {
        let mut guard = self.baselines.write().await;
        guard.insert(baseline.asset_id, baseline.clone());
        Ok(())
    }

    async fn get_baseline(&self, asset_id: Uuid) -> Result<Option<AssetBaseline>, StorageError> {
        let guard = self.baselines.read().await;
        Ok(guard.get(&asset_id).cloned())
    }

    async fn save_anomaly(&self, anomaly: &AnomalySignal) -> Result<(), StorageError> {
        let mut guard = self.anomalies.write().await;
        guard.push(anomaly.clone());
        Ok(())
    }

    async fn list_anomalies(
        &self,
        asset_id: Option<Uuid>,
        limit: usize,
    ) -> Result<Vec<AnomalySignal>, StorageError> {
        let guard = self.anomalies.read().await;
        let mut filtered: Vec<AnomalySignal> = guard
            .iter()
            .filter(|a| asset_id.is_none() || asset_id == Some(a.asset_id))
            .cloned()
            .collect();
        filtered.sort_by_key(|a| std::cmp::Reverse(a.observed_at));
        filtered.truncate(limit);
        Ok(filtered)
    }
}

#[async_trait]
impl InvestigationRepository for InMemoryStorage {
    async fn attach_probe(&self, run: &ProbeRun) -> Result<(), StorageError> {
        if let Some(id) = run.investigation_id {
            let mut guard = self.investigations.write().await;
            if let Some(inv) = guard.iter_mut().find(|inv| inv.id == id) {
                if !inv.external_intelligence.is_object() {
                    inv.external_intelligence = serde_json::json!({});
                }
                let obj = inv
                    .external_intelligence
                    .as_object_mut()
                    .expect("object initialized");
                let probes = obj
                    .entry("active_verifications")
                    .or_insert_with(|| serde_json::json!({}));
                probes[run.id.to_string()] =
                    serde_json::to_value(run).map_err(|e| StorageError::Backend(e.to_string()))?;
            }
        }
        Ok(())
    }

    async fn save(&self, investigation: &Investigation) -> Result<(), StorageError> {
        let mut guard = self.investigations.write().await;
        if let Some(pos) = guard.iter().position(|i| i.id == investigation.id) {
            let existing = &guard[pos];
            let mut merged = investigation.clone();
            merged.status = existing.status;
            merged.first_observed = existing.first_observed.min(investigation.first_observed);
            merged.last_observed = existing.last_observed.max(investigation.last_observed);
            merged
                .finding_ids
                .extend(existing.finding_ids.iter().cloned());
            merged.finding_ids.sort();
            merged.finding_ids.dedup();
            merged.drift_event_ids.extend(&existing.drift_event_ids);
            merged.drift_event_ids.sort();
            merged.drift_event_ids.dedup();
            merged.anomaly_ids.extend(&existing.anomaly_ids);
            merged.anomaly_ids.sort();
            merged.anomaly_ids.dedup();
            let mut intel = existing
                .external_intelligence
                .as_object()
                .cloned()
                .unwrap_or_default();
            intel.extend(
                investigation
                    .external_intelligence
                    .as_object()
                    .cloned()
                    .unwrap_or_default(),
            );
            let mut probes = existing.external_intelligence["active_verifications"]
                .as_object()
                .cloned()
                .unwrap_or_default();
            probes.extend(
                investigation.external_intelligence["active_verifications"]
                    .as_object()
                    .cloned()
                    .unwrap_or_default(),
            );
            if !probes.is_empty() {
                intel.insert(
                    "active_verifications".into(),
                    serde_json::Value::Object(probes),
                );
            }
            merged.external_intelligence = serde_json::Value::Object(intel);
            guard[pos] = merged;
        } else {
            guard.push(investigation.clone());
        }
        Ok(())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Investigation>, StorageError> {
        let guard = self.investigations.read().await;
        Ok(guard.iter().find(|i| i.id == id).cloned())
    }

    async fn list_all(&self, limit: usize) -> Result<Vec<Investigation>, StorageError> {
        let guard = self.investigations.read().await;
        let mut items = guard.clone();
        items.sort_by_key(|a| std::cmp::Reverse(a.last_observed));
        items.truncate(limit);
        Ok(items)
    }

    async fn list_for_asset(&self, asset_id: Uuid) -> Result<Vec<Investigation>, StorageError> {
        let guard = self.investigations.read().await;
        let mut items: Vec<Investigation> = guard
            .iter()
            .filter(|i| i.asset_id == asset_id)
            .cloned()
            .collect();
        items.sort_by_key(|a| std::cmp::Reverse(a.last_observed));
        Ok(items)
    }

    async fn update_status(
        &self,
        id: Uuid,
        status: InvestigationStatus,
    ) -> Result<(), StorageError> {
        let mut guard = self.investigations.write().await;
        if let Some(item) = guard.iter_mut().find(|i| i.id == id) {
            item.status = status;
            item.last_observed = OffsetDateTime::now_utc();
        }
        Ok(())
    }
}

#[async_trait]
impl DecisionRepository for InMemoryStorage {
    async fn save_record(&self, record: &DecisionRecord) -> Result<(), StorageError> {
        let mut guard = self.decision_records.write().await;
        guard.push(record.clone());
        Ok(())
    }

    async fn list_recent(&self, limit: usize) -> Result<Vec<DecisionRecord>, StorageError> {
        let guard = self.decision_records.read().await;
        let mut items = guard.clone();
        items.sort_by_key(|a| std::cmp::Reverse(a.created_at));
        items.truncate(limit);
        Ok(items)
    }
}

#[async_trait]
impl ProbeRepository for InMemoryStorage {
    async fn reserve(&self, run: &ProbeRun, cooldown_seconds: u64) -> Result<bool, StorageError> {
        let mut runs = self.probe_runs.write().await;
        let cutoff = run.started_at - time::Duration::seconds(cooldown_seconds as i64);
        if runs.iter().any(|r| {
            r.target == run.target
                && (r.finished_at.is_none() || r.finished_at.is_some_and(|at| at > cutoff))
        }) {
            return Ok(false);
        }
        runs.push(run.clone());
        Ok(true)
    }
    async fn unfinished(&self) -> Result<Vec<ProbeRun>, StorageError> {
        Ok(self
            .probe_runs
            .read()
            .await
            .iter()
            .filter(|r| r.finished_at.is_none())
            .cloned()
            .collect())
    }

    async fn save(&self, run: &ProbeRun) -> Result<(), StorageError> {
        let mut guard = self.probe_runs.write().await;
        if let Some(existing) = guard.iter_mut().find(|r| r.id == run.id) {
            *existing = run.clone();
        } else {
            guard.push(run.clone());
        }
        Ok(())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<ProbeRun>, StorageError> {
        let guard = self.probe_runs.read().await;
        Ok(guard.iter().find(|r| r.id == id).cloned())
    }

    async fn list_for_asset(
        &self,
        asset_id: Uuid,
        limit: usize,
    ) -> Result<Vec<ProbeRun>, StorageError> {
        let guard = self.probe_runs.read().await;
        let mut items: Vec<ProbeRun> = guard
            .iter()
            .filter(|r| r.asset_id == asset_id)
            .cloned()
            .collect();
        items.sort_by_key(|r| std::cmp::Reverse(r.started_at));
        items.truncate(limit);
        Ok(items)
    }

    async fn list_recent(&self, limit: usize) -> Result<Vec<ProbeRun>, StorageError> {
        let guard = self.probe_runs.read().await;
        let mut items = guard.clone();
        items.sort_by_key(|r| std::cmp::Reverse(r.started_at));
        items.truncate(limit);
        Ok(items)
    }

    async fn latest_for_target(
        &self,
        asset_id: Uuid,
        target: &str,
    ) -> Result<Option<ProbeRun>, StorageError> {
        let guard = self.probe_runs.read().await;
        let latest = guard
            .iter()
            .filter(|r| r.asset_id == asset_id && r.target == target)
            .max_by_key(|r| r.started_at);
        Ok(latest.cloned())
    }

    async fn update(&self, run: &ProbeRun) -> Result<(), StorageError> {
        let mut guard = self.probe_runs.write().await;
        if let Some(existing) = guard.iter_mut().find(|r| r.id == run.id) {
            *existing = run.clone();
        }
        Ok(())
    }
}

#[async_trait]
impl TrainingRecordRepository for InMemoryStorage {
    async fn attach_remediation_outcome(
        &self,
        id: Uuid,
        outcome: &mailent_domain::RemediationTrainingOutcome,
    ) -> Result<(), StorageError> {
        let mut records = self.training_records.write().await;
        let r = records
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or_else(|| StorageError::NotFound(id.to_string()))?;
        r.remediation_outcomes
            .entry(outcome.request_id)
            .or_insert_with(|| outcome.clone());
        Ok(())
    }

    async fn save(&self, record: &TrainingRecord) -> Result<(), StorageError> {
        let mut guard = self.training_records.write().await;
        if let Some(existing) = guard.iter().find(|r| r.id == record.id) {
            if !existing.same_snapshot(record) {
                return Err(StorageError::Conflict(
                    "training features are immutable".into(),
                ));
            }
        } else {
            guard.push(record.clone());
        }
        Ok(())
    }

    async fn list_recent(
        &self,
        investigation_id: Option<Uuid>,
        asset_id: Option<Uuid>,
        limit: usize,
    ) -> Result<Vec<TrainingRecord>, StorageError> {
        let guard = self.training_records.read().await;
        let mut items: Vec<TrainingRecord> = guard
            .iter()
            .filter(|r| investigation_id.is_none_or(|id| r.investigation_id == id))
            .filter(|r| asset_id.is_none_or(|id| r.asset_id == id))
            .cloned()
            .collect();
        items.sort_by_key(|r| std::cmp::Reverse(r.captured_at));
        items.truncate(limit);
        Ok(items)
    }

    async fn list_unlabeled(&self, limit: usize) -> Result<Vec<TrainingRecord>, StorageError> {
        let guard = self.training_records.read().await;
        let mut items: Vec<TrainingRecord> = guard
            .iter()
            .filter(|r| r.analyst_label.is_none())
            .cloned()
            .collect();
        items.sort_by_key(|r| std::cmp::Reverse(r.captured_at));
        items.truncate(limit);
        Ok(items)
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<TrainingRecord>, StorageError> {
        let guard = self.training_records.read().await;
        Ok(guard.iter().find(|r| r.id == id).cloned())
    }

    async fn attach_analyst_label(
        &self,
        id: Uuid,
        label: &mailent_domain::AnalystLabel,
    ) -> Result<(), StorageError> {
        let mut guard = self.training_records.write().await;
        if let Some(record) = guard.iter_mut().find(|r| r.id == id) {
            record.analyst_label = Some(label.clone());
            record.labeled_at = Some(OffsetDateTime::now_utc());
        } else {
            return Err(StorageError::NotFound(format!(
                "training record {id} not found"
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl crate::repository::RemediationRepository for InMemoryStorage {
    async fn create(
        &self,
        record: &mailent_domain::RemediationRecord,
    ) -> Result<mailent_domain::RemediationRecord, StorageError> {
        let mut records = self.remediations.write().await;
        if let Some(existing) = records.iter().find(|r| r.id == record.id) {
            return Ok(existing.clone());
        }
        records.push(record.clone());
        Ok(record.clone())
    }
    async fn find_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<mailent_domain::RemediationRecord>, StorageError> {
        Ok(self
            .remediations
            .read()
            .await
            .iter()
            .find(|r| r.id == id)
            .cloned())
    }
    async fn list_for_asset(
        &self,
        asset_id: Uuid,
    ) -> Result<Vec<mailent_domain::RemediationRecord>, StorageError> {
        Ok(self
            .remediations
            .read()
            .await
            .iter()
            .filter(|r| r.asset_id == asset_id)
            .cloned()
            .collect())
    }
    async fn list_verifying(&self) -> Result<Vec<mailent_domain::RemediationRecord>, StorageError> {
        Ok(self
            .remediations
            .read()
            .await
            .iter()
            .filter(|r| r.state == mailent_domain::RemediationState::Verifying)
            .cloned()
            .collect())
    }
    async fn update(
        &self,
        record: &mailent_domain::RemediationRecord,
        expected_revision: i64,
    ) -> Result<bool, StorageError> {
        let mut records = self.remediations.write().await;
        if let Some(existing) = records
            .iter_mut()
            .find(|r| r.id == record.id && r.revision == expected_revision)
        {
            *existing = record.clone();
            return Ok(true);
        }
        Ok(false)
    }
}

#[async_trait]
impl PostureRepository for InMemoryStorage {
    async fn save_snapshot(
        &self,
        snapshot: &mailent_domain::PostureSnapshot,
    ) -> Result<(), StorageError> {
        let mut list = self.posture_snapshots.write().await;
        list.retain(|s| s.id != snapshot.id);
        list.push(snapshot.clone());
        Ok(())
    }

    async fn list_for_asset(
        &self,
        asset_id: Uuid,
        limit: usize,
    ) -> Result<Vec<mailent_domain::PostureSnapshot>, StorageError> {
        let list = self.posture_snapshots.read().await;
        let mut asset_snapshots: Vec<_> = list
            .iter()
            .filter(|s| s.asset_id == asset_id)
            .cloned()
            .collect();
        asset_snapshots.sort_by_key(|s| std::cmp::Reverse(s.recorded_at));
        if asset_snapshots.len() > limit {
            asset_snapshots.truncate(limit);
        }
        Ok(asset_snapshots)
    }

    async fn latest_for_asset(
        &self,
        asset_id: Uuid,
    ) -> Result<Option<mailent_domain::PostureSnapshot>, StorageError> {
        let list = self.posture_snapshots.read().await;
        let mut asset_snapshots: Vec<_> = list
            .iter()
            .filter(|s| s.asset_id == asset_id)
            .cloned()
            .collect();
        asset_snapshots.sort_by_key(|s| std::cmp::Reverse(s.recorded_at));
        Ok(asset_snapshots.into_iter().next())
    }
}

#[async_trait]
impl IntegrationRepository for InMemoryStorage {
    async fn save(&self, config: &mailent_domain::IntegrationConfig) -> Result<(), StorageError> {
        let mut list = self.integrations.write().await;
        list.retain(|c| c.id != config.id);
        list.push(config.clone());
        Ok(())
    }

    async fn list_all(&self) -> Result<Vec<mailent_domain::IntegrationConfig>, StorageError> {
        let list = self.integrations.read().await;
        let mut configs = list.clone();
        configs.sort_by_key(|c| std::cmp::Reverse(c.created_at));
        Ok(configs)
    }

    async fn find_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<mailent_domain::IntegrationConfig>, StorageError> {
        let list = self.integrations.read().await;
        Ok(list.iter().find(|c| c.id == id).cloned())
    }

    async fn delete(&self, id: Uuid) -> Result<bool, StorageError> {
        let mut list = self.integrations.write().await;
        let initial_len = list.len();
        list.retain(|c| c.id != id);
        Ok(list.len() < initial_len)
    }

    async fn update_status(
        &self,
        id: Uuid,
        status_code: Option<u16>,
        error: Option<String>,
        at: time::OffsetDateTime,
    ) -> Result<(), StorageError> {
        let mut list = self.integrations.write().await;
        if let Some(config) = list.iter_mut().find(|c| c.id == id) {
            config.last_delivery_at = Some(at);
            config.last_status_code = status_code;
            config.last_error = error;
            config.updated_at = at;
        }
        Ok(())
    }
}

#[async_trait]
impl ArchivedReportRepository for InMemoryStorage {
    async fn archive(
        &self,
        report: &mailent_domain::ArchivedReportRecord,
    ) -> Result<(), StorageError> {
        let mut list = self.archived_reports.write().await;
        list.retain(|r| r.id != report.id);
        list.push(report.clone());
        Ok(())
    }

    async fn list_all(
        &self,
        limit: usize,
    ) -> Result<Vec<mailent_domain::ArchivedReportSummary>, StorageError> {
        let list = self.archived_reports.read().await;
        let mut summaries: Vec<_> = list
            .iter()
            .map(|r| mailent_domain::ArchivedReportSummary {
                id: r.id,
                report_id: r.report_id.clone(),
                subject_kind: r.subject_kind,
                subject_id: r.subject_id,
                title: r.title.clone(),
                fingerprint: r.fingerprint.clone(),
                generated_at: r.generated_at,
                archived_at: r.archived_at,
                archived_by: r.archived_by.clone(),
                notes: r.notes.clone(),
            })
            .collect();
        summaries.sort_by_key(|s| std::cmp::Reverse(s.archived_at));
        if summaries.len() > limit {
            summaries.truncate(limit);
        }
        Ok(summaries)
    }

    async fn list_for_subject(
        &self,
        subject_id: Uuid,
    ) -> Result<Vec<mailent_domain::ArchivedReportSummary>, StorageError> {
        let list = self.archived_reports.read().await;
        let mut summaries: Vec<_> = list
            .iter()
            .filter(|r| r.subject_id == subject_id)
            .map(|r| mailent_domain::ArchivedReportSummary {
                id: r.id,
                report_id: r.report_id.clone(),
                subject_kind: r.subject_kind,
                subject_id: r.subject_id,
                title: r.title.clone(),
                fingerprint: r.fingerprint.clone(),
                generated_at: r.generated_at,
                archived_at: r.archived_at,
                archived_by: r.archived_by.clone(),
                notes: r.notes.clone(),
            })
            .collect();
        summaries.sort_by_key(|s| std::cmp::Reverse(s.archived_at));
        Ok(summaries)
    }

    async fn find_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<mailent_domain::ArchivedReportRecord>, StorageError> {
        let list = self.archived_reports.read().await;
        Ok(list.iter().find(|r| r.id == id).cloned())
    }
}

#[async_trait]
impl AssessmentRepository for InMemoryStorage {
    async fn latest_installation_syncs(
        &self,
        organization_id: Uuid,
    ) -> Result<HashMap<Uuid, String>, StorageError> {
        let mut result = HashMap::<Uuid, String>::new();
        for assessment in self
            .assessments
            .read()
            .await
            .iter()
            .filter(|a| a.organization_id == Some(organization_id))
        {
            let Some(device_id) = assessment
                .metadata
                .get("source_device_id")
                .and_then(|v| v.as_str())
                .and_then(|v| Uuid::parse_str(v).ok())
            else {
                continue;
            };
            let Some(synced_at) = assessment
                .metadata
                .get("synced_at")
                .and_then(|v| v.as_str())
            else {
                continue;
            };
            result
                .entry(device_id)
                .and_modify(|current| {
                    if synced_at > current.as_str() {
                        *current = synced_at.to_string();
                    }
                })
                .or_insert_with(|| synced_at.to_string());
        }
        Ok(result)
    }
    async fn save(&self, assessment: &AssessmentRecord) -> Result<(), StorageError> {
        let mut list = self.assessments.write().await;
        if let Some(pos) = list.iter().position(|a| a.id == assessment.id) {
            list[pos] = assessment.clone();
        } else {
            list.push(assessment.clone());
        }
        Ok(())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<AssessmentRecord>, StorageError> {
        let list = self.assessments.read().await;
        Ok(list.iter().find(|a| a.id == id).cloned())
    }

    async fn list_all(&self) -> Result<Vec<AssessmentSummary>, StorageError> {
        let list = self.assessments.read().await;
        let mut summaries: Vec<AssessmentSummary> =
            list.iter().map(AssessmentSummary::from).collect();
        summaries.sort_by_key(|a| std::cmp::Reverse(a.created_at));
        Ok(summaries)
    }

    async fn list_for_org(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<AssessmentSummary>, StorageError> {
        let list = self.assessments.read().await;
        let mut summaries: Vec<AssessmentSummary> = list
            .iter()
            .filter(|a| a.organization_id == Some(organization_id))
            .map(AssessmentSummary::from)
            .collect();
        summaries.sort_by_key(|a| std::cmp::Reverse(a.created_at));
        Ok(summaries)
    }

    async fn find_by_id_scoped(
        &self,
        id: Uuid,
        organization_id: Uuid,
    ) -> Result<Option<AssessmentRecord>, StorageError> {
        let list = self.assessments.read().await;
        Ok(list
            .iter()
            .find(|a| a.id == id && a.organization_id == Some(organization_id))
            .cloned())
    }
}

#[async_trait]
impl OrganizationRepository for InMemoryStorage {
    async fn find_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<mailent_domain::Organization>, StorageError> {
        let list = self.organizations.read().await;
        Ok(list.iter().find(|o| o.id == id).cloned())
    }

    async fn find_by_slug(
        &self,
        slug: &str,
    ) -> Result<Option<mailent_domain::Organization>, StorageError> {
        let list = self.organizations.read().await;
        Ok(list.iter().find(|o| o.slug == slug).cloned())
    }

    async fn list_for_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<mailent_domain::Organization>, StorageError> {
        let members = self.organization_members.read().await;
        let org_ids: Vec<Uuid> = members
            .iter()
            .filter(|m| m.user_id == user_id)
            .map(|m| m.organization_id)
            .collect();
        let orgs = self.organizations.read().await;
        if org_ids.is_empty() {
            return Ok(orgs.clone());
        }
        Ok(orgs
            .iter()
            .filter(|o| org_ids.contains(&o.id))
            .cloned()
            .collect())
    }

    async fn save(&self, org: &mailent_domain::Organization) -> Result<(), StorageError> {
        let mut list = self.organizations.write().await;
        if let Some(pos) = list.iter().position(|o| o.id == org.id) {
            list[pos] = org.clone();
        } else {
            list.push(org.clone());
        }
        Ok(())
    }

    async fn add_member(
        &self,
        member: &mailent_domain::OrganizationMember,
    ) -> Result<(), StorageError> {
        let mut list = self.organization_members.write().await;
        if let Some(pos) = list.iter().position(|m| {
            m.organization_id == member.organization_id && m.user_id == member.user_id
        }) {
            list[pos] = member.clone();
        } else {
            list.push(member.clone());
        }
        Ok(())
    }

    async fn get_member(
        &self,
        organization_id: Uuid,
        user_id: &str,
    ) -> Result<Option<mailent_domain::OrganizationMember>, StorageError> {
        let list = self.organization_members.read().await;
        Ok(list
            .iter()
            .find(|m| m.organization_id == organization_id && m.user_id == user_id)
            .cloned())
    }
}

#[async_trait]
impl DeviceRepository for InMemoryStorage {
    async fn report_installation(
        &self,
        device_id: Uuid,
        version: String,
        capabilities: Vec<String>,
        now: OffsetDateTime,
    ) -> Result<(), StorageError> {
        if let Some(device) = self
            .devices
            .write()
            .await
            .iter_mut()
            .find(|d| d.id == device_id && d.is_active())
        {
            device.version = Some(version);
            device.capabilities = capabilities;
            device.last_seen_at = now;
        }
        Ok(())
    }
    async fn save_device(&self, device: &mailent_domain::Device) -> Result<(), StorageError> {
        let mut list = self.devices.write().await;
        if let Some(pos) = list.iter().position(|d| d.id == device.id) {
            list[pos] = device.clone();
        } else {
            list.push(device.clone());
        }
        Ok(())
    }

    async fn find_device_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<mailent_domain::Device>, StorageError> {
        let list = self.devices.read().await;
        Ok(list.iter().find(|d| d.id == id).cloned())
    }

    async fn list_devices_for_org(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<mailent_domain::Device>, StorageError> {
        let list = self.devices.read().await;
        Ok(list
            .iter()
            .filter(|d| d.organization_id == organization_id)
            .cloned()
            .collect())
    }

    async fn revoke_device(&self, id: Uuid) -> Result<(), StorageError> {
        let mut list = self.devices.write().await;
        if let Some(device) = list.iter_mut().find(|d| d.id == id) {
            device.revoked_at = Some(OffsetDateTime::now_utc());
        }
        Ok(())
    }

    async fn create_challenge(
        &self,
        challenge: &mailent_domain::DeviceAuthorizationChallenge,
    ) -> Result<(), StorageError> {
        let mut list = self.device_challenges.write().await;
        list.retain(|c| c.code != challenge.code);
        list.push(challenge.clone());
        Ok(())
    }

    async fn get_challenge(
        &self,
        code: &str,
    ) -> Result<Option<mailent_domain::DeviceAuthorizationChallenge>, StorageError> {
        let list = self.device_challenges.read().await;
        Ok(list.iter().find(|c| c.code == code).cloned())
    }

    async fn approve_challenge(
        &self,
        code: &str,
        user_id: &str,
        org_id: Uuid,
        device_token: &str,
        device_id: Uuid,
    ) -> Result<(), StorageError> {
        let mut list = self.device_challenges.write().await;
        if let Some(c) = list.iter_mut().find(|c| c.code == code) {
            c.authorized_at = Some(OffsetDateTime::now_utc());
            c.authorized_by_user_id = Some(user_id.to_string());
            c.organization_id = Some(org_id);
            c.issued_token = Some(device_token.to_string());
            c.device_id = Some(device_id);
        }
        Ok(())
    }

    async fn save_device_token(
        &self,
        token_hash: &str,
        device_id: Uuid,
        org_id: Uuid,
    ) -> Result<(), StorageError> {
        let mut list = self.device_tokens.write().await;
        list.retain(|t| t.token_hash != token_hash);
        list.push(mailent_domain::DeviceTokenRecord {
            token_hash: token_hash.to_string(),
            device_id,
            organization_id: org_id,
            created_at: OffsetDateTime::now_utc(),
            last_used_at: OffsetDateTime::now_utc(),
        });
        Ok(())
    }

    async fn validate_device_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<(mailent_domain::Device, Uuid)>, StorageError> {
        let tokens = self.device_tokens.read().await;
        let tok = match tokens.iter().find(|t| t.token_hash == token_hash) {
            Some(t) => t.clone(),
            None => return Ok(None),
        };
        let devices = self.devices.read().await;
        if let Some(dev) = devices
            .iter()
            .find(|d| d.id == tok.device_id && d.is_active())
        {
            Ok(Some((dev.clone(), tok.organization_id)))
        } else {
            Ok(None)
        }
    }

    async fn revoke_device_token(&self, token_hash: &str) -> Result<(), StorageError> {
        let mut list = self.device_tokens.write().await;
        if let Some(tok) = list.iter().find(|t| t.token_hash == token_hash).cloned() {
            let mut devices = self.devices.write().await;
            if let Some(dev) = devices.iter_mut().find(|d| d.id == tok.device_id) {
                dev.revoked_at = Some(OffsetDateTime::now_utc());
            }
        }
        list.retain(|t| t.token_hash != token_hash);
        Ok(())
    }

    async fn heartbeat(
        &self,
        device_id: Uuid,
        version: Option<String>,
        capabilities: Vec<String>,
        status: String,
        now: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let mut list = self.devices.write().await;
        if let Some(device) = list.iter_mut().find(|d| d.id == device_id)
            && device.revoked_at.is_none()
        {
            device.last_seen_at = now;
            if let Some(v) = version {
                device.version = Some(v);
            }
            if !capabilities.is_empty() {
                device.capabilities = capabilities;
            }
            device.agent_enabled = true;
            device.agent_status = Some(status);
        }
        Ok(())
    }

    async fn update_agent_status(
        &self,
        device_id: Uuid,
        status: Option<String>,
        current_job_id: Option<Uuid>,
        increment_completed: bool,
    ) -> Result<(), StorageError> {
        let mut list = self.devices.write().await;
        if let Some(device) = list.iter_mut().find(|d| d.id == device_id) {
            if let Some(s) = status {
                device.agent_status = Some(s);
            }
            device.current_job_id = current_job_id;
            if increment_completed {
                device.completed_jobs_count += 1;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl JobRepository for InMemoryStorage {
    async fn cancel_active_for_device(
        &self,
        org_id: Uuid,
        device_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<u64, StorageError> {
        let mut jobs = self.agent_jobs.write().await;
        let mut count = 0;
        for job in jobs.iter_mut().filter(|j| {
            j.organization_id == org_id
                && j.target_agent_id == Some(device_id)
                && matches!(
                    j.state,
                    mailent_domain::JobState::Pending
                        | mailent_domain::JobState::Leased
                        | mailent_domain::JobState::Running
                )
        }) {
            job.state = mailent_domain::JobState::Canceled;
            job.completed_at = Some(now);
            job.lease_expires_at = None;
            job.last_error =
                Some("Device access was revoked. Connect a device to run this check again.".into());
            count += 1;
        }
        Ok(count)
    }

    async fn create_job(&self, job: &mailent_domain::AgentJob) -> Result<(), StorageError> {
        let mut list = self.agent_jobs.write().await;
        list.retain(|j| j.id != job.id);
        list.push(job.clone());
        Ok(())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<mailent_domain::AgentJob>, StorageError> {
        let list = self.agent_jobs.read().await;
        Ok(list.iter().find(|j| j.id == id).cloned())
    }

    async fn find_by_idempotency_key(
        &self,
        org_id: Uuid,
        key: &str,
    ) -> Result<Option<mailent_domain::AgentJob>, StorageError> {
        let list = self.agent_jobs.read().await;
        Ok(list
            .iter()
            .find(|j| j.organization_id == org_id && j.idempotency_key.as_deref() == Some(key))
            .cloned())
    }

    async fn lease_next_job(
        &self,
        agent_id: Uuid,
        org_id: Uuid,
        now: OffsetDateTime,
        lease_duration_secs: u64,
    ) -> Result<Option<mailent_domain::AgentJob>, StorageError> {
        let mut list = self.agent_jobs.write().await;
        for job in list.iter_mut() {
            if job.organization_id == org_id
                && (job.state == mailent_domain::JobState::Pending
                    || (job.is_lease_expired(now)
                        && job.state != mailent_domain::JobState::Completed
                        && job.state != mailent_domain::JobState::Canceled))
                && (job.target_agent_id == Some(agent_id)
                    || (job.target_agent_id.is_none()
                        && matches!(
                            job.execution_target,
                            mailent_domain::JobExecutionTarget::Agent(_)
                        )))
            {
                job.state = mailent_domain::JobState::Leased;
                job.leased_at = Some(now);
                job.lease_expires_at =
                    Some(now + time::Duration::seconds(lease_duration_secs as i64));
                job.attempt += 1;
                return Ok(Some(job.clone()));
            }
        }
        Ok(None)
    }

    async fn lease_next_cloud_job(
        &self,
        now: OffsetDateTime,
        lease_duration_secs: u64,
    ) -> Result<Option<mailent_domain::AgentJob>, StorageError> {
        let mut list = self.agent_jobs.write().await;
        for job in list.iter_mut() {
            if matches!(
                job.execution_target,
                mailent_domain::JobExecutionTarget::Cloud
            ) && (job.state == mailent_domain::JobState::Pending
                || (job.is_lease_expired(now)
                    && job.state != mailent_domain::JobState::Completed
                    && job.state != mailent_domain::JobState::Canceled))
            {
                job.state = mailent_domain::JobState::Leased;
                job.leased_at = Some(now);
                job.lease_expires_at =
                    Some(now + time::Duration::seconds(lease_duration_secs as i64));
                job.attempt += 1;
                return Ok(Some(job.clone()));
            }
        }
        Ok(None)
    }

    async fn update_job(&self, job: &mailent_domain::AgentJob) -> Result<(), StorageError> {
        let mut list = self.agent_jobs.write().await;
        if let Some(pos) = list.iter().position(|j| j.id == job.id) {
            list[pos] = job.clone();
        } else {
            list.push(job.clone());
        }
        Ok(())
    }

    async fn recover_expired_leases(&self, now: OffsetDateTime) -> Result<u64, StorageError> {
        let mut list = self.agent_jobs.write().await;
        let mut count = 0;
        for job in list.iter_mut() {
            if job.is_lease_expired(now)
                && job.state != mailent_domain::JobState::Completed
                && job.state != mailent_domain::JobState::Canceled
            {
                if job.attempt >= job.max_attempts {
                    job.state = mailent_domain::JobState::Failed;
                    job.last_error = Some("Max lease attempts exceeded".to_string());
                } else {
                    job.state = mailent_domain::JobState::Pending;
                    job.leased_at = None;
                    job.lease_expires_at = None;
                }
                count += 1;
            }
        }
        Ok(count)
    }

    async fn list_for_org(
        &self,
        org_id: Uuid,
        limit: usize,
    ) -> Result<Vec<mailent_domain::AgentJob>, StorageError> {
        let list = self.agent_jobs.read().await;
        Ok(list
            .iter()
            .filter(|j| j.organization_id == org_id)
            .take(limit)
            .cloned()
            .collect())
    }

    async fn count_active_for_org(&self, org_id: Uuid) -> Result<usize, StorageError> {
        let list = self.agent_jobs.read().await;
        Ok(list
            .iter()
            .filter(|j| {
                j.organization_id == org_id
                    && (j.state == mailent_domain::JobState::Pending
                        || j.state == mailent_domain::JobState::Leased
                        || j.state == mailent_domain::JobState::Running)
            })
            .count())
    }

    async fn count_active_for_agent(&self, agent_id: Uuid) -> Result<usize, StorageError> {
        let list = self.agent_jobs.read().await;
        Ok(list
            .iter()
            .filter(|j| {
                j.target_agent_id == Some(agent_id)
                    && (j.state == mailent_domain::JobState::Leased
                        || j.state == mailent_domain::JobState::Running)
            })
            .count())
    }
}

#[async_trait]
impl MonitorRepository for InMemoryStorage {
    async fn save(
        &self,
        monitor: &mailent_domain::InfrastructureMonitor,
    ) -> Result<(), StorageError> {
        let mut list = self.infrastructure_monitors.write().await;
        if let Some(pos) = list.iter().position(|m| m.id == monitor.id) {
            list[pos] = monitor.clone();
        } else {
            list.push(monitor.clone());
        }
        Ok(())
    }

    async fn find_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<mailent_domain::InfrastructureMonitor>, StorageError> {
        let list = self.infrastructure_monitors.read().await;
        Ok(list.iter().find(|m| m.id == id).cloned())
    }

    async fn find_by_domain(
        &self,
        org_id: Uuid,
        domain: &str,
    ) -> Result<Option<mailent_domain::InfrastructureMonitor>, StorageError> {
        let list = self.infrastructure_monitors.read().await;
        Ok(list
            .iter()
            .find(|m| m.organization_id == org_id && m.domain.eq_ignore_ascii_case(domain))
            .cloned())
    }

    async fn list_for_org(
        &self,
        org_id: Uuid,
    ) -> Result<Vec<mailent_domain::InfrastructureMonitor>, StorageError> {
        let list = self.infrastructure_monitors.read().await;
        Ok(list
            .iter()
            .filter(|m| m.organization_id == org_id)
            .cloned()
            .collect())
    }

    async fn find_due_monitors(
        &self,
        now: OffsetDateTime,
        limit: usize,
    ) -> Result<Vec<mailent_domain::InfrastructureMonitor>, StorageError> {
        let list = self.infrastructure_monitors.read().await;
        Ok(list
            .iter()
            .filter(|m| m.enabled && m.next_run_at <= now)
            .take(limit)
            .cloned()
            .collect())
    }

    async fn delete(&self, id: Uuid, org_id: Uuid) -> Result<bool, StorageError> {
        let mut list = self.infrastructure_monitors.write().await;
        let len_before = list.len();
        list.retain(|m| !(m.id == id && m.organization_id == org_id));
        Ok(list.len() < len_before)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailent_domain::{EvidenceRef, FindingCategory, FindingSeverity};
    use time::OffsetDateTime;

    #[tokio::test]
    async fn test_in_memory_finding_repository() {
        let storage = InMemoryStorage::new();
        let now = OffsetDateTime::now_utc();
        let finding = Finding {
            id: Uuid::new_v4(),
            rule_id: "TLS_LEGACY_VERSION".to_string(),
            policy_name: "modern".into(),
            policy_version: "1.0.0".into(),
            reference: "rfc8996".into(),
            severity: FindingSeverity::Critical,
            category: FindingCategory::TlsConfiguration,
            title: "Legacy TLS".to_string(),
            description: "Test".to_string(),
            remediation: "Upgrade".to_string(),
            affected_count: 1,
            first_seen: now,
            last_seen: now,
            evidence: vec![EvidenceRef {
                session_id: None,
                observation_id: None,
                description: "Evidence 1".to_string(),
            }],
            organization_id: None,
        };

        FindingRepository::save(&storage, finding.clone())
            .await
            .expect("save should work");
        let list = FindingRepository::list_all(&storage)
            .await
            .expect("list should work");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].rule_id, "TLS_LEGACY_VERSION");
    }
}
