use async_trait::async_trait;
use mailent_domain::{
    AnomalySignal, Asset, AssetBaseline, CertificateRecord, CtCertificateRecord,
    CtIntelligenceEvent, DecisionRecord, DriftEvent, EmailSession, Finding,
    IntelligenceRefreshStatus, Investigation, InvestigationStatus, MtaStsPolicy, MxRecord,
    NormalizedObservation, ProbeRun, SensorHeartbeat, SensorRecord, SensorStatus,
    TlsRptAggregateReport, TlsRptPolicy, TlsaRecord,
};
use std::{collections::HashMap, sync::Arc};
use time::OffsetDateTime;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    error::StorageError,
    repository::{
        AssetRepository, BaselineRepository, CertificateRepository, DecisionRepository,
        EvidenceStore, FindingRepository, IntelligenceRepository, InvestigationRepository,
        ObservationRepository, ProbeRepository, SensorRepository, SessionRepository,
    },
};

/// In-memory storage implementation used exclusively for testing, local scaffolding,
/// and fast iteration during isolated unit tests.
#[derive(Debug, Default, Clone)]
pub struct InMemoryStorage {
    assets: Arc<RwLock<Vec<Asset>>>,
    drift_events: Arc<RwLock<Vec<DriftEvent>>>,
    findings: Arc<RwLock<Vec<Finding>>>,
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
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self::default()
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

    async fn list_for_asset(&self, _asset_id: Uuid) -> Result<Vec<Finding>, StorageError> {
        let guard = self.findings.read().await;
        Ok(guard.clone())
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
            guard[pos] = investigation.clone();
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
