//! Owned request-scoped evidence shared by posture, guidance and forensic reports.
use crate::state::AppState;
use mailent_correlation::{PostureInput, build_guidance, compute_posture};
use mailent_domain::*;
use mailent_storage::StorageError;
use uuid::Uuid;

#[derive(Default)]
pub struct EvidenceSnapshot {
    pub asset: Option<Asset>,
    pub investigation: Option<Investigation>,
    pub sessions: Vec<EmailSession>,
    pub findings: Vec<Finding>,
    pub anomalies: Vec<AnomalySignal>,
    pub drifts: Vec<DriftEvent>,
    pub certificates: Vec<CertificateRecord>,
    pub probes: Vec<ProbeRun>,
    pub remediations: Vec<RemediationRecord>,
}

impl EvidenceSnapshot {
    pub async fn asset(state: &AppState, id: Uuid) -> Result<Option<Self>, StorageError> {
        let Some(asset) = state.assets.find_by_id(id).await? else {
            return Ok(None);
        };
        let mut sessions = Vec::new();
        for address in &asset.addresses {
            sessions.extend(state.sessions.list_for_asset(address, 100).await?);
        }
        sessions.sort_by_key(|s| (std::cmp::Reverse(s.last_seen), s.session_id));
        let mut seen = std::collections::HashSet::new();
        sessions.retain(|s| seen.insert(s.session_id));
        // Older ingestion persisted findings without the existing asset foreign key.
        // Recover association only from actual session evidence, never descriptions.
        let mut findings = state.findings.list_for_asset(id).await?;
        for session in &sessions {
            findings.extend(state.findings.list_for_session(session.session_id).await?);
        }
        findings.sort_by_key(|f| (std::cmp::Reverse(f.last_seen), f.id));
        let mut seen_findings = std::collections::HashSet::new();
        findings.retain(|f| seen_findings.insert(f.id));
        Ok(Some(Self {
            investigation: state
                .investigations
                .list_for_asset(id)
                .await?
                .into_iter()
                .max_by_key(|i| (i.last_observed, i.id)),
            asset: Some(asset),
            sessions,
            findings,
            anomalies: state.baselines.list_anomalies(Some(id), 100).await?,
            drifts: state.assets.list_drift_events(Some(id), 100).await?,
            certificates: state.certificates.list_for_asset(id).await?,
            probes: state.probes.list_for_asset(id, 50).await?,
            remediations: state.remediations.list_for_asset(id).await?,
        }))
    }
    pub async fn investigation(state: &AppState, id: Uuid) -> Result<Option<Self>, StorageError> {
        let Some(inv) = state.investigations.find_by_id(id).await? else {
            return Ok(None);
        };
        let Some(mut evidence) = Self::asset(state, inv.asset_id).await? else {
            return Ok(None);
        };
        evidence.findings.retain(|f| {
            inv.finding_ids.contains(&f.rule_id)
                && f.last_seen.unix_timestamp_nanos() / 1000
                    >= inv.first_observed.unix_timestamp_nanos() / 1000
                && f.first_seen.unix_timestamp_nanos() / 1000
                    <= inv.last_observed.unix_timestamp_nanos() / 1000
        });
        evidence
            .anomalies
            .retain(|a| inv.anomaly_ids.contains(&a.id));
        evidence
            .drifts
            .retain(|d| inv.drift_event_ids.contains(&d.id));
        evidence.probes.retain(|p| p.investigation_id == Some(id));
        evidence
            .remediations
            .retain(|r| r.investigation_id == Some(id));
        let ids: std::collections::HashSet<_> = evidence
            .findings
            .iter()
            .flat_map(|f| {
                f.evidence
                    .iter()
                    .filter_map(|e| e.session_id.or(e.observation_id))
            })
            .chain(evidence.drifts.iter().filter_map(|d| d.session_id))
            .collect();
        evidence.sessions.retain(|s| ids.contains(&s.session_id));
        evidence.certificates.retain(|c| {
            evidence.sessions.iter().any(|s| {
                s.certificate
                    .as_ref()
                    .is_some_and(|sc| sc.reference.sha256_fingerprint == c.sha256_fingerprint)
            })
        });
        evidence.investigation = Some(inv);
        Ok(Some(evidence))
    }
    pub async fn session(state: &AppState, id: Uuid) -> Result<Option<Self>, StorageError> {
        let Some(session) = state.sessions.find_by_id(id).await? else {
            return Ok(None);
        };
        let asset = state
            .assets
            .find_by_address_or_identity(&session.flow.dst_ip)
            .await?;
        let remediations = if let Some(asset) = &asset {
            state
                .remediations
                .list_for_asset(asset.id)
                .await?
                .into_iter()
                .filter(|r| r.before.session_id == id)
                .collect()
        } else {
            vec![]
        };
        Ok(Some(Self {
            asset,
            remediations,
            sessions: vec![session],
            findings: state.findings.list_for_session(id).await?,
            ..Default::default()
        }))
    }
    pub fn posture(
        &self,
        kind: PostureSubjectKind,
        id: Uuid,
    ) -> (SecurityPosture, Vec<RemediationGuidance>) {
        let input = PostureInput {
            findings: &self.findings,
            anomalies: &self.anomalies,
            asset: self
                .asset
                .as_ref()
                .filter(|_| kind != PostureSubjectKind::Session),
            asset_sessions: &self.sessions,
            certificates: &self.certificates,
            probe_runs: &self.probes,
            investigation: self.investigation.as_ref(),
        };
        let posture = compute_posture(kind, id, &input);
        let guidance = build_guidance(
            id,
            &self.findings,
            self.asset.as_ref(),
            &self.sessions,
            &self.anomalies,
            posture.computed_at,
        );
        (posture, guidance)
    }
    pub fn report(
        &self,
        kind: PostureSubjectKind,
        id: Uuid,
        state: &AppState,
    ) -> mailent_reporting::ForensicReport {
        let (posture, guidance) = self.posture(kind, id);
        let input = mailent_reporting::ReportInput {
            investigation: self.investigation.as_ref(),
            asset: self.asset.as_ref(),
            sessions: &self.sessions,
            findings: &self.findings,
            anomalies: &self.anomalies,
            drifts: &self.drifts,
            probe_runs: &self.probes,
            posture: Some(&posture),
            guidance: &guidance,
            remediation_records: &self.remediations,
            policy_name: state.policy_pack.name.clone(),
            policy_version: state.policy_pack.version.clone(),
        };
        let title = self
            .investigation
            .as_ref()
            .filter(|_| kind == PostureSubjectKind::Investigation)
            .map(|i| i.title.clone())
            .unwrap_or_else(|| {
                format!(
                    "Forensic report — {}",
                    self.asset
                        .as_ref()
                        .map(|a| a.hostname().unwrap_or_else(|| a.ip_address()))
                        .unwrap_or("session")
                )
            });
        mailent_reporting::build_report(
            title,
            env!("CARGO_PKG_VERSION"),
            &input,
            time::OffsetDateTime::now_utc(),
        )
    }
}
