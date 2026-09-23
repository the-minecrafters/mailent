use mailent_domain::{
    Asset, AssetBaseline, AutomatedLabel, BaselineFeatures, CertificateFeature, DaneStatus,
    DecisionResult, DeliveryContextFeatures, DriftEvent, EmailSession, Finding, Investigation,
    MtaStsMode, PolicyFindingFeature, ProbeRun, ProbeStartTlsResult, TrainingFeatures,
    TrainingRecord, name_hash,
};
use mailent_storage::StorageError;
use serde::Serialize;

use crate::state::AppState;

/// Inputs gathered at decision time by the pipeline.  The snapshot is built from
/// exactly these values and persisted verbatim — never refetched later.
pub struct CaptureContext<'a> {
    pub inv: &'a Investigation,
    pub asset: &'a Asset,
    pub session: &'a EmailSession,
    pub findings: &'a [Finding],
    pub drift_events: &'a [DriftEvent],
    pub anomalies: &'a [mailent_domain::AnomalySignal],
    pub baseline: Option<&'a AssetBaseline>,
    pub dane_status: Option<DaneStatus>,
    pub mta_sts_mode: Option<MtaStsMode>,
    pub mta_sts_failed: bool,
    pub mta_sts_enforced: bool,
    pub tlsa_record_count: usize,
    pub active_verification: Option<&'a ProbeRun>,
    pub jev_decision: Option<&'a DecisionResult>,
    /// Domain used to check TLS-RPT policy presence (best effort).
    pub delivery_domain: Option<&'a str>,
    pub captured_at: time::OffsetDateTime,
}

/// Build the structured, derived feature snapshot from the decision-time context.
///
/// Only derived features are emitted.  Raw packets, mail bodies, credentials,
/// hostnames, addresses and SMTP prose are deliberately excluded; identities
/// are reduced to stable hashes where possible.
fn build_features(ctx: &CaptureContext<'_>) -> TrainingFeatures {
    let asset = &ctx.asset;
    let session = &ctx.session;

    let certificate = session.certificate.as_ref().map(|c| CertificateFeature {
        fingerprint_hash: c.reference.sha256_fingerprint.clone(),
        issuer_hash: Some(name_hash(&c.reference.issuer)),
        san_count: c.san.len(),
        validity_days_remaining: (c.validity.not_after - ctx.captured_at).whole_days(),
    });

    let forward_secrecy = session
        .key_exchange
        .as_ref()
        .map(|k| k.provides_forward_secrecy())
        .unwrap_or(mailent_domain::ForwardSecrecyState::Unknown);

    let probe = ctx.active_verification.map(|p| {
        let result = p.result.as_ref();
        mailent_domain::ProbeFeature {
            protocol: p.protocol,
            port: p.port,
            outcome: snake_str(&p.outcome),
            starttls: probe_starttls_string(p),
            tls_version: result
                .and_then(|r| r.tls_version.as_ref())
                .map(ToString::to_string),
            dane_status: result.map(|r| format!("{:?}", r.dane_status)),
            has_mismatch: p.has_mismatch,
            mismatch_kinds: p
                .perspective_mismatches
                .iter()
                .map(|m| m.kind.clone())
                .collect(),
            verified_drift_count: result
                .and_then(|r| r.verification.as_ref())
                .map(|v| v.drift.len())
                .unwrap_or(0),
            latency_ms: result.map(|r| r.latency_ms).unwrap_or(0),
        }
    });

    let jev =
        ctx.jev_decision
            .filter(|d| !d.is_deterministic())
            .map(|d| mailent_domain::JevFeature {
                role: "teacher".to_string(),
                provider: d.provider_info.clone(),
                risk: d.risk,
                anomalous: d.anomalous,
                human_review: d.human_review,
                priority: d.priority,
                confidence: d.confidence,
            });

    TrainingFeatures {
        asset: mailent_domain::AssetFeatures {
            endpoint_count: asset.endpoints.len(),
            protocols: asset
                .endpoints
                .iter()
                .map(|e| e.protocol)
                .collect::<Vec<_>>(),
            tls_versions: asset.tls_versions.clone(),
            cipher_suite_count: asset.cipher_suites.len(),
            certificate_count: asset.certificate_fingerprints.len(),
            has_domain_name: asset
                .primary_name
                .as_ref()
                .or_else(|| asset.hostnames.first())
                .is_some(),
            name_hash: asset.primary_name.as_deref().map(name_hash),
        },
        policy: ctx
            .findings
            .iter()
            .map(PolicyFindingFeature::from)
            .collect(),
        baseline: ctx.baseline.map(|b| BaselineFeatures {
            sample_count: b.sample_count,
            coverage: b.coverage,
            starttls_success_rate: b.starttls_success_rate,
            handshake_failure_rate: b.handshake_failure_rate,
            session_frequency_per_hour: b.session_frequency_per_hour,
            tls_version_distribution: b.tls_version_distribution.clone(),
            peer_count: b.peer_set.len(),
            ports: b.ports.clone(),
        }),
        anomalies: ctx
            .anomalies
            .iter()
            .map(mailent_domain::AnomalyFeature::from)
            .collect(),
        tls: mailent_domain::TlsFeatures {
            protocol: session.protocol,
            port: session.flow.dst_port,
            tls_version: session.tls_version.clone(),
            cipher_name: session.cipher_suite.as_ref().map(|c| c.name.clone()),
            forward_secrecy,
            starttls_state: session.starttls_state,
            tls_established: session.tls_version.is_some(),
        },
        certificate,
        drift: ctx
            .drift_events
            .iter()
            .map(mailent_domain::DriftFeature::from)
            .collect(),
        delivery: DeliveryContextFeatures {
            dane_status: ctx.dane_status.map(|d| format!("{:?}", d)),
            mta_sts_mode: ctx.mta_sts_mode,
            mta_sts_enforced: ctx.mta_sts_enforced,
            mta_sts_failed: ctx.mta_sts_failed,
            tlsa_record_count: ctx.tlsa_record_count,
            tls_rpt_policy_present: false,
        },
        probe,
        jev,
    }
}

/// Persist a versioned training record from the current decision context.
/// The feature snapshot is the structured decision-time context, never rebuilt.
pub async fn capture_training(
    state: &AppState,
    ctx: &CaptureContext<'_>,
) -> Result<TrainingRecord, StorageError> {
    let mut features = build_features(ctx);

    // Best-effort TLS-RPT presence lookup at capture time.
    if let Some(domain) = ctx.delivery_domain {
        let present = state
            .intelligence
            .get_tls_rpt_policy(domain)
            .await
            .map(|opt| opt.is_some())
            .unwrap_or(false);
        features.delivery.tls_rpt_policy_present = present;
    }

    let automated_label = automated_label(ctx);
    let record = TrainingRecord::new(
        ctx.inv.id,
        ctx.asset.id,
        ctx.captured_at,
        features,
        automated_label,
    );

    // Best-effort save: training capture must never block ingestion.
    if let Err(e) = state.training.save(&record).await {
        tracing::warn!(%record.id, %record.investigation_id, "training capture save failed: {e}");
        return Err(e);
    }
    Ok(record)
}

/// Automated label derived purely from the automated decision path.  Structurally
/// separate from analyst labels; Jev output is a teacher signal, never ground truth.
fn automated_label(ctx: &CaptureContext<'_>) -> Option<AutomatedLabel> {
    ctx.jev_decision.map(|d| AutomatedLabel {
        source: if d.is_deterministic() {
            d.provider_info.clone()
        } else {
            format!("jev/{}", d.provider_info)
        },
        risk: Some(d.risk),
        priority: Some(d.priority),
        anomalous: d.anomalous,
        human_review: d.human_review,
    })
}

fn snake_str<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|x| x.as_str().map(String::from))
        .unwrap_or_else(|| "unknown".to_string())
}

fn probe_starttls_string(run: &ProbeRun) -> String {
    let s = run
        .result
        .as_ref()
        .map(|r| match r.starttls {
            ProbeStartTlsResult::AdvertisedAndAccepted
            | ProbeStartTlsResult::AdvertisedAndRejected => "advertised",
            ProbeStartTlsResult::NotAdvertised => "not_advertised",
            ProbeStartTlsResult::NotReached => "not_reached",
            ProbeStartTlsResult::ImplicitTls => "implicit_tls",
            ProbeStartTlsResult::AcceptedHandshakeFailed => "accepted_handshake_failed",
        })
        .unwrap_or("unknown");
    s.to_string()
}
