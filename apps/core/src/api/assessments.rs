use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use mailent_domain::{AssessmentRecord, RiskLevel};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{auth::ExecutionContext, state::AppState};

#[derive(Debug, Deserialize)]
pub struct SyncAssessmentRequest {
    pub client_sync_id: Option<String>,
    pub assessment: AssessmentRecord,
    #[serde(default)]
    pub findings: Vec<mailent_domain::Finding>,
    #[serde(default)]
    pub assets: Vec<mailent_domain::Asset>,
    #[serde(default)]
    pub sessions: Vec<mailent_domain::EmailSession>,
}

#[derive(Debug, Serialize)]
pub struct SyncAssessmentResponse {
    pub synced: bool,
    pub assessment_id: Uuid,
    pub organization_id: Option<Uuid>,
    pub findings_count: usize,
    pub assets_count: usize,
}

pub async fn sync_assessment_handler(
    State(state): State<AppState>,
    ctx: Option<Extension<ExecutionContext>>,
    Json(mut req): Json<SyncAssessmentRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let context = ctx.as_ref().map(|Extension(c)| c);
    let org_id = context.and_then(|c| c.organization_id).ok_or((
        StatusCode::UNAUTHORIZED,
        "Connect Mailent CLI before syncing results.".to_string(),
    ))?;
    if !matches!(
        context.map(|c| &c.actor),
        Some(crate::auth::Actor::Device { .. })
    ) {
        return Err((
            StatusCode::FORBIDDEN,
            "Sync results from a connected Mailent CLI installation.".into(),
        ));
    }
    let storage_error =
        |e: mailent_storage::StorageError| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    if let Some(existing) = state
        .assessments
        .find_by_id(req.assessment.id)
        .await
        .map_err(storage_error)?
    {
        if existing.organization_id != Some(org_id) {
            return Err((
                StatusCode::CONFLICT,
                "Assessment ID is already in use.".into(),
            ));
        }
        return Ok((
            StatusCode::OK,
            Json(SyncAssessmentResponse {
                synced: true,
                assessment_id: existing.id,
                organization_id: Some(org_id),
                findings_count: existing.finding_ids.len(),
                assets_count: existing.asset_ids.len(),
            }),
        ));
    }
    // Namespace incoming identifiers so the same capture can be synced to separate workspaces.
    let scoped = |id: Uuid| Uuid::new_v5(&org_id, id.as_bytes());
    let session_ids: std::collections::HashSet<_> =
        req.sessions.iter().map(|s| s.session_id).collect();
    let finding_ids: std::collections::HashSet<_> = req.findings.iter().map(|f| f.id).collect();
    let asset_ids: std::collections::HashSet<_> = req.assets.iter().map(|a| a.id).collect();
    if req
        .assessment
        .session_ids
        .iter()
        .any(|id| !session_ids.contains(id))
        || req
            .assessment
            .finding_ids
            .iter()
            .any(|id| !finding_ids.contains(id))
        || (!req.assets.is_empty()
            && req
                .assessment
                .asset_ids
                .iter()
                .any(|id| !asset_ids.contains(id)))
    {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "Sync must include the assessment's structured evidence.".into(),
        ));
    }
    if req
        .findings
        .iter()
        .flat_map(|f| &f.evidence)
        .any(|e| e.session_id.is_some_and(|id| !session_ids.contains(&id)))
    {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "Finding refers to a session outside this sync.".into(),
        ));
    }
    let mut observations = Vec::new();
    for session in &mut req.sessions {
        session.session_id = scoped(session.session_id);
        session.sensor_id = format!("{org_id}:{}", session.sensor_id);
        let observation = mailent_domain::NormalizedObservation {
            observation_id: session.session_id,
            timestamp: session.first_seen,
            sensor_id: session.sensor_id.clone(),
            provenance: session.provenance.clone(),
            flow: session.flow.clone(),
            protocol: session.protocol,
            starttls_state: session.starttls_state,
            tls_version: session.tls_version.clone(),
            cipher_suite: session.cipher_suite.clone(),
            key_exchange: session.key_exchange.clone(),
            certificate: session.certificate.clone(),
            capture: session.capture.clone(),
            raw_metadata: None,
        };
        observation
            .validate()
            .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
        observations.push(observation);
    }
    req.assessment.organization_id = Some(org_id);
    req.assessment.session_ids = req.sessions.iter().map(|s| s.session_id).collect();
    req.assessment.asset_ids.clear();
    req.assessment.finding_ids.clear();
    if !req.assessment.metadata.is_object() {
        req.assessment.metadata = serde_json::json!({});
    }
    if let Some(crate::auth::Actor::Device { device_id, .. }) = context.map(|c| &c.actor) {
        req.assessment.metadata["source_device_id"] = serde_json::json!(device_id);
        req.assessment.metadata["synced_at"] = serde_json::json!(
            OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap()
        );
    }
    let mut assets = Vec::new();
    for mut asset in req.assets {
        asset.id = scoped(asset.id);
        asset.organization_id = Some(org_id);
        // Keep stable workspace identity across scans of the same server.
        for address in &asset.addresses {
            if let Some(existing) = state
                .assets
                .find_by_address_or_identity_scoped(address, Some(org_id))
                .await
                .map_err(storage_error)?
            {
                asset.id = existing.id;
                break;
            }
        }
        assets.push(asset);
    }
    let mut findings = Vec::new();
    let mut anomalies = Vec::new();
    let mut drifts = Vec::new();
    for observation in observations {
        let result = crate::pipeline::process_observation_scoped(&state, observation, Some(org_id))
            .await
            .map_err(storage_error)?;
        req.assessment.asset_ids.push(result.asset_id);
        findings.extend(result.findings);
        anomalies.extend(result.anomalies);
        drifts.extend(result.drift_events);
    }
    // Domain policy findings and DNS-only assets may have no packet session.
    for mut finding in req.findings {
        finding.id = scoped(finding.id);
        finding.organization_id = Some(org_id);
        for evidence in &mut finding.evidence {
            if evidence
                .session_id
                .is_some_and(|id| !session_ids.contains(&id))
            {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Finding refers to a session outside this sync.".into(),
                ));
            }
            evidence.session_id = evidence.session_id.map(scoped);
            evidence.observation_id = evidence.observation_id.map(scoped);
        }
        if !findings
            .iter()
            .any(|f| f.rule_id == finding.rule_id && f.evidence == finding.evidence)
        {
            findings.push(finding);
        }
    }
    for asset in assets {
        let existing = match asset.addresses.first() {
            Some(address) => state
                .assets
                .find_by_address_or_identity_scoped(address, Some(org_id))
                .await
                .map_err(storage_error)?,
            None => None,
        };
        if let Some(existing) = existing {
            req.assessment.asset_ids.push(existing.id);
        } else {
            req.assessment.asset_ids.push(asset.id);
            state.assets.upsert(asset).await.map_err(storage_error)?;
        }
    }
    req.assessment.asset_ids.sort();
    req.assessment.asset_ids.dedup();
    for finding in &findings {
        state
            .findings
            .save(finding.clone())
            .await
            .map_err(storage_error)?;
        if req.assessment.asset_ids.len() == 1 {
            state
                .findings
                .link_asset(finding.id, req.assessment.asset_ids[0])
                .await
                .map_err(storage_error)?;
        }
        req.assessment.finding_ids.push(finding.id);
    }
    if let Some(domain) = req.assessment.target_domain() {
        let prior = state
            .assessments
            .list_for_org(org_id)
            .await
            .map_err(storage_error)?
            .into_iter()
            .filter(|a| {
                a.target == domain
                    && a.source_type == "infrastructure"
                    && a.created_at < req.assessment.created_at
            })
            .max_by_key(|a| a.created_at);
        if let Some(prior) = prior {
            if let Some(previous) = state
                .assessments
                .find_by_id_scoped(prior.id, org_id)
                .await
                .map_err(storage_error)?
            {
                let mut previous_findings = Vec::new();
                for id in &previous.finding_ids {
                    if let Some(f) = state
                        .findings
                        .find_by_id(*id)
                        .await
                        .map_err(storage_error)?
                    {
                        previous_findings.push(f);
                    }
                }
                let changes =
                    mailent_correlation::drift::InfrastructureDriftCorrelator::compare_assessments(
                        &previous,
                        &req.assessment,
                        &previous_findings,
                        &findings,
                    );
                super::agent::sync_infrastructure_investigation(
                    &state,
                    &req.assessment,
                    domain,
                    &changes,
                    &findings,
                    OffsetDateTime::now_utc(),
                )
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
                drifts.extend(changes);
            }
        }
    }
    review_synced_assessment(&state, &mut req.assessment, &findings, &anomalies, &drifts).await?;
    state
        .assessments
        .save(&req.assessment)
        .await
        .map_err(storage_error)?;
    Ok((
        StatusCode::OK,
        Json(SyncAssessmentResponse {
            synced: true,
            assessment_id: req.assessment.id,
            organization_id: Some(org_id),
            findings_count: req.assessment.finding_ids.len(),
            assets_count: req.assessment.asset_ids.len(),
        }),
    ))
}

pub async fn review_synced_assessment(
    state: &AppState,
    assessment: &mut AssessmentRecord,
    findings: &[mailent_domain::Finding],
    anomalies: &[mailent_domain::AnomalySignal],
    drifts: &[mailent_domain::DriftEvent],
) -> Result<(), (StatusCode, String)> {
    let storage_error =
        |e: mailent_storage::StorageError| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    // AI reviews structured evidence only. Local acquisition and policy facts stay unchanged.
    let decision_context = mailent_domain::DecisionContext {
        session_id: assessment
            .session_ids
            .first()
            .copied()
            .unwrap_or(assessment.id),
        findings: findings
            .iter()
            .map(|f| mailent_domain::FindingCandidate {
                rule_id: f.rule_id.clone(),
                policy_name: f.policy_name.clone(),
                policy_version: f.policy_version.clone(),
                reference: f.reference.clone(),
                severity: f.severity,
                category: f.category,
                title: f.title.clone(),
                description: f.description.clone(),
                remediation: f.remediation.clone(),
                evidence: f.evidence.clone(),
            })
            .collect(),
        metadata: serde_json::json!({"assessment_id": assessment.id, "anomalies": anomalies, "drifts": drifts,
            "session_count": assessment.session_ids.len(), "posture_score": assessment.posture_score}),
    };
    let decision = state
        .decision_provider
        .assess(decision_context.clone())
        .await
        .unwrap_or_else(|_| {
            mailent_decision::JevProvider::deterministic_fallback(&decision_context)
        });
    let provider = if decision.provider_info.starts_with("jev:") {
        "jev"
    } else {
        "deterministic_fallback"
    };
    let finding_risk = findings
        .iter()
        .map(|f| RiskLevel::from(f.severity))
        .max()
        .unwrap_or(RiskLevel::Low);
    if assessment.ai_risk_classification != "INCONCLUSIVE" {
        assessment.ai_risk_classification =
            format!("{:?}", decision.risk.max(finding_risk)).to_uppercase();
    }
    assessment.ai_risk_rationale = decision.reasons.join(" ");
    assessment.ai_confidence = decision.confidence;
    assessment.metadata["ai_provider"] = serde_json::json!(provider);
    assessment.metadata["workspace_analysis"] =
        serde_json::json!({"drifts": drifts.len(), "anomalies": anomalies.len()});
    state
        .decisions
        .save_record(&mailent_domain::DecisionRecord {
            id: Uuid::new_v4(),
            session_id: assessment.session_ids.first().copied(),
            asset_id: assessment.asset_ids.first().copied(),
            provider: provider.into(),
            model: decision.provider_info.clone(),
            decision,
            latency_ms: 0,
            created_at: OffsetDateTime::now_utc(),
        })
        .await
        .map_err(storage_error)?;
    Ok(())
}

pub async fn list_assessments_handler(
    State(state): State<AppState>,
    ctx: Option<Extension<ExecutionContext>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let org_id = ctx.as_ref().and_then(|Extension(c)| c.organization_id);
    let list = if let Some(org_id) = org_id {
        state.assessments.list_for_org(org_id).await
    } else {
        state.assessments.list_all().await
    }
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(list))
}

pub async fn get_assessment_handler(
    State(state): State<AppState>,
    ctx: Option<Extension<ExecutionContext>>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let org_id = ctx.as_ref().and_then(|Extension(c)| c.organization_id);
    let assessment = if let Some(org_id) = org_id {
        state.assessments.find_by_id_scoped(id, org_id).await
    } else {
        state.assessments.find_by_id(id).await
    }
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Assessment not found".to_string()))?;
    Ok(Json(assessment))
}
