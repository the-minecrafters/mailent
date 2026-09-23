use crate::{evidence::EvidenceSnapshot, state::AppState};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use mailent_domain::{PostureSubjectKind, RemediationGuidance, SecurityPosture};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct AssetPostureResponse {
    pub posture: SecurityPosture,
    pub guidance: Vec<RemediationGuidance>,
    pub remediations: Vec<mailent_domain::RemediationRecord>,
    pub asset_id: Option<Uuid>,
    pub verification_conditions:
        std::collections::BTreeMap<Uuid, mailent_domain::RemediationCondition>,
}
async fn posture(
    state: &AppState,
    id: Uuid,
    kind: PostureSubjectKind,
) -> Result<Json<AssetPostureResponse>, (StatusCode, String)> {
    let snapshot = match kind {
        PostureSubjectKind::Asset => EvidenceSnapshot::asset(state, id).await,
        PostureSubjectKind::Session => EvidenceSnapshot::session(state, id).await,
        PostureSubjectKind::Investigation => EvidenceSnapshot::investigation(state, id).await,
    }
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((StatusCode::NOT_FOUND, format!("subject {id} not found")))?;
    let (posture, guidance) = snapshot.posture(kind, id);
    let verification_conditions = guidance
        .iter()
        .filter_map(|g| mailent_domain::RemediationCondition::for_guidance(g).map(|c| (g.id, c)))
        .collect();
    Ok(Json(AssetPostureResponse {
        posture,
        guidance,
        remediations: snapshot.remediations,
        asset_id: snapshot.asset.map(|a| a.id),
        verification_conditions,
    }))
}
pub async fn get_asset_posture_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AssetPostureResponse>, (StatusCode, String)> {
    let res = posture(&state, id, PostureSubjectKind::Asset).await?;
    let _ = record_posture_snapshot_if_changed(&state, id, &res.posture, None).await;
    Ok(res)
}
pub async fn get_session_posture_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AssetPostureResponse>, (StatusCode, String)> {
    posture(&state, id, PostureSubjectKind::Session).await
}
pub async fn get_investigation_posture_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AssetPostureResponse>, (StatusCode, String)> {
    posture(&state, id, PostureSubjectKind::Investigation).await
}

pub async fn get_asset_posture_history_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<mailent_domain::AssetPostureHistory>, (StatusCode, String)> {
    let snapshot = EvidenceSnapshot::asset(&state, id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, format!("asset {id} not found")))?;

    let (current_posture, _) = snapshot.posture(PostureSubjectKind::Asset, id);
    let _ = record_posture_snapshot_if_changed(&state, id, &current_posture, None).await;

    let history = state
        .postures
        .list_for_asset(id, 50)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let previous = history.get(1).cloned();

    let change_summary = if let Some(ref prev) = previous {
        let score_delta = current_posture.score - prev.score;
        let mut what_changed = Vec::new();

        if (score_delta).abs() > 0.01 {
            what_changed.push(format!(
                "Score: {:.1} → {:.1} ({:+.1} points)",
                prev.score, current_posture.score, score_delta
            ));
        }
        if current_posture.grade != prev.grade {
            what_changed.push(format!("Grade: {} → {}", prev.grade, current_posture.grade));
        }

        let old_rules: std::collections::HashSet<_> =
            prev.deductions.iter().map(|d| &d.rule_id).collect();
        let new_rules: std::collections::HashSet<_> = current_posture
            .deductions
            .iter()
            .map(|d| &d.rule_id)
            .collect();

        for rule in new_rules.difference(&old_rules) {
            what_changed.push(format!("New finding deduction: {rule}"));
        }
        for rule in old_rules.difference(&new_rules) {
            what_changed.push(format!("Resolved finding: {rule}"));
        }

        let why_score_changed = if score_delta > 0.0 {
            format!(
                "Security posture improved by {:.1} points due to remediated transport weaknesses",
                score_delta
            )
        } else if score_delta < 0.0 {
            format!(
                "Security posture decreased by {:.1} points due to newly detected findings or configuration drift",
                score_delta.abs()
            )
        } else {
            "Posture score stable; no score change observed between snapshots".into()
        };

        let evidence_caused: Vec<_> = current_posture
            .deductions
            .iter()
            .map(|d| mailent_domain::EvidenceRef {
                session_id: None,
                observation_id: None,
                description: d.evidence_description.clone(),
            })
            .collect();

        Some(mailent_domain::PostureChangeSummary {
            score_delta,
            previous_score: prev.score,
            current_score: current_posture.score,
            what_changed,
            why_score_changed,
            evidence_caused,
            changed_at: current_posture.computed_at,
        })
    } else {
        None
    };

    Ok(Json(mailent_domain::AssetPostureHistory {
        asset_id: id,
        current: current_posture,
        previous,
        history,
        change_summary,
    }))
}

pub async fn record_posture_snapshot_if_changed(
    state: &AppState,
    asset_id: Uuid,
    posture: &SecurityPosture,
    reason: Option<&str>,
) -> Result<Option<mailent_domain::PostureSnapshot>, mailent_storage::StorageError> {
    let latest = state.postures.latest_for_asset(asset_id).await?;
    let new_snapshot = mailent_domain::PostureSnapshot::from_posture(
        asset_id,
        posture,
        reason.map(ToString::to_string),
        latest.as_ref().map(|l| posture.score - l.score),
    );

    if let Some(ref prev) = latest
        && !new_snapshot.has_meaningful_difference(prev)
    {
        return Ok(None);
    }

    state.postures.save_snapshot(&new_snapshot).await?;
    Ok(Some(new_snapshot))
}

pub async fn evaluate_and_record_asset_posture_snapshot(
    state: &AppState,
    asset_id: Uuid,
    reason: Option<&str>,
) -> Result<Option<mailent_domain::PostureSnapshot>, mailent_storage::StorageError> {
    if let Ok(Some(evidence)) = crate::evidence::EvidenceSnapshot::asset(state, asset_id).await {
        let (posture, _) = evidence.posture(mailent_domain::PostureSubjectKind::Asset, asset_id);
        record_posture_snapshot_if_changed(state, asset_id, &posture, reason).await
    } else {
        Ok(None)
    }
}
