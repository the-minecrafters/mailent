//! Analyst workflow and persistence orchestration; condition evaluation lives in domain.
use crate::{evidence::EvidenceSnapshot, state::AppState};
use axum::http::StatusCode;
use mailent_domain::*;
use mailent_storage::StorageError;
use time::OffsetDateTime;
use uuid::Uuid;
type Error = (StatusCode, String);
fn storage(e: StorageError) -> Error {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}
fn conflict(message: &str) -> Error {
    (StatusCode::CONFLICT, message.into())
}

pub async fn get(state: &AppState, id: Uuid) -> Result<RemediationRecord, Error> {
    state
        .remediations
        .find_by_id(id)
        .await
        .map_err(storage)?
        .ok_or((StatusCode::NOT_FOUND, "remediation not found".into()))
}
pub async fn start(
    state: &AppState,
    asset_id: Uuid,
    finding_id: Uuid,
    session_id: Option<Uuid>,
    investigation_id: Option<Uuid>,
) -> Result<RemediationRecord, Error> {
    let evidence = EvidenceSnapshot::asset(state, asset_id)
        .await
        .map_err(storage)?
        .ok_or((StatusCode::NOT_FOUND, "asset not found".into()))?;
    let finding = evidence
        .findings
        .iter()
        .find(|f| f.id == finding_id)
        .ok_or((
            StatusCode::NOT_FOUND,
            "finding does not belong to this asset".into(),
        ))?;
    let (_, guidance) = evidence.posture(PostureSubjectKind::Asset, asset_id);
    let guidance = guidance
        .into_iter()
        .find(|g| g.finding_id == Some(finding_id))
        .ok_or((
            StatusCode::UNPROCESSABLE_ENTITY,
            "no remediation guidance for finding".into(),
        ))?;
    let condition = RemediationCondition::for_guidance(&guidance).ok_or((StatusCode::UNPROCESSABLE_ENTITY, "active verification is not implemented for this guidance; no vulnerability inferred from best-practice advice".into()))?;
    let sessions: Vec<_> = evidence
        .sessions
        .iter()
        .filter(|s| {
            session_id.is_none_or(|id| s.session_id == id)
                && finding
                    .evidence
                    .iter()
                    .any(|e| e.session_id.or(e.observation_id) == Some(s.session_id))
        })
        .collect();
    if sessions.len() != 1 {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "select one captured evidence session for this finding; each affected endpoint must be verified separately".into()));
    }
    let before = sessions[0].clone();
    let inv_id = investigation_id.or_else(|| {
        evidence
            .investigation
            .as_ref()
            .filter(|i| {
                i.finding_ids.contains(&finding.rule_id)
                    && finding.last_seen.unix_timestamp_nanos() / 1000
                        >= i.first_observed.unix_timestamp_nanos() / 1000
                    && finding.first_seen.unix_timestamp_nanos() / 1000
                        <= i.last_observed.unix_timestamp_nanos() / 1000
            })
            .map(|i| i.id)
    });
    if let Some(id) = inv_id {
        let inv = state
            .investigations
            .find_by_id(id)
            .await
            .map_err(storage)?
            .ok_or((StatusCode::NOT_FOUND, "investigation not found".into()))?;
        if inv.asset_id != asset_id
            || !inv.finding_ids.contains(&finding.rule_id)
            || finding.last_seen.unix_timestamp_nanos() / 1000
                < inv.first_observed.unix_timestamp_nanos() / 1000
            || finding.first_seen.unix_timestamp_nanos() / 1000
                > inv.last_observed.unix_timestamp_nanos() / 1000
        {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                "investigation does not contain the affected finding".into(),
            ));
        }
    }
    let record = RemediationRecord {
        id: Uuid::new_v5(
            &Uuid::NAMESPACE_OID,
            format!(
                "remediation:{asset_id}:{finding_id}:{}:{inv_id:?}",
                before.session_id
            )
            .as_bytes(),
        ),
        asset_id,
        investigation_id: inv_id,
        finding: finding.clone(),
        guidance,
        before,
        condition,
        state: RemediationState::InProgress,
        revision: 0,
        started_at: OffsetDateTime::now_utc(),
        applied_at: None,
        analyst_note: None,
        attempts: vec![],
    };
    state.remediations.create(&record).await.map_err(storage)
}
pub async fn mark_applied(
    state: &AppState,
    id: Uuid,
    note: Option<String>,
) -> Result<RemediationRecord, Error> {
    let mut record = get(state, id).await?;
    if record.state == RemediationState::Verifying {
        return Err(conflict("verification already running"));
    }
    if note.as_ref().is_some_and(|n| n.len() > 4096) {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "analyst note exceeds 4096 bytes".into(),
        ));
    }
    let revision = record.revision;
    record.revision += 1;
    record.state = RemediationState::Applied;
    record.applied_at = Some(OffsetDateTime::now_utc());
    record.analyst_note = note;
    if !state
        .remediations
        .update(&record, revision)
        .await
        .map_err(storage)?
    {
        return Err(conflict("remediation changed concurrently; reload"));
    }
    Ok(record)
}
pub async fn request_verification(
    state: &AppState,
    id: Uuid,
    request_id: Uuid,
) -> Result<RemediationRecord, Error> {
    if request_id.is_nil() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "request_id must be nonzero".into(),
        ));
    }
    let mut record = get(state, id).await?;
    if record.attempts.iter().any(|a| a.request_id == request_id) {
        return Ok(record);
    }
    if record.applied_at.is_none() || record.state == RemediationState::Verifying {
        return Err(conflict(
            "mark the change applied before requesting verification; only one verification may run",
        ));
    }
    let asset = state
        .assets
        .find_by_id(record.asset_id)
        .await
        .map_err(storage)?
        .ok_or((StatusCode::NOT_FOUND, "asset not found".into()))?;
    if crate::probes::authorized_asset_target(&asset, &state.probe_config.to_scope()).is_none() {
        return Err((
            StatusCode::FORBIDDEN,
            "no authorized probe target for asset".into(),
        ));
    }
    let revision = record.revision;
    record.revision += 1;
    record.state = RemediationState::Verifying;
    let probe_id = Uuid::new_v4();
    record.attempts.push(RemediationAttempt {
        request_id,
        probe_id,
        requested_at: OffsetDateTime::now_utc(),
        completed_at: None,
        outcome: None,
        explanation: "Authorized transport verification requested".into(),
        after: None,
    });
    if !state
        .remediations
        .update(&record, revision)
        .await
        .map_err(storage)?
    {
        return Err(conflict("remediation changed concurrently; reload"));
    }
    if let Err(error) = crate::probes::schedule_remediation_probe(state, &record, probe_id).await {
        let revision = record.revision;
        record.revision += 1;
        record.state = RemediationState::Inconclusive;
        let attempt = record.attempts.last_mut().expect("attempt appended");
        attempt.completed_at = Some(OffsetDateTime::now_utc());
        attempt.outcome = Some(RemediationState::Inconclusive);
        attempt.explanation = format!("No network verification started: {}", error.1);
        state
            .remediations
            .update(&record, revision)
            .await
            .map_err(storage)?;
        return Err(error);
    }
    Ok(record)
}

pub async fn complete_probe(state: &AppState, probe: &ProbeRun) -> Result<(), StorageError> {
    let Some(id) = probe.remediation_id else {
        return Ok(());
    };
    for _ in 0..3 {
        let Some(mut record) = state.remediations.find_by_id(id).await? else {
            return Err(StorageError::NotFound(id.to_string()));
        };
        let Some(index) = record.attempts.iter().position(|a| a.probe_id == probe.id) else {
            return Err(StorageError::Conflict(
                "probe is not a remediation attempt".into(),
            ));
        };
        if record.attempts[index].completed_at.is_none() {
            let (outcome, explanation) = verify_remediation(&record, probe);
            let revision = record.revision;
            record.revision += 1;
            let attempt = &mut record.attempts[index];
            attempt.outcome = Some(outcome);
            attempt.completed_at = probe.finished_at;
            attempt.explanation = explanation;
            attempt.after = Some(probe.clone());
            record.state = outcome;
            if !state.remediations.update(&record, revision).await? {
                continue;
            }
        }
        let attempt = &record.attempts[index];
        if let (Some(inv_id), Some(outcome), Some(at)) = (
            record.investigation_id,
            attempt.outcome,
            attempt.completed_at,
        ) {
            let label = RemediationTrainingOutcome {
                remediation_id: id,
                request_id: attempt.request_id,
                probe_id: probe.id,
                rule_id: record.finding.rule_id.clone(),
                outcome,
                verified_at: at,
            };
            for training in state
                .training
                .list_recent(Some(inv_id), Some(record.asset_id), 100_000)
                .await?
            {
                if training.captured_at.unix_timestamp_nanos() / 1000
                    == record.before.last_seen.unix_timestamp_nanos() / 1000
                    && training.features.tls.protocol == record.before.protocol
                    && training.features.tls.port == record.before.flow.dst_port
                    && training
                        .features
                        .policy
                        .iter()
                        .any(|f| f.rule_id == label.rule_id)
                {
                    state
                        .training
                        .attach_remediation_outcome(training.id, &label)
                        .await?;
                }
            }
        }
        return Ok(());
    }
    Err(StorageError::Conflict(
        "remediation update contention".into(),
    ))
}

pub async fn recover(state: &AppState) -> Result<(), StorageError> {
    for mut record in state.remediations.list_verifying().await? {
        let Some(attempt) = record.attempts.last() else {
            continue;
        };
        if let Some(probe) = state.probes.find_by_id(attempt.probe_id).await? {
            if probe.finished_at.is_some() {
                complete_probe(state, &probe).await?;
            }
        } else if OffsetDateTime::now_utc() - attempt.requested_at > time::Duration::seconds(30) {
            let revision = record.revision;
            record.revision += 1;
            record.state = RemediationState::Inconclusive;
            let attempt = record.attempts.last_mut().expect("attempt checked");
            attempt.completed_at = Some(OffsetDateTime::now_utc());
            attempt.outcome = Some(RemediationState::Inconclusive);
            attempt.explanation =
                "Core stopped before a probe could be scheduled; no fix established".into();
            state.remediations.update(&record, revision).await?;
        }
    }
    Ok(())
}
