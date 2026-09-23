use mailent_domain::IntelligenceRefreshStatus;
use std::time::Duration as StdDuration;
use time::{Duration, OffsetDateTime};
use tracing::{debug, error, info, warn};

use crate::state::AppState;

/// Spawns a background worker that periodically polls for domain intelligence refreshes.
pub fn start_intelligence_refresh_scheduler(state: AppState) {
    tokio::spawn(async move {
        info!("Starting external intelligence background refresh scheduler");
        // Initial delay before first sweep
        tokio::time::sleep(StdDuration::from_secs(5)).await;

        loop {
            if let Err(e) = run_refresh_cycle(&state).await {
                error!("Error in intelligence refresh cycle: {e}");
            }
            tokio::time::sleep(StdDuration::from_secs(60)).await;
        }
    });
}

/// Executes one pass of checking and refreshing due domain intelligence.
pub async fn run_refresh_cycle(
    state: &AppState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 1. Discover any active assets that don't yet have an intelligence refresh scheduled
    if let Ok(assets) = state.assets.list_all().await {
        for asset in assets {
            for host in &asset.hostnames {
                if let Ok(None) = state.intelligence.get_refresh_status(host).await {
                    let initial_status = IntelligenceRefreshStatus {
                        domain: host.clone(),
                        last_checked: None,
                        next_check: Some(OffsetDateTime::now_utc()),
                        last_success: None,
                        last_error: None,
                    };
                    let _ = state
                        .intelligence
                        .save_refresh_status(&initial_status)
                        .await;
                }
            }
        }
    }

    // 2. Fetch list of domains due for refresh
    let due_domains = state.intelligence.list_due_refreshes().await?;
    if due_domains.is_empty() {
        debug!("No domain intelligence refreshes currently due");
        return Ok(());
    }

    info!(
        count = due_domains.len(),
        "Processing due domain intelligence refreshes"
    );

    for domain in due_domains {
        refresh_domain_intelligence(state, &domain).await;
    }

    Ok(())
}

/// Refreshes MX, TLSA, MTA-STS, TLS-RPT, and CT intelligence for a single domain.
pub async fn refresh_domain_intelligence(state: &AppState, domain: &str) {
    let now = OffsetDateTime::now_utc();
    debug!(domain = %domain, "Refreshing domain intelligence");

    let mut had_error = false;
    let mut err_msg = None;

    // 1. MX Records
    let mx_records = match state.intelligence_resolver.fetch_mx(domain).await {
        Ok(records) => {
            if let Err(e) = state.intelligence.save_mx_records(domain, &records).await {
                warn!("Failed to save MX records for {domain}: {e}");
            }
            records
        }
        Err(e) => {
            had_error = true;
            err_msg = Some(format!("MX fetch error: {e}"));
            Vec::new()
        }
    };

    // 2. TLSA Records for MX hosts
    for mx in &mx_records {
        match state
            .intelligence_resolver
            .fetch_tlsa(&mx.hostname, 25)
            .await
        {
            Ok(tlsa) => {
                if !tlsa.is_empty() {
                    let _ = state
                        .intelligence
                        .save_tlsa_records(&mx.hostname, &tlsa)
                        .await;
                }
            }
            Err(e) => {
                debug!("TLSA fetch error for {}: {e}", mx.hostname);
            }
        }
    }

    // Also fetch TLSA for the domain itself
    if let Ok(tlsa) = state.intelligence_resolver.fetch_tlsa(domain, 25).await
        && !tlsa.is_empty()
    {
        let _ = state.intelligence.save_tlsa_records(domain, &tlsa).await;
    }

    // 3. MTA-STS Policy
    match state.intelligence_resolver.fetch_mta_sts(domain).await {
        Ok(Some(policy)) => {
            let _ = state.intelligence.save_mta_sts_policy(&policy).await;
        }
        Ok(None) => {}
        Err(e) => {
            debug!("MTA-STS fetch error for {domain}: {e}");
        }
    }

    // 4. TLS-RPT Policy
    match state
        .intelligence_resolver
        .fetch_tls_rpt_policy(domain)
        .await
    {
        Ok(Some(policy)) => {
            let _ = state.intelligence.save_tls_rpt_policy(&policy).await;
        }
        Ok(None) => {}
        Err(e) => {
            debug!("TLS-RPT fetch error for {domain}: {e}");
        }
    }

    // 5. Certificate Transparency
    match state
        .intelligence_resolver
        .fetch_ct_certificates(domain)
        .await
    {
        Ok(certs) => {
            if !certs.is_empty() {
                let existing = state
                    .intelligence
                    .get_ct_certificates(domain)
                    .await
                    .unwrap_or_default();
                let _ = state
                    .intelligence
                    .save_ct_certificates(domain, &certs)
                    .await;

                for cert in &certs {
                    let events = mailent_integrations::evaluate_ct_certificate_event(
                        cert,
                        &existing,
                        &[],
                        false,
                    );
                    for event in events {
                        let _ = state.intelligence.save_ct_event(&event).await;
                    }
                }
            }
        }
        Err(e) => {
            debug!("CT certificates fetch error for {domain}: {e}");
        }
    }

    // Update refresh status
    let next_check = if had_error {
        now + Duration::hours(1) // Backoff on error
    } else {
        now + Duration::hours(24) // 24h refresh cycle
    };

    let status = IntelligenceRefreshStatus {
        domain: domain.to_string(),
        last_checked: Some(now),
        next_check: Some(next_check),
        last_success: if had_error { None } else { Some(now) },
        last_error: err_msg,
    };

    let _ = state.intelligence.save_refresh_status(&status).await;
}

/// Spawns a background worker that periodically evaluates verification freshness
/// and schedules re-verification probes for stale or drift-affected authorized targets.
pub fn start_verification_scheduler(state: AppState) {
    tokio::spawn(async move {
        info!("Starting scheduled active reverification worker");
        tokio::time::sleep(StdDuration::from_secs(10)).await;

        loop {
            if let Err(e) = run_verification_cycle(&state).await {
                error!("Error in verification schedule cycle: {e}");
            }
            tokio::time::sleep(StdDuration::from_secs(60)).await;
        }
    });
}

pub async fn run_verification_cycle(
    state: &AppState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let assets = state.assets.list_all().await?;
    let now = OffsetDateTime::now_utc();

    for asset in assets {
        let authorized_target =
            crate::probes::authorized_asset_target(&asset, &state.probe_config.to_scope());
        if authorized_target.is_none() {
            continue;
        }

        let probes = state.probes.list_for_asset(asset.id, 20).await?;
        let drift_events = state.assets.list_drift_events(Some(asset.id), 20).await?;

        let verification = mailent_domain::probe::AssetVerificationState::evaluate(
            asset.id,
            authorized_target.clone(),
            &probes,
            &drift_events,
            now,
        );

        if verification.freshness == mailent_domain::VerificationFreshness::Stale {
            // Consecutive failure backoff: if failing repeatedly (>= 3 consecutive failures),
            // do not spam failing target; require at least 6 hours since last attempt
            if verification.consecutive_failures >= 3
                && let Some(last_probe) = probes.first()
                && (now - last_probe.started_at).whole_seconds() < 6 * 3600
            {
                continue;
            }

            let trigger = if verification.drift_detected_since_verification {
                mailent_domain::ProbeTrigger::DriftTriggered
            } else {
                mailent_domain::ProbeTrigger::Scheduled
            };

            let req = mailent_domain::ProbeRequest {
                protocol: Some(mailent_domain::EmailProtocol::Smtp),
                port: Some(25),
                trigger: Some(trigger.clone()),
                investigation_id: None,
            };

            // schedule_probe handles allowlist scope, bounded concurrency semaphore, cooldown, and inflight deduplication
            match crate::probes::schedule_probe(state, asset.id, req).await {
                Ok(probe_id) => {
                    info!(asset_id = %asset.id, %probe_id, ?trigger, "Scheduled reverification probe initiated");
                }
                Err((status, msg)) => {
                    debug!(asset_id = %asset.id, %status, %msg, "Reverification probe skipped");
                }
            }
        }
    }

    Ok(())
}

/// Spawns a background worker that polls due infrastructure monitors, manages bounded
/// concurrency, recovers expired leases, and dispatches jobs to agents or executes Cloud jobs.
pub fn start_infrastructure_monitoring_scheduler(state: AppState) {
    tokio::spawn(async move {
        info!("Starting scheduled infrastructure monitoring scheduler");
        tokio::time::sleep(StdDuration::from_secs(5)).await;

        loop {
            if let Err(e) = run_monitoring_cycle(&state).await {
                error!("Error in infrastructure monitoring cycle: {e}");
            }
            tokio::time::sleep(StdDuration::from_secs(10)).await;
        }
    });
}

/// Executes one pass of monitoring: recovers expired leases, discovers due monitors,
/// enforces bounded concurrency, enqueues agent jobs, and processes cloud jobs.
pub async fn run_monitoring_cycle(
    state: &AppState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let now = OffsetDateTime::now_utc();

    // 1. Expiration recovery: reclaim expired leases
    let recovered = state.jobs.recover_expired_leases(now).await?;
    if recovered > 0 {
        info!(recovered, "Recovered expired agent job leases");
    }

    // 2. Discover due monitors
    let due_monitors = state.monitors.find_due_monitors(now, 20).await?;
    for mut monitor in due_monitors {
        let org_id = monitor.organization_id;

        // Bounded concurrency per org (max 5 active jobs)
        let active_org_jobs = state.jobs.count_active_for_org(org_id).await.unwrap_or(0);
        if active_org_jobs >= 5 {
            debug!(org_id = %org_id, "Max active jobs reached for org; deferring monitor");
            continue;
        }

        // Bounded concurrency per agent (max 1 active job per agent)
        let target_agent_id = match monitor.execution_target {
            mailent_domain::MonitorExecutionTarget::Cloud => None,
            mailent_domain::MonitorExecutionTarget::Agent(agent_id) => {
                let active_agent_jobs = state
                    .jobs
                    .count_active_for_agent(agent_id)
                    .await
                    .unwrap_or(0);
                if active_agent_jobs >= 1 {
                    debug!(agent_id = %agent_id, "Agent already busy; deferring monitor");
                    continue;
                }
                Some(agent_id)
            }
        };

        // Deduplication via idempotency key: one run per monitor scheduled time slot
        let idempotency_key = format!(
            "monitor-{}-{}",
            monitor.id,
            monitor.next_run_at.unix_timestamp()
        );

        if let Ok(Some(_)) = state
            .jobs
            .find_by_idempotency_key(org_id, &idempotency_key)
            .await
        {
            // Already created a job for this slot
            continue;
        }

        // Advance monitor schedule
        monitor.next_run_at = monitor.cadence.next_run_after(now);
        monitor.updated_at = now;
        let _ = state.monitors.save(&monitor).await;

        // Enqueue the job
        let job = mailent_domain::AgentJob::new_infrastructure_assessment(
            org_id,
            monitor.domain.clone(),
            120,
            target_agent_id,
            Some(idempotency_key),
            Some(monitor.id),
        );

        state.jobs.create_job(&job).await?;
        info!(
            job_id = %job.id,
            domain = %monitor.domain,
            target = ?monitor.execution_target,
            "Enqueued scheduled infrastructure assessment job"
        );
    }

    // 3. Process pending Cloud jobs
    while let Ok(Some(job)) = state.jobs.lease_next_cloud_job(now, 300).await {
        let state_clone = state.clone();
        tokio::spawn(async move {
            execute_cloud_job(state_clone, job).await;
        });
    }

    Ok(())
}

/// Executes a leased Cloud-targeted infrastructure assessment job directly within Mailent Core.
pub async fn execute_cloud_job(state: AppState, mut job: mailent_domain::AgentJob) {
    let now = OffsetDateTime::now_utc();
    job.state = mailent_domain::JobState::Running;
    job.started_at = Some(now);
    let _ = state.jobs.update_job(&job).await;

    let domain = match &job.job_type {
        mailent_domain::AgentJobType::InfrastructureAssessment { domain, .. } => domain.clone(),
        _ => {
            job.state = mailent_domain::JobState::Failed;
            job.last_error = Some("Unsupported cloud job type".into());
            job.completed_at = Some(OffsetDateTime::now_utc());
            let _ = state.jobs.update_job(&job).await;
            return;
        }
    };

    info!(job_id = %job.id, domain = %domain, "Executing cloud-targeted infrastructure scan");

    let scanner_res = mailent_scanner::DomainScanner::new_live();
    let scanner = match scanner_res {
        Ok(s) => s,
        Err(e) => {
            let err_msg = format!("Failed to initialize DomainScanner: {e}");
            job.state = mailent_domain::JobState::Failed;
            job.last_error = Some(err_msg.clone());
            job.completed_at = Some(OffsetDateTime::now_utc());
            let _ = state.jobs.update_job(&job).await;
            if let Some(monitor_id) = job.monitor_id {
                if let Ok(Some(mut monitor)) = state.monitors.find_by_id(monitor_id).await {
                    monitor.last_run_at = Some(now);
                    monitor.last_failure_at = Some(now);
                    monitor.last_error = Some(err_msg);
                    monitor.updated_at = OffsetDateTime::now_utc();
                    let _ = state.monitors.save(&monitor).await;
                }
            }
            return;
        }
    };

    match scanner.scan_domain(&domain).await {
        Ok(scan_result) => {
            let assessment = scan_result
                .assessment
                .with_organization(job.organization_id);
            let assessment_id = assessment.id;

            // Save assessment
            let _ = state.assessments.save(&assessment).await;

            let current_findings = scan_result.findings.clone();
            for f in &current_findings {
                let _ = state.findings.save(f.clone()).await;
            }

            // Check for domain drift against prior infrastructure assessment
            if let Ok(summaries) = state.assessments.list_for_org(job.organization_id).await {
                let prior_summary = summaries
                    .into_iter()
                    .filter(|s| {
                        s.source_type == "infrastructure"
                            && s.target == domain
                            && s.id != assessment_id
                    })
                    .max_by_key(|s| s.created_at);

                if let Some(prior_s) = prior_summary {
                    if let Ok(Some(prior_rec)) = state
                        .assessments
                        .find_by_id_scoped(prior_s.id, job.organization_id)
                        .await
                    {
                        let mut prior_findings = Vec::new();
                        for fid in &prior_rec.finding_ids {
                            if let Ok(Some(f)) = state.findings.find_by_id(*fid).await {
                                prior_findings.push(f);
                            }
                        }

                        let drift_events = mailent_correlation::drift::InfrastructureDriftCorrelator::compare_assessments(
                            &prior_rec,
                            &assessment,
                            &prior_findings,
                            &current_findings,
                        );

                        let regressions = mailent_correlation::drift::InfrastructureDriftCorrelator::extract_security_regressions(&drift_events, &current_findings);

                        if !regressions.is_empty() {
                            info!(
                                domain = %domain,
                                regressions_count = regressions.len(),
                                "Security regressions detected in scheduled cloud scan"
                            );
                            crate::integrations::notify_event(
                                &state,
                                crate::integrations::EventNotification::new(
                                    mailent_domain::IntegrationEventType::SecurityRegressionDetected,
                                    format!("Security regression on {domain}"),
                                    format!(
                                        "Detected {} security regression(s) during scheduled scan.",
                                        regressions.len()
                                    ),
                                )
                                .with_details(serde_json::json!({
                                    "domain": domain,
                                    "regressions": regressions,
                                    "assessment_id": assessment_id,
                                })),
                            );
                        } else if !drift_events.is_empty() {
                            info!(
                                domain = %domain,
                                drift_count = drift_events.len(),
                                "Infrastructure drift detected in scheduled cloud scan"
                            );
                            crate::integrations::notify_event(
                                &state,
                                crate::integrations::EventNotification::new(
                                    mailent_domain::IntegrationEventType::InfrastructureDriftDetected,
                                    format!("Infrastructure drift on {domain}"),
                                    format!(
                                        "Detected {} configuration change(s) during scheduled scan.",
                                        drift_events.len()
                                    ),
                                )
                                .with_details(serde_json::json!({
                                    "domain": domain,
                                    "drift_events": drift_events,
                                    "assessment_id": assessment_id,
                                })),
                            );
                        }

                        // Create or enrich investigation if meaningful regressions exist
                        let _ = crate::api::agent::sync_infrastructure_investigation(
                            &state,
                            &assessment,
                            &domain,
                            &drift_events,
                            &current_findings,
                            now,
                        )
                        .await;
                    }
                }
            }

            // Update monitor if linked
            if let Some(monitor_id) = job.monitor_id {
                if let Ok(Some(mut monitor)) = state.monitors.find_by_id(monitor_id).await {
                    let finish_time = OffsetDateTime::now_utc();
                    monitor.last_run_at = Some(finish_time);
                    monitor.last_success_at = Some(finish_time);
                    monitor.last_assessment_id = Some(assessment_id);
                    monitor.updated_at = finish_time;
                    let _ = state.monitors.save(&monitor).await;
                }
            }

            // Mark job completed
            job.state = mailent_domain::JobState::Completed;
            job.completed_at = Some(OffsetDateTime::now_utc());
            job.result_assessment_id = Some(assessment_id);
            let _ = state.jobs.update_job(&job).await;
            info!(job_id = %job.id, assessment_id = %assessment_id, "Cloud infrastructure scan completed successfully");
        }
        Err(e) => {
            let err_msg = format!("Cloud scan failed: {e}");
            warn!(job_id = %job.id, error = %err_msg, "Cloud infrastructure scan failed");
            job.state = mailent_domain::JobState::Failed;
            job.last_error = Some(err_msg.clone());
            job.completed_at = Some(OffsetDateTime::now_utc());
            let _ = state.jobs.update_job(&job).await;

            if let Some(monitor_id) = job.monitor_id {
                if let Ok(Some(mut monitor)) = state.monitors.find_by_id(monitor_id).await {
                    let finish_time = OffsetDateTime::now_utc();
                    monitor.last_run_at = Some(finish_time);
                    monitor.last_failure_at = Some(finish_time);
                    monitor.last_error = Some(err_msg);
                    monitor.updated_at = finish_time;
                    let _ = state.monitors.save(&monitor).await;
                }
            }
        }
    }
}
