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
