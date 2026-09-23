//! Practical Crypto Digital Twin simulation engine.
//!
//! Replays historical network sessions against hypothetical stronger policies
//! using the deterministic rule engine. Never mutates real findings, assets,
//! or production configuration.
use axum::http::StatusCode;
use mailent_domain::{
    AssetCompatibility, AssetSimulationResult, BreakageSummary, FindingSeverity,
    PolicySimulationRequest, PolicySimulationResult, SimulationBreakage,
};
use mailent_policy::PolicyPack;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::state::AppState;

/// Lightweight summary of an available policy pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPackSummary {
    pub name: String,
    pub version: String,
    pub title: String,
    pub description: String,
    pub rule_count: usize,
    pub rules_count: usize,
    pub require_pfs: bool,
    pub require_mta_sts: bool,
    pub require_dane: bool,
    pub rules: Vec<PolicyRuleSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRuleSummary {
    pub id: String,
    pub title: String,
    pub severity: FindingSeverity,
    pub description: String,
    pub remediation: String,
    pub reference: String,
}

impl PolicyPackSummary {
    pub fn from_pack(pack: &PolicyPack) -> Self {
        let title = match pack.name.as_str() {
            "modern" => "Modern Baseline".to_string(),
            "high-security" => "High Security Strict".to_string(),
            "permissive" => "Permissive Transport".to_string(),
            other => other.to_string(),
        };
        let require_pfs = pack
            .rules
            .iter()
            .any(|r| r.id == "FORWARD_SECRECY_MISSING" || r.id == "PFS_REQUIRED");
        let require_mta_sts = pack.rules.iter().any(|r| r.id.contains("MTA_STS"));
        let require_dane = pack.rules.iter().any(|r| r.id.contains("DANE"));

        Self {
            name: pack.name.clone(),
            version: pack.version.clone(),
            title,
            description: pack.description.clone(),
            rule_count: pack.rules.len(),
            rules_count: pack.rules.len(),
            require_pfs,
            require_mta_sts,
            require_dane,
            rules: pack
                .rules
                .iter()
                .map(|r| PolicyRuleSummary {
                    id: r.id.clone(),
                    title: r.title.clone(),
                    severity: r.severity,
                    description: r.description.clone(),
                    remediation: r.remediation.clone(),
                    reference: r.reference.clone(),
                })
                .collect(),
        }
    }
}

pub fn list_available_policies() -> Vec<PolicyPackSummary> {
    vec![
        PolicyPackSummary::from_pack(&PolicyPack::modern()),
        PolicyPackSummary::from_pack(&PolicyPack::high_security()),
        PolicyPackSummary::from_pack(&PolicyPack::legacy_compatible()),
    ]
}

pub fn get_policy_pack_by_name(name: &str) -> Option<PolicyPack> {
    match name.trim().to_ascii_lowercase().as_str() {
        "modern" => Some(PolicyPack::modern()),
        "high-security" | "high_security" => Some(PolicyPack::high_security()),
        "legacy-compatible" | "legacy_compatible" => Some(PolicyPack::legacy_compatible()),
        _ => None,
    }
}

pub async fn run_simulation(
    state: &AppState,
    req: PolicySimulationRequest,
) -> Result<PolicySimulationResult, (StatusCode, String)> {
    let policy = get_policy_pack_by_name(&req.policy_name).ok_or((
        StatusCode::BAD_REQUEST,
        format!(
            "Unknown policy pack '{}'. Available: modern, high-security, legacy-compatible",
            req.policy_name
        ),
    ))?;

    let assets = if req.target_asset_ids.is_empty() {
        state
            .assets
            .list_all()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    } else {
        let mut list = Vec::new();
        for id in &req.target_asset_ids {
            if let Some(asset) = state
                .assets
                .find_by_id(*id)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            {
                list.push(asset);
            }
        }
        list
    };

    let now = OffsetDateTime::now_utc();
    let lookback_cutoff = req
        .lookback_hours
        .map(|hours| now - time::Duration::hours(hours as i64));

    let mut asset_results = Vec::new();
    let mut breakage_map: HashMap<String, (String, String, usize, usize)> = HashMap::new(); // rule_id -> (deprecated_behavior, description, affected_assets, affected_sessions)
    let mut total_sessions_evaluated = 0;
    let mut compatible_assets_count = 0;
    let mut would_fail_assets_count = 0;
    let mut insufficient_evidence_assets_count = 0;

    for asset in assets {
        // Collect historical sessions for all known IP addresses of this asset
        let mut sessions = Vec::new();
        for addr in &asset.addresses {
            if let Ok(sess_list) = state.sessions.list_for_asset(addr, 500).await {
                sessions.extend(sess_list);
            }
        }

        // Deduplicate sessions by session_id
        let mut unique_sessions = HashMap::new();
        for s in sessions {
            unique_sessions.entry(s.session_id).or_insert(s);
        }
        let mut sessions: Vec<_> = unique_sessions.into_values().collect();

        // Apply lookback filter if present
        if let Some(cutoff) = lookback_cutoff {
            sessions.retain(|s| s.last_seen >= cutoff);
        }

        let evaluated_sessions_count = sessions.len();
        total_sessions_evaluated += evaluated_sessions_count;

        let primary_name = asset
            .primary_name
            .clone()
            .or_else(|| asset.hostnames.first().cloned())
            .unwrap_or_else(|| {
                asset
                    .addresses
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "Unknown asset".into())
            });

        if sessions.is_empty() {
            insufficient_evidence_assets_count += 1;
            asset_results.push(AssetSimulationResult {
                asset_id: asset.id,
                primary_name,
                addresses: asset.addresses.clone(),
                compatibility: AssetCompatibility::InsufficientEvidence,
                evaluated_sessions_count: 0,
                breakages: Vec::new(),
                explanation:
                    "No observed sessions recorded for this asset within the simulation window."
                        .into(),
            });
            continue;
        }

        let mut asset_breakages: HashMap<String, SimulationBreakage> = HashMap::new();
        let mut has_sufficient_evidence = false;

        for session in &sessions {
            // Evaluate deterministic rules under proposed policy
            let findings = mailent_policy::evaluator::evaluate(session, &policy);

            if session.tls_version.is_some() || session.certificate.is_some() {
                has_sufficient_evidence = true;
            }

            for finding in findings {
                let deprecated_behavior = match finding.rule_id.as_str() {
                    "TLS_MINIMUM_VERSION" | "TLS_LEGACY_VERSION" => {
                        format!(
                            "Negotiated {}",
                            session
                                .tls_version
                                .as_ref()
                                .map(ToString::to_string)
                                .unwrap_or_else(|| "legacy TLS".into())
                        )
                    }
                    "NO_FORWARD_SECRECY" => {
                        format!(
                            "Key exchange {:?}",
                            session
                                .key_exchange
                                .as_ref()
                                .unwrap_or(&mailent_domain::KeyExchange::RsaStatic)
                        )
                    }
                    "CERTIFICATE_EXPIRED" => "Expired X.509 leaf certificate presented".into(),
                    "STARTTLS_MISSING" => "STARTTLS not advertised in SMTP capabilities".into(),
                    _ => finding.description.clone(),
                };

                let entry = asset_breakages
                    .entry(finding.rule_id.clone())
                    .or_insert_with(|| SimulationBreakage {
                        rule_id: finding.rule_id.clone(),
                        severity: finding.severity,
                        title: finding.title.clone(),
                        description: finding.description.clone(),
                        remediation: finding.remediation.clone(),
                        deprecated_behavior: deprecated_behavior.clone(),
                        affected_sessions_count: 0,
                        sample_flow: session.flow.to_string(),
                    });
                entry.affected_sessions_count += 1;
            }
        }

        let breakages: Vec<SimulationBreakage> = asset_breakages.into_values().collect();

        // Update overall breakage summary map
        for b in &breakages {
            let entry = breakage_map
                .entry(b.rule_id.clone())
                .or_insert_with(|| (b.deprecated_behavior.clone(), b.description.clone(), 0, 0));
            entry.2 += 1; // assets count
            entry.3 += b.affected_sessions_count; // sessions count
        }

        let (compatibility, explanation) = if !breakages.is_empty() {
            would_fail_assets_count += 1;
            let failure_titles: Vec<&str> = breakages.iter().map(|b| b.title.as_str()).collect();
            (
                AssetCompatibility::WouldFail,
                format!(
                    "Would fail under '{}': {} policy violation(s) across {} session(s) ({})",
                    policy.name,
                    breakages.len(),
                    breakages
                        .iter()
                        .map(|b| b.affected_sessions_count)
                        .sum::<usize>(),
                    failure_titles.join(", ")
                ),
            )
        } else if has_sufficient_evidence {
            compatible_assets_count += 1;
            (
                AssetCompatibility::Compatible,
                format!(
                    "Fully compatible with '{}': all {} observed session(s) satisfy proposed requirements.",
                    policy.name, evaluated_sessions_count
                ),
            )
        } else {
            insufficient_evidence_assets_count += 1;
            (
                AssetCompatibility::InsufficientEvidence,
                format!(
                    "Insufficient cryptographic evidence: {} session(s) observed, but TLS handshake parameters were incomplete or unobserved.",
                    evaluated_sessions_count
                ),
            )
        };

        asset_results.push(AssetSimulationResult {
            asset_id: asset.id,
            primary_name,
            addresses: asset.addresses.clone(),
            compatibility,
            evaluated_sessions_count,
            breakages,
            explanation,
        });
    }

    let mut breakage_summaries: Vec<BreakageSummary> = breakage_map
        .into_iter()
        .map(
            |(
                rule_id,
                (deprecated_behavior, description, affected_assets_count, affected_sessions_count),
            )| {
                BreakageSummary {
                    rule_id,
                    deprecated_behavior,
                    affected_assets_count,
                    affected_sessions_count,
                    description,
                }
            },
        )
        .collect();
    breakage_summaries.sort_by_key(|b| std::cmp::Reverse(b.affected_sessions_count));

    // Sort assets: WouldFail first, then InsufficientEvidence, then Compatible
    asset_results.sort_by_key(|a| match a.compatibility {
        AssetCompatibility::WouldFail => 0,
        AssetCompatibility::InsufficientEvidence => 1,
        AssetCompatibility::Compatible => 2,
    });

    let total_assets = asset_results.len();

    Ok(PolicySimulationResult {
        id: Uuid::new_v4(),
        policy_name: policy.name,
        policy_version: policy.version,
        policy_description: policy.description,
        total_assets,
        compatible_assets_count,
        would_fail_assets_count,
        insufficient_evidence_assets_count,
        total_sessions_evaluated,
        breakage_summaries,
        asset_results,
        simulated_at: now,
    })
}
