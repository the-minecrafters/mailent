use mailent_domain::{
    AnomalySignal, Asset, CertificateRecord, EmailSession, Finding, FindingCategory,
    FindingSeverity, GuidanceKind, Investigation, InvestigationStatus, PostureCategory,
    PostureCategoryScore, PostureDeduction, PostureGrade, PostureSubjectKind, RemediationGuidance,
    SecurityPosture, TlsVersion, category_weight,
};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use uuid::Uuid;

/// Deterministic category mapping for every known finding rule ID.
/// Unknown rule IDs still map deterministically (to their finding category)
/// so new policy rules score without code changes.
fn rule_category(rule_id: &str, fallback: FindingCategory) -> PostureCategory {
    match rule_id {
        "TLS_LEGACY_VERSION"
        | "STARTTLS_NOT_ENFORCED"
        | "STARTTLS_MISSING"
        | "PLAINTEXT_SESSION" => PostureCategory::TransportSecurity,
        "CERTIFICATE_EXPIRED" | "CERTIFICATE_SELF_SIGNED" | "CERTIFICATE_WEAK_KEY" => {
            PostureCategory::CertificateHygiene
        }
        "NO_FORWARD_SECRECY" | "WEAK_CIPHER_SUITE" => PostureCategory::ProtocolConfiguration,
        _ => map_finding_category(fallback),
    }
}

fn map_finding_category(category: FindingCategory) -> PostureCategory {
    match category {
        FindingCategory::TlsConfiguration => PostureCategory::TransportSecurity,
        FindingCategory::Certificate => PostureCategory::CertificateHygiene,
        FindingCategory::ProtocolDowngrade => PostureCategory::ProtocolConfiguration,
        FindingCategory::AuthenticationExposed => PostureCategory::ProtocolConfiguration,
        FindingCategory::PolicyViolation => PostureCategory::AnomalyRiskContext,
    }
}

/// Deterministic deduction points per severity, per category score.
fn severity_deduction(severity: FindingSeverity) -> f32 {
    match severity {
        FindingSeverity::Critical => 70.0,
        FindingSeverity::High => 40.0,
        FindingSeverity::Medium => 20.0,
        FindingSeverity::Low => 8.0,
    }
}

/// Inputs assembled from Mailent's own stores; nothing is invented here.
#[derive(Debug, Clone, Default)]
pub struct PostureInput<'a> {
    pub findings: &'a [Finding],
    pub anomalies: &'a [AnomalySignal],
    pub asset: Option<&'a Asset>,
    pub asset_sessions: &'a [EmailSession],
    pub certificates: &'a [CertificateRecord],
    pub probe_runs: &'a [mailent_domain::ProbeRun],
    pub investigation: Option<&'a Investigation>,
}

struct CategoryBuilder {
    score: f32,
    rule_ids: Vec<String>,
    explanations: Vec<String>,
}

impl CategoryBuilder {
    fn new(base: f32) -> Self {
        Self {
            score: base,
            rule_ids: Vec::new(),
            explanations: Vec::new(),
        }
    }

    fn deduct(&mut self, rule_id: &str, points: f32, explanation: String) {
        self.score = (self.score - points).max(0.0);
        if !self.rule_ids.contains(&rule_id.to_string()) {
            self.rule_ids.push(rule_id.to_string());
        }
        self.explanations.push(explanation);
    }

    fn finish(self, category: PostureCategory) -> PostureCategoryScore {
        PostureCategoryScore {
            category,
            score: self.score,
            weight: category_weight(category),
            weighted_score: self.score * category_weight(category),
            finding_rule_ids: self.rule_ids,
            rationale: if self.explanations.is_empty() {
                format!("No {category} deductions; baseline score retained.")
            } else {
                format!("Deductions applied: {}.", self.explanations.join("; "))
            },
        }
    }
}

fn severity_order(severity: FindingSeverity) -> u8 {
    match severity {
        FindingSeverity::Critical => 3,
        FindingSeverity::High => 2,
        FindingSeverity::Medium => 1,
        FindingSeverity::Low => 0,
    }
}

/// Cap applied when serious findings would otherwise hide behind a high average.
/// A single Critical finding caps the composite at 25 (grade Critical); a High
/// caps at 60 (grade at most Moderate). Grades can therefore never read better
/// than the worst unremediated finding.
fn serious_finding_cap(findings: &[Finding]) -> Option<f32> {
    let mut cap: Option<f32> = None;
    for f in findings {
        let c = match f.severity {
            FindingSeverity::Critical => Some(25.0),
            FindingSeverity::High => Some(60.0),
            _ => None,
        };
        if let Some(c) = c {
            cap = Some(cap.map_or(c, |existing: f32| existing.min(c)));
        }
    }
    cap
}

/// Compute the deterministic, versioned security posture for a subject.
///
/// Identical evidence always yields an identical score, grade, deductions,
/// and UUID: the subject UUID and finding rule/ID set fully determine the
/// result (no wall-clock, no randomness, no Jev input).
pub fn compute_posture(
    subject_kind: PostureSubjectKind,
    subject_id: Uuid,
    input: &PostureInput<'_>,
) -> SecurityPosture {
    let mut transport = CategoryBuilder::new(100.0);
    let mut certificate = CategoryBuilder::new(100.0);
    let mut protocol = CategoryBuilder::new(100.0);
    let mut anomaly = CategoryBuilder::new(100.0);

    let mut deductions = Vec::new();
    let mut findings_by_severity: BTreeMap<u8, Vec<&Finding>> = BTreeMap::new();

    for finding in input.findings {
        findings_by_severity
            .entry(severity_order(finding.severity))
            .or_default()
            .push(finding);
    }

    // Most severe first for stable ordering of deductions/worst findings.
    let mut ordered: Vec<&Finding> = findings_by_severity
        .values()
        .rev()
        .flatten()
        .copied()
        .collect();

    ordered.sort_by_key(|f| (std::cmp::Reverse(f.severity), f.id));
    for finding in &ordered {
        let category = rule_category(&finding.rule_id, finding.category);
        let points = severity_deduction(finding.severity);
        let evidence_desc = finding
            .evidence
            .first()
            .map(|e| e.description.clone())
            .unwrap_or_else(|| finding.description.clone());

        let builder = match category {
            PostureCategory::TransportSecurity => &mut transport,
            PostureCategory::CertificateHygiene => &mut certificate,
            PostureCategory::ProtocolConfiguration => &mut protocol,
            PostureCategory::AnomalyRiskContext => &mut anomaly,
        };
        builder.deduct(
            &finding.rule_id,
            points,
            format!("{}: -{points:.0} ({})", finding.rule_id, finding.severity),
        );

        deductions.push(PostureDeduction {
            rule_id: finding.rule_id.clone(),
            finding_id: finding.id,
            severity: finding.severity,
            category,
            points,
            evidence_description: evidence_desc,
        });
    }

    // Anomaly context: anomalies are risk context, not deterministic policy
    // violations, so they weigh modestly and never claim to be findings.
    // Bounded so context never dominates deterministic policy findings.
    let anomaly_block = anomaly_context_score(input.anomalies);
    anomaly.score = (anomaly.score - anomaly_block.0).max(0.0);
    if !anomaly_block.1.is_empty() {
        for s in &anomaly_block.1 {
            if !anomaly.rule_ids.contains(s) {
                anomaly.rule_ids.push(s.clone());
            }
        }
        anomaly
            .explanations
            .push(format!("Anomaly signals: {}.", anomaly_block.2));
    }

    // Passive evidence context adjustments (deterministic, evidence-grounded):
    // STARTTLS behaviour across observed sessions informs transport score.
    if let Some(asset) = input.asset {
        let legacy_versions: Vec<&TlsVersion> = asset
            .tls_versions
            .iter()
            .filter(|v| v.is_legacy())
            .collect();
        if legacy_versions.is_empty() && !asset.tls_versions.is_empty() {
            transport.explanations.push(format!(
                "All observed TLS versions modern ({}).",
                asset
                    .tls_versions
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    let plaintext = input
        .asset_sessions
        .iter()
        .filter(|s| {
            s.starttls_state
                .is_some_and(|st| matches!(st, mailent_domain::StartTlsState::NotAdvertised))
        })
        .count();
    if plaintext > 0
        && !input
            .findings
            .iter()
            .any(|f| f.rule_id == "STARTTLS_MISSING")
    {
        transport.deduct(
            "STARTTLS_NOT_ENFORCED",
            15.0,
            format!("STARTTLS not advertised on {plaintext} observed session(s)"),
        );
    }

    // Certificate hygiene from observed certificate records (expiry windows).
    let now = input
        .asset_sessions
        .iter()
        .map(|s| s.last_seen)
        .chain(input.findings.iter().map(|f| f.last_seen))
        .chain(input.probe_runs.iter().filter_map(|p| p.finished_at))
        .chain(input.anomalies.iter().map(|a| a.observed_at))
        .chain(input.certificates.iter().map(|c| c.last_seen))
        .max()
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    for cert in input.certificates {
        let days_left = (cert.not_after - now).whole_days();
        if days_left < 0 {
            certificate.deduct(
                "CERTIFICATE_EXPIRED",
                0.0, // already deducted via findings when applicable
                format!(
                    "Certificate {} expired {} day(s) ago (observed validity).",
                    cert.subject, -days_left
                ),
            );
        } else if days_left <= 14 {
            certificate.explanations.push(format!(
                "Certificate {} expires in {days_left} day(s).",
                cert.subject
            ));
        }
    }

    // Anomalous probe evidence: confirmed perspective mismatches are risk context.
    for probe in input.probe_runs {
        if probe.has_mismatch
            && probe
                .perspective_mismatches
                .iter()
                .any(|m| m.kind == mailent_domain::MismatchKind::TlsVersion)
        {
            anomaly.deduct(
                "PERSPECTIVE_TLS_MISMATCH",
                8.0,
                "Active probe saw a different TLS version than passive observation".to_string(),
            );
        }
    }

    // Investigation status context: a resolved investigation signals human triage.
    if let Some(inv) = input.investigation
        && inv.status == InvestigationStatus::Resolved
    {
        anomaly
            .explanations
            .push("Related investigation resolved by analyst triage.".to_string());
    }

    let categories = vec![
        transport.finish(PostureCategory::TransportSecurity),
        certificate.finish(PostureCategory::CertificateHygiene),
        protocol.finish(PostureCategory::ProtocolConfiguration),
        anomaly.finish(PostureCategory::AnomalyRiskContext),
    ];

    let mut composite: f32 = categories.iter().map(|c| c.weighted_score).sum();

    let cap = serious_finding_cap(input.findings);
    let score_capped = cap.is_some_and(|c| composite > c);
    let pre_cap_score = composite;
    if let Some(c) = cap
        && composite > c
    {
        composite = c;
    }

    let worst_findings = ordered
        .iter()
        .take(3)
        .map(|f| f.rule_id.clone())
        .collect::<Vec<_>>();

    // Deterministic UUID: same subject + same finding set → same ID.
    let mut evidence_key = format!(
        "{:?}:{subject_id}:v{}",
        subject_kind,
        mailent_domain::POSTURE_SCORE_VERSION
    );
    for d in &deductions {
        evidence_key.push_str(&format!("|{}:{}", d.rule_id, d.finding_id));
    }
    for a in input.anomalies {
        evidence_key.push_str(&format!("|a:{}", a.id));
    }
    evidence_key
        .push_str(&serde_json::to_string(&categories).expect("finite posture scores serialize"));
    let id = Uuid::new_v5(&Uuid::NAMESPACE_OID, evidence_key.as_bytes());

    SecurityPosture {
        id,
        score_version: mailent_domain::POSTURE_SCORE_VERSION.to_string(),
        subject_kind,
        subject_id,
        score: composite,
        grade: PostureGrade::from_score(composite),
        score_capped,
        pre_cap_score,
        categories,
        deductions,
        worst_findings,
        findings_considered: ordered.len(),
        computed_at: now,
    }
}

// Helper for anomaly context: deterministic per-signal deduction points.
fn anomaly_context_score(anomalies: &[AnomalySignal]) -> (f32, Vec<String>, String) {
    let mut points: f32 = 0.0;
    let mut signals = Vec::new();
    for a in anomalies {
        let p = match a.signal.as_str() {
            "NewDaneMismatch" | "InternalExternalInconsistency" => 10.0,
            "StarttlsSuccessRateDrop" | "HandshakeFailureSpike" => 8.0,
            "UnseenTlsVersion" | "RareCipher" | "NewCtCertificate" => 4.0,
            _ => 3.0,
        };
        points += p;
        signals.push(a.signal.clone());
    }
    let total = points.min(30.0); // bounded so context never dominates policy findings
    (
        total,
        signals,
        format!(
            "{} signal(s) contributing -{total:.0} points",
            anomalies.len()
        ),
    )
}

/// Build evidence-grounded remediation and best-practice guidance.
///
/// Remediation entries map 1:1 onto observed findings and quote Mailent's
/// observed evidence; best-practice entries are distinct (`GuidanceKind::BestPractice`)
/// and never reference a finding, so remediation vs. hardening stays clearly separated.
pub fn build_guidance(
    _subject_id: Uuid,
    findings: &[Finding],
    asset: Option<&Asset>,
    sessions: &[EmailSession],
    anomalies: &[AnomalySignal],
    now: OffsetDateTime,
) -> Vec<RemediationGuidance> {
    let mut out = Vec::new();

    for finding in findings {
        let observed = finding
            .evidence
            .first()
            .map(|e| e.description.clone())
            .unwrap_or_else(|| finding.description.clone());

        let compat: Vec<String> = compatibility_caveats(finding, sessions);
        let (why, recommendation, recommended_state, verification) = remediation_facts(finding);

        out.push(RemediationGuidance {
            id: Uuid::new_v5(
                &Uuid::NAMESPACE_OID,
                format!("guidance:remediation:{}:{}", finding.id, finding.rule_id).as_bytes(),
            ),
            kind: GuidanceKind::Remediation,
            finding_id: Some(finding.id),
            rule_id: finding.rule_id.clone(),
            title: finding.title.clone(),
            observed,
            why_it_matters: why,
            recommendation,
            recommended_state,
            compatibility_caveats: compat,
            verification,
            evidence: finding.evidence.clone(),
            severity: finding.severity,
            category: finding.category,
            generated_at: now,
        });
    }

    // Best-practice guidance: contextual hardening for non-violating assets.
    for bp in best_practices(asset, sessions, anomalies, now) {
        out.push(bp);
    }

    out
}

fn remediation_facts(finding: &Finding) -> (String, String, String, String) {
    match finding.rule_id.as_str() {
        "STARTTLS_MISSING" => (
            "The captured SMTP endpoint did not offer a TLS upgrade.".into(),
            finding.remediation.clone(),
            "STARTTLS advertised and accepted, followed by an established TLS handshake.".into(),
            "Verify the same endpoint using an authorized SMTP STARTTLS probe; timeout or failed handshake is inconclusive.".into(),
        ),
        "TLS_LEGACY_VERSION" => (
            "Legacy TLS allows downgrade-adjacent attacks and fails modern compliance \
             baselines; TLS 1.0/1.1 are formally deprecated by RFC 8996."
                .to_string(),
            "Disable TLS 1.0/1.1 on the mail service and retain TLS 1.2/1.3 as required."
                .to_string(),
            "TLS 1.2 minimum, TLS 1.3 preferred; legacy protocol versions disabled.".to_string(),
            "After the change, run an active Mailent probe against the endpoint: it must \
             negotiate TLS 1.2+ and fail (or refuse) TLS 1.0/1.1 handshakes."
                .to_string(),
        ),
        "CERTIFICATE_EXPIRED" => (
            "Expired certificates break chain validation; peers may reject connections \
             or fall back to weaker trust decisions, exposing delivery to interception."
                .to_string(),
            "Renew and deploy a currently valid certificate issued by an authorized CA."
                .to_string(),
            "A valid, unexpired certificate whose SANs cover the mail hostname.".to_string(),
            "Run an active Mailent probe after deployment: it must present the renewed \
             certificate (new fingerprint) with hostname validation passing."
                .to_string(),
        ),
        "NO_FORWARD_SECRECY" => (
            "Static RSA key exchange means captured traffic can be decrypted later if the \
             private key ever leaks; forward secrecy eliminates that retrospective risk."
                .to_string(),
            "Enable ECDHE cipher suites (X25519 or P-256) or migrate the endpoint to TLS 1.3."
                .to_string(),
            "Only ephemeral key exchange (ECDHE/DHE or TLS 1.3) is negotiated.".to_string(),
            "Run an active Mailent probe: the negotiated key exchange must report forward \
             secrecy supported."
                .to_string(),
        ),
        _ => (
            finding.description.clone(),
            finding.remediation.clone(),
            format!(
                "State consistent with policy '{}' ({}).",
                finding.policy_name, finding.reference
            ),
            format!(
                "Re-observe the endpoint passively and, where authorized, run an active \
                 probe to confirm rule '{}' no longer matches.",
                finding.rule_id
            ),
        ),
    }
}

/// Compatibility caveats derived from Mailent's observed history, not generic tips.
fn compatibility_caveats(finding: &Finding, sessions: &[EmailSession]) -> Vec<String> {
    let mut out = Vec::new();
    match finding.rule_id.as_str() {
        "TLS_LEGACY_VERSION" => {
            let legacy_peers: Vec<String> = sessions
                .iter()
                .filter(|s| s.tls_version.as_ref().is_some_and(|v| v.is_legacy()))
                .map(|s| s.flow.src_ip.clone())
                .collect();
            if !legacy_peers.is_empty() {
                let mut unique = legacy_peers.clone();
                unique.sort();
                unique.dedup();
                out.push(format!(
                    "Observed compatibility: {} historical peer(s) negotiated legacy TLS \
                     (e.g. {}). Disabling TLS 1.0/1.1 may break delivery for them; stage the \
                     change and monitor for connection failures after rollout.",
                    unique.len(),
                    unique
                        .iter()
                        .take(3)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
        "NO_FORWARD_SECRECY" => {
            let rsa_clients: Vec<String> = sessions
                .iter()
                .filter(|s| matches!(s.key_exchange, Some(mailent_domain::KeyExchange::RsaStatic)))
                .map(|s| s.flow.src_ip.clone())
                .collect();
            if !rsa_clients.is_empty() {
                let mut unique = rsa_clients.clone();
                unique.sort();
                unique.dedup();
                out.push(format!(
                    "Observed compatibility: {} peer(s) currently negotiate static RSA. \
                     Very old clients may fail after ECDHE-only enforcement; verify which \
                     peers still require it before disabling.",
                    unique.len()
                ));
            }
        }
        _ => {}
    }
    out
}

/// Best-practice guidance is hardening advice for assets that are NOT currently
/// in violation of the matched rule — kept structurally distinct from remediation.
fn best_practices(
    asset: Option<&Asset>,
    sessions: &[EmailSession],
    anomalies: &[AnomalySignal],
    now: OffsetDateTime,
) -> Vec<RemediationGuidance> {
    let mut out = Vec::new();
    let subject = asset.map(|a| a.id).unwrap_or_else(Uuid::nil);
    let label = asset
        .and_then(|a| a.hostname().map(str::to_string))
        .unwrap_or_else(|| "asset".to_string());

    // 1. TLS 1.3 not yet observed on any endpoint → encourage enabling it.
    let has_tls13 = sessions
        .iter()
        .any(|s| matches!(s.tls_version, Some(TlsVersion::Tls13)))
        || asset.is_some_and(|a| {
            a.tls_versions
                .iter()
                .any(|v| matches!(v, TlsVersion::Tls13))
        });
    if !has_tls13 {
        out.push(guidance_bp(
            subject,
            &label,
            "BP_ENABLE_TLS13",
            "TLS 1.3 not observed on this asset",
            format!(
                "Mailent has not observed a TLS 1.3 handshake on {label}. TLS 1.2 remains \
                 acceptable, but TLS 1.3 removes legacy cipher negotiation and completes \
                 handshakes in fewer round trips."
            ),
            "Enable TLS 1.3 alongside TLS 1.2 on the mail service; keep TLS 1.2 for \
             compatibility until peers no longer require it."
                .to_string(),
            now,
        ));
    }

    // 2. MTA-STS: no anomaly signals about MTA-STS and no enforced policy seen → suggest it.
    let mta_sts_mentioned = anomalies
        .iter()
        .any(|a| a.signal.contains("MtaSts") || a.signal.contains("Dane"));
    if !mta_sts_mentioned {
        out.push(guidance_bp(
            subject,
            &label,
            "BP_MTA_STS_DANE",
            "No MTA-STS/DANE posture signals recorded",
            format!(
                "Mailent has no MTA-STS or DANE signals for {label}. This does not establish whether either policy is deployed; inspect existing intelligence before changing configuration."
            ),
            "Publish an MTA-STS policy (mode: enforce once validated) and DANE TLSA records \
             to make STARTTLS downgrade-resistant."
                .to_string(),
            now,
        ));
    }

    out
}

fn guidance_bp(
    subject: Uuid,
    label: &str,
    rule: &str,
    title: &str,
    observed: String,
    recommendation: String,
    now: OffsetDateTime,
) -> RemediationGuidance {
    RemediationGuidance {
        id: Uuid::new_v5(
            &Uuid::NAMESPACE_OID,
            format!("guidance:bestpractice:{subject}:{rule}").as_bytes(),
        ),
        kind: GuidanceKind::BestPractice,
        finding_id: None,
        rule_id: rule.to_string(),
        title: title.to_string(),
        observed,
        why_it_matters: format!(
            "Hardening {label} reduces exposure without implying an active violation."
        ),
        recommendation,
        recommended_state:
            "Hardened configuration adopted; Mailent observes the improved state passively."
                .to_string(),
        compatibility_caveats: vec![],
        verification: format!(
            "Verify passively: Mailent should observe the improved configuration on {label} within one observation window."
        ),
        evidence: vec![],
        severity: FindingSeverity::Low,
        category: FindingCategory::TlsConfiguration,
        generated_at: now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailent_domain::{
        EvidenceRef, FindingCategory, FindingSeverity, NetworkFlow, StartTlsState,
    };
    use time::Duration;

    fn sample_finding(rule_id: &str, severity: FindingSeverity) -> Finding {
        let now = OffsetDateTime::now_utc();
        Finding {
            id: Uuid::new_v5(&Uuid::NAMESPACE_OID, rule_id.as_bytes()),
            rule_id: rule_id.to_string(),
            policy_name: "modern".into(),
            policy_version: "1.0.0".into(),
            reference: "rfc8996".into(),
            severity,
            category: FindingCategory::TlsConfiguration,
            title: format!("Finding {rule_id}"),
            description: "desc".into(),
            remediation: "rem".into(),
            affected_count: 1,
            first_seen: now,
            last_seen: now,
            evidence: vec![EvidenceRef {
                session_id: None,
                observation_id: None,
                description: format!("Observed {rule_id}"),
            }],
            organization_id: None,
        }
    }

    fn empty_input<'a>() -> PostureInput<'a> {
        PostureInput::default()
    }

    #[test]
    fn posture_is_repeatable_for_identical_evidence() {
        let f = sample_finding("TLS_LEGACY_VERSION", FindingSeverity::Critical);
        let input = PostureInput {
            findings: std::slice::from_ref(&f),
            ..empty_input()
        };
        let subject = Uuid::new_v4();
        let a = compute_posture(PostureSubjectKind::Asset, subject, &input);
        let b = compute_posture(PostureSubjectKind::Asset, subject, &input);
        assert_eq!(a.id, b.id);
        assert_eq!(a.score, b.score);
        assert_eq!(a.grade, b.grade);
        assert_eq!(a.categories, b.categories);
    }

    #[test]
    fn score_changes_when_security_state_changes() {
        let subject = Uuid::new_v4();
        let clean = PostureInput::default();
        let clean_score = compute_posture(PostureSubjectKind::Asset, subject, &clean).score;

        let f = sample_finding("TLS_LEGACY_VERSION", FindingSeverity::Critical);
        let worse = PostureInput {
            findings: std::slice::from_ref(&f),
            ..empty_input()
        };
        let worse_score = compute_posture(PostureSubjectKind::Asset, subject, &worse).score;
        assert!(
            worse_score < clean_score,
            "adding a critical finding must lower the score ({worse_score} < {clean_score})"
        );
    }

    #[test]
    fn critical_finding_caps_score_below_good() {
        let f = sample_finding("TLS_LEGACY_VERSION", FindingSeverity::Critical);
        let input = PostureInput {
            findings: std::slice::from_ref(&f),
            ..empty_input()
        };
        let posture = compute_posture(PostureSubjectKind::Asset, Uuid::new_v4(), &input);
        assert!(posture.score_capped);
        assert!(posture.score <= 35.0, "capped score must be <= 35");
        assert_eq!(posture.grade, PostureGrade::Critical);
    }

    #[test]
    fn remediation_maps_to_finding_and_quotes_evidence() {
        let f = sample_finding("TLS_LEGACY_VERSION", FindingSeverity::Critical);
        let input = PostureInput {
            findings: std::slice::from_ref(&f),
            ..empty_input()
        };
        let subject = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        let guidance = build_guidance(subject, input.findings, None, &[], &[], now);
        let remediations: Vec<_> = guidance
            .iter()
            .filter(|g| g.kind == GuidanceKind::Remediation)
            .collect();
        assert_eq!(remediations.len(), 1, "one remediation per finding");
        let g = remediations[0];
        assert_eq!(g.finding_id, Some(f.id));
        assert_eq!(g.rule_id, "TLS_LEGACY_VERSION");
        assert!(g.observed.contains("TLS_LEGACY_VERSION"));
    }

    #[test]
    fn best_practice_is_distinct_from_remediation() {
        let now = OffsetDateTime::now_utc();
        let subject = Uuid::new_v4();
        let guidance = build_guidance(subject, &[], None, &[], &[], now);
        assert!(
            guidance
                .iter()
                .all(|g| g.kind == GuidanceKind::BestPractice)
        );
        assert!(guidance.iter().all(|g| g.finding_id.is_none()));
    }

    #[test]
    fn compatibility_context_included_when_legacy_peers_observed() {
        let now = OffsetDateTime::now_utc();
        let session = EmailSession {
            session_id: Uuid::new_v4(),
            sensor_id: "s".into(),
            provenance: mailent_domain::ObservationProvenance {
                source: "synthetic".into(),
                parser: "fixture".into(),
                parser_version: "1".into(),
            },
            flow: NetworkFlow {
                src_ip: "198.51.100.7".into(),
                src_port: 1,
                dst_ip: "203.0.113.9".into(),
                dst_port: 25,
            },
            protocol: mailent_domain::EmailProtocol::Smtp,
            starttls_state: Some(StartTlsState::AdvertisedAndUsed),
            tls_version: Some(TlsVersion::Tls10),
            cipher_suite: None,
            key_exchange: None,
            certificate: None,
            capture: None,
            first_seen: now,
            last_seen: now,
        };
        let f = sample_finding("TLS_LEGACY_VERSION", FindingSeverity::Critical);
        let now2 = OffsetDateTime::now_utc();
        let guidance = build_guidance(Uuid::new_v4(), &[f], None, &[session], &[], now2);
        let remediation = guidance
            .iter()
            .find(|g| g.kind == GuidanceKind::Remediation)
            .expect("remediation entry");
        assert!(
            remediation
                .compatibility_caveats
                .iter()
                .any(|c| c.contains("1 historical peer"))
        );
    }

    #[test]
    fn anomaly_context_bounded_and_does_not_dominate() {
        let now = OffsetDateTime::now_utc();
        let anomalies = (0..5)
            .map(|_i| AnomalySignal {
                id: Uuid::new_v4(),
                asset_id: Uuid::new_v4(),
                signal: "StarttlsSuccessRateDrop".into(),
                title: "drop".into(),
                current_value: "0%".into(),
                baseline_value: "100%".into(),
                deviation: 1.0,
                confidence: 0.9,
                evidence: "e".into(),
                observed_at: now,
            })
            .collect::<Vec<_>>();
        let input = PostureInput {
            anomalies: &anomalies,
            ..empty_input()
        };
        let posture = compute_posture(PostureSubjectKind::Asset, Uuid::new_v4(), &input);
        let anomaly_cat = posture
            .categories
            .iter()
            .find(|c| c.category == PostureCategory::AnomalyRiskContext)
            .unwrap();
        assert!(anomaly_cat.score >= 70.0, "bounded anomaly deduction");
        // Composite should stay strong-ish: policy findings absent.
        assert!(posture.score >= 80.0);
    }

    #[test]
    fn jev_failure_does_not_affect_scoring() {
        // Posture computation takes no Jev/DecisionProvider input at all;
        // this test documents the contract: scoring is purely deterministic.
        let f = sample_finding("TLS_LEGACY_VERSION", FindingSeverity::Critical);
        let input = PostureInput {
            findings: std::slice::from_ref(&f),
            ..empty_input()
        };
        let subject = Uuid::new_v4();
        let a = compute_posture(PostureSubjectKind::Asset, subject, &input);
        let b = compute_posture(PostureSubjectKind::Asset, subject, &input);
        assert_eq!(a.score, b.score);
    }

    #[test]
    fn active_verification_suggested_after_remediation() {
        let f = sample_finding("CERTIFICATE_EXPIRED", FindingSeverity::High);
        let now = OffsetDateTime::now_utc();
        let guidance = build_guidance(Uuid::new_v4(), &[f], None, &[], &[], now);
        let g = &guidance[0];
        assert!(g.verification.contains("active Mailent probe"));
    }

    #[test]
    fn deterministic_uuids_stable_across_instances() {
        let f1 = sample_finding("TLS_LEGACY_VERSION", FindingSeverity::Critical);
        let f2 = sample_finding("TLS_LEGACY_VERSION", FindingSeverity::Critical);
        let subject = Uuid::new_v4();
        let a = compute_posture(
            PostureSubjectKind::Asset,
            subject,
            &PostureInput {
                findings: std::slice::from_ref(&f1),
                ..empty_input()
            },
        );
        let b = compute_posture(
            PostureSubjectKind::Asset,
            subject,
            &PostureInput {
                findings: std::slice::from_ref(&f2),
                ..empty_input()
            },
        );
        // sample_finding uses v5 UUID from rule id, so identical inputs agree.
        assert_eq!(a.id, b.id);
    }

    #[test]
    fn time_helpers_work() {
        let now = OffsetDateTime::now_utc();
        assert!((now + Duration::days(1)) > now);
    }
}
