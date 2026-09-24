//! Export of the canonical [`ForensicReport`] to JSON, HTML, and PDF.
//!
//! All three formats render the same model; the HTML and PDF renderers are
//! deterministic (no timestamps, no randomness) so the same report produces
//! byte-identical output across runs.
use crate::model::{ForensicReport, Maybe, ProvenanceClass, UnavailableReason};
use mailent_domain::GuidanceKind;
use thiserror::Error;
use time::OffsetDateTime;

#[derive(Error, Debug)]
pub enum ReportError {
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("pdf assembly failed: {0}")]
    Pdf(String),
}

/// Export formats supported by Mailent forensic reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    Json,
    Html,
    Pdf,
}

impl ReportFormat {
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Html => "text/html; charset=utf-8",
            Self::Pdf => "application/pdf",
        }
    }

    pub fn file_extension(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Html => "html",
            Self::Pdf => "pdf",
        }
    }
}

fn fmt_time(t: OffsetDateTime) -> String {
    format!("{t}")
}

fn maybe_string(value: &Maybe<String>, reason: UnavailableReason) -> String {
    value
        .as_deref()
        .map(str::to_string)
        .unwrap_or_else(|| reason.render().to_string())
}

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// JSON export: canonical serialization of the report model.
pub fn to_json(report: &ForensicReport) -> Result<String, ReportError> {
    Ok(serde_json::to_string_pretty(report)?)
}

/// Shared renderer data used by both HTML and PDF output so they cannot drift.
struct SectionData {
    heading: String,
    provenance: ProvenanceClass,
    /// (label, value) rows; values already carry honest unavailability text.
    rows: Vec<(String, String)>,
    /// Free-text bullet lines.
    bullets: Vec<String>,
}

fn evidence_sections(report: &ForensicReport) -> Vec<SectionData> {
    let mut sections = Vec::new();

    // Mail Infrastructure & External Policies (when present)
    if let Some(infra) = &report.infrastructure {
        let mut rows = vec![
            ("Target domain".to_string(), infra.domain.clone()),
            ("DNSSEC state".to_string(), infra.dnssec_status.clone()),
            (
                "MX records".to_string(),
                if infra.mx_records.is_empty() {
                    "None discovered".to_string()
                } else {
                    infra.mx_records.join(", ")
                },
            ),
            (
                "MTA-STS policy".to_string(),
                infra
                    .mta_sts_mode
                    .as_deref()
                    .unwrap_or("Not published")
                    .to_string(),
            ),
            (
                "TLS-RPT destination".to_string(),
                infra
                    .tls_rpt_destination
                    .as_deref()
                    .unwrap_or("Not published")
                    .to_string(),
            ),
        ];
        if let Some(details) = &infra.mta_sts_policy_details {
            rows.push(("MTA-STS details".to_string(), details.clone()));
        }

        let mut bullets = Vec::new();
        for ep in &infra.discovered_endpoints {
            bullets.push(format!(
                "[{}] {}:{} (priority: {}) | STARTTLS: {} | TLS: {} | Cipher: {} | DANE: {}",
                ep.service,
                ep.host,
                ep.port,
                ep.priority
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "n/a".into()),
                ep.starttls_status,
                ep.tls_version.as_deref().unwrap_or("unavailable"),
                ep.cipher.as_deref().unwrap_or("unavailable"),
                ep.dane_status,
            ));
        }

        sections.push(SectionData {
            heading: format!("Mail Infrastructure & Policies: {}", infra.domain),
            provenance: ProvenanceClass::ObservedFact,
            rows,
            bullets,
        });
    }

    // Sessions & transport
    for session in &report.sessions {
        let mut rows = vec![
            ("Session".to_string(), session.session_id.to_string()),
            (
                "Protocol".to_string(),
                session.protocol_identification.clone(),
            ),
            ("Flow".to_string(), session.flow.clone()),
            (
                "STARTTLS".to_string(),
                if session.starttls_transitions.is_empty() {
                    UnavailableReason::NotCaptured.render().to_string()
                } else {
                    session.starttls_transitions.join(" → ")
                },
            ),
            (
                "TLS version".to_string(),
                maybe_string(&session.tls_version, UnavailableReason::NotCaptured),
            ),
            (
                "Cipher suite".to_string(),
                maybe_string(&session.cipher_suite, UnavailableReason::NotCaptured),
            ),
            (
                "Key exchange".to_string(),
                maybe_string(&session.key_exchange, UnavailableReason::NotCaptured),
            ),
            (
                "Forward secrecy".to_string(),
                maybe_string(&session.forward_secrecy, UnavailableReason::NotCaptured),
            ),
            ("Provenance".to_string(), session.provenance.clone()),
        ];
        if !session.gaps.is_empty() {
            rows.push(("Capture gaps".to_string(), session.gaps.join("; ")));
        }
        sections.push(SectionData {
            heading: format!("Session {}", session.flow),
            provenance: ProvenanceClass::ObservedFact,
            rows,
            bullets: session
                .timeline
                .iter()
                .map(|t| format!("{} {} ({})", fmt_time(t.timestamp), t.kind, t.source))
                .collect(),
        });
    }

    // Certificates
    for cert in &report.certificates {
        let mut rows = vec![
            ("Subject".to_string(), cert.subject.clone()),
            ("Issuer".to_string(), cert.issuer.clone()),
            ("SHA-256".to_string(), cert.sha256_fingerprint.clone()),
            (
                "Validity".to_string(),
                format!(
                    "{} → {} ({})",
                    cert.not_before
                        .map(fmt_time)
                        .unwrap_or_else(|| UnavailableReason::NotCaptured.render().to_string()),
                    cert.not_after
                        .map(fmt_time)
                        .unwrap_or_else(|| UnavailableReason::NotCaptured.render().to_string()),
                    cert.expiry_state
                ),
            ),
            (
                "SANs".to_string(),
                if cert.san.is_empty() {
                    UnavailableReason::NotCaptured.render().to_string()
                } else {
                    cert.san.join(", ")
                },
            ),
            (
                "Self-signed".to_string(),
                cert.is_self_signed
                    .map(|b| b.to_string())
                    .unwrap_or_else(|| UnavailableReason::NotCaptured.render().to_string()),
            ),
        ];
        if let Some(details) = &cert.crypto_details {
            rows.push(("Public key".to_string(), details.public_key_display()));
            rows.push((
                "Signature algorithm".to_string(),
                details.signature_algorithm_display(),
            ));
            rows.push((
                "Chain validation".to_string(),
                chain_display(details.chain_validation).to_string(),
            ));
            if let Some(len) = details.chain_length {
                rows.push(("Chain length".to_string(), len.to_string()));
            }
            if !details.extensions.key_usage.is_empty() {
                rows.push((
                    "Key usage".to_string(),
                    details.extensions.key_usage.join(", "),
                ));
            }
            if !details.extensions.extended_key_usage.is_empty() {
                rows.push((
                    "Extended key usage".to_string(),
                    details.extensions.extended_key_usage.join(", "),
                ));
            }
        } else {
            rows.push((
                "Public key / signature algorithm / chain".to_string(),
                UnavailableReason::NotCaptured.render().to_string(),
            ));
        }
        sections.push(SectionData {
            heading: format!("Certificate {}", cert.subject),
            provenance: cert.source,
            rows,
            bullets: vec![],
        });
    }

    for record in &report.remediation_lifecycle {
        sections.push(SectionData {
            heading: format!(
                "Remediation {} — {:?}",
                record.finding.rule_id, record.state
            ),
            provenance: ProvenanceClass::ActiveVerification,
            rows: vec![
                (
                    "Original policy finding (preserved)".into(),
                    format!("{}: {}", record.finding.id, record.finding.description),
                ),
                (
                    "Passive evidence session".into(),
                    record.before.session_id.to_string(),
                ),
                (
                    "Affected endpoint".into(),
                    format!(
                        "{}:{}",
                        record.before.flow.dst_ip, record.before.flow.dst_port
                    ),
                ),
                (
                    "Recommended action".into(),
                    record.guidance.recommendation.clone(),
                ),
                (
                    "Analyst note".into(),
                    record.analyst_note.clone().unwrap_or_else(|| "None".into()),
                ),
            ],
            bullets: record
                .attempts
                .iter()
                .map(|a| {
                    format!(
                        "Probe {} / request {} / completed {:?}: {:?}. {}",
                        a.probe_id, a.request_id, a.completed_at, a.outcome, a.explanation
                    )
                })
                .collect(),
        });
    }
    sections
}

fn chain_display(cv: mailent_domain::ChainValidation) -> &'static str {
    match cv {
        mailent_domain::ChainValidation::Verified => "verified against trust anchor",
        mailent_domain::ChainValidation::Failed => "FAILED",
        mailent_domain::ChainValidation::NotVerified => {
            UnavailableReason::RequiresActiveVerification.render()
        }
    }
}

fn guidance_rows(report: &ForensicReport, kind: GuidanceKind) -> Vec<(String, String, String)> {
    let list = match kind {
        GuidanceKind::Remediation => &report.remediation,
        GuidanceKind::BestPractice => &report.best_practices,
    };
    list.iter()
        .map(|g| {
            (
                format!("[{}] {}", g.severity, g.rule_id),
                format!(
                    "Observed: {}\nWhy it matters: {}\nChange: {}\nRecommended state: {}\nVerification: {}",
                    g.observed, g.why_it_matters, g.recommendation, g.recommended_state, g.verification
                ),
                g.compatibility_caveats.join("\n"),
            )
        })
        .collect()
}

const MAILENT_LOGO_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" width="36" height="36" role="img" aria-label="Mailent"><defs><clipPath id="mailent-body"><rect x="20" y="52" width="216" height="152" rx="40"/></clipPath></defs><rect x="20" y="52" width="216" height="152" rx="40" fill="#6366F1"/><path clip-path="url(#mailent-body)" fill="#A5B4FC" d="M-10 0 H266 V88 Q128 212 -10 88 Z"/><circle cx="94" cy="104" r="9" fill="#312E81"/><circle cx="162" cy="104" r="9" fill="#312E81"/><circle cx="200" cy="190" r="34" fill="#34D399" stroke="#6366F1" stroke-width="8"/><path d="M184 190 l11 11 l21 -23" fill="none" stroke="#fff" stroke-width="9" stroke-linecap="round" stroke-linejoin="round"/></svg>"##;

/// HTML export: standalone, self-contained document.
pub fn render_html(report: &ForensicReport) -> Result<String, ReportError> {
    let mut body = String::new();

    // Metadata header
    body.push_str("<section class=\"meta\">\n");
    body.push_str(&format!(
        "<div style=\"display:flex;align-items:center;gap:12px;margin-bottom:8px;\">{}<h1 style=\"margin:0;\">{}</h1></div>\n<p>Report ID: {} · Content fingerprint: <code>{}</code></p>\n",
        MAILENT_LOGO_SVG,
        escape_html(&report.metadata.title),
        escape_html(&report.metadata.report_id),
        report.content_fingerprint()
    ));
    body.push_str(&format!(
        "<p>Generated {} by {} · Policy {} v{} · Posture model v{}</p>\n",
        fmt_time(report.metadata.generated_at),
        escape_html(&report.metadata.generator),
        escape_html(&report.metadata.policy_name),
        escape_html(&report.metadata.policy_version),
        escape_html(&report.metadata.posture_score_version),
    ));
    if let Some(name) = &report.metadata.asset_name {
        body.push_str(&format!(
            "<p>Asset: {} ({})</p>\n",
            escape_html(name),
            escape_html(&report.metadata.asset_addresses.join(", "))
        ));
    }
    body.push_str("</section>\n");

    // Posture & risk
    if let Some(posture) = &report.posture {
        body.push_str("<section class=\"posture\">\n<h2>Security posture</h2>\n");
        body.push_str(&format!(
            "<p>Score <strong>{:.0}/100</strong> ({}){} · findings considered: {}</p>\n",
            posture.score,
            posture.grade,
            if posture.score_capped {
                format!(
                    " · capped from {:.0} by serious findings",
                    posture.pre_cap_score
                )
            } else {
                String::new()
            },
            posture.findings_considered
        ));
        body.push_str("<ul>\n");
        for cat in &posture.categories {
            body.push_str(&format!(
                "<li>{}: {:.0}/100 (weight {:.2}) — {}</li>\n",
                escape_html(&cat.category.to_string()),
                cat.score,
                cat.weight,
                escape_html(&cat.rationale)
            ));
        }
        body.push_str("</ul>\n</section>\n");
    }
    if let Some(risk) = &report.risk {
        body.push_str("<section class=\"risk\">\n<h2>Risk prioritization</h2>\n<ol>\n");
        for action in &risk.prioritized_actions {
            body.push_str(&format!("<li>{}</li>\n", escape_html(action)));
        }
        body.push_str("</ol>\n</section>\n");
    }

    // Findings
    body.push_str("<section class=\"findings\">\n<h2>Policy findings (deterministic)</h2>\n");
    if report.findings.is_empty() {
        body.push_str("<p>No policy findings.</p>\n");
    }
    for f in &report.findings {
        body.push_str(&format!(
            "<article><h3>[{}] {} <code>{}</code></h3>\n<p>{}</p>\n<p>Policy {} v{} · {} · provenance: {}</p>\n",
            escape_html(&f.severity),
            escape_html(&f.title),
            escape_html(&f.rule_id),
            escape_html(&f.description),
            escape_html(&f.policy_name),
            escape_html(&f.policy_version),
            escape_html(&f.reference),
            f.provenance,
        ));
        for e in &f.evidence {
            body.push_str(&format!(
                "<p class=\"evidence\">Evidence: {} (session: {})</p>\n",
                escape_html(&e.description),
                e.session_id
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "n/a".to_string())
            ));
        }
        body.push_str("</article>\n");
    }
    body.push_str("</section>\n");

    // Evidence sections (sessions + certificates)
    for section in evidence_sections(report) {
        body.push_str(&format!(
            "<section class=\"evidence\"><h2>{} <span class=\"prov\">[{}]</span></h2>\n<dl>\n",
            escape_html(&section.heading),
            section.provenance,
        ));
        for (label, value) in &section.rows {
            body.push_str(&format!(
                "<dt>{}</dt><dd>{}</dd>\n",
                escape_html(label),
                escape_html(value)
            ));
        }
        body.push_str("</dl>\n");
        if !section.bullets.is_empty() {
            body.push_str("<ul>\n");
            for b in &section.bullets {
                body.push_str(&format!("<li>{}</li>\n", escape_html(b)));
            }
            body.push_str("</ul>\n");
        }
        body.push_str("</section>\n");
    }

    // Anomaly / drift context
    if !report.context.is_empty() {
        body.push_str("<section class=\"context\">\n<h2>Anomaly &amp; drift context</h2>\n<ul>\n");
        for c in &report.context {
            body.push_str(&format!(
                "<li>{} — {}: {} (baseline: {}, current: {}) [{}]</li>\n",
                escape_html(&c.kind),
                escape_html(&c.signal),
                escape_html(&c.title),
                escape_html(
                    &c.baseline_value
                        .clone()
                        .unwrap_or_else(|| "n/a".to_string())
                ),
                escape_html(&c.current_value.clone().unwrap_or_else(|| "n/a".to_string())),
                c.provenance,
            ));
        }
        body.push_str("</ul>\n</section>\n");
    }

    // Active verification
    if !report.active_verifications.is_empty() {
        body.push_str("<section class=\"verification\">\n<h2>Active verification evidence</h2>\n");
        for v in &report.active_verifications {
            body.push_str(&format!(
                "<article><h3>Probe {} — {}:{} ({})</h3>\n<p>Outcome: {} · trigger: {} · TLS: {} · FS: {}</p>\n",
                v.probe_id,
                escape_html(&v.target),
                v.port,
                escape_html(&v.protocol),
                escape_html(&v.outcome),
                escape_html(&v.trigger),
                escape_html(&v.tls_version.clone().unwrap_or_else(|| "n/a".to_string())),
                escape_html(&v.forward_secrecy.clone().unwrap_or_else(|| "n/a".to_string())),
            ));
            if !v.verification_summary.is_empty() {
                body.push_str("<ul>\n");
                for line in &v.verification_summary {
                    body.push_str(&format!("<li>{}</li>\n", escape_html(line)));
                }
                body.push_str("</ul>\n");
            }
            body.push_str("</article>\n");
        }
        body.push_str("</section>\n");
    }

    // Guidance
    for (kind, label) in [
        (GuidanceKind::Remediation, "Remediation"),
        (GuidanceKind::BestPractice, "Best practice"),
    ] {
        let rows = guidance_rows(report, kind);
        if rows.is_empty() {
            continue;
        }
        body.push_str(&format!(
            "<section class=\"guidance\"><h2>{label} guidance</h2>\n"
        ));
        for (head, detail, caveats) in rows {
            body.push_str(&format!(
                "<article><h3>{}</h3><pre>{}</pre>\n",
                escape_html(&head),
                escape_html(&detail)
            ));
            if !caveats.is_empty() {
                body.push_str(&format!(
                    "<p class=\"caveats\">Observed compatibility: {}</p>\n",
                    escape_html(&caveats)
                ));
            }
            body.push_str("</article>\n");
        }
        body.push_str("</section>\n");
    }

    // AI assessment (supplemental)
    if let Some(ai) = &report.ai_assessment {
        body.push_str("<section class=\"ai\">\n<h2>AI assessment (supplemental)</h2>\n");
        body.push_str(&format!(
            "<p>Provider: {} · model: {} · risk: {} · priority: {}</p>\n",
            escape_html(&ai.provider),
            escape_html(&ai.model),
            escape_html(ai.risk.as_deref().unwrap_or("n/a")),
            escape_html(ai.priority.as_deref().unwrap_or("n/a")),
        ));
        body.push_str(&format!("<p>{}</p>\n", escape_html(&ai.caveat)));
        body.push_str("</section>\n");
    }

    // Evidence gaps
    if !report.evidence_gaps.is_empty() {
        body.push_str("<section class=\"gaps\">\n<h2>Evidence gaps</h2>\n<ul>\n");
        for gap in &report.evidence_gaps {
            body.push_str(&format!("<li>{}</li>\n", escape_html(gap)));
        }
        body.push_str("</ul>\n</section>\n");
    }

    let html_style = r#"
:root {
  --ink-primary: #1d1d1f;
  --ink-secondary: #6e6e73;
  --bg: #f5f5f7;
  --card: #ffffff;
  --hairline: #e5e5ea;
  --accent: #0066cc;
}
* { box-sizing: border-box; }
body {
  font-family: 'Merriweather Sans', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background-color: var(--bg);
  color: var(--ink-primary);
  margin: 0;
  padding: 2rem 1rem;
  line-height: 1.5;
  font-size: 15px;
}
.report-container {
  max-width: 56rem;
  margin: 0 auto;
}
.report-header-bar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  background: #ffffff;
  border: 1px solid var(--hairline);
  border-radius: 8px;
  padding: 0.75rem 1.25rem;
  margin-bottom: 1.5rem;
}
.report-brand {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}
.brand-badge {
  font-weight: 700;
  letter-spacing: 0.05em;
  font-size: 0.8125rem;
  color: #ffffff;
  background: var(--ink-primary);
  padding: 0.2rem 0.6rem;
  border-radius: 4px;
}
.report-type {
  font-size: 0.8125rem;
  font-weight: 600;
  color: var(--ink-secondary);
}
.print-button {
  background: var(--accent);
  color: #ffffff;
  border: none;
  font-size: 0.8125rem;
  font-weight: 600;
  padding: 0.45rem 1rem;
  border-radius: 9999px;
  cursor: pointer;
}
.print-button:hover { background: #0071e3; }
section {
  background: var(--card);
  border: 1px solid var(--hairline);
  border-radius: 10px;
  padding: 1.5rem;
  margin-bottom: 1.25rem;
}
section.meta {
  border-left: 4px solid var(--accent);
}
h1 {
  font-size: 1.5rem;
  font-weight: 600;
  margin: 0 0 0.5rem;
  color: var(--ink-primary);
}
h2 {
  font-size: 1.15rem;
  font-weight: 600;
  margin: 0 0 0.875rem;
  padding-bottom: 0.5rem;
  border-bottom: 1px solid var(--hairline);
  display: flex;
  justify-content: space-between;
  align-items: center;
}
h3 {
  font-size: 1rem;
  font-weight: 600;
  margin: 0 0 0.4rem;
}
p { margin: 0 0 0.6rem; }
.meta-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 0.5rem 1rem;
  margin-top: 0.75rem;
  font-size: 0.8125rem;
}
.meta-item { display: flex; flex-direction: column; }
.meta-item span.label { color: var(--ink-secondary); font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
.meta-item span.val { color: var(--ink-primary); word-break: break-all; }
.prov {
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--ink-secondary);
  background: #f0f0f4;
  border: 1px solid var(--hairline);
  padding: 0.15rem 0.5rem;
  border-radius: 4px;
  text-transform: uppercase;
}
dl {
  display: grid;
  grid-template-columns: 170px 1fr;
  gap: 0.35rem 1rem;
  margin: 0.5rem 0;
  font-size: 0.875rem;
}
dt {
  font-weight: 600;
  color: var(--ink-secondary);
  font-size: 0.75rem;
  text-transform: uppercase;
  margin: 0;
}
dd {
  margin: 0;
  font-family: ui-monospace, 'SF Mono', Menlo, monospace;
  word-break: break-all;
}
article {
  border: 1px solid var(--hairline);
  background: #fafafc;
  border-radius: 8px;
  padding: 1rem;
  margin-bottom: 0.875rem;
}
article:last-child { margin-bottom: 0; }
pre {
  background: #f5f5f7;
  border: 1px solid var(--hairline);
  padding: 0.75rem;
  border-radius: 6px;
  font-size: 0.8125rem;
  overflow-x: auto;
  white-space: pre-wrap;
  font-family: ui-monospace, 'SF Mono', monospace;
  margin: 0.5rem 0;
}
code {
  font-family: ui-monospace, 'SF Mono', monospace;
  font-size: 0.8125rem;
  background: #f5f5f7;
  padding: 0.15rem 0.4rem;
  border-radius: 4px;
  border: 1px solid var(--hairline);
}
ul, ol { margin: 0.5rem 0; padding-left: 1.25rem; font-size: 0.875rem; }
li { margin-bottom: 0.25rem; }
.caveats {
  font-size: 0.8125rem;
  color: #854d0e;
  background: #fefce8;
  border: 1px solid #fef08a;
  padding: 0.5rem 0.75rem;
  border-radius: 6px;
  margin-top: 0.5rem;
}
@media print {
  .no-print { display: none !important; }
  body {
    background: #ffffff !important;
    color: #000000 !important;
    padding: 0 !important;
    font-size: 10pt;
    -webkit-print-color-adjust: exact !important;
    print-color-adjust: exact !important;
  }
  .report-container { max-width: 100% !important; margin: 0 !important; }
  section {
    page-break-inside: avoid;
    break-inside: avoid;
    border: 1px solid #d1d5db !important;
    box-shadow: none !important;
    margin-bottom: 1rem !important;
    padding: 1rem 1.25rem !important;
    border-radius: 6px !important;
  }
  article {
    page-break-inside: avoid;
    break-inside: avoid;
    border: 1px solid #e5e7eb !important;
    margin-bottom: 0.75rem !important;
    padding: 0.75rem !important;
  }
  @page { margin: 12mm; size: A4 portrait; }
}
"#;

    Ok(format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n<title>{}</title>\n<style>\n{}\n</style>\n</head>\n<body>\n<div class=\"report-container\">\n<div class=\"report-header-bar no-print\">\n<div class=\"report-brand\">\n<span class=\"brand-badge\">MAILENT</span>\n<span class=\"report-type\">FORENSIC EVIDENCE REPORT</span>\n</div>\n<button onclick=\"window.print()\" class=\"print-button\">Save as PDF / Print</button>\n</div>\n{}</div>\n<script>\nif (window.location.hash === '#print' || new URLSearchParams(window.location.search).get('print') === 'true') {{\n  window.addEventListener('DOMContentLoaded', () => {{\n    setTimeout(() => window.print(), 350);\n  }});\n}}\n</script>\n</body>\n</html>\n",
        escape_html(&report.metadata.title),
        html_style.trim(),
        body
    ))
}

/// Minimal but valid PDF 1.4 writer: deterministic text-based rendering of the
/// same content as the HTML export. No external dependencies; text objects
/// carry the same sections with provenance labels.
pub fn render_pdf(report: &ForensicReport) -> Result<Vec<u8>, ReportError> {
    // Reuse the exact same section construction as HTML to guarantee content parity.
    let html = render_html(report)?;
    let text = extract_plain_text(&html);

    // Basic PDF with WinAnsi-safe characters only (sanitize non-ASCII).
    let safe: String = text
        .chars()
        .map(|c| {
            if (c as u32) < 128 && c != '\u{0}' {
                c
            } else {
                ' '
            }
        })
        .collect();

    let mut objects: Vec<String> = Vec::new();
    // 1: Catalog, 2: Pages, 3: Page, 4: Contents stream, 5: Font
    let lines: Vec<&str> = safe.lines().collect();
    let mut content = String::from("BT /F1 10 Tf 12 TL 40 800 Td\n");
    for line in lines.iter().take(6000) {
        let escaped = line
            .replace('\\', "\\\\")
            .replace('(', "\\(")
            .replace(')', "\\)");
        content.push_str(&format!("({escaped}) Tj T*\n"));
    }
    content.push_str("ET");
    objects.push("<< /Type /Catalog /Pages 2 0 R >>".to_string());
    objects.push("<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string());
    objects.push(
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>"
            .to_string(),
    );
    objects.push(format!(
        "<< /Length {} >>\nstream\n{content}\nendstream",
        content.len()
    ));
    objects.push("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string());

    let mut pdf = String::from("%PDF-1.4\n");
    let mut offsets = Vec::new();
    for (i, obj) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.push_str(&format!("{} 0 obj\n{obj}\nendobj\n", i + 1));
    }
    let xref_pos = pdf.len();
    pdf.push_str(&format!("xref\n0 {}\n", objects.len() + 1));
    pdf.push_str("0000000000 65535 f \n");
    for off in &offsets {
        pdf.push_str(&format!("{off:010} 00000 n \n"));
    }
    pdf.push_str(&format!(
        "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF",
        objects.len() + 1
    ));

    Ok(pdf.into_bytes())
}

/// Extract plain text lines from the rendered HTML (shared by PDF writer) so
/// PDF and HTML content can be compared for equivalence in tests.
pub fn extract_plain_text(html: &str) -> String {
    // Strip <style>...</style>, <script>...</script>, and <svg>...</svg> blocks first so CSS/JS/SVG don't leak into text
    let mut stripped_blocks = String::new();
    let mut rest = html;
    while let Some(start_idx) = rest
        .find("<style")
        .or_else(|| rest.find("<script"))
        .or_else(|| rest.find("<svg"))
    {
        stripped_blocks.push_str(&rest[..start_idx]);
        let after_tag = &rest[start_idx..];
        let (end_needle, offset) = if after_tag.starts_with("<style") {
            ("</style>", 8)
        } else if after_tag.starts_with("<script") {
            ("</script>", 9)
        } else {
            ("</svg>", 6)
        };
        if let Some(close_idx) = after_tag.find(end_needle) {
            rest = &after_tag[close_idx + offset..];
        } else {
            rest = "";
            break;
        }
    }
    stripped_blocks.push_str(rest);

    let without_tags = {
        let mut out = String::new();
        let mut in_tag = false;
        for ch in stripped_blocks.chars() {
            match ch {
                '<' => in_tag = true,
                '>' => in_tag = false,
                c if !in_tag => out.push(c),
                _ => {}
            }
        }
        out
    };
    // Decode the handful of entities we emit.
    without_tags
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::{ReportInput, build_report};
    use mailent_domain::{
        CertificateCryptoDetails, ChainValidation, EmailProtocol, NetworkFlow,
        ObservationProvenance, PublicKeyDetails,
    };
    use time::Duration;
    use uuid::Uuid;

    fn sample_report() -> ForensicReport {
        let now = OffsetDateTime::UNIX_EPOCH + Duration::days(900);
        let mut session = mailent_domain::EmailSession {
            session_id: Uuid::new_v4(),
            sensor_id: "s1".into(),
            provenance: ObservationProvenance {
                source: "pcap".into(),
                parser: "zeek".into(),
                parser_version: "8".into(),
            },
            flow: NetworkFlow {
                src_ip: "10.0.0.1".into(),
                src_port: 1000,
                dst_ip: "10.0.0.2".into(),
                dst_port: 25,
            },
            protocol: EmailProtocol::Smtp,
            starttls_state: Some(StartTlsState::AdvertisedAndUsed),
            tls_version: Some(mailent_domain::TlsVersion::Tls12),
            cipher_suite: Some(mailent_domain::CipherSuite {
                id: Some(49199),
                name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".into(),
            }),
            key_exchange: Some(mailent_domain::KeyExchange::Ecdhe),
            certificate: None,
            capture: None,
            first_seen: now,
            last_seen: now,
        };
        session.certificate = Some(mailent_domain::CertificateObservation {
            reference: mailent_domain::CertificateReference {
                sha256_fingerprint: "ff".repeat(32),
                subject: "CN=mail.test".into(),
                issuer: "CN=CA".into(),
            },
            validity: mailent_domain::ValidityPeriod {
                not_before: now - Duration::days(30),
                not_after: now + Duration::days(30),
            },
            is_self_signed: Some(false),
            san: vec!["mail.test".into()],
            crypto_details: Some(CertificateCryptoDetails {
                signature_algorithm: Some("sha256WithRSAEncryption".into()),
                public_key: PublicKeyDetails {
                    algorithm: Some("RSA".into()),
                    rsa_bits: Some(2048),
                    ec_curve: None,
                    spki_sha256: None,
                },
                chain_validation: ChainValidation::NotVerified,
                chain_length: None,
                extensions: mailent_domain::CertificateExtensions {
                    basic_constraints: None,
                    key_usage: vec![],
                    extended_key_usage: vec![],
                },
            }),
        });
        let input = ReportInput {
            remediation_records: &[],
            sessions: std::slice::from_ref(&session),
            ..Default::default()
        };
        build_report(
            "Test report",
            "0.1.0",
            &input,
            OffsetDateTime::UNIX_EPOCH + Duration::days(901),
        )
    }

    use mailent_domain::StartTlsState;

    #[test]
    fn json_html_pdf_share_core_content() {
        let report = sample_report();
        let json = to_json(&report).unwrap();
        let html = render_html(&report).unwrap();
        let pdf = render_pdf(&report).unwrap();

        // All formats carry the session's server IP and the certificate subject.
        for needle in ["10.0.0.2", "mail.test", "TLSv1.2"] {
            assert!(json.contains(needle), "json missing {needle}");
            assert!(html.contains(needle), "html missing {needle}");
            let pdf_text = String::from_utf8_lossy(&pdf);
            assert!(pdf_text.contains(needle), "pdf missing {needle}");
        }

        // PDF parses as PDF and HTML is a document.
        assert!(pdf.starts_with(b"%PDF-1.4"));
        assert!(html.starts_with("<!DOCTYPE html>"));
    }

    #[test]
    fn provenance_labels_present_in_all_formats() {
        let report = sample_report();
        let json = to_json(&report).unwrap();
        let html = render_html(&report).unwrap();
        let pdf_bytes = render_pdf(&report).unwrap();
        let pdf_text = String::from_utf8_lossy(&pdf_bytes);
        assert!(
            json.contains("observed_fact") || json.contains("ObservedFact"),
            "json missing provenance enum"
        );
        for fmt in [html.as_str(), pdf_text.as_ref()] {
            assert!(
                fmt.contains("observed fact"),
                "format missing provenance label"
            );
        }
    }

    #[test]
    fn rendering_is_deterministic() {
        let report = sample_report();
        let html_a = render_html(&report).unwrap();
        let html_b = render_html(&report).unwrap();
        assert_eq!(html_a, html_b);
        let pdf_a = render_pdf(&report).unwrap();
        let pdf_b = render_pdf(&report).unwrap();
        assert_eq!(pdf_a, pdf_b);
    }

    #[test]
    fn no_private_content_in_exports() {
        // Build a report whose evidence contains privacy-marker text; the
        // builder must redact it before it reaches any export format.
        let mut session = mailent_domain::EmailSession {
            session_id: Uuid::new_v4(),
            sensor_id: "s1".into(),
            provenance: ObservationProvenance {
                source: "pcap".into(),
                parser: "zeek".into(),
                parser_version: "8".into(),
            },
            flow: NetworkFlow {
                src_ip: "10.0.0.1".into(),
                src_port: 1000,
                dst_ip: "10.0.0.2".into(),
                dst_port: 25,
            },
            protocol: EmailProtocol::Smtp,
            starttls_state: Some(StartTlsState::AdvertisedAndUsed),
            tls_version: Some(mailent_domain::TlsVersion::Tls12),
            cipher_suite: None,
            key_exchange: None,
            certificate: None,
            capture: Some(mailent_domain::CaptureEvidence {
                capture_sha256: "cafe".repeat(16),
                connection_uid: "uid1".into(),
                normalizer_version: "1".into(),
                source_logs: vec!["smtp.log:9".into()],
                timeline: vec![],
                gaps: vec!["Message-ID header not captured".into()],
                tls_established: Some(true),
                protocol_hint: None,
            }),
            first_seen: OffsetDateTime::UNIX_EPOCH + Duration::days(900),
            last_seen: OffsetDateTime::UNIX_EPOCH + Duration::days(900),
        };
        session.starttls_state = Some(StartTlsState::AdvertisedAndUsed);
        let input = ReportInput {
            remediation_records: &[],
            sessions: std::slice::from_ref(&session),
            ..Default::default()
        };
        let report = build_report(
            "t",
            "0.1.0",
            &input,
            OffsetDateTime::UNIX_EPOCH + Duration::days(901),
        );
        let html = render_html(&report).unwrap();
        let pdf_bytes = render_pdf(&report).unwrap();
        let pdf_text = String::from_utf8_lossy(&pdf_bytes);
        let json = to_json(&report).unwrap();
        // The report builder sanitizes descriptions; the renderers must not add leaks.
        assert!(!html.to_lowercase().contains("message-id header"));
        assert!(!pdf_text.to_lowercase().contains("message-id header"));
        assert!(json.contains("[redacted"));
    }
}
