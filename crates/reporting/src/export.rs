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

/// HTML export: standalone, self-contained document.
pub fn render_html(report: &ForensicReport) -> Result<String, ReportError> {
    let mut body = String::new();

    // Metadata header
    body.push_str("<section class=\"meta\">\n");
    body.push_str(&format!(
        "<h1>{}</h1>\n<p>Report ID: {} · Content fingerprint: <code>{}</code></p>\n",
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

    Ok(format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>{}</title>\n<style>\nbody {{ font-family: sans-serif; margin: 2rem; max-width: 60rem; }}\nsection {{ margin-bottom: 1.5rem; }}\n.prov {{ font-size: 0.75rem; color: #555; }}\ndt {{ font-weight: bold; }}\ndd {{ margin: 0 0 0.4rem 0; }}\ncode, pre {{ font-family: monospace; }}\n</style>\n</head>\n<body>\n{body}</body>\n</html>\n",
        escape_html(&report.metadata.title)
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
                '?'
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
    let without_tags = {
        let mut out = String::new();
        let mut in_tag = false;
        for ch in html.chars() {
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
