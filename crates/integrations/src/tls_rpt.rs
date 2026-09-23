use mailent_domain::{TlsRptAggregateReport, TlsRptFailureDetail, TlsRptPolicy};
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::IntegrationError;

/// Parse a `_smtp._tls.<domain>` TXT record into a `TlsRptPolicy` (RFC 8460).
/// e.g. `v=TLSRPTv1; rua=mailto:reports@example.com,https://tlsrpt.example.com/v1`
pub fn parse_tls_rpt_policy(
    domain: &str,
    txt_record: &str,
) -> Result<TlsRptPolicy, IntegrationError> {
    let mut rua_list = Vec::new();
    let mut version_found = false;

    for tag in txt_record.split(';') {
        let tag = tag.trim();
        if tag.is_empty() {
            continue;
        }

        if let Some((k, v)) = tag.split_once('=') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim();

            match k.as_str() {
                "v" => {
                    if v != "TLSRPTv1" {
                        return Err(IntegrationError::Format(format!(
                            "unsupported TLS-RPT version: {v}"
                        )));
                    }
                    version_found = true;
                }
                "rua" => {
                    for uri in v.split(',') {
                        let uri = uri.trim();
                        if !uri.is_empty() {
                            rua_list.push(uri.to_string());
                        }
                    }
                }
                _ => {}
            }
        }
    }

    if !version_found {
        return Err(IntegrationError::Format(
            "missing 'v=TLSRPTv1' tag in TLS-RPT record".into(),
        ));
    }

    Ok(TlsRptPolicy {
        domain: domain.to_string(),
        rua: rua_list,
        checked_at: OffsetDateTime::now_utc(),
    })
}

// RFC 8460 Wire Schema for Deserialization
#[derive(Debug, Deserialize)]
struct WireReport {
    #[serde(rename = "organization-name")]
    organization_name: String,
    #[serde(rename = "date-range")]
    date_range: WireDateRange,
    policies: Vec<WirePolicyContainer>,
}

#[derive(Debug, Deserialize)]
struct WireDateRange {
    #[serde(rename = "start-datetime")]
    start_datetime: String,
    #[serde(rename = "end-datetime")]
    end_datetime: String,
}

#[derive(Debug, Deserialize)]
struct WirePolicyContainer {
    policy: WirePolicyInner,
    summary: WireSummary,
    #[serde(rename = "failure-details", default)]
    failure_details: Vec<WireFailureDetail>,
}

#[derive(Debug, Deserialize)]
struct WirePolicyInner {
    #[serde(rename = "policy-domain")]
    policy_domain: String,
}

#[derive(Debug, Deserialize)]
struct WireSummary {
    #[serde(rename = "total-successful-session-count", default)]
    total_successful_session_count: u64,
    #[serde(rename = "total-failure-session-count", default)]
    total_failure_session_count: u64,
}

#[derive(Debug, Deserialize)]
struct WireFailureDetail {
    #[serde(rename = "result-type")]
    result_type: String,
    #[serde(rename = "receiving-mx-hostname", default)]
    receiving_mx_hostname: Option<String>,
    #[serde(rename = "failed-session-count", default)]
    failed_session_count: u64,
    #[serde(rename = "additional-information", default)]
    additional_information: Option<String>,
}

/// Parses an RFC 8460 JSON TLS-RPT report.
pub fn parse_tls_rpt_json(json_str: &str) -> Result<Vec<TlsRptAggregateReport>, IntegrationError> {
    let wire: WireReport = serde_json::from_str(json_str)
        .map_err(|e| IntegrationError::Format(format!("failed to parse TLS-RPT JSON: {e}")))?;

    let start_date = OffsetDateTime::parse(
        &wire.date_range.start_datetime,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|e| IntegrationError::Format(format!("invalid start-datetime: {e}")))?;

    let end_date = OffsetDateTime::parse(
        &wire.date_range.end_datetime,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|e| IntegrationError::Format(format!("invalid end-datetime: {e}")))?;

    let now = OffsetDateTime::now_utc();
    let mut reports = Vec::new();

    for p in wire.policies {
        let failure_details = p
            .failure_details
            .into_iter()
            .map(|f| TlsRptFailureDetail {
                failure_type: f.result_type,
                receiving_mx: f.receiving_mx_hostname.unwrap_or_default(),
                failed_count: f.failed_session_count,
                additional_info: f.additional_information,
            })
            .collect();

        reports.push(TlsRptAggregateReport {
            id: Uuid::new_v4(),
            organization_name: wire.organization_name.clone(),
            start_date,
            end_date,
            policy_domain: p.policy.policy_domain,
            successful_sessions: p.summary.total_successful_session_count,
            failed_sessions: p.summary.total_failure_session_count,
            failure_details,
            imported_at: now,
        });
    }

    Ok(reports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tls_rpt_policy() {
        let txt = "v=TLSRPTv1; rua=mailto:reports@example.com,https://tlsrpt.example.com/v1";
        let policy = parse_tls_rpt_policy("example.com", txt).unwrap();
        assert_eq!(policy.domain, "example.com");
        assert_eq!(
            policy.rua,
            vec![
                "mailto:reports@example.com".to_string(),
                "https://tlsrpt.example.com/v1".to_string()
            ]
        );
    }

    #[test]
    fn test_parse_tls_rpt_json_report() {
        let json_data = r#"{
          "organization-name": "Acme Mail Providers",
          "date-range": {
            "start-datetime": "2026-09-20T00:00:00Z",
            "end-datetime": "2026-09-20T23:59:59Z"
          },
          "policies": [
            {
              "policy": {
                "policy-domain": "example.com"
              },
              "summary": {
                "total-successful-session-count": 1000,
                "total-failure-session-count": 50
              },
              "failure-details": [
                {
                  "result-type": "certificate-expired",
                  "receiving-mx-hostname": "mx1.example.com",
                  "failed-session-count": 50
                }
              ]
            }
          ]
        }"#;

        let reports = parse_tls_rpt_json(json_data).unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].organization_name, "Acme Mail Providers");
        assert_eq!(reports[0].policy_domain, "example.com");
        assert_eq!(reports[0].successful_sessions, 1000);
        assert_eq!(reports[0].failed_sessions, 50);
        assert_eq!(reports[0].failure_details.len(), 1);
        assert_eq!(
            reports[0].failure_details[0].failure_type,
            "certificate-expired"
        );
    }
}
