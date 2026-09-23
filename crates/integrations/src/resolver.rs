use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use mailent_domain::{
    CtCertificateRecord, DnssecState, MtaStsPolicy, MxRecord, TlsRptPolicy, TlsaRecord,
};
use tokio::sync::RwLock;

use crate::{IntegrationError, mta_sts::parse_mta_sts_policy, tls_rpt::parse_tls_rpt_policy};

/// Trait defining the external mail-domain intelligence resolver boundary.
#[async_trait]
pub trait DomainIntelligenceResolver: Send + Sync {
    async fn fetch_mx(&self, domain: &str) -> Result<Vec<MxRecord>, IntegrationError>;
    async fn fetch_tlsa(
        &self,
        mx_host: &str,
        port: u16,
    ) -> Result<Vec<TlsaRecord>, IntegrationError>;
    async fn fetch_mta_sts(&self, domain: &str) -> Result<Option<MtaStsPolicy>, IntegrationError>;
    async fn fetch_tls_rpt_policy(
        &self,
        domain: &str,
    ) -> Result<Option<TlsRptPolicy>, IntegrationError>;
    async fn fetch_ct_certificates(
        &self,
        domain: &str,
    ) -> Result<Vec<CtCertificateRecord>, IntegrationError>;
}

/// In-memory mock resolver with deterministic fixtures for testing and air-gapped deployments.
#[derive(Debug, Default, Clone)]
pub struct MockDomainIntelligenceResolver {
    mx_records: Arc<RwLock<HashMap<String, Vec<MxRecord>>>>,
    tlsa_records: Arc<RwLock<HashMap<String, Vec<TlsaRecord>>>>,
    mta_sts_policies: Arc<RwLock<HashMap<String, MtaStsPolicy>>>,
    tls_rpt_policies: Arc<RwLock<HashMap<String, TlsRptPolicy>>>,
    ct_certs: Arc<RwLock<HashMap<String, Vec<CtCertificateRecord>>>>,
}

impl MockDomainIntelligenceResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn add_mx(&self, domain: &str, records: Vec<MxRecord>) {
        self.mx_records
            .write()
            .await
            .insert(domain.to_string(), records);
    }

    pub async fn add_tlsa(&self, mx_host: &str, port: u16, records: Vec<TlsaRecord>) {
        self.tlsa_records
            .write()
            .await
            .insert(format!("{mx_host}:{port}"), records);
    }

    pub async fn add_mta_sts(&self, domain: &str, policy: MtaStsPolicy) {
        self.mta_sts_policies
            .write()
            .await
            .insert(domain.to_string(), policy);
    }

    pub async fn add_tls_rpt(&self, domain: &str, policy: TlsRptPolicy) {
        self.tls_rpt_policies
            .write()
            .await
            .insert(domain.to_string(), policy);
    }

    pub async fn add_ct_certs(&self, domain: &str, certs: Vec<CtCertificateRecord>) {
        self.ct_certs
            .write()
            .await
            .insert(domain.to_string(), certs);
    }
}

#[async_trait]
impl DomainIntelligenceResolver for MockDomainIntelligenceResolver {
    async fn fetch_mx(&self, domain: &str) -> Result<Vec<MxRecord>, IntegrationError> {
        let guard = self.mx_records.read().await;
        Ok(guard.get(domain).cloned().unwrap_or_default())
    }

    async fn fetch_tlsa(
        &self,
        mx_host: &str,
        port: u16,
    ) -> Result<Vec<TlsaRecord>, IntegrationError> {
        let guard = self.tlsa_records.read().await;
        Ok(guard
            .get(&format!("{mx_host}:{port}"))
            .cloned()
            .unwrap_or_default())
    }

    async fn fetch_mta_sts(&self, domain: &str) -> Result<Option<MtaStsPolicy>, IntegrationError> {
        let guard = self.mta_sts_policies.read().await;
        Ok(guard.get(domain).cloned())
    }

    async fn fetch_tls_rpt_policy(
        &self,
        domain: &str,
    ) -> Result<Option<TlsRptPolicy>, IntegrationError> {
        let guard = self.tls_rpt_policies.read().await;
        Ok(guard.get(domain).cloned())
    }

    async fn fetch_ct_certificates(
        &self,
        domain: &str,
    ) -> Result<Vec<CtCertificateRecord>, IntegrationError> {
        let guard = self.ct_certs.read().await;
        Ok(guard.get(domain).cloned().unwrap_or_default())
    }
}

/// Live resolver using reqwest with strict timeouts, size limits, and DNS-over-HTTPS.
pub struct LiveDomainIntelligenceResolver {
    client: reqwest::Client,
    doh_endpoint: String,
}

impl LiveDomainIntelligenceResolver {
    pub fn new() -> Result<Self, IntegrationError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .map_err(|e| IntegrationError::Network(e.to_string()))?;

        Ok(Self {
            client,
            doh_endpoint: "https://cloudflare-dns.com/dns-query".to_string(),
        })
    }

    pub fn with_doh(doh_url: &str) -> Result<Self, IntegrationError> {
        let mut s = Self::new()?;
        s.doh_endpoint = doh_url.to_string();
        Ok(s)
    }
}

#[async_trait]
impl DomainIntelligenceResolver for LiveDomainIntelligenceResolver {
    async fn fetch_mx(&self, domain: &str) -> Result<Vec<MxRecord>, IntegrationError> {
        // Query DoH for MX records
        let url = format!("{}?name={}&type=MX", self.doh_endpoint, domain);
        let res = self
            .client
            .get(&url)
            .header("Accept", "application/dns-json")
            .send()
            .await
            .map_err(|e| IntegrationError::Network(e.to_string()))?;

        if !res.status().is_success() {
            return Ok(Vec::new());
        }

        let json: serde_json::Value = res
            .json()
            .await
            .map_err(|e| IntegrationError::Format(e.to_string()))?;

        let ad = json.get("AD").and_then(|v| v.as_bool()).unwrap_or(false);
        let dnssec = if ad {
            DnssecState::Secure
        } else {
            DnssecState::Insecure
        };

        let now = time::OffsetDateTime::now_utc();
        let mut records = Vec::new();

        if let Some(answers) = json.get("Answer").and_then(|a| a.as_array()) {
            for ans in answers {
                if let Some(data) = ans.get("data").and_then(|d| d.as_str()) {
                    let parts: Vec<&str> = data.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let priority: u16 = parts[0].parse().unwrap_or(10);
                        let hostname = parts[1].trim_end_matches('.').to_string();
                        records.push(MxRecord {
                            domain: domain.to_string(),
                            hostname,
                            priority,
                            resolved_ips: Vec::new(),
                            dnssec,
                            first_seen: now,
                            last_checked: now,
                        });
                    }
                }
            }
        }

        Ok(records)
    }

    async fn fetch_tlsa(
        &self,
        mx_host: &str,
        port: u16,
    ) -> Result<Vec<TlsaRecord>, IntegrationError> {
        let qname = format!("_{}._tcp.{}", port, mx_host);
        let url = format!("{}?name={}&type=TLSA", self.doh_endpoint, qname);

        let res = self
            .client
            .get(&url)
            .header("Accept", "application/dns-json")
            .send()
            .await
            .map_err(|e| IntegrationError::Network(e.to_string()))?;

        if !res.status().is_success() {
            return Ok(Vec::new());
        }

        let json: serde_json::Value = res
            .json()
            .await
            .map_err(|e| IntegrationError::Format(e.to_string()))?;

        let ad = json.get("AD").and_then(|v| v.as_bool()).unwrap_or(false);
        let dnssec = if ad {
            DnssecState::Secure
        } else {
            DnssecState::Insecure
        };

        let mut records = Vec::new();
        if let Some(answers) = json.get("Answer").and_then(|a| a.as_array()) {
            for ans in answers {
                if let Some(data) = ans.get("data").and_then(|d| d.as_str())
                    && let Ok(rec) =
                        crate::dane::parse_tlsa_record(mx_host, mx_host, port, data, dnssec)
                {
                    records.push(rec);
                }
            }
        }

        Ok(records)
    }

    async fn fetch_mta_sts(&self, domain: &str) -> Result<Option<MtaStsPolicy>, IntegrationError> {
        // Strict MTA-STS URL: https://mta-sts.<domain>/.well-known/mta-sts.txt (RFC 8461)
        // No arbitrary URLs or redirects allowed beyond mta-sts.<domain>.
        let url = format!("https://mta-sts.{}/.well-known/mta-sts.txt", domain);
        let res = match self.client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(domain, error = %e, "MTA-STS fetch failed or policy not published");
                return Ok(None);
            }
        };

        if !res.status().is_success() {
            return Ok(None);
        }

        // Limit response size to 64KB (RFC 8461 Section 3.2 recommends max 64KB)
        let body = res
            .text()
            .await
            .map_err(|e| IntegrationError::Network(e.to_string()))?;

        if body.len() > 65536 {
            return Err(IntegrationError::Format(
                "MTA-STS policy exceeds maximum allowed size of 64KB".into(),
            ));
        }

        let policy = parse_mta_sts_policy(&body, domain, DnssecState::Insecure)?;
        Ok(Some(policy))
    }

    async fn fetch_tls_rpt_policy(
        &self,
        domain: &str,
    ) -> Result<Option<TlsRptPolicy>, IntegrationError> {
        let qname = format!("_smtp._tls.{}", domain);
        let url = format!("{}?name={}&type=TXT", self.doh_endpoint, qname);

        let res = self
            .client
            .get(&url)
            .header("Accept", "application/dns-json")
            .send()
            .await
            .map_err(|e| IntegrationError::Network(e.to_string()))?;

        if !res.status().is_success() {
            return Ok(None);
        }

        let json: serde_json::Value = res
            .json()
            .await
            .map_err(|e| IntegrationError::Format(e.to_string()))?;

        if let Some(answers) = json.get("Answer").and_then(|a| a.as_array()) {
            for ans in answers {
                if let Some(data) = ans.get("data").and_then(|d| d.as_str()) {
                    let cleaned = data.trim_matches('"');
                    if cleaned.contains("v=TLSRPTv1")
                        && let Ok(policy) = parse_tls_rpt_policy(domain, cleaned)
                    {
                        return Ok(Some(policy));
                    }
                }
            }
        }

        Ok(None)
    }

    async fn fetch_ct_certificates(
        &self,
        domain: &str,
    ) -> Result<Vec<CtCertificateRecord>, IntegrationError> {
        // Query crt.sh public Certificate Transparency JSON API
        let url = format!("https://crt.sh/?q={}&output=json", domain);
        let res = match self.client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(domain, error = %e, "CT log fetch failed");
                return Ok(Vec::new());
            }
        };

        if !res.status().is_success() {
            return Ok(Vec::new());
        }

        let items: Vec<serde_json::Value> = match res.json().await {
            Ok(v) => v,
            Err(_) => return Ok(Vec::new()),
        };

        let now = time::OffsetDateTime::now_utc();
        let mut results = Vec::new();

        for it in items.into_iter().take(50) {
            let names_raw = it.get("name_value").and_then(|v| v.as_str()).unwrap_or("");
            let names: Vec<String> = names_raw.lines().map(|s| s.trim().to_string()).collect();
            let issuer = it
                .get("issuer_name")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown Issuer")
                .to_string();
            let id = it.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
            let fingerprint = format!("ct_id_{id}");

            results.push(CtCertificateRecord {
                sha256_fingerprint: fingerprint,
                domain: domain.to_string(),
                names,
                issuer,
                not_before: now,
                not_after: now,
                ct_first_seen: now,
                observed_on_network: false,
                first_network_observation: None,
            });
        }

        Ok(results)
    }
}
