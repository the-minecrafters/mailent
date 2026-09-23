use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{protocol::EmailProtocol, tls::TlsVersion};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetIdentity {
    pub kind: String,
    pub value: String,
    #[serde(with = "time::serde::rfc3339")]
    pub first_seen: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_seen: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetEndpoint {
    pub protocol: EmailProtocol,
    pub port: u16,
    pub tls_versions: Vec<TlsVersion>,
    pub cipher_suites: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub first_seen: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_seen: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Asset {
    pub id: Uuid,
    pub primary_name: Option<String>,
    #[serde(default)]
    pub addresses: Vec<String>,
    #[serde(default)]
    pub hostnames: Vec<String>,
    #[serde(default)]
    pub identities: Vec<AssetIdentity>,
    #[serde(default)]
    pub endpoints: Vec<AssetEndpoint>,
    #[serde(default)]
    pub tls_versions: Vec<TlsVersion>,
    #[serde(default)]
    pub cipher_suites: Vec<String>,
    #[serde(default)]
    pub certificate_fingerprints: Vec<String>,
    #[serde(default)]
    pub active_findings_count: usize,
    #[serde(with = "time::serde::rfc3339")]
    pub first_seen: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_seen: OffsetDateTime,
}

impl Asset {
    pub fn hostname(&self) -> Option<&str> {
        self.primary_name
            .as_deref()
            .or_else(|| self.hostnames.first().map(|s| s.as_str()))
    }

    pub fn ip_address(&self) -> &str {
        self.addresses
            .first()
            .map(|s| s.as_str())
            .unwrap_or("unknown")
    }

    pub fn protocols(&self) -> Vec<EmailProtocol> {
        let mut p: Vec<EmailProtocol> = self.endpoints.iter().map(|e| e.protocol).collect();
        p.sort();
        p.dedup();
        p
    }
}
