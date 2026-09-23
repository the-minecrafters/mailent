use mailent_domain::{FindingSeverity, KeyExchange, TlsVersion};
use serde::{Deserialize, Serialize};

use crate::PolicyError;

/// A deliberately small DSL: only implemented, deterministic predicates are accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Predicate {
    TlsVersionIn { versions: Vec<TlsVersion> },
    CertificateExpired,
    SmtpStartTlsNotAdvertised,
    KeyExchangeIn { values: Vec<KeyExchange> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub id: String,
    pub title: String,
    pub severity: FindingSeverity,
    pub description: String,
    pub remediation: String,
    pub reference: String,
    pub when: Predicate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPack {
    pub name: String,
    pub version: String,
    pub description: String,
    pub rules: Vec<PolicyRule>,
}

impl PolicyPack {
    pub fn from_yaml(yaml: &str) -> Result<Self, PolicyError> {
        let pack: Self =
            serde_yaml::from_str(yaml).map_err(|e| PolicyError::ParseError(e.to_string()))?;
        pack.validate()?;
        Ok(pack)
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        let invalid = |message: &str| PolicyError::ParseError(message.into());
        if self.name.trim().is_empty() || self.version.trim().is_empty() || self.rules.is_empty() {
            return Err(invalid("policy name, version and rules must be present"));
        }
        let mut ids = std::collections::HashSet::new();
        for rule in &self.rules {
            if [
                &rule.id,
                &rule.title,
                &rule.description,
                &rule.remediation,
                &rule.reference,
            ]
            .iter()
            .any(|s| s.trim().is_empty())
                || !ids.insert(&rule.id)
            {
                return Err(invalid("rules must have nonempty fields and unique IDs"));
            }
            match &rule.when {
                Predicate::TlsVersionIn { versions }
                    if versions.is_empty()
                        || versions.iter().any(|v| matches!(v, TlsVersion::Unknown(_))) =>
                {
                    return Err(invalid("TLS predicates require known versions"));
                }
                Predicate::KeyExchangeIn { values }
                    if values.is_empty()
                        || values.iter().any(|v| matches!(v, KeyExchange::Unknown(_))) =>
                {
                    return Err(invalid("key exchange predicates require known values"));
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn modern() -> Self {
        Self::from_yaml(include_str!("../../../policies/modern/policy.yaml"))
            .expect("the bundled modern policy must validate")
    }
}
