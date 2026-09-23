use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProbeScopeError {
    #[error("target domain '{0}' is not authorized in current operator probe scope")]
    UnauthorizedTarget(String),
}

/// An explicitly permitted domain (exact match or wildcard prefix like `*.example.com`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedDomain {
    pub domain: String,
    pub authorization_ref: String,
}

impl AuthorizedDomain {
    /// Returns true if `candidate` matches this entry.
    ///
    /// Matching rules (all case-insensitive):
    /// - Exact:     `mail.example.com` matches `mail.example.com`
    /// - Wildcard:  `*.example.com`    matches `mail.example.com`, `smtp.example.com`
    /// - Suffix:    `.example.com`     matches any host under `example.com`
    pub fn matches(&self, candidate: &str) -> bool {
        if let (Ok(net), Ok(ip)) = (
            self.domain.parse::<ipnet::IpNet>(),
            candidate.parse::<std::net::IpAddr>(),
        ) {
            return net.contains(&ip);
        }
        let c = candidate.trim_end_matches('.').to_lowercase();
        let d = self.domain.trim_end_matches('.').to_lowercase();
        if d.starts_with("*.") {
            // *.example.com — at least one label prefix
            c.ends_with(&d[1..]) && c.len() > d.len() - 1
        } else if d.starts_with('.') {
            // .example.com — any subdomain
            c.ends_with(&d)
        } else {
            c == d
        }
    }
}

/// Active-probe scope — the explicit allowlist of targets this operator has
/// authorized.  Probing anything outside this list is always refused.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeScope {
    pub authorized_domains: Vec<AuthorizedDomain>,
}

impl ProbeScope {
    pub fn new(domains: Vec<AuthorizedDomain>) -> Self {
        Self {
            authorized_domains: domains,
        }
    }

    pub fn is_authorized(&self, candidate: &str) -> bool {
        (candidate.parse::<std::net::IpAddr>().is_ok()
            || (candidate.len() <= 253
                && candidate.trim_end_matches('.').split('.').all(|l| {
                    !l.is_empty()
                        && l.len() <= 63
                        && !l.starts_with('-')
                        && !l.ends_with('-')
                        && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })))
            && self
                .authorized_domains
                .iter()
                .any(|ad| ad.matches(candidate))
    }

    pub fn validate(&self, target: &str) -> Result<(), ProbeScopeError> {
        if self.is_authorized(target) {
            Ok(())
        } else {
            Err(ProbeScopeError::UnauthorizedTarget(target.to_string()))
        }
    }
}

/// Probe target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeTarget {
    pub domain: String,
    pub port: u16,
    pub protocol: mailent_domain::EmailProtocol,
}

/// Runtime configuration for the probe, loaded from environment or CLI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeConfiguration {
    pub allowed_domains: Vec<String>,
    /// Maximum simultaneous active probes.
    pub max_concurrency: usize,
    /// Per-probe timeout in seconds.
    pub timeout_seconds: u64,
    /// Per-domain cooldown in seconds (no repeat probes within this window).
    pub cooldown_seconds: u64,
}

impl Default for ProbeConfiguration {
    fn default() -> Self {
        Self {
            allowed_domains: vec![],
            max_concurrency: 5,
            timeout_seconds: 15,
            cooldown_seconds: 300, // 5 minutes
        }
    }
}

impl ProbeConfiguration {
    pub fn from_env() -> Self {
        let mut config = Self::default();
        if let Ok(domains) = std::env::var("MAILENT_PROBE_ALLOWED_DOMAINS") {
            config.allowed_domains = domains
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        config.timeout_seconds = std::env::var("MAILENT_PROBE_TIMEOUT_SECONDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(15)
            .clamp(1, 120);
        config.cooldown_seconds = std::env::var("MAILENT_PROBE_COOLDOWN_SECONDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300)
            .clamp(1, 86400);
        config.max_concurrency = std::env::var("MAILENT_PROBE_MAX_CONCURRENCY")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5)
            .clamp(1, 32);
        config
    }

    pub fn to_scope(&self) -> ProbeScope {
        let authorized = self
            .allowed_domains
            .iter()
            .map(|d| AuthorizedDomain {
                domain: d.clone(),
                authorization_ref: "operator-config".to_string(),
            })
            .collect();
        ProbeScope::new(authorized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailent_domain::EmailProtocol;

    #[test]
    fn test_exact_domain_match() {
        let scope = ProbeScope::new(vec![AuthorizedDomain {
            domain: "mail.example.org".to_string(),
            authorization_ref: "AUTH-1".to_string(),
        }]);
        assert!(scope.is_authorized("mail.example.org"));
        assert!(scope.is_authorized("MAIL.EXAMPLE.ORG")); // case-insensitive
        assert!(!scope.is_authorized("smtp.example.org"));
        assert!(!scope.is_authorized("unauthorized.target.com"));
    }

    #[test]
    fn test_wildcard_subdomain_match() {
        let scope = ProbeScope::new(vec![AuthorizedDomain {
            domain: "*.example.com".to_string(),
            authorization_ref: "AUTH-2".to_string(),
        }]);
        assert!(scope.is_authorized("mail.example.com"));
        assert!(scope.is_authorized("smtp.example.com"));
        assert!(!scope.is_authorized("example.com")); // bare domain excluded
        assert!(!scope.is_authorized("evil.notexample.com"));
    }

    #[test]
    fn test_scope_validate_rejects_unauthorized() {
        let scope = ProbeScope::new(vec![AuthorizedDomain {
            domain: "mail.example.org".to_string(),
            authorization_ref: "AUTH-123".to_string(),
        }]);
        assert!(scope.validate("mail.example.org").is_ok());
        let err = scope.validate("unauthorized.target.com");
        assert!(matches!(err, Err(ProbeScopeError::UnauthorizedTarget(_))));
        if let Err(ProbeScopeError::UnauthorizedTarget(t)) = err {
            assert_eq!(t, "unauthorized.target.com");
        }
    }

    #[test]
    fn test_probe_target_within_scope() {
        let config = ProbeConfiguration {
            allowed_domains: vec!["mail.example.org".to_string()],
            ..Default::default()
        };
        let scope = config.to_scope();
        let target = ProbeTarget {
            domain: "mail.example.org".to_string(),
            port: 25,
            protocol: EmailProtocol::Smtp,
        };
        assert!(scope.validate(&target.domain).is_ok());
    }
}
