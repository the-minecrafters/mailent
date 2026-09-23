use async_trait::async_trait;
use mailent_domain::{DecisionContext, DecisionResult, FindingSeverity, PriorityLevel, RiskLevel};
use std::time::Duration;
use tracing::{debug, warn};

use crate::{DecisionError, DecisionProvider, circuit_breaker::CircuitBreaker};

#[derive(Debug, Clone)]
pub struct JevConfig {
    pub base_url: String,
    pub api_key: String,
    pub model: String,
    pub timeout: Duration,
    pub allow_fallback: bool,
}

impl Default for JevConfig {
    fn default() -> Self {
        let base_url = std::env::var("TYPESAFE_BASE_URL")
            .or_else(|_| std::env::var("JEV_BASE_URL"))
            .unwrap_or_else(|_| "https://api.codiv.ai".to_string());
        let api_key = std::env::var("TYPESAFE_API_KEY")
            .or_else(|_| std::env::var("JEV_API_KEY"))
            .unwrap_or_default();
        let model = std::env::var("TYPESAFE_MODEL")
            .or_else(|_| std::env::var("JEV_MODEL"))
            .unwrap_or_else(|_| "openjev-latest".to_string());

        Self {
            base_url,
            api_key,
            model,
            timeout: Duration::from_secs(10),
            allow_fallback: true,
        }
    }
}

pub struct JevProvider {
    config: JevConfig,
    client: reqwest::Client,
    circuit_breaker: CircuitBreaker,
}

impl JevProvider {
    pub fn new(config: JevConfig) -> Self {
        let client = reqwest::Client::builder()
            .user_agent("Mailent/0.1")
            .timeout(config.timeout)
            .build()
            .unwrap_or_default();

        Self {
            config,
            client,
            circuit_breaker: CircuitBreaker::new(3, Duration::from_secs(30)),
        }
    }

    pub fn with_client(config: JevConfig, client: reqwest::Client) -> Self {
        Self {
            config,
            client,
            circuit_breaker: CircuitBreaker::new(3, Duration::from_secs(30)),
        }
    }

    /// Derives a deterministic assessment without contacting external decision services.
    pub fn deterministic_fallback(context: &DecisionContext) -> DecisionResult {
        let has_critical = context
            .findings
            .iter()
            .any(|f| f.severity == FindingSeverity::Critical);
        let has_high = context
            .findings
            .iter()
            .any(|f| f.severity == FindingSeverity::High);
        let has_medium = context
            .findings
            .iter()
            .any(|f| f.severity == FindingSeverity::Medium);

        let (risk, priority, human_review) = if has_critical {
            (RiskLevel::Critical, PriorityLevel::Immediate, true)
        } else if has_high {
            (RiskLevel::High, PriorityLevel::High, true)
        } else if has_medium {
            (RiskLevel::Medium, PriorityLevel::Normal, false)
        } else {
            (RiskLevel::Low, PriorityLevel::Low, false)
        };

        let has_anomalies = context
            .metadata
            .get("anomalies")
            .and_then(|a| a.as_array())
            .map(|arr| !arr.is_empty())
            .unwrap_or(false);

        let reasons: Vec<String> = context
            .findings
            .iter()
            .map(|f| format!("[{}] {}", f.severity, f.title))
            .collect();

        DecisionResult {
            risk,
            anomalous: has_anomalies || has_high || has_critical,
            human_review,
            priority,
            confidence: 0.85,
            provider_info: mailent_domain::DETERMINISTIC_DECISION_PROVIDER.to_string(),
            reasons,
        }
    }

    fn build_systemone_payload(&self, context: &DecisionContext) -> serde_json::Value {
        // Sanitize and extract only high-level structured context:
        // Never include raw packet bytes, credentials, or email body.
        let sanitized_findings: Vec<serde_json::Value> = context
            .findings
            .iter()
            .map(|f| {
                serde_json::json!({
                    "severity": f.severity.to_string(),
                    "title": f.title,
                    "description": f.description,
                })
            })
            .collect();

        let state = serde_json::json!({
            "session_id": context.session_id.to_string(),
            "findings": sanitized_findings,
            "metadata": context.metadata,
        });

        serde_json::json!({
            "model": self.config.model,
            "state": state,
            "questions": {
                "risk": {
                    "type": "choice",
                    "instructions": "Determine the overall security risk level of this mail observation or asset state",
                    "criteria": {
                        "low": "Benign or expected modern TLS configuration without security regressions",
                        "medium": "Minor configuration deviation or deprecated cipher with low exploitability",
                        "high": "Clear cryptographic degradation, unencrypted sensitive mail, or MTA-STS/DANE policy failure",
                        "critical": "Active plaintext downgrade, certificate spoofing/untrusted CA, or MITM indicator"
                    }
                },
                "anomalous": {
                    "type": "choice",
                    "instructions": "Is this observation significantly anomalous compared to expected mail traffic?",
                    "criteria": {
                        "yes": "Observed behavior is an unusual anomaly or policy divergence",
                        "no": "Observed behavior conforms to expected operations"
                    }
                },
                "human_review": {
                    "type": "choice",
                    "instructions": "Does this require security analyst or administrator intervention?",
                    "criteria": {
                        "yes": "Immediate or near-term manual investigation recommended",
                        "no": "Can be tracked automatically without manual intervention"
                    }
                },
                "priority": {
                    "type": "choice",
                    "instructions": "Assign investigation handling priority",
                    "criteria": {
                        "low": "Low priority, routine review",
                        "normal": "Standard operational follow-up",
                        "high": "High priority incident or security degradation",
                        "immediate": "Immediate triage required"
                    }
                }
            }
        })
    }

    pub fn parse_systemone_response(
        response_json: &serde_json::Value,
    ) -> Result<DecisionResult, DecisionError> {
        let answers = response_json
            .get("answers")
            .or_else(|| response_json.get("choices"))
            .ok_or_else(|| {
                DecisionError::ProviderFailure(format!(
                    "response missing 'answers' or 'choices' object, full response: {}",
                    response_json
                ))
            })?;

        for (field, allowed) in [
            ("risk", &["low", "medium", "high", "critical"][..]),
            ("anomalous", &["yes", "no", "true", "false"][..]),
            ("human_review", &["yes", "no", "true", "false"][..]),
            ("priority", &["low", "normal", "high", "immediate"][..]),
        ] {
            let choice = answers
                .get(field)
                .and_then(|v| v.get("choice"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if !allowed.contains(&choice.as_str()) {
                return Err(DecisionError::ProviderFailure(format!(
                    "Missing or invalid Jev answer: {field}"
                )));
            }
        }
        let model = response_json
            .get("model")
            .and_then(|m| m.as_str())
            .unwrap_or("openjev");

        // Parse risk
        let risk_obj = answers.get("risk");
        let risk_str = risk_obj
            .and_then(|r| r.get("choice"))
            .and_then(|c| c.as_str())
            .unwrap_or("low");
        let risk = match risk_str.to_ascii_lowercase().as_str() {
            "critical" => RiskLevel::Critical,
            "high" => RiskLevel::High,
            "medium" => RiskLevel::Medium,
            _ => RiskLevel::Low,
        };

        // Parse anomalous
        let anomalous_obj = answers.get("anomalous");
        let anomalous_str = anomalous_obj
            .and_then(|r| r.get("choice"))
            .and_then(|c| c.as_str())
            .unwrap_or("no");
        let anomalous = matches!(anomalous_str.to_ascii_lowercase().as_str(), "yes" | "true");

        // Parse human_review
        let hr_obj = answers.get("human_review");
        let hr_str = hr_obj
            .and_then(|r| r.get("choice"))
            .and_then(|c| c.as_str())
            .unwrap_or("no");
        let human_review = matches!(hr_str.to_ascii_lowercase().as_str(), "yes" | "true");

        // Parse priority
        let priority_obj = answers.get("priority");
        let priority_str = priority_obj
            .and_then(|r| r.get("choice"))
            .and_then(|c| c.as_str())
            .unwrap_or("low");
        let priority = match priority_str.to_ascii_lowercase().as_str() {
            "immediate" => PriorityLevel::Immediate,
            "high" => PriorityLevel::High,
            "normal" => PriorityLevel::Normal,
            _ => PriorityLevel::Low,
        };

        // Extract confidence (prioritize risk confidence, or average)
        let risk_confidence = risk_obj
            .and_then(|r| r.get("confidence"))
            .and_then(|c| c.as_f64())
            .map(|f| f as f32)
            .filter(|f| f.is_finite() && (0.0..=1.0).contains(f))
            .unwrap_or(0.0);

        // Extract reasons
        let mut reasons = Vec::new();
        for key in ["risk", "anomalous", "human_review", "priority"] {
            if let Some(item) = answers.get(key) {
                let choice = item
                    .get("choice")
                    .and_then(|c| c.as_str())
                    .unwrap_or_default();
                let conf = item.get("confidence").and_then(|c| c.as_f64());
                if let Some(c) = conf {
                    reasons.push(format!("{key}={choice} (confidence: {:.1}%)", c * 100.0));
                } else if let Some(crit) = item.get("criteria").and_then(|c| c.as_str()) {
                    reasons.push(format!("{key}={choice}: {crit}"));
                } else {
                    reasons.push(format!("{key}={choice}"));
                }
            }
        }

        Ok(DecisionResult {
            risk,
            anomalous,
            human_review,
            priority,
            confidence: risk_confidence,
            provider_info: format!("jev:{model}"),
            reasons,
        })
    }
}

#[async_trait]
impl DecisionProvider for JevProvider {
    async fn assess(&self, context: DecisionContext) -> Result<DecisionResult, DecisionError> {
        if self.config.api_key.trim().is_empty() {
            if self.config.allow_fallback {
                debug!("Jev API key not set, using deterministic fallback");
                return Ok(Self::deterministic_fallback(&context));
            } else {
                return Err(DecisionError::Disabled);
            }
        }

        if !self.circuit_breaker.is_allowed() {
            warn!("Jev circuit breaker is open; skipping live call");
            if self.config.allow_fallback {
                return Ok(Self::deterministic_fallback(&context));
            } else {
                return Err(DecisionError::CircuitBreakerOpen);
            }
        }

        let url = format!(
            "{}/v1/systemone",
            self.config.base_url.trim_end_matches('/')
        );
        let payload = self.build_systemone_payload(&context);

        let req = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .header("Content-Type", "application/json")
            .json(&payload);

        match req.send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    match resp.json::<serde_json::Value>().await {
                        Ok(json) => match Self::parse_systemone_response(&json) {
                            Ok(res) => {
                                self.circuit_breaker.record_success();
                                Ok(res)
                            }
                            Err(e) => {
                                self.circuit_breaker.record_failure();
                                warn!("Jev response parsing failed: {e}");
                                if self.config.allow_fallback {
                                    Ok(Self::deterministic_fallback(&context))
                                } else {
                                    Err(e)
                                }
                            }
                        },
                        Err(e) => {
                            self.circuit_breaker.record_failure();
                            warn!("Jev JSON decoding failed: {e}");
                            if self.config.allow_fallback {
                                Ok(Self::deterministic_fallback(&context))
                            } else {
                                Err(DecisionError::ProviderFailure(e.to_string()))
                            }
                        }
                    }
                } else {
                    self.circuit_breaker.record_failure();
                    let err_msg = format!("Jev endpoint returned HTTP {status}");
                    warn!("{err_msg}");
                    if self.config.allow_fallback {
                        Ok(Self::deterministic_fallback(&context))
                    } else {
                        Err(DecisionError::ProviderFailure(err_msg))
                    }
                }
            }
            Err(e) => {
                self.circuit_breaker.record_failure();
                let is_timeout = e.is_timeout();
                warn!("Jev request failed: {e} (timeout={is_timeout})");
                if self.config.allow_fallback {
                    Ok(Self::deterministic_fallback(&context))
                } else if is_timeout {
                    Err(DecisionError::Timeout(
                        self.config.timeout.as_millis() as u64
                    ))
                } else {
                    Err(DecisionError::ProviderFailure(e.to_string()))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailent_domain::FindingCandidate;
    use uuid::Uuid;

    #[test]
    fn test_parse_jev_valid_response() {
        let json = serde_json::json!({
            "id": "cmpl-12345",
            "model": "openjev-0.1",
            "choices": {
                "risk": {
                    "choice": "high",
                    "criteria": "Clear cryptographic degradation or MTA-STS policy failure",
                    "type": "choice"
                },
                "anomalous": {
                    "choice": "yes",
                    "criteria": "Observed behavior is an unusual anomaly or policy divergence",
                    "type": "choice"
                },
                "human_review": {
                    "choice": "yes",
                    "criteria": "Immediate or near-term manual investigation recommended",
                    "type": "choice"
                },
                "priority": {
                    "choice": "high",
                    "criteria": "High priority incident or security degradation",
                    "type": "choice"
                }
            }
        });

        let res = JevProvider::parse_systemone_response(&json).unwrap();
        assert_eq!(res.risk, RiskLevel::High);
        assert_eq!(res.priority, PriorityLevel::High);
        assert!(res.anomalous);
        assert!(res.human_review);
        assert_eq!(res.provider_info, "jev:openjev-0.1");
        assert_eq!(res.reasons.len(), 4);
    }

    #[test]
    fn test_parse_jev_malformed_response() {
        let json = serde_json::json!({
            "error": "internal error"
        });

        let err = JevProvider::parse_systemone_response(&json).unwrap_err();
        assert!(matches!(err, DecisionError::ProviderFailure(_)));
    }

    #[test]
    fn incomplete_answers_cannot_become_a_low_risk_decision() {
        assert!(
            JevProvider::parse_systemone_response(&serde_json::json!({"answers": {}})).is_err()
        );
        assert!(
            JevProvider::parse_systemone_response(
                &serde_json::json!({"answers": {"risk": {"choice":"low"}}})
            )
            .is_err()
        );
    }

    #[test]
    fn test_deterministic_fallback() {
        let ctx = DecisionContext {
            session_id: Uuid::new_v4(),
            findings: vec![FindingCandidate {
                rule_id: "RULE_STARTTLS_STRIPPED".to_string(),
                policy_name: "RFC 7817 Compliance".to_string(),
                policy_version: "1.0".to_string(),
                reference: "RFC 7817".to_string(),
                severity: FindingSeverity::Critical,
                category: mailent_domain::FindingCategory::ProtocolDowngrade,
                title: "STARTTLS Stripped".to_string(),
                description: "Plaintext downgrade detected".to_string(),
                remediation: "Enforce TLS".to_string(),
                evidence: vec![mailent_domain::EvidenceRef {
                    session_id: None,
                    observation_id: None,
                    description: "STRIPPED".to_string(),
                }],
            }],
            metadata: serde_json::json!({
                "anomalies": ["UnseenTlsVersion"]
            }),
        };

        let res = JevProvider::deterministic_fallback(&ctx);
        assert_eq!(res.risk, RiskLevel::Critical);
        assert_eq!(res.priority, PriorityLevel::Immediate);
        assert!(res.anomalous);
        assert!(res.human_review);
        assert_eq!(res.provider_info, "mailent-deterministic-fallback");
    }

    #[tokio::test]
    async fn test_jev_circuit_breaker_and_timeout_fallback() {
        let config = JevConfig {
            api_key: "test-key".to_string(),
            base_url: "http://127.0.0.1:1".to_string(), // unreachable
            timeout: Duration::from_millis(50),
            allow_fallback: true,
            ..Default::default()
        };

        let provider = JevProvider::new(config);
        let ctx = DecisionContext {
            session_id: Uuid::new_v4(),
            findings: vec![],
            metadata: serde_json::json!({}),
        };

        // Even though connection to 127.0.0.1:1 fails, fallback ensures assess succeeds!
        let res = provider.assess(ctx).await.unwrap();
        assert_eq!(res.provider_info, "mailent-deterministic-fallback");
    }
}
