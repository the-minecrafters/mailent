use mailent_decision::{DecisionProvider, JevConfig, JevProvider};
use mailent_domain::{DecisionContext, FindingCandidate, FindingCategory, FindingSeverity};
use std::time::Duration;
use uuid::Uuid;

#[tokio::test]
async fn test_live_jev_integration_if_key_available() {
    let Ok(api_key) =
        std::env::var("MAILENT_JEV_API_KEY").or_else(|_| std::env::var("TYPESAFE_API_KEY"))
    else {
        return;
    };

    let config = JevConfig {
        base_url: "https://api.codiv.ai".to_string(),
        api_key,
        model: "openjev-latest".to_string(),
        timeout: Duration::from_secs(10),
        allow_fallback: false,
    };

    let provider = JevProvider::new(config);
    let ctx = DecisionContext {
        session_id: Uuid::new_v4(),
        findings: vec![FindingCandidate {
            rule_id: "RULE_STARTTLS_STRIPPED".to_string(),
            policy_name: "Strict Transport Security".to_string(),
            policy_version: "1.0".to_string(),
            reference: "RFC 8461".to_string(),
            severity: FindingSeverity::High,
            category: FindingCategory::ProtocolDowngrade,
            title: "STARTTLS Downgrade Attack Detected".to_string(),
            description:
                "Mail session negotiated unencrypted traffic while domain enforced MTA-STS"
                    .to_string(),
            remediation: "Block plaintext connections and verify upstream MTA-STS compliance"
                .to_string(),
            evidence: vec![],
        }],
        metadata: serde_json::json!({
            "domain": "secure.example.com",
            "protocol": "smtp",
            "tls_version": "none",
            "mta_sts_mode": "enforce"
        }),
    };

    let res = provider.assess(ctx).await;
    match res {
        Ok(decision) => {
            println!("Live Jev decision received: {:?}", decision);
            assert!(decision.provider_info.starts_with("jev:"));
            assert!(decision.confidence > 0.0);
            assert!(!decision.reasons.is_empty());
        }
        Err(e) => {
            panic!("Live Jev call failed: {e}");
        }
    }
}
