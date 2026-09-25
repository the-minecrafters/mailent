use std::path::Path;
use mailent_domain::{ProbeRun, RemediationRecord};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::credentials;

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncRemediationPayload {
    pub client_sync_id: Uuid,
    pub record: RemediationRecord,
    pub probe: Option<ProbeRun>,
    pub device_note: Option<String>,
}

pub async fn sync_remediation(
    server_override: Option<String>,
    record: &RemediationRecord,
    probe: Option<&ProbeRun>,
    config_path: &Path,
) -> Result<(), String> {
    let creds = credentials::load_credentials().ok_or_else(|| {
        "Not logged in. Run `mailent login` to register this device before using --sync."
            .to_string()
    })?;

    let server_url = server_override
        .or_else(|| std::env::var("MAILENT_SERVER_URL").ok())
        .unwrap_or(creds.server_url.clone());

    let client = reqwest::Client::new();
    let url = format!(
        "{}/api/v1/remediations/sync",
        server_url.trim_end_matches('/')
    );

    let payload = SyncRemediationPayload {
        client_sync_id: Uuid::new_v4(),
        record: record.clone(),
        probe: probe.cloned(),
        device_note: Some(format!(
            "Remediation applied locally to {}",
            config_path.display()
        )),
    };

    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", creds.device_token))
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("Failed to connect to Mailent server at {url}: {e}"))?;

    if credentials::handle_rejection(resp.status(), &creds)? {
        return Err("Sign in again before syncing results.".into());
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Sync failed (HTTP {status}): {body}"));
    }

    println!(
        "\x1b[32m✔ Successfully synced remediation {} to {}\x1b[0m",
        record.id, server_url
    );

    Ok(())
}
