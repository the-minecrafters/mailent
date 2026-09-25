use crate::credentials::{self, DeviceCredentials};
use std::{path::Path, time::Duration};

/// Setup reporting is advisory. A workspace running an older version can still receive results.
pub async fn report_best_effort(creds: &DeviceCredentials, server: &str, zeek: Option<&Path>) {
    if let Err(error) = report(creds, server, zeek).await {
        eprintln!("Installation status could not be updated: {error}");
    }
}

async fn report(
    creds: &DeviceCredentials,
    server: &str,
    zeek: Option<&Path>,
) -> Result<(), String> {
    let zeek_version = crate::locate_zeek(zeek)
        .and_then(|path| crate::verified_zeek_version(&path))
        .ok();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    let response = client.post(format!("{}/api/v1/devices/status", server.trim_end_matches('/')))
        .bearer_auth(&creds.device_token)
        .json(&serde_json::json!({"version": env!("CARGO_PKG_VERSION"), "zeek_version": zeek_version}))
        .send().await.map_err(|e| e.to_string())?;
    if credentials::handle_rejection(response.status(), creds)? {
        return Err("Workspace access was removed. Run mailent login to reconnect.".into());
    }
    if matches!(response.status().as_u16(), 404 | 405) {
        return Ok(());
    }
    response.error_for_status().map_err(|e| e.to_string())?;
    Ok(())
}
